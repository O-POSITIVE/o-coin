"""The actual chain: blocks linked by hash, proof-of-work mining, and full
chain validation. This is a real, working blockchain in the literal
technical sense — not a database table pretending to be one. Every block
genuinely has to satisfy a computationally-expensive proof-of-work
condition to be accepted, and the chain can be independently re-verified
by anyone from scratch, from genesis, using nothing but is_chain_valid().

Deliberately built lean rather than as a fork of Bitcoin/Dogecoin/Litecoin's
own C++ codebase (see O-coin/README.md for the full reasoning and the
roadmap toward that heavier infrastructure later) — no real P2P discovery
protocol yet (node.py's /nodes/register + /nodes/resolve are a genuine
"most-work valid chain wins" consensus implementation, just without
automatic peer discovery — peers are added by hand for now); real Scrypt
mining IS implemented (see Block.compute_hash), same algorithm and same
real parameters Litecoin/Dogecoin use, not a placeholder.

Four upgrades baked in from the start rather than retrofitted later, in
answer to "cheap, fast, efficient, secure":
  - CHEAP: transactions carry a small FEE (see transaction.py), kept
    deliberately tiny by design — the "low gas price" lever.
  - FAST: difficulty RETARGETS toward a short target block time (see
    _maybe_retarget) — the same mechanism every real PoW chain uses to
    keep block times roughly constant as total mining power on the
    network rises and falls. TARGET_BLOCK_TIME is 15 seconds on purpose —
    Dogecoin-fast, not Bitcoin-slow.
  - EFFICIENT: miners fill a block with the HIGHEST-FEE pending
    transactions first (see build_candidate_block) rather than
    first-in-first-out, so limited block space always goes to whoever's
    actually paying for priority, same as every real fee market.
  - SECURE: every transaction is individually signed with real ECDSA
    (see transaction.py, same curve family Bitcoin uses) and every
    block's entire transaction set is committed to by a Merkle root, so
    tampering with ANYTHING — a single transaction's amount, a
    signature, a whole block — breaks a hash chain that's cheap to
    verify and computationally expensive to fake. is_chain_valid() is
    the "trust nothing, verify everything from genesis" function that
    makes this a real guarantee rather than a promise.
"""
import hashlib
import json
import math
import time

from pow_hash import header_fields_to_hash

from transaction import Transaction, is_real_number

# The ledger counts whole UNITS, never fractional coins (2026-09-30), the
# way Bitcoin counts satoshis: 1 coin = 100,000,000 units, the smallest
# amount anything can hold. See _apply_transaction_to_balance_dict.
UNITS_PER_COIN = 10 ** 8


def to_units(amount):
    """A decimal amount, as a transaction carries it, in whole units.
    Deterministic on every platform: the multiplication and Python's
    round() are both exactly specified for IEEE 754 doubles. An int is
    multiplied exactly, never through a float."""
    if isinstance(amount, int):
        return amount * UNITS_PER_COIN
    if not math.isfinite(amount):
        raise ValueError(f"not a finite amount: {amount!r}")
    return int(round(amount * UNITS_PER_COIN))


def to_coins(units):
    """Units back to coins, for display and the HTTP API only -- never for a
    consensus decision."""
    return units / UNITS_PER_COIN


class Block:
    def __init__(self, index, transactions, previous_hash, target, timestamp=None, nonce=0, staker_address=None):
        self.index = index
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.transactions = transactions  # list[Transaction]
        self.previous_hash = previous_hash
        # Stored ON the block (not just read from the chain's current
        # difficulty) so historical blocks stay independently verifiable
        # even after later retargets change what "valid" means for NEW
        # blocks — is_chain_valid() checks each block against the target
        # IT recorded, never against today's target. Means two different
        # things depending on the block: a PoW difficulty target for a
        # mined block, or a PoS difficulty target for a staked one (see
        # staker_address) — never both, only one production method wins
        # per block.
        self.target = target
        self.nonce = nonce
        # None for an ordinary mined (PoW) block. A real address for a
        # STAKED (PoS) block — set, this block wasn't found by brute-force
        # hashing at all, it was minted by this address demonstrating
        # ownership of a large-enough, long-enough-untouched balance (see
        # compute_stake_kernel_hash and Blockchain.build_stake_block).
        self.staker_address = staker_address
        self.merkle_root = self.compute_merkle_root()

    def compute_merkle_root(self):
        """A simplified Merkle tree: pair up transaction hashes and hash
        each pair together, repeating until one hash remains. This is
        what lets a block commit to its *entire* transaction set with a
        single fixed-size hash — tampering with any one transaction
        anywhere in the block changes this root, which changes the
        block's own hash, which breaks every block after it (see
        Blockchain.is_chain_valid). An empty block (genesis) gets a
        root of all zeros.
        """
        if not self.transactions:
            return "0" * 64
        layer = [tx.hash() for tx in self.transactions]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])  # odd one out pairs with itself
            layer = [
                hashlib.sha256((layer[i] + layer[i + 1]).encode()).hexdigest()
                for i in range(0, len(layer), 2)
            ]
        return layer[0]

    def header_string(self):
        # Exactly what gets hashed for proof-of-work — deliberately just
        # the header fields (not the full transaction list), same as real
        # chains: the merkle_root already commits to the transactions, so
        # re-hashing the whole transaction list on every nonce attempt
        # during mining would be needless repeated work.
        return json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "target": self.target,
            "nonce": self.nonce,
        }, sort_keys=True)

    def compute_hash(self):
        # Real, ASIC-resistant Scrypt PoW hash — see pow_hash.py's own
        # docstring for the full reasoning. Shared with miner.py's local
        # search loop via that one module specifically so the two can
        # never silently drift out of sync with each other.
        return header_fields_to_hash(self.index, self.timestamp, self.merkle_root, self.previous_hash, self.target, self.nonce)

    def meets_target(self):
        return int(self.compute_hash(), 16) < self.target

    def compute_stake_kernel_hash(self):
        """The proof-of-STAKE equivalent of compute_hash()/meets_target()
        — but deliberately NOT the same (Scrypt, memory-hard, meant to be
        slow-ish) hash used for PoW search. There's no brute-force search
        happening here at all: plain, fast SHA-256 over previous_hash +
        staker_address + the CURRENT SECOND (int(timestamp), floored —
        not sub-second precision) is exactly the point. A staker gets
        ONE kernel value per second, full stop, because the input space
        is just "which second is it" — there's no nonce field to grind
        through here, so waiting for real wall-clock time to pass is the
        only way to get a new attempt. That's what stops proof-of-stake
        from secretly becoming a second proof-of-COMPUTE race for
        whoever has the fastest CPU: your odds of success scale with
        your stake weight (see Blockchain.build_stake_block /
        _validate_stake_proof), never with how many hashes you can crunch
        per second, because you only ever get one shot per second no
        matter how fast your machine is."""
        s = f"{self.previous_hash}{self.staker_address}{int(self.timestamp)}"
        return hashlib.sha256(s.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index, "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash, "target": self.target, "nonce": self.nonce,
            "staker_address": self.staker_address,
            "merkle_root": self.merkle_root, "hash": self.compute_hash(),
        }

    @staticmethod
    def from_dict(d):
        return Block(
            d["index"], [Transaction.from_dict(t) for t in d["transactions"]],
            d["previous_hash"], d["target"], d["timestamp"], d["nonce"],
            staker_address=d.get("staker_address"),
        )


class Blockchain:
    # Starting target: a block hash (treated as a 256-bit number) has to
    # come out below this to be valid. Tuned specifically for Scrypt's
    # real, much-slower-than-SHA-256 rate — that's the entire point of
    # using it, but it means the difficulty that felt right for a plain
    # SHA-256 chain would be wildly too hard here. Benchmarked
    # hashlib.scrypt at these exact parameters in this environment: ~4000
    # hashes/sec on one CPU core. 2**256 // 2**13 needs on average 2**13
    # (~8,200) attempts — a couple of seconds at that rate, easy enough
    # for the first blocks to come quickly, with _maybe_retarget() taking
    # over from there. Matches how Speepcoin's own starting difficulty was
    # deliberately picked easy (see contracts/Speepcoin.sol) for the same
    # reason: don't make early miners sit idle for ages before the
    # network's real difficulty has ever been calibrated.
    INITIAL_TARGET = 2 ** 256 // 2 ** 13
    MAX_TARGET = 2 ** 256 // 2 ** 8  # retargeting can never make it easier than this, same ceiling idea Speepcoin's contract uses
    TARGET_BLOCK_TIME = 15  # seconds — short and Dogecoin-fast on purpose, not Bitcoin-slow
    RETARGET_INTERVAL = 10  # re-check every 10 blocks
    MAX_ADJUSTMENT_FACTOR = 4  # difficulty can at most 4x or /4 in one retarget, same anti-whiplash cap Speepcoin's contract uses
    # Once /transactions/new is a PUBLIC route (decentralization phase D2),
    # the mempool must be bounded so anyone can't grow it without limit. When
    # full, a new transaction only displaces the current lowest-fee pending one
    # if it pays a strictly higher fee — the same fee-priority the block builder
    # already uses to choose what to include. ~25 min of backlog at the ~50-tx,
    # 15s block cadence, so it never bites legitimate use.
    MEMPOOL_MAX = 5000
    # The release whose consensus rules this code enforces; node.py reports
    # it in /status. Bump it with every change to what a valid block is.
    RULES_VERSION = "0.2.0"
    # From this block on (2026-09-30): signed quantities must be whole
    # units, a block's coinbase must equal reward + fees EXACTLY in units,
    # and the pool formulas are integer ones (see
    # _apply_transaction_to_balance_dict). Before it, history keeps the
    # rules it was made under. The units LEDGER itself applies from genesis:
    # the whole live chain was replayed both ways before this was added and
    # agrees to the unit. Must be ahead of the live tip when this ships --
    # a block the old code made at or past it would be judged by new rules.
    INTEGER_UNITS_ACTIVATION_HEIGHT = 17_500
    OP_QUANTITY_FIELDS = ("amount_a", "amount_b", "amount_in", "min_amount_out", "lp_amount")

    # ── Emission curve — smooth EXPONENTIAL decay toward a permanent
    # floor, not Bitcoin/Dogecoin-style discrete halving and not a
    # straight linear ramp either (an earlier version of this file used a
    # linear ramp — replaced because a reward that flattens out completely
    # stops responding to anything and stagnates; a reward that keeps
    # shrinking forever, geometrically, stays "alive" — always a little
    # smaller than last year, same as a dollar's real purchasing power —
    # while a floor (REWARD_FLOOR) still guarantees miners will always be
    # paid something, so the chain never has to defend itself on
    # transaction fees alone once emission gets small).
    #
    # The DECAY RATE itself isn't arbitrary: it's set to shrink the
    # reward by ANNUAL_DECAY_PERCENT (currently 3%) of its distance above
    # the floor every ~year of blocks — 3% because that's the commonly
    # cited long-run historical average for US CPI inflation (the Fed's
    # explicit modern target is 2%; 3% is the broader ~100-year average).
    # The idea: block reward should lose "real" value at roughly the same
    # pace the dollar does, rather than at some unrelated made-up rate.
    # This is a judgment call, not a law of nature — ANNUAL_DECAY_PERCENT
    # is a single named constant specifically so it's easy to revisit if
    # actual inflation data suggests a different long-run number later.
    #
    # Consensus-critical code can't use raw floating-point exponentiation
    # (math.pow/** with a fractional exponent) — libm implementations
    # aren't guaranteed bit-identical across platforms for transcendental
    # functions, so two perfectly honest nodes could compute two
    # different "correct" rewards for the same height and fork over
    # nothing. Fixed-point exponentiation-by-squaring (_fixed_pow below)
    # solves this the same way real on-chain compound-interest/decay math
    # is done in Solidity DeFi (e.g. ABDKMath64x64): the per-block decay
    # ratio is pre-derived ONCE, offline (see the comment above
    # REWARD_DECAY_RATE_FIXED), baked in as a fixed integer literal, and
    # every node then only ever does integer multiply/shift — no library
    # transcendental call anywhere in the actual per-block calculation.
    BASE_REWARD = 100
    REWARD_FLOOR = 0.5  # the permanent asymptote — reward gets arbitrarily close to this but is mathematically incapable of ever reaching or crossing it
    FRAC_BITS = 64  # fixed-point precision used for the decay math below (Q0.64 — values are integers representing value * 2**64)
    ANNUAL_DECAY_PERCENT = 3  # documented above — long-run US CPI average, not the Fed's 2% target, chosen for a "long set period of time" per the design brief

    # REWARD_DECAY_RATE_FIXED is DERIVED from ANNUAL_DECAY_PERCENT and
    # TARGET_BLOCK_TIME — it is not itself an independent knob. It's kept
    # as a hardcoded integer literal (rather than computed fresh at
    # import time) specifically so no node ever runs a floating-point
    # transcendental function as part of starting up its consensus logic
    # — see the class docstring above for why that matters. The tradeoff
    # is that changing ANNUAL_DECAY_PERCENT or TARGET_BLOCK_TIME requires
    # regenerating this literal by hand; the self-check right after this
    # class (using _derive_rate_fixed, a dev-only helper) exists
    # specifically to catch anyone who tunes one without the other —
    # it'll refuse to start with a clear regenerate-it-like-this message
    # instead of silently running a curve that doesn't match its own
    # documented decay rate.
    REWARD_DECAY_RATE_FIXED = 18446743806639241216

    # Minted directly into genesis, before any mining happens — a
    # deliberate, one-time, fully transparent allocation (see
    # README/commit history for exactly who and how much and why), not
    # something that can be added later without every node agreeing to a
    # rule change. Real precedent for minting supply at genesis rather
    # than starting from zero: XRP Ledger's entire supply was created
    # this way. sender="0" (the same coinbase convention used for every
    # mining reward) since these coins are also being newly created, not
    # transferred from an existing balance.
    GENESIS_PREMINE_ADDRESS = "3b770ab425c217f6615442fcc0517ad8445cf4ba"
    GENESIS_PREMINE_AMOUNT = 5_000_000_000

    @staticmethod
    def _derive_rate_fixed(annual_decay_percent, target_block_time, frac_bits=64):
        """Dev-only — recomputes what REWARD_DECAY_RATE_FIXED *should* be
        for the given ANNUAL_DECAY_PERCENT/TARGET_BLOCK_TIME. Uses plain
        floating-point math (math.pow with a fractional exponent), which
        is exactly what reward_at_height() is NOT allowed to do — the
        difference is this function's result never decides whether a
        block is valid, it's only ever compared against the hardcoded
        REWARD_DECAY_RATE_FIXED literal as a staleness check (see below
        the class), or run by hand after deliberately tuning the decay
        rate/block time to get the new literal to paste in."""
        seconds_per_year = 365.25 * 24 * 3600
        blocks_per_year = seconds_per_year / target_block_time
        r_annual = 1 - annual_decay_percent / 100
        r_block = r_annual ** (1 / blocks_per_year)
        return round(r_block * (1 << frac_bits))

    @staticmethod
    def _fixed_pow(base_fixed, exponent, frac_bits=64):
        """base_fixed ** exponent, computed entirely in fixed-point
        integer math via exponentiation by squaring (O(log exponent)
        multiplications, each immediately truncated back down to
        frac_bits so intermediate values never grow unbounded). No float,
        no library transcendental call — same integer result on every
        machine, every time, for the same inputs."""
        result = 1 << frac_bits  # 1.0 in fixed point
        b = base_fixed
        while exponent > 0:
            if exponent & 1:
                result = (result * b) >> frac_bits
            b = (b * b) >> frac_bits
            exponent >>= 1
        return result

    @classmethod
    def reward_at_height(cls, height):
        """Exponential decay from BASE_REWARD toward REWARD_FLOOR — gets
        arbitrarily close, never reaches or crosses it. See the class
        docstring block above for why this replaced a straight linear
        ramp, and why the decay rate is 3%/year."""
        one = 1 << cls.FRAC_BITS
        floor_fixed = round(cls.REWARD_FLOOR * one)  # exact: 0.5 * 2**64 == 2**63, no rounding error
        base_fixed = cls.BASE_REWARD * one
        factor_fixed = cls._fixed_pow(cls.REWARD_DECAY_RATE_FIXED, height, cls.FRAC_BITS)
        excess_fixed = ((base_fixed - floor_fixed) * factor_fixed) >> cls.FRAC_BITS
        reward_fixed = floor_fixed + excess_fixed
        # The only floating-point operation in the whole calculation: one
        # final division, which (unlike pow/exp/log) IEEE 754 guarantees
        # is correctly rounded — identical on every platform. Rounded to
        # 6 decimal places purely for a clean, displayable amount.
        return round(reward_fixed / one, 6)

    # A block's timestamp can't be more than this far in the future
    # (clock drift / dishonest miners lying to skew future retargets) — the
    # same "not too far ahead" sanity check Bitcoin enforces.
    MAX_FUTURE_DRIFT_SECONDS = 2 * 60 * 60
    # ...and can't be older than the MEDIAN of the last this-many blocks —
    # median (not "must be after the single previous block") specifically
    # because it can't be manipulated by any one miner controlling just
    # one recent block, only by controlling a majority of the whole
    # window, which is a much higher bar. Same idea as Bitcoin's
    # median-time-past rule, just over a shorter window to match this
    # chain's much shorter block time.
    MEDIAN_TIME_WINDOW = 11

    # Blocks at or before (latest - CHECKPOINT_DEPTH) are treated as
    # PERMANENT — replace_chain() will refuse any candidate chain that
    # disagrees with our own history at or before that depth, no matter
    # how much longer or how validly-mined the candidate is. This is the
    # direct, standard mitigation for the fact that a small/new chain
    # doesn't yet have Bitcoin/Dogecoin-scale distributed hashpower behind
    # it: it trades away a small amount of pure "longest chain always
    # wins, no exceptions" decentralization for a hard guarantee that
    # nobody — regardless of hashpower — can rewrite history past this
    # point. 20 blocks at a 15s target is ~5 minutes of "not yet
    # permanent" — tunable; lower is more paranoid but makes checkpointed
    # history stale faster, higher is the reverse.
    CHECKPOINT_DEPTH = 20

    # ── Proof-of-stake (Peercoin-style hybrid consensus) ────────────
    # PoW stays the chain's PRIMARY security mechanism — this is a
    # supplementary second way to produce a block, coexisting on the
    # same chain, not a replacement. That's a deliberate, real echo of
    # Peercoin's own actual design (PoS was introduced alongside PoW,
    # not instead of it). Real Peercoin is UTXO-based, so "staking"
    # there literally spends-and-recreates a specific aged coin (a
    # "coinstake" transaction carrying coin-age as a weighting factor).
    # O-Coin's ledger is account-based (see get_balance) — there's no
    # per-coin age to track, so this adapts the same ECONOMIC idea (your
    # chance of producing a block scales with how much you hold, checked
    # against real wall-clock time, at effectively zero energy cost) to
    # a flat balance-weighted model instead: stake weight is simply an
    # address's current whole-coin balance, floored to an integer (same
    # "avoid float in a consensus decision" reasoning as everywhere else
    # in this file — sub-1-OCN balances just don't get any stake weight,
    # a deliberate, harmless simplification for a hobby chain).
    #
    # PoS gets its OWN separate difficulty target (pos_target) and its
    # own independent retargeting (_maybe_retarget_pos) — mixing PoS
    # block timestamps into PoW's retarget window (or vice versa) would
    # corrupt both signals, since they're measuring two unrelated
    # things (hashpower vs. total actively-staking balance).
    #
    # POS_INITIAL_TARGET is deliberately a FORMULA, not a hardcoded
    # literal like REWARD_DECAY_RATE_FIXED — this is pure integer
    # division (no transcendental function), so there's no cross-
    # platform float-determinism risk in computing it fresh, and doing
    # so means it automatically stays sensible if TARGET_BLOCK_TIME or
    # GENESIS_PREMINE_AMOUNT are ever retuned, with nothing to remember
    # to regenerate by hand. It assumes roughly the whole premine is the
    # initial active stake (true for early solo testing) — like PoW's
    # own INITIAL_TARGET, it only has to be a reasonable starting guess,
    # because retargeting corrects it from real observed timing after
    # that.
    POS_MAX_TARGET = 2 ** 256 // 2 ** 4  # PoS retargeting can never make it easier than this
    POS_RETARGET_INTERVAL = 10  # re-check every 10 PoS blocks (mirrors PoW's RETARGET_INTERVAL)
    # A staked block earns a much smaller reward than a mined one —
    # proportional, real reasoning: PoW's reward has to be big enough to
    # cover real electricity/hardware cost, which is what actually makes
    # a 51%-attack expensive. Staking costs (near) nothing, so paying it
    # the same would undermine PoW's role as the chain's primary
    # security spend without adding any real security in return — this
    # mirrors Peercoin's real ~1%-ish annual "interest" framing for
    # staking rewards, deliberately modest rather than a full subsidy.
    POS_REWARD_FRACTION = 0.1

    def __init__(self):
        self.chain = []
        self.mempool = []  # list[Transaction] waiting to be mined
        self.current_target = self.INITIAL_TARGET
        self.pos_target = self._initial_pos_target()
        # ── BFT finality attachment (DORMANT) ──────────────────────────
        # index -> block hash the BFT finality gadget (bft_finality.py) has
        # cryptographically finalized. This is the ADDITIVE finality layer's
        # one and only reach into consensus: a veto against reorging away a
        # finalized block (see _conflicts_with_bft_finality + replace_chain).
        # It is INERT until a BFT committee actually finalizes something —
        # and nothing here or in node.py runs that committee yet (activation
        # waits on choosing a real cross-machine committee). While this dict
        # stays empty, every reorg decision behaves EXACTLY as it always has;
        # block production, rewards, emission, PoW/PoS are untouched. Same
        # dormant-until-activated shape as the TX_SCHEMA hard fork.
        self.bft_finalized = {}
        self._create_genesis_block()
        self.genesis_hash = self.chain[0].compute_hash()
        self._rebuild_balance_index()

    @classmethod
    def _initial_pos_target(cls):
        return 2 ** 256 // (cls.TARGET_BLOCK_TIME * max(1, cls.GENESIS_PREMINE_AMOUNT))

    def _create_genesis_block(self):
        premine_tx = Transaction(
            sender="0", recipient=self.GENESIS_PREMINE_ADDRESS, amount=self.GENESIS_PREMINE_AMOUNT,
            fee=0, timestamp=0,
        )
        genesis = Block(0, [premine_tx], "0" * 64, self.current_target, timestamp=0, nonce=0)
        self.chain.append(genesis)

    @property
    def latest_block(self):
        return self.chain[-1]

    # ── Difficulty retargeting (the "fast" lever) ───────────────────
    @staticmethod
    def _retarget_ratio(actual_time, expected_time, max_adjustment_factor):
        ratio = actual_time / expected_time
        return max(1 / max_adjustment_factor, min(max_adjustment_factor, ratio))

    @classmethod
    def _next_target(cls, target, window_start_ts, window_end_ts, interval, max_target):
        """One retarget step, shared by the live path (_maybe_retarget,
        _maybe_retarget_pos) and the from-scratch replay in _walk_chain, so
        the two can never compute different targets for the same history."""
        actual_time = max(1, window_end_ts - window_start_ts)
        expected_time = cls.TARGET_BLOCK_TIME * interval
        ratio = cls._retarget_ratio(actual_time, expected_time, cls.MAX_ADJUSTMENT_FACTOR)
        return min(int(target * ratio), max_target)

    @staticmethod
    def block_work(target):
        """Expected hashes to find a block at this target -- Bitcoin's
        "chainwork". Summed over a chain, it is what fork choice compares
        (see replace_chain): a chain of many EASY blocks is long but light."""
        return 2 ** 256 // (target + 1)

    def _maybe_retarget(self):
        """Called right after a PoW block is accepted. Every
        RETARGET_INTERVAL PoW blocks, compares how long that batch
        actually took against TARGET_BLOCK_TIME * RETARGET_INTERVAL, and
        nudges current_target proportionally — found blocks too fast
        (lots of mining power) -> lower target (harder); too slow ->
        raise it (easier). This is the exact mechanism that keeps a real
        PoW chain's block time roughly steady over time instead of
        drifting as total network hashpower changes.

        Deliberately only counts PoW blocks (staker_address is None) —
        genesis included, same as before PoS existed, but any staked
        blocks interleaved in the chain are skipped entirely. Counting
        them here would corrupt this signal: a fast staked block doesn't
        mean mining power went up, it just means someone staked, and
        mixing the two would make PoW difficulty chase a rhythm that has
        nothing to do with actual hashpower."""
        pow_blocks = [b for b in self.chain if b.staker_address is None]
        n = len(pow_blocks) - 1  # PoW blocks mined so far, excluding genesis
        if n < self.RETARGET_INTERVAL or n % self.RETARGET_INTERVAL != 0:
            return
        window_start = pow_blocks[-1 - self.RETARGET_INTERVAL]
        window_end = pow_blocks[-1]
        self.current_target = self._next_target(self.current_target, window_start.timestamp, window_end.timestamp,
                                                self.RETARGET_INTERVAL, self.MAX_TARGET)

    def _maybe_retarget_pos(self):
        """PoS's own fully independent difficulty retarget — same
        mechanism as _maybe_retarget above, applied only to PoS blocks'
        own timestamps (staker_address is not None; genesis never
        qualifies, so no "-1" adjustment is needed here the way PoW's
        version excludes genesis). Kept completely separate from PoW's
        retarget so the two block-production methods never interfere
        with each other's difficulty signal."""
        pos_blocks = [b for b in self.chain if b.staker_address is not None]
        n = len(pos_blocks)
        if n < self.POS_RETARGET_INTERVAL or n % self.POS_RETARGET_INTERVAL != 0:
            return
        window_start = pos_blocks[-self.POS_RETARGET_INTERVAL]
        window_end = pos_blocks[-1]
        self.pos_target = self._next_target(self.pos_target, window_start.timestamp, window_end.timestamp,
                                            self.POS_RETARGET_INTERVAL, self.POS_MAX_TARGET)

    # ── Mempool / transactions ────────────────────────────────────────
    # Track A, Phase A2/A3: reject any op-bearing transaction before this
    # height, so the multi-asset cutover is a deliberate, coordinated event
    # rather than something that could activate by surprise the moment this
    # code merely ships. REAL VALUE CHOSEN 2026-07-14 with the user: the
    # live chain was at height 40, user picked "current + 50" -> 90. Every
    # phase (A1-A7) was built, unit-tested, AND live-network-tested
    # (test_live_network.py, real multi-node HTTP) before this was set —
    # see docs/07-onchain-dex-plan.md in the trading-platform repo for the
    # full plan this activates. From block 90 onward, op-bearing
    # transactions (multi-asset transfers, the stOCN liquid-staking pool,
    # the OCN:stOCN AMM pool) are accepted; before it, rejected, exactly
    # as they always were.
    TX_SCHEMA_ACTIVATION_HEIGHT = 90

    # Recognized ops — never an open "anything goes" op namespace.
    KNOWN_OPS = {
        "transfer_asset", "stake_pool_deposit", "stake_pool_withdraw",
        "pool_add_liquidity", "pool_swap", "pool_remove_liquidity",
    }

    # AMM swap-fee cut, taken from the INPUT side of every swap (same
    # convention Uniswap V2 uses) — a fixed integer ratio (997/1000 = 0.3%
    # fee), never a float, so the exact same output is reproducible on
    # every node regardless of platform, the same "no float in a
    # consensus-relevant calculation" discipline as everywhere else in this
    # file. The 0.3% fee accrues directly to the pool's reserves (nobody
    # separately collects it) — it's what pays existing LPs for providing
    # liquidity, same as every real constant-product AMM.
    POOL_SWAP_FEE_NUMERATOR = 997
    POOL_SWAP_FEE_DENOMINATOR = 1000

    # Protocol-recognized liquid-staking pool address (Track A, Phase A4) —
    # a plain SHA-256 hash, deterministic and identical on every node, that
    # no real ECDSA keypair can ever match (finding a private key whose
    # public key hashes to a CHOSEN value is exactly as hard as breaking
    # SHA-256 itself). That's what makes this pool genuinely keyless: it can
    # accumulate deposits and receive staking rewards with no private key
    # existing for it anywhere, because blocks on this chain were never
    # signed by their staker/miner in the first place — a PoS block's
    # validity depends only on kernel-hash math against the staker
    # address's BALANCE (see compute_stake_kernel_hash /
    # _validate_stake_proof), never a signature proving ownership of that
    # address. Any node can run `python node.py --stake <this address>` and
    # legitimately produce real staked blocks crediting this pool, exactly
    # the same way it would for a real user's own address. This is a
    # materially safer design than docs/07-onchain-dex-plan.md's original
    # assumption (written without the real staking code checked out) that a
    # server-held operator signing key would be required — there is no key
    # to protect, lose, or leak, because nothing here is keyed at all.
    STAKE_POOL_ADDRESS = hashlib.sha256(b"STAKE_POOL:OCN").hexdigest()[:40]

    @staticmethod
    def _pool_key(asset_a, asset_b):
        """Canonical, order-independent identifier for an asset pair's AMM
        pool — assets sorted so a pool for (OCN, TEST) and (TEST, OCN) are
        the same pool, never two different ones by accident."""
        a, b = sorted([asset_a, asset_b])
        return f"{a}:{b}"

    @staticmethod
    def _pool_address(pool_key):
        """Protocol-recognized AMM pool address (Track A, Phase A5) — same
        keyless design as STAKE_POOL_ADDRESS above: a plain SHA-256 hash no
        real keypair can ever match, so a pool can accumulate reserves with
        no private key existing for it anywhere. Swap/liquidity credits are
        protocol-computed (every node independently re-derives the same
        constant-product math from the same prior reserves), never
        separately signed — the same trust model this chain already
        applies to mining/staking rewards, just extended to AMM pools."""
        return hashlib.sha256(f"POOL:{pool_key}".encode()).hexdigest()[:40]

    @staticmethod
    def _lp_asset_id(pool_key):
        return f"LP:{pool_key}"

    @staticmethod
    def _validate_pool_key(pool_key):
        if not isinstance(pool_key, str) or pool_key.count(":") != 1:
            raise ValueError("op_data.pool_key must be a string of the form 'asset_a:asset_b'")
        asset_a, asset_b = pool_key.split(":")
        if not asset_a or not asset_b:
            raise ValueError("pool_key assets must both be non-empty")
        if asset_a == asset_b:
            raise ValueError("a pool cannot pair an asset with itself")
        if [asset_a, asset_b] != sorted([asset_a, asset_b]):
            raise ValueError(f"pool_key must be in canonical sorted order: '{Blockchain._pool_key(asset_a, asset_b)}'")

    @staticmethod
    def _asset_id_of(tx):
        """The asset a plain transfer or transfer_asset op moves — "OCN" by
        default (every transaction that existed before Phase A2), or
        whatever transfer_asset's op_data names. The stake-pool ops handle
        their own OCN/stOCN accounting directly inside
        _apply_transaction_to_balance_dict and never reach this function."""
        if tx.op == "transfer_asset" and tx.op_data:
            return tx.op_data.get("asset_id", "OCN")
        return "OCN"

    @staticmethod
    def _validate_op(tx):
        """Structural validation of an op-bearing transaction — raises
        ValueError with a human-readable reason, same convention as
        add_transaction. Called from both add_transaction (mempool gate) and
        accept_block/is_chain_valid (block gate) so a malformed op can never
        reach the chain by skipping mempool admission (e.g. a block
        submitted directly by a miner/peer)."""
        if tx.op not in Blockchain.KNOWN_OPS:
            raise ValueError(f"Unknown transaction op: {tx.op}")
        # A list or string here would raise AttributeError from the .get()
        # calls below -- not the ValueError every caller treats as "reject"
        # -- and take the request, or a peer's chain check, down with it.
        if tx.op_data is not None and not isinstance(tx.op_data, dict):
            raise ValueError("op_data must be an object")
        if tx.op == "transfer_asset":
            asset_id = (tx.op_data or {}).get("asset_id") if tx.op_data else None
            if not isinstance(asset_id, str) or not asset_id:
                raise ValueError("transfer_asset requires op_data.asset_id (non-empty string)")
            if asset_id == "OCN":
                raise ValueError('transfer_asset cannot move "OCN" — use a plain transfer (op=None) for OCN itself')
            if tx.amount <= 0:
                raise ValueError("transfer_asset requires amount > 0")
        elif tx.op == "stake_pool_deposit":
            if tx.recipient != Blockchain.STAKE_POOL_ADDRESS:
                raise ValueError(f"stake_pool_deposit must send to the pool address ({Blockchain.STAKE_POOL_ADDRESS}), not {tx.recipient}")
            if tx.amount <= 0:
                raise ValueError("stake_pool_deposit requires amount > 0")
        elif tx.op == "stake_pool_withdraw":
            if tx.recipient != tx.sender:
                raise ValueError("stake_pool_withdraw redeems to the sender's own address — recipient must equal sender")
            if tx.amount <= 0:
                raise ValueError("stake_pool_withdraw requires amount > 0 (the stOCN amount being redeemed)")
        elif tx.op == "pool_add_liquidity":
            pool_key = (tx.op_data or {}).get("pool_key")
            Blockchain._validate_pool_key(pool_key)
            if tx.recipient != Blockchain._pool_address(pool_key):
                raise ValueError("pool_add_liquidity must send to the pool's own derived address")
            amount_a = (tx.op_data or {}).get("amount_a")
            amount_b = (tx.op_data or {}).get("amount_b")
            if not is_real_number(amount_a) or amount_a <= 0:
                raise ValueError("pool_add_liquidity requires op_data.amount_a > 0")
            if not is_real_number(amount_b) or amount_b <= 0:
                raise ValueError("pool_add_liquidity requires op_data.amount_b > 0")
        elif tx.op == "pool_swap":
            pool_key = (tx.op_data or {}).get("pool_key")
            Blockchain._validate_pool_key(pool_key)
            asset_a, asset_b = pool_key.split(":")
            asset_in = (tx.op_data or {}).get("asset_in")
            if asset_in not in (asset_a, asset_b):
                raise ValueError(f"pool_swap op_data.asset_in must be one of the pool's two assets ({asset_a}, {asset_b})")
            amount_in = (tx.op_data or {}).get("amount_in")
            if not is_real_number(amount_in) or amount_in <= 0:
                raise ValueError("pool_swap requires op_data.amount_in > 0")
            min_amount_out = (tx.op_data or {}).get("min_amount_out", 0)
            if not is_real_number(min_amount_out) or min_amount_out < 0:
                raise ValueError("pool_swap op_data.min_amount_out must be a number >= 0")
            if tx.recipient != tx.sender:
                raise ValueError("pool_swap redeems to the sender's own address — recipient must equal sender")
        elif tx.op == "pool_remove_liquidity":
            pool_key = (tx.op_data or {}).get("pool_key")
            Blockchain._validate_pool_key(pool_key)
            lp_amount = (tx.op_data or {}).get("lp_amount")
            if not is_real_number(lp_amount) or lp_amount <= 0:
                raise ValueError("pool_remove_liquidity requires op_data.lp_amount > 0")
            if tx.recipient != tx.sender:
                raise ValueError("pool_remove_liquidity redeems to the sender's own address — recipient must equal sender")

    @staticmethod
    def _stake_pool_exchange_rate(balances, asset_supply):
        """OCN-per-stOCN, Lido-style rebasing: starts at 1.0 (empty pool —
        the first depositor mints 1:1) and rises as the pool's OCN balance
        grows from staking rewards while stOCN supply stays fixed between
        deposits/withdrawals. A pure function of (balances, asset_supply),
        exactly as independently re-derivable by every node as everything
        else in this file — never a separately-signed or separately-stored
        number. Balances are in units, so this is a ratio of units, the
        same ratio as of coins."""
        stocn_supply = asset_supply.get("stOCN", 0)
        if stocn_supply <= 0:
            return 1.0
        pool_ocn = balances.get((Blockchain.STAKE_POOL_ADDRESS, "OCN"), 0)
        return pool_ocn / stocn_supply

    def stake_pool_status(self):
        """Read-only snapshot for node.py's /stake_pool/status — current
        exchange rate (OCN redeemable per stOCN), total OCN actually staked
        in the pool, and total stOCN in circulation. Always derived from
        the live self.balances/self.asset_supply index, never separately
        tracked/stored."""
        return {
            "pool_address": self.STAKE_POOL_ADDRESS,
            "exchange_rate": self._stake_pool_exchange_rate(self.balances, self.asset_supply),
            "total_staked_ocn": to_coins(self.balances.get((self.STAKE_POOL_ADDRESS, "OCN"), 0)),
            "total_stocn_supply": to_coins(self.asset_supply.get("stOCN", 0)),
        }

    def list_pools(self):
        """Every pool_key that has ever had liquidity added — derived from
        self.asset_supply's "LP:" keys (an "LP:{pool_key}" asset only ever
        exists once pool_add_liquidity has minted some of it at least once)
        rather than a separate tracked set, since this implementation
        deliberately skipped a standalone pool_create op (see
        test_amm_pools.py's module docstring): a pool has no meaningful
        state to "exist" ahead of its first real liquidity deposit."""
        return sorted(asset_id[len("LP:"):] for asset_id in self.asset_supply if asset_id.startswith("LP:"))

    def pool_status(self, pool_key):
        """Read-only snapshot for node.py's /pools/<id> — reserves, LP
        supply, and derived spot price for one AMM pool. Always derived
        from the live self.balances/self.asset_supply index, same as
        stake_pool_status above; returns zeros for a pool_key nobody has
        ever added liquidity to rather than raising, so callers can use
        this to check "does this pool have anything in it yet"."""
        self._validate_pool_key(pool_key)
        asset_a, asset_b = pool_key.split(":")
        pool_addr = self._pool_address(pool_key)
        lp_asset = self._lp_asset_id(pool_key)
        reserve_a = to_coins(self.balances.get((pool_addr, asset_a), 0))
        reserve_b = to_coins(self.balances.get((pool_addr, asset_b), 0))
        return {
            "pool_key": pool_key,
            "pool_address": pool_addr,
            "asset_a": asset_a, "reserve_a": reserve_a,
            "asset_b": asset_b, "reserve_b": reserve_b,
            "lp_asset": lp_asset,
            "lp_supply": to_coins(self.asset_supply.get(lp_asset, 0)),
            "price_a_in_b": (reserve_b / reserve_a) if reserve_a > 0 else None,
            "price_b_in_a": (reserve_a / reserve_b) if reserve_b > 0 else None,
        }

    def stake_pool_history(self):
        """Time series of the liquid-staking pool's state at every block
        that CHANGED it — replayed from the chain itself (the same
        _apply_transaction_to_balance_dict math the live index uses), never
        separately stored, so it's as trustlessly re-derivable as any other
        read in this file. Read-only analytics for node.py — zero effect on
        consensus. Snapshots only on change (deposits/withdrawals/rewards
        landing in the pool), not every block, so the payload stays small
        no matter how long the chain gets between pool events."""
        history = []
        balances, asset_supply = {}, {}
        pool_ocn_key = (self.STAKE_POOL_ADDRESS, "OCN")
        # Seeded with the empty-pool state (not None) so the leading run of
        # blocks from before the pool ever saw activity contributes zero
        # points instead of one meaningless all-zero snapshot at genesis.
        last = (0, 0)
        for block in self.chain:
            for tx in block.transactions:
                self._apply_transaction_to_balance_dict(balances, tx, asset_supply, height=block.index)
            snapshot = (balances.get(pool_ocn_key, 0), asset_supply.get("stOCN", 0))
            if snapshot != last:
                last = snapshot
                history.append({
                    "height": block.index,
                    "timestamp": block.timestamp,
                    "total_staked_ocn": to_coins(snapshot[0]),
                    "total_stocn_supply": to_coins(snapshot[1]),
                    "exchange_rate": self._stake_pool_exchange_rate(balances, asset_supply),
                })
        return history

    def pool_history(self, pool_key):
        """Same idea as stake_pool_history, for one AMM pool: reserves/
        price/LP-supply at every block that changed them, plus that block's
        swap volume (sum of amount_in across its pool_swap ops for this
        pool — the number a volume chart wants). Replayed from the chain,
        read-only, no consensus effect."""
        self._validate_pool_key(pool_key)
        asset_a, asset_b = pool_key.split(":")
        pool_addr = self._pool_address(pool_key)
        lp_asset = self._lp_asset_id(pool_key)
        history = []
        balances, asset_supply = {}, {}
        last = (0, 0, 0)  # same empty-state seeding as stake_pool_history
        for block in self.chain:
            swap_volume = 0
            for tx in block.transactions:
                if tx.op == "pool_swap" and (tx.op_data or {}).get("pool_key") == pool_key:
                    swap_volume += (tx.op_data or {}).get("amount_in", 0)
                self._apply_transaction_to_balance_dict(balances, tx, asset_supply, height=block.index)
            snapshot = (balances.get((pool_addr, asset_a), 0), balances.get((pool_addr, asset_b), 0), asset_supply.get(lp_asset, 0))
            if snapshot != last:
                last = snapshot
                reserve_a, reserve_b, lp_supply = (to_coins(u) for u in snapshot)
                history.append({
                    "height": block.index,
                    "timestamp": block.timestamp,
                    "reserve_a": reserve_a, "reserve_b": reserve_b,
                    "lp_supply": lp_supply,
                    "price_a_in_b": (reserve_b / reserve_a) if reserve_a > 0 else None,
                    "swap_volume_in": swap_volume,
                })
        return history

    @classmethod
    def _apply_transaction_to_balance_dict(cls, balances, tx, asset_supply, *, height):
        """The one place transaction accounting actually happens, for every
        transaction/op kind this chain knows about. Operates on passed-in
        dicts rather than self.balances/self.asset_supply directly so it can
        be reused both for the real index (_rebuild_balance_index/
        accept_block) and for throwaway local/scratch dicts (get_balance's
        explicit chain= scan, the from-scratch candidate-chain walk,
        add_transaction's pending-mempool preview) without duplicating this
        logic anywhere and risking the copies drifting apart.

        Every balance and supply here is a whole number of UNITS (1 coin =
        UNITS_PER_COIN units, as Bitcoin counts satoshis), since 2026-09-30.
        Decimal fractions cannot be added exactly in binary floating point, so
        a float ledger drifts by specks, a whole balance can land a hair below
        zero, and "can this sender afford it" needed a tolerance. Integers add
        exactly. Transactions still CARRY decimal amounts, exactly as they are
        signed; each one is converted to units once, here, by to_units.

        `height` is the block the transaction is in (or would be in). It
        selects the pool formulas: below INTEGER_UNITS_ACTIVATION_HEIGHT the
        original floating-point formulas, reproducing every historical pool
        result exactly; from it on, integer formulas that round in the
        pool's favour and can never pay out more than a reserve holds.

        Returns the list of (address, asset_id) balance keys this call
        DEBITED (subtracted from) — callers doing balance-sufficiency checks
        use this to verify none of them went negative, without needing their
        own per-op knowledge of what gets debited by what."""
        exact = height >= cls.INTEGER_UNITS_ACTIVATION_HEIGHT
        debited = []

        def debit(key, units):
            balances[key] = balances.get(key, 0) - units
            debited.append(key)

        def credit(key, units):
            balances[key] = balances.get(key, 0) + units

        fee_u = to_units(tx.fee)
        if tx.op == "stake_pool_deposit":
            # Rate from state BEFORE this deposit's own effects, so every node
            # computes the identical mint. OCN-per-stOCN: as the pool earns
            # rewards each stOCN redeems for more OCN, so a deposit mints
            # fewer stOCN -- divide OCN by the rate.
            amount_u = to_units(tx.amount)
            pool_u = balances.get((cls.STAKE_POOL_ADDRESS, "OCN"), 0)
            supply_u = asset_supply.get("stOCN", 0)
            if exact:
                minted_u = amount_u * supply_u // pool_u if supply_u > 0 and pool_u > 0 else amount_u
            else:
                rate = cls._stake_pool_exchange_rate(balances, asset_supply)
                minted_u = to_units(round(tx.amount / rate, 6) if rate > 0 else tx.amount)
            if tx.sender != "0":
                debit((tx.sender, "OCN"), amount_u + fee_u)
            credit((tx.recipient, "OCN"), amount_u)  # tx.recipient == STAKE_POOL_ADDRESS, enforced by _validate_op
            credit((tx.sender, "stOCN"), minted_u)
            asset_supply["stOCN"] = asset_supply.get("stOCN", 0) + minted_u
            return debited
        if tx.op == "stake_pool_withdraw":
            # Inverse of the deposit: redeeming stOCN at OCN-per-stOCN gives
            # back that many OCN -- multiply.
            amount_u = to_units(tx.amount)
            pool_u = balances.get((cls.STAKE_POOL_ADDRESS, "OCN"), 0)
            supply_u = asset_supply.get("stOCN", 0)
            if exact:
                redeemed_u = amount_u * pool_u // supply_u if supply_u > 0 else amount_u
            else:
                rate = cls._stake_pool_exchange_rate(balances, asset_supply)
                redeemed_u = to_units(round(tx.amount * rate, 6))
            debit((tx.sender, "stOCN"), amount_u)
            asset_supply["stOCN"] = asset_supply.get("stOCN", 0) - amount_u
            if tx.sender != "0":
                debit((tx.sender, "OCN"), fee_u)
            debit((cls.STAKE_POOL_ADDRESS, "OCN"), redeemed_u)
            credit((tx.recipient, "OCN"), redeemed_u)  # tx.recipient == tx.sender, enforced by _validate_op
            return debited
        if tx.op == "pool_add_liquidity":
            pool_key = tx.op_data["pool_key"]
            asset_a, asset_b = pool_key.split(":")
            amount_a, amount_b = tx.op_data["amount_a"], tx.op_data["amount_b"]
            a_u, b_u = to_units(amount_a), to_units(amount_b)
            pool_addr = cls._pool_address(pool_key)
            lp_asset = cls._lp_asset_id(pool_key)
            reserve_a_u = balances.get((pool_addr, asset_a), 0)
            reserve_b_u = balances.get((pool_addr, asset_b), 0)
            lp_supply_u = asset_supply.get(lp_asset, 0)
            bootstrap = lp_supply_u <= 0 or reserve_a_u <= 0 or reserve_b_u <= 0
            if exact:
                # Uniswap V2's formulas in whole units: the first deposit
                # mints sqrt(a*b) (sqrt of units*units is units), later ones
                # the SMALLER of the two proportional shares, rounded down.
                if bootstrap:
                    minted_lp_u = math.isqrt(a_u * b_u)
                else:
                    minted_lp_u = min(a_u * lp_supply_u // reserve_a_u, b_u * lp_supply_u // reserve_b_u)
            elif bootstrap:
                # IEEE 754 requires sqrt to be correctly rounded, so this is
                # identical on every conformant platform, like division.
                minted_lp_u = to_units(round((amount_a * amount_b) ** 0.5, 6))
            else:
                reserve_a, reserve_b, lp_supply = to_coins(reserve_a_u), to_coins(reserve_b_u), to_coins(lp_supply_u)
                minted_lp_u = to_units(round(min(amount_a / reserve_a, amount_b / reserve_b) * lp_supply, 6))
            if tx.sender != "0":
                debit((tx.sender, "OCN"), fee_u)
                debit((tx.sender, asset_a), a_u)
                debit((tx.sender, asset_b), b_u)
            credit((pool_addr, asset_a), a_u)
            credit((pool_addr, asset_b), b_u)
            credit((tx.sender, lp_asset), minted_lp_u)
            asset_supply[lp_asset] = asset_supply.get(lp_asset, 0) + minted_lp_u
            return debited
        if tx.op == "pool_swap":
            pool_key = tx.op_data["pool_key"]
            asset_a, asset_b = pool_key.split(":")
            asset_in = tx.op_data["asset_in"]
            asset_out = asset_b if asset_in == asset_a else asset_a
            amount_in = tx.op_data["amount_in"]
            min_amount_out = tx.op_data.get("min_amount_out", 0)
            in_u = to_units(amount_in)
            pool_addr = cls._pool_address(pool_key)
            reserve_in_u = balances.get((pool_addr, asset_in), 0)
            reserve_out_u = balances.get((pool_addr, asset_out), 0)
            # Constant product x*y=k with a 0.3% input-side fee (see
            # POOL_SWAP_FEE_NUMERATOR/DENOMINATOR).
            if exact:
                in_after_fee = in_u * cls.POOL_SWAP_FEE_NUMERATOR
                denominator = reserve_in_u * cls.POOL_SWAP_FEE_DENOMINATOR + in_after_fee
                out_u = in_after_fee * reserve_out_u // denominator if denominator > 0 else 0
            else:
                reserve_in, reserve_out = to_coins(reserve_in_u), to_coins(reserve_out_u)
                amount_in_after_fee = amount_in * cls.POOL_SWAP_FEE_NUMERATOR
                denominator = reserve_in * cls.POOL_SWAP_FEE_DENOMINATOR + amount_in_after_fee
                out_u = to_units(round((amount_in_after_fee * reserve_out) / denominator, 6) if denominator > 0 else 0)
            if out_u < to_units(min_amount_out):
                # State-dependent slippage failure — _validate_op only sees
                # the transaction, never chain state, so this is the one op
                # that can make this accounting function raise. Every caller
                # treats a ValueError here as the transaction/block rejected.
                raise ValueError(f"pool_swap would output {to_coins(out_u)} {asset_out}, below min_amount_out {min_amount_out} (slippage)")
            if tx.sender != "0":
                debit((tx.sender, "OCN"), fee_u)
                debit((tx.sender, asset_in), in_u)
            credit((pool_addr, asset_in), in_u)
            debit((pool_addr, asset_out), out_u)  # the pool's reserve must never go negative either
            credit((tx.recipient, asset_out), out_u)  # tx.recipient == tx.sender, enforced by _validate_op
            return debited
        if tx.op == "pool_remove_liquidity":
            pool_key = tx.op_data["pool_key"]
            asset_a, asset_b = pool_key.split(":")
            lp_amount = tx.op_data["lp_amount"]
            lp_u = to_units(lp_amount)
            pool_addr = cls._pool_address(pool_key)
            lp_asset = cls._lp_asset_id(pool_key)
            lp_supply_u = asset_supply.get(lp_asset, 0)
            reserve_a_u = balances.get((pool_addr, asset_a), 0)
            reserve_b_u = balances.get((pool_addr, asset_b), 0)
            if exact:
                # Rounded down, so the last provider out can never be owed
                # more than the reserve holds.
                out_a_u = reserve_a_u * lp_u // lp_supply_u if lp_supply_u > 0 else 0
                out_b_u = reserve_b_u * lp_u // lp_supply_u if lp_supply_u > 0 else 0
            else:
                share = (lp_amount / to_coins(lp_supply_u)) if lp_supply_u > 0 else 0
                out_a_u = to_units(round(to_coins(reserve_a_u) * share, 6))
                out_b_u = to_units(round(to_coins(reserve_b_u) * share, 6))
            debit((tx.sender, lp_asset), lp_u)
            asset_supply[lp_asset] = asset_supply.get(lp_asset, 0) - lp_u
            if tx.sender != "0":
                debit((tx.sender, "OCN"), fee_u)
            debit((pool_addr, asset_a), out_a_u)
            debit((pool_addr, asset_b), out_b_u)
            credit((tx.recipient, asset_a), out_a_u)  # tx.recipient == tx.sender, enforced by _validate_op
            credit((tx.recipient, asset_b), out_b_u)
            return debited
        # Plain transfer (op=None) or transfer_asset: the sender pays amount
        # plus fee when the moved asset IS OCN, otherwise the fee in OCN and
        # the amount in the asset; the recipient gains the amount.
        asset_id = cls._asset_id_of(tx)
        amount_u = to_units(tx.amount)
        if tx.sender != "0":
            if asset_id == "OCN":
                debit((tx.sender, "OCN"), amount_u + fee_u)
            else:
                debit((tx.sender, "OCN"), fee_u)
                debit((tx.sender, asset_id), amount_u)
        credit((tx.recipient, asset_id), amount_u)
        return debited

    def _apply_transaction_to_balances(self, tx, height):
        self._apply_transaction_to_balance_dict(self.balances, tx, self.asset_supply, height=height)

    def _rebuild_balance_index(self):
        """Full walk of self.chain, recomputing every address's balance
        (across every asset_id seen) AND every non-OCN asset's total
        circulating supply from scratch, in units. Called whenever self.chain
        is replaced WHOLESALE — genesis creation, load_chain() adopting the
        startup chain, replace_chain() swapping in a candidate — as opposed
        to growing by one block, which accept_block updates incrementally
        instead (see _apply_transaction_to_balances)."""
        self.balances = {}
        self.asset_supply = {}
        for block in self.chain:
            for tx in block.transactions:
                self._apply_transaction_to_balances(tx, block.index)

    def get_balance_units(self, address, asset_id="OCN", include_pending=False, chain=None):
        """Balance of one (address, asset_id) pair, in whole units. No
        balance table exists anywhere — a balance is always *derived* from
        transaction history, so there's nothing else to trust or that could
        get out of sync.

        An explicit `chain` is scanned from scratch (a candidate chain must
        be judged by ITS OWN history, never this instance's index); every
        other caller gets the O(1) indexed lookup. Both funnel through
        _apply_transaction_to_balance_dict so they can never disagree."""
        if chain is not None:
            local, local_supply = {}, {}
            for block in chain:
                for tx in block.transactions:
                    self._apply_transaction_to_balance_dict(local, tx, local_supply, height=block.index)
            balance = local.get((address, asset_id), 0)
        else:
            balance = self.balances.get((address, asset_id), 0)
        if include_pending:
            pending_local, pending_supply = {}, {}
            next_height = self.latest_block.index + 1
            for tx in self.mempool:
                self._apply_transaction_to_balance_dict(pending_local, tx, pending_supply, height=next_height)
            balance += pending_local.get((address, asset_id), 0)
        return balance

    def get_balance(self, address, asset_id="OCN", include_pending=False, chain=None):
        """The same balance in coins, for display and the HTTP API, which
        have always spoken in coins. Consensus checks use get_balance_units."""
        return to_coins(self.get_balance_units(address, asset_id, include_pending, chain))

    def add_transaction(self, tx: Transaction):
        """Raises ValueError with a human-readable reason on rejection —
        callers (the HTTP API) turn that straight into an error response."""
        if not tx.is_valid():
            raise ValueError("Transaction signature is invalid (or fee is below the network minimum)")
        if tx.op is not None:
            if (self.latest_block.index + 1) < self.TX_SCHEMA_ACTIVATION_HEIGHT:
                raise ValueError(f"op-bearing transactions are not active until block {self.TX_SCHEMA_ACTIVATION_HEIGHT}")
            self._validate_op(tx)
        # Replay/double-inclusion guard: a signed transaction's hash is
        # fully deterministic from its own fields (see
        # Transaction.to_signing_string) — nothing about a signature
        # limits it to being honored only ONCE, the way a UTXO (Bitcoin)
        # or an account nonce (Ethereum) would. Without this check, the
        # exact same already-broadcast, already-signed transaction could
        # be resubmitted (by anyone, not just the original sender — it's
        # public once broadcast) and mined again, debiting the sender and
        # crediting the recipient a second time for one authorization
        # the sender only actually signed once. Caught for real during
        # this project's own end-to-end testing, not theoretical.
        if any(tx.hash() == pending.hash() for pending in self.mempool):
            raise ValueError("Transaction already pending (resubmitting an identical signed transaction doesn't authorize it a second time)")
        if any(tx.hash() == t.hash() for block in self.chain for t in block.transactions):
            raise ValueError("Transaction already confirmed on-chain (a signed transaction can only ever be honored once)")
        if tx.sender != "0":
            # Checks against balance MINUS whatever's already pending in the
            # mempool from this same sender — otherwise someone could submit
            # two transactions spending the same coins twice before either
            # one is actually mined (a real double-spend, the exact problem
            # proof-of-work chains exist to solve for confirmed blocks —
            # this closes the same gap one step earlier, at mempool-
            # acceptance time). Generic across every op: preview confirmed +
            # already-pending + this new tx on a throwaway copy, then check
            # every balance bucket THIS tx itself debited didn't go negative
            # — the same "apply on a scratch copy, then check what got
            # debited" pattern accept_block/is_chain_valid use for their own
            # block-level version of this check, so there's exactly one
            # place that knows what each op debits, not three.
            next_height = self.latest_block.index + 1
            self._validate_unit_precision(tx, next_height)
            preview_balances = dict(self.balances)
            preview_supply = dict(self.asset_supply)
            for pending in self.mempool:
                self._apply_transaction_to_balance_dict(preview_balances, pending, preview_supply, height=next_height)
            debited_keys = self._apply_transaction_to_balance_dict(preview_balances, tx, preview_supply, height=next_height)
            for key in debited_keys:
                if preview_balances.get(key, 0) < 0:
                    addr, asset = key
                    raise ValueError(f"Insufficient {asset} balance: {addr} would go to {to_coins(preview_balances[key])}")
        # Bounded mempool (see MEMPOOL_MAX): when full, only accept a new tx if
        # it outbids the cheapest pending one, then evict that cheapest. Keeps
        # the now-public submission endpoint from being an unbounded-growth DoS
        # while preserving fee priority.
        if len(self.mempool) >= self.MEMPOOL_MAX:
            cheapest = min(self.mempool, key=lambda t: t.fee)
            if tx.fee <= cheapest.fee:
                raise ValueError(f"Mempool is full ({self.MEMPOOL_MAX} pending); fee {tx.fee} does not beat the lowest pending fee {cheapest.fee}")
            self.mempool.remove(cheapest)
        self.mempool.append(tx)
        return tx.hash()

    def _select_includable(self, max_transactions):
        """Which pending transactions a new block can carry, in the order it
        must carry them. Highest fee first, but only a transaction that
        applies cleanly ON TOP OF the ones already chosen -- the same in-order
        check accept_block now makes. The mempool admits a spend of coins
        that are themselves still pending (it previews every pending tx in
        arrival order), and pure fee order could put that spend AHEAD of the
        transfer paying for it; the block would then fail its own node's
        check and every template after it would too, because the tx never
        leaves the mempool. So a tx that cannot apply yet is retried after
        the rest (its funding may come later in the same pass), and one that
        still cannot is left out -- of this block, not of the mempool.
        Coinbase is not counted as funding: conservative, and it keeps the
        choice independent of who is paid."""
        from collections import ChainMap
        height = self.latest_block.index + 1
        balances, supply = dict(self.balances), dict(self.asset_supply)
        pending = sorted(self.mempool, key=lambda t: t.fee, reverse=True)
        chosen = []
        progress = True
        while progress and pending and len(chosen) < max_transactions:
            progress, deferred = False, []
            for tx in pending:
                if len(chosen) >= max_transactions:
                    break
                trial_b, trial_s = ChainMap({}, balances), ChainMap({}, supply)
                try:
                    if tx.op is not None:
                        self._validate_op(tx)
                    self._validate_unit_precision(tx, height)
                    debited = self._apply_transaction_to_balance_dict(trial_b, tx, trial_s, height=height)
                except ValueError:
                    deferred.append(tx)
                    continue
                if any(trial_b.get(k, 0) < 0 for k in debited):
                    deferred.append(tx)
                    continue
                balances.update(trial_b.maps[0])
                supply.update(trial_s.maps[0])
                chosen.append(tx)
                progress = True
            pending = deferred
        return chosen

    # ── Mining ───────────────────────────────────────────────────────
    def build_candidate_block(self, miner_address, max_transactions=50):
        """A 'block template' — everything a miner needs to start
        searching for a valid nonce, EXCEPT the nonce itself. Mirrors
        get_mining_template()'s job on the HTTP API side; kept here too
        so the node can also mine its own blocks directly (used by
        /mine and local testing).

        Highest-fee-first (the "efficient" lever): with limited space per
        block, sorting the mempool by fee descending before truncating to
        max_transactions means paying a bit more is what actually buys
        priority, same as every real fee market — instead of strictly
        first-in-first-out, which has no way to express "this one's more
        urgent to me."

        The coinbase transaction pays the miner the base reward PLUS
        every fee from the transactions actually included — exactly how
        real chains incentivize miners to keep including transactions
        even as the block reward itself shrinks over a chain's lifetime.
        """
        included = self._select_includable(max_transactions)
        # Summed in units so the coinbase is exactly reward + fees (a float
        # sum of decimals can land a speck off; see _check_coinbase).
        total_u = to_units(self.reward_at_height(self.latest_block.index + 1)) + sum(to_units(t.fee) for t in included)
        reward_tx = Transaction(sender="0", recipient=miner_address, amount=to_coins(total_u), fee=0)
        return Block(
            index=self.latest_block.index + 1,
            transactions=[reward_tx] + included,
            previous_hash=self.latest_block.compute_hash(),
            target=self.current_target,
        )

    def build_pool_block(self, shares: dict, max_transactions=50):
        """Same idea as build_candidate_block, except the single coinbase
        transaction becomes one PER contributing address, each paid
        proportional to how many shares (near-miss proofs of real work —
        see node.py's pool endpoints) they submitted, instead of the
        entire reward going to whoever happened to find the one winning
        nonce. `shares` is {address: share_count} and must be non-empty —
        it is deliberately NOT based on shares submitted *during* the
        round this block belongs to (that would be circular: the payout
        has to be baked into the coinbase, hence the merkle root, before
        any miner can start searching for this exact block's nonce).
        node.py instead calls this with the *previous* round's completed
        share tally — the same "pay based on already-closed work" fix
        real mining pools use (PPLNS-style), which is what makes it safe
        to fix the payout list before mining begins.

        Integer division, in units, leaves a small remainder (the reward
        doesn't always divide evenly across contributors) — that dust goes to
        whichever address contributed the most shares, a simple
        deterministic tie-break rather than trying to split fractional
        units perfectly."""
        if not shares:
            raise ValueError("build_pool_block requires a non-empty shares tally")
        included = self._select_includable(max_transactions)
        total_u = to_units(self.reward_at_height(self.latest_block.index + 1)) + sum(to_units(t.fee) for t in included)
        total_shares = sum(shares.values())
        reward_txs = []
        distributed_u = 0
        for address, count in shares.items():
            cut_u = (total_u * count) // total_shares if total_shares else 0
            if cut_u > 0:
                reward_txs.append(Transaction(sender="0", recipient=address, amount=to_coins(cut_u), fee=0))
                distributed_u += cut_u
        remainder_u = total_u - distributed_u
        if remainder_u > 0:
            top_address = max(sorted(shares.keys()), key=lambda a: shares[a])
            # top_address may already have a reward_tx above — a second
            # small coinbase tx to the same address is completely valid,
            # nothing requires coinbase recipients to be unique.
            reward_txs.append(Transaction(sender="0", recipient=top_address, amount=to_coins(remainder_u), fee=0))
        return Block(
            index=self.latest_block.index + 1,
            transactions=reward_txs + included,
            previous_hash=self.latest_block.compute_hash(),
            target=self.current_target,
        )

    def mine_block(self, miner_address, max_transactions=50):
        """Does the actual proof-of-work search itself, in-process — used
        for local testing and by the standalone Python REPL. The real
        miner (miner.py) does this same search OUTSIDE the node process
        (mirroring Speepcoin's miner.js) and submits a finished block via
        the HTTP API instead, so mining work can run on a different
        machine than the node itself."""
        block = self.build_candidate_block(miner_address, max_transactions)
        block = proof_of_work(block)
        self.accept_block(block)
        return block

    def stake_weight_of(self, address, chain=None):
        """An address's staking power — its current confirmed balance,
        floored to a whole coin (see the class docstring above
        POS_MAX_TARGET for why: avoiding float in a consensus-relevant
        weight, same reasoning as everywhere else in this file).
        Splitting one balance across many addresses doesn't increase
        total success odds — probability scales linearly with weight, so
        N addresses each holding 1/N of a balance have exactly the same
        combined chance as one address holding all of it. That's what
        makes stake weight Sybil-resistant the same way hashpower is."""
        return self.get_balance_units(address, chain=chain) // UNITS_PER_COIN

    def build_stake_block(self, staker_address, max_transactions=50):
        """A PoS 'block template' — everything try_stake needs except
        the actual kernel check against the current second. Mirrors
        build_candidate_block, with two differences: it's paid at
        POS_REWARD_FRACTION of the normal reward (see that constant's
        docstring), and target here is pos_target, not current_target."""
        weight = self.stake_weight_of(staker_address)
        if weight < 1:
            raise ValueError(f"{staker_address} has no stakeable balance (needs at least 1 whole O-Coin)")
        included = self._select_includable(max_transactions)
        stake_reward = round(self.reward_at_height(self.latest_block.index + 1) * self.POS_REWARD_FRACTION, 6)
        total_u = to_units(stake_reward) + sum(to_units(t.fee) for t in included)
        reward_tx = Transaction(sender="0", recipient=staker_address, amount=to_coins(total_u), fee=0)
        return Block(
            index=self.latest_block.index + 1,
            transactions=[reward_tx] + included,
            previous_hash=self.latest_block.compute_hash(),
            target=self.pos_target,
            staker_address=staker_address,
        )

    def try_stake(self, staker_address, max_transactions=50):
        """One single kernel-check attempt, right now, for staker_address
        — call this roughly once per second (see node.py's staking
        thread) rather than in a tight loop; a second try before the
        wall clock has actually advanced to a new second recomputes the
        exact same kernel hash and can't possibly succeed where the
        first attempt didn't (see compute_stake_kernel_hash — there's no
        nonce to vary). Returns the accepted Block on success, None on a
        failed attempt (not an error — failing most seconds is normal
        and expected, same as failing most nonces is normal for PoW)."""
        block = self.build_stake_block(staker_address, max_transactions)
        weight = self.stake_weight_of(staker_address)
        kernel_int = int(block.compute_stake_kernel_hash(), 16)
        if kernel_int >= block.target * weight:
            return None
        self.accept_block(block)
        return block

    @staticmethod
    def _median_time(preceding_blocks):
        """Median timestamp of up to the last MEDIAN_TIME_WINDOW blocks
        BEFORE the one being validated. Median specifically (not "must be
        after the single immediately-previous block") because manipulating
        a median requires controlling a majority of the whole window, not
        just the one most recent block — the same reasoning Bitcoin's
        median-time-past rule uses."""
        window = preceding_blocks[-Blockchain.MEDIAN_TIME_WINDOW:]
        timestamps = sorted(b.timestamp for b in window)
        return timestamps[len(timestamps) // 2]

    def _validate_timestamp(self, block: Block, preceding_blocks):
        if block.timestamp > time.time() + self.MAX_FUTURE_DRIFT_SECONDS:
            raise ValueError("Block timestamp is too far in the future")
        if preceding_blocks and block.timestamp <= self._median_time(preceding_blocks):
            raise ValueError("Block timestamp is not after the median of recent block times (possible difficulty-retarget manipulation)")

    def _validate_stake_proof(self, block: Block):
        """PoS equivalent of the PoW target+meets_target() checks in
        accept_block below — called INSTEAD of them when
        block.staker_address is set. Weight is read from self.chain as
        it stands right now, i.e. BEFORE this candidate block is
        appended — a staker is judged on the balance they actually held
        at the moment they'd have needed to produce this block, not on
        anything this block itself pays them."""
        if block.target != self.pos_target:
            raise ValueError(f"Block was staked against a stale PoS difficulty target (expected {self.pos_target}, got {block.target})")
        weight = self.stake_weight_of(block.staker_address)
        if weight < 1:
            raise ValueError(f"{block.staker_address} has no stakeable balance to justify this block")
        kernel_int = int(block.compute_stake_kernel_hash(), 16)
        if kernel_int >= block.target * weight:
            raise ValueError("Stake kernel hash does not meet the PoS difficulty target for this staker's weight")

    def _check_block_balances(self, transactions, balances, asset_supply, height):
        """Applies a block's transactions IN ORDER to the passed-in dicts
        (the caller's throwaway copies) and raises ValueError the moment a
        signed transaction takes any balance it debits below zero. Shared by
        accept_block and _walk_chain so a block and a whole chain are judged
        by the same rule. Coinbase entries are applied too (a miner may
        spend its own reward later in the same block) but never judged:
        they debit nothing. Balances are whole units, so "below zero" is
        exact -- no tolerance for rounding, because there is none."""
        for tx in transactions:
            if tx.op is not None:
                self._validate_op(tx)
            self._validate_unit_precision(tx, height)
            debited_keys = self._apply_transaction_to_balance_dict(balances, tx, asset_supply, height=height)
            if tx.sender == "0":
                continue
            for key in debited_keys:
                if balances.get(key, 0) < 0:
                    addr, asset = key
                    raise ValueError(f"Block contains a transaction that would drive {addr}'s {asset} balance negative")

    @classmethod
    def _validate_unit_precision(cls, tx, height):
        """From INTEGER_UNITS_ACTIVATION_HEIGHT on, every quantity a signed
        transaction carries must be a whole number of units (at most 8
        decimal places), so what the sender signed is exactly what moves.
        Before it, a finer amount was simply rounded to the nearest unit.
        Coinbase entries are exempt: the node computes them, and
        _check_coinbase holds their sum exact in units instead."""
        if height < cls.INTEGER_UNITS_ACTIVATION_HEIGHT or tx.sender == "0":
            return
        quantities = [("amount", tx.amount), ("fee", tx.fee)]
        if isinstance(tx.op_data, dict):
            quantities += [(k, tx.op_data[k]) for k in cls.OP_QUANTITY_FIELDS if k in tx.op_data]
        for name, value in quantities:
            if to_coins(to_units(value)) != value:
                raise ValueError(f"{name} {value!r} has more than 8 decimal places; the smallest amount is 0.00000001")

    def _check_coinbase(self, block, block_subsidy):
        """The block's coinbase entries must pay the subsidy plus the fees
        of the transactions it carries, no more and no less. From
        INTEGER_UNITS_ACTIVATION_HEIGHT on that is an EXACT equality in
        units; before it, within 1e-6 of a coin, as it always was, because
        some historical coinbases are float sums like 100.00955500000001."""
        reward_txs = [tx for tx in block.transactions if tx.sender == "0"]
        if not reward_txs:
            raise ValueError("Block has no coinbase transaction")
        signed = [tx for tx in block.transactions if tx.sender != "0"]
        if block.index >= self.INTEGER_UNITS_ACTIVATION_HEIGHT:
            paid = sum(to_units(tx.amount) for tx in reward_txs)
            owed = to_units(block_subsidy) + sum(to_units(tx.fee) for tx in signed)
            ok = paid == owed
        else:
            expected = block_subsidy + sum(tx.fee for tx in signed)
            ok = abs(sum(tx.amount for tx in reward_txs) - expected) <= 1e-6
        if not ok:
            raise ValueError("Block's coinbase transaction(s) do not sum to the expected reward + collected fees")

    @staticmethod
    def _validate_header_fields(block: Block):
        """The header's own fields must be the types the rules assume
        (security review, 2026-09-29). A NaN timestamp compares False with
        everything, so it slipped through both timestamp checks and then
        poisoned every median and retarget after it; a float or out-of-range
        target makes the work arithmetic meaningless. Every live block was
        scanned before this was added and passes."""
        if not (isinstance(block.index, int) and not isinstance(block.index, bool) and block.index >= 0):
            raise ValueError("Block index must be a non-negative integer")
        if not (isinstance(block.timestamp, (int, float)) and not isinstance(block.timestamp, bool)
                and math.isfinite(block.timestamp) and block.timestamp >= 0):
            raise ValueError("Block timestamp must be a real, finite number")
        if not (isinstance(block.target, int) and not isinstance(block.target, bool) and 0 < block.target < 2 ** 256):
            raise ValueError("Block target must be an integer between 1 and 2**256 - 1")
        if not (isinstance(block.nonce, int) and not isinstance(block.nonce, bool)):
            raise ValueError("Block nonce must be an integer")
        if block.staker_address is not None and not isinstance(block.staker_address, str):
            raise ValueError("Block staker_address must be a string")
        if not isinstance(block.transactions, list) or not all(isinstance(tx, Transaction) for tx in block.transactions):
            raise ValueError("Block transactions must be a list of transactions")

    def accept_block(self, block: Block):
        """Validates and appends a block that was mined OR staked
        elsewhere (by node.py's /mining/submit, its staking thread, or
        here). Raises ValueError on any failure — never silently drops
        an invalid block. This function, together with is_chain_valid()
        below, IS the chain's security model: every rule that makes
        O-Coin hard to cheat (correct proof-of-work OR proof-of-stake,
        correct reward math, every transaction genuinely signed by its
        real sender, honest timestamps) is enforced right here,
        unconditionally, for every block from any source — mined,
        staked, submitted by an external miner, or received from a peer
        during sync."""
        self._validate_header_fields(block)
        if block.previous_hash != self.latest_block.compute_hash():
            raise ValueError("Block does not build on the current chain tip (someone else's block won the race, or this one is stale)")
        if block.index != self.latest_block.index + 1:
            raise ValueError("Block index out of sequence")
        self._validate_timestamp(block, self.chain)
        if block.staker_address is not None:
            self._validate_stake_proof(block)
            block_subsidy = round(self.reward_at_height(block.index) * self.POS_REWARD_FRACTION, 6)
        else:
            if block.target != self.current_target:
                raise ValueError(f"Block was mined against a stale difficulty target (expected {self.current_target}, got {block.target})")
            if not block.meets_target():
                raise ValueError("Block hash does not meet the difficulty target — nonce is not a valid proof of work")
            block_subsidy = self.reward_at_height(block.index)
        if block.merkle_root != block.compute_merkle_root():
            raise ValueError("Merkle root does not match the block's actual transactions")
        # One coinbase transaction for a solo-mined block, or MANY for a
        # pool-mined one (one per contributing address, proportional to
        # their share of the work — see build_pool_block) — either way,
        # what actually matters is that they SUM to (approximately) the
        # reward this block is entitled to, no more, no less. Nothing
        # about solo vs. pool vs. staked distribution changes the total
        # amount of new O-Coin a block is allowed to create — a staked
        # block's total is just smaller, per POS_REWARD_FRACTION. A
        # small epsilon tolerance, not exact equality, on purpose:
        # reward_at_height() returns a float, and splitting a float
        # reward across several coinbase transactions (build_pool_block)
        # involves float subtraction/addition that isn't guaranteed
        # bit-exactly reversible — real financial code never compares
        # floats for exact equality for the same reason.
        self._check_coinbase(block, block_subsidy)
        # Defense in depth against transaction replay (see
        # add_transaction's docstring for the full reasoning) — that
        # check protects the normal mempool path, but a block can also
        # arrive directly (from a miner, or a peer during sync) without
        # ever passing through add_transaction, so the same guarantee
        # has to be re-enforced here too. Deliberately scoped to SIGNED
        # transactions only (sender != "0") — coinbase transactions have
        # no signature to replay, and a pool-mined block legitimately
        # contains several coinbase entries to different (sometimes the
        # same) address on purpose, see build_pool_block.
        signed_hashes = [tx.hash() for tx in block.transactions if tx.sender != "0"]
        if len(signed_hashes) != len(set(signed_hashes)):
            raise ValueError("Block contains the same signed transaction more than once")
        confirmed_hashes = {t.hash() for b in self.chain for t in b.transactions if t.sender != "0"}
        if any(h in confirmed_hashes for h in signed_hashes):
            raise ValueError("Block replays a transaction that's already confirmed earlier in the chain")
        for tx in block.transactions:
            if not tx.is_valid():
                raise ValueError(f"Block contains an invalid transaction: {tx.hash()}")
        op_txs = [tx for tx in block.transactions if tx.op is not None]
        if op_txs and block.index < self.TX_SCHEMA_ACTIVATION_HEIGHT:
            raise ValueError(f"Block contains op-bearing transactions before activation height {self.TX_SCHEMA_ACTIVATION_HEIGHT}")
        # Balance sufficiency for EVERY signed transaction, in block order
        # (security review, 2026-09-29). This used to cover op-bearing
        # transactions only: a plain OCN transfer's balance was checked at
        # mempool admission and nowhere else, so a block arriving directly --
        # from anyone mining one, via /mining/submit or /blocks/receive --
        # could spend a balance that was never there: an unlimited mint. The
        # live chain was scanned before this was added and no historical
        # transaction ever overdrew, so the rule applies at every height.
        # In order, on a throwaway copy, so several spends from one sender in
        # one block are checked against each other; self.balances only gets
        # its REAL update below, once, so nothing is ever applied twice.
        self._check_block_balances(block.transactions, dict(self.balances), dict(self.asset_supply), block.index)
        self.chain.append(block)
        # O(1) incremental update — the common case, a full rebuild would
        # be wasteful here since only this one block's worth of
        # transactions actually changed anything (see _rebuild_balance_index
        # for the wholesale-replacement counterpart to this).
        for tx in block.transactions:
            self._apply_transaction_to_balances(tx, block.index)
        # Remove any mempool transactions that made it into this block —
        # by hash, so this works regardless of which miner/node actually
        # produced the block.
        mined_hashes = {tx.hash() for tx in block.transactions}
        self.mempool = [tx for tx in self.mempool if tx.hash() not in mined_hashes]
        if block.staker_address is not None:
            self._maybe_retarget_pos()
        else:
            self._maybe_retarget()

    # ── Validation / consensus (the "secure" lever) ─────────────────
    def is_chain_valid(self, chain=None):
        """Re-derives every block's hash from scratch and checks the whole
        chain links together correctly, every block carries the difficulty
        target the retarget rules give for that exact point in history, and
        meets it -- the function that makes the whole thing trustworthy
        without trusting whoever's node you're talking to: anyone can run
        this against any claimed chain and get the same true/false answer,
        using nothing but math. node.py runs it before ever adopting a
        peer's claimed chain -- a malicious or buggy peer can SEND whatever
        it wants, it just can't get an invalid chain ACCEPTED. The rules
        themselves live in _walk_chain; this is its yes/no answer, and a
        chain too malformed to even inspect is simply "no"."""
        chain = chain if chain is not None else self.chain
        try:
            self._walk_chain(chain)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            return False
        return True

    def _walk_chain(self, chain):
        """Every rule, block by block from genesis, in ONE linear pass.
        Raises ValueError on the first failure; on success returns the
        (PoW, PoS) targets the NEXT block of each kind must carry.

        Security review, 2026-09-29, changed three things here:

        - Historical targets are re-derived, not taken on trust. A block
          used to be checked only against the target written in its own
          header, and fork choice was by length, so anyone could serve a
          long chain of blocks that each named an EASY target and have it
          win -- rewriting up to CHECKPOINT_DEPTH blocks of history with
          almost no work. The replay below runs the same _next_target step
          the live path runs. The whole live chain (14,175 blocks at the
          time) was replayed before this was added and every block's target
          matched, so it applies at every height.
        - Every signed transaction's balance is checked, in block order, not
          only op-bearing ones (see accept_block).
        - It is linear. The replay guard used to rebuild the set of every
          earlier transaction hash for EACH block, and each staked block
          re-scanned the chain for its staker's weight: quadratic, and a
          peer could make a node spend minutes on one bad chain. Both are
          now running state carried forward as the loop walks.

        Stake weight comes from the running balances, i.e. the candidate
        chain's OWN history up to that block -- never self.balances, since a
        candidate must be judged without trusting that any of it ever passed
        through accept_block."""
        if not chain:
            raise ValueError("Empty chain")
        if chain[0].compute_hash() != self.genesis_hash:
            raise ValueError("Chain does not start from this network's genesis block")
        balances, supply = {}, {}
        for tx in chain[0].transactions:
            self._apply_transaction_to_balance_dict(balances, tx, supply, height=0)
        pow_target, pos_target = self.INITIAL_TARGET, self._initial_pos_target()
        pow_times, pos_times = [chain[0].timestamp], []
        confirmed = set()
        prev_hash = self.genesis_hash
        for i in range(1, len(chain)):
            block, prev = chain[i], chain[i - 1]
            self._validate_header_fields(block)
            if block.previous_hash != prev_hash:
                raise ValueError(f"Block {i} does not link to the block before it")
            if block.index != prev.index + 1:
                raise ValueError(f"Block {i} index out of sequence")
            self._validate_timestamp(block, chain[max(0, i - self.MEDIAN_TIME_WINDOW):i])
            block_hash = block.compute_hash()
            if block.staker_address is not None:
                if block.target != pos_target:
                    raise ValueError(f"Block {i} carries a PoS target the retarget rules do not give")
                weight = balances.get((block.staker_address, "OCN"), 0) // UNITS_PER_COIN
                if weight < 1:
                    raise ValueError(f"Block {i} staker has no stakeable balance")
                if int(block.compute_stake_kernel_hash(), 16) >= block.target * weight:
                    raise ValueError(f"Block {i} stake kernel does not meet its target")
                block_subsidy = round(self.reward_at_height(block.index) * self.POS_REWARD_FRACTION, 6)
            else:
                if block.target != pow_target:
                    raise ValueError(f"Block {i} carries a PoW target the retarget rules do not give")
                if int(block_hash, 16) >= block.target:
                    raise ValueError(f"Block {i} hash does not meet its target")
                block_subsidy = self.reward_at_height(block.index)
            if block.merkle_root != block.compute_merkle_root():
                raise ValueError(f"Block {i} merkle root does not match its transactions")
            # Before any arithmetic touches their amounts (a NaN must never
            # reach a sum or a balance).
            for tx in block.transactions:
                if not tx.is_valid():
                    raise ValueError(f"Block {i} contains an invalid transaction")
            self._check_coinbase(block, block_subsidy)
            # Same replay guard as accept_block, re-checked independently.
            signed_hashes = [tx.hash() for tx in block.transactions if tx.sender != "0"]
            if len(signed_hashes) != len(set(signed_hashes)) or any(h in confirmed for h in signed_hashes):
                raise ValueError(f"Block {i} replays a signed transaction")
            if block.index < self.TX_SCHEMA_ACTIVATION_HEIGHT and any(tx.op is not None for tx in block.transactions):
                raise ValueError(f"Block {i} contains op-bearing transactions before activation height")
            # Checked on a copy; the running state takes the block only once
            # it has passed.
            scratch_balances, scratch_supply = dict(balances), dict(supply)
            self._check_block_balances(block.transactions, scratch_balances, scratch_supply, block.index)
            balances, supply = scratch_balances, scratch_supply
            confirmed.update(signed_hashes)
            prev_hash = block_hash
            if block.staker_address is not None:
                pos_times.append(block.timestamp)
                n = len(pos_times)
                if n >= self.POS_RETARGET_INTERVAL and n % self.POS_RETARGET_INTERVAL == 0:
                    pos_target = self._next_target(pos_target, pos_times[-self.POS_RETARGET_INTERVAL], pos_times[-1],
                                                   self.POS_RETARGET_INTERVAL, self.POS_MAX_TARGET)
            else:
                pow_times.append(block.timestamp)
                n = len(pow_times) - 1  # PoW blocks so far, excluding genesis -- as _maybe_retarget counts
                if n >= self.RETARGET_INTERVAL and n % self.RETARGET_INTERVAL == 0:
                    pow_target = self._next_target(pow_target, pow_times[-1 - self.RETARGET_INTERVAL], pow_times[-1],
                                                   self.RETARGET_INTERVAL, self.MAX_TARGET)
        return pow_target, pos_target

    def chain_work(self, chain):
        """Total work a chain represents: each PoW block's block_work, and
        each staked block counted as one block at the PoW difficulty in force
        just before it (the most recent PoW block's target). A staked block
        is no harder to make than its stake allows, so it gets no MORE weight
        than an ordinary block; counting it as one keeps fork choice where it
        was for staked blocks while PoW blocks are weighed by real work.
        Reads targets as written -- only meaningful for a chain that
        _walk_chain has confirmed (or is about to confirm) carries the
        targets the rules give."""
        total = 0
        last_pow_work = self.block_work(chain[0].target) if chain else 0
        for block in chain[1:]:
            if block.staker_address is None:
                last_pow_work = self.block_work(block.target)
            total += last_pow_work
        return total

    def adopt_chain(self, chain):
        """Validate a whole chain from genesis and make it this node's --
        used for the startup chain (node.py load_chain) and by replace_chain.
        Raises ValueError if it is not valid. The next targets come from the
        replay, not from the last block's header: a chain whose last PoW
        block closed a retarget window already owes its next block the NEW
        target, and reading the old one back used to leave the node mining
        against a stale difficulty until the next window."""
        try:
            pow_target, pos_target = self._walk_chain(chain)
        except (TypeError, KeyError, AttributeError, OverflowError) as e:
            raise ValueError(f"Malformed chain: {e}")
        self.chain = chain
        self._rebuild_balance_index()
        self.current_target, self.pos_target = pow_target, pos_target
        self.mempool = []  # conservative: a reorg can invalidate assumptions about what's still pending

    def _diverges_before_checkpoint(self, candidate_chain):
        """True if candidate_chain disagrees with our own history at or
        before our checkpoint boundary — the actual enforcement behind
        "nobody can rewrite history past this point, regardless of
        hashpower." Checked BEFORE the (much more expensive) full
        is_chain_valid() pass, so a chain attempting to rewrite ancient
        history gets rejected immediately rather than after fully
        re-validating it."""
        checkpoint_index = max(0, len(self.chain) - self.CHECKPOINT_DEPTH)
        if len(candidate_chain) <= checkpoint_index:
            return True  # shorter than our own checkpointed history — can't possibly agree with all of it
        for i in range(checkpoint_index + 1):
            if candidate_chain[i].compute_hash() != self.chain[i].compute_hash():
                return True
        return False

    def mark_bft_finalized(self, index, block_hash):
        """Called ONLY by the BFT finality gadget (bft_finality.py) when its
        committee has committed a checkpoint — records that the block at
        `index` is now cryptographically final. Only accepts a hash that
        matches our OWN block at that index (you can't finalize a block you
        don't hold), so a bad or malicious call can never poison the reorg
        veto. Idempotent. DORMANT: nothing in this file or node.py calls it
        until a real committee is wired in, so self.bft_finalized stays empty
        and the veto below never fires."""
        if 0 <= index < len(self.chain) and self.chain[index].compute_hash() == block_hash:
            self.bft_finalized[index] = block_hash
            return True
        return False

    def _conflicts_with_bft_finality(self, candidate_chain):
        """True if candidate_chain would DROP or REWRITE any block the BFT
        gadget has finalized — the cryptographic counterpart to the
        depth-based _diverges_before_checkpoint, and strictly stronger (a
        block can be BFT-final long before it is CHECKPOINT_DEPTH deep).
        Empty finalized set (the default, and the current live state) =>
        always False => zero behavior change. This one method is the entire
        'additive, not a replacement' contract: PoW/PoS still decides which
        chain wins; this only ever ADDS a veto on rewriting finalized
        history."""
        for index, block_hash in self.bft_finalized.items():
            if index >= len(candidate_chain):
                return True  # can't drop a finalized block
            if candidate_chain[index].compute_hash() != block_hash:
                return True  # can't rewrite a finalized block
        return False

    def replace_chain(self, candidate_chain):
        """Fork choice: the valid chain with the MOST WORK wins (Bitcoin's
        rule), EXCEPT past the checkpoint boundary, where it also has to
        agree with what we've already checkpointed (the depth checkpoint
        always, plus -- once the BFT finality gadget is active -- any
        cryptographically-finalized block). This used to be "the longest
        valid chain", which with unverified historical targets let a long
        chain of easy blocks beat a shorter chain of real work (security
        review, 2026-09-29). The candidate needs STRICTLY more work, so a
        tie keeps the chain we already have.
        Returns True if the candidate replaced our chain, False if it was
        rejected (lighter, invalid, or attempting to rewrite checkpointed
        or BFT-finalized history)."""
        try:
            # Cheapest check first: no hashing at all. Its answer is trusted
            # only because adopt_chain below re-derives every target.
            if self.chain_work(candidate_chain) <= self.chain_work(self.chain):
                return False
        except (TypeError, AttributeError):
            return False
        if self._diverges_before_checkpoint(candidate_chain):
            return False
        if self.bft_finalized and self._conflicts_with_bft_finality(candidate_chain):
            return False
        try:
            self.adopt_chain(candidate_chain)
        except ValueError:
            return False
        return True

# Self-check, run once at import time: catches the single most likely
# emission-curve tuning mistake — changing ANNUAL_DECAY_PERCENT or
# TARGET_BLOCK_TIME without regenerating REWARD_DECAY_RATE_FIXED to
# match. Comparing floats here is safe (this never feeds a consensus
# decision, only this developer-facing check), and the tolerance is wide
# enough to absorb ordinary cross-platform libm noise in the last few
# bits while still catching a real, deliberate parameter change, which
# shifts the rate by far more than that.
_expected_rate = Blockchain._derive_rate_fixed(Blockchain.ANNUAL_DECAY_PERCENT, Blockchain.TARGET_BLOCK_TIME, Blockchain.FRAC_BITS)
if abs(_expected_rate - Blockchain.REWARD_DECAY_RATE_FIXED) > 1_000_000:
    raise RuntimeError(
        f"REWARD_DECAY_RATE_FIXED ({Blockchain.REWARD_DECAY_RATE_FIXED}) is stale for the "
        f"current ANNUAL_DECAY_PERCENT={Blockchain.ANNUAL_DECAY_PERCENT} / "
        f"TARGET_BLOCK_TIME={Blockchain.TARGET_BLOCK_TIME} (expected ~{_expected_rate}). "
        f"Regenerate it with: python -c \"from blockchain import Blockchain as B; "
        f"print(B._derive_rate_fixed(B.ANNUAL_DECAY_PERCENT, B.TARGET_BLOCK_TIME))\" "
        f"and paste the printed value in as the new REWARD_DECAY_RATE_FIXED."
    )
del _expected_rate


def proof_of_work(block: Block) -> Block:
    """The actual brute-force search: try nonces until the block's hash,
    read as a number, happens to come out below the target. This is real,
    genuine computational work — there's no shortcut, you just have to
    try nonces until you get lucky, which is exactly what makes
    proof-of-work meaningful as a "proof" of anything (spending real CPU
    time is the whole point)."""
    block.nonce = 0
    while not block.meets_target():
        block.nonce += 1
    return block
