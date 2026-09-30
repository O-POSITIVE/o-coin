"""The security review of 2026-09-29: each rule it added, shown refusing
the thing it exists to refuse, and shown NOT refusing the honest case next
to it. Same no-networking, direct-object style as the other test_*.py files.

A small subclass with a very easy starting difficulty keeps the mining here
to a few dozen hashes a block; every rule under test is the real one.
"""
import math
import time

from blockchain import Block, Blockchain, proof_of_work
from transaction import Transaction
from wallet import Wallet


class EasyChain(Blockchain):
    INITIAL_TARGET = 2 ** 256 // 2 ** 6
    MAX_TARGET = 2 ** 256 // 2 ** 4


def mine(bc, address, ts=None, max_transactions=50):
    block = bc.build_candidate_block(address, max_transactions)
    block.timestamp = ts if ts is not None else bc.latest_block.timestamp + 1
    block = proof_of_work(block)
    bc.accept_block(block)
    return block


def signed(wallet, recipient, amount, fee=0.01, ts=None):
    tx = Transaction(wallet.address, recipient, amount, fee=fee, timestamp=ts)
    tx.sign(wallet)
    return tx


def rejected(fn):
    try:
        fn()
    except ValueError as e:
        return str(e)
    raise AssertionError("expected a ValueError, got none")


alice, bob, carol, miner = Wallet(), Wallet(), Wallet(), Wallet()

print("=== 1: amounts, fees and timestamps must be real, finite numbers ===")
for bad in (float("nan"), float("inf"), -float("inf"), True, 10 ** 13):
    assert not signed(alice, bob.address, bad).is_valid(), f"amount {bad!r} must be refused"
    assert not signed(alice, bob.address, 1, fee=bad).is_valid(), f"fee {bad!r} must be refused"
assert not signed(alice, bob.address, 1, ts=float("nan")).is_valid()
assert signed(alice, bob.address, 1).is_valid(), "an ordinary transfer still passes"
assert not Transaction("0", bob.address, float("nan"), fee=0).is_valid(), "nor a NaN coinbase"
bc = EasyChain()
print("  refused:", rejected(lambda: bc.add_transaction(signed(alice, bob.address, 1, fee=float("nan")))))
print("  NaN, infinity, booleans and absurd sizes are refused; ordinary values pass")

print("\n=== 2: a coinbase entry can never be negative ===")
assert not Transaction("0", bob.address, -1, fee=0).is_valid()
bc = EasyChain()
mine(bc, alice.address)                         # alice now holds a reward
template = bc.build_candidate_block(miner.address)
reward = template.transactions[0].amount
theft = Block(template.index, [Transaction("0", miner.address, reward + 50, fee=0),
                               Transaction("0", alice.address, -50, fee=0)],
              template.previous_hash, template.target, timestamp=bc.latest_block.timestamp + 1)
theft = proof_of_work(theft)
print("  refused:", rejected(lambda: bc.accept_block(theft)))
assert bc.get_balance(alice.address) > 0, "alice keeps what she had"

print("\n=== 3: a block cannot spend a balance that is not there ===")
bc = EasyChain()
mine(bc, miner.address)
broke = Wallet()                                  # never received anything
template = bc.build_candidate_block(miner.address)
spend = signed(broke, carol.address, 1000)
forged = Block(template.index, [Transaction("0", miner.address, template.transactions[0].amount + spend.fee, fee=0), spend],
               template.previous_hash, template.target, timestamp=bc.latest_block.timestamp + 1)
forged = proof_of_work(forged)
print("  accept_block refused:", rejected(lambda: bc.accept_block(forged)))
assert bc.get_balance(carol.address) == 0
assert bc.is_chain_valid(bc.chain + [forged]) is False, "and a whole chain carrying it is invalid too"
assert bc.is_chain_valid() is True
print("  is_chain_valid refuses a chain carrying it; the honest chain stays valid")

print("\n=== 4: a spend of still-pending coins is placed AFTER the transfer that pays for it ===")
bc = EasyChain()
mine(bc, alice.address)
a_to_b = signed(alice, bob.address, 10, fee=0.01)
b_to_c = signed(bob, carol.address, 5, fee=1)       # higher fee: pure fee order would put it first
bc.add_transaction(a_to_b)
bc.add_transaction(b_to_c)                           # the mempool admits it (a_to_b is pending)
template = bc.build_candidate_block(miner.address)
order = [tx.hash() for tx in template.transactions[1:]]
assert order == [a_to_b.hash(), b_to_c.hash()], "funding first, then the spend"
fee_order = Block(template.index, [template.transactions[0], b_to_c, a_to_b], template.previous_hash,
                  template.target, timestamp=bc.latest_block.timestamp + 1)
fee_order = proof_of_work(fee_order)
print("  in fee order it would be refused:", rejected(lambda: bc.accept_block(fee_order)))
mine(bc, miner.address)
assert bc.get_balance(carol.address) == 5 and not bc.mempool, "both mined, in the right order"
print("  both mined in one block; mining never stalls on the pair")

print("\n=== 5: every block must carry the target the retarget rules give ===")
bc = EasyChain()
for _ in range(3):
    mine(bc, miner.address)
attacker = list(bc.chain[:1])
for i in range(1, 8):                                # longer, and each block names an easy target
    coinbase = Transaction("0", carol.address, bc.reward_at_height(i), fee=0)
    b = proof_of_work(Block(i, [coinbase], attacker[-1].compute_hash(), 2 ** 255, timestamp=attacker[-1].timestamp + 1))
    attacker.append(b)
assert bc.is_chain_valid(attacker) is False, "an easy target the rules never gave is refused"
assert bc.replace_chain(attacker) is False
assert bc.latest_block.index == 3, "the honest chain stays"
harder = list(bc.chain[:1])                          # even a HARDER target than the rule is refused
b = proof_of_work(Block(1, [Transaction("0", carol.address, bc.reward_at_height(1), fee=0)],
                        harder[-1].compute_hash(), EasyChain.INITIAL_TARGET // 2, timestamp=1))
assert bc.is_chain_valid(harder + [b]) is False
print("  a longer chain of self-chosen easy targets is refused; so is any target off the rules")

print("\n=== 6: fork choice is by total work, not by length ===")
now = time.time()
base = now - 7000
heavy, light = EasyChain(), EasyChain()
# A shared first 10 blocks, then a fork -- recent enough that the checkpoint
# (CHECKPOINT_DEPTH) allows the reorg. Genesis is timestamped 0, so that
# first window always reads as slow and eases to MAX_TARGET; the second
# window, where the two chains differ, is the test.
for k in range(1, 11):
    mine(heavy, miner.address, ts=base + k)
light.adopt_chain(list(heavy.chain))
for k in range(11, 22):                              # 10 more fast blocks -> 4x harder -> 1 hard block
    mine(heavy, miner.address, ts=base + k)
for k in range(11, 23):                              # 10 more slow blocks -> stays easy -> 2 easy blocks
    mine(light, carol.address, ts=base + 10 + 600 * (k - 10))
assert heavy.chain[11].target == light.chain[21].target == EasyChain.MAX_TARGET
assert heavy.chain[21].target < EasyChain.MAX_TARGET, "the two retargets went opposite ways"
light_work, heavy_work = light.chain_work(light.chain), heavy.chain_work(heavy.chain)
assert len(light.chain) > len(heavy.chain) and light_work < heavy_work
assert heavy.replace_chain(light.chain) is False, "longer but lighter loses"
assert light.replace_chain(heavy.chain) is True, "shorter but heavier wins"
assert light.chain[-1].compute_hash() == heavy.chain[-1].compute_hash()
assert heavy.replace_chain(list(heavy.chain)) is False, "a tie keeps the chain we have"
print(f"  22 light blocks (work {light_work}) lost to 21 heavy ones (work {heavy_work})")

print("\n=== 7: a node loading a chain takes the NEXT target from the rules, not the last header ===")
fresh = EasyChain()
fresh.adopt_chain(list(heavy.chain[:21]))            # ends on the block that closed a retarget window
assert fresh.current_target == heavy.chain[21].target != heavy.chain[20].target
print("  after the 20th block the next target is the retargeted one")

print("\n=== 8: header fields must be the types the rules assume ===")
bc = EasyChain()
for field, value in (("timestamp", float("nan")), ("target", float(EasyChain.INITIAL_TARGET)), ("target", 0), ("nonce", "1")):
    block = bc.build_candidate_block(miner.address)
    block.timestamp = bc.latest_block.timestamp + 1
    setattr(block, field, value)
    print(f"  {field}={value!r}:", rejected(lambda: bc.accept_block(block)))

print("\n=== 9: pool op amounts must be real numbers; op_data must be an object ===")
for field, value in (("amount_in", float("nan")), ("amount_in", float("inf"))):
    tx = Transaction(alice.address, alice.address, 0, op="pool_swap",
                     op_data={"pool_key": "OCN:TEST", "asset_in": "OCN", field: value})
    print(f"  pool_swap {field}={value!r}:", rejected(lambda: Blockchain._validate_op(tx)))
tx = Transaction(alice.address, alice.address, 0, op="pool_swap", op_data=["not", "an", "object"])
print("  op_data list:", rejected(lambda: Blockchain._validate_op(tx)))

print("\n=== 10: validation is linear -- a long chain is checked in one pass ===")
bc = EasyChain()
for _ in range(300):                                 # on the 15s target, so difficulty holds steady
    mine(bc, miner.address, ts=bc.latest_block.timestamp + Blockchain.TARGET_BLOCK_TIME)
t = time.time()
assert bc.is_chain_valid() is True
elapsed = time.time() - t
assert elapsed < 30, f"300 blocks took {elapsed:.1f}s"
print(f"  301 blocks validated in {elapsed:.2f}s")

print("\n=== ALL SECURITY-HARDENING SCENARIOS PASSED ===")
