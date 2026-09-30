"""The units ledger (2026-09-30): balances are whole numbers of units
(1 coin = 100,000,000 units), so they add exactly; and from
INTEGER_UNITS_ACTIVATION_HEIGHT on, signed amounts must be whole units, the
coinbase must be exact, and the pools use integer formulas that can never
pay out more than a reserve holds. Same no-networking style as the rest.
"""
from blockchain import Block, Blockchain, proof_of_work, to_units, to_coins, UNITS_PER_COIN
from transaction import Transaction
from wallet import Wallet


class Before(Blockchain):
    """The rules as they stand below the activation height."""
    INITIAL_TARGET = 2 ** 256 // 2 ** 6
    MAX_TARGET = 2 ** 256 // 2 ** 4
    INTEGER_UNITS_ACTIVATION_HEIGHT = 10 ** 9


class After(Before):
    """The rules from the activation height on, from genesis."""
    INTEGER_UNITS_ACTIVATION_HEIGHT = 0
    TX_SCHEMA_ACTIVATION_HEIGHT = 0


def mine(bc, address):
    block = bc.build_candidate_block(address)
    block.timestamp = bc.latest_block.timestamp + Blockchain.TARGET_BLOCK_TIME
    bc.accept_block(proof_of_work(block))
    return block


def signed(wallet, recipient, amount, fee=0.01, op=None, op_data=None):
    tx = Transaction(wallet.address, recipient, amount, fee=fee, op=op, op_data=op_data)
    tx.sign(wallet)
    return tx


def rejected(fn):
    try:
        fn()
    except ValueError as e:
        return str(e)
    raise AssertionError("expected a ValueError")


alice, bob, miner = Wallet(), Wallet(), Wallet()

print("=== 1: converting amounts is exact and deterministic ===")
assert to_units(0.1) == 10_000_000 and to_units(100) == 100 * UNITS_PER_COIN
assert to_units(5_000_000_000) == 500_000_000_000_000_000, "ints never pass through a float"
assert to_units(99.979552) == 9_997_955_200
assert to_coins(to_units(0.12345678)) == 0.12345678
print("  0.1 coin = 10,000,000 units; 8 decimal places round-trip exactly")

print("\n=== 2: balances add exactly -- ten payments of 0.1 are exactly 1 coin ===")
running = 0.0
for _ in range(10):
    running += 0.1                                  # how the float ledger added (sum() compensates; it did not)
assert running != 1.0, "the float running total is 0.9999999999999999"
bc = After()
mine(bc, alice.address)
for _ in range(10):
    bc.add_transaction(signed(alice, bob.address, 0.1))
mine(bc, miner.address)
assert bc.get_balance_units(bob.address) == UNITS_PER_COIN and bc.get_balance(bob.address) == 1.0
print("  bob holds exactly", bc.get_balance(bob.address))

print("\n=== 3: spending an entire balance lands on exactly zero, never a hair below ===")
whole = bc.get_balance(bob.address)
bc.add_transaction(signed(bob, alice.address, round(whole - 0.01, 8)))
mine(bc, miner.address)
assert bc.get_balance_units(bob.address) == 0
print("  bob sent everything minus the fee; his balance is exactly 0")

print("\n=== 4: from the activation height, a signed amount must be whole units ===")
bc = After()
mine(bc, alice.address)
print("  mempool:", rejected(lambda: bc.add_transaction(signed(alice, bob.address, 0.123456789))))
bc.add_transaction(signed(alice, bob.address, 0.12345678))
template = bc.build_candidate_block(miner.address)
fine = signed(alice, bob.address, 1.000000001)
forged = Block(template.index, [Transaction("0", miner.address, to_coins(to_units(template.transactions[0].amount) + to_units(fine.fee)), fee=0)]
               + template.transactions[1:] + [fine], template.previous_hash, template.target,
               timestamp=bc.latest_block.timestamp + 15)
print("  block:  ", rejected(lambda: bc.accept_block(proof_of_work(forged))))
mine(bc, miner.address)
assert bc.get_balance(bob.address) == 0.12345678
early = Before()
mine(early, alice.address)
early.add_transaction(signed(alice, bob.address, 0.123456789))
mine(early, miner.address)
assert early.get_balance_units(bob.address) == 12_345_679, "below the height, a finer amount is rounded to the nearest unit"
print("  below the height the same amount is accepted and rounded to the nearest unit, as history was")

print("\n=== 5: from the activation height, the coinbase must equal reward + fees exactly ===")
bc = After()
mine(bc, alice.address)
bc.add_transaction(signed(alice, bob.address, 1))
template = bc.build_candidate_block(miner.address)
assert to_units(template.transactions[0].amount) == to_units(bc.reward_at_height(template.index)) + to_units(0.01)
greedy = Block(template.index, [Transaction("0", miner.address, template.transactions[0].amount + 0.00000001, fee=0)]
               + template.transactions[1:], template.previous_hash, template.target, timestamp=bc.latest_block.timestamp + 15)
print("  one unit too much:", rejected(lambda: bc.accept_block(proof_of_work(greedy))))
early = Before()
mine(early, alice.address)
early.add_transaction(signed(alice, bob.address, 1))
t = early.build_candidate_block(miner.address)
sloppy = Block(t.index, [Transaction("0", miner.address, t.transactions[0].amount + 0.0000005, fee=0)] + t.transactions[1:],
               t.previous_hash, t.target, timestamp=early.latest_block.timestamp + 15)
early.accept_block(proof_of_work(sloppy))
print("  below the height the old 1e-6 tolerance still applies, as history was made under it")

print("\n=== 6: integer pool formulas never pay out more than a reserve holds ===")
bc = After()
lp = Wallet()
for _ in range(3):
    mine(bc, lp.address)
bc.balances[(lp.address, "TEST")] = to_units(50)      # test-only seed, as test_amm_pools does
pool = "OCN:TEST"
bc.add_transaction(signed(lp, Blockchain._pool_address(pool), 0, op="pool_add_liquidity",
                          op_data={"pool_key": pool, "amount_a": 10.12345678, "amount_b": 7.00000001}))
mine(bc, miner.address)
lp_units = bc.balances[(lp.address, Blockchain._lp_asset_id(pool))]
assert lp_units == int((to_units(10.12345678) * to_units(7.00000001)) ** 0.5), "first deposit mints sqrt(a*b) in units"
bc.add_transaction(signed(lp, lp.address, 0, op="pool_swap",
                          op_data={"pool_key": pool, "asset_in": "TEST", "amount_in": 0.33333333, "min_amount_out": 0}))
mine(bc, miner.address)
bc.add_transaction(signed(lp, lp.address, 0, op="pool_remove_liquidity",
                          op_data={"pool_key": pool, "lp_amount": to_coins(lp_units)}))
mine(bc, miner.address)
status = bc.pool_status(pool)
assert status["reserve_a"] >= 0 and status["reserve_b"] >= 0 and status["lp_supply"] == 0
assert bc.is_chain_valid() is False, "(seeded TEST cannot be re-derived from the chain -- expected)"
print(f"  the last provider withdrew everything; reserves left: {status['reserve_a']} OCN, {status['reserve_b']} TEST")

print("\n=== 7: the API still speaks coins ===")
bc = After()
mine(bc, alice.address)
assert isinstance(bc.get_balance(alice.address), float) and bc.get_balance(alice.address) == bc.reward_at_height(1)
assert bc.stake_weight_of(alice.address) == int(bc.reward_at_height(1)), "stake weight is still whole coins"
print("  get_balance returns coins; stake weight is whole coins")

print("\n=== ALL INTEGER-UNITS SCENARIOS PASSED ===")
