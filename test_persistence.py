"""The stored chain stays equal to the chain in memory (2026-10-06).

Found while fixing peer sync: the main node's table was missing blocks
#14,828 and #14,829 (accepted 2026-09-30 23:30-23:45 UTC while a save to the
database failed). The node ran on, but it refuses to start on a stored chain
that fails validation, so its next restart would have kept it down. The rows
were restored from the live node by hand; this is what makes that automatic:
a failed save no longer escapes, and the persistence check writes whatever
the table is missing, holds stale, or holds past the tip, from memory.

An in-memory stand-in for the blocks table. No database and no network.
"""
import time

import node
from blockchain import Blockchain, proof_of_work
from wallet import Wallet


class EasyChain(Blockchain):
    INITIAL_TARGET = 2 ** 256 // 2 ** 6
    MAX_TARGET = 2 ** 256 // 2 ** 4


table = {}            # idx -> block dict, what the database holds
queries = []


class Cursor:
    def execute(self, sql, args=None):
        s = " ".join(sql.split())
        queries.append(s.split(" FROM")[0])
        if s.startswith("INSERT INTO"):
            idx, data = args
            table[idx] = data.adapted
        elif s.startswith("DELETE"):
            if "idx >= %s" in s:
                gone = [i for i in table if i >= args[0]]
            else:
                gone = [i for i in table if i > args[0]]
            for i in gone:
                del table[i]
        elif "count(*)" in s:
            stored = [i for i in table if i > 0]
            self.rows = [(len(stored), max(stored, default=0))]
        elif s.startswith("SELECT idx, data"):
            self.rows = [(i, table[i]) for i in sorted(table) if args[0] <= i <= args[1]]
        elif s.startswith("SELECT idx FROM"):
            self.rows = [(i,) for i in sorted(table) if 0 < i <= args[0]]
        elif s.startswith("SELECT data"):
            self.rows = [(table[i],) for i in sorted(table) if i > 0]

    def fetchone(self):
        return self.rows[0]

    def fetchall(self):
        return self.rows


class Conn:
    def cursor(self):
        return Cursor()

    def commit(self):
        pass

    def close(self):
        pass


def execute_batch(cur, sql, rows):
    for row in rows:
        cur.execute(sql, row)


def broken():
    raise ConnectionError("SSL connection has been closed unexpectedly")


def fresh_table():
    table.clear()
    table.update({b.index: b.to_dict() for b in chain[1:]})


def tampered(i):
    stale = dict(table[i])
    stale["nonce"] = stale["nonce"] + 1         # not the block in memory
    return stale


# Borrowed from the node module and given back at the end: unittest runs
# every test file in ONE process.
_real = (node.get_pg, node.psycopg2.extras.execute_batch, node.init_db, node.BLOCKS_TABLE,
         node.persistence_check, node._persist_needed, node.time.sleep)
node.get_pg = lambda: Conn()
node.psycopg2.extras.execute_batch = execute_batch
node.init_db = lambda: None
node.BLOCKS_TABLE = "ocoin_blocks_test"

miner = Wallet()
node.blockchain = EasyChain()
base = time.time() - 3600
for k in range(1, 41):
    block = node.blockchain.build_candidate_block(miner.address, 50)
    block.timestamp = base + k
    node.blockchain.accept_block(proof_of_work(block))
chain = node.blockchain.chain
tip = len(chain) - 1

print("=== 1: a save that fails no longer escapes; it flags the check ===")
node._persist_needed.clear()
node.get_pg = broken
node.save_block(chain[5])                      # would have raised before
assert node._persist_needed.is_set(), "flagged for the persistence check"
node.get_pg = lambda: Conn()
print("  no exception; the check is flagged")

print("\n=== 2: the 2026-09-30 case: two blocks missing from the table are written from memory ===")
fresh_table()
del table[28], table[29]
assert node.persistence_check() == 2
assert sorted(table) == list(range(1, len(chain))), "no gap left"
assert table[28] == chain[28].to_dict() and table[29] == chain[29].to_dict()
print("  #28 and #29 stored again")

print("\n=== 3: a healthy table costs one small query and writes nothing ===")
queries.clear()
assert node.persistence_check() == 0
assert queries == ["SELECT count(*), coalesce(max(idx), 0)"], queries
print(f"  queries: {queries}")

print("\n=== 4: a stale block near the tip (a reorg the table missed) is rewritten by the deep pass ===")
table[tip - 1] = tampered(tip - 1)
assert node.persistence_check() == 0, "the ten-minute count cannot see it"
assert node.persistence_check(deep=True) == 1
assert table[tip - 1] == chain[-2].to_dict()
print("  the tip's neighbour matches memory again")

print("\n=== 5: rows past the tip (an old, longer fork) are removed ===")
table[tip + 1] = dict(table[tip], index=tip + 1)
table[tip + 2] = dict(table[tip], index=tip + 2)
assert node.persistence_check() == 2
assert sorted(table) == list(range(1, len(chain)))
print(f"  rows #{tip + 1}-#{tip + 2} gone; load_chain would have refused them")

print("\n=== 6: a rewrite after a sync replaces only the rows from the shared block on ===")
before = dict(table)
queries.clear()
node.save_full_chain(30)
assert all(table[i] is before[i] for i in range(1, 30)), "rows before #30 untouched"
assert [table[i] for i in range(30, len(chain))] == [b.to_dict() for b in chain[30:]]
assert queries.count("DELETE") == 1 and queries.count("INSERT INTO ocoin_blocks_test (idx, data) VALUES (%s, %s)") == tip - 29
print(f"  {tip - 29} rows rewritten, not {tip}")

print("\n=== 7: a failed rewrite is checked from where it started, past the usual tail ===")
fresh_table()
table[5], table[6] = tampered(5), tampered(6)  # deeper than PERSIST_TAIL from the tip
assert node.persistence_check(deep=True) == 0, "the hourly pass looks at the tail only"
node._persist_needed.clear()
node.get_pg = broken
node.save_full_chain(5)                        # would have raised before
node.get_pg = lambda: Conn()
assert node._persist_from == [5] and node._persist_needed.is_set()
assert node.persistence_check(deep=True) == 2
assert table[5] == chain[5].to_dict() and table[6] == chain[6].to_dict()
assert node._persist_from == [None], "done: back to the tail"
print("  #5 and #6 rewritten; the next deep pass is the usual tail again")

print("\n=== 8: after the checks, the node would start: the stored chain validates ===")
node.blockchain = EasyChain()
node.load_chain()
assert len(node.blockchain.chain) == len(chain)
assert node.blockchain.latest_block.compute_hash() == chain[-1].compute_hash()
print(f"  load_chain adopted all {len(chain)} blocks")

print("\n=== 9: the loop: a count every ten minutes, the deep pass hourly or right after a failure ===")


class Stop(Exception):
    pass


wakes = iter([False] * 5 + [False] + [True] + [False])   # True = a save failed meanwhile


class Event:
    def wait(self, timeout):
        assert timeout == node.PERSIST_CHECK_S
        try:
            return next(wakes)
        except StopIteration:
            raise Stop

    def clear(self):
        pass

    def set(self):
        pass


deeps = []
node._persist_needed = Event()
node.persistence_check = lambda deep=False: deeps.append(deep)
node.time.sleep = lambda s: None
try:
    node.persistence_loop()
except Stop:
    pass
assert deeps == [False] * 5 + [True] + [True] + [False], deeps
print(f"  passes: {['deep' if d else 'count' for d in deeps]}")

(node.get_pg, node.psycopg2.extras.execute_batch, node.init_db, node.BLOCKS_TABLE,
 node.persistence_check, node._persist_needed, node.time.sleep) = _real
node.blockchain = node.Blockchain()

print("\n=== ALL PERSISTENCE SCENARIOS PASSED ===")
