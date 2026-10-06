"""Incremental peer sync (2026-10-06): a node downloads only the blocks after
the last one it shares with a heavier peer, never a peer's whole chain on a
timer, and backs off from a chain it had to refuse.

Why: with the primary and backup nodes on a lasting fork, peer_sync_loop
pulled the backup's ENTIRE chain (10.6 MB raw, 1.7 MB compressed) every two
minutes over public URLs and refused it every time -- 7.46 GB of the Render
workspace's 10.59 GB of billed bandwidth in the first six days of October.

Real chains (an easy starting difficulty, every rule the real one) and a fake
peer that answers the same JSON as /chain/hashes, /chain/blocks and /chain,
counting what is asked for. No database and no network.
"""
import time
from urllib.parse import urlparse, parse_qs

import node
from blockchain import Blockchain, proof_of_work
from wallet import Wallet


class EasyChain(Blockchain):
    INITIAL_TARGET = 2 ** 256 // 2 ** 6
    MAX_TARGET = 2 ** 256 // 2 ** 4


def mine(bc, address, ts):
    block = bc.build_candidate_block(address, 50)
    block.timestamp = ts
    bc.accept_block(proof_of_work(block))


miner, other = Wallet(), Wallet()
base = time.time() - 7000
# The fork test_security_hardening.py builds: 10 shared blocks, then a
# heavier 21-block chain and a longer-but-lighter 22-block one.
heavy, light = EasyChain(), EasyChain()
for k in range(1, 11):
    mine(heavy, miner.address, base + k)
light.adopt_chain(list(heavy.chain))
for k in range(11, 22):
    mine(heavy, miner.address, base + k)
for k in range(11, 23):
    mine(light, other.address, base + 10 + 600 * (k - 10))
assert heavy.chain_work(heavy.chain) > light.chain_work(light.chain) and len(light.chain) > len(heavy.chain)


class Peer:
    """Answers like node.py's own routes, from a chain of its own."""

    def __init__(self, chain, old=False, work=None):
        self.chain, self.old, self.work, self.asked = chain, old, work, []

    def get(self, url, headers=None, timeout=None):
        u = urlparse(url)
        q = {k: int(v[0]) for k, v in parse_qs(u.query).items()}
        self.asked.append((u.path, q))
        start, limit = q.get("start", 0), min(q.get("limit", node.SYNC_PAGE), node.SYNC_PAGE)
        work = self.work if self.work is not None else self.chain.chain_work(self.chain.chain)
        if u.path == "/chain/hashes" and not self.old:
            return Reply(200, {"length": len(self.chain.chain), "start": start, "chain_work": str(work),
                               "hashes": [b.compute_hash() for b in self.chain.chain[start:start + limit]]})
        if u.path == "/chain/blocks" and not self.old:
            return Reply(200, {"length": len(self.chain.chain), "start": start,
                               "blocks": [b.to_dict() for b in self.chain.chain[start:start + limit]]})
        if u.path == "/chain":
            return Reply(200, {"length": len(self.chain.chain), "chain": [b.to_dict() for b in self.chain.chain]})
        if u.path == "/status":
            return Reply(200, {"chain_work": None if self.old else str(work), "chain_length": len(self.chain.chain)})
        return Reply(404, {"reason": "Not Found"})

    def blocks_fetched(self):
        return sum(q.get("limit", node.SYNC_PAGE) for p, q in self.asked if p == "/chain/blocks")


class Reply:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def json(self):
        return self.body


# Borrowed from the node module and given back at the end: unittest runs
# every test file in ONE process.
_real = (node.save_full_chain, node._sync_from_peer, node.requests.get)
saved_from = []                                # the start each rewrite of the table was asked for
node.save_full_chain = lambda start=0: saved_from.append(start)


def ours(chain):
    """This node, on a copy of `chain`."""
    node.blockchain = EasyChain()
    node.blockchain.adopt_chain(list(chain.chain))
    node._work_cache["key"] = None
    saved_from.clear()


def run(peer, **kw):
    node.requests.get = peer.get
    return node._sync_from_peer("https://peer.example", {}, **kw)


print("=== 1: a heavier peer: only the blocks after the shared one are downloaded ===")
ours(light)
peer = Peer(heavy)
assert run(peer) == "replaced"
assert node.blockchain.latest_block.compute_hash() == heavy.latest_block.compute_hash()
paths = [p for p, _ in peer.asked]
assert "/chain" not in paths, "never the whole chain"
assert [q["start"] for p, q in peer.asked if p == "/chain/blocks"] == [11], "from the block after the shared one"
assert saved_from == [11], "and only those rows are rewritten in the table"
print(f"  asked: {paths}; {len(heavy.chain) - 11} blocks of {len(heavy.chain)} came over, not the chain")

print("\n=== 2: a peer with no more work: one small question, nothing downloaded ===")
ours(heavy)
peer = Peer(light)
assert run(peer) == "kept"
assert [p for p, _ in peer.asked] == ["/chain/hashes"], peer.asked
print("  only the first hash and the work were asked for")

print("\n=== 3: a fork deeper than the window is past the checkpoint: nothing downloaded ===")
ours(light)
window = node.SYNC_HASH_WINDOW
node.SYNC_HASH_WINDOW = 5                      # the shared block (#10) is outside the last 5
peer = Peer(heavy)
assert run(peer) == "kept"
assert peer.blocks_fetched() == 0 and "/chain" not in [p for p, _ in peer.asked]
node.SYNC_HASH_WINDOW = window
print("  hashes compared, no blocks fetched (replace_chain would refuse it anyway)")

print("\n=== 4: a fresh node catches up page by page ===")
node.blockchain = EasyChain()
node._work_cache["key"] = None
saved_from.clear()
page = node.SYNC_PAGE
node.SYNC_PAGE = 7
peer = Peer(heavy)
assert run(peer) == "replaced"
assert len(node.blockchain.chain) == len(heavy.chain)
assert [q["start"] for p, q in peer.asked if p == "/chain/blocks"] == [1, 8, 15]
assert saved_from == [1]
node.SYNC_PAGE = page
print(f"  {len(heavy.chain) - 1} blocks in pages of 7")

print("\n=== 5: an old peer (no /chain/hashes) is read in full only at startup ===")
ours(light)
peer = Peer(heavy, old=True)
assert run(peer) == "old-peer"
assert "/chain" not in [p for p, _ in peer.asked], "the loop, gossip and /nodes/resolve never pull a whole chain"
assert run(peer, allow_full=True) == "replaced", "startup still can"
assert saved_from == [0], "a whole chain read is a whole rewrite"
print("  skipped by default; read in full with allow_full (startup)")

print("\n=== 6: a peer that claims more work but serves a chain the rules refuse ===")
ours(light)
liar = Peer(light, work=10 ** 30)              # the same lighter chain, a made-up claim
assert run(liar) in ("rejected", "kept")
assert node.blockchain.latest_block.compute_hash() == light.latest_block.compute_hash(), "our chain is untouched"
print("  refused; our chain stays")

print("\n=== 7: the two-minute loop backs off from a refused chain, and skips old peers ===")
clock = [1000.0]
real_time, real_sleep = node.time.time, node.time.sleep   # node.time IS the time module: restored below
node.time.time = lambda: clock[0]
calls = []
node._sync_from_peer = lambda peer, headers, allow_full=False: (calls.append(peer), "rejected")[1]
status = {"chain_work": str(10 ** 30)}
node.requests.get = lambda url, timeout=None, headers=None: Reply(200, status)
node._peer_retry_at.clear(); node._peer_backoff_s.clear()


class Stop(Exception):
    pass


def tick():
    """One pass of peer_sync_loop, 120 s after the last."""
    clock[0] += 120
    sleeps = []

    def sleep(_):
        sleeps.append(1)
        if len(sleeps) > 1:
            raise Stop
    node.time.sleep = sleep
    node.peers.clear(); node.peers.add("https://peer.example")
    try:
        node.peer_sync_loop()
    except Stop:
        pass


tick()
assert len(calls) == 1 and node._peer_backoff_s["https://peer.example"] == 240, "refused: wait 4 minutes"
tick()
assert len(calls) == 1, "not asked again two minutes later"
tick()
assert len(calls) == 2 and node._peer_backoff_s["https://peer.example"] == 480, "then 8"
for _ in range(60):
    tick()
assert node._peer_backoff_s["https://peer.example"] == node.SYNC_BACKOFF_MAX_S, "capped at an hour"
calls.clear()
status = {"chain_length": 10 ** 6}             # an old peer: no work reported
node._peer_retry_at.clear(); node._peer_backoff_s.clear()
tick()
assert calls == [], "an old peer is never synced from the loop, however long"
node.time.time, node.time.sleep = real_time, real_sleep
print("  4, 8 ... 60 minutes after a refusal; old peers skipped")

print("\n=== 8: the routes a peer reads ===")
node.blockchain = EasyChain()
node.blockchain.adopt_chain(list(heavy.chain))
node._work_cache["key"] = None
client = node.app.test_client()
h = client.get("/chain/hashes?start=5&limit=3").get_json()
assert h["length"] == len(heavy.chain) and h["start"] == 5 and h["hashes"] == [b.compute_hash() for b in heavy.chain[5:8]]
assert int(h["chain_work"]) == heavy.chain_work(heavy.chain)
b = client.get("/chain/blocks?start=19&limit=10").get_json()
assert [x["index"] for x in b["blocks"]] == list(range(19, len(heavy.chain))), "clipped at the tip"
assert len(client.get("/chain/hashes?limit=100000").get_json()["hashes"]) <= node.SYNC_PAGE
assert client.get("/chain/blocks?start=x").status_code == 400
print("  /chain/hashes and /chain/blocks serve slices, capped")

node.save_full_chain, node._sync_from_peer, node.requests.get = _real
node.blockchain = node.Blockchain()

print("\n=== ALL PEER SYNC SCENARIOS PASSED ===")
