"""node.py's /status says which code a node runs and how much work its chain
holds, and peer_sync_loop fetches a peer's chain when it claims MORE WORK --
the same measure replace_chain decides by -- not merely a longer chain
(2026-09-30). No database and no network: the Flask test client, and a fake
peer answering one sync tick at a time.
"""
import os

os.environ["RENDER_GIT_COMMIT"] = "0246c69cdabc0000"

import node  # noqa: E402

print("=== 1: /status carries the rules version, the deployed commit and the chain's work ===")
s = node.app.test_client().get("/status").get_json()
assert s["version"] == {"rules": node.Blockchain.RULES_VERSION, "commit": "0246c69"}, s["version"]
assert isinstance(s["chain_work"], str), "a string, so a JavaScript reader cannot round it"
assert int(s["chain_work"]) == node.blockchain.chain_work(node.blockchain.chain)
print("  ", s["version"], "chain_work", s["chain_work"])

print("\n=== 2: peer sync looks at a peer that claims more work, and only then ===")
resolves = []
node._resolve_with_peers = lambda: resolves.append(1)
answer = {}


class Reply:
    def json(self):
        if isinstance(answer["body"], Exception):
            raise answer["body"]
        return answer["body"]


node.requests.get = lambda url, timeout=None: Reply()


class StopLoop(Exception):
    pass


def one_tick(body):
    """Runs peer_sync_loop for exactly one pass against one fake peer."""
    resolves.clear()
    answer["body"] = body
    node.peers.clear()
    node.peers.add("https://peer.example")
    sleeps = []

    def sleep(_):
        sleeps.append(1)
        if len(sleeps) > 1:
            raise StopLoop

    node.time.sleep = sleep
    try:
        node.peer_sync_loop()
    except StopLoop:
        pass
    return bool(resolves)


ours = node._our_chain_work()
assert one_tick({"chain_work": str(ours + 1), "chain_length": 1}) is True, "more work at the same length: fetch it"
assert one_tick({"chain_work": str(ours), "chain_length": 10 ** 6}) is False, "longer but no more work: leave it"
assert one_tick({"chain_length": 5}) is True, "a peer too old to report work falls back to length"
assert one_tick({"chain_length": 1}) is False
assert one_tick(ValueError("an HTML error page")) is False, "a junk answer is skipped"
assert one_tick({"chain_work": "not-a-number"}) is False
print("  more work -> fetched; longer-but-lighter -> ignored; old peers -> by length; junk -> skipped")

print("\n=== ALL NODE STATUS/SYNC SCENARIOS PASSED ===")
