# Contributing to O-Coin

Thanks for looking. O-Coin is MIT-licensed, and anything you contribute is
released under the same licence.

To run a node of your own, see "Run your own node / join the live network"
in `README.md`. If you have found a security problem, don't open an issue:
follow `SECURITY.md`.

## Getting set up

```
pip install -r requirements.txt
python wallet.py            # a throwaway wallet for local testing
python node.py --port 5100  # a local node, not connected to the live network
```

## Running the tests

The tests are plain Python scripts. Each one runs its scenarios when it is
imported, prints what it checked, and stops at the first failure.

These run anywhere, with no database and no network. CI runs them on every
push:

```
python test_amm_pools.py
python test_stake_pool.py
python test_pool_history.py
python test_security_hardening.py
```

These are slower, because the pure-Python BLS fallback takes minutes:

```
python test_bft_finality.py
python test_bft_consensus.py
python test_bft_accountability.py
python test_bft_onchain_stake.py
python test_bft_node.py
```

`test_balance_index.py` and `test_multiasset.py` re-validate a real chain
read from Postgres. They need a `DATABASE_URL` in `.env` and skip without
one. `test_live_network.py` needs running nodes.

## Changing consensus rules

A consensus rule decides which blocks every node accepts. A mistake there
can split the network or reject history that is already on the chain, and
real balances depend on that history. So a change to validation, rewards,
difficulty or fork choice needs:

1. **A test** that shows the new rule refusing what it should refuse and
   still accepting the honest case next to it.
2. **A check against the live chain's full history.** Fetch the chain from
   a node's `/chain` endpoint and run the new rule over every block. If any
   existing block breaks the rule, the rule has to start at a future block
   height (see `TX_SCHEMA_ACTIVATION_HEIGHT` for how that is done) rather
   than apply from genesis.
3. **A note in the pull request** saying which of the two it is, and what
   the history check found.

Consensus changes are merged and deployed deliberately, never as a side
effect of another change.

## Style

- Comments explain *why*, not what. Most of this codebase reads as a
  walkthrough; please keep it that way.
- Keep documentation technical. Describe what the software does, not what
  anyone might gain from holding the coin.
- Never commit a private key, a `.env` file or a node secret.
  `.gitignore` covers the usual names; check `git status` before you commit.
