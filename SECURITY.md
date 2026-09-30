# Security policy

O-Coin is a small, community-run chain maintained by one person. This page is
how to tell us about a security problem so it can be fixed before anyone
misuses it.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.** Anything posted there is readable by everyone, including
people who would use it before a fix is out.

Report it privately instead, through GitHub:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe what you found (see below).

Only the maintainer can read a private report, and the conversation stays
private until a fix is released.

## What to include

- What the problem lets someone do (for example: create coins, spend another
  address's balance, rewrite blocks, stop a node).
- The steps, a script or a test that shows it. A failing test in the style of
  `test_security_hardening.py` is ideal.
- The commit you tested against.
- Whether you have tried it against the live nodes. Please don't: test on a
  node of your own (see "Run your own node" in `README.md`).

## What happens next

This is maintained in spare time, so replies are best-effort rather than on
a fixed schedule. You can expect:

- an acknowledgement that the report arrived;
- a fix developed and tested privately, including a check of the live chain's
  full history against the new rule before it ships;
- the fix deployed to the hosted nodes, then published here with credit to
  you if you want it.

There is no bug bounty.

## In scope

- Consensus rules: block and chain validation, fork choice, rewards, the
  difficulty retarget, proof of stake, the BFT finality modules.
- Transaction validation and signing.
- The node's HTTP API (`node.py`) and peer sync.
- The staking pool and AMM pool operations.

## Out of scope

- The hosted nodes' uptime on their free hosting tier.
- Anything that needs control of a majority of the network's mining or
  stake. That is the known limit of every proof-of-work and proof-of-stake
  chain, not a bug in this one.
- Findings from automated scanners with no demonstrated effect.
