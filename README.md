# RSI

**Recursive Self-Improvement — a live economic agent that learns from every move.**

RSI also carries two useful secondary meanings:

- **Relative Strength Index:** the market-native reference.
- **Research → Signal → Iterate:** the operating loop.

RSI researches markets, converts adversarial internet activity into provenance-bearing evidence, proposes bounded actions, and learns from the results. A deterministic safety kernel—not the learning agent—owns transaction eligibility.

> [!WARNING]
> RSI is pre-alpha foundation code. Every external adapter is disabled. The repository does not currently hold keys, connect accounts, pay for APIs, sign orders, or send transactions.

## What exists now

- Strict schemas for observations, claims, NFT purchase intents, policies, and mutable strategies.
- EIP-712 typed-data hashing for transaction intents.
- A frozen policy kernel that checks allowlists, evidence freshness and independence, canonical marketplace evidence, per-transaction/daily limits, and duplicate intent IDs.
- A recursive-improvement state machine that requires adversarial testing, a bounded live canary, and evaluation before promotion.
- Capability-separated interfaces for X, AgentCash/x402, OpenSea, Robinhood Trading, Robinhood Banking, and a Robinhood Chain ERC-4337 wallet. All are disabled placeholders.
- Regression tests for the first hard invariants.

```text
X / paid APIs / marketplace / onchain reads
                    │ untrusted bytes
                    ▼
       quarantine → typed evidence graph
                    ▼
               mutable strategy
                    ▼ unsigned intent
       deterministic policy kernel
                    ▼ PolicyApproval only
           exclusive execution adapter
                    ▼
       receipts → evaluator → candidate patch
                    ▼
 adversarial replay → live canary → promote/rollback
```

## Run it

Requirements: Node.js 24+ and pnpm 11+.

```bash
pnpm install
pnpm check
pnpm demo
```

The demo uses fictional addresses and an in-memory policy. It evaluates an intent but cannot execute it.

## Repository map

```text
apps/cli             Safe local policy-decision demo
packages/domain      Runtime schemas and EIP-712 intent format
packages/policy      Non-self-modifying authorization kernel
packages/engine      Recursive strategy proposal/promotion loop
packages/adapters    Capability boundaries; no live implementations yet
docs/                Architecture, threat model, standards, charter, roadmap
```

Start with [the architecture](docs/architecture.md), [the live-capital charter](docs/live-capital-charter.md), and [the roadmap](docs/roadmap.md).

## Core law

**X and every other external source create hypotheses. They never create transaction authority.**
