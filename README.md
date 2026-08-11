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
- A frozen policy kernel that checks chain/target/collection/payment/recipient allowlists, source and capture freshness, independent evidence, exact marketplace order evidence, per-transaction/daily limits, and duplicate intent IDs/nonces.
- A restart-safe policy ledger whose state is bound to the exact policy hash and whose authorization step is serialized across SQLite writers.
- A bounded quarantine pipeline for recorded X, OpenSea, and onchain fixtures. Raw hostile text is reduced to typed observations and never enters the event log or policy kernel.
- Exact asset correlation by `(chainId, contract, tokenId)`, coordination clustering, prompt-injection flags, and deterministic adversarial scenarios.
- A transactional SQLite event store with idempotent appends and a SHA-256 hash chain that detects edits, reordering, and tail deletion.
- A loopback-only, read-only operator API with pagination, query validation, security headers, and recursive sensitive-field redaction.
- A recursive-improvement state machine that requires adversarial testing, a bounded live canary, and evaluation before promotion.
- Capability-separated interfaces for X, AgentCash/x402, OpenSea, Robinhood Trading, Robinhood Banking, and a Robinhood Chain ERC-4337 wallet. All are disabled placeholders.
- Regression and integration tests for the first hard invariants, database reopen behavior, tamper detection, hostile fixtures, and the real HTTP boundary.

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
pnpm demo:pipeline
```

`pnpm demo` exercises the original in-memory policy decision. `pnpm demo:pipeline` runs five recorded scenarios through quarantine, typed extraction, correlation, durable events, and policy evaluation. Both use fictional assets and cannot execute anything.

To seed a local database and inspect its read-only API:

```bash
pnpm operator:demo

# In another terminal:
curl http://127.0.0.1:8787/api/summary
curl 'http://127.0.0.1:8787/api/events?limit=20'
```

The operator service binds to IPv4 loopback and has no authentication. Do not expose it to a network. Its default database is `.local/rsi.sqlite`, which is gitignored. Stop it with `Ctrl-C`.

## Repository map

```text
apps/cli             Safe local policy-decision demo
apps/operator        Read-only loopback HTTP boundary
packages/domain      Runtime schemas and EIP-712 intent format
packages/policy      Non-self-modifying authorization kernel
packages/engine      Recursive strategy proposal/promotion loop
packages/adapters    Capability boundaries; no live implementations yet
packages/research    Quarantine, extraction, clustering, fixture corpus
packages/store       Transactional tamper-evident SQLite event log
packages/pipeline    Durable recorded-fixture orchestration
docs/                Architecture, threat model, standards, charter, roadmap
```

Start with [the architecture](docs/architecture.md), [the live-capital charter](docs/live-capital-charter.md), and [the roadmap](docs/roadmap.md).

## Core law

**X and every other external source create hypotheses. They never create transaction authority.**

## Current limits

- The sources are recorded fixtures, not live X, marketplace, or RPC connections.
- The event chain is tamper-evident, not tamper-proof. Its head metadata lives in the same database; external signed or write-once anchoring is still required to detect wholesale database replacement.
- Policy spend/replay state survives a clean reopen, and SQLite serializes concurrent writers that share one database file. Separate database copies have no distributed coordinator and must never act as parallel execution authorities.
- Raw fixture bytes are deliberately not persisted by the integrated pipeline. A future isolated snapshot vault must be added before live collection.
- `node:sqlite` may emit an experimental-feature warning on supported Node releases.
- There is no wallet, signer, transaction builder, AgentCash payment, x402 request, Robinhood connection, or live-capital path in this build.
