# RSI

**Recursive Self-Improvement — a live economic agent that learns from every move.**

RSI also carries two useful secondary meanings:

- **Relative Strength Index:** the market-native reference.
- **Research → Signal → Iterate:** the operating loop.

RSI researches markets, converts adversarial internet activity into provenance-bearing evidence, proposes bounded actions, and learns from the results. A deterministic safety kernel—not the learning agent—owns transaction eligibility.

> [!WARNING]
> RSI is pre-alpha foundation code. State-changing and paid adapters are disabled; the X collector is quarantined and has not passed a credentialed live canary. The repository does not connect accounts, pay for APIs, sign orders, or send transactions.

## What exists now

- Strict schemas for observations, claims, NFT purchase intents, policies, and mutable strategies.
- EIP-712 typed-data hashing for transaction intents.
- A frozen policy kernel that checks chain/target/collection/payment/recipient allowlists, source and capture freshness, independent evidence, exact marketplace order evidence, per-transaction/daily limits, and duplicate intent IDs/nonces.
- A restart-safe policy ledger whose state is bound to the exact policy hash and whose authorization step is serialized across SQLite writers.
- A bounded quarantine pipeline for recorded X, OpenSea, and onchain fixtures. Raw hostile text is reduced to typed observations and never enters the event log or policy kernel.
- Exact asset correlation by `(chainId, contract, tokenId)`, coordination clustering, prompt-injection flags, and deterministic adversarial scenarios.
- A transactional SQLite event store with idempotent appends and a SHA-256 hash chain that detects edits, reordering, and tail deletion.
- Portable Ed25519-signed event-store checkpoints in a separate hash-linked journal. An independently retained journal head can detect journal rollback or suffix deletion.
- A content-addressed AES-256-GCM snapshot vault that encrypts raw bytes and metadata, fails closed on tampering, and keeps hostile content outside the event/operator boundary.
- A read-only X recent-search collector with a pinned API contract, strict query/response schemas, bounded transport, credential injection, and in-memory record/replay. It remains quarantined pending a real credentialed canary.
- An encrypt-first X ingestion boundary that archives malformed responses for forensics while persisting only bounded, text-free projections.
- A loopback-only, read-only operator API with pagination, query validation, security headers, and recursive sensitive-field redaction.
- A recursive-improvement state machine that requires adversarial testing, a bounded live canary, and evaluation before promotion.
- Capability-separated interfaces for X, AgentCash/x402, OpenSea, Robinhood Trading, Robinhood Banking, and a Robinhood Chain ERC-4337 wallet. Only the read-only X collector has an implementation, and it remains quarantined; every state-changing adapter is disabled.
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
pnpm demo:ingestion
```

`pnpm demo` exercises the original in-memory policy decision. `pnpm demo:pipeline` runs five recorded scenarios through quarantine, typed extraction, correlation, durable events, and policy evaluation. `pnpm demo:ingestion` runs an entirely offline X cassette through encrypted snapshot storage, a sanitized event, and a signed checkpoint. All demos use fictional data and cannot execute anything.

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
packages/adapters    Capability catalog and disabled execution interfaces
packages/research    Quarantine, extraction, clustering, fixture corpus
packages/store       Transactional tamper-evident SQLite event log
packages/pipeline    Durable recorded-fixture orchestration
packages/checkpoints Portable signed store-head journal and verifier
packages/vault       Encrypted content-addressed raw snapshot storage
packages/x-collector Quarantined X recent-search live/record/replay client
packages/ingestion   Encrypt-first X snapshot and safe event boundary
docs/                Architecture, threat model, standards, charter, roadmap
```

Start with [the architecture](docs/architecture.md), [the live-capital charter](docs/live-capital-charter.md), and [the roadmap](docs/roadmap.md).

## Core law

**X and every other external source create hypotheses. They never create transaction authority.**

## Current limits

- X recent-search has a credential-injected live/record implementation, but no real credential was used and upstream X documentation is currently inconsistent about response-field terminology. Until a credentialed canary validates the pinned contract, the adapter remains quarantined. Marketplace and RPC sources are still recorded fixtures only.
- Signed checkpoints can authenticate an event-store head and a separately retained trusted journal head can expose journal rollback. This build does not publish that head to an independent service or write-once medium, so the demo alone does not protect against wholesale replacement of the database, journal, and local trusted-head state together.
- Policy spend/replay state survives a clean reopen, and SQLite serializes concurrent writers that share one database file. Separate database copies have no distributed coordinator and must never act as parallel execution authorities.
- The new X ingestion path encrypts exact response bytes and metadata before typed parsing. The recorded-fixture policy pipeline still stores bounded capture metadata rather than its fixture files. The demo uses an ephemeral vault key; production key custody, rotation, backup, and recovery are not implemented.
- `node:sqlite` may emit an experimental-feature warning on supported Node releases.
- There is no wallet, transaction signer, transaction builder, AgentCash payment, x402 request, Robinhood connection, or live-capital path in this build. The only signing code signs offchain event-store checkpoints.
