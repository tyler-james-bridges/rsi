# RSI

**Recursive Self-Improvement — a research system that learns from every bounded run.**

RSI also carries two useful secondary meanings:

- **Relative Strength Index:** the market-native reference.
- **Research → Signal → Iterate:** the operating loop.

RSI researches markets, converts adversarial internet activity into typed evidence, measures its own work, and improves under explicit promotion gates. The first production contract is **Observer v1**: private, supervised, read-only research with no capital authority. The longer-term execution architecture remains a separate, unapproved roadmap.

> [!WARNING]
> RSI is pre-alpha foundation code. State-changing adapters are disabled; paid collectors are quarantined and have not passed credentialed live canaries. The repository does not connect financial accounts, sign orders, or send transactions. Do not provision credentials until every Observer v1 readiness gate passes.

## What exists now

- Strict schemas for observations, claims, NFT purchase intents, policies, and mutable strategies.
- EIP-712 typed-data hashing for transaction intents.
- A frozen policy kernel that checks chain/target/collection/payment/recipient allowlists, source and capture freshness, independent evidence, exact marketplace order evidence, per-transaction/daily limits, and duplicate intent IDs/nonces.
- A restart-safe policy ledger whose state is bound to the exact policy hash and whose authorization step is serialized across SQLite writers.
- A bounded quarantine pipeline for recorded X, OpenSea, and onchain fixtures. Raw hostile text is reduced to typed observations and never enters the event log or policy kernel.
- Exact asset correlation by `(chainId, contract, tokenId)`, coordination clustering, prompt-injection flags, and deterministic adversarial scenarios.
- A transactional SQLite event store with idempotent appends and a SHA-256 hash chain that detects edits, reordering, and tail deletion.
- Portable Ed25519-signed event-store checkpoints in a separate hash-linked journal. An independently retained journal head can detect journal rollback or suffix deletion.
- An ephemeral AES-256-GCM capture vault with opaque random IDs, per-capture data keys, encrypted metadata, authenticated deletion tombstones, expiry sweeps, and crash recovery. Raw captures—including malformed responses—have no forensic-retention exception.
- A read-only X recent-search collector with an exact ten-result contract, strict query/response schemas, bounded transport, durable one-shot cost authorization, clock-regression checks, and offline replay. It remains quarantined pending a real credentialed canary.
- An encrypt-first X ingestion boundary that keeps hostile bytes ephemeral while persisting only closed, content-free projections.
- A durable operations ledger for hard paid-request budgets, exact operation/amount bindings, and encrypted cursor advancement gated by safe events, checkpoints, external anchors, and independent verification.
- A profile-bound encrypted capture registry with exact-attempt retry binding, per-attempt keys, content-free deletion records, and restart reconciliation.
- A signed external-anchor protocol and authenticated publication outbox with retention-policy binding, rollback detection, and offline provider simulations. No real B2 adapter or bucket is configured.
- A strict supervised-session lifecycle with deterministic acknowledgement windows, crash invalidation, cost gating, trusted-head rollback detection, and content-free acceptance evidence.
- A content-free alert outbox with bounded delivery attempts, trusted-head recovery, and profile separation. No Resend or Healthchecks adapter is configured.
- Three closed recovery components: signed state evidence, a restorable sanitized event archive, and a restorable signed release/code/runbook bundle. A genuine-store controller verifies their exact cross-bindings and local closure facts before advancing lifecycle state; physical two-copy restore remains pending.
- A read-only production preflight that fails closed on runtime, host, credential-presence, clock, wake-session, and environment-isolation requirements without reading secret values or changing the host.
- A loopback-only operator dashboard/API with fixed same-origin assets, defensive headers, recursive sensitive-field redaction, and a closed set of local lifecycle controls. Without an authenticated control provider it remains read-only.
- A signed, content-free public receipt/correction/tombstone chain with explicit approval, a 24-hour delay, retained-head rollback detection, and a browser-safe fail-closed verifier. It has no deployment or publication adapter.
- Offline OpenSea REST/Stream and finalized Base/Robinhood Chain request contracts with strict normalized fixtures, exact asset/order correlation, block-pinned ownership/code checks, and explicit runtime/proxy code bindings. They have no transport or credentials.
- An executable Stage A drill gate that runs the full suite and offline demos while denying external destinations at the Node process boundary. This is an application test control, not an operating-system network sandbox or provider canary.
- A recursive-improvement state machine that requires adversarial testing, a bounded live canary, and evaluation before promotion.
- Capability-separated interfaces for X, AgentCash/x402, OpenSea, Robinhood Trading, Robinhood Banking, and a Robinhood Chain ERC-4337 wallet. Only the read-only X collector has an implementation, and it remains quarantined; every state-changing adapter is disabled.
- Regression and integration tests for the first hard invariants, database reopen behavior, tamper detection, hostile fixtures, and the real HTTP boundary.

```text
bounded read ticket → untrusted provider bytes → encrypted ephemeral capture
                                               ↓
                                  closed typed safe event
                                               ↓
                     local checkpoint → external anchor → independent verify
                                               ↓
                         private evaluation → gated strategy proposal
```

## Run it

Requirements: exactly Node.js 24.19.0 and pnpm 11.20.0.

```bash
pnpm install
pnpm check
pnpm demo
pnpm demo:pipeline
pnpm demo:ingestion
pnpm ci:drills
pnpm ci:release
```

`pnpm demo` exercises the original in-memory policy decision. `pnpm demo:pipeline` runs five recorded scenarios through quarantine, typed extraction, correlation, durable events, and policy evaluation. `pnpm demo:ingestion` runs an entirely offline X cassette through encrypted snapshot storage, a sanitized event, and a signed checkpoint. All demos use fictional data and cannot execute anything.

`pnpm ci:release` runs only on a clean committed tree. It classifies every tracked file into the
closed release inventory and validates the resulting source/config/runbook/SBOM/test-summary
candidate. It does not sign or publish a release; the retained CI receipts and separate MacBook
release key are required for that later step.

To seed a local database and inspect its read-only API:

```bash
pnpm operator:demo

# In another terminal:
curl http://127.0.0.1:8787/api/summary
curl 'http://127.0.0.1:8787/api/events?limit=20'
```

The operator service binds to IPv4 loopback and has no network authentication. Do not expose it to a network. The root page serves its fixed local dashboard; a server without a genuine lifecycle-control provider exposes no control actions. Its default database is `.local/rsi.sqlite`, which is gitignored. Stop it with `Ctrl-C`.

## Repository map

```text
apps/cli             Safe local policy-decision demo
apps/operator        Loopback dashboard/API and closed local lifecycle controls
packages/domain      Runtime schemas and EIP-712 intent format
packages/policy      Non-self-modifying authorization kernel
packages/engine      Recursive strategy proposal/promotion loop
packages/adapters    Capability catalog and disabled execution interfaces
packages/research    Quarantine, extraction, clustering, fixture corpus
packages/store       Transactional tamper-evident SQLite event log
packages/pipeline    Durable recorded-fixture orchestration
packages/checkpoints Portable signed store-head journal and verifier
packages/vault       Ephemeral encrypted capture storage and crypto-shredding
packages/x-collector Quarantined X recent-search live/replay client
packages/ingestion   Encrypt-first X snapshot and safe event boundary
packages/capture-registry Profile-bound encrypted ephemeral capture index
packages/operations  Paid-attempt budgets and verified encrypted cursors
packages/preflight   Read-only production-host and credential-presence checks
packages/alerts      Content-free offline incident-delivery outbox
packages/external-anchor Signed checkpoint-anchor protocol and offline outbox
packages/session-lifecycle Supervised Observer session state and acceptance evidence
packages/session-controller Verified recovery-to-lifecycle composition
packages/public-projection Signed content-free public receipt chain and browser verifier
packages/source-contracts Offline OpenSea/Stream/finalized-chain request contracts
packages/backup      Signed sanitized state-evidence component
packages/event-archive Restorable signed sanitized event history
packages/release-bundle Restorable signed source/config/runbook release
docs/                Architecture, threat model, standards, charter, roadmap
```

Start with the normative [Observer v1 production-readiness contract](docs/production-readiness/v1/README.md). The broader [architecture](docs/architecture.md), [live-capital charter](docs/live-capital-charter.md), and [roadmap](docs/roadmap.md) describe later, non-authorized work and defer to Observer v1 wherever they conflict.

## Core law

**X and every other external source create hypotheses. They never create transaction authority.**

## Current limits

- X recent-search has a credential-injected live implementation and an offline synthetic replay path, but no real credential was used and upstream X documentation is currently inconsistent about response-field terminology. There is no live recording/cassette mode. Until a credentialed canary validates the pinned contract, the adapter remains quarantined.
- Marketplace and chain packages now define exact offline request and normalized-response contracts for OpenSea, Base, and Robinhood Chain. They deliberately contain no HTTP/WebSocket/RPC transport, provider credential, retry policy, or live-schema claim; separately approved canaries must validate current provider behavior before adapters can be commissioned.
- Signed checkpoints and the external-anchor protocol can authenticate an event-store head, retention policy, and independently pinned suffix. This build still has no real B2 adapter, bucket, write-only credential, or MacBook verifier deployment, so the offline simulations are not independent storage evidence.
- Policy spend/replay state survives a clean reopen, and SQLite serializes concurrent writers that share one database file. Separate database copies have no distributed coordinator and must never act as parallel execution authorities.
- The X ingestion path encrypts exact response bytes and metadata before typed parsing, binds retries through the encrypted capture registry, destroys collector-owned raw copies, and reconciles pending or orphaned capture state after restart. A real credentialed canary and session-close orchestration remain prohibited until the broader Observer readiness gates pass.
- Recovery files can now be created and verified in three closed components, and the local controller consumes their genuine verification reports. RSI does not yet have the production command that assembles them from one accepted session and writes/verifies both approved physical copies.
- The complete test suite and Stage A drills pass when invoked with the pinned Node 24.19.0 toolchain. Host preflight still correctly reports this Mac as not production-ready: the dedicated standard account, host hardening, independent clock references, bounded wake evidence, and isolated Keychain credentials remain unprovisioned.
- `node:sqlite` may emit an experimental-feature warning on supported Node releases.
- There is no wallet, transaction signer, transaction builder, AgentCash payment, x402 request, Robinhood connection, or live-capital path in this build. The only signing code signs offchain event-store checkpoints.
