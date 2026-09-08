# RSI

**Recursive Self-Improvement — a research system that learns from every bounded run.**

RSI also carries two useful secondary meanings:

- **Relative Strength Index:** the market-native reference.
- **Research → Signal → Iterate:** the operating loop.

RSI researches markets, converts adversarial internet activity into typed evidence, measures its own work, and improves under explicit promotion gates. Its active production path is supervised and single-machine: begin with live research and proposals on the owner's existing Mac, then add narrowly bounded capabilities one at a time. No additional computer or signing device is required.

> [!WARNING]
> RSI is pre-alpha code. Exactly one bounded X `READ_CANARY` was commissioned successfully on
> 2026-08-25, but no continuously enabled live adapter, wallet integration, transaction builder, or
> wallet signer exists. The repository does not connect financial accounts, sign orders, or send
> transactions. Keep credentials and funds out until the relevant stage in the
> [production path](docs/production-readiness/README.md) is explicitly configured and verified.

> [!NOTE]
> RSI is a public project developed in the public
> [`tyler-james-bridges/rsi`](https://github.com/tyler-james-bridges/rsi)
> repository. Public project and source visibility do not expose operational data
> or grant live authority. The workspace's `"private": true` package metadata only
> prevents accidental npm publication. No open-source license has been selected yet;
> adding one is a separate owner decision.

## What exists now

- Strict schemas for observations, claims, NFT purchase intents, policies, and mutable strategies.
- EIP-712 typed-data hashing for transaction intents.
- A frozen policy kernel that checks chain/target/collection/payment/recipient allowlists, source and capture freshness, independent evidence, exact marketplace order evidence, per-transaction/daily limits, and duplicate intent IDs/nonces.
- A restart-safe policy ledger whose state is bound to the exact policy hash and whose authorization step is serialized across SQLite writers.
- A bounded quarantine pipeline for synthetic X, OpenSea, and onchain fixtures. Raw hostile text is reduced to typed observations and never enters the event log or policy kernel.
- Exact asset correlation by `(chainId, contract, tokenId)`, coordination clustering, prompt-injection flags, and deterministic adversarial scenarios.
- A transactional SQLite event store with idempotent appends and a SHA-256 hash chain that detects edits, reordering, and tail deletion.
- Portable Ed25519-signed event-store checkpoints in a separate hash-linked journal. An independently retained journal head can detect journal rollback or suffix deletion.
- An ephemeral AES-256-GCM capture vault with opaque random IDs, per-capture data keys, encrypted metadata, authenticated deletion tombstones, expiry sweeps, and crash recovery. Raw captures—including malformed responses—have no forensic-retention exception.
- A read-only X recent-search collector with an exact ten-result contract, strict query/response schemas, bounded transport, two independent one-shot authorizations (runtime plus durable attempt), clock-regression checks, and offline replay. One credentialed canary has validated that bounded path; the collector remains quarantined from continuous operation.
- An encrypt-first X ingestion boundary that keeps hostile bytes ephemeral while persisting only closed, content-free projections.
- A production-shaped, offline-verified OpenSea read-canary path for one fixed Base-only GET. Its durable singleton controller retains the authentic runtime authorization through STOP-guarded completion, verifies capture deletion before a content-free receipt, and recovers without the API key or egress. The collector cannot retry, paginate, redirect, pay, sign, or trade; no OpenSea request has been commissioned.
- A production-shaped, offline-verified Base RPC read-canary path for one fixed Alchemy batch containing only `eth_chainId` and `eth_getBlockByNumber("finalized", false)`. It accepts only Base Mainnet and a strict fresh provider-reported finalized block, encrypts bytes before parsing, deletes the capture before a content-free receipt, and recovers without credentials, a collector, or egress. No Alchemy credential has been accessed and no Base RPC request has been commissioned.
- A durable operations ledger for hard paid-request budgets, exact operation/amount bindings, and encrypted cursor advancement gated by safe events, checkpoints, external anchors, and independent verification.
- A profile-bound encrypted capture registry with exact-attempt retry binding, per-attempt keys, content-free deletion records, and restart reconciliation.
- A signed external-anchor protocol and authenticated publication outbox with retention-policy binding, rollback detection, and offline provider simulations. No real remote immutable-storage adapter is configured.
- A strict supervised-session lifecycle with deterministic acknowledgement windows, crash invalidation, cost gating, trusted-head rollback detection, and content-free acceptance evidence.
- A content-free alert outbox with bounded delivery attempts, trusted-head recovery, and profile separation. No Resend or Healthchecks adapter is configured.
- Three recovery components: signed state evidence, a restorable sanitized event archive, and a restorable signed release/code/runbook bundle. A genuine-store controller verifies their exact cross-bindings and local closure facts before advancing lifecycle state. Off-host encrypted backup and remote retention remain optional operator deployments.
- A deterministic clean-tree source inventory for ordinary reviewed GitHub releases. It does not sign, tag, publish, or require a separate release device or custom release key.
- An optional read-only compatibility preflight that reports runtime and host facts without reading secret values or changing the host. Its earlier all-provider profile is not a staged-readiness verdict.
- A signer-blind, SQLite-backed Stage 0 runtime with exact `STOPPED`, `RESEARCH`, and `PROPOSE_ONLY` modes. Every process boot persists a new STOP, transitions use compare-and-swap revisions, STOP is universal, and one-shot boundary authorizations are invalidated by any transition or restart.
- A separate typed research ledger for non-executable proposal scorecards. It accepts only a genuine `proposal_persist` authorization in `PROPOSE_ONLY`, rejects raw or executable fields, and exposes exact assets, provenance, scam flags, bounded scores, candidates, and abstentions.
- A loopback-only operator dashboard/API with fixed same-origin assets, defensive headers, strict runtime/research projections, and closed Stage 0 controls. STOP remains independently available when another dashboard read fails.
- An optional Stage 1 X read-canary operator with a code-owned query, durable singleton claim, fixed one-request/ten-result/$0.05 ceiling, macOS Keychain boundary, STOP-linearized dispatch/completion, encrypted raw capture, verified crypto-shredding before receipt, and credential-free/no-egress restart recovery. Its single authenticated canary completed successfully on 2026-08-25 and returned to `STOPPED`.
- A separate optional OpenSea read-canary operator with a fixed Base trending-collections plan, one-request/ten-result/no-payment acknowledgements, its own Keychain account, the same STOP/deletion/recovery guarantees, and a dedicated executable authority-graph gate. It remains uncommissioned.
- A separate optional Base RPC read-canary operator with a fixed Base Mainnet finalized-anchor plan, one-request/two-read-method/no-payment acknowledgements, its own Keychain account, the same STOP/deletion/recovery guarantees, and a dedicated executable authority-graph gate. It remains uncommissioned.
- Permanent Keychain one-shot claim markers shared by no provider credential. X operator startup now requires a presence-only marker for its historical completed receipt; a separate exact-plan, receipt-verifying migration CLI can create that marker only after an explicitly authorized Keychain action. New OpenSea and Base claims are consumed before their provider credential is revealed.
- An executable module-graph gate proving the active runtime/operator path cannot reach policy approval, adapters, wallets, signers, AgentCash/x402, transaction, deployment, or arbitrary-call code. Payment, signing, execution, broadcast, policy approval, and publication are explicit permanent denials in Stage 0.
- A signed, content-free public receipt/correction/tombstone chain with explicit approval, a 24-hour delay, retained-head rollback detection, and a browser-safe fail-closed verifier. It has no deployment or publication adapter.
- Legacy synthetic OpenSea Get Order/Stream fixtures and offline finalized Base/Robinhood Chain request contracts. The OpenSea fixtures have no transport, credentials, or live-schema status and remain quarantined from the new REST-only canary build; the chain contracts retain strict block-pinned ownership/code and runtime/proxy bindings.
- An executable offline drill gate that runs the full suite and demos while denying external destinations at the Node process boundary. This is an application test control, not an operating-system network sandbox or provider canary.
- A recursive-improvement state machine that requires adversarial testing, a bounded live canary, and evaluation before promotion.
- Capability-separated interfaces for X, AgentCash/x402, OpenSea, Base/Robinhood chain reads, Robinhood Trading, Robinhood Banking, and a Robinhood Chain ERC-4337 wallet. X, OpenSea, and Base RPC now have narrowly bounded read-only transports, but only the single X canary has been commissioned; every state-changing adapter is disabled.
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
pnpm ci:stage1
pnpm ci:opensea
pnpm ci:base-rpc
pnpm ci:release
```

`pnpm demo` exercises the original in-memory policy decision. `pnpm demo:pipeline` runs five recorded scenarios through quarantine, typed extraction, correlation, durable events, and policy evaluation. `pnpm demo:ingestion` runs an entirely offline X cassette through encrypted snapshot storage, a sanitized event, and a signed checkpoint. All demos use fictional data and cannot execute anything.

`pnpm ci:release` runs only on a clean committed tree. It generates a deterministic inventory of
tracked source and verifies every recorded Git object and content hash. Running the verifier twice
must produce the same result. It does not sign, tag, or publish; normal reviewed GitHub CI and
GitHub tags/releases provide the release path.

To start the local Stage 0 operator:

```bash
pnpm operator

# In another terminal:
curl http://127.0.0.1:8787/api/runtime
curl http://127.0.0.1:8787/api/research
curl http://127.0.0.1:8787/api/summary
curl 'http://127.0.0.1:8787/api/events?limit=20'
```

The operator service binds to IPv4 loopback and has no network authentication. Do not expose it to a network. Every launch begins in persisted `STOPPED`; the dashboard can enter research, enter proposal-only mode, de-escalate, or STOP, but it has no financial authority. Its development-only runtime and research databases live under `.local/stage0/`; the command refuses canonical Stage 1 storage namespaces before creating or opening a path. Stop it with `Ctrl-C`, which persists STOP before closing.

The production-shaped Stage 1 host is `pnpm operator:x-canary`. It also boots `STOPPED` and cannot
sign, pay, trade, publish, or paginate. Its local data directory must be owner-only (`0700`), which
startup verifies before reading credentials or reporting readiness. Starting the host alone makes
no X request. The durable singleton canary was consumed successfully on 2026-08-25; that result does
not authorize resetting its state or issuing another request. See the
[commissioning record](docs/production-readiness/evidence/x-read-canary-2026-08-25.md).

The production-shaped OpenSea host is `pnpm operator:opensea-canary`. It uses a separate local data
directory and Keychain account, boots `STOPPED`, and cannot pay, sign, trade, publish, follow a
cursor, or select another request. Starting it alone makes no OpenSea provider request. The durable
singleton remains unclaimed; creating or reading its API key and issuing the first live request
require a separate commissioning authorization.

The production-shaped Base host is `pnpm operator:base-rpc-canary`. It uses separate canonical
owner-only storage and a separate Keychain account, boots `STOPPED`, and cannot select a provider,
URL, method, block tag, fallback, payment, signer, or transaction. Starting it alone makes no Base
RPC provider request. The durable and permanent singleton claims remain unclaimed; creating or
reading its Alchemy credential and issuing the one live request require a separate commissioning
authorization.

## Repository map

```text
apps/cli             Stage 0 operator plus isolated offline demos
apps/operator        Loopback dashboard/API and closed local lifecycle controls
packages/domain      Runtime schemas and EIP-712 intent format
packages/runtime     Persisted signer-blind Stage 0 mode and boundary authority
packages/research-ledger Typed non-executable proposal scorecards
packages/policy      Non-self-modifying authorization kernel
packages/engine      Recursive strategy proposal/promotion loop
packages/adapters    Capability catalog and disabled execution interfaces
packages/research    Quarantine, extraction, clustering, fixture corpus
packages/store       Transactional tamper-evident SQLite event log
packages/pipeline    Durable recorded-fixture orchestration
packages/checkpoints Portable signed store-head journal and verifier
packages/vault       Ephemeral encrypted capture storage and crypto-shredding
packages/x-collector Quarantined X recent-search live/replay client
packages/opensea-collector Fixed one-shot Base trending-collections client
packages/base-rpc-collector Fixed one-shot Base Mainnet finalized-anchor client
packages/ingestion   Isolated encrypt-first X, OpenSea, and Base RPC safe-event boundaries
packages/read-canary Separate durable one-shot X, OpenSea, and Base RPC coordinators
packages/credential-host Separate fixed macOS Keychain boundaries for read canaries
packages/capture-registry Profile-bound encrypted ephemeral capture index
packages/operations  Paid-attempt budgets and verified encrypted cursors
packages/preflight   Optional compatibility host and credential-presence checks
packages/alerts      Content-free offline incident-delivery outbox
packages/external-anchor Signed checkpoint-anchor protocol and offline outbox
packages/session-lifecycle Supervised session state and acceptance evidence
packages/session-controller Verified recovery-to-lifecycle composition
packages/public-projection Signed content-free public receipt chain and browser verifier
packages/source-contracts Live-wire OpenSea trending, legacy fixtures, and offline finalized-chain contracts
packages/backup      Signed sanitized state-evidence component
packages/event-archive Restorable signed sanitized event history
packages/release-bundle Restorable signed source/config/runbook release
docs/                Architecture, threat model, standards, charter, roadmap
```

Start with the active [single-machine production path](docs/production-readiness/README.md). The broader [architecture](docs/architecture.md), [live-capital charter](docs/live-capital-charter.md), and [roadmap](docs/roadmap.md) defer to that contract wherever they conflict.

## Core law

**X and every other external source create hypotheses. They never create transaction authority.**

Any future paid-read and execution stages use two separate, deliberately low-balance software wallet accounts on the existing Mac: one for research payments and one for execution. Neither may be a primary personal wallet, and the owner confirms every transaction in the wallet's own UI.

## Current limits

- X recent-search has a credential-injected live implementation, a production-shaped one-shot operator path, and an offline synthetic replay path. The single 2026-08-25 canary validated exactly one ten-result request with no retry or pagination; it did not approve a continuously enabled adapter. The request deliberately used only the minimum `id`/`text` response and no optional field dialect. There is no live recording/cassette mode.
- OpenSea now has a production-shaped but uncommissioned one-shot path for `GET https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10`. Offline tests cover the singleton claim, retained runtime authorization, STOP races, deletion-before-receipt, storage-only recovery, operator process, and static authority graph. This work has not created, accessed, or used an OpenSea API key; whether the owner already has one is unknown. No OpenSea provider request has been made or authorized. Orders, Stream, wallets, payment, x402, policy approval, and execution are excluded; legacy Get Order/Stream schemas remain synthetic-only and quarantined.
- Base RPC now has a separate production-shaped but uncommissioned one-shot path for one fixed Alchemy `POST` batch. Offline tests cover strict Base/freshness parsing, exact runtime and durable-attempt authorization, singleton and permanent claims, STOP races, deletion-before-receipt, statically collector-free storage-only recovery, operator process, and the authority graph. This work has not created, accessed, or used an Alchemy credential and made no Base RPC request. The one provider-reported `finalized` response is not independent canonical-chain proof. Robinhood Chain remains an offline request/fixture contract with no provider credential or live-schema claim.
- Signed checkpoints and the external-anchor protocol can authenticate an event-store head, retention policy, and independently pinned suffix. This build still has no real remote immutable-storage adapter or scoped publication credential, so the offline simulations are not independent storage evidence.
- Policy spend/replay state survives a clean reopen, and SQLite serializes concurrent writers that share one database file. Separate database copies have no distributed coordinator and must never act as parallel execution authorities.
- The X ingestion path encrypts exact response bytes and metadata before typed parsing, binds retries through the encrypted capture registry, destroys collector-owned raw copies, and reconciles pending or orphaned capture state after restart. The successful one-shot canary did not move the adapter out of quarantine; continuous collection requires a separate promotion decision.
- Recovery files can be created and verified in three closed components, and the local controller consumes their genuine verification reports. Encrypted off-host backup, remote immutable retention, and a same-Mac restore drill are not yet commissioned.
- The complete test suite and offline drills pass when invoked with the pinned Node 24.19.0 toolchain. Host preflight remains diagnostic: it does not provision or prove provider credentials, live schemas, wallet confirmation, or operational recovery. The Stage 0 runtime now provides the persisted local STOP control; later authority stages must integrate and re-test that boundary independently.
- `node:sqlite` may emit an experimental-feature warning on supported Node releases.
- There is no wallet, transaction signer, transaction builder, AgentCash payment, x402 request, Robinhood connection, or live-capital path in this build. All current signing code is limited to optional offchain integrity evidence; none can authorize a payment or transaction.
