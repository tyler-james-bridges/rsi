# Build roadmap

Each phase produces evidence that unlocks the next. “Live” begins with bounded canaries; no phase silently grants broader authority.

## Phase 0 — Foundation

Status: **complete as a non-executing local foundation**

- TypeScript monorepo and local CLI.
- Strict evidence, policy, strategy, and NFT-intent schemas.
- Frozen policy kernel and spend/duplicate ledger.
- EIP-712 intent digest.
- Recursive candidate strategy state machine.
- Disabled integration interfaces and initial adversarial tests.
- Architecture, threat model, standards profile, and live-capital charter.

Exit: `pnpm check` passes and the declared prohibited intents are rejected.

## Phase 1 — Provenance-first research

Status: **offline provenance and quarantined X ingestion complete through Build Session 3; production live reads remain unapproved**

- [x] Transactional SQLite event store with an integrity chain, retry idempotency, reopen verification, and tail-deletion detection.
- [x] Bounded quarantine capture and strict recorded X/OpenSea/onchain fixture schemas.
- [x] Typed observation extraction, source-observed timestamps, instruction-risk flags, URL normalization, stable-author coordination clustering, and exact asset/order correlation.
- [x] Durable end-to-end runs covering safe, prompt-injection, coordinated-shill, stale-evidence, and contract-substitution cases.
- [x] Read-only local operator API showing integrity, evidence lineage, decisions, and abstentions without raw hostile text.
- [x] Portable Ed25519-signed event-log checkpoints with an independent journal and verifier.
- [ ] Publish or retain the newest trusted checkpoint head in an independently controlled system and test backup/recovery.
- [x] Separate content-addressed AES-256-GCM snapshot vault with encrypted metadata and adversarial filesystem tests.
- [x] Credential-injected, read-only X recent-search collector with pinned transport/schema and offline record/replay fixtures.
- [ ] Run a credentialed X canary in a network-isolated process, reconcile the current official documentation dialect, and approve or revise the pinned contract.
- [ ] Authenticated OpenSea and chain read adapters with recorded replay fixtures.
- [ ] Stable-account history, edit tracking, exact proxy/deployer resolution, and wash-trade/funding graphs.
- [ ] A richer local UI; the current operator surface is JSON HTTP plus CLI.

Exit: recorded adversarial corpus produces zero policy escapes; no state-changing credentials exist.

## Phase 2 — AgentCash and x402 research economy

- AgentCash discovery adapter with tool quarantine.
- ERC-8257 manifest/origin/hash verification and SSRF defenses.
- x402 quote validator for network, token, payee, amount, nonce, deadline, redirects, retries, and budgets.
- Provider calibration and “unique information lift minus total cost” evaluation.
- First RSI-owned paid research endpoint, initially in settlement-disabled development mode.

Exit: capped paid-read flow is reproducible with sanitized quote/receipt evidence and cannot call state-changing catalog tools.

## Phase 3 — NFT execution

- Select exactly one launch chain after confirming activity, liquidity, official deployments, and provider support.
- Existing ERC-4337 smart account with expiring session permission.
- Pinned OpenSea/Seaport adapter that rebuilds, decodes, simulates, and revalidates orders.
- Human-approved live transaction followed by a tiny autonomous canary restricted to approved secondary collections.
- Reconciliation, public accounting, drawdown watchdog, and kill sequence.

Exit: a live purchase and exit complete inside the charter with exact receipts and zero policy bypasses.

## Phase 4 — Public agent and tool business

- ERC-8004 registration with MCP/OASF/x402 service metadata.
- ERC-8257 publication of narrowly scoped RSI tools.
- Sell provenance-rich market observations, risk checks, or monitoring—not unsupported financial promises.
- Reputation filtered to trusted counterparties and independently verifiable receipts.

Exit: RSI earns its first attributable service revenue and accounts for it separately from trading P&L.

## Phase 5 — Optional Robinhood surfaces

- Robinhood Trading MCP behind the same policy-intent gateway, using a dedicated Agentic account.
- Research and `review_*` calls before any supported limit order.
- Banking MCP only for an approved non-x402 checkout workflow.
- Keep all-account brokerage reads and virtual-card data out of model memory, streams, and public logs.

Exit: the optional connector can be disconnected without affecting RSI's onchain wallet, evidence graph, or other agents.

## Near-term next session

Externally retain/publish the checkpoint journal head, run the X collector's credentialed network-isolated canary, and add authenticated OpenSea plus chain read adapters with encrypted record/replay snapshots. Keep every paid and state-changing capability disabled.
