# Build roadmap

Each phase produces evidence that unlocks the next. “Live” begins with bounded canaries; no phase silently grants broader authority.

## Phase 0 — Foundation

Status: **started in Build Session 1**

- TypeScript monorepo and local CLI.
- Strict evidence, policy, strategy, and NFT-intent schemas.
- Frozen policy kernel and spend/duplicate ledger.
- EIP-712 intent digest.
- Recursive candidate strategy state machine.
- Disabled integration interfaces and initial adversarial tests.
- Architecture, threat model, standards profile, and live-capital charter.

Exit: `pnpm check` passes and the declared prohibited intents are rejected.

## Phase 1 — Provenance-first research

- Append-only SQLite event store and content-addressed snapshot store.
- X collector in a network-isolated process.
- OpenSea and chain read adapters.
- Claim extraction, coordination clustering, stable-account history, edit tracking, exact contract resolution, and wash-trade graph.
- Public local dashboard showing hypotheses, evidence lineage, costs, decisions, and abstentions.

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

Build Phase 1's append-only event store and ingest one recorded X fixture plus one canonical marketplace/onchain fixture through the quarantine-to-evidence pipeline.
