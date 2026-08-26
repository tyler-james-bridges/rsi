# Build roadmap

The active [single-machine production contract](./production-readiness/README.md) controls live
authority. RSI uses the owner's existing Mac and adds capability in small, supervised steps. No
stage silently enables the next one, and all activation limits default to zero or unset.

## Stage 0 — Reset and local verification

Status: **complete**

- [x] Public TypeScript monorepo with exact runtime and lockfile pins.
- [x] Strict evidence, policy, strategy, and NFT-intent schemas.
- [x] Frozen policy kernel, durable spend/duplicate ledger, and EIP-712 intent digest.
- [x] Hostile-content quarantine, adversarial fixtures, tamper-evident SQLite events, and offline
      provider contracts.
- [x] Loopback operator UI and disabled state-changing adapters.
- [x] Retire the hardware-dependent readiness ceremony and replace it with the single-machine
      contract.
- [x] Add a persisted runtime mode: `STOPPED → RESEARCH → PROPOSE_ONLY`. Startup defaults to
      `STOPPED`, and STOP is checked at every authority boundary.
- [x] Show findings, exact assets, provenance, scam flags, abstentions, and candidate-strategy
      scorecards in the local dashboard.

Exit: normal CI passes and RSI can run locally without credentials, funds, or additional hardware.

## Stage 1 — Live research and proposals

Status: **X READ_CANARY commissioned; OpenSea READ_CANARY implementation complete and uncommissioned**

- [x] Build the signer-blind X read-canary path with a fixed query, dual one-shot authorization,
      durable singleton claim, Keychain isolation, encrypted capture, sanitized receipt, STOP races,
      operator UI, and a dedicated authority-graph gate.
- [x] Commission one authenticated X read canary and retain its content-free receipt. The
      2026-08-25 run issued exactly one GET with no retry or pagination, accepted 10 posts, verified
      raw-capture deletion, and returned to `STOPPED`; it did not approve continuous collection.
- [x] Build and verify the fixed OpenSea source contract, one-shot collector, isolated Keychain
      boundary, exact dispatch provenance, and encrypt-first ingestion/recovery path without a
      credential or provider request.
- [x] Add the supervised OpenSea singleton controller, STOP-guarded completion, verified deletion
      before receipt, storage-only recovery, loopback operator, and dedicated authority-graph gate.
- [ ] Separately authorize and commission the one Base trending-collections read, then retain and
      inspect its content-free receipt without promoting continuous collection.
- [ ] Build and separately commission the Base RPC read.
- Re-check current official documentation, authentication, pricing, schemas, and deployed addresses
  immediately before each bounded canary.
- Keep raw provider content inside quarantine and persist only typed, provenance-rich evidence.
- Add opportunity scoring, outcome labels, source information-lift measurement, and explicit
  abstention reasons.
- Keep all wallet, payment, and transaction authority absent.

Exit: RSI produces useful live NFT proposals and can be stopped durably, but cannot spend or sign.

## Stage 2 — AgentCash/x402 paid research

- Use a dedicated software wallet account on the same Mac with only a deliberately small USDC
  balance.
- Add one closed AgentCash/x402 adapter with approved origin and endpoint lists, quote inspection,
  per-call and daily caps, attempt limits, timeout, response-size limit, and durable reservations.
- Require user approval for the first call to every provider and retain exact quote, payment, and
  response receipts.
- Never install a tool or obey instructions discovered in provider content.

Exit: one approved paid read finishes within its declared cap and demonstrates measurable research
value. No custom payment contract is deployed.

## Stage 3 — Human-confirmed NFT execution

- Use a separate, deliberately low-balance software wallet account; never use a primary wallet.
- Launch on Base with approved OpenSea secondary orders only. Exclude arbitrary mints, approvals,
  bridges, withdrawals, and provider-supplied calldata.
- Bind one-shot approval to the exact typed-intent digest. Independently rebuild, decode, simulate,
  and revalidate ownership, code, order state, price, fees, and expiry before prompting the wallet.
- Display the exact chain, contract, token ID, seller, recipient, consideration, fees, gas ceiling,
  and expiry. The user confirms every transaction in the wallet's native UI.
- Enforce transaction, position, gas, failed-transaction, daily-loss, and drawdown limits plus the
  persisted STOP state. Reconcile holdings, receipts, costs, and realized P&L.

Exit: one tiny supervised purchase and manual exit reconcile correctly. RSI still holds no signing
key.

## Stage 4 — Optional bounded automation

- Consider ERC-4337 only after supervised results justify it.
- Require audited account permissions enforcing Base-only use, exact targets and selectors,
  approved assets and recipients, short expiry, per-transaction and cumulative limits, and immediate
  human revocation.
- Keep the human wallet as owner and recovery authority. If the account cannot enforce every
  restriction, remain at human confirmation.

Exit: one tiny pre-approved autonomous canary completes without bypassing local or account-level
controls.

## Stage 5 — Public service and optional connectors

- Register ERC-8004 only after RSI has a stable public service endpoint. Identity and reputation are
  evidence, never transaction authority.
- Publish ERC-8257 tools only when an individual tool provides concrete user value.
- Offer provenance-rich monitoring or risk reports through x402 before broader financial products.
- Treat Robinhood Agent, Trading, Banking, and Chain surfaces as detachable adapters. Start
  read-only and route any later action through the same typed-intent, cap, STOP, and human-approval
  path. Defer banking and card access.

Exit: each connector can be disabled without affecting the evidence store, onchain wallet, or other
agents.

## Immediate next work

Re-check the official OpenSea endpoint, authentication, account limits, rate-limit receipt, and
response schema immediately before commissioning. No OpenSea API key creation, access, or provider
request is authorized or has occurred. Request separate authorization for that first bounded read,
inspect its content-free receipt, and keep continuous collection quarantined; then add Base RPC.
Keep proposal persistence behind `PROPOSE_ONLY`; only after proposals are useful should the owner
choose an expendable research-wallet balance for one AgentCash/x402 call.
