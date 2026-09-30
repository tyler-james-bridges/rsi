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
- [x] Run five closed recorded scenarios through quarantine, evidence-derived abstention scoring,
      genuine `PROPOSE_ONLY` authorization, durable proposal persistence, and the local dashboard.
      Recorded evidence has zero opportunity and cannot become a trade recommendation.

Exit: normal CI passes and RSI can run locally without credentials, funds, or additional hardware.

## Stage 1 — Live research and proposals

Status: **X READ_CANARY commissioned; OpenSea READ_CANARY complete and uncommissioned; Base RPC READ_CANARY complete but commissioning-blocked**

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
- [x] Build the signer-blind Base Mainnet finalized-anchor source, fixed one-batch Alchemy
      collector, isolated Keychain boundary, encrypt-first ingestion, singleton controller,
      storage-only recovery, loopback operator, permanent one-shot claim, and dedicated
      authority-graph gate without a credential or provider request.
- [ ] Separately authorize and commission the one OpenSea Base trending-collections read, then retain and
      inspect its content-free receipt without promoting continuous collection.
- [ ] Separately authorize and commission the one Base Mainnet finalized-anchor read, then retain
      and inspect its content-free receipt without promoting continuous collection.
      Blocked by the 2026-09-07 public-provider-documentation contradiction recorded in the dated
      Base RPC provider-contract review; do not run or claim the one-shot marker until cleared.
- Re-check current official documentation, authentication, pricing, schemas, and deployed addresses
  immediately before each bounded canary. The read-only
  [OpenSea provider-contract evidence, rechecked 2026-09-07](./production-readiness/evidence/opensea-provider-contract-review-2026-09-05.md)
  and
  [Base RPC provider-contract evidence, rechecked 2026-09-07](./production-readiness/evidence/base-rpc-provider-contract-review-2026-09-05.md)
  record the latest checks without commissioning either canary; the Base recheck currently blocks
  its live request.
- Keep raw provider content inside quarantine and persist only typed, provenance-rich evidence.
- [ ] Add live opportunity scoring, outcome labels, source information-lift measurement, and
      explicit abstention reasons. The completed recorded replay deliberately supplies no price or
      return input and therefore always abstains.
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

First migrate the already-completed X canary into the new permanent one-shot claim boundary. The
backfill command must verify the canonical content-free X receipt and exact typed plan ID before it
may create only the missing Keychain marker; it has no provider credential, transport, or path
override. Creating that marker is a separately authorized Keychain action and is not part of an
offline build.

The OpenSea contract was rechecked again on 2026-09-07 without a credential or provider request and
remains eligible for a separately authorized first bounded read. The Base/Alchemy public contract
was also rechecked on 2026-09-07. Its fixed request remains supported, but contradictory provider
response documentation blocks Base commissioning. Keep its strict parser and one-shot marker
untouched until the hold conditions in the provider-contract review are satisfied. Keep proposal
persistence behind `PROPOSE_ONLY`; only after proposals are useful should the owner choose an
expendable research-wallet balance for one AgentCash/x402 call.
