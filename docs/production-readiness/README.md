# Production path

Status: **active single-machine contract**

Operator steps, fixed Keychain identities, and the independent authorization boundaries are in the
[Stage 1 commissioning runbook](./commissioning-runbook.md).

RSI is built and operated on the computer already available to the owner. **No additional
physical hardware is required.** A second computer, removable media, custom signing ceremony,
hardware wallet, and hardware security key are not launch gates.

This contract supersedes the retired Observer v1 readiness design. That design remains available
in Git history as optional high-assurance research; it is not active policy and cannot block the
steps below.

## Current authority

RSI currently has no live transaction authority. State-changing adapters are disabled, financial
credentials are absent, activation caps are unset, and the operator UI is loopback-only. Its
persisted Stage 0 runtime always boots into `STOPPED`; `RESEARCH` and `PROPOSE_ONLY` grant only
one-shot collection and non-executable proposal-persistence boundaries. Payment, signing, policy
approval, execution, broadcast, and publication are permanently denied. Exactly one X
`READ_CANARY` was commissioned successfully on 2026-08-25 and returned to `STOPPED`; it did not
authorize continuous collection or any other provider. OpenSea and Base RPC remain uncommissioned.

## Compatibility components are not gates

The existing preflight, session-lifecycle, session-controller, backup, event-archive,
release-bundle, external-anchor, alerts, and public-projection packages preserve useful optional
high-assurance components from the earlier design. Their `production-observer` profile name and
all-source acceptance equation are versioned compatibility interfaces; they do **not** define or
block the staged activation states below. In particular, a `production-observer` preflight result is
not a readiness verdict for `READ_CANARY`, and no new staged runtime may silently substitute the
legacy all-source closure equation for stage-specific acceptance.

Each Stage 1 coordinator records exactly one code-owned plan, request fingerprint, runtime
authorization, durable attempt, encrypted capture receipt, and terminal sanitized outcome.
Recovery remains a credentialless, storage-only boundary and cannot retry the provider request.
Optional publication components may be added later without expanding that authority.

## Staged activation

Each stage requires the previous stage to pass. A stage grants only the authority named here.

1. **`LOCAL_VERIFIED`** — exact runtime and lockfile, normal public GitHub CI, offline fixtures,
   adversarial tests, demos, and recovery drills pass on the existing computer.
2. **`READ_CANARY`** — one supervised live read against one explicitly approved provider succeeds.
   No wallet or programmable payment authority is present, but the approved provider credential
   may consume prepaid provider credits for this one bounded read. Current official provider
   documentation and account pricing are checked immediately before the canary.
3. **`PAID_READ_CANARY`** — one user-approved AgentCash/x402 request uses a dedicated, deliberately
   low-balance research wallet. Approved origin, endpoint, network, asset, payee, per-call price,
   daily spend, attempts, timeout, and response size are all bounded locally and default to zero or
   unset.
4. **`HUMAN_CONFIRMED_EXECUTION`** — a separate, deliberately low-balance execution wallet may
   submit one exact Base/OpenSea secondary-market intent at a time. RSI independently rebuilds,
   decodes, simulates, and revalidates the order; the owner confirms every transaction in the
   wallet's own UI. Arbitrary calls, mints, approvals, bridges, and withdrawals remain forbidden.
5. **`BOUNDED_AUTOMATION`** — optional later stage. It requires measured supervised results and an
   audited ERC-4337 account permission that enforces exact chain, targets, selectors, assets,
   recipients, expiry, per-transaction and cumulative limits, and immediate human revocation. If
   those restrictions cannot be enforced, RSI remains at human confirmation.

There is no readiness-label ladder beyond these capability states. Missing optional hardening
reduces available authority; it does not create a hardware-purchase requirement.

## Single-machine controls

- Use the existing FileVault-protected Mac, a standard non-administrator runtime account where
  practical, macOS Keychain for credentials, and a loopback-only operator UI.
- Never put credentials, seed phrases, private keys, bearer tokens, or recovery codes in chat,
  Git, `.env` files, logs, screenshots, model context, or provider payloads.
- Never use a primary personal wallet, primary brokerage account, or primary payment card. The
  research and execution wallets are separate software accounts with only expendable balances.
- Keep one durable authorization writer. Activation limits default to zero or unset, and policy,
  allowlists, caps, logs, tests, and emergency controls are outside the self-improvement loop.
- X, OpenSea, Base RPC, and the X marker backfill share one owner-only Stage 1 profile lock acquired
  before storage, recovery, or Keychain access. Stage 0 development state remains isolated under
  `.local/stage0/` and cannot open canonical Stage 1 storage.
- The Stage 0 runtime persists fail-closed `STOPPED`, checks a revision-bound one-shot permit
  before collection or proposal persistence, and records denied attempts. Every future approval,
  payment, signing, execution, and broadcast component must integrate the same STOP boundary and
  retain its own exact receipts before that capability can be commissioned.
- Treat all X posts, webpages, NFT metadata, tool descriptions, manifests, and paid responses as
  hostile content. They may produce typed evidence and hypotheses, never credentials, policy
  changes, tool installation, calldata, or transaction authority.

## Recovery and releases

Source recovery comes from the public Git repository and ordinary GitHub CI. Local operational
state may be copied to a client-side encrypted off-host cloud backup using scoped credentials, then
restored into a fresh temporary directory on the same Mac as a drill. An immutable remote receipt
or retained hash may provide independent tamper evidence. None of these controls requires another
computer or physical media.

Releases use normal reviewed Git commits, green CI, dependency and secret scans, reproducible source
inventory, and ordinary GitHub tags/releases. Custom release keys and signing ceremonies are not
required. Loss of an optional signing key starts a clearly recorded new lineage; it does not require
an offline physical copy.

Graceful Stage 1 `SIGINT`/`SIGTERM` shutdown releases the shared profile lock only after the full
operator close. Abrupt process termination such as `SIGKILL` leaves the artifact fail-closed while
the OS remains running. After a host crash or power loss, any retained artifact receives the same
treatment: it is never auto-deleted or judged stale from its contents. Manual removal requires
first proving that no RSI process remains.
The implementation synchronizes the lock file and containing directory before startup continues;
its `SIGKILL` regression validates live-OS behavior and does not claim to simulate power loss.
Restart the Mac if that proof is uncertain, then remove only the exact
`apps/cli/.local/.rsi-stage1-canary.lock` file according to the
[commissioning runbook](./commissioning-runbook.md).

## Standards order

- AgentCash/x402 paid research comes first and inherits deployed payment infrastructure; RSI
  deploys no payment contract.
- EIP-712 binds exact intents and approvals.
- ERC-4337 is considered only for the optional bounded-automation stage.
- ERC-8004 is useful only after RSI exposes a stable public service endpoint. Identity and
  reputation never grant transaction authority.
- ERC-8257 remains optional until publishing individual tools creates concrete value.
- RSI v0 deploys zero custom contracts.

## Volatile integration rule

X, OpenSea, Base, AgentCash/x402, Robinhood products, ERC deployments, wallet clients, provider
pricing, authentication, schemas, and contract addresses can change. Before any live canary, verify
the current official documentation and deployed addresses, pin the exact accepted contract, and
repeat the bounded canary. Historical notes or social posts are not activation evidence.

## X read-canary commissioning — completed 2026-08-25

The reviewed plan issued exactly one `GET` to
`https://api.x.com/2/tweets/search/recent`, with `max_results=10`, `sort_order=recency`, no
pagination, no retry, and a maximum authorized reservation of 50,000 USD micro-units ($0.05). The
request succeeded with 10 accepted posts and 2,739 response bytes. The response reported a next
page, but it was not requested. Rate-limit remaining changed from 450 to 449. The exact provider
charge remains unknown because no independently verifiable billing receipt was supplied.

The durable attempt closed `succeeded`, the raw-capture key was destroyed, the keyed deletion was
verified before receipt, and the operator returned to `STOPPED`. The complete content-free record
is [X read-canary evidence](./evidence/x-read-canary-2026-08-25.md). This result validates only that
single bounded request. It does not authorize resetting the singleton state, making another X
request, or promoting the collector to continuous operation.

The Stage 1 data directory remains owner-only (`0700`). Credential and storage-key values remain
forbidden in shell history, environment variables, `.env`, chat, Git, screenshots, livestream
output, events, and operator projections. Restart recovery may finish only the already-recorded
content-free result; it has no credential or egress path and cannot retry the provider request.

The permanent Keychain one-shot marker was added after this historical canary completed, so its
marker migration remains uncommissioned. Production X operator startup now fails closed when it
finds a completed receipt without a presence-only marker status of `present`. The dedicated
backfill CLI accepts only the exact typed X plan acknowledgement, verifies the canonical completed
receipt, and can create only the missing marker; it has no provider credential, transport, database
path, or port input. Running that CLI is a separate Keychain action that requires explicit
authorization. The marker is never reset or deleted by RSI.

## OpenSea read-canary implementation — complete but uncommissioned

The fixed candidate contract is plan `opensea-base-trending-collections-v1`, provider
`opensea-api-v2`, and operation
`opensea.trending-collections.v1`: exactly one `GET` to
`https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10`.
It is Base-only, JSON-only, identity-encoded, limited to at most 10 collections, and permits no
retry, redirect, pagination, alternate query, or alternate destination.
The official provider contract was rechecked on 2026-09-05; the sources, verified facts, and RSI's
deliberately narrower acceptance rules are recorded in the
[OpenSea provider-contract review](./evidence/opensea-provider-contract-review-2026-09-05.md).

The reviewed source parser, one-shot dual-authorized collector, separate macOS Keychain boundary,
exact dispatch provenance, encrypt-before-parse ingestion, durable singleton controller,
STOP-guarded completion, verified deletion-before-receipt lifecycle, storage-only restart recovery,
loopback operator, and dedicated executable authority-graph gate with an exact reviewed dashboard
module pin are present and offline-tested.
The public plan and receipt contain no collection slug, contract address, attempt ID, capture ID, or
API key. The one USD micro-unit value is an internal nonzero ledger reserve, not a provider price;
the actual provider charge remains unknown and the controller has no payment path.

This build excludes order and fulfillment endpoints, OpenSea Stream/WebSocket access, wallets,
payments, x402, signing, policy approval, execution, and transaction code. An HTTP 402 response
must fail closed rather than invoke a payment path. The older synthetic Get Order and Stream
fixtures are quarantined historical test contracts, not current live-schema or activation evidence.

This work has not created, accessed, or used an OpenSea API key; whether the owner already has one
is unknown. No OpenSea provider request has been made or authorized.
Credential creation or access and the first live request require separate explicit authorization
after current official documentation, account limits, and RSI's stricter response acceptance
policy have been reviewed. The 2026-09-05 provider-contract review satisfies only that read-only
documentation check; it did not commission the canary. The canary may produce a content-free
commissioning receipt only. Before any later
marketplace observation can become policy-eligible, trusted provenance must bind it to an exact
commissioned endpoint, parser contract, request, capture lifecycle, and freshness proof;
`source.kind = "opensea"` alone is never sufficient.

## Base RPC read-canary implementation — complete but uncommissioned

The fixed candidate contract is plan `base-mainnet-finalized-anchor-v1`: exactly one HTTP `POST`
to `https://base-mainnet.g.alchemy.com/v2`, authenticated only by an
`Authorization: Bearer` header, containing one two-item JSON-RPC batch for `eth_chainId` and
`eth_getBlockByNumber` with `finalized` and `false`. The destination, method, headers, request IDs,
RPC methods, parameters, timeout, response limit, and identity encoding are code-owned. Retry,
redirect, fallback, payment, x402, wallet, signing, transaction, WebSocket, and arbitrary RPC
method paths are absent. An HTTP `402` or `429` is terminal and cannot trigger another request.

The strict source contract accepts only Base Mainnet chain ID `8453` and a reviewed nonzero block
shape returned for the `finalized` tag. It applies a two-hour local freshness limit and labels the
result only `providerReportedFinalized`; one provider response is not independent finality or
canonical-chain proof. Raw response bytes are encrypted before parsing, private block identifiers
remain inside authenticated storage, and verified key deletion precedes the content-free public
receipt. Recovery has a separate static entry point with no collector, credential, or egress
dependency and cannot replay the request.

The singleton controller, permanent one-shot Keychain claim, canonical owner-only storage,
fixed-port loopback operator, production runtime guard, and executable authority-graph gate are
offline-tested. The public dashboard and receipt expose no block number, block hash, parent hash,
JSON-RPC ID, provider header, quota value, raw content, capture ID, attempt ID, or request UUID.
The provider contract, deliberate RSI narrowings, and remaining uncertainties are recorded in the
[Base RPC provider-contract review](./evidence/base-rpc-provider-contract-review-2026-09-05.md).

This work has not created, accessed, or used an Alchemy credential; no Base RPC provider request
has been made or authorized. The strict response shape has therefore not been compared with a live
account response, and current account-specific quota and pricing remain unknown. Credential setup
or access and the one live request require separate explicit authorization immediately after a
fresh official-documentation and account-limit check. A schema mismatch consumes the one-shot
claim and does not retry.

## Next build target

First migrate the historical completed X receipt into the permanent one-shot marker with the
receipt-verifying, typed-plan-acknowledged backfill CLI. Do not run it without separate explicit
authorization for that Keychain write. OpenSea and Base RPC then remain separate, uncommissioned
one-shot reads: each requires its own credential decision, current official-documentation and
account-limit recheck, exact-plan acknowledgement, and explicit live-request authorization. Inspect
each content-free receipt while its adapter remains quarantined. Only after live proposals are
useful and auditable should the owner fund the tiny research wallet for one AgentCash/x402 paid
read. Capital activation values remain local and unset in source.
