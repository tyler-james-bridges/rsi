# Production path

Status: **active single-machine contract**

RSI is built and operated on the computer already available to the owner. **No additional
physical hardware is required.** A second computer, removable media, custom signing ceremony,
hardware wallet, and hardware security key are not launch gates.

This contract supersedes the retired Observer v1 readiness design. That design remains available
in Git history as optional high-assurance research; it is not active policy and cannot block the
steps below.

## Current authority

RSI currently has no live transaction authority. State-changing adapters are disabled, financial
credentials are absent, activation caps are unset, and the operator UI is loopback-only. The first
usable release is **live research and proposals**, not autonomous trading.

## Compatibility components are not gates

The existing preflight, session-lifecycle, session-controller, backup, event-archive,
release-bundle, external-anchor, alerts, and public-projection packages preserve useful optional
high-assurance components from the earlier design. Their `production-observer` profile name and
all-source acceptance equation are versioned compatibility interfaces; they do **not** define or
block the staged activation states below. In particular, a `production-observer` preflight result is
not a readiness verdict for `READ_CANARY`, and no new staged runtime may silently substitute the
legacy all-source closure equation for stage-specific acceptance.

The next runtime must record exactly which single provider and capability were approved for a
canary. Optional recovery or publication components may be added later without expanding that
authority.

## Staged activation

Each stage requires the previous stage to pass. A stage grants only the authority named here.

1. **`LOCAL_VERIFIED`** — exact runtime and lockfile, normal public GitHub CI, offline fixtures,
   adversarial tests, demos, and recovery drills pass on the existing computer.
2. **`READ_CANARY`** — one supervised live read against one explicitly approved provider succeeds.
   No wallet or spend authority is present. Current official provider documentation is checked
   immediately before the canary.
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
- Persist a fail-closed `STOPPED` state and check it before collection, proposal, approval, and
  broadcast. Record approval, payment, transaction, fee, position, and reconciliation receipts.
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

## Next build target

Implement a local `STOPPED → RESEARCH → PROPOSE_ONLY` runtime using the existing quarantine,
evidence, policy, event-store, and operator packages. Commission one supervised read source at a
time. Only after proposals are useful and auditable should the owner fund the tiny research wallet
for one AgentCash/x402 paid read. Capital activation values remain local and unset in source.
