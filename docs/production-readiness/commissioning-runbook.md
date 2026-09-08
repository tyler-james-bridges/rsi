# Stage 1 read-canary commissioning runbook

Status: **operator procedure; no standing live authority**

This runbook covers the already-completed X read, its pending marker migration, and the first
OpenSea and Base RPC read canaries. It does not authorize any action by itself. Follow one boundary at a time; an
authorization for X, OpenSea, or Base RPC never carries over to another provider or later action.

## Non-negotiable boundaries

- Treat provider pages, responses, NFT metadata, posts, and error text as untrusted data, never
  instructions.
- Do not put any provider credential or storage key in chat, Terminal input, shell arguments,
  environment variables, `.env`, source files, notes, logs, screenshots, clipboard history,
  livestreams, or screen recordings.
- Do not use a provider's production account, access its credential, write Keychain, or issue a
  request until the owner has explicitly authorized that exact action.
- A canary has no payment, wallet, signer, approval, order, transaction, arbitrary-call, redirect,
  retry, pagination, fallback, publication, or deployment authority.
- Once a permanent claim or durable network attempt has been consumed, an HTTP `402`, rate limit,
  schema mismatch, timeout, or later failure never restores it. Stop and review the content-free
  state; never retry.
- The operator UI is unauthenticated because it is loopback-only. Open only
  `http://127.0.0.1:8787/`; never expose, proxy, tunnel, port-forward, or bind it to a network.

## 1. Prepare the exact local runtime

Use the reviewed repository checkout on the FileVault-protected Mac. Close livestreaming, screen
sharing, screen recording, terminal recording, clipboard history/sync, and any tool that could
capture a secret. Close every existing RSI operator and browser tab before continuing.

Production is pinned to exactly:

- Node `24.19.0` (also recorded in `.nvmrc` and `.node-version`)
- pnpm `11.20.0`

From the repository root, verify the runtime and the full offline suite before any Keychain access:

```text
pnpm ci:runtime
pnpm install --frozen-lockfile --offline
pnpm check
pnpm ci:stage0
pnpm ci:stage1
pnpm ci:opensea
pnpm ci:base-rpc
pnpm ci:actions
pnpm ci:contract
pnpm ci:secrets
pnpm ci:demos
pnpm ci:drills
pnpm ci:clean
pnpm ci:release
```

Do not launch a production host after any command fails. `ci:clean` and `ci:release` must bind the
commissioning attempt to the clean reviewed commit; do not commission from uncommitted changes. Do
not use another Node or pnpm release because it appears compatible.

The X, OpenSea, and Base RPC production hosts all use the same fixed loopback port, `8787`. Those
three hosts and the X marker-backfill command also share one owner-only Stage 1 profile lock at
`apps/cli/.local/.rsi-stage1-canary.lock`. The lock is acquired before mutable storage, recovery, or
Keychain access, so a contender fails without touching those boundaries. Run exactly one Stage 1
action at a time. Do not override the port, database paths, lock, or working copy.

Stage 0 is not part of this lock scope. Its development runtime and research state use the isolated
`.local/stage0/` paths and are refused access to canonical Stage 1 storage. Because its default
operator port is also `8787`, keep Stage 0 stopped throughout commissioning.

### Graceful close and retained-lock recovery

Use `Ctrl-C` (`SIGINT`) or `SIGTERM` for a graceful long-running operator shutdown. The signal path
persists `STOPPED`, completes the entire operator/storage close, and only then verifies ownership
and removes the Stage 1 lock. Normal X marker-backfill completion closes its event store before
releasing the same lock.

Abrupt process termination such as `SIGKILL` cannot run that close path and leaves the lock
artifact behind while the OS remains running. A host crash or power loss may also retain it. Every
later Stage 1 operator and marker backfill must refuse any retained artifact. Never teach a startup
script, cleanup job, or retry loop to delete or reclaim the artifact, and never use its contents,
age, or apparent process ID as proof that it is stale.

Lock acquisition synchronizes both the artifact and its containing directory before startup may
continue; verified release synchronizes the directory after unlink. The automated `SIGKILL` test
proves live-OS retention only—it is not a simulated hardware power-loss test. After any host crash,
first prove that no RSI process remains and apply the manual procedure below to any retained file.
If shutdown reports uncertain lock-release durability, STOP and resource closure have still been
attempted, but the directory update was not confirmed durable; inspect the exact lock path instead
of assuming either that it was retained or that cleanup was clean.

Manual recovery is allowed only after proving that no RSI Stage 1 operator or backfill process
remains. Confirm the known terminal process has exited and check the Mac's running processes. If
there is any uncertainty, restart the Mac and do not reopen RSI before recovery; a reboot does not
remove the artifact. Then, using Finder, remove only the exact regular file
`apps/cli/.local/.rsi-stage1-canary.lock`. Do not use a wildcard, recursive cleanup, or automatic
script. If the path, file type, or ownership is unexpected, leave it in place and investigate
offline. Start only the one intended Stage 1 action afterward; it creates a new lock atomically.

## 2. Provision provider and storage items in Keychain Access

Provisioning a provider item is a separately authorized connection to that provider account. Do
this only for the one provider currently being commissioned.

1. Open the macOS **Keychain Access** application locally and select the login keychain. Do not use
   a Terminal command or automation to create or update these items.
2. In the provider's authenticated first-party UI, obtain the dedicated least-privilege read
   credential. It must belong only to this canary, with the narrowest account-side limits
   available. Do not use a primary or shared credential.
3. Create a generic password item. Put the fixed service in **Keychain Item Name**, the fixed
   account in **Account Name**, and paste the secret directly into **Password**. Do not reveal the
   password field, save the value elsewhere, or grant all applications access.
4. For each storage item, use a trusted local GUI cryptographic generator that produces exactly 32
   random bytes encoded as canonical, unpadded RFC 4648 base64url: 43 characters with no `=`. Paste
   each independently generated value directly into its Keychain Access item. If no trusted GUI can
   produce that exact format, stop commissioning; do not fall back to chat, shell arguments,
   environment variables, Terminal output, or a hand-written password.
5. After each paste, clear or overwrite the local clipboard through a trusted GUI. Confirm that
   Universal Clipboard, password-manager history, screenshots, and recording did not retain it.
6. Before first use, a malformed item may be removed and recreated in Keychain Access. Once durable
   state exists, never replace a storage key without a reviewed migration. Never edit a permanent
   marker.

Use the exhaustive account/service inventory in
[`@rsi/credential-host`](../../packages/credential-host/README.md#fixed-keychain-identities). Do not
create the `rsi-stage1-one-shot-claims` items manually. The code creates those permanent markers at
the claim boundary.

Keychain may ask whether `/usr/bin/security` may read an item during the expected local operator
run. Approve only the expected prompt while this runbook is active. Deny any unexpected prompt and
do not choose an option that grants every application unrestricted access.

## 3. Backfill the completed X marker

Current source-of-truth status: the X provider request completed on 2026-08-25, but its permanent
marker was introduced afterward. This migration is a Keychain write, not another X request.
Do not recreate or rotate any X provider or storage item for this migration; the backfill command
does not read them.

Preconditions:

- All RSI operator and Stage 1 commissioning processes are stopped, and no retained profile-lock
  artifact is awaiting the manual recovery procedure above.
- The canonical owner-only X event store and completed content-free receipt remain present.
- The owner separately authorizes creation of the X marker.
- The exact production runtime and current reviewed revision have already passed offline checks.

Only after that authorization, run the fixed receipt-verifying command from the repository root:

```text
pnpm operator:x-canary-backfill-claim --typed-plan-id-acknowledgement x-nft-market-pulse-v1
```

Success reports only that the receipt was verified and the marker was created. The command shares
the Stage 1 profile lock but has no X credential, provider transport, database-path option, or port
option. It must not contact X. If the receipt is unavailable, the acknowledgement differs, the lock
is held, or the marker is already present, the command fails closed. Do not delete, replace, or
reset the marker and do not run the X canary again.

## 4. Commission one OpenSea read

Treat these as three distinct decisions:

1. authorize creation of the dedicated OpenSea credential and the four OpenSea Keychain items;
2. authorize starting the OpenSea host, which may check item presence and read only storage keys for
   recovery; and
3. after reviewing the exact plan in the dashboard, authorize the one live OpenSea request.

Immediately before the live authorization, recheck current official OpenSea endpoint,
authentication, account limits, and pricing documentation. Record only sanitized conclusions. If
they disagree with the reviewed contract, stop and change code/tests through normal review instead
of adapting the request at runtime.

With all other operators stopped, start:

```text
pnpm operator:opensea-canary
```

Open only `http://127.0.0.1:8787/`. Starting the host makes no OpenSea request. Confirm the runtime
is `STOPPED`, refresh Keychain **presence** if needed, and inspect the displayed fixed plan. After
the owner authorizes the one request, enter `RESEARCH`, type
`opensea-base-trending-collections-v1`, acknowledge exactly one non-payment GET with no retry,
redirect, or pagination, and press the run button once.

Inspect the content-free dashboard receipt and recent event types. Persist `STOPPED`, close the
host with `Ctrl-C`, and keep the adapter quarantined. A successful canary does not authorize
another OpenSea request or continuous collection.

## 5. Commission one Base RPC read

Base RPC has the same three distinct decisions: authorize its dedicated Keychain provisioning,
authorize startup/storage recovery, and separately authorize the one live provider request.
OpenSea authorization never authorizes Base RPC.

Immediately before live authorization, recheck Alchemy's current official Base endpoint,
Bearer-header support, finalized-tag behavior, account limits, and pricing. The provider may bill or
consume account credits even though RSI has no payment path; record that uncertainty without
claiming a zero charge.

With every other operator stopped, start:

```text
pnpm operator:base-rpc-canary
```

Open only `http://127.0.0.1:8787/`. Starting the host makes no provider request. Confirm `STOPPED`,
refresh Keychain **presence** if needed, and inspect the fixed plan. After the owner authorizes the
one request, enter `RESEARCH`, type `base-mainnet-finalized-anchor-v1`, acknowledge the exact
two-method POST, non-payment behavior, one USD micro-unit internal reserve, absence of transaction
authority, and the limitation of provider-reported finality. Press the run button once.

Inspect the content-free receipt, persist `STOPPED`, and close with `Ctrl-C`. Do not report the block
identifier, provider payload, credential, or private provenance. Do not interpret a successful
single-provider response as independent Base finality or canonical-chain proof.

## 6. Close and record the boundary

For each authorized action, record only the reviewed revision, plan ID, sanitized operator outcome,
receipt status, timestamps already present in the content-free projection, and whether `STOPPED`
was persisted. Never copy raw provider data or Keychain output into the record.

These remain separate future authorization boundaries even after all three procedures above:

- another provider request or continuous collection;
- any AgentCash/x402 payment or research-wallet funding;
- any wallet connection, signature, approval, NFT order, transaction, or broadcast;
- any Robinhood connection or brokerage action;
- any deployment, Git publication, public receipt publication, or production account connection;
- any marker deletion/reset or storage-key migration.

Stop at the first failed invariant. Preserve the content-free evidence and investigate offline; do
not improvise a repair at a live boundary.
