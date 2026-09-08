# `@rsi/credential-host`

This package contains the fixed macOS Keychain boundaries for the supervised Stage 1 read
canaries. Provider credentials and authenticated-storage keys are isolated by account. Permanent
one-shot markers use a fourth account that contains no provider credential.

## Export boundaries

| Import                                          | Production authority                                                               |
| ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| `@rsi/credential-host`                          | X credential and storage-key host                                                  |
| `@rsi/credential-host/opensea-trending`         | OpenSea credential and storage-key host                                            |
| `@rsi/credential-host/base-rpc`                 | Base RPC credential and storage-key host                                           |
| `@rsi/credential-host/one-shot-claim`           | Create-once X, OpenSea, and Base RPC marker hosts; contains no provider credential |
| `@rsi/credential-host/testing`                  | X executor/platform substitution for tests only                                    |
| `@rsi/credential-host/opensea-trending-testing` | OpenSea executor/platform substitution for tests only                              |
| `@rsi/credential-host/base-rpc-testing`         | Base RPC executor/platform substitution for tests only                             |
| `@rsi/credential-host/one-shot-claim-testing`   | Marker executor/platform substitution for tests only                               |

Production hosts have zero-argument constructors. Never import a `*-testing` entry into a
production graph.

The production CLI acquires the shared Stage 1 profile lock before it opens mutable storage,
performs recovery, or constructs any of these Keychain hosts. X, OpenSea, Base RPC, and the X
marker backfill all share that lock.

## Fixed Keychain identities

The following inventory is exhaustive. In Keychain Access, **Keychain Item Name** is the service
and **Account Name** is the account.

| Boundary | Account                           | Service                                    | Value purpose                       |
| -------- | --------------------------------- | ------------------------------------------ | ----------------------------------- |
| X        | `rsi-stage1-x-read-canary`        | `dev.rsi.canary.x-read`                    | X bearer token                      |
| X        | `rsi-stage1-x-read-canary`        | `dev.rsi.canary.operations-state`          | operations-state authentication key |
| X        | `rsi-stage1-x-read-canary`        | `dev.rsi.canary.capture-registry`          | capture-registry authentication key |
| X        | `rsi-stage1-x-read-canary`        | `dev.rsi.canary.vault-wrapping`            | capture-wrapping key                |
| OpenSea  | `rsi-stage1-opensea-read-canary`  | `dev.rsi.canary.opensea-read`              | OpenSea API key                     |
| OpenSea  | `rsi-stage1-opensea-read-canary`  | `dev.rsi.canary.operations-state`          | operations-state authentication key |
| OpenSea  | `rsi-stage1-opensea-read-canary`  | `dev.rsi.canary.capture-registry`          | capture-registry authentication key |
| OpenSea  | `rsi-stage1-opensea-read-canary`  | `dev.rsi.canary.vault-wrapping`            | capture-wrapping key                |
| Base RPC | `rsi-stage1-base-rpc-read-canary` | `dev.rsi.canary.alchemy-base-read`         | Alchemy Base API key                |
| Base RPC | `rsi-stage1-base-rpc-read-canary` | `dev.rsi.canary.base-rpc-operations-state` | operations-state authentication key |
| Base RPC | `rsi-stage1-base-rpc-read-canary` | `dev.rsi.canary.base-rpc-capture-registry` | capture-registry authentication key |
| Base RPC | `rsi-stage1-base-rpc-read-canary` | `dev.rsi.canary.base-rpc-vault-wrapping`   | capture-wrapping key                |

X and OpenSea deliberately reuse three service names but remain distinct because their accounts
differ. Base RPC uses both a distinct account and distinct storage service names. Do not rename,
alias, merge, or reuse any item.

Provider values must be nonempty visible ASCII without spaces or control characters. Every storage
value must be an independently generated, canonical, unpadded RFC 4648 base64url encoding of
exactly 32 random bytes: 43 characters and no `=` padding. Storage keys are not passwords and must
not be human-authored or reused. Once a canary has durable state, changing one of its storage keys
without a reviewed migration destroys the ability to authenticate or recover that state.

Permanent markers have account `rsi-stage1-one-shot-claims` and these fixed services:

| Canary   | Marker service                                                 |
| -------- | -------------------------------------------------------------- |
| X        | `dev.rsi.canary.one-shot.x-nft-market-pulse-v1`                |
| OpenSea  | `dev.rsi.canary.one-shot.opensea-base-trending-collections-v1` |
| Base RPC | `dev.rsi.canary.one-shot.base-mainnet-finalized-anchor-v1`     |

**Do not create, update, reset, or delete marker items in Keychain Access.** The create-once claim
host writes the code-owned marker value without an update flag. The historical X receipt requires
the dedicated receipt-verifying backfill command; new OpenSea and Base RPC markers are claimed by
their operator immediately before provider-credential reveal. A present marker is permanent.

## Runtime behavior

Provider hosts invoke only `/usr/bin/security find-generic-password`. Presence checks omit `-w`.
Commissioning reads use `-w`, enforce an 8 KiB output ceiling, and never interpret stderr. Recovery
uses `withStorageSecrets`, which reads only the three local state keys and never reveals the
provider credential.

The marker hosts use fixed `find-generic-password` presence checks and create-only
`add-generic-password`; they expose no update, delete, or reset operation. Only the Keychain
item-not-found exit status is treated as `missing`. Timeouts, execution failures, malformed
results, and all other exit statuses fail closed as `unavailable` or `unknown`.

Secret properties are non-enumerable, so accidental JSON serialization or object spread emits no
credential material. The host clears original command buffers, executor handoff buffers, Base64
decode buffers, temporary state-key arrays, and callback key views. Provider credential text
necessarily exists briefly in process memory while Node constructs the request header; JavaScript
strings cannot be overwritten in place. A live controller must remain one-shot and release its
reference after the call.

Package tests use injected executors and never access the real Keychain. Provision production
items only through the safe GUI procedure in the
[Stage 1 commissioning runbook](../../docs/production-readiness/commissioning-runbook.md).
