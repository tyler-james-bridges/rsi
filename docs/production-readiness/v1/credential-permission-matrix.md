# Observer v1 credential and permission matrix

## Custody rules

- The operator owns all provider accounts and enables MFA/passkeys plus offline
  recovery wherever supported.
- Credentials are unique per provider, purpose, and environment. Canary and
  production never share values.
- Provider credentials are replaceable and are not backed up. Long-lived signing
  keys use the explicit offline recovery policy below.
- The local masked provisioning command writes directly to the correct macOS
  Keychain, validates scope through a harmless request, and records only presence,
  key identifier, and verification time.
- Values never enter chat, shell history, `.env`, repository files, GitHub,
  screenshots, logs, events, models, backups, public artifacts, or livestreams.
- A credential that cannot be constrained to the maximum authority below MUST NOT
  be provisioned until the affected design branch is reopened.

### Stage A logical Keychain aliases

Preflight uses a closed set of logical aliases and records alias/presence only:

| Logical alias           | Canary Keychain service                | Production Keychain service              | Role                                                |
| ----------------------- | -------------------------------------- | ---------------------------------------- | --------------------------------------------------- |
| `x_read`                | `dev.rsi.canary.x-read`                | `dev.rsi.observer.x-read`                | X read-only source credential                       |
| `opensea_read`          | `dev.rsi.canary.opensea-read`          | `dev.rsi.observer.opensea-read`          | OpenSea read-only source credential                 |
| `alchemy_read`          | `dev.rsi.canary.alchemy-read`          | `dev.rsi.observer.alchemy-read`          | Alchemy read-only chain credential                  |
| `b2_writer`             | `dev.rsi.canary.b2-writer`             | `dev.rsi.observer.b2-writer`             | Private checkpoint write-only credential            |
| `b2_outbox_writer`      | `dev.rsi.canary.b2-outbox-writer`      | `dev.rsi.observer.b2-outbox-writer`      | Separate review-outbox write-only credential        |
| `resend_send`           | `dev.rsi.canary.resend-send`           | `dev.rsi.observer.resend-send`           | Domain-restricted alert send credential             |
| `healthchecks_ping`     | `dev.rsi.canary.healthchecks-ping`     | `dev.rsi.observer.healthchecks-ping`     | Dead-man ping credential                            |
| `checkpoint_signing`    | `dev.rsi.canary.checkpoint-signing`    | `dev.rsi.observer.checkpoint-signing`    | Environment checkpoint signing key                  |
| `capture_registry`      | `dev.rsi.canary.capture-registry`      | `dev.rsi.observer.capture-registry`      | Ephemeral capture-registry encryption root key      |
| `operations_state`      | `dev.rsi.canary.operations-state`      | `dev.rsi.observer.operations-state`      | Operations integrity and cursor-encryption root key |
| `external_anchor_state` | `dev.rsi.canary.external-anchor-state` | `dev.rsi.observer.external-anchor-state` | External-anchor outbox integrity/encryption key     |
| `alert_state`           | `dev.rsi.canary.alert-state`           | `dev.rsi.observer.alert-state`           | Alert-outbox integrity/encryption root key          |
| `session_state`         | `dev.rsi.canary.session-state`         | `dev.rsi.observer.session-state`         | Session-lifecycle integrity/encryption root key     |
| `vault_wrapping`        | `dev.rsi.canary.vault-wrapping`        | `dev.rsi.observer.vault-wrapping`        | Vault DEK-wrapping root key                         |

Cross-profile resolution, role collapsing, and unknown aliases fail closed. The
offline `dev` profile resolves no live alias. These service identifiers are names,
not evidence that a Keychain item or provider credential exists. The checkpoint
writer and review-outbox writer MUST remain distinct even if one provider account
owns both buckets.

## Runtime and provider matrix

| Principal or credential               | Custodian/location                                    | Maximum authority                                                                      | Explicitly forbidden                                                                               | Backup/rotation                                                             |
| ------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `dev` profile                         | Operator's normal offline development environment     | Read repository fixtures; run offline tests and demos                                  | Any production credential, live provider call, canary/production state                             | No secrets to back up                                                       |
| `rsi-canary` macOS account            | Mac mini standard non-iCloud account and its Keychain | Supervised bounded canary collection through exact egress allowlist                    | Production state/credentials, remote login, root, payments, transactions                           | Replaceable provider credentials; state backup excludes secrets/cursors/raw |
| `rsi-observer` macOS account          | Mac mini standard non-iCloud account and its Keychain | Qualified read-only production collection through exact allowlist                      | Canary state/credentials, remote login, root, payments, transactions                               | Same separation as canary                                                   |
| X source credential                   | Correct environment Keychain                          | Read-only recent search for accepted use declaration and bounded lanes                 | Post, reply, like, follow, profile, DM, ads, account mutation, broader endpoints, auto-recharge    | Never backed up; revoke/replace on suspected exposure                       |
| OpenSea source credential             | Correct environment Keychain                          | Read-only REST/Stream observation on approved endpoints                                | Create/cancel/fill order, sign, transfer, buy, sell, bid, mint, metadata/media retrieval           | Never backed up; revoke/replace                                             |
| Alchemy credential                    | Correct environment Keychain                          | Read-only Base/Robinhood canonical RPC/indexing endpoints                              | Send transaction, wallet/signing service, write endpoint, arbitrary unsupported chain              | Never backed up; revoke/replace                                             |
| Optional public RPC/Blockscout access | Exact egress allowlist; no credential when possible   | Noncritical read-only cross-check                                                      | Qualification dependency, silent Alchemy replacement, transaction relay                            | Replaceable; no secret backup                                               |
| B2 checkpoint writer                  | Correct environment Keychain on Mac mini              | Write a unique object to the private checkpoint bucket                                 | Read, list, overwrite, delete, retention-policy/admin change, source data                          | Never backed up; rotate by replacement                                      |
| B2 checkpoint verifier                | MacBook Keychain                                      | Read/list checkpoint objects needed to verify suffix                                   | Write, overwrite, delete, alter retention, provider admin                                          | Never backed up; replaceable                                                |
| B2 review-outbox writer               | Mac mini Keychain, separate bucket/key                | Write one unique schema-valid unsigned candidate, maximum 16 KiB                       | Read, list, overwrite, delete, checkpoint access                                                   | Never backed up; replaceable                                                |
| B2 review-outbox reviewer             | MacBook Keychain                                      | Read/list/delete candidates after review or seven-day expiry                           | Modify candidate in place, checkpoint-bucket authority                                             | Never backed up; replaceable                                                |
| Resend sender                         | Correct runtime Keychain                              | Send-only from `observer@rsi.tylerjb.dev` to the one locally configured recipient      | Domain/DNS/account admin, arbitrary sender, inbound mail, sensitive alert content                  | Never backed up; replaceable                                                |
| Healthchecks ping credential          | Correct runtime Keychain                              | Ping only the approved dead-man check                                                  | Read/admin account data, inbound control, runtime resume                                           | Never backed up; replaceable                                                |
| GitHub CI token                       | GitHub-managed ephemeral token                        | Repository read-only checkout and check reporting required by workflow                 | Secrets, deployment, packages write, broad org access, Mac access                                  | Ephemeral; no stored project secret                                         |
| Mac mini Git deploy key               | Mac mini Keychain/SSH agent                           | Read-only access to the private RSI repository or approved release bundle              | Push, PR/admin, actions/secrets, other repositories                                                | Replaceable; never backed up                                                |
| Cloudflare Pages publication token    | MacBook Keychain only                                 | Deploy the static Observer viewer project                                              | DNS, Workers, unrelated zones/accounts, Mac mini custody                                           | Replaceable; never backed up                                                |
| Cloudflare R2 publication token       | MacBook Keychain only                                 | Write/delete approved signed artifacts/head in the one public-artifact bucket          | Checkpoint/outbox access, unrelated buckets, account admin                                         | Replaceable; never backed up                                                |
| Cloudflare DNS token                  | MacBook Keychain only                                 | Narrow record edits needed for approved Observer hostnames and key pin                 | Broad zone/account mutation, Mac mini custody                                                      | Replaceable; never backed up                                                |
| Optional OpenAI service credential    | Dedicated project/service account, local Keychain     | Post-session sanitized requests with $5 hard cap, `store: false`, approved models only | Raw/provider data, tools, web, files, state mutation, expensive fallback, qualification dependency | Never backed up; replaceable                                                |

Cloudflare, provider, and live-network credentials are not provisioned during
Stage A. The table is a maximum-authority contract, not evidence that an account or
resource exists.

## Signing and encryption-key hierarchy

| Key                                  | Custodian                             | Purpose                                                                 | Must not do                                                               | Recovery and rotation                                                                                 |
| ------------------------------------ | ------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Release Ed25519 key                  | MacBook                               | Sign reviewed source/release manifests and whole-bundle identity        | Sign operator approvals, public artifacts, checkpoints, provider requests | Two separately stored encrypted offline copies; annual exercise/rotation; signed successor transition |
| Operator-approval Ed25519 key        | MacBook                               | Sign strategy promotion, qualification, activation, and resume records  | Sign source releases, public artifacts, checkpoints                       | Same long-lived recovery/rotation policy                                                              |
| Public-artifact Ed25519 key          | MacBook                               | Sign canonical receipt/correction/tombstone bytes                       | Sign collection state, release, operator resume, checkpoints              | Same long-lived recovery/rotation policy; fingerprint pinned independently in DNS/GitHub              |
| Canary checkpoint Ed25519 key        | `rsi-canary` environment              | Sign exact canary event heads                                           | Sign production, release, approval, or public artifacts                   | Two encrypted offline copies; separate key ID/lineage; annual or compromise rotation                  |
| Production checkpoint Ed25519 key    | `rsi-observer` environment            | Sign exact production event heads                                       | Sign canary, release, approval, or public artifacts                       | Same, with independent copies and lineage                                                             |
| Canary operations-state key          | `rsi-canary` Keychain only            | Derive canary operations-integrity and cursor-encryption subkeys        | Wrap vault DEKs, sign, leave host, enter backup, authenticate production  | No backup; loss/rotation creates a new operations and cursor lineage                                  |
| Production operations-state key      | `rsi-observer` Keychain only          | Derive production operations-integrity and cursor-encryption subkeys    | Wrap vault DEKs, sign, leave host, enter backup, authenticate canary      | No backup; loss/rotation creates a new operations and cursor lineage                                  |
| Canary capture-registry key          | `rsi-canary` Keychain only            | Encrypt and authenticate canary's ephemeral capture lifecycle/index     | Wrap Vault DEKs, authenticate production, sign, leave host, enter backup  | No backup; loss invalidates the session and creates a new registry lineage                            |
| Production capture-registry key      | `rsi-observer` Keychain only          | Encrypt and authenticate production's ephemeral capture lifecycle/index | Wrap Vault DEKs, authenticate canary, sign, leave host, enter backup      | No backup; loss invalidates the session and creates a new registry lineage                            |
| Canary external-anchor state key     | `rsi-canary` Keychain only            | Authenticate/encrypt the canary B2 publication outbox                   | Sign checkpoints, authenticate production, act as a B2 credential         | No backup; loss abandons pending outbox work and starts a new local outbox lineage                    |
| Production external-anchor state key | `rsi-observer` Keychain only          | Authenticate/encrypt the production B2 publication outbox               | Sign checkpoints, authenticate canary, act as a B2 credential             | No backup; loss abandons pending outbox work and starts a new local outbox lineage                    |
| Canary alert state key               | `rsi-canary` Keychain only            | Authenticate/encrypt canary alert delivery and attempt state            | Send alerts, authenticate production, sign, leave host, enter backup      | No backup; loss starts a new alert-outbox lineage and invalidates affected qualification evidence     |
| Production alert state key           | `rsi-observer` Keychain only          | Authenticate/encrypt production alert delivery and attempt state        | Send alerts, authenticate canary, sign, leave host, enter backup          | No backup; loss starts a new alert-outbox lineage and invalidates affected qualification evidence     |
| Canary session state key             | `rsi-canary` Keychain only            | Authenticate canary session-lifecycle state and audit history           | Grant egress, authenticate production, sign, leave host, enter backup     | No backup; loss invalidates nonaccepted session state and starts a new session lineage                |
| Production session state key         | `rsi-observer` Keychain only          | Authenticate production session-lifecycle state and audit history       | Grant egress, authenticate canary, sign, leave host, enter backup         | No backup; loss invalidates nonaccepted session state and starts a new session lineage                |
| Canary vault wrapping key            | `rsi-canary` Keychain only            | Wrap canary per-capture DEKs                                            | Sign, leave host, enter backup, decrypt production                        | No backup; destroy on retirement or required lineage reset                                            |
| Production vault wrapping key        | `rsi-observer` Keychain only          | Wrap production per-capture DEKs                                        | Sign, leave host, enter backup, decrypt canary                            | No backup; destroy on retirement or required lineage reset                                            |
| Per-capture DEK                      | Process memory/encrypted vault record | Encrypt exactly one raw capture                                         | Reuse across captures, persist after purge, enter event/backup            | No backup; crypto-shred at purge                                                                      |

Private digest integrity is committed through the signed event/checkpoint lineage; a
separate digest-signing key is intentionally not introduced.

## Forbidden credentials and capabilities

Observer v1 MUST NOT possess any of the following, even when an interface exists in
source code:

- wallet private key, seed phrase, smart-account/session key, RPC signer, or
  transaction relay capability;
- AgentCash balance/key, x402 payment authority, token allowance, facilitator
  credential, or paid-call auto-recharge;
- Robinhood brokerage, banking, Agentic Trading, Robinhood Agent, card, or order
  credential;
- OpenSea signing, order-creation, fulfillment, cancellation, minting, or transfer
  capability;
- X write/engagement capability;
- remote shell, screen sharing, remote management, inbound webhook, or restart
  credential for the Mac mini;
- primary personal wallet, brokerage, bank, or credit-card authority.

Discovery of any financial or state-changing credential in canary/production is a
Class C incident: stop, isolate, revoke, inspect cross-environment exposure, and
reopen the affected design branch before qualification can restart.

## Compromise handling

For a replaceable provider credential: stop the affected plane, revoke it, inspect
events/logs and account activity without retaining raw source content, rotate it,
repeat its scope test, and require the operator to resume locally. A clean rotation
alone does not restart qualification if it was a planned drill and no compromise
occurred; an actual compromise is Class B unless evidence shows leakage or
cross-environment access, which is Class C.

For a signing key: freeze the affected plane, pin the last verified B2/public head,
retire the key, create a new offline-recoverable key, sign or otherwise document the
recovery transition from an independently trusted authority, restore state, and
restart qualification under the incident taxonomy. A forged or leaked public,
release, approval, or checkpoint signature is Class C.

For an operations-state or vault-wrapping key: stop the profile, complete safe
ephemeral purge if possible, destroy the key, create a non-reused replacement, and
start new operations/cursor/vault lineages as applicable. It is Class B only when
independent evidence bounds the event to key replacement with no raw disclosure,
state mutation, or cross-profile access; otherwise it is Class C.
