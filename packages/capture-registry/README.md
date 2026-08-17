# `@rsi/capture-registry`

Encrypted, profile-bound lifecycle state for ephemeral provider captures. The
registry is private control-plane storage; its attempt IDs, opaque capture IDs,
request fingerprints, and source identifiers must never enter logs, durable
events, alerts, checkpoints, backups, model inputs, or public projections.

## Profile and key isolation

Open each database with an exact `expectedProfile` (`dev`, `canary`, or
`production-observer`) and a dedicated 32-byte `registryKey`. The profile is
authenticated in the database metadata and key-check sentinel, and every begun
attempt must carry the same profile. Every encrypted begin record also binds its
research lane, so a crash retry cannot relabel an observation. Opening a database
under another profile or beginning a cross-profile or cross-lane retry fails closed.

Canary and production must use different macOS accounts, Keychains, keys,
directories, and database files. Store the two runtime keys under the dedicated
Keychain services `dev.rsi.canary.capture-registry` and
`dev.rsi.observer.capture-registry`. Do not reuse the Vault wrapping key or the
operations state key. `dev` uses synthetic fixtures only and resolves no live
credential alias.

The database is single-process/single-writer by design. It must live inside a
caller-owned `0700` directory; the SQLite file is restricted to `0600` and is
rejected if linked, replaced, or opened twice in the same process.

## Lifecycle order

For collection:

1. prepare the exact request and call `beginAttempt` with its authenticated
   fingerprint, lane, profile, and expiry window before any paid network dispatch;
2. collect the response into quarantine and encrypt it in Vault v2;
3. parse it and `commitCapture` with the encrypted source-identifier index;
4. append only the closed content-free event projection;
5. destroy all in-memory raw copies.

At startup, recover Vault temporary state, remove pending registry attempts,
repair any Vault-deletion/registry-tombstone boundary, and reconcile Vault's
active captures against `listCommittedCaptures()`. At session close, obtain an
exact Vault deletion receipt before `recordVerifiedDeletion`. Only after the
registry confirms key destruction may a content-free deletion event be emitted.

Removed records retain only authenticated content-free tombstones. Sensitive
records use random per-attempt DEKs; deletion destroys the wrapped DEK and
compacts SQLite before returning. Recovery repeats compaction when a prior
process crashed after committing a tombstone.

## Retention and backup

The registry is ephemeral session state. It is not backed up, copied to another
profile, or used as incident-forensics storage. Purge removed tombstones only
after the canonical content-free deletion event and checkpoint are durable.
Losing a registry key invalidates the affected session; it is not reconstructed
from Vault contents.

Run `pnpm --filter @rsi/capture-registry test` for the adversarial lifecycle,
tamper, filesystem, concurrency, profile-isolation, and erasure suite.
