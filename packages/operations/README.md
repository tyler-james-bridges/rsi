# `@rsi/operations`

Offline operational primitives for RSI Observer's paid read-only source calls.

## Cost reservations

`SqliteOperationsStore` durably reserves worst-case `USD_MICRO` cost and an attempt
slot before any network dispatch. Reservations are never refunded for errors, empty
responses, timeouts, or aborts. A random permit can be converted to a nominal
`NetworkAttemptAuthorization`; the collector consumes it synchronously and exactly once
immediately before calling `fetch`.

After dispatch, `readNetworkAttemptBinding(attemptId)` returns the authenticated
permit-free binding plus durable attempt state and dispatch time. It exists for
crash recovery: ingestion can prove that a committed Vault capture came from the
original dispatched attempt after the one-shot authorization object is gone. The
receipt contains no permit token and performs no network action.

SQLite `BEGIN IMMEDIATE`, strict runtime schemas, authenticated rows, and an HMAC audit
chain enforce the cap across independent store instances. Reservation IDs and
idempotency keys are retry-safe but conflict if reused with different content.

## Cursor sequencing

Cursors and staged candidates are AES-256-GCM encrypted under independent random DEKs.
Each DEK is separately AES-256-GCM wrapped and authenticated by a key derived from the
operations state key; wrapper AAD binds the role, profile/lane/source cursor identity,
lineage, revision, and candidate identity. A candidate advances only through:

```text
staged -> validated -> event_persisted -> checkpointed
       -> anchor_published -> externally_verified -> committed
```

The attempt must already be closed successfully and match the cursor's canonical
profile, source plane, and lane. Receipts, heads, sequences, timestamps, and retry
content must agree. Competing revisions serialize at commit. Commit re-encrypts the
candidate under a fresh head DEK, then destroys both the candidate wrapper and the
superseded head wrapper. Abort destroys the candidate wrapper. The authenticated
metadata row records a pending erasure before the logical transition commits;
`secure_delete`, `VACUUM`, and truncating WAL checkpoints remove the old envelope and
ciphertext from the live SQLite namespace before the API returns. Reopen completes an
interrupted erasure before serving operations. A committed cursor never enters the
audit log in plaintext.

## Boundaries

- The package performs no network requests and stores no provider credentials.
- `stateKey` must be a dedicated 32-byte Keychain secret and is not a backup artifact.
- Profile IDs are exactly `dev`, `canary`, and `production-observer`.
- The caller still owns end-to-end receipt production, checkpoint publication, external
  verification, attempt closure, session cleanup, and process/service locking.
- JavaScript and OpenSSL memory wiping is best effort; same-user process compromise is
  outside this package's boundary.
- Crypto-erasure covers the live database, WAL, journal, and freelist namespace after
  hardening. A wrapper copied before erasure, storage-controller/APFS forensic remnants,
  and unencrypted backups remain outside this package's boundary; production therefore
  also requires FileVault, no-backup paths, and the single-service-writer lock.
