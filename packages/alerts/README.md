# `@rsi/alerts`

Offline, content-free incident alert domain and durable delivery outbox for Observer v1.

The package intentionally contains no Resend or Healthchecks client, no credential reader,
and no network code. A later qualified adapter may claim one strict alert at a time and use
the opaque `deliveryId` as its provider idempotency key.

## Alert contract

`IncidentAlertV1` is a closed runtime schema. It permits only:

- canonical lowercase UUIDv4 incident and session IDs;
- one allowlisted incident code;
- literal `critical` severity;
- a canonical UTC timestamp;
- the closed Observer profile;
- template revision `1`; and
- literal instruction `OPEN_LOCAL_RSI_CONSOLE`.

Message text, raw content, source identifiers, assets, addresses, URLs, stacks, queries,
credentials, recipients, and provider errors have no schema field and are rejected.

The incident-code allowlist covers the v1 runbook boundaries: preflight/host/network and
supervision; provider outage/schema/terms-price drift; policy/data/cross-profile and
financial-adapter escapes; cost/resource/clock/cursor/purge failures; credential/signing-key
compromise; database/event/release/anchor/backup/publication integrity; alert-path failure;
second-writer, crash, and incident-latch failure. `ALERT_PATH_CANARY` is the only synthetic
path-test code. There is no caller-defined code or error-text escape hatch.

## State and recovery

Create one database for exactly one profile, then retain its content-free authenticated
audit-prefix head outside the SQLite file:

```ts
const outbox = AlertOutbox.open({
  databasePath,
  profile: "canary",
  stateKey, // exactly 32 bytes, supplied by the caller
});
const trustedHead = outbox.getTrustedHead();
```

Every existing database requires an independently retained head on reopen:

```ts
const reopened = AlertOutbox.open({
  databasePath,
  profile: "canary",
  stateKey,
  trustedHead,
});
```

Persist a new `getTrustedHead()` result after successful mutations. The head contains only a
version, profile, audit sequence/event MAC, authenticated schema MAC, and authentication MAC.
It contains no incident, session, delivery, provider, recipient, or message identifier.

A database file cannot prove that it has not been wholly replaced by an older internally valid
copy. That requires an independently retained head. Reopen proves that the retained audit row is
still present with the same event MAC; a valid newer authenticated suffix is allowed. This permits
recovery when a mutation committed but the process crashed before externalizing its newer head,
while any rollback before the last retained prefix still fails closed. Reopening any pre-existing
database without `trustedHead` is rejected. Supplying a head copied from the same rolled-back
database would forfeit rollback detection and is not a valid recovery procedure.

Canary and production use separate databases and distinct caller-held state keys. The key
derivation, authenticated database sentinel, encrypted-payload AAD, and delivery identity
are also profile-domain-separated, so a database cannot be reopened under another profile.

`enqueue` is deterministically idempotent by profile, plane, incident ID, and session ID.
Reusing that identity with different alert content or queue time is a conflict. `claim`
consumes attempt one or two. `fail` can return attempt one to `pending`; attempt two is always terminal.
`complete` makes the delivery terminal. Provider message IDs, when supplied, are encrypted
and never returned by receipts or projections.

An interrupted `in_flight` attempt stays latched after reopen. The local lifecycle must call
`recover` explicitly; recovery consumes that attempt, permits at most the one remaining
retry, and never performs network work. This preserves the no-automatic-resume boundary.

The SQLite payload and provider ID are AES-256-GCM encrypted. Delivery/attempt rows and the
append-only audit chain are HMAC authenticated. The exact canonical `sqlite_schema`, the complete
row-set projection, and metadata/audit head are separately MAC authenticated. Triggers, views,
extra indexes/tables, altered table SQL, deleted metadata, profile/key mismatch, and state or audit
tail tampering fail closed before mutation. Each transaction checks affected-row cardinality,
reseals the full state, and verifies integrity again before commit.
