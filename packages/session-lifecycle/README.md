# `@rsi/session-lifecycle`

Keyed, local-only SQLite coordination for an Observer v1 supervised session. This package exposes no
cursor, provider, network, credential, payment, signer, or execution capability.

## State machine

The only successful path is:

```text
planned → preflighted → running → stopping → locally_verified
        → externally_verified → cost_pending → accepted
```

Every state before `accepted` can instead become terminal `invalid`. `accepted` and `invalid` never
transition again. At most one nonterminal session exists in a profile database. `stopSession` and
`invalidateSession` always leave egress marked `blocked`; the lifecycle record is only a state proof,
not a network authorization.

`qualificationDate` is an exact `YYYY-MM-DD` in `America/Phoenix` and must match both `plannedAt` and
the eventual `startedAt`. Invalid attempts can be replanned on that date, but a second session cannot
be accepted for a date already occupied by an accepted session. The rolling ten-sessions-in-fourteen-
days promotion ledger is intentionally a later package and is not inferred here.

## Opening and crash recovery

```ts
declare const stateKey: Uint8Array; // Injected from the profile-specific local secret store.

const first = SqliteSessionCoordinator.open({
  expectedProfile: "canary",
  path: "/private/state/canary/session.sqlite",
  recoveredAt: "2026-08-14T15:00:00.000Z",
  stateKey,
});

const pinned = first.coordinator.getTrustedHead();
first.coordinator.close();

const restarted = SqliteSessionCoordinator.open({
  expectedProfile: "canary",
  path: "/private/state/canary/session.sqlite",
  recoveredAt: "2026-08-14T15:10:00.000Z",
  stateKey,
  trustedHead: pinned,
});
```

The key must be a dedicated, ordinary `ArrayBuffer`-backed, exact `Uint8Array` of 32 bytes. Buffers,
subclasses, proxies, `SharedArrayBuffer` views, wrong profile keys, and wrong keys are rejected. Key
derivation is profile-domain-separated and every database row has a keyed MAC.

Every reopen of an initialized namespace requires an independently retained `trustedHead`. A valid
older head is accepted only when it is still an authenticated prefix of the current audit chain. This
detects a whole-file rollback only when the operator retains the latest accepted head independently;
a self-consistent rolled-back SQLite file cannot prove its own freshness. The accepted external
anchor/MacBook record is the intended independent pin. A new empty namespace may omit the head or use
the genesis head.

Before returning from reopen, the coordinator atomically invalidates every nonterminal session and
returns only:

```ts
{ schemaVersion: 1, invalidatedSessionCount: number, cleanupRequired: boolean }
```

No session ID appears in that receipt. The caller must complete the separately authenticated purge
and orphan-clean workflow whenever `cleanupRequired` is true. A backward recovery clock rejects with
zero mutation.

## Supervision and evidence

Starting requires a successful closed preflight record, the operator-typed lowercase UUIDv4 session
ID, and an explicit Observer-only acknowledgement. A qualifying run is no longer than 120 minutes.
The deterministic Observer v1 interpretation of “approximately minute 45 and 90” is:

- minute-45 acknowledgement: inclusive `[startedAt + 45m, startedAt + 50m]`;
- minute-90 acknowledgement: inclusive `[startedAt + 90m, startedAt + 95m]`.

An early acknowledgement rejects without mutation. A late or missing acknowledgement atomically
invalidates the attempt. There is no auto-extension.

Each evidence object is an exact plain-data schema and carries one lowercase SHA-256 digest binding
the already-sanitized receipt/report. The digest must never be computed over or used to retain raw or
provider content. Acceptance is composed only after all of these closed facts succeed:

- successful preflight;
- all five X lanes closed;
- OpenSea REST and Stream closed;
- canonical-chain closure;
- event and digest integrity;
- raw/index/key purge and clean orphan scan;
- local checkpoint;
- external anchor, retained suffix, and MacBook verification;
- the exact sanitized-state-evidence, sanitized-event-archive, and signed-release-bundle archive
  hashes, each carrying its component's closed successful verification status;
- healthy alert/dead-man check and explicit close;
- complete billing within 48 hours, zero outstanding cost, and reconciled cost no greater than the
  reservation;
- zero incidents.

Missing fields, extra fields, accessors, proxies, malformed values, or unknown structure reject
before mutation. A well-formed `fail`/`unknown`, late lifecycle fact, cost excess, or incident
atomically invalidates. Durable records and aggregate APIs contain no provider/source IDs, queries,
URLs, free-form reasons, or arbitrary prose.

## Integrity and idempotency

The 32-byte profile key authenticates a key check, every session row, every chained audit row, the
complete sorted session row set, the complete audit head, exact SQLite schema projection, counts,
profile, global monotonic time, and metadata. Initialization is allowed only over a truly empty SQLite
namespace; a missing metadata row or pre-existing table/trigger is never silently initialized or
rekeyed. SQLite uses an exclusive local writer lock.

Every transition has one authenticated action binding. An exact retry returns its original frozen
post-transition record even if the session later advanced. Reusing that action with changed input
throws `SessionLifecycleConflictError` with `RETRY_CONFLICT`. All writes use `BEGIN IMMEDIATE`, verify
the whole authenticated database before and after mutation, and roll back completely on failure.
