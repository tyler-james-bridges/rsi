# `@rsi/event-archive`

`@rsi/event-archive` is the restorable event-history component required by the
Observer v1 sanitized recovery bundle. Its signed role is exactly
`sanitized-event-archive`, the companion named by `@rsi/backup` state evidence.
It is not a complete OBS-REC-003 backup by itself: verified recovery also
requires the matching `sanitized-state-evidence` component and a
`signed-release-bundle` containing the sanitized code and runbook bytes.

The package accepts typed event objects only. It never accepts SQLite bytes,
WAL/SHM files, arbitrary directories, raw Vault content, capture indexes,
cursors, credentials, keys, queries, provider responses, or a generic artifact
map. Version 1 admits only the two closed permanent-event schemas implemented by
the production ingestion path:

- `source.capture.recorded.v2`;
- `source.capture.deleted.v1`.

Every field is parsed before serialization. The archive recomputes the exact
`@rsi/store` hash for every record, requires a contiguous genesis-to-head chain,
checks unique event and idempotency IDs, and binds all payload profiles plus the
tail session to the independently verified `@rsi/backup` receipt and event-state
evidence. Adding another event type requires a versioned schema change; unknown
types and fields fail closed.

## API

```ts
import {
  createSanitizedEventArchive,
  importSanitizedEventArchiveToEmptyStore,
  restoreSanitizedEventArchive,
  verifySanitizedEventArchive,
} from "@rsi/event-archive";

const receipt = await createSanitizedEventArchive({
  createdAt: "2026-08-14T12:21:00.000Z",
  destinationPath: "/private/backup/session.rsievents",
  signer: releaseSigner,
  snapshot: {
    events: eventStore.list(),
    profile: "production-observer",
    retention: "session-30d",
    sessionId,
    sessionState: "acceptance-ready",
    sessionStateAt,
    stateEvidence: {
      eventState,
      manifestEnvelope: independentlyVerifiedStateEvidenceManifestEnvelope,
      profile: "production-observer",
      releaseKeyId: "release-key-v1",
      receipt: independentlyRetainedStateEvidenceReceipt,
      retention: "session-30d",
      sessionId,
      sessionState: "acceptance-ready",
      sessionStateAt,
    },
  },
});

const trust = {
  receipt, // retain outside the archive to detect rollback
  releasePublicKeySpkiDer,
  stateEvidence: {
    eventState,
    manifestEnvelope: independentlyVerifiedStateEvidenceManifestEnvelope,
    profile: "production-observer",
    releaseKeyId: "release-key-v1",
    receipt: independentlyRetainedStateEvidenceReceipt,
    retention: "session-30d",
    sessionId,
    sessionState: "acceptance-ready",
    sessionStateAt,
  },
};

await verifySanitizedEventArchive({ archivePath, trust });
await restoreSanitizedEventArchive({ archivePath, destinationDirectory, trust });
await importSanitizedEventArchiveToEmptyStore({ archivePath, target: emptyEventStore, trust });
```

Creation publishes one immutable file with create-only filesystem semantics.
Verification requires both independently retained receipts, the exact signed
`@rsi/backup` manifest envelope, and the release public key. The manifest proof's
canonical digest must equal the backup receipt, and its signature and all
event-state/profile/retention/session/release-key bindings are checked locally.
Filesystem restore verifies the complete archive before creating an
exactly two-file, mode-0700 directory and never merges or overwrites. Store
reimport likewise verifies first, requires a genuinely constructed,
genesis-empty `@rsi/store` target, reconstructs all records inside one synchronous
exclusive transaction, and rolls back unless the final integrity report exactly
matches the archived head. Structurally similar or proxied targets are rejected.

The archive format is bounded to one signed canonical manifest and one canonical
NDJSON event artifact. Each event line is at most 16 KiB, the event epoch is at
most 250 MiB, and keys/signatures must be ordinary `ArrayBuffer`-backed
`Uint8Array` values. Proxies, accessors, symbols, exotic prototypes, sparse
arrays, cycles, `Buffer`, and `SharedArrayBuffer` views are rejected at input
boundaries.
