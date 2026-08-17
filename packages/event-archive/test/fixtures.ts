import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";

import { EVENT_ARCHIVE_MAGIC, type SanitizedEventArchiveManifestV1 } from "../src/archive.js";
import { canonicalJson, sha256 } from "../src/canonical.js";
import { computeStoreEventHash } from "../src/schema.js";
import type {
  EventArchiveSignerV1,
  JsonValue,
  SanitizedEventArchiveReceiptV1,
  SanitizedEventArchiveSnapshotV1,
  SanitizedEventArchiveTrustV1,
  SanitizedStoredEventV1,
  StateEvidenceBackupManifestV1,
  StateEvidenceCompanionV1,
} from "../src/types.js";

const SIGNATURE_DOMAIN = Buffer.from("rsi-sanitized-event-archive-manifest-v1\0", "utf8");
const STATE_EVIDENCE_SIGNATURE_DOMAIN = Buffer.from(
  "rsi-sanitized-state-evidence-manifest-v1\0",
  "utf8",
);

export const PRIOR_SESSION_ID = "11111111-1111-4111-8111-111111111111";
export const SESSION_ID = "22222222-2222-4222-8222-222222222222";

export interface Fixture {
  readonly privateKey: KeyObject;
  readonly publicKeyDer: Uint8Array;
  readonly signer: EventArchiveSignerV1;
  readonly snapshot: SanitizedEventArchiveSnapshotV1;
  readonly stateEvidence: StateEvidenceCompanionV1;
}

export function makeFixture(): Fixture {
  const keys = generateKeyPairSync("ed25519");
  const publicKeyDer = Uint8Array.from(
    keys.publicKey.export({ format: "der", type: "spki" }) as Buffer,
  );
  const events = makeEvents();
  const head = events.at(-1)!;
  const releaseManifestSha256 = digest("release-manifest");
  const checkpointHash = digest("checkpoint-head");
  const artifacts = Object.freeze(
    [
      ["application/json", "event-state-evidence.v1.json", "event-state-evidence"],
      ["application/x-ndjson", "checkpoint-journal.v1.jsonl", "checkpoint-journal"],
      ["application/json", "checkpoint-head.v1.json", "checkpoint-head"],
      ["application/json", "public-keys.v1.json", "public-keys"],
      ["application/json", "config-schema-hashes.v1.json", "config-schema-hashes"],
      ["application/json", "recovery-evidence.v1.json", "recovery-evidence"],
      ["application/json", "release-evidence.v1.json", "release-evidence"],
    ].map(([mediaType, path, role], index) =>
      Object.freeze({
        mediaType,
        path,
        role,
        sha256: digest(`state-evidence-artifact-${role}`),
        sizeBytes: 100 + index,
      }),
    ),
  ) as StateEvidenceBackupManifestV1["artifacts"];
  const stateEvidenceManifest: StateEvidenceBackupManifestV1 = Object.freeze({
    artifactCount: 7,
    artifacts,
    backupId: "33333333-3333-4333-8333-333333333333",
    backupType: "rsi.sanitized-state-evidence-component",
    checkpoint: Object.freeze({
      checkpointHash,
      journalSequence: 4,
      keyId: "checkpoint-key-v1",
      publicKeyFingerprintSha256: digest("checkpoint-key"),
      storeHeadHash: head.eventHash,
      storeHeadSequence: head.sequence,
      storeId: "observer-store-v1",
    }),
    componentScope: "observer-sanitized-state-evidence",
    createdAt: "2026-08-14T12:20:30.000Z",
    eventStateEvidence: Object.freeze({
      eventCount: events.length,
      headHash: head.eventHash,
      headSequence: head.sequence,
      storeId: "observer-store-v1",
    }),
    profile: "production-observer",
    recoveryCompleteness: "evidence-only",
    release: Object.freeze({
      commitSha: digest("release-commit").slice(0, 40),
      configSetSha256: digest("config-set"),
      keyId: "release-key-v1",
      publicKeyFingerprintSha256: sha256(publicKeyDer),
      releaseManifestSha256,
      releaseVersion: "1.0.0",
    }),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    retention: "session-30d",
    session: Object.freeze({
      id: SESSION_ID,
      state: "acceptance-ready",
      stateAt: "2026-08-14T12:20:00.000Z",
    }),
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: "release-key-v1",
      publicKeyFingerprintSha256: sha256(publicKeyDer),
    }),
    totalArtifactBytes: artifacts.reduce((total, artifact) => total + artifact.sizeBytes, 0),
    version: 1,
  });
  const stateEvidenceManifestEnvelope = Object.freeze({
    manifest: stateEvidenceManifest,
    signature: sign(
      null,
      Buffer.concat([
        STATE_EVIDENCE_SIGNATURE_DOMAIN,
        Buffer.from(canonicalJson(stateEvidenceManifest as unknown as JsonValue), "utf8"),
      ]),
      keys.privateKey,
    ).toString("base64url"),
  });
  const stateEvidence: StateEvidenceCompanionV1 = Object.freeze({
    eventState: Object.freeze({
      eventCount: events.length,
      eventStateType: "rsi.backup.event-state-evidence",
      headHash: head.eventHash,
      headSequence: head.sequence,
      storeId: "observer-store-v1",
      version: 1,
    }),
    manifestEnvelope: stateEvidenceManifestEnvelope,
    profile: "production-observer",
    releaseKeyId: "release-key-v1",
    receipt: Object.freeze({
      archiveSha256: digest("state-evidence-archive"),
      archiveSizeBytes: 4_096,
      backupId: "33333333-3333-4333-8333-333333333333",
      checkpointHash,
      checkpointJournalSequence: 4,
      componentScope: "observer-sanitized-state-evidence",
      manifestSha256: sha256(canonicalJson(stateEvidenceManifest as unknown as JsonValue)),
      profile: "production-observer",
      receiptType: "rsi.backup.state-evidence-receipt",
      recoveryCompleteness: "evidence-only",
      releaseManifestSha256,
      requiredCompanionArtifacts: Object.freeze([
        "sanitized-event-archive",
        "signed-release-bundle",
      ] as const),
      sessionId: SESSION_ID,
      signerFingerprintSha256: sha256(publicKeyDer),
      version: 1,
    }),
    retention: "session-30d",
    sessionId: SESSION_ID,
    sessionState: "acceptance-ready",
    sessionStateAt: "2026-08-14T12:20:00.000Z",
  });
  const snapshot: SanitizedEventArchiveSnapshotV1 = Object.freeze({
    events,
    profile: "production-observer",
    retention: "session-30d",
    sessionId: SESSION_ID,
    sessionState: "acceptance-ready",
    sessionStateAt: "2026-08-14T12:20:00.000Z",
    stateEvidence,
  });
  const signer: EventArchiveSignerV1 = Object.freeze({
    keyId: "release-key-v1",
    publicKeySpkiDer: Uint8Array.from(publicKeyDer),
    sign: (message: Uint8Array) => Uint8Array.from(sign(null, message, keys.privateKey)),
  });
  return Object.freeze({
    privateKey: keys.privateKey,
    publicKeyDer,
    signer,
    snapshot,
    stateEvidence,
  });
}

export function trustFor(
  fixture: Fixture,
  receipt: SanitizedEventArchiveReceiptV1,
): SanitizedEventArchiveTrustV1 {
  return Object.freeze({
    receipt,
    releasePublicKeySpkiDer: Uint8Array.from(fixture.publicKeyDer),
    stateEvidence: fixture.stateEvidence,
  });
}

export function refreshStateEvidenceProof(fixture: Fixture, companion: any): void {
  const manifestBytes = Buffer.from(
    canonicalJson(companion.manifestEnvelope.manifest as JsonValue),
    "utf8",
  );
  companion.receipt.manifestSha256 = sha256(manifestBytes);
  companion.manifestEnvelope.signature = sign(
    null,
    Buffer.concat([STATE_EVIDENCE_SIGNATURE_DOMAIN, manifestBytes]),
    fixture.privateKey,
  ).toString("base64url");
}

function makeEvents(): readonly SanitizedStoredEventV1[] {
  const inputs: readonly Omit<SanitizedStoredEventV1, "eventHash" | "previousHash" | "sequence">[] =
    [
      {
        aggregateId: `session:${PRIOR_SESSION_ID}`,
        eventId: "40000000-0000-4000-8000-000000000001",
        idempotencyKey: "capture-recorded-v2:50000000-0000-4000-8000-000000000001",
        occurredAt: "2026-08-14T12:00:00.000Z",
        payload: {
          capture: {
            acquiredAt: "2026-08-14T12:00:00.000Z",
            attemptId: "50000000-0000-4000-8000-000000000001",
            byteLength: 800,
            counts: { actorCount: 2, editedRecordCount: 0, recordCount: 3 },
            expiresAt: "2026-08-14T12:45:00.000Z",
            failureCode: null,
            lane: "official",
            profile: "production-observer",
            rawDisposition: "encrypted_ephemeral",
            schemaVersion: 2,
            sessionId: PRIOR_SESSION_ID,
            sourcePlane: "social",
            status: "accepted",
          },
        },
        type: "source.capture.recorded.v2",
      },
      {
        aggregateId: `session:${PRIOR_SESSION_ID}`,
        eventId: "40000000-0000-4000-8000-000000000002",
        idempotencyKey: "capture-deleted-v1:60000000-0000-4000-8000-000000000001",
        occurredAt: "2026-08-14T12:01:00.000Z",
        payload: {
          deletion: {
            deletedAt: "2026-08-14T12:01:00.000Z",
            deletionId: "60000000-0000-4000-8000-000000000001",
            expiredCount: 0,
            explicitCount: 1,
            orphanCount: 0,
            profile: "production-observer",
            schemaVersion: 1,
            sessionId: PRIOR_SESSION_ID,
            sourcePlane: "social",
            status: "verified",
          },
        },
        type: "source.capture.deleted.v1",
      },
      {
        aggregateId: `session:${SESSION_ID}`,
        eventId: "40000000-0000-4000-8000-000000000003",
        idempotencyKey: "capture-recorded-v2:50000000-0000-4000-8000-000000000002",
        occurredAt: "2026-08-14T12:10:00.000Z",
        payload: {
          capture: {
            acquiredAt: "2026-08-14T12:10:00.000Z",
            attemptId: "50000000-0000-4000-8000-000000000002",
            byteLength: 1_024,
            counts: { actorCount: 1, editedRecordCount: 1, recordCount: 2 },
            expiresAt: "2026-08-14T12:55:00.000Z",
            failureCode: null,
            lane: "security",
            profile: "production-observer",
            rawDisposition: "encrypted_ephemeral",
            schemaVersion: 2,
            sessionId: SESSION_ID,
            sourcePlane: "social",
            status: "accepted",
          },
        },
        type: "source.capture.recorded.v2",
      },
      {
        aggregateId: `session:${SESSION_ID}`,
        eventId: "40000000-0000-4000-8000-000000000004",
        idempotencyKey: "capture-deleted-v1:60000000-0000-4000-8000-000000000002",
        occurredAt: "2026-08-14T12:11:00.000Z",
        payload: {
          deletion: {
            deletedAt: "2026-08-14T12:11:00.000Z",
            deletionId: "60000000-0000-4000-8000-000000000002",
            expiredCount: 0,
            explicitCount: 1,
            orphanCount: 0,
            profile: "production-observer",
            schemaVersion: 1,
            sessionId: SESSION_ID,
            sourcePlane: "social",
            status: "verified",
          },
        },
        type: "source.capture.deleted.v1",
      },
    ];
  const events: SanitizedStoredEventV1[] = [];
  let previousHash = "0".repeat(64);
  for (let index = 0; index < inputs.length; index += 1) {
    const candidate = {
      ...inputs[index]!,
      eventHash: "0".repeat(64),
      previousHash,
      sequence: index + 1,
    } as SanitizedStoredEventV1;
    const event = Object.freeze({
      ...candidate,
      eventHash: computeStoreEventHash(candidate),
    }) as SanitizedStoredEventV1;
    events.push(event);
    previousHash = event.eventHash;
  }
  return Object.freeze(events);
}

export interface RawArchive {
  eventBytes: Buffer;
  manifest: SanitizedEventArchiveManifestV1 & Record<string, any>;
  signature: string;
}

export function unpackArchive(bytes: Buffer): RawArchive {
  const envelopeLength = bytes.readUInt32BE(EVENT_ARCHIVE_MAGIC.length);
  const envelopeStart = EVENT_ARCHIVE_MAGIC.length + 4;
  const envelope = JSON.parse(
    bytes.subarray(envelopeStart, envelopeStart + envelopeLength).toString("utf8"),
  ) as {
    manifest: SanitizedEventArchiveManifestV1 & Record<string, any>;
    signature: string;
  };
  return {
    eventBytes: Buffer.from(bytes.subarray(envelopeStart + envelopeLength)),
    manifest: envelope.manifest,
    signature: envelope.signature,
  };
}

export function repackArchive(
  raw: RawArchive,
  privateKey: KeyObject,
  priorReceipt: SanitizedEventArchiveReceiptV1,
  signManifest = true,
): { readonly bytes: Buffer; readonly receipt: SanitizedEventArchiveReceiptV1 } {
  const signature = signManifest
    ? sign(
        null,
        Buffer.concat([
          SIGNATURE_DOMAIN,
          Buffer.from(canonicalJson(raw.manifest as unknown as JsonValue), "utf8"),
        ]),
        privateKey,
      ).toString("base64url")
    : raw.signature;
  const envelopeBytes = Buffer.from(
    canonicalJson({ manifest: raw.manifest, signature } as unknown as JsonValue),
    "utf8",
  );
  const header = Buffer.alloc(EVENT_ARCHIVE_MAGIC.length + 4);
  EVENT_ARCHIVE_MAGIC.copy(header);
  header.writeUInt32BE(envelopeBytes.length, EVENT_ARCHIVE_MAGIC.length);
  const bytes = Buffer.concat([header, envelopeBytes, raw.eventBytes]);
  const receipt = Object.freeze({
    ...priorReceipt,
    archiveId: raw.manifest.archiveId,
    archiveSha256: sha256(bytes),
    archiveSizeBytes: bytes.length,
    eventCount: raw.manifest.store.eventCount,
    headHash: raw.manifest.store.headHash,
    headSequence: raw.manifest.store.headSequence,
    manifestSha256: sha256(canonicalJson(raw.manifest as unknown as JsonValue)),
    profile: raw.manifest.profile,
    releaseManifestSha256: raw.manifest.releaseManifestSha256,
    sessionId: raw.manifest.session.id,
    signerFingerprintSha256: raw.manifest.signer.publicKeyFingerprintSha256,
    stateEvidenceArchiveSha256: raw.manifest.stateEvidence.archiveSha256,
    stateEvidenceBackupId: raw.manifest.stateEvidence.backupId,
    stateEvidenceCheckpointHash: raw.manifest.stateEvidence.checkpointHash,
    stateEvidenceManifestSha256: raw.manifest.stateEvidence.manifestSha256,
    storeId: raw.manifest.store.storeId,
  });
  return { bytes, receipt };
}

export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function digest(label: string): string {
  return createHash("sha256").update(label, "utf8").digest("hex");
}

export function unrelatedUuid(): string {
  return randomUUID();
}
