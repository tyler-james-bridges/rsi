import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import {
  canonicalJson,
  decodeSignature,
  deepFreezeJson,
  exactArray,
  exactObject,
  parseCanonicalJsonBytes,
  sha256,
  validateEnum,
  validateHash,
  validateIdentifier,
  validateLiteral,
  validateSafeInteger,
  validateTimestamp,
  validateUuidV4,
} from "./canonical.js";
import { fail } from "./errors.js";
import type {
  CaptureCountsV2,
  CaptureDeletedPayloadV1,
  CaptureDeletedStoredEventV1,
  CaptureFailureCode,
  CaptureRecordedPayloadV2,
  CaptureRecordedStoredEventV2,
  EventArchiveProfile,
  EventArchiveRetention,
  EventArchiveSessionState,
  EventStateEvidenceV1,
  JsonValue,
  SanitizedEventArchiveSnapshotV1,
  SanitizedStoredEventV1,
  StateEvidenceArtifactDescriptorV1,
  StateEvidenceBackupManifestV1,
  StateEvidenceCompanionV1,
  StateEvidenceManifestEnvelopeV1,
  StateEvidenceReceiptV1,
} from "./types.js";

export const EVENT_STORE_SCHEMA_VERSION = 1 as const;
export const EVENT_STORE_GENESIS_HASH = "0".repeat(64);
export const MAX_EVENT_LINE_BYTES = 16 * 1024;
export const MAX_EVENT_ARTIFACT_BYTES = 250 * 1024 * 1024;
export const MAX_EVENT_RECORDS = 100_000;

const MAX_STATE_EVIDENCE_ARCHIVE_BYTES = 5 * 1024 * 1024;
const MAX_STATE_EVIDENCE_MANIFEST_BYTES = 128 * 1024;
const MAX_STATE_EVIDENCE_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_COUNT = 100_000;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const PROFILES = ["canary", "production-observer"] as const;
const RETENTIONS = ["month-end-365d", "session-30d"] as const;
const SESSION_STATES = ["accepted", "acceptance-ready", "locally-verified"] as const;
const LANES = ["contract", "discovery", "marketplace", "official", "security"] as const;
const SOURCE_PLANES = ["canonical_chain", "marketplace", "social"] as const;
const CAPTURE_FAILURE_CODES = [
  "ABORTED",
  "CONTENT_LENGTH_MISMATCH",
  "CREDENTIAL_IN_RESPONSE",
  "HTTP_STATUS",
  "INVALID_RESPONSE_SCHEMA",
  "MALFORMED_JSON",
  "RESPONSE_TOO_LARGE",
  "TIMEOUT",
  "TRANSPORT_FAILURE",
  "UNSUPPORTED_CONTENT_ENCODING",
  "UNSUPPORTED_CONTENT_TYPE",
] as const;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const SEMVER_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const SENSITIVE_METADATA_PATTERN =
  /secret|token|password|credential|private|bearer|api[_-]?key|mnemonic|seed|sk_live|xox|ghp_|https?:|@/i;
const STATE_EVIDENCE_ARTIFACTS = Object.freeze([
  Object.freeze({
    maximumBytes: 64 * 1024,
    mediaType: "application/json" as const,
    path: "event-state-evidence.v1.json",
    role: "event-state-evidence" as const,
  }),
  Object.freeze({
    maximumBytes: 2 * 1024 * 1024,
    mediaType: "application/x-ndjson" as const,
    path: "checkpoint-journal.v1.jsonl",
    role: "checkpoint-journal" as const,
  }),
  Object.freeze({
    maximumBytes: 64 * 1024,
    mediaType: "application/json" as const,
    path: "checkpoint-head.v1.json",
    role: "checkpoint-head" as const,
  }),
  Object.freeze({
    maximumBytes: 64 * 1024,
    mediaType: "application/json" as const,
    path: "public-keys.v1.json",
    role: "public-keys" as const,
  }),
  Object.freeze({
    maximumBytes: 64 * 1024,
    mediaType: "application/json" as const,
    path: "config-schema-hashes.v1.json",
    role: "config-schema-hashes" as const,
  }),
  Object.freeze({
    maximumBytes: 64 * 1024,
    mediaType: "application/json" as const,
    path: "recovery-evidence.v1.json",
    role: "recovery-evidence" as const,
  }),
  Object.freeze({
    maximumBytes: 64 * 1024,
    mediaType: "application/json" as const,
    path: "release-evidence.v1.json",
    role: "release-evidence" as const,
  }),
] as const);

export interface SanitizedArchiveData {
  readonly eventBytes: Buffer;
  readonly events: readonly SanitizedStoredEventV1[];
  readonly eventState: EventStateEvidenceV1;
  readonly profile: EventArchiveProfile;
  readonly retention: EventArchiveRetention;
  readonly sessionId: string;
  readonly sessionState: EventArchiveSessionState;
  readonly sessionStateAt: string;
  readonly stateEvidence: StateEvidenceCompanionV1;
  readonly stateEvidenceBindingSha256: string;
}

export function sanitizeSnapshot(value: unknown): SanitizedArchiveData {
  const record = exactObject(
    value,
    [
      "events",
      "profile",
      "retention",
      "sessionId",
      "sessionState",
      "sessionStateAt",
      "stateEvidence",
    ],
    "Event archive snapshot",
  );
  const profile = validateEnum(record.profile, PROFILES, "Archive profile");
  const retention = validateEnum(record.retention, RETENTIONS, "Archive retention");
  const sessionId = validateUuidV4(record.sessionId, "Archive session identifier");
  const sessionState = validateEnum(record.sessionState, SESSION_STATES, "Archive session state");
  const sessionStateAt = validateTimestamp(record.sessionStateAt, "Archive session-state time");
  const stateEvidence = parseStateEvidenceCompanion(record.stateEvidence);
  if (
    stateEvidence.profile !== profile ||
    stateEvidence.retention !== retention ||
    stateEvidence.sessionId !== sessionId ||
    stateEvidence.sessionState !== sessionState ||
    stateEvidence.sessionStateAt !== sessionStateAt
  ) {
    fail("INPUT_INVALID", "State-evidence session binding does not match the archive snapshot");
  }
  const inputEvents = exactArray(record.events, "Sanitized event records");
  if (inputEvents.length === 0 || inputEvents.length > MAX_EVENT_RECORDS) {
    fail("ARCHIVE_BOUNDS", "Sanitized event record count is outside its bound");
  }
  const events = Object.freeze(inputEvents.map((event) => parseSanitizedEvent(event)));
  validateEventChain(events, stateEvidence.eventState, profile, sessionId, sessionStateAt);
  const eventBytes = encodeEventJournal(events);
  return Object.freeze({
    eventBytes,
    events,
    eventState: stateEvidence.eventState,
    profile,
    retention,
    sessionId,
    sessionState,
    sessionStateAt,
    stateEvidence,
    stateEvidenceBindingSha256: sha256(canonicalJson(stateEvidence as unknown as JsonValue)),
  });
}

export function parseStateEvidenceCompanion(value: unknown): StateEvidenceCompanionV1 {
  const record = exactObject(
    value,
    [
      "eventState",
      "manifestEnvelope",
      "profile",
      "releaseKeyId",
      "receipt",
      "retention",
      "sessionId",
      "sessionState",
      "sessionStateAt",
    ],
    "State-evidence companion",
  );
  const eventState = parseEventState(record.eventState);
  const receipt = parseStateEvidenceReceipt(record.receipt);
  const manifestEnvelope = parseStateEvidenceManifestEnvelope(record.manifestEnvelope);
  const manifest = manifestEnvelope.manifest;
  const profile = validateEnum(record.profile, PROFILES, "State-evidence profile");
  const sessionId = validateUuidV4(record.sessionId, "State-evidence session identifier");
  const retention = validateEnum(record.retention, RETENTIONS, "State-evidence retention");
  const sessionState = validateEnum(
    record.sessionState,
    SESSION_STATES,
    "State-evidence session state",
  );
  const sessionStateAt = validateTimestamp(
    record.sessionStateAt,
    "State-evidence session-state time",
  );
  const releaseKeyId = validateIdentifier(
    record.releaseKeyId,
    "State-evidence release key identifier",
  );
  if (
    sha256(canonicalJson(manifest as unknown as JsonValue)) !== receipt.manifestSha256 ||
    manifest.backupId !== receipt.backupId ||
    manifest.checkpoint.checkpointHash !== receipt.checkpointHash ||
    manifest.checkpoint.journalSequence !== receipt.checkpointJournalSequence ||
    manifest.profile !== receipt.profile ||
    manifest.release.releaseManifestSha256 !== receipt.releaseManifestSha256 ||
    manifest.session.id !== receipt.sessionId ||
    manifest.signer.publicKeyFingerprintSha256 !== receipt.signerFingerprintSha256 ||
    manifest.profile !== profile ||
    manifest.retention !== retention ||
    manifest.session.id !== sessionId ||
    manifest.session.state !== sessionState ||
    manifest.session.stateAt !== sessionStateAt ||
    manifest.release.keyId !== releaseKeyId ||
    canonicalJson(manifest.eventStateEvidence as unknown as JsonValue) !==
      canonicalJson({
        eventCount: eventState.eventCount,
        headHash: eventState.headHash,
        headSequence: eventState.headSequence,
        storeId: eventState.storeId,
      })
  ) {
    fail("INPUT_INVALID", "Signed state-evidence manifest binding does not match");
  }
  return deepFreezeJson({
    eventState,
    manifestEnvelope,
    profile,
    releaseKeyId,
    receipt,
    retention,
    sessionId,
    sessionState,
    sessionStateAt,
  }) as StateEvidenceCompanionV1;
}

export function parseEventState(value: unknown): EventStateEvidenceV1 {
  const record = exactObject(
    value,
    ["eventCount", "eventStateType", "headHash", "headSequence", "storeId", "version"],
    "Event-state evidence",
  );
  validateLiteral(record.eventStateType, "rsi.backup.event-state-evidence", "Event-state type");
  validateLiteral(record.version, 1, "Event-state version");
  const eventCount = validateSafeInteger(record.eventCount, "Event count", 1, MAX_EVENT_RECORDS);
  const headSequence = validateSafeInteger(
    record.headSequence,
    "Event head sequence",
    1,
    MAX_EVENT_RECORDS,
  );
  if (eventCount !== headSequence) {
    fail("INPUT_INVALID", "Event count must equal the contiguous head sequence");
  }
  return Object.freeze({
    eventCount,
    eventStateType: "rsi.backup.event-state-evidence",
    headHash: validateHash(record.headHash, "Event head hash"),
    headSequence,
    storeId: validateIdentifier(record.storeId, "Event store identifier"),
    version: 1,
  });
}

export function parseStateEvidenceReceipt(value: unknown): StateEvidenceReceiptV1 {
  const record = exactObject(
    value,
    [
      "archiveSha256",
      "archiveSizeBytes",
      "backupId",
      "checkpointHash",
      "checkpointJournalSequence",
      "componentScope",
      "manifestSha256",
      "profile",
      "receiptType",
      "recoveryCompleteness",
      "releaseManifestSha256",
      "requiredCompanionArtifacts",
      "sessionId",
      "signerFingerprintSha256",
      "version",
    ],
    "State-evidence receipt",
  );
  validateLiteral(record.receiptType, "rsi.backup.state-evidence-receipt", "Receipt type");
  validateLiteral(record.componentScope, "observer-sanitized-state-evidence", "Component scope");
  validateLiteral(record.recoveryCompleteness, "evidence-only", "Recovery completeness");
  validateLiteral(record.version, 1, "State-evidence receipt version");
  const companions = exactArray(record.requiredCompanionArtifacts, "Required companion artifacts");
  if (
    companions.length !== 2 ||
    companions[0] !== "sanitized-event-archive" ||
    companions[1] !== "signed-release-bundle"
  ) {
    fail("INPUT_INVALID", "State-evidence companion set is invalid");
  }
  return deepFreezeJson({
    archiveSha256: validateHash(record.archiveSha256, "State-evidence archive hash"),
    archiveSizeBytes: validateSafeInteger(
      record.archiveSizeBytes,
      "State-evidence archive size",
      1,
      MAX_STATE_EVIDENCE_ARCHIVE_BYTES,
    ),
    backupId: validateUuidV4(record.backupId, "State-evidence backup identifier"),
    checkpointHash: validateHash(record.checkpointHash, "State-evidence checkpoint hash"),
    checkpointJournalSequence: validateSafeInteger(
      record.checkpointJournalSequence,
      "State-evidence checkpoint sequence",
      1,
    ),
    componentScope: "observer-sanitized-state-evidence" as const,
    manifestSha256: validateHash(record.manifestSha256, "State-evidence manifest hash"),
    profile: validateEnum(record.profile, PROFILES, "State-evidence profile"),
    receiptType: "rsi.backup.state-evidence-receipt" as const,
    recoveryCompleteness: "evidence-only" as const,
    releaseManifestSha256: validateHash(record.releaseManifestSha256, "Release manifest hash"),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    sessionId: validateUuidV4(record.sessionId, "State-evidence session identifier"),
    signerFingerprintSha256: validateHash(
      record.signerFingerprintSha256,
      "State-evidence signer fingerprint",
    ),
    version: 1 as const,
  }) as StateEvidenceReceiptV1;
}

export function parseStateEvidenceManifestEnvelope(
  value: unknown,
): StateEvidenceManifestEnvelopeV1 {
  const record = exactObject(
    value,
    ["manifest", "signature"],
    "Signed state-evidence manifest envelope",
  );
  const envelope = deepFreezeJson({
    manifest: parseStateEvidenceBackupManifest(record.manifest),
    signature: decodeSignature(record.signature).toString("base64url"),
  }) as StateEvidenceManifestEnvelopeV1;
  if (
    Buffer.byteLength(canonicalJson(envelope as unknown as JsonValue), "utf8") >
    MAX_STATE_EVIDENCE_MANIFEST_BYTES
  ) {
    fail("ARCHIVE_BOUNDS", "Signed state-evidence manifest exceeds its byte bound");
  }
  return envelope;
}

function parseStateEvidenceBackupManifest(value: unknown): StateEvidenceBackupManifestV1 {
  const record = exactObject(
    value,
    [
      "artifactCount",
      "artifacts",
      "backupId",
      "backupType",
      "checkpoint",
      "componentScope",
      "createdAt",
      "eventStateEvidence",
      "profile",
      "recoveryCompleteness",
      "release",
      "requiredCompanionArtifacts",
      "retention",
      "session",
      "signer",
      "totalArtifactBytes",
      "version",
    ],
    "State-evidence backup manifest",
  );
  validateLiteral(record.artifactCount, 7, "State-evidence artifact count");
  validateLiteral(
    record.backupType,
    "rsi.sanitized-state-evidence-component",
    "State-evidence backup type",
  );
  validateLiteral(
    record.componentScope,
    "observer-sanitized-state-evidence",
    "State-evidence component scope",
  );
  validateLiteral(record.recoveryCompleteness, "evidence-only", "Recovery completeness");
  validateLiteral(record.version, 1, "State-evidence manifest version");
  const artifactValues = exactArray(record.artifacts, "State-evidence artifact descriptors");
  if (artifactValues.length !== STATE_EVIDENCE_ARTIFACTS.length) {
    fail("INPUT_INVALID", "State-evidence artifact descriptor count is invalid");
  }
  let computedArtifactBytes = 0;
  const artifacts = artifactValues.map((artifactValue, index) => {
    const expected = STATE_EVIDENCE_ARTIFACTS[index]!;
    const artifact = exactObject(
      artifactValue,
      ["mediaType", "path", "role", "sha256", "sizeBytes"],
      "State-evidence artifact descriptor",
    );
    validateLiteral(artifact.mediaType, expected.mediaType, "State-evidence artifact media type");
    validateLiteral(artifact.path, expected.path, "State-evidence artifact path");
    validateLiteral(artifact.role, expected.role, "State-evidence artifact role");
    const sizeBytes = validateSafeInteger(
      artifact.sizeBytes,
      "State-evidence artifact size",
      1,
      expected.maximumBytes,
    );
    computedArtifactBytes += sizeBytes;
    if (
      !Number.isSafeInteger(computedArtifactBytes) ||
      computedArtifactBytes > MAX_STATE_EVIDENCE_ARTIFACT_BYTES
    ) {
      fail("ARCHIVE_BOUNDS", "State-evidence artifact total exceeds its byte bound");
    }
    return Object.freeze({
      mediaType: expected.mediaType,
      path: expected.path,
      role: expected.role,
      sha256: validateHash(artifact.sha256, "State-evidence artifact hash"),
      sizeBytes,
    }) satisfies StateEvidenceArtifactDescriptorV1;
  });
  const totalArtifactBytes = validateSafeInteger(
    record.totalArtifactBytes,
    "State-evidence artifact total",
    1,
    MAX_STATE_EVIDENCE_ARTIFACT_BYTES,
  );
  if (totalArtifactBytes !== computedArtifactBytes) {
    fail("INPUT_INVALID", "State-evidence artifact byte total is inconsistent");
  }
  const checkpoint = exactObject(
    record.checkpoint,
    [
      "checkpointHash",
      "journalSequence",
      "keyId",
      "publicKeyFingerprintSha256",
      "storeHeadHash",
      "storeHeadSequence",
      "storeId",
    ],
    "State-evidence checkpoint binding",
  );
  const eventState = exactObject(
    record.eventStateEvidence,
    ["eventCount", "headHash", "headSequence", "storeId"],
    "State-evidence event-state binding",
  );
  const release = exactObject(
    record.release,
    [
      "commitSha",
      "configSetSha256",
      "keyId",
      "publicKeyFingerprintSha256",
      "releaseManifestSha256",
      "releaseVersion",
    ],
    "State-evidence release binding",
  );
  const session = exactObject(record.session, ["id", "state", "stateAt"], "State-evidence session");
  const signer = exactObject(
    record.signer,
    ["algorithm", "keyId", "publicKeyFingerprintSha256"],
    "State-evidence manifest signer",
  );
  validateLiteral(signer.algorithm, "Ed25519", "State-evidence signature algorithm");
  const companions = exactArray(
    record.requiredCompanionArtifacts,
    "State-evidence required companions",
  );
  if (
    companions.length !== 2 ||
    companions[0] !== "sanitized-event-archive" ||
    companions[1] !== "signed-release-bundle"
  ) {
    fail("INPUT_INVALID", "State-evidence required companion set is invalid");
  }
  const eventCount = validateSafeInteger(
    eventState.eventCount,
    "State-evidence manifest event count",
    1,
    MAX_EVENT_RECORDS,
  );
  const headSequence = validateSafeInteger(
    eventState.headSequence,
    "State-evidence manifest head sequence",
    1,
    MAX_EVENT_RECORDS,
  );
  if (eventCount !== headSequence) {
    fail("INPUT_INVALID", "State-evidence manifest event counts are inconsistent");
  }
  const headHash = validateHash(eventState.headHash, "State-evidence manifest head hash");
  const storeId = validateIdentifier(
    eventState.storeId,
    "State-evidence manifest store identifier",
  );
  const checkpointHash = validateHash(
    checkpoint.checkpointHash,
    "State-evidence manifest checkpoint hash",
  );
  const journalSequence = validateSafeInteger(
    checkpoint.journalSequence,
    "State-evidence manifest checkpoint sequence",
    1,
  );
  const checkpointStoreHeadHash = validateHash(
    checkpoint.storeHeadHash,
    "State-evidence checkpoint store-head hash",
  );
  const checkpointStoreHeadSequence = validateSafeInteger(
    checkpoint.storeHeadSequence,
    "State-evidence checkpoint store-head sequence",
    1,
    MAX_EVENT_RECORDS,
  );
  const checkpointStoreId = validateIdentifier(
    checkpoint.storeId,
    "State-evidence checkpoint store identifier",
  );
  if (
    checkpointStoreHeadHash !== headHash ||
    checkpointStoreHeadSequence !== headSequence ||
    checkpointStoreId !== storeId
  ) {
    fail("INPUT_INVALID", "State-evidence checkpoint does not bind the event-state head");
  }
  const createdAt = validateTimestamp(record.createdAt, "State-evidence manifest creation time");
  const sessionStateAt = validateTimestamp(session.stateAt, "State-evidence session-state time");
  if (createdAt < sessionStateAt) {
    fail("INPUT_INVALID", "State-evidence manifest predates its session state");
  }
  const releaseKeyId = validateIdentifier(release.keyId, "State-evidence release key identifier");
  const releaseFingerprint = validateHash(
    release.publicKeyFingerprintSha256,
    "State-evidence release-key fingerprint",
  );
  const signerKeyId = validateIdentifier(signer.keyId, "State-evidence signer key identifier");
  const signerFingerprint = validateHash(
    signer.publicKeyFingerprintSha256,
    "State-evidence signer fingerprint",
  );
  if (signerKeyId !== releaseKeyId || signerFingerprint !== releaseFingerprint) {
    fail("INPUT_INVALID", "State-evidence signer does not bind the release key");
  }
  const commitSha = validateCommit(release.commitSha);
  const releaseVersion = validateSemver(release.releaseVersion);
  return deepFreezeJson({
    artifactCount: 7,
    artifacts: Object.freeze(artifacts),
    backupId: validateUuidV4(record.backupId, "State-evidence backup identifier"),
    backupType: "rsi.sanitized-state-evidence-component" as const,
    checkpoint: Object.freeze({
      checkpointHash,
      journalSequence,
      keyId: validateIdentifier(checkpoint.keyId, "State-evidence checkpoint key identifier"),
      publicKeyFingerprintSha256: validateHash(
        checkpoint.publicKeyFingerprintSha256,
        "State-evidence checkpoint-key fingerprint",
      ),
      storeHeadHash: checkpointStoreHeadHash,
      storeHeadSequence: checkpointStoreHeadSequence,
      storeId: checkpointStoreId,
    }),
    componentScope: "observer-sanitized-state-evidence" as const,
    createdAt,
    eventStateEvidence: Object.freeze({ eventCount, headHash, headSequence, storeId }),
    profile: validateEnum(record.profile, PROFILES, "State-evidence manifest profile"),
    recoveryCompleteness: "evidence-only" as const,
    release: Object.freeze({
      commitSha,
      configSetSha256: validateHash(release.configSetSha256, "State-evidence config-set hash"),
      keyId: releaseKeyId,
      publicKeyFingerprintSha256: releaseFingerprint,
      releaseManifestSha256: validateHash(
        release.releaseManifestSha256,
        "State-evidence release manifest hash",
      ),
      releaseVersion,
    }),
    requiredCompanionArtifacts: Object.freeze([
      "sanitized-event-archive",
      "signed-release-bundle",
    ] as const),
    retention: validateEnum(record.retention, RETENTIONS, "State-evidence manifest retention"),
    session: Object.freeze({
      id: validateUuidV4(session.id, "State-evidence manifest session identifier"),
      state: validateEnum(session.state, SESSION_STATES, "State-evidence manifest session state"),
      stateAt: sessionStateAt,
    }),
    signer: Object.freeze({
      algorithm: "Ed25519" as const,
      keyId: signerKeyId,
      publicKeyFingerprintSha256: signerFingerprint,
    }),
    totalArtifactBytes,
    version: 1 as const,
  }) as StateEvidenceBackupManifestV1;
}

function validateCommit(value: unknown): string {
  if (typeof value !== "string" || !COMMIT_PATTERN.test(value)) {
    fail("INPUT_INVALID", "State-evidence release commit is invalid");
  }
  return value;
}

function validateSemver(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !SEMVER_PATTERN.test(value) ||
    SENSITIVE_METADATA_PATTERN.test(value)
  ) {
    fail("INPUT_INVALID", "State-evidence release version is invalid");
  }
  return value;
}

export function parseSanitizedEvent(value: unknown): SanitizedStoredEventV1 {
  const record = exactObject(
    value,
    [
      "aggregateId",
      "eventHash",
      "eventId",
      "idempotencyKey",
      "occurredAt",
      "payload",
      "previousHash",
      "sequence",
      "type",
    ],
    "Sanitized event",
  );
  const common = {
    eventHash: validateHash(record.eventHash, "Event hash"),
    eventId: validateUuidV4(record.eventId, "Event identifier"),
    occurredAt: validateTimestamp(record.occurredAt, "Event timestamp"),
    previousHash: validateHash(record.previousHash, "Event predecessor hash"),
    sequence: validateSafeInteger(record.sequence, "Event sequence", 1, MAX_EVENT_RECORDS),
  };
  let event: SanitizedStoredEventV1;
  if (record.type === "source.capture.recorded.v2") {
    const payloadRecord = exactObject(record.payload, ["capture"], "Capture-recorded envelope");
    const capture = parseCaptureRecorded(payloadRecord.capture);
    const aggregateId = `session:${capture.sessionId}`;
    const idempotencyKey = `capture-recorded-v2:${capture.attemptId}`;
    if (
      record.aggregateId !== aggregateId ||
      record.idempotencyKey !== idempotencyKey ||
      common.occurredAt !== capture.acquiredAt
    ) {
      fail("INPUT_INVALID", "Capture-recorded event bindings are invalid");
    }
    event = {
      ...common,
      aggregateId,
      idempotencyKey,
      payload: Object.freeze({ capture }),
      type: "source.capture.recorded.v2",
    };
  } else if (record.type === "source.capture.deleted.v1") {
    const payloadRecord = exactObject(record.payload, ["deletion"], "Capture-deleted envelope");
    const deletion = parseCaptureDeleted(payloadRecord.deletion);
    const aggregateId = `session:${deletion.sessionId}`;
    const idempotencyKey = `capture-deleted-v1:${deletion.deletionId}`;
    if (
      record.aggregateId !== aggregateId ||
      record.idempotencyKey !== idempotencyKey ||
      common.occurredAt !== deletion.deletedAt
    ) {
      fail("INPUT_INVALID", "Capture-deleted event bindings are invalid");
    }
    event = {
      ...common,
      aggregateId,
      idempotencyKey,
      payload: Object.freeze({ deletion }),
      type: "source.capture.deleted.v1",
    };
  } else {
    fail("INPUT_INVALID", "Sanitized event type is not allowlisted");
  }
  return deepFreezeJson(event) as SanitizedStoredEventV1;
}

function parseCaptureRecorded(value: unknown): Readonly<CaptureRecordedPayloadV2> {
  const record = exactObject(
    value,
    [
      "acquiredAt",
      "attemptId",
      "byteLength",
      "counts",
      "expiresAt",
      "failureCode",
      "lane",
      "profile",
      "rawDisposition",
      "schemaVersion",
      "sessionId",
      "sourcePlane",
      "status",
    ],
    "Capture-recorded payload",
  );
  const acquiredAt = validateTimestamp(record.acquiredAt, "Capture acquisition time");
  const expiresAt = validateTimestamp(record.expiresAt, "Capture expiry time");
  const sourcePlane = validateEnum(record.sourcePlane, SOURCE_PLANES, "Capture source plane");
  const byteLength = validateSafeInteger(
    record.byteLength,
    "Capture byte count",
    0,
    sourcePlane === "marketplace" ? 2_097_152 : 1_048_576,
  );
  const status = validateEnum(record.status, ["accepted", "rejected"] as const, "Capture status");
  const counts = record.counts === null ? null : parseCaptureCounts(record.counts);
  const failureCode =
    record.failureCode === null
      ? null
      : validateEnum(record.failureCode, CAPTURE_FAILURE_CODES, "Capture failure code");
  if (
    (status === "accepted" && (counts === null || failureCode !== null)) ||
    (status === "rejected" && (counts !== null || failureCode === null))
  ) {
    fail("INPUT_INVALID", "Capture status evidence is inconsistent");
  }
  const acquiredMilliseconds = Date.parse(acquiredAt);
  const expiresMilliseconds = Date.parse(expiresAt);
  if (
    expiresMilliseconds < acquiredMilliseconds ||
    expiresMilliseconds - acquiredMilliseconds > 2 * 60 * 60 * 1_000
  ) {
    fail("INPUT_INVALID", "Capture expiry is outside its allowed window");
  }
  return deepFreezeJson({
    acquiredAt,
    attemptId: validateUuidV4(record.attemptId, "Capture attempt identifier"),
    byteLength,
    counts,
    expiresAt,
    failureCode: failureCode as CaptureFailureCode | null,
    lane: validateEnum(record.lane, LANES, "Capture lane"),
    profile: validateEnum(record.profile, PROFILES, "Capture profile"),
    rawDisposition: validateLiteral(
      record.rawDisposition,
      "encrypted_ephemeral",
      "Raw-data disposition",
    ),
    schemaVersion: validateLiteral(record.schemaVersion, 2, "Capture schema version"),
    sessionId: validateUuidV4(record.sessionId, "Capture session identifier"),
    sourcePlane,
    status,
  }) as Readonly<CaptureRecordedPayloadV2>;
}

function parseCaptureDeleted(value: unknown): Readonly<CaptureDeletedPayloadV1> {
  const record = exactObject(
    value,
    [
      "deletedAt",
      "deletionId",
      "expiredCount",
      "explicitCount",
      "orphanCount",
      "profile",
      "schemaVersion",
      "sessionId",
      "sourcePlane",
      "status",
    ],
    "Capture-deleted payload",
  );
  return deepFreezeJson({
    deletedAt: validateTimestamp(record.deletedAt, "Deletion time"),
    deletionId: validateUuidV4(record.deletionId, "Deletion identifier"),
    expiredCount: validateSafeInteger(record.expiredCount, "Expired capture count", 0, MAX_COUNT),
    explicitCount: validateSafeInteger(
      record.explicitCount,
      "Explicit deletion count",
      0,
      MAX_COUNT,
    ),
    orphanCount: validateSafeInteger(record.orphanCount, "Orphan capture count", 0, MAX_COUNT),
    profile: validateEnum(record.profile, PROFILES, "Deletion profile"),
    schemaVersion: validateLiteral(record.schemaVersion, 1, "Deletion schema version"),
    sessionId: validateUuidV4(record.sessionId, "Deletion session identifier"),
    sourcePlane: validateEnum(record.sourcePlane, SOURCE_PLANES, "Deletion source plane"),
    status: validateLiteral(record.status, "verified", "Deletion status"),
  }) as Readonly<CaptureDeletedPayloadV1>;
}

function parseCaptureCounts(value: unknown): Readonly<CaptureCountsV2> {
  const record = exactObject(
    value,
    ["actorCount", "editedRecordCount", "recordCount"],
    "Capture counts",
  );
  const counts = {
    actorCount: validateSafeInteger(record.actorCount, "Actor count", 0, MAX_COUNT),
    editedRecordCount: validateSafeInteger(
      record.editedRecordCount,
      "Edited-record count",
      0,
      MAX_COUNT,
    ),
    recordCount: validateSafeInteger(record.recordCount, "Record count", 0, MAX_COUNT),
  };
  if (counts.editedRecordCount > counts.recordCount) {
    fail("INPUT_INVALID", "Edited-record count exceeds record count");
  }
  return Object.freeze(counts);
}

export function encodeEventJournal(events: readonly SanitizedStoredEventV1[]): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  for (const event of events) {
    const bytes = Buffer.from(`${canonicalJson(event as unknown as JsonValue)}\n`, "utf8");
    if (bytes.length > MAX_EVENT_LINE_BYTES) {
      fail("ARCHIVE_BOUNDS", "Sanitized event record exceeds its byte bound");
    }
    total += bytes.length;
    if (!Number.isSafeInteger(total) || total > MAX_EVENT_ARTIFACT_BYTES) {
      fail("ARCHIVE_BOUNDS", "Sanitized event archive exceeds its epoch bound");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, total);
}

export function parseEventJournal(bytes: Uint8Array): readonly SanitizedStoredEventV1[] {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_EVENT_ARTIFACT_BYTES) {
    fail("ARCHIVE_BOUNDS", "Sanitized event artifact is outside its byte bound");
  }
  let lineBytes = 0;
  let lineCount = 0;
  for (const byte of bytes) {
    if (byte === 0x0a) {
      if (lineBytes === 0) fail("ARCHIVE_FORMAT", "Sanitized event artifact has an empty record");
      lineCount += 1;
      if (lineCount > MAX_EVENT_RECORDS) {
        fail("ARCHIVE_BOUNDS", "Sanitized event record count is outside its bound");
      }
      lineBytes = 0;
    } else {
      lineBytes += 1;
      if (lineBytes + 1 > MAX_EVENT_LINE_BYTES) {
        fail("ARCHIVE_BOUNDS", "Sanitized event record exceeds its byte bound");
      }
    }
  }
  if (lineBytes !== 0 || bytes.at(-1) !== 0x0a) {
    fail("ARCHIVE_FORMAT", "Sanitized event artifact is truncated");
  }
  if (lineCount === 0) {
    fail("ARCHIVE_BOUNDS", "Sanitized event record count is outside its bound");
  }
  let text: string;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    fail("ARCHIVE_FORMAT", "Sanitized event artifact is not valid UTF-8");
  }
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== lineCount) {
    fail("ARCHIVE_FORMAT", "Sanitized event record framing is invalid");
  }
  const events = lines.map((line) => {
    const lineBytes = Buffer.from(line, "utf8");
    if (lineBytes.length + 1 > MAX_EVENT_LINE_BYTES) {
      fail("ARCHIVE_BOUNDS", "Sanitized event record exceeds its byte bound");
    }
    return parseSanitizedEvent(parseCanonicalJsonBytes(lineBytes, "Sanitized event record"));
  });
  return Object.freeze(events);
}

export function validateEventChain(
  events: readonly SanitizedStoredEventV1[],
  eventState: EventStateEvidenceV1,
  profile: EventArchiveProfile,
  sessionId: string,
  sessionStateAt: string,
): void {
  if (events.length !== eventState.eventCount || events.length !== eventState.headSequence) {
    fail("INTEGRITY_MISMATCH", "Event artifact count does not match state evidence");
  }
  let previousHash = EVENT_STORE_GENESIS_HASH;
  const eventIds = new Set<string>();
  const idempotencyKeys = new Set<string>();
  let tailSessionId = "";
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]!;
    const expectedSequence = index + 1;
    if (event.sequence !== expectedSequence || event.previousHash !== previousHash) {
      fail("INTEGRITY_MISMATCH", "Event sequence or predecessor chain is invalid");
    }
    if (eventIds.has(event.eventId) || idempotencyKeys.has(event.idempotencyKey)) {
      fail("INTEGRITY_MISMATCH", "Event identities are not unique");
    }
    eventIds.add(event.eventId);
    idempotencyKeys.add(event.idempotencyKey);
    const eventProfile =
      event.type === "source.capture.recorded.v2"
        ? event.payload.capture.profile
        : event.payload.deletion.profile;
    const eventSessionId =
      event.type === "source.capture.recorded.v2"
        ? event.payload.capture.sessionId
        : event.payload.deletion.sessionId;
    if (eventProfile !== profile || event.occurredAt > sessionStateAt) {
      fail("INTEGRITY_MISMATCH", "Event profile or time does not match the archive binding");
    }
    const expectedHash = computeStoreEventHash(event);
    if (event.eventHash !== expectedHash) {
      fail("INTEGRITY_MISMATCH", "Event hash does not match the exact sanitized record");
    }
    previousHash = event.eventHash;
    tailSessionId = eventSessionId;
  }
  if (tailSessionId !== sessionId) {
    fail("INTEGRITY_MISMATCH", "Event tail does not bind the archive session");
  }
  const tail = events.at(-1)!;
  if (tail.sequence !== eventState.headSequence || tail.eventHash !== eventState.headHash) {
    fail("INTEGRITY_MISMATCH", "Event tail does not match state evidence");
  }
}

export function computeStoreEventHash(event: SanitizedStoredEventV1): string {
  const payloadJson = canonicalJson(event.payload as unknown as JsonValue);
  const hashInput: JsonValue = {
    aggregateId: event.aggregateId,
    eventId: event.eventId,
    idempotencyKey: event.idempotencyKey,
    occurredAt: event.occurredAt,
    payloadJson,
    previousHash: event.previousHash,
    schemaVersion: EVENT_STORE_SCHEMA_VERSION,
    sequence: event.sequence,
    type: event.type,
  };
  return createHash("sha256")
    .update("rsi-event-v1\0", "utf8")
    .update(canonicalJson(hashInput), "utf8")
    .digest("hex");
}

export function validateDecodedArchiveData(
  events: readonly SanitizedStoredEventV1[],
  binding: {
    readonly eventState: unknown;
    readonly profile: unknown;
    readonly retention: unknown;
    readonly sessionId: unknown;
    readonly sessionState: unknown;
    readonly sessionStateAt: unknown;
    readonly stateEvidence: unknown;
  },
): SanitizedArchiveData {
  const eventState = parseEventState(binding.eventState);
  const profile = validateEnum(binding.profile, PROFILES, "Archive profile");
  const retention = validateEnum(binding.retention, RETENTIONS, "Archive retention");
  const sessionId = validateUuidV4(binding.sessionId, "Archive session identifier");
  const sessionState = validateEnum(binding.sessionState, SESSION_STATES, "Archive session state");
  const sessionStateAt = validateTimestamp(binding.sessionStateAt, "Archive session-state time");
  const stateEvidence = parseStateEvidenceCompanion(binding.stateEvidence);
  if (
    canonicalJson(eventState as unknown as JsonValue) !==
      canonicalJson(stateEvidence.eventState as unknown as JsonValue) ||
    stateEvidence.profile !== profile ||
    stateEvidence.retention !== retention ||
    stateEvidence.sessionId !== sessionId ||
    stateEvidence.sessionState !== sessionState ||
    stateEvidence.sessionStateAt !== sessionStateAt
  ) {
    fail("INTEGRITY_MISMATCH", "Archive/state-evidence binding is invalid");
  }
  validateEventChain(events, eventState, profile, sessionId, sessionStateAt);
  return Object.freeze({
    eventBytes: encodeEventJournal(events),
    events,
    eventState,
    profile,
    retention,
    sessionId,
    sessionState,
    sessionStateAt,
    stateEvidence,
    stateEvidenceBindingSha256: sha256(canonicalJson(stateEvidence as unknown as JsonValue)),
  });
}
