import { Buffer } from "node:buffer";
import { randomUUID, verify } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  canonicalJson,
  copyOrdinaryBytes,
  decodeSignature,
  exactArray,
  exactObject,
  importEd25519PublicKey,
  parseCanonicalJsonBytes,
  secureEqualHex,
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
import {
  EVENT_STORE_GENESIS_HASH,
  EVENT_STORE_SCHEMA_VERSION,
  MAX_EVENT_ARTIFACT_BYTES,
  encodeEventJournal,
  parseEventJournal,
  parseEventState,
  parseStateEvidenceCompanion,
  validateDecodedArchiveData,
  type SanitizedArchiveData,
} from "./schema.js";
import {
  EVENT_ARCHIVE_COMPONENT_ROLE,
  EVENT_ARCHIVE_RECEIPT_TYPE,
  EVENT_ARCHIVE_REPORT_TYPE,
  EVENT_ARCHIVE_TYPE,
  EVENT_ARCHIVE_VERSION,
  type EventArchiveSignerV1,
  type JsonValue,
  type SanitizedEventArchiveReceiptV1,
  type SanitizedEventArchiveTrustV1,
  type SanitizedEventArchiveVerificationReportV1,
  type SanitizedStoredEventV1,
  type StateEvidenceCompanionV1,
} from "./types.js";

export const EVENT_ARCHIVE_MAGIC = Buffer.from("RSIEVENT1", "ascii");
export const MAX_MANIFEST_ENVELOPE_BYTES = 64 * 1024;
export const MAX_EVENT_ARCHIVE_BYTES =
  EVENT_ARCHIVE_MAGIC.length + 4 + MAX_MANIFEST_ENVELOPE_BYTES + MAX_EVENT_ARTIFACT_BYTES;

const SIGNATURE_DOMAIN = Buffer.from("rsi-sanitized-event-archive-manifest-v1\0", "utf8");
const STATE_EVIDENCE_SIGNATURE_DOMAIN = Buffer.from(
  "rsi-sanitized-state-evidence-manifest-v1\0",
  "utf8",
);
const PROFILES = ["canary", "production-observer"] as const;
const RETENTIONS = ["month-end-365d", "session-30d"] as const;
const SESSION_STATES = ["accepted", "acceptance-ready", "locally-verified"] as const;
const ALLOWED_EVENT_TYPES = Object.freeze([
  "source.capture.recorded.v2",
  "source.capture.deleted.v1",
] as const);
const REQUIRED_COMPANIONS = Object.freeze([
  "sanitized-state-evidence",
  "signed-release-bundle",
] as const);

export interface EventArtifactDescriptorV1 {
  readonly eventCount: number;
  readonly mediaType: "application/x-ndjson";
  readonly path: "sanitized-events.v1.jsonl";
  readonly role: "sanitized-event-records";
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface SanitizedEventArchiveManifestV1 {
  readonly allowedEventTypes: readonly ["source.capture.recorded.v2", "source.capture.deleted.v1"];
  readonly archiveId: string;
  readonly archiveType: typeof EVENT_ARCHIVE_TYPE;
  readonly artifact: EventArtifactDescriptorV1;
  readonly artifactCount: 1;
  readonly companionFor: "@rsi/backup:observer-sanitized-state-evidence";
  readonly componentRole: typeof EVENT_ARCHIVE_COMPONENT_ROLE;
  readonly createdAt: string;
  readonly profile: "canary" | "production-observer";
  readonly recoveryCompleteness: "event-history-only";
  readonly releaseManifestSha256: string;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-state-evidence",
    "signed-release-bundle",
  ];
  readonly retention: "month-end-365d" | "session-30d";
  readonly session: {
    readonly id: string;
    readonly state: "accepted" | "acceptance-ready" | "locally-verified";
    readonly stateAt: string;
  };
  readonly signer: {
    readonly algorithm: "Ed25519";
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
  };
  readonly stateEvidence: {
    readonly archiveSha256: string;
    readonly backupId: string;
    readonly bindingSha256: string;
    readonly checkpointHash: string;
    readonly manifestSha256: string;
  };
  readonly store: {
    readonly eventCount: number;
    readonly genesisHash: string;
    readonly headHash: string;
    readonly headSequence: number;
    readonly schemaVersion: 1;
    readonly storeId: string;
  };
  readonly version: typeof EVENT_ARCHIVE_VERSION;
}

export interface EventArchiveEnvelopeV1 {
  readonly manifest: SanitizedEventArchiveManifestV1;
  readonly signature: string;
}

export interface NormalizedEventArchiveSigner {
  readonly keyId: string;
  readonly publicKeySpkiDer: Uint8Array;
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface EncodedEventArchive {
  readonly bytes: Buffer;
  readonly receipt: SanitizedEventArchiveReceiptV1;
}

export interface VerifiedEventArchive {
  readonly envelope: EventArchiveEnvelopeV1;
  readonly eventBytes: Buffer;
  readonly events: readonly SanitizedStoredEventV1[];
  readonly report: SanitizedEventArchiveVerificationReportV1;
}

export function normalizeSigner(value: unknown): NormalizedEventArchiveSigner {
  const record = exactObject(value, ["keyId", "publicKeySpkiDer", "sign"], "Archive signer");
  const publicKeySpkiDer = copyOrdinaryBytes(
    record.publicKeySpkiDer,
    "Archive signer public key",
    512,
  );
  importEd25519PublicKey(publicKeySpkiDer, "Archive signer public key");
  if (typeof record.sign !== "function" || utilTypes.isProxy(record.sign))
    fail("INPUT_INVALID", "Archive signer callback is invalid");
  return Object.freeze({
    keyId: validateIdentifier(record.keyId, "Archive signer key identifier"),
    publicKeySpkiDer,
    sign: record.sign as EventArchiveSignerV1["sign"],
  });
}

export async function encodeSignedEventArchive(
  data: SanitizedArchiveData,
  createdAtValue: unknown,
  signer: NormalizedEventArchiveSigner,
): Promise<EncodedEventArchive> {
  const createdAt = validateTimestamp(createdAtValue, "Archive creation time");
  if (
    createdAt < data.sessionStateAt ||
    createdAt < data.events.at(-1)!.occurredAt ||
    createdAt < data.stateEvidence.manifestEnvelope.manifest.createdAt
  ) {
    fail("INPUT_INVALID", "Archive creation time predates bound evidence");
  }
  const signerFingerprint = sha256(signer.publicKeySpkiDer);
  assertStateEvidenceManifestProofSignature(data.stateEvidence, signer.publicKeySpkiDer);
  if (
    signerFingerprint !== data.stateEvidence.receipt.signerFingerprintSha256 ||
    signer.keyId !== data.stateEvidence.releaseKeyId
  ) {
    fail("INPUT_INVALID", "Archive signer does not match state-evidence signer");
  }
  const artifact: EventArtifactDescriptorV1 = Object.freeze({
    eventCount: data.events.length,
    mediaType: "application/x-ndjson",
    path: "sanitized-events.v1.jsonl",
    role: "sanitized-event-records",
    sha256: sha256(data.eventBytes),
    sizeBytes: data.eventBytes.length,
  });
  const manifest: SanitizedEventArchiveManifestV1 = Object.freeze({
    allowedEventTypes: ALLOWED_EVENT_TYPES,
    archiveId: randomUUID(),
    archiveType: EVENT_ARCHIVE_TYPE,
    artifact,
    artifactCount: 1,
    companionFor: "@rsi/backup:observer-sanitized-state-evidence",
    componentRole: EVENT_ARCHIVE_COMPONENT_ROLE,
    createdAt,
    profile: data.profile,
    recoveryCompleteness: "event-history-only",
    releaseManifestSha256: data.stateEvidence.receipt.releaseManifestSha256,
    requiredCompanionArtifacts: REQUIRED_COMPANIONS,
    retention: data.retention,
    session: Object.freeze({
      id: data.sessionId,
      state: data.sessionState,
      stateAt: data.sessionStateAt,
    }),
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: signer.keyId,
      publicKeyFingerprintSha256: signerFingerprint,
    }),
    stateEvidence: Object.freeze({
      archiveSha256: data.stateEvidence.receipt.archiveSha256,
      backupId: data.stateEvidence.receipt.backupId,
      bindingSha256: data.stateEvidenceBindingSha256,
      checkpointHash: data.stateEvidence.receipt.checkpointHash,
      manifestSha256: data.stateEvidence.receipt.manifestSha256,
    }),
    store: Object.freeze({
      eventCount: data.eventState.eventCount,
      genesisHash: EVENT_STORE_GENESIS_HASH,
      headHash: data.eventState.headHash,
      headSequence: data.eventState.headSequence,
      schemaVersion: EVENT_STORE_SCHEMA_VERSION,
      storeId: data.eventState.storeId,
    }),
    version: EVENT_ARCHIVE_VERSION,
  });
  const message = signatureMessage(manifest);
  let signatureValue: Uint8Array;
  try {
    signatureValue = await signer.sign(Uint8Array.from(message));
  } catch {
    fail("SIGNER_FAILED", "Archive signer failed");
  }
  const signature = copyOrdinaryBytes(signatureValue, "Archive signature", 64);
  if (signature.length !== 64)
    fail("SIGNER_FAILED", "Archive signer returned an invalid signature");
  const publicKey = importEd25519PublicKey(signer.publicKeySpkiDer, "Archive signer public key");
  if (!verify(null, message, publicKey, signature)) {
    fail("SIGNATURE_INVALID", "Archive signer returned an unverifiable signature");
  }
  const envelope: EventArchiveEnvelopeV1 = Object.freeze({
    manifest,
    signature: Buffer.from(signature).toString("base64url"),
  });
  signature.fill(0);
  const envelopeBytes = Buffer.from(canonicalJson(envelope as unknown as JsonValue), "utf8");
  if (envelopeBytes.length === 0 || envelopeBytes.length > MAX_MANIFEST_ENVELOPE_BYTES) {
    fail("ARCHIVE_BOUNDS", "Signed event-archive manifest exceeds its byte bound");
  }
  const header = Buffer.alloc(EVENT_ARCHIVE_MAGIC.length + 4);
  EVENT_ARCHIVE_MAGIC.copy(header);
  header.writeUInt32BE(envelopeBytes.length, EVENT_ARCHIVE_MAGIC.length);
  const bytes = Buffer.concat([header, envelopeBytes, data.eventBytes]);
  if (bytes.length > MAX_EVENT_ARCHIVE_BYTES) {
    fail("ARCHIVE_BOUNDS", "Event archive exceeds its byte bound");
  }
  const receipt = receiptFor(manifest, bytes);
  return Object.freeze({ bytes, receipt });
}

export function verifyEventArchiveBytes(
  bytesValue: Uint8Array,
  trustValue: unknown,
): VerifiedEventArchive {
  const bytes = Buffer.from(bytesValue);
  if (bytes.length <= EVENT_ARCHIVE_MAGIC.length + 4 || bytes.length > MAX_EVENT_ARCHIVE_BYTES) {
    fail("ARCHIVE_BOUNDS", "Event archive is outside its byte bound");
  }
  const trust = parseTrust(trustValue);
  assertStateEvidenceManifestProofSignature(trust.stateEvidence, trust.releasePublicKeySpkiDer);
  if (
    bytes.length !== trust.receipt.archiveSizeBytes ||
    !secureEqualHex(sha256(bytes), trust.receipt.archiveSha256)
  ) {
    fail("TRUST_MISMATCH", "Event archive does not match the retained receipt");
  }
  const { envelope, eventBytes } = decodeArchive(bytes);
  const { manifest } = envelope;
  const manifestSha256 = sha256(canonicalJson(manifest as unknown as JsonValue));
  assertReceiptMatchesManifest(trust.receipt, manifest, manifestSha256);
  const stateEvidenceBindingSha256 = sha256(
    canonicalJson(trust.stateEvidence as unknown as JsonValue),
  );
  if (
    !secureEqualHex(manifest.stateEvidence.bindingSha256, stateEvidenceBindingSha256) ||
    manifest.stateEvidence.archiveSha256 !== trust.stateEvidence.receipt.archiveSha256 ||
    manifest.stateEvidence.backupId !== trust.stateEvidence.receipt.backupId ||
    manifest.stateEvidence.checkpointHash !== trust.stateEvidence.receipt.checkpointHash ||
    manifest.stateEvidence.manifestSha256 !== trust.stateEvidence.receipt.manifestSha256 ||
    manifest.releaseManifestSha256 !== trust.stateEvidence.receipt.releaseManifestSha256 ||
    manifest.profile !== trust.stateEvidence.receipt.profile ||
    manifest.session.id !== trust.stateEvidence.receipt.sessionId ||
    manifest.createdAt < trust.stateEvidence.manifestEnvelope.manifest.createdAt
  ) {
    fail("TRUST_MISMATCH", "Event archive does not match retained state evidence");
  }
  const releaseKey = importEd25519PublicKey(
    trust.releasePublicKeySpkiDer,
    "Trusted release public key",
  );
  if (
    sha256(trust.releasePublicKeySpkiDer) !== manifest.signer.publicKeyFingerprintSha256 ||
    manifest.signer.publicKeyFingerprintSha256 !==
      trust.stateEvidence.receipt.signerFingerprintSha256 ||
    manifest.signer.keyId !== trust.stateEvidence.releaseKeyId ||
    !verify(null, signatureMessage(manifest), releaseKey, decodeSignature(envelope.signature))
  ) {
    fail("SIGNATURE_INVALID", "Event-archive signature or release-key binding is invalid");
  }
  if (
    eventBytes.length !== manifest.artifact.sizeBytes ||
    sha256(eventBytes) !== manifest.artifact.sha256
  ) {
    fail("INTEGRITY_MISMATCH", "Sanitized event artifact digest is invalid");
  }
  const events = parseEventJournal(eventBytes);
  const data = validateDecodedArchiveData(events, {
    eventState: {
      eventCount: manifest.store.eventCount,
      eventStateType: "rsi.backup.event-state-evidence",
      headHash: manifest.store.headHash,
      headSequence: manifest.store.headSequence,
      storeId: manifest.store.storeId,
      version: 1,
    },
    profile: manifest.profile,
    retention: manifest.retention,
    sessionId: manifest.session.id,
    sessionState: manifest.session.state,
    sessionStateAt: manifest.session.stateAt,
    stateEvidence: trust.stateEvidence,
  });
  if (
    !data.eventBytes.equals(eventBytes) ||
    canonicalJson(data.eventState as unknown as JsonValue) !==
      canonicalJson(trust.stateEvidence.eventState as unknown as JsonValue) ||
    manifest.artifact.eventCount !== events.length
  ) {
    fail("INTEGRITY_MISMATCH", "Event archive semantic bindings are invalid");
  }
  const report: SanitizedEventArchiveVerificationReportV1 = Object.freeze({
    archiveId: manifest.archiveId,
    archiveSha256: trust.receipt.archiveSha256,
    artifactCount: 1,
    componentRole: EVENT_ARCHIVE_COMPONENT_ROLE,
    eventCount: events.length,
    headHash: manifest.store.headHash,
    headSequence: manifest.store.headSequence,
    manifestSha256,
    profile: manifest.profile,
    releaseManifestSha256: manifest.releaseManifestSha256,
    reportType: EVENT_ARCHIVE_REPORT_TYPE,
    sessionId: manifest.session.id,
    signerFingerprintSha256: trust.receipt.signerFingerprintSha256,
    stateEvidenceBackupId: manifest.stateEvidence.backupId,
    status: "verified-restorable-event-archive",
    storeId: manifest.store.storeId,
    version: EVENT_ARCHIVE_VERSION,
  });
  return Object.freeze({
    envelope,
    eventBytes: Buffer.from(eventBytes),
    events,
    report,
  });
}

function decodeArchive(bytes: Buffer): {
  readonly envelope: EventArchiveEnvelopeV1;
  readonly eventBytes: Buffer;
} {
  const minimum = EVENT_ARCHIVE_MAGIC.length + 4;
  if (
    bytes.length < minimum ||
    !bytes.subarray(0, EVENT_ARCHIVE_MAGIC.length).equals(EVENT_ARCHIVE_MAGIC)
  ) {
    fail("ARCHIVE_FORMAT", "Event archive magic is invalid");
  }
  const envelopeLength = bytes.readUInt32BE(EVENT_ARCHIVE_MAGIC.length);
  if (
    envelopeLength === 0 ||
    envelopeLength > MAX_MANIFEST_ENVELOPE_BYTES ||
    minimum + envelopeLength >= bytes.length
  ) {
    fail("ARCHIVE_BOUNDS", "Signed event-archive manifest is outside its bound");
  }
  const envelopeValue = parseCanonicalJsonBytes(
    bytes.subarray(minimum, minimum + envelopeLength),
    "Signed event-archive manifest",
  );
  const envelopeRecord = exactObject(
    envelopeValue,
    ["manifest", "signature"],
    "Event-archive envelope",
  );
  const envelope: EventArchiveEnvelopeV1 = Object.freeze({
    manifest: parseManifest(envelopeRecord.manifest),
    signature: decodeSignature(envelopeRecord.signature).toString("base64url"),
  });
  const eventBytes = Buffer.from(bytes.subarray(minimum + envelopeLength));
  if (eventBytes.length !== envelope.manifest.artifact.sizeBytes) {
    fail("ARCHIVE_FORMAT", "Event archive is truncated or has trailing bytes");
  }
  return Object.freeze({ envelope, eventBytes });
}

export function parseManifest(value: unknown): SanitizedEventArchiveManifestV1 {
  const record = exactObject(
    value,
    [
      "allowedEventTypes",
      "archiveId",
      "archiveType",
      "artifact",
      "artifactCount",
      "companionFor",
      "componentRole",
      "createdAt",
      "profile",
      "recoveryCompleteness",
      "releaseManifestSha256",
      "requiredCompanionArtifacts",
      "retention",
      "session",
      "signer",
      "stateEvidence",
      "store",
      "version",
    ],
    "Event-archive manifest",
  );
  validateLiteral(record.archiveType, EVENT_ARCHIVE_TYPE, "Archive type");
  validateLiteral(record.artifactCount, 1, "Archive artifact count");
  validateLiteral(record.componentRole, EVENT_ARCHIVE_COMPONENT_ROLE, "Archive component role");
  validateLiteral(
    record.companionFor,
    "@rsi/backup:observer-sanitized-state-evidence",
    "Archive companion binding",
  );
  validateLiteral(record.recoveryCompleteness, "event-history-only", "Recovery completeness");
  validateLiteral(record.version, EVENT_ARCHIVE_VERSION, "Archive version");
  parseExactTuple(record.allowedEventTypes, ALLOWED_EVENT_TYPES, "Allowed event types");
  parseExactTuple(record.requiredCompanionArtifacts, REQUIRED_COMPANIONS, "Required companions");
  const artifactRecord = exactObject(
    record.artifact,
    ["eventCount", "mediaType", "path", "role", "sha256", "sizeBytes"],
    "Event artifact descriptor",
  );
  validateLiteral(artifactRecord.mediaType, "application/x-ndjson", "Event artifact media type");
  validateLiteral(artifactRecord.path, "sanitized-events.v1.jsonl", "Event artifact path");
  validateLiteral(artifactRecord.role, "sanitized-event-records", "Event artifact role");
  const eventCount = validateSafeInteger(artifactRecord.eventCount, "Event artifact count", 1);
  const artifact: EventArtifactDescriptorV1 = Object.freeze({
    eventCount,
    mediaType: "application/x-ndjson",
    path: "sanitized-events.v1.jsonl",
    role: "sanitized-event-records",
    sha256: validateHash(artifactRecord.sha256, "Event artifact hash"),
    sizeBytes: validateSafeInteger(
      artifactRecord.sizeBytes,
      "Event artifact size",
      1,
      MAX_EVENT_ARTIFACT_BYTES,
    ),
  });
  const sessionRecord = exactObject(record.session, ["id", "state", "stateAt"], "Archive session");
  const signerRecord = exactObject(
    record.signer,
    ["algorithm", "keyId", "publicKeyFingerprintSha256"],
    "Archive signer",
  );
  validateLiteral(signerRecord.algorithm, "Ed25519", "Archive signature algorithm");
  const stateEvidenceRecord = exactObject(
    record.stateEvidence,
    ["archiveSha256", "backupId", "bindingSha256", "checkpointHash", "manifestSha256"],
    "State-evidence binding",
  );
  const storeRecord = exactObject(
    record.store,
    ["eventCount", "genesisHash", "headHash", "headSequence", "schemaVersion", "storeId"],
    "Event-store binding",
  );
  validateLiteral(storeRecord.genesisHash, EVENT_STORE_GENESIS_HASH, "Event-store genesis hash");
  validateLiteral(
    storeRecord.schemaVersion,
    EVENT_STORE_SCHEMA_VERSION,
    "Event-store schema version",
  );
  const storeCount = validateSafeInteger(storeRecord.eventCount, "Store event count", 1);
  const headSequence = validateSafeInteger(storeRecord.headSequence, "Store head sequence", 1);
  if (storeCount !== headSequence || storeCount !== eventCount) {
    fail("ARCHIVE_FORMAT", "Manifest event counts are inconsistent");
  }
  const createdAt = validateTimestamp(record.createdAt, "Archive creation time");
  const stateAt = validateTimestamp(sessionRecord.stateAt, "Archive session-state time");
  if (createdAt < stateAt) fail("ARCHIVE_FORMAT", "Archive predates its session state");
  return Object.freeze({
    allowedEventTypes: ALLOWED_EVENT_TYPES,
    archiveId: validateUuidV4(record.archiveId, "Archive identifier"),
    archiveType: EVENT_ARCHIVE_TYPE,
    artifact,
    artifactCount: 1,
    companionFor: "@rsi/backup:observer-sanitized-state-evidence",
    componentRole: EVENT_ARCHIVE_COMPONENT_ROLE,
    createdAt,
    profile: validateEnum(record.profile, PROFILES, "Archive profile"),
    recoveryCompleteness: "event-history-only",
    releaseManifestSha256: validateHash(record.releaseManifestSha256, "Release manifest hash"),
    requiredCompanionArtifacts: REQUIRED_COMPANIONS,
    retention: validateEnum(record.retention, RETENTIONS, "Archive retention"),
    session: Object.freeze({
      id: validateUuidV4(sessionRecord.id, "Archive session identifier"),
      state: validateEnum(sessionRecord.state, SESSION_STATES, "Archive session state"),
      stateAt,
    }),
    signer: Object.freeze({
      algorithm: "Ed25519",
      keyId: validateIdentifier(signerRecord.keyId, "Archive signer key identifier"),
      publicKeyFingerprintSha256: validateHash(
        signerRecord.publicKeyFingerprintSha256,
        "Archive signer fingerprint",
      ),
    }),
    stateEvidence: Object.freeze({
      archiveSha256: validateHash(stateEvidenceRecord.archiveSha256, "State-evidence archive hash"),
      backupId: validateUuidV4(stateEvidenceRecord.backupId, "State-evidence backup identifier"),
      bindingSha256: validateHash(stateEvidenceRecord.bindingSha256, "State-evidence binding hash"),
      checkpointHash: validateHash(
        stateEvidenceRecord.checkpointHash,
        "State-evidence checkpoint hash",
      ),
      manifestSha256: validateHash(
        stateEvidenceRecord.manifestSha256,
        "State-evidence manifest hash",
      ),
    }),
    store: Object.freeze({
      eventCount: storeCount,
      genesisHash: EVENT_STORE_GENESIS_HASH,
      headHash: validateHash(storeRecord.headHash, "Store head hash"),
      headSequence,
      schemaVersion: EVENT_STORE_SCHEMA_VERSION,
      storeId: validateIdentifier(storeRecord.storeId, "Store identifier"),
    }),
    version: EVENT_ARCHIVE_VERSION,
  });
}

function parseExactTuple(value: unknown, expected: readonly string[], safeName: string): void {
  const actual = exactArray(value, safeName);
  if (actual.length !== expected.length || actual.some((item, index) => item !== expected[index])) {
    fail("ARCHIVE_FORMAT", `${safeName} is invalid`);
  }
}

function parseReceipt(value: unknown): SanitizedEventArchiveReceiptV1 {
  const record = exactObject(
    value,
    [
      "archiveId",
      "archiveSha256",
      "archiveSizeBytes",
      "componentRole",
      "eventCount",
      "headHash",
      "headSequence",
      "manifestSha256",
      "profile",
      "receiptType",
      "releaseManifestSha256",
      "sessionId",
      "signerFingerprintSha256",
      "stateEvidenceArchiveSha256",
      "stateEvidenceBackupId",
      "stateEvidenceCheckpointHash",
      "stateEvidenceManifestSha256",
      "storeId",
      "version",
    ],
    "Retained event-archive receipt",
  );
  validateLiteral(record.componentRole, EVENT_ARCHIVE_COMPONENT_ROLE, "Receipt component role");
  validateLiteral(record.receiptType, EVENT_ARCHIVE_RECEIPT_TYPE, "Event-archive receipt type");
  validateLiteral(record.version, EVENT_ARCHIVE_VERSION, "Event-archive receipt version");
  const eventCount = validateSafeInteger(record.eventCount, "Receipt event count", 1);
  const headSequence = validateSafeInteger(record.headSequence, "Receipt head sequence", 1);
  if (eventCount !== headSequence) fail("INPUT_INVALID", "Receipt event counts are inconsistent");
  return Object.freeze({
    archiveId: validateUuidV4(record.archiveId, "Receipt archive identifier"),
    archiveSha256: validateHash(record.archiveSha256, "Receipt archive hash"),
    archiveSizeBytes: validateSafeInteger(
      record.archiveSizeBytes,
      "Receipt archive size",
      1,
      MAX_EVENT_ARCHIVE_BYTES,
    ),
    componentRole: EVENT_ARCHIVE_COMPONENT_ROLE,
    eventCount,
    headHash: validateHash(record.headHash, "Receipt head hash"),
    headSequence,
    manifestSha256: validateHash(record.manifestSha256, "Receipt manifest hash"),
    profile: validateEnum(record.profile, PROFILES, "Receipt profile"),
    receiptType: EVENT_ARCHIVE_RECEIPT_TYPE,
    releaseManifestSha256: validateHash(record.releaseManifestSha256, "Receipt release hash"),
    sessionId: validateUuidV4(record.sessionId, "Receipt session identifier"),
    signerFingerprintSha256: validateHash(
      record.signerFingerprintSha256,
      "Receipt signer fingerprint",
    ),
    stateEvidenceArchiveSha256: validateHash(
      record.stateEvidenceArchiveSha256,
      "Receipt state-evidence archive hash",
    ),
    stateEvidenceBackupId: validateUuidV4(
      record.stateEvidenceBackupId,
      "Receipt state-evidence backup identifier",
    ),
    stateEvidenceCheckpointHash: validateHash(
      record.stateEvidenceCheckpointHash,
      "Receipt state-evidence checkpoint hash",
    ),
    stateEvidenceManifestSha256: validateHash(
      record.stateEvidenceManifestSha256,
      "Receipt state-evidence manifest hash",
    ),
    storeId: validateIdentifier(record.storeId, "Receipt store identifier"),
    version: EVENT_ARCHIVE_VERSION,
  });
}

function parseTrust(value: unknown): SanitizedEventArchiveTrustV1 {
  const record = exactObject(
    value,
    ["receipt", "releasePublicKeySpkiDer", "stateEvidence"],
    "Event-archive trust",
  );
  const releasePublicKeySpkiDer = copyOrdinaryBytes(
    record.releasePublicKeySpkiDer,
    "Trusted release public key",
    512,
  );
  importEd25519PublicKey(releasePublicKeySpkiDer, "Trusted release public key");
  return Object.freeze({
    receipt: parseReceipt(record.receipt),
    releasePublicKeySpkiDer,
    stateEvidence: parseStateEvidenceCompanion(record.stateEvidence),
  });
}

function signatureMessage(manifest: SanitizedEventArchiveManifestV1): Buffer {
  return Buffer.concat([
    SIGNATURE_DOMAIN,
    Buffer.from(canonicalJson(manifest as unknown as JsonValue), "utf8"),
  ]);
}

function assertStateEvidenceManifestProofSignature(
  stateEvidence: StateEvidenceCompanionV1,
  releasePublicKeySpkiDer: Uint8Array,
): void {
  const { manifest, signature } = stateEvidence.manifestEnvelope;
  const releaseKey = importEd25519PublicKey(
    releasePublicKeySpkiDer,
    "State-evidence manifest release public key",
  );
  if (
    sha256(releasePublicKeySpkiDer) !== manifest.signer.publicKeyFingerprintSha256 ||
    !verify(
      null,
      Buffer.concat([
        STATE_EVIDENCE_SIGNATURE_DOMAIN,
        Buffer.from(canonicalJson(manifest as unknown as JsonValue), "utf8"),
      ]),
      releaseKey,
      decodeSignature(signature),
    )
  ) {
    fail("SIGNATURE_INVALID", "Signed state-evidence manifest proof is invalid");
  }
}

function receiptFor(
  manifest: SanitizedEventArchiveManifestV1,
  bytes: Buffer,
): SanitizedEventArchiveReceiptV1 {
  return Object.freeze({
    archiveId: manifest.archiveId,
    archiveSha256: sha256(bytes),
    archiveSizeBytes: bytes.length,
    componentRole: EVENT_ARCHIVE_COMPONENT_ROLE,
    eventCount: manifest.store.eventCount,
    headHash: manifest.store.headHash,
    headSequence: manifest.store.headSequence,
    manifestSha256: sha256(canonicalJson(manifest as unknown as JsonValue)),
    profile: manifest.profile,
    receiptType: EVENT_ARCHIVE_RECEIPT_TYPE,
    releaseManifestSha256: manifest.releaseManifestSha256,
    sessionId: manifest.session.id,
    signerFingerprintSha256: manifest.signer.publicKeyFingerprintSha256,
    stateEvidenceArchiveSha256: manifest.stateEvidence.archiveSha256,
    stateEvidenceBackupId: manifest.stateEvidence.backupId,
    stateEvidenceCheckpointHash: manifest.stateEvidence.checkpointHash,
    stateEvidenceManifestSha256: manifest.stateEvidence.manifestSha256,
    storeId: manifest.store.storeId,
    version: EVENT_ARCHIVE_VERSION,
  });
}

function assertReceiptMatchesManifest(
  receipt: SanitizedEventArchiveReceiptV1,
  manifest: SanitizedEventArchiveManifestV1,
  manifestSha256: string,
): void {
  if (
    receipt.archiveId !== manifest.archiveId ||
    receipt.componentRole !== manifest.componentRole ||
    receipt.eventCount !== manifest.store.eventCount ||
    receipt.headHash !== manifest.store.headHash ||
    receipt.headSequence !== manifest.store.headSequence ||
    receipt.manifestSha256 !== manifestSha256 ||
    receipt.profile !== manifest.profile ||
    receipt.releaseManifestSha256 !== manifest.releaseManifestSha256 ||
    receipt.sessionId !== manifest.session.id ||
    receipt.signerFingerprintSha256 !== manifest.signer.publicKeyFingerprintSha256 ||
    receipt.stateEvidenceArchiveSha256 !== manifest.stateEvidence.archiveSha256 ||
    receipt.stateEvidenceBackupId !== manifest.stateEvidence.backupId ||
    receipt.stateEvidenceCheckpointHash !== manifest.stateEvidence.checkpointHash ||
    receipt.stateEvidenceManifestSha256 !== manifest.stateEvidence.manifestSha256 ||
    receipt.storeId !== manifest.store.storeId
  ) {
    fail("TRUST_MISMATCH", "Event-archive manifest does not match the retained receipt");
  }
}

export function stateEvidenceForInternalTrust(
  value: StateEvidenceCompanionV1,
): StateEvidenceCompanionV1 {
  return parseStateEvidenceCompanion(value);
}

export function eventStateFromManifest(
  manifest: SanitizedEventArchiveManifestV1,
): ReturnType<typeof parseEventState> {
  return parseEventState({
    eventCount: manifest.store.eventCount,
    eventStateType: "rsi.backup.event-state-evidence",
    headHash: manifest.store.headHash,
    headSequence: manifest.store.headSequence,
    storeId: manifest.store.storeId,
    version: 1,
  });
}

export function canonicalEventBytes(events: readonly SanitizedStoredEventV1[]): Buffer {
  return encodeEventJournal(events);
}
