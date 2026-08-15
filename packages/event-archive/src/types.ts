export const EVENT_ARCHIVE_VERSION = 1 as const;
export const EVENT_ARCHIVE_TYPE = "rsi.sanitized-event-archive" as const;
export const EVENT_ARCHIVE_RECEIPT_TYPE = "rsi.event-archive.receipt" as const;
export const EVENT_ARCHIVE_REPORT_TYPE = "rsi.event-archive.verification-report" as const;
export const EVENT_ARCHIVE_COMPONENT_ROLE = "sanitized-event-archive" as const;

export type EventArchiveProfile = "canary" | "production-observer";
export type EventArchiveRetention = "month-end-365d" | "session-30d";
export type EventArchiveSessionState = "accepted" | "acceptance-ready" | "locally-verified";
export type ResearchLane = "contract" | "discovery" | "marketplace" | "official" | "security";
export type SourcePlane = "canonical_chain" | "marketplace" | "social";

export type JsonPrimitive = boolean | null | number | string;
export type JsonValue =
  JsonPrimitive | { readonly [key: string]: JsonValue } | readonly JsonValue[];

export interface CaptureCountsV2 {
  readonly actorCount: number;
  readonly editedRecordCount: number;
  readonly recordCount: number;
}

export type CaptureFailureCode =
  | "ABORTED"
  | "CONTENT_LENGTH_MISMATCH"
  | "CREDENTIAL_IN_RESPONSE"
  | "HTTP_STATUS"
  | "INVALID_RESPONSE_SCHEMA"
  | "MALFORMED_JSON"
  | "RESPONSE_TOO_LARGE"
  | "TIMEOUT"
  | "TRANSPORT_FAILURE"
  | "UNSUPPORTED_CONTENT_ENCODING"
  | "UNSUPPORTED_CONTENT_TYPE";

export interface CaptureRecordedPayloadV2 {
  readonly acquiredAt: string;
  readonly attemptId: string;
  readonly byteLength: number;
  readonly counts: CaptureCountsV2 | null;
  readonly expiresAt: string;
  readonly failureCode: CaptureFailureCode | null;
  readonly lane: ResearchLane;
  readonly profile: EventArchiveProfile;
  readonly rawDisposition: "encrypted_ephemeral";
  readonly schemaVersion: 2;
  readonly sessionId: string;
  readonly sourcePlane: SourcePlane;
  readonly status: "accepted" | "rejected";
}

export interface CaptureDeletedPayloadV1 {
  readonly deletedAt: string;
  readonly deletionId: string;
  readonly expiredCount: number;
  readonly explicitCount: number;
  readonly orphanCount: number;
  readonly profile: EventArchiveProfile;
  readonly schemaVersion: 1;
  readonly sessionId: string;
  readonly sourcePlane: SourcePlane;
  readonly status: "verified";
}

interface StoredEventEnvelopeV1 {
  readonly aggregateId: string;
  readonly eventHash: string;
  readonly eventId: string;
  readonly idempotencyKey: string;
  readonly occurredAt: string;
  readonly previousHash: string;
  readonly sequence: number;
}

export interface CaptureRecordedStoredEventV2 extends StoredEventEnvelopeV1 {
  readonly payload: Readonly<{ readonly capture: Readonly<CaptureRecordedPayloadV2> }>;
  readonly type: "source.capture.recorded.v2";
}

export interface CaptureDeletedStoredEventV1 extends StoredEventEnvelopeV1 {
  readonly payload: Readonly<{ readonly deletion: Readonly<CaptureDeletedPayloadV1> }>;
  readonly type: "source.capture.deleted.v1";
}

export type SanitizedStoredEventV1 = CaptureRecordedStoredEventV2 | CaptureDeletedStoredEventV1;

export interface EventStateEvidenceV1 {
  readonly eventCount: number;
  readonly eventStateType: "rsi.backup.event-state-evidence";
  readonly headHash: string;
  readonly headSequence: number;
  readonly storeId: string;
  readonly version: 1;
}

/** Structural copy of the independently retained receipt returned by `@rsi/backup`. */
export interface StateEvidenceReceiptV1 {
  readonly archiveSha256: string;
  readonly archiveSizeBytes: number;
  readonly backupId: string;
  readonly checkpointHash: string;
  readonly checkpointJournalSequence: number;
  readonly componentScope: "observer-sanitized-state-evidence";
  readonly manifestSha256: string;
  readonly profile: EventArchiveProfile;
  readonly recoveryCompleteness: "evidence-only";
  readonly receiptType: "rsi.backup.state-evidence-receipt";
  readonly releaseManifestSha256: string;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-event-archive",
    "signed-release-bundle",
  ];
  readonly sessionId: string;
  readonly signerFingerprintSha256: string;
  readonly version: 1;
}

export type StateEvidenceArtifactRole =
  | "event-state-evidence"
  | "checkpoint-journal"
  | "checkpoint-head"
  | "public-keys"
  | "config-schema-hashes"
  | "recovery-evidence"
  | "release-evidence";

export interface StateEvidenceArtifactDescriptorV1 {
  readonly mediaType: "application/json" | "application/x-ndjson";
  readonly path: string;
  readonly role: StateEvidenceArtifactRole;
  readonly sha256: string;
  readonly sizeBytes: number;
}

/** Closed structural copy of the signed manifest produced by `@rsi/backup`. */
export interface StateEvidenceBackupManifestV1 {
  readonly artifactCount: 7;
  readonly artifacts: readonly StateEvidenceArtifactDescriptorV1[];
  readonly backupId: string;
  readonly backupType: "rsi.sanitized-state-evidence-component";
  readonly checkpoint: {
    readonly checkpointHash: string;
    readonly journalSequence: number;
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
    readonly storeHeadHash: string;
    readonly storeHeadSequence: number;
    readonly storeId: string;
  };
  readonly componentScope: "observer-sanitized-state-evidence";
  readonly createdAt: string;
  readonly eventStateEvidence: {
    readonly eventCount: number;
    readonly headHash: string;
    readonly headSequence: number;
    readonly storeId: string;
  };
  readonly profile: EventArchiveProfile;
  readonly recoveryCompleteness: "evidence-only";
  readonly release: {
    readonly commitSha: string;
    readonly configSetSha256: string;
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
    readonly releaseManifestSha256: string;
    readonly releaseVersion: string;
  };
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-event-archive",
    "signed-release-bundle",
  ];
  readonly retention: EventArchiveRetention;
  readonly session: {
    readonly id: string;
    readonly state: EventArchiveSessionState;
    readonly stateAt: string;
  };
  readonly signer: {
    readonly algorithm: "Ed25519";
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
  };
  readonly totalArtifactBytes: number;
  readonly version: 1;
}

export interface StateEvidenceManifestEnvelopeV1 {
  readonly manifest: StateEvidenceBackupManifestV1;
  readonly signature: string;
}

/** Carries the exact signed manifest from the independently retained `@rsi/backup` component. */
export interface StateEvidenceCompanionV1 {
  readonly eventState: EventStateEvidenceV1;
  readonly manifestEnvelope: StateEvidenceManifestEnvelopeV1;
  readonly profile: EventArchiveProfile;
  readonly releaseKeyId: string;
  readonly receipt: StateEvidenceReceiptV1;
  readonly retention: EventArchiveRetention;
  readonly sessionId: string;
  readonly sessionState: EventArchiveSessionState;
  readonly sessionStateAt: string;
}

export interface SanitizedEventArchiveSnapshotV1 {
  readonly events: readonly SanitizedStoredEventV1[];
  readonly profile: EventArchiveProfile;
  readonly retention: EventArchiveRetention;
  readonly sessionId: string;
  readonly sessionState: EventArchiveSessionState;
  readonly sessionStateAt: string;
  readonly stateEvidence: StateEvidenceCompanionV1;
}

export interface EventArchiveSignerV1 {
  readonly keyId: string;
  readonly publicKeySpkiDer: Uint8Array;
  /** Receives only the domain-separated canonical manifest bytes. */
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface CreateSanitizedEventArchiveOptions {
  readonly createdAt: string;
  readonly destinationPath: string;
  readonly signer: EventArchiveSignerV1;
  readonly snapshot: SanitizedEventArchiveSnapshotV1;
}

export interface SanitizedEventArchiveReceiptV1 {
  readonly archiveId: string;
  readonly archiveSha256: string;
  readonly archiveSizeBytes: number;
  readonly componentRole: typeof EVENT_ARCHIVE_COMPONENT_ROLE;
  readonly eventCount: number;
  readonly headHash: string;
  readonly headSequence: number;
  readonly manifestSha256: string;
  readonly profile: EventArchiveProfile;
  readonly receiptType: typeof EVENT_ARCHIVE_RECEIPT_TYPE;
  readonly releaseManifestSha256: string;
  readonly sessionId: string;
  readonly signerFingerprintSha256: string;
  readonly stateEvidenceArchiveSha256: string;
  readonly stateEvidenceBackupId: string;
  readonly stateEvidenceCheckpointHash: string;
  readonly stateEvidenceManifestSha256: string;
  readonly storeId: string;
  readonly version: typeof EVENT_ARCHIVE_VERSION;
}

export interface SanitizedEventArchiveTrustV1 {
  readonly receipt: SanitizedEventArchiveReceiptV1;
  readonly releasePublicKeySpkiDer: Uint8Array;
  readonly stateEvidence: StateEvidenceCompanionV1;
}

export interface VerifySanitizedEventArchiveOptions {
  readonly archivePath: string;
  readonly trust: SanitizedEventArchiveTrustV1;
}

export interface RestoreSanitizedEventArchiveOptions extends VerifySanitizedEventArchiveOptions {
  readonly destinationDirectory: string;
}

export interface SanitizedEventArchiveVerificationReportV1 {
  readonly archiveId: string;
  readonly archiveSha256: string;
  readonly artifactCount: 1;
  readonly componentRole: typeof EVENT_ARCHIVE_COMPONENT_ROLE;
  readonly eventCount: number;
  readonly headHash: string;
  readonly headSequence: number;
  readonly manifestSha256: string;
  readonly profile: EventArchiveProfile;
  readonly releaseManifestSha256: string;
  readonly reportType: typeof EVENT_ARCHIVE_REPORT_TYPE;
  readonly sessionId: string;
  readonly signerFingerprintSha256: string;
  readonly stateEvidenceBackupId: string;
  readonly status: "verified-restorable-event-archive";
  readonly storeId: string;
  readonly version: typeof EVENT_ARCHIVE_VERSION;
}

export interface SanitizedEventArchiveRestoreReportV1 extends SanitizedEventArchiveVerificationReportV1 {
  readonly restoredFileCount: 2;
}

export interface EventArchiveImportIntegrityReportLike {
  readonly errors: readonly unknown[];
  readonly eventCount: number;
  readonly headHash: string;
  readonly headSequence: number;
  readonly valid: boolean;
}

export interface EventArchiveImportTarget {
  append(input: {
    readonly aggregateId: string;
    readonly eventId: string;
    readonly idempotencyKey: string;
    readonly occurredAt: string;
    readonly payload: JsonValue;
    readonly type: string;
  }): unknown;
  list(filters?: {
    readonly afterSequence?: number;
    readonly beforeSequence?: number;
    readonly limit?: number;
    readonly order?: "asc" | "desc";
  }): readonly unknown[];
  verifyIntegrity(): EventArchiveImportIntegrityReportLike;
  withExclusiveTransaction<T>(operation: () => T): T;
}

export interface ImportSanitizedEventArchiveOptions extends VerifySanitizedEventArchiveOptions {
  readonly target: EventArchiveImportTarget;
}

export type SanitizedEventArchiveImportReportV1 = Omit<
  SanitizedEventArchiveVerificationReportV1,
  "status"
> & {
  readonly importedEventCount: number;
  readonly status: "imported-and-verified";
};
