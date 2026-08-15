export const BACKUP_VERSION = 1 as const;
export const BACKUP_TYPE = "rsi.sanitized-state-evidence-component" as const;
export const BACKUP_RECEIPT_TYPE = "rsi.backup.state-evidence-receipt" as const;
export const BACKUP_REPORT_TYPE = "rsi.backup.state-evidence-verification-report" as const;

export type BackupProfile = "canary" | "production-observer";
export type BackupRetention = "month-end-365d" | "session-30d";
export type BackupSessionState = "accepted" | "acceptance-ready" | "locally-verified";

export interface EventStateEvidenceV1 {
  readonly eventStateType: "rsi.backup.event-state-evidence";
  readonly eventCount: number;
  readonly headHash: string;
  readonly headSequence: number;
  readonly storeId: string;
  readonly version: 1;
}

export interface CheckpointPayloadV1 {
  readonly checkpointType: "rsi.store.head";
  readonly createdAt: string;
  readonly journalSequence: number;
  readonly keyId: string;
  readonly previousCheckpointHash: string;
  readonly storeHeadHash: string;
  readonly storeHeadSequence: number;
  readonly storeId: string;
  readonly version: 1;
}

export interface SignedCheckpointV1 {
  readonly checkpointHash: string;
  readonly payload: CheckpointPayloadV1;
  readonly signature: string;
}

export interface CheckpointHeadExportV1 {
  readonly checkpointHash: string;
  readonly checkpointHeadType: "rsi.backup.checkpoint-head";
  readonly journalSequence: number;
  readonly keyId: string;
  readonly storeHeadHash: string;
  readonly storeHeadSequence: number;
  readonly storeId: string;
  readonly version: 1;
}

export interface BackupPublicKeyV1 {
  readonly fingerprintSha256: string;
  readonly keyId: string;
  /** Canonical unpadded base64url Ed25519 SubjectPublicKeyInfo DER. */
  readonly spkiDerBase64url: string;
}

export interface ConfigSchemaHashV1 {
  readonly name: ConfigSchemaName;
  readonly schemaSha256: string;
  readonly version: number;
}

export type ConfigSchemaName =
  | "alert-outbox"
  | "backup-manifest"
  | "capture-registry"
  | "checkpoint-journal"
  | "event-state"
  | "external-anchor-outbox"
  | "observer-config"
  | "operations-state"
  | "preflight-report"
  | "public-projection"
  | "sanitized-event-archive"
  | "sanitized-state-evidence"
  | "session-controller"
  | "session-lifecycle"
  | "source-contracts"
  | "vault";

export type RecoveryRunbookId =
  | "RB-01"
  | "RB-02"
  | "RB-03"
  | "RB-04"
  | "RB-05"
  | "RB-06"
  | "RB-07"
  | "RB-08"
  | "RB-09"
  | "RB-10"
  | "RB-11"
  | "RB-12"
  | "RB-13"
  | "RB-14"
  | "RB-15"
  | "RB-16"
  | "RB-17"
  | "RB-18"
  | "RB-19";

export interface RecoveryEvidenceV1 {
  readonly completedAt: string;
  readonly evidenceSha256: string;
  readonly outcome: "failed" | "passed";
  readonly releaseManifestSha256: string;
  readonly runbookId: RecoveryRunbookId;
}

export interface ReleaseEvidenceV1 {
  readonly commitSha: string;
  readonly configSetSha256: string;
  readonly keyId: string;
  readonly publicKeyFingerprint: string;
  readonly releaseEvidenceType: "rsi.backup.release-evidence";
  readonly releaseManifestSha256: string;
  readonly releaseVersion: string;
  readonly sbomSha256: string;
  readonly sourceTreeSha256: string;
  readonly status: "verified";
  readonly version: 1;
}

export interface SanitizedStateEvidenceSnapshotV1 {
  readonly checkpointJournal: readonly SignedCheckpointV1[];
  readonly checkpointPublicKey: BackupPublicKeyV1;
  readonly configSchemas: readonly ConfigSchemaHashV1[];
  /** Head/count evidence only; this cannot reconstruct any accepted event. */
  readonly eventState: EventStateEvidenceV1;
  readonly profile: BackupProfile;
  readonly recoveryEvidence: readonly RecoveryEvidenceV1[];
  readonly release: ReleaseEvidenceV1;
  readonly releasePublicKey: BackupPublicKeyV1;
  readonly retention: BackupRetention;
  readonly sessionId: string;
  /**
   * `acceptance-ready` is pre-commit evidence; `accepted` is a later
   * post-commit evidence archive. Neither state means the required companion
   * artifacts exist. This package does not orchestrate the cross-store
   * acceptance transition or close its RPO window.
   */
  readonly sessionState: BackupSessionState;
  readonly sessionStateAt: string;
  readonly trustedCheckpointHead: {
    readonly checkpointHash: string;
    readonly journalSequence: number;
  };
}

export interface StateEvidenceSignerV1 {
  readonly keyId: string;
  readonly publicKeySpkiDer: Uint8Array;
  /** The callback receives only the domain-separated manifest bytes. */
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface CreateSanitizedStateEvidenceOptions {
  readonly destinationPath: string;
  readonly signer: StateEvidenceSignerV1;
  readonly snapshot: SanitizedStateEvidenceSnapshotV1;
}

export interface StateEvidenceReceiptV1 {
  readonly archiveSha256: string;
  readonly archiveSizeBytes: number;
  readonly backupId: string;
  readonly checkpointHash: string;
  readonly checkpointJournalSequence: number;
  readonly componentScope: "observer-sanitized-state-evidence";
  readonly manifestSha256: string;
  readonly profile: BackupProfile;
  readonly recoveryCompleteness: "evidence-only";
  readonly receiptType: typeof BACKUP_RECEIPT_TYPE;
  readonly releaseManifestSha256: string;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-event-archive",
    "signed-release-bundle",
  ];
  readonly sessionId: string;
  readonly signerFingerprintSha256: string;
  readonly version: typeof BACKUP_VERSION;
}

export interface StateEvidenceTrustV1 {
  readonly checkpointPublicKeySpkiDer: Uint8Array;
  readonly receipt: StateEvidenceReceiptV1;
  readonly releasePublicKeySpkiDer: Uint8Array;
}

export interface VerifySanitizedStateEvidenceOptions {
  readonly archivePath: string;
  readonly trust: StateEvidenceTrustV1;
}

export interface RestoreSanitizedStateEvidenceOptions extends VerifySanitizedStateEvidenceOptions {
  readonly destinationDirectory: string;
}

export interface StateEvidenceVerificationReportV1 {
  readonly archiveSha256: string;
  readonly artifactCount: 7;
  readonly backupId: string;
  readonly checkpointHash: string;
  readonly componentScope: "observer-sanitized-state-evidence";
  readonly manifestSha256: string;
  readonly profile: BackupProfile;
  /** A verified component is never a claim of complete OBS-REC-003 recovery. */
  readonly recoveryCompleteness: "evidence-only";
  readonly reportType: typeof BACKUP_REPORT_TYPE;
  readonly releaseManifestSha256: string;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-event-archive",
    "signed-release-bundle",
  ];
  readonly sessionId: string;
  readonly signerFingerprintSha256: string;
  readonly status: "verified-evidence-component";
  readonly totalArtifactBytes: number;
  readonly version: typeof BACKUP_VERSION;
}

export interface StateEvidenceRestoreReportV1 extends StateEvidenceVerificationReportV1 {
  readonly restoredFileCount: 8;
}
