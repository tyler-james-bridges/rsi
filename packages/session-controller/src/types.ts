import type { VerifySanitizedStateEvidenceOptions } from "@rsi/backup";
import type { VerifySanitizedEventArchiveOptions } from "@rsi/event-archive";
import type { VerifySignedReleaseBundleOptions } from "@rsi/release-bundle";
import type {
  SessionLocalVerificationEvidenceV1,
  SessionProfile,
  SessionRecordV1,
  SqliteSessionCoordinator,
} from "@rsi/session-lifecycle";

export interface ExpectedSessionRecoveryBindingsV1 {
  readonly profile: SessionProfile;
  readonly releaseManifestSha256: string;
  readonly sessionId: string;
}

export interface VerifySessionRecoveryArtifactsOptions {
  readonly eventArchive: VerifySanitizedEventArchiveOptions;
  readonly expected: ExpectedSessionRecoveryBindingsV1;
  readonly releaseBundle: VerifySignedReleaseBundleOptions;
  readonly stateEvidence: VerifySanitizedStateEvidenceOptions;
}

export interface VerifiedSessionRecoveryArtifactsV1 {
  readonly schemaVersion: 1;
  readonly profile: SessionProfile;
  readonly releaseManifestSha256: string;
  readonly sessionId: string;
  readonly signerFingerprintSha256: string;
  readonly stateEvidence: Readonly<{
    archiveSha256: string;
    backupId: string;
    manifestSha256: string;
    status: "verified-evidence-component";
  }>;
  readonly eventArchive: Readonly<{
    archiveSha256: string;
    eventCount: number;
    headHash: string;
    headSequence: number;
    manifestSha256: string;
    status: "verified-restorable-event-archive";
    storeId: string;
  }>;
  readonly releaseBundle: Readonly<{
    archiveSha256: string;
    commitSha: string;
    manifestSha256: string;
    releaseVersion: string;
    status: "verified-restorable-release-component";
  }>;
}

export type SessionLocalVerificationFactsV1 = Omit<
  SessionLocalVerificationEvidenceV1,
  "evidenceHash" | "recoveryArtifacts"
>;

export interface RecordVerifiedLocalClosureOptions {
  readonly coordinator: SqliteSessionCoordinator;
  readonly facts: SessionLocalVerificationFactsV1;
  readonly recovery: VerifiedSessionRecoveryArtifactsV1;
  readonly sessionId: string;
  readonly verifiedAt: string;
}

export type RecordVerifiedLocalClosureResult = Readonly<SessionRecordV1>;
