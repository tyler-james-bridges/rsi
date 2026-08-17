export const SESSION_LIFECYCLE_SCHEMA_VERSION = 1 as const;

export const SESSION_PROFILES = ["canary", "production-observer"] as const;
export type SessionProfile = (typeof SESSION_PROFILES)[number];

export const SESSION_STATES = [
  "planned",
  "preflighted",
  "running",
  "stopping",
  "locally_verified",
  "externally_verified",
  "cost_pending",
  "accepted",
  "invalid",
] as const;
export type SessionState = (typeof SESSION_STATES)[number];

export const SESSION_INVALIDATION_REASONS = [
  "operator-abort",
  "crash-recovery",
  "preflight-failed",
  "clock-violation",
  "bound-violation",
  "supervision-expired",
  "missed-supervision-acknowledgement",
  "source-incomplete",
  "purge-failed",
  "local-verification-failed",
  "external-verification-failed",
  "cost-reconciliation-failed",
  "cost-over-reservation",
  "cost-reconciliation-late",
  "incident-detected",
  "qualification-date-conflict",
] as const;
export type SessionInvalidationReason = (typeof SESSION_INVALIDATION_REASONS)[number];

export type PreflightCheckStatus = "fail" | "pass" | "unknown";
export type ClosureStatus = "closed" | "failed" | "unknown";
export type VerificationStatus = "failed" | "unknown" | "verified";
export type CleanlinessStatus = "clean" | "failed" | "unknown";

export type SessionRecoveryArtifactEvidenceV1 = Readonly<{
  sanitizedStateEvidence:
    | Readonly<{ archiveSha256: null; status: "failed" | "unknown" }>
    | Readonly<{ archiveSha256: string; status: "verified-evidence-component" }>;
  sanitizedEventArchive:
    | Readonly<{ archiveSha256: null; status: "failed" | "unknown" }>
    | Readonly<{ archiveSha256: string; status: "verified-restorable-event-archive" }>;
  signedReleaseBundle:
    | Readonly<{ archiveSha256: null; status: "failed" | "unknown" }>
    | Readonly<{ archiveSha256: string; status: "verified-restorable-release-component" }>;
}>;

export interface SessionPreflightEvidenceV1 {
  readonly schemaVersion: 1;
  readonly evidenceHash: string;
  readonly profile: SessionProfile;
  readonly observedAt: string;
  readonly ready: boolean;
  readonly checks: Readonly<{
    alertPath: PreflightCheckStatus;
    backupTarget: PreflightCheckStatus;
    budgetReservations: PreflightCheckStatus;
    clock: PreflightCheckStatus;
    credentialScopes: PreflightCheckStatus;
    databaseIntegrity: PreflightCheckStatus;
    disk: PreflightCheckStatus;
    externalAnchor: PreflightCheckStatus;
    financialAdaptersDisabled: PreflightCheckStatus;
    networkAllowlist: PreflightCheckStatus;
    releaseConfiguration: PreflightCheckStatus;
    runtime: PreflightCheckStatus;
  }>;
}

export interface SessionLocalVerificationEvidenceV1 {
  readonly schemaVersion: 1;
  readonly evidenceHash: string;
  readonly xLanes: Readonly<{
    contract: ClosureStatus;
    discovery: ClosureStatus;
    marketplace: ClosureStatus;
    official: ClosureStatus;
    security: ClosureStatus;
  }>;
  readonly openSea: Readonly<{
    rest: ClosureStatus;
    stream: ClosureStatus;
  }>;
  readonly canonicalChain: ClosureStatus;
  readonly eventIntegrity: VerificationStatus;
  readonly digestIntegrity: VerificationStatus;
  readonly purge: Readonly<{
    captureKeys: "destroyed" | "failed" | "unknown";
    encryptedIndexes: CleanlinessStatus;
    orphanScan: CleanlinessStatus;
    rawCaptures: CleanlinessStatus;
  }>;
  readonly localCheckpoint: VerificationStatus;
  readonly recoveryArtifacts: SessionRecoveryArtifactEvidenceV1;
  readonly alertCheck: "failed" | "healthy" | "unknown";
  readonly explicitClose: "complete" | "failed" | "unknown";
  readonly incidentCount: number;
}

export interface SessionExternalVerificationEvidenceV1 {
  readonly schemaVersion: 1;
  readonly evidenceHash: string;
  readonly externalAnchor: VerificationStatus;
  readonly retainedSuffix: VerificationStatus;
  readonly macBookVerification: VerificationStatus;
}

export interface SessionCostEvidenceV1 {
  readonly schemaVersion: 1;
  readonly evidenceHash: string;
  readonly billingStatus: "complete" | "missing" | "unknown";
  readonly currency: "USD_MICRO";
  readonly outstandingAtomic: string;
  readonly reconciledAtomic: string;
  readonly reservedAtomic: string;
}

export interface SessionAcceptanceEvidenceV1 {
  readonly schemaVersion: 1;
  readonly preflight: "pass";
  readonly xLanes: Readonly<{
    contract: "closed";
    discovery: "closed";
    marketplace: "closed";
    official: "closed";
    security: "closed";
  }>;
  readonly openSea: Readonly<{ rest: "closed"; stream: "closed" }>;
  readonly canonicalChain: "closed";
  readonly eventIntegrity: "verified";
  readonly digestIntegrity: "verified";
  readonly purge: Readonly<{
    captureKeys: "destroyed";
    encryptedIndexes: "clean";
    orphanScan: "clean";
    rawCaptures: "clean";
  }>;
  readonly localCheckpoint: "verified";
  readonly externalAnchor: "verified";
  readonly retainedSuffix: "verified";
  readonly macBookVerification: "verified";
  readonly recoveryArtifacts: Readonly<{
    sanitizedStateEvidence: Readonly<{
      archiveSha256: string;
      status: "verified-evidence-component";
    }>;
    sanitizedEventArchive: Readonly<{
      archiveSha256: string;
      status: "verified-restorable-event-archive";
    }>;
    signedReleaseBundle: Readonly<{
      archiveSha256: string;
      status: "verified-restorable-release-component";
    }>;
  }>;
  readonly alertCheck: "healthy";
  readonly explicitClose: "complete";
  readonly costs: Readonly<{
    billingStatus: "complete";
    currency: "USD_MICRO";
    outstandingAtomic: "0";
    reconciledAtomic: string;
    reservedAtomic: string;
  }>;
  readonly incidents: "zero";
  readonly evidenceHashes: Readonly<{
    cost: string;
    external: string;
    local: string;
    preflight: string;
  }>;
  readonly supervision: Readonly<{
    minute45: "acknowledged";
    minute90: "acknowledged";
    observerOnly: "acknowledged";
    typedSessionId: "acknowledged";
    duration: "within-limit";
  }>;
}

export interface SessionStartAcknowledgementsV1 {
  readonly observerOnly: "acknowledged";
  readonly typedSessionId: "acknowledged";
}

export interface SessionRecordV1 {
  readonly schemaVersion: 1;
  readonly sessionId: string;
  readonly profile: SessionProfile;
  readonly qualificationDate: string;
  readonly state: SessionState;
  readonly egressStatus: "blocked" | "eligible";
  readonly plannedAt: string;
  readonly supervisedUntil: string;
  readonly updatedAt: string;
  readonly preflightedAt: string | null;
  readonly preflightEvidence: Readonly<SessionPreflightEvidenceV1> | null;
  readonly startedAt: string | null;
  readonly startAcknowledgements: Readonly<SessionStartAcknowledgementsV1> | null;
  readonly minute45AcknowledgedAt: string | null;
  readonly minute90AcknowledgedAt: string | null;
  readonly stoppedAt: string | null;
  readonly locallyVerifiedAt: string | null;
  readonly localEvidence: Readonly<SessionLocalVerificationEvidenceV1> | null;
  readonly externallyVerifiedAt: string | null;
  readonly externalEvidence: Readonly<SessionExternalVerificationEvidenceV1> | null;
  readonly costReconciledAt: string | null;
  readonly costEvidence: Readonly<SessionCostEvidenceV1> | null;
  readonly acceptedAt: string | null;
  readonly acceptanceEvidence: Readonly<SessionAcceptanceEvidenceV1> | null;
  readonly invalidatedAt: string | null;
  readonly invalidationReason: SessionInvalidationReason | null;
}

export interface OpenSessionCoordinatorOptions {
  readonly expectedProfile: SessionProfile;
  readonly path: string;
  readonly recoveredAt: string;
  readonly stateKey: Uint8Array;
  readonly trustedHead?: SessionLifecycleTrustedHeadV1;
}

export interface PlanSessionInput {
  readonly plannedAt: string;
  readonly qualificationDate: string;
  readonly sessionId: string;
  readonly supervisedUntil: string;
}

export interface RecordSessionPreflightInput {
  readonly evidence: SessionPreflightEvidenceV1;
  readonly recordedAt: string;
  readonly sessionId: string;
}

export interface StartSessionInput {
  readonly observerOnlyAcknowledgement: true;
  readonly sessionId: string;
  readonly startedAt: string;
  readonly typedSessionIdAcknowledgement: string;
}

export interface RecordSupervisionAcknowledgementInput {
  readonly acknowledgedAt: string;
  readonly checkpoint: "minute-45" | "minute-90";
  readonly sessionId: string;
}

export interface StopSessionInput {
  readonly sessionId: string;
  readonly stoppedAt: string;
}

export interface RecordLocalVerificationInput {
  readonly evidence: SessionLocalVerificationEvidenceV1;
  readonly sessionId: string;
  readonly verifiedAt: string;
}

export interface RecordExternalVerificationInput {
  readonly evidence: SessionExternalVerificationEvidenceV1;
  readonly sessionId: string;
  readonly verifiedAt: string;
}

export interface RecordCostReconciliationInput {
  readonly evidence: SessionCostEvidenceV1;
  readonly reconciledAt: string;
  readonly sessionId: string;
}

export interface AcceptSessionInput {
  readonly acceptedAt: string;
  readonly sessionId: string;
}

export interface InvalidateSessionInput {
  readonly invalidatedAt: string;
  readonly reason: SessionInvalidationReason;
  readonly sessionId: string;
}

export interface SessionRecoveryReceiptV1 {
  readonly cleanupRequired: boolean;
  readonly invalidatedSessionCount: number;
  readonly schemaVersion: 1;
}

export interface SessionLifecycleSummaryV1 {
  readonly activeSessionCount: number;
  readonly auditEntryCount: number;
  readonly profile: SessionProfile;
  readonly schemaVersion: 1;
  readonly sessionCount: number;
  readonly states: Readonly<Record<SessionState, number>>;
}

export interface SessionLifecycleIntegrityReportV1 {
  readonly activeSessionCount: number;
  readonly auditEntryCount: number;
  readonly profile: SessionProfile;
  readonly schemaVersion: 1;
  readonly sessionCount: number;
  readonly valid: true;
}

export interface SessionLifecycleTrustedHeadV1 {
  readonly auditMac: string;
  readonly auditSequence: number;
  readonly profile: SessionProfile;
  readonly schemaVersion: 1;
}
