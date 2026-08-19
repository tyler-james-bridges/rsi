import type {
  ReleaseArtifactBindingsV1,
  ReleaseArtifactInputV1,
  ReleaseBundleReceiptV1,
  ReleaseBundleSignerV1,
  ReleaseIdentityV1,
} from "@rsi/release-bundle";

export const FOUNDATION_RELEASE_VERSION = "0.1.0-foundation.1" as const;
export const FOUNDATION_TAG = "foundation-v1" as const;
export const FOUNDATION_CI_EVIDENCE_TYPE = "rsi.foundation-ci-evidence" as const;
export const FOUNDATION_CI_EVIDENCE_VERSION = 1 as const;
export const FOUNDATION_CEREMONY_REPORT_TYPE = "rsi.foundation-ceremony-report" as const;
export const FOUNDATION_CEREMONY_REPORT_VERSION = 1 as const;

export type FoundationRequiredCheckName =
  | "actions-pinned"
  | "contract-traceability"
  | "dependency-audit"
  | "format"
  | "full-history-secret-scan"
  | "generated-files"
  | "offline-drills"
  | "offline-demos"
  | "release-inventory"
  | "test"
  | "typecheck"
  | "working-tree-clean";

export interface FoundationCiCheckV1 {
  readonly name: FoundationRequiredCheckName;
  readonly outcome: "passed";
}

export interface FoundationCiJobV1 {
  readonly conclusion: "success";
  readonly name: "gitleaks-history" | "quality";
}

export interface FoundationCiEvidenceV1 {
  readonly branch: "main";
  readonly commitSha: string;
  readonly completedAt: string;
  readonly evidenceType: typeof FOUNDATION_CI_EVIDENCE_TYPE;
  readonly event: "push";
  readonly jobs: readonly [FoundationCiJobV1, FoundationCiJobV1];
  readonly repository: "tyler-james-bridges/rsi";
  readonly requiredChecks: readonly FoundationCiCheckV1[];
  readonly runId: string;
  readonly runUrl: string;
  readonly version: typeof FOUNDATION_CI_EVIDENCE_VERSION;
  readonly workflow: "ci";
}

export interface FoundationInventoryReportV1 extends ReleaseArtifactBindingsV1 {
  readonly artifactCount: number;
  readonly commitSha: string;
  readonly gitTreeSha: string;
  readonly releaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly sourceTreeSha256: string;
  readonly trackedFileCount: number;
}

export interface FoundationReleaseInventory {
  readonly artifacts: readonly ReleaseArtifactInputV1[];
  readonly release: ReleaseIdentityV1;
  readonly report: FoundationInventoryReportV1;
}

export interface FoundationCeremonyOptions {
  readonly ciEvidencePath: string;
  readonly confirmCommit: string;
  readonly confirmReleaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly destinationPath: string;
  readonly receiptPath: string;
}

export interface FoundationCeremonyReportV1 extends ReleaseArtifactBindingsV1 {
  readonly archiveSha256: string;
  readonly bundleId: string;
  readonly ciEvidenceSha256: string;
  readonly ciRunId: string;
  readonly commitSha: string;
  readonly gitTreeSha: string;
  readonly manifestSha256: string;
  readonly releaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly reportType: typeof FOUNDATION_CEREMONY_REPORT_TYPE;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly status: "verified-foundation-release";
  readonly version: typeof FOUNDATION_CEREMONY_REPORT_VERSION;
}

export interface FoundationCeremonyCustody {
  readonly withSigner: <T>(operation: (signer: ReleaseBundleSignerV1) => Promise<T>) => Promise<T>;
}

export interface FoundationCeremonyDependencies {
  readonly collectInventory: (
    evidence: FoundationCiEvidenceV1,
    createdAt: string,
  ) => Promise<FoundationReleaseInventory>;
  readonly custody: FoundationCeremonyCustody;
  readonly now: () => Date;
  readonly platformModel: () => Promise<string>;
  readonly readCiEvidence: (path: string) => Promise<{
    readonly evidence: FoundationCiEvidenceV1;
    readonly sha256: string;
  }>;
  readonly removeOwnOutput: (path: string, receipt: ReleaseBundleReceiptV1) => Promise<void>;
  readonly writeReceipt: (path: string, receipt: ReleaseBundleReceiptV1) => Promise<void>;
}
