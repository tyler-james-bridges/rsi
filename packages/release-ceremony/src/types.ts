import type {
  ReleaseArtifactBindingsV1,
  ReleaseArtifactInputV1,
  ReleaseBundleSignerV1,
  ReleaseIdentityV1,
} from "@rsi/release-bundle";

import type { FoundationTagSignerV1 } from "./foundation-tag.js";
import type { FoundationPinnedReleaseIdentityV1 } from "./release-identity.js";
import type { FoundationIndependentReviewEvidenceV1 } from "./review-evidence.js";

export const FOUNDATION_RELEASE_VERSION = "0.1.0-foundation.1" as const;
export const FOUNDATION_TAG = "foundation-v1" as const;
export const FOUNDATION_CI_EVIDENCE_TYPE = "rsi.foundation-ci-evidence" as const;
export const FOUNDATION_CI_EVIDENCE_VERSION = 1 as const;
export const FOUNDATION_CEREMONY_REPORT_TYPE = "rsi.foundation-ceremony-report" as const;
export const FOUNDATION_CEREMONY_REPORT_VERSION = 2 as const;

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
  readonly conclusionPath: string;
  readonly confirmCommit: string;
  readonly confirmReleaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly destinationPath: string;
  readonly reportPath: string;
  readonly receiptPath: string;
  readonly reviewEvidencePath: string;
  readonly tagObjectPath: string;
}

export interface FoundationCeremonyReportV2 extends ReleaseArtifactBindingsV1 {
  readonly archiveSha256: string;
  readonly bundleId: string;
  readonly ciEvidenceSha256: string;
  readonly ciRunId: string;
  readonly commitSha: string;
  readonly gitTreeSha: string;
  readonly helperBinarySha256: string;
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly helperCompilerIdentitySha256: string;
  readonly helperSourceSha256: string;
  readonly identitySha256: string;
  readonly independentReviewEvidenceSha256: string;
  readonly manifestSha256: string;
  readonly platformIdentitySha256: string;
  readonly provisioningReceiptSha256: string;
  readonly readinessConclusionSha256: string;
  readonly releaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly reportType: typeof FOUNDATION_CEREMONY_REPORT_TYPE;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly signatureCount: 2;
  readonly status: "verified-foundation-release-and-detached-tag";
  readonly tagGitObjectSha1: string;
  readonly tagName: typeof FOUNDATION_TAG;
  readonly tagObjectSha256: string;
  readonly tagUnsignedPayloadSha256: string;
  readonly version: typeof FOUNDATION_CEREMONY_REPORT_VERSION;
}

export interface FoundationCeremonyCustody {
  readonly withSigners: <T>(
    identity: FoundationPinnedReleaseIdentityV1,
    operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
  ) => Promise<T>;
}

export interface FoundationCeremonySignersV1 {
  readonly releaseSigner: ReleaseBundleSignerV1;
  readonly tagSigner: FoundationTagSignerV1;
}

export type FoundationCeremonyOutputSuffix =
  ".ceremony-report.json" | ".foundation-tag" | ".readiness-conclusion.json" | ".receipt.json";

export interface FoundationOutputReservation {
  /**
   * Publishes into the owner-only file reserved before custody begins. A failed
   * publication must preserve every byte that may have reached the file.
   */
  readonly publish: (bytes: Uint8Array) => Promise<void>;
  /** Closes the reservation without deleting or truncating its partial file. */
  readonly preserve: () => Promise<void>;
}

export type FoundationTagObjectReservation = FoundationOutputReservation;

export interface FoundationCeremonyDependencies {
  readonly assertHostOffline: () => Promise<void>;
  readonly collectInventory: (
    evidence: FoundationCiEvidenceV1,
    createdAt: string,
  ) => Promise<FoundationReleaseInventory>;
  readonly custody: FoundationCeremonyCustody;
  readonly now: () => Date;
  readonly platformIdentitySha256: () => Promise<string>;
  readonly platformModel: () => Promise<string>;
  readonly readCiEvidence: (path: string) => Promise<{
    readonly evidence: FoundationCiEvidenceV1;
    readonly sha256: string;
  }>;
  readonly readPinnedIdentity: (commitSha: string) => Promise<FoundationPinnedReleaseIdentityV1>;
  readonly readReviewEvidence: (path: string) => Promise<{
    readonly evidence: FoundationIndependentReviewEvidenceV1;
    readonly sha256: string;
  }>;
  readonly reserveOutput: (
    path: string,
    suffix: FoundationCeremonyOutputSuffix,
  ) => Promise<FoundationOutputReservation>;
}
