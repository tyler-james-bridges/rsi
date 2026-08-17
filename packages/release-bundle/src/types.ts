export const RELEASE_BUNDLE_VERSION = 1 as const;
export const RELEASE_BUNDLE_TYPE = "rsi.signed-release-bundle" as const;
export const RELEASE_BUNDLE_RECEIPT_TYPE = "rsi.release-bundle.retained-receipt" as const;
export const RELEASE_BUNDLE_REPORT_TYPE = "rsi.release-bundle.verification-report" as const;

export type ReleaseArtifactRole =
  | "config-schema"
  | "lockfile"
  | "recovery-procedure"
  | "runbook"
  | "sbom"
  | "source"
  | "test-summary";

export type ReleaseArtifactMediaType =
  "application/json" | "application/yaml" | "text/markdown" | "text/plain" | "text/typescript";

export interface ReleaseArtifactInputV1 {
  readonly bytes: Uint8Array;
  readonly mediaType: ReleaseArtifactMediaType;
  readonly path: string;
  readonly role: ReleaseArtifactRole;
}

export interface ReleaseArtifactDescriptorV1 {
  readonly mediaType: ReleaseArtifactMediaType;
  readonly path: string;
  readonly role: ReleaseArtifactRole;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface ReleaseArtifactBindingsV1 {
  readonly artifactSetSha256: string;
  readonly configSetSha256: string;
  readonly lockfileSha256: string;
  readonly recoverySetSha256: string;
  readonly runbookSetSha256: string;
  readonly sbomSha256: string;
  readonly sourceTreeSha256: string;
  readonly testSummarySha256: string;
}

export interface ReleaseIdentityV1 extends ReleaseArtifactBindingsV1 {
  readonly commitSha: string;
  readonly createdAt: string;
  readonly gitTreeSha: string;
  readonly nodeVersion: string;
  readonly pnpmVersion: string;
  readonly predecessorManifestSha256: string | null;
  readonly releaseVersion: string;
}

export interface ReleaseBundleSignerV1 {
  readonly keyId: string;
  /** Canonical Ed25519 SubjectPublicKeyInfo DER. */
  readonly publicKeySpkiDer: Uint8Array;
  /** Receives only a copy of the domain-separated canonical manifest bytes. */
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface CreateSignedReleaseBundleOptions {
  readonly artifacts: readonly ReleaseArtifactInputV1[];
  readonly destinationPath: string;
  readonly release: ReleaseIdentityV1;
  readonly signer: ReleaseBundleSignerV1;
}

export interface ReleaseBundleReceiptV1 extends ReleaseArtifactBindingsV1 {
  readonly archiveSha256: string;
  readonly archiveSizeBytes: number;
  readonly bundleId: string;
  readonly commitSha: string;
  readonly companionType: "signed-release-bundle";
  readonly gitTreeSha: string;
  readonly manifestSha256: string;
  readonly predecessorManifestSha256: string | null;
  readonly receiptType: typeof RELEASE_BUNDLE_RECEIPT_TYPE;
  readonly recoveryCompleteness: "release-component";
  readonly releaseVersion: string;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-state-evidence",
    "sanitized-event-archive",
  ];
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
  readonly version: typeof RELEASE_BUNDLE_VERSION;
}

export interface ReleaseBundleTrustV1 {
  readonly receipt: ReleaseBundleReceiptV1;
  readonly releasePublicKeySpkiDer: Uint8Array;
}

export interface VerifySignedReleaseBundleOptions {
  readonly archivePath: string;
  readonly trust: ReleaseBundleTrustV1;
}

export interface RestoreSignedReleaseBundleOptions extends VerifySignedReleaseBundleOptions {
  readonly destinationDirectory: string;
}

export interface ReleaseBundleVerificationReportV1 extends ReleaseArtifactBindingsV1 {
  readonly archiveSha256: string;
  readonly artifactCount: number;
  readonly bundleId: string;
  readonly commitSha: string;
  readonly companionType: "signed-release-bundle";
  readonly gitTreeSha: string;
  readonly manifestSha256: string;
  readonly recoveryCompleteness: "release-component";
  readonly releaseVersion: string;
  readonly reportType: typeof RELEASE_BUNDLE_REPORT_TYPE;
  readonly requiredCompanionArtifacts: readonly [
    "sanitized-state-evidence",
    "sanitized-event-archive",
  ];
  readonly signerFingerprintSha256: string;
  readonly status: "verified-restorable-release-component";
  readonly totalArtifactBytes: number;
  readonly version: typeof RELEASE_BUNDLE_VERSION;
}

export interface ReleaseBundleRestoreReportV1 extends ReleaseBundleVerificationReportV1 {
  readonly restoredFileCount: number;
}
