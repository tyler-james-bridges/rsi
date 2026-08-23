import { spawnSync } from "node:child_process";
import { constants as fsConstants, existsSync, type BigIntStats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { types as utilTypes } from "node:util";

import {
  deriveReleaseArtifactBindings,
  verifySignedReleaseBundle,
  type ReleaseArtifactBindingsV1,
  type ReleaseBundleReceiptV1,
  type ReleaseBundleVerificationReportV1,
} from "@rsi/release-bundle";

import {
  canonicalJson,
  exactObject,
  validateGitHash,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail, FoundationCeremonyError } from "./errors.js";
import { verifyFoundationSignedTagArtifact } from "./foundation-tag.js";
import {
  readFoundationCiEvidenceFile,
  readPinnedFoundationReleaseIdentity,
  readFoundationIndependentReviewEvidenceFile,
} from "./host.js";
import { collectFoundationReleaseInventory } from "./inventory.js";
import type { FoundationPinnedReleaseIdentityV1 } from "./release-identity.js";
import type { FoundationIndependentReviewEvidenceV1 } from "./review-evidence.js";
import {
  decodeFoundationStageAReadinessConclusion,
  foundationStageAReadinessConclusionSha256,
  verifyFoundationBuiltReadinessConclusion,
  type FoundationStageAReadinessBindingsV1,
} from "./readiness-conclusion.js";
import {
  FOUNDATION_CEREMONY_REPORT_TYPE,
  FOUNDATION_CEREMONY_REPORT_VERSION,
  FOUNDATION_RELEASE_VERSION,
  FOUNDATION_TAG,
  type FoundationCiEvidenceV1,
  type FoundationCeremonyReportV2,
  type FoundationReleaseInventory,
} from "./types.js";

const MAX_JSON_BYTES = 64 * 1024;
const MAX_TAG_BYTES = 64 * 1024;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RUN_ID_PATTERN = /^[1-9]\d{0,19}$/u;
const APPROVED_REMOTE = "https://github.com/tyler-james-bridges/rsi.git";
const APPROVED_SSH_REMOTE = "git@github.com:tyler-james-bridges/rsi.git";
const EXPECTED_NODE_VERSION = "24.19.0";
const EXPECTED_PNPM_VERSION = "11.20.0";
const MAX_EVIDENCE_AGE_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const HARDENED_GIT_ENV = Object.freeze({
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
});
const HARDENED_GIT_OPTIONS = Object.freeze([
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
] as const);

const ARTIFACT_BINDING_KEYS = Object.freeze([
  "artifactSetSha256",
  "configSetSha256",
  "lockfileSha256",
  "recoverySetSha256",
  "runbookSetSha256",
  "sbomSha256",
  "sourceTreeSha256",
  "testSummarySha256",
] as const satisfies readonly (keyof ReleaseArtifactBindingsV1)[]);

export interface FoundationCeremonyVerificationOptions {
  readonly archivePath: string;
  readonly ciEvidencePath: string;
  readonly conclusionPath: string;
  readonly confirmCommit: string;
  readonly confirmReleaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly receiptPath: string;
  readonly reportPath: string;
  readonly reviewEvidencePath: string;
  readonly tagObjectPath: string;
}

export interface FoundationCeremonyVerificationDependencies {
  readonly collectInventory: (
    repositoryRoot: string,
    evidence: FoundationCiEvidenceV1,
    createdAt: string,
  ) => Promise<FoundationReleaseInventory>;
  readonly readCiEvidence: (
    path: string,
    repositoryRoot: string,
  ) => Promise<{ readonly evidence: FoundationCiEvidenceV1; readonly sha256: string }>;
  readonly readPinnedIdentity: (
    repositoryRoot: string,
    commitSha: string,
  ) => Promise<FoundationPinnedReleaseIdentityV1>;
  readonly readRepositoryTree: (repositoryRoot: string, commitSha: string) => string;
  readonly readReviewEvidence: (
    path: string,
    repositoryRoot: string,
    commitSha: string,
  ) => Promise<{
    readonly evidence: FoundationIndependentReviewEvidenceV1;
    readonly sha256: string;
  }>;
}

const PRODUCTION_VERIFICATION_DEPENDENCIES: FoundationCeremonyVerificationDependencies =
  Object.freeze({
    collectInventory: async (
      repositoryRoot: string,
      evidence: FoundationCiEvidenceV1,
      createdAt: string,
    ) =>
      collectFoundationReleaseInventory({
        ciEvidence: evidence,
        createdAt,
        mode: "ceremony",
        repositoryRoot,
      }),
    readCiEvidence: readFoundationCiEvidenceFile,
    readPinnedIdentity: readPinnedFoundationReleaseIdentity,
    readRepositoryTree: readFoundationVerificationRepositoryTree,
    readReviewEvidence: readFoundationIndependentReviewEvidenceFile,
  });

/** Strictly parse the fixed v2 report shape and all of its claimed identities. */
export function parseFoundationCeremonyReport(value: unknown): FoundationCeremonyReportV2 {
  const record = exactObject(
    value,
    [
      "archiveSha256",
      "artifactSetSha256",
      "bundleId",
      "ciEvidenceSha256",
      "ciRunId",
      "commitSha",
      "configSetSha256",
      "gitTreeSha",
      "helperBinarySha256",
      "helperCompatibilityEvidenceSha256",
      "helperCompatibilityTestedCommitSha",
      "helperCompilerIdentitySha256",
      "helperSourceSha256",
      "identitySha256",
      "independentReviewEvidenceSha256",
      "lockfileSha256",
      "manifestSha256",
      "platformIdentitySha256",
      "provisioningReceiptSha256",
      "readinessConclusionSha256",
      "recoverySetSha256",
      "releaseVersion",
      "reportType",
      "runbookSetSha256",
      "sbomSha256",
      "signatureCount",
      "signerFingerprintSha256",
      "signerKeyId",
      "sourceTreeSha256",
      "status",
      "tagGitObjectSha1",
      "tagName",
      "tagObjectSha256",
      "tagUnsignedPayloadSha256",
      "testSummarySha256",
      "version",
    ],
    "Foundation ceremony report",
  );
  if (
    record.reportType !== FOUNDATION_CEREMONY_REPORT_TYPE ||
    record.version !== FOUNDATION_CEREMONY_REPORT_VERSION ||
    record.releaseVersion !== FOUNDATION_RELEASE_VERSION ||
    record.signatureCount !== 2 ||
    record.status !== "verified-foundation-release-and-detached-tag" ||
    record.tagName !== FOUNDATION_TAG
  ) {
    fail("VERIFICATION_FAILED", "Foundation ceremony report identity or status is invalid");
  }
  if (typeof record.bundleId !== "string" || !UUID_V4_PATTERN.test(record.bundleId)) {
    fail("INPUT_INVALID", "Foundation ceremony bundle identifier is invalid");
  }
  if (typeof record.ciRunId !== "string" || !RUN_ID_PATTERN.test(record.ciRunId)) {
    fail("INPUT_INVALID", "Foundation ceremony CI run identifier is invalid");
  }
  const signerFingerprintSha256 = validateHash(
    record.signerFingerprintSha256,
    "Foundation ceremony signer fingerprint",
  );
  const signerKeyId = validateIdentifier(record.signerKeyId, "Foundation ceremony signer key ID");
  if (signerKeyId !== `rsi-release-${signerFingerprintSha256.slice(0, 16)}`) {
    fail("VERIFICATION_FAILED", "Foundation ceremony signer identity is invalid");
  }
  return Object.freeze({
    archiveSha256: validateHash(record.archiveSha256, "Foundation ceremony archive SHA-256"),
    artifactSetSha256: validateHash(
      record.artifactSetSha256,
      "Foundation ceremony artifact-set SHA-256",
    ),
    bundleId: record.bundleId,
    ciEvidenceSha256: validateHash(
      record.ciEvidenceSha256,
      "Foundation ceremony CI evidence SHA-256",
    ),
    ciRunId: record.ciRunId,
    commitSha: validateGitHash(record.commitSha, "Foundation ceremony commit"),
    configSetSha256: validateHash(
      record.configSetSha256,
      "Foundation ceremony configuration-set SHA-256",
    ),
    gitTreeSha: validateGitHash(record.gitTreeSha, "Foundation ceremony Git tree"),
    helperBinarySha256: validateHash(
      record.helperBinarySha256,
      "Foundation ceremony helper binary SHA-256",
    ),
    helperCompatibilityEvidenceSha256: validateHash(
      record.helperCompatibilityEvidenceSha256,
      "Foundation ceremony helper compatibility evidence SHA-256",
    ),
    helperCompatibilityTestedCommitSha: validateGitHash(
      record.helperCompatibilityTestedCommitSha,
      "Foundation ceremony helper compatibility tested commit",
    ),
    helperCompilerIdentitySha256: validateHash(
      record.helperCompilerIdentitySha256,
      "Foundation ceremony helper compiler identity SHA-256",
    ),
    helperSourceSha256: validateHash(
      record.helperSourceSha256,
      "Foundation ceremony helper source SHA-256",
    ),
    identitySha256: validateHash(record.identitySha256, "Foundation ceremony identity SHA-256"),
    independentReviewEvidenceSha256: validateHash(
      record.independentReviewEvidenceSha256,
      "Foundation ceremony independent-review evidence SHA-256",
    ),
    lockfileSha256: validateHash(record.lockfileSha256, "Foundation ceremony lockfile SHA-256"),
    manifestSha256: validateHash(record.manifestSha256, "Foundation ceremony manifest SHA-256"),
    platformIdentitySha256: validateHash(
      record.platformIdentitySha256,
      "Foundation ceremony platform identity SHA-256",
    ),
    provisioningReceiptSha256: validateHash(
      record.provisioningReceiptSha256,
      "Foundation ceremony provisioning receipt SHA-256",
    ),
    readinessConclusionSha256: validateHash(
      record.readinessConclusionSha256,
      "Foundation ceremony readiness conclusion SHA-256",
    ),
    recoverySetSha256: validateHash(
      record.recoverySetSha256,
      "Foundation ceremony recovery-set SHA-256",
    ),
    releaseVersion: FOUNDATION_RELEASE_VERSION,
    reportType: FOUNDATION_CEREMONY_REPORT_TYPE,
    runbookSetSha256: validateHash(
      record.runbookSetSha256,
      "Foundation ceremony runbook-set SHA-256",
    ),
    sbomSha256: validateHash(record.sbomSha256, "Foundation ceremony SBOM SHA-256"),
    signatureCount: 2,
    signerFingerprintSha256,
    signerKeyId,
    sourceTreeSha256: validateHash(
      record.sourceTreeSha256,
      "Foundation ceremony source-tree SHA-256",
    ),
    status: "verified-foundation-release-and-detached-tag",
    tagGitObjectSha1: validateGitHash(
      record.tagGitObjectSha1,
      "Foundation ceremony tag Git object SHA-1",
    ),
    tagName: FOUNDATION_TAG,
    tagObjectSha256: validateHash(record.tagObjectSha256, "Foundation ceremony tag object SHA-256"),
    tagUnsignedPayloadSha256: validateHash(
      record.tagUnsignedPayloadSha256,
      "Foundation ceremony tag unsigned payload SHA-256",
    ),
    testSummarySha256: validateHash(
      record.testSummarySha256,
      "Foundation ceremony test-summary SHA-256",
    ),
    version: FOUNDATION_CEREMONY_REPORT_VERSION,
  });
}

/** Decode only the exact canonical bytes retained by the ceremony. */
export function decodeFoundationCeremonyReport(
  value: string | Uint8Array,
): FoundationCeremonyReportV2 {
  const text = decodeBoundedText(value, MAX_JSON_BYTES, "Foundation ceremony report");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", "Foundation ceremony report is not valid JSON");
  }
  const report = parseFoundationCeremonyReport(parsed);
  if (canonicalJson(report) !== text) {
    fail("INPUT_INVALID", "Foundation ceremony report is not canonical JSON");
  }
  return report;
}

/**
 * Independently reopens and verifies every retained ceremony output and its
 * repository-pinned evidence. This function is read-only and has no signing,
 * Keychain, restoration, publication, or Git-object/ref capability.
 */
export async function verifyFoundationCeremonyOutputs(
  optionsValue: FoundationCeremonyVerificationOptions,
  repositoryRootValue: string,
  dependenciesValue: FoundationCeremonyVerificationDependencies = PRODUCTION_VERIFICATION_DEPENDENCIES,
): Promise<FoundationCeremonyReportV2> {
  const repositoryRoot = await validateRepositoryRoot(repositoryRootValue);
  const options = parseVerificationOptions(optionsValue, repositoryRoot);
  const dependencies = parseVerificationDependencies(dependenciesValue);

  const [reportBytes, receiptBytes, conclusionBytes, tagObjectBytes, retained, reviewed] =
    await Promise.all([
      readOwnerOnlyExternalFile(
        options.reportPath,
        repositoryRoot,
        ".ceremony-report.json",
        MAX_JSON_BYTES,
      ),
      readOwnerOnlyExternalFile(
        options.receiptPath,
        repositoryRoot,
        ".receipt.json",
        MAX_JSON_BYTES,
      ),
      readOwnerOnlyExternalFile(
        options.conclusionPath,
        repositoryRoot,
        ".readiness-conclusion.json",
        MAX_JSON_BYTES,
      ),
      readOwnerOnlyExternalFile(
        options.tagObjectPath,
        repositoryRoot,
        ".foundation-tag",
        MAX_TAG_BYTES,
      ),
      dependencies.readCiEvidence(options.ciEvidencePath, repositoryRoot),
      dependencies.readReviewEvidence(
        options.reviewEvidencePath,
        repositoryRoot,
        options.confirmCommit,
      ),
    ]);

  try {
    const report = decodeFoundationCeremonyReport(reportBytes);
    const receiptValue = decodeCanonicalJson(receiptBytes, "Foundation release receipt");
    const receipt = receiptValue as ReleaseBundleReceiptV1;
    const conclusion = decodeFoundationStageAReadinessConclusion(conclusionBytes);

    assertEqual(report.commitSha, options.confirmCommit, "report commit");
    assertEqual(report.releaseVersion, options.confirmReleaseVersion, "report release version");
    assertEqual(retained.evidence.commitSha, options.confirmCommit, "CI evidence commit");
    assertEqual(retained.sha256, report.ciEvidenceSha256, "CI evidence SHA-256");
    assertEqual(retained.evidence.runId, report.ciRunId, "CI run identifier");
    assertEqual(reviewed.evidence.commitSha, options.confirmCommit, "independent-review commit");
    if (reviewed.evidence.reviewedAt < retained.evidence.completedAt) {
      fail("VERIFICATION_FAILED", "Foundation independent review predates retained CI completion");
    }
    assertEqual(
      reviewed.sha256,
      report.independentReviewEvidenceSha256,
      "independent-review evidence SHA-256",
    );

    const identity = await dependencies.readPinnedIdentity(repositoryRoot, options.confirmCommit);
    const repositoryTree = dependencies.readRepositoryTree(repositoryRoot, options.confirmCommit);
    assertEqual(
      identity.pinningRepositoryCommitSha,
      options.confirmCommit,
      "identity pinning commit",
    );
    assertEqual(repositoryTree, report.gitTreeSha, "repository Git tree");
    assertEqual(reviewed.evidence.gitTreeSha, repositoryTree, "independent-review Git tree");

    const bundle = await verifyReleaseBundle(
      options.archivePath,
      receipt,
      identity.publicKeySpkiDer,
    );
    assertBundleBindings(report, bundle);
    assertReviewTimeline(
      retained.evidence.completedAt,
      reviewed.evidence.reviewedAt,
      bundle.createdAt,
    );
    const expectedInventory = await dependencies.collectInventory(
      repositoryRoot,
      retained.evidence,
      bundle.createdAt,
    );
    assertExpectedInventoryBindings(bundle, expectedInventory);
    assertEqual(receipt.signerKeyId, identity.keyId, "release receipt signer key ID");
    assertEqual(
      bundle.signerFingerprintSha256,
      identity.signerFingerprintSha256,
      "release bundle signer fingerprint",
    );
    assertEqual(report.signerKeyId, identity.keyId, "report signer key ID");
    assertEqual(
      report.signerFingerprintSha256,
      identity.signerFingerprintSha256,
      "report signer fingerprint",
    );
    assertEqual(report.identitySha256, identity.identitySha256, "release identity SHA-256");
    assertEqual(
      report.provisioningReceiptSha256,
      identity.provisioningReceiptSha256,
      "provisioning receipt SHA-256",
    );
    assertEqual(
      report.platformIdentitySha256,
      identity.platformIdentitySha256,
      "platform identity SHA-256",
    );
    assertEqual(report.helperBinarySha256, identity.helperBinarySha256, "helper binary SHA-256");
    assertEqual(
      report.helperCompatibilityEvidenceSha256,
      identity.helperCompatibilityEvidenceSha256,
      "helper compatibility evidence SHA-256",
    );
    assertEqual(
      report.helperCompatibilityTestedCommitSha,
      identity.helperCompatibilityTestedCommitSha,
      "helper compatibility tested commit",
    );
    assertEqual(
      report.helperCompilerIdentitySha256,
      identity.helperCompilerIdentitySha256,
      "helper compiler identity SHA-256",
    );
    assertEqual(report.helperSourceSha256, identity.helperSourceSha256, "helper source SHA-256");

    const readinessBindings = readinessBindingsFor(
      bundle,
      report,
      retained.sha256,
      reviewed.sha256,
      identity,
    );
    verifyFoundationBuiltReadinessConclusion(conclusion, readinessBindings);
    assertEqual(
      foundationStageAReadinessConclusionSha256(conclusion),
      report.readinessConclusionSha256,
      "readiness conclusion SHA-256",
    );

    const tag = verifyFoundationSignedTagArtifact(tagObjectBytes, {
      archiveSha256: bundle.archiveSha256,
      ciEvidenceSha256: retained.sha256,
      manifestSha256: bundle.manifestSha256,
      publicKeySpkiDer: identity.publicKeySpkiDer,
      readinessConclusionSha256: report.readinessConclusionSha256,
      signerFingerprintSha256: identity.signerFingerprintSha256,
      signerKeyId: identity.keyId,
      targetCommit: options.confirmCommit,
    });
    assertEqual(tag.gitObjectSha1, report.tagGitObjectSha1, "detached tag Git object SHA-1");
    assertEqual(tag.tagObjectSha256, report.tagObjectSha256, "detached tag object SHA-256");
    assertEqual(
      tag.unsignedPayloadSha256,
      report.tagUnsignedPayloadSha256,
      "detached tag unsigned payload SHA-256",
    );

    assertEqual(
      dependencies.readRepositoryTree(repositoryRoot, options.confirmCommit),
      repositoryTree,
      "repository tree changed during inspection",
    );
    return report;
  } finally {
    reportBytes.fill(0);
    receiptBytes.fill(0);
    conclusionBytes.fill(0);
    tagObjectBytes.fill(0);
  }
}

function parseVerificationOptions(
  value: FoundationCeremonyVerificationOptions,
  repositoryRoot: string,
): FoundationCeremonyVerificationOptions {
  const record = exactObject(
    value,
    [
      "archivePath",
      "ciEvidencePath",
      "conclusionPath",
      "confirmCommit",
      "confirmReleaseVersion",
      "receiptPath",
      "reportPath",
      "reviewEvidencePath",
      "tagObjectPath",
    ],
    "Foundation ceremony verification options",
  );
  if (record.confirmReleaseVersion !== FOUNDATION_RELEASE_VERSION) {
    fail("INPUT_INVALID", "Foundation ceremony verification release is invalid");
  }
  const options: FoundationCeremonyVerificationOptions = Object.freeze({
    archivePath: validateExternalPath(record.archivePath, repositoryRoot, ".rsi-release"),
    ciEvidencePath: validateExternalPath(record.ciEvidencePath, repositoryRoot, ".json"),
    conclusionPath: validateExternalPath(
      record.conclusionPath,
      repositoryRoot,
      ".readiness-conclusion.json",
    ),
    confirmCommit: validateGitHash(record.confirmCommit, "Confirmed foundation commit"),
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    receiptPath: validateExternalPath(record.receiptPath, repositoryRoot, ".receipt.json"),
    reportPath: validateExternalPath(record.reportPath, repositoryRoot, ".ceremony-report.json"),
    reviewEvidencePath: validateExternalPath(
      record.reviewEvidencePath,
      repositoryRoot,
      ".review-evidence.json",
    ),
    tagObjectPath: validateExternalPath(record.tagObjectPath, repositoryRoot, ".foundation-tag"),
  });
  if (
    new Set(
      Object.values(options).filter((entry) => typeof entry === "string" && isAbsolute(entry)),
    ).size !== 7
  ) {
    fail("INPUT_INVALID", "Foundation ceremony verification paths must be distinct");
  }
  return options;
}

function parseVerificationDependencies(
  value: FoundationCeremonyVerificationDependencies,
): FoundationCeremonyVerificationDependencies {
  const record = exactObject(
    value,
    [
      "collectInventory",
      "readCiEvidence",
      "readPinnedIdentity",
      "readRepositoryTree",
      "readReviewEvidence",
    ],
    "Foundation ceremony verification dependencies",
  );
  if (
    typeof record.collectInventory !== "function" ||
    typeof record.readCiEvidence !== "function" ||
    typeof record.readPinnedIdentity !== "function" ||
    typeof record.readRepositoryTree !== "function" ||
    typeof record.readReviewEvidence !== "function"
  ) {
    fail("INPUT_INVALID", "Foundation ceremony verification dependencies are invalid");
  }
  return Object.freeze({
    collectInventory:
      record.collectInventory as FoundationCeremonyVerificationDependencies["collectInventory"],
    readCiEvidence:
      record.readCiEvidence as FoundationCeremonyVerificationDependencies["readCiEvidence"],
    readPinnedIdentity:
      record.readPinnedIdentity as FoundationCeremonyVerificationDependencies["readPinnedIdentity"],
    readRepositoryTree:
      record.readRepositoryTree as FoundationCeremonyVerificationDependencies["readRepositoryTree"],
    readReviewEvidence:
      record.readReviewEvidence as FoundationCeremonyVerificationDependencies["readReviewEvidence"],
  });
}

function assertReviewTimeline(
  completedAtValue: string,
  reviewedAtValue: string,
  createdAtValue: string,
): void {
  const completedAt = new Date(completedAtValue).getTime();
  const reviewedAt = new Date(reviewedAtValue).getTime();
  const createdAt = new Date(createdAtValue).getTime();
  if (
    !Number.isFinite(completedAt) ||
    !Number.isFinite(reviewedAt) ||
    !Number.isFinite(createdAt) ||
    reviewedAt < completedAt ||
    reviewedAt > createdAt + MAX_FUTURE_SKEW_MS ||
    createdAt - reviewedAt > MAX_EVIDENCE_AGE_MS
  ) {
    fail("VERIFICATION_FAILED", "Foundation independent-review timeline is invalid");
  }
}

function assertExpectedInventoryBindings(
  bundle: ReleaseBundleVerificationReportV1,
  inventory: FoundationReleaseInventory,
): void {
  const derivedBindings = deriveReleaseArtifactBindings(inventory.artifacts);
  for (const key of ARTIFACT_BINDING_KEYS) {
    assertEqual(bundle[key], derivedBindings[key], `release inventory ${key}`);
    assertEqual(bundle[key], inventory.release[key], `release inventory identity ${key}`);
    assertEqual(bundle[key], inventory.report[key], `release inventory report ${key}`);
  }
  if (
    bundle.artifactCount !== inventory.artifacts.length ||
    bundle.artifactCount !== inventory.report.artifactCount
  ) {
    fail("VERIFICATION_FAILED", "Foundation release inventory artifact count binding is invalid");
  }
  assertEqual(bundle.commitSha, inventory.release.commitSha, "release inventory commit");
  assertEqual(bundle.commitSha, inventory.report.commitSha, "release inventory report commit");
  assertEqual(bundle.gitTreeSha, inventory.release.gitTreeSha, "release inventory Git tree");
  assertEqual(bundle.gitTreeSha, inventory.report.gitTreeSha, "release inventory report Git tree");
  assertEqual(
    bundle.releaseVersion,
    inventory.release.releaseVersion,
    "release inventory release version",
  );
  assertEqual(
    bundle.releaseVersion,
    inventory.report.releaseVersion,
    "release inventory report release version",
  );
  assertEqual(bundle.createdAt, inventory.release.createdAt, "release inventory creation time");
  assertEqual(bundle.nodeVersion, EXPECTED_NODE_VERSION, "release bundle Node version");
  assertEqual(
    inventory.release.nodeVersion,
    EXPECTED_NODE_VERSION,
    "release inventory Node version",
  );
  assertEqual(bundle.pnpmVersion, EXPECTED_PNPM_VERSION, "release bundle pnpm version");
  assertEqual(
    inventory.release.pnpmVersion,
    EXPECTED_PNPM_VERSION,
    "release inventory pnpm version",
  );
  if (
    bundle.predecessorManifestSha256 !== null ||
    inventory.release.predecessorManifestSha256 !== null
  ) {
    fail("VERIFICATION_FAILED", "Foundation release predecessor binding is invalid");
  }
}

function assertBundleBindings(
  report: FoundationCeremonyReportV2,
  bundle: ReleaseBundleVerificationReportV1,
): void {
  if (bundle.status !== "verified-restorable-release-component") {
    fail("VERIFICATION_FAILED", "Foundation release bundle status is invalid");
  }
  for (const key of ARTIFACT_BINDING_KEYS) {
    assertEqual(bundle[key], report[key], `release bundle ${key}`);
  }
  assertEqual(bundle.archiveSha256, report.archiveSha256, "release bundle archive SHA-256");
  assertEqual(bundle.bundleId, report.bundleId, "release bundle identifier");
  assertEqual(bundle.commitSha, report.commitSha, "release bundle commit");
  assertEqual(bundle.gitTreeSha, report.gitTreeSha, "release bundle Git tree");
  assertEqual(bundle.manifestSha256, report.manifestSha256, "release bundle manifest SHA-256");
  assertEqual(bundle.releaseVersion, report.releaseVersion, "release bundle version");
}

function readinessBindingsFor(
  bundle: ReleaseBundleVerificationReportV1,
  report: FoundationCeremonyReportV2,
  ciEvidenceSha256: string,
  independentReviewEvidenceSha256: string,
  identity: FoundationPinnedReleaseIdentityV1,
): FoundationStageAReadinessBindingsV1 {
  return Object.freeze({
    archiveSha256: bundle.archiveSha256,
    artifactSetSha256: bundle.artifactSetSha256,
    ciEvidenceSha256,
    commitSha: bundle.commitSha,
    configSetSha256: bundle.configSetSha256,
    gitTreeSha: bundle.gitTreeSha,
    helperCompatibilityEvidenceSha256: identity.helperCompatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: identity.helperCompatibilityTestedCommitSha,
    identitySha256: identity.identitySha256,
    independentReviewEvidenceSha256,
    lockfileSha256: bundle.lockfileSha256,
    manifestSha256: bundle.manifestSha256,
    platformIdentitySha256: identity.platformIdentitySha256,
    provisioningReceiptSha256: identity.provisioningReceiptSha256,
    recoverySetSha256: bundle.recoverySetSha256,
    runbookSetSha256: bundle.runbookSetSha256,
    sbomSha256: bundle.sbomSha256,
    signerFingerprintSha256: report.signerFingerprintSha256,
    signerKeyId: report.signerKeyId,
    sourceTreeSha256: bundle.sourceTreeSha256,
    testSummarySha256: bundle.testSummarySha256,
  });
}

async function verifyReleaseBundle(
  archivePath: string,
  receipt: ReleaseBundleReceiptV1,
  releasePublicKeySpkiDer: Uint8Array,
): Promise<ReleaseBundleVerificationReportV1> {
  try {
    return await verifySignedReleaseBundle({
      archivePath,
      trust: { receipt, releasePublicKeySpkiDer },
    });
  } catch {
    fail("VERIFICATION_FAILED", "Foundation release bundle or retained receipt is invalid");
  }
}

function decodeCanonicalJson(bytes: Uint8Array, label: string): unknown {
  const text = decodeBoundedText(bytes, MAX_JSON_BYTES, label);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", `${label} is not valid JSON`);
  }
  if (canonicalJson(parsed) !== text) fail("INPUT_INVALID", `${label} is not canonical JSON`);
  return parsed;
}

function decodeBoundedText(value: string | Uint8Array, maxBytes: number, label: string): string {
  if (typeof value === "string") {
    const size = Buffer.byteLength(value, "utf8");
    if (size === 0 || size > maxBytes) fail("INPUT_INVALID", `${label} size is invalid`);
    return value;
  }
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > maxBytes
  ) {
    fail("INPUT_INVALID", `${label} bytes are invalid`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    fail("INPUT_INVALID", `${label} is not valid UTF-8`);
  }
}

function validateExternalPath(value: unknown, repositoryRoot: string, suffix: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 1_024 ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    !value.endsWith(suffix) ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail("INPUT_INVALID", "Foundation ceremony verification path is invalid");
  }
  const within = relative(repositoryRoot, value);
  if (within === "" || (!within.startsWith(`..${sep}`) && within !== ".." && !isAbsolute(within))) {
    fail(
      "INPUT_INVALID",
      "Foundation ceremony verification files must remain outside the repository",
    );
  }
  return value;
}

interface DirectoryGuard {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: number;
  readonly path: string;
  readonly uid: bigint;
}

async function readOwnerOnlyExternalFile(
  path: string,
  repositoryRoot: string,
  suffix: string,
  maxBytes: number,
): Promise<Buffer> {
  const absolute = validateExternalPath(path, repositoryRoot, suffix);
  const parent = await guardDirectory(dirname(absolute));
  const before = await lstat(absolute, { bigint: true }).catch(() => undefined);
  if (
    before === undefined ||
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.uid !== currentUserId(before.uid) ||
    (Number(before.mode) & 0o077) !== 0 ||
    before.size <= 0n ||
    before.size > BigInt(maxBytes)
  ) {
    fail("INPUT_INVALID", "Foundation ceremony verification file is missing, partial, or unsafe");
  }
  let handle: FileHandle | undefined;
  try {
    handle = await open(absolute, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    if (!sameFile(before, opened)) {
      fail("INPUT_INVALID", "Foundation ceremony verification file changed before reading");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(absolute, { bigint: true }).catch(() => undefined);
    if (pathAfter === undefined || !sameFile(opened, after) || !sameFile(after, pathAfter)) {
      bytes.fill(0);
      fail("INPUT_INVALID", "Foundation ceremony verification file changed while reading");
    }
    await assertDirectoryGuard(parent);
    return bytes;
  } catch (error) {
    if (error instanceof FoundationCeremonyError) throw error;
    throw new FoundationCeremonyError(
      "INPUT_INVALID",
      "Foundation ceremony verification file could not be read safely",
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function validateRepositoryRoot(value: unknown): Promise<string> {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 1_024 ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail("INPUT_INVALID", "Foundation verification repository root is invalid");
  }
  const stats = await lstat(value, { bigint: true }).catch(() => undefined);
  if (
    stats === undefined ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (await realpath(value).catch(() => "")) !== value
  ) {
    fail("INPUT_INVALID", "Foundation verification repository root is unsafe");
  }
  return value;
}

async function guardDirectory(path: string): Promise<DirectoryGuard> {
  const stats = await lstat(path, { bigint: true }).catch(() => undefined);
  if (
    stats === undefined ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.uid !== currentUserId(stats.uid) ||
    (Number(stats.mode) & 0o077) !== 0 ||
    (await realpath(path).catch(() => "")) !== path
  ) {
    fail("INPUT_INVALID", "Foundation ceremony verification directory is unsafe");
  }
  return Object.freeze({
    device: stats.dev,
    inode: stats.ino,
    mode: Number(stats.mode) & 0o777,
    path,
    uid: stats.uid,
  });
}

async function assertDirectoryGuard(guard: DirectoryGuard): Promise<void> {
  const stats = await lstat(guard.path, { bigint: true }).catch(() => undefined);
  if (
    stats === undefined ||
    !stats.isDirectory() ||
    stats.dev !== guard.device ||
    stats.ino !== guard.inode ||
    stats.uid !== guard.uid ||
    (Number(stats.mode) & 0o777) !== guard.mode ||
    (await realpath(guard.path).catch(() => "")) !== guard.path
  ) {
    fail("INPUT_INVALID", "Foundation ceremony verification directory changed during use");
  }
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.isFile() &&
    right.isFile() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === 1n &&
    right.nlink === 1n
  );
}

function currentUserId(fallback: bigint): bigint {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : fallback;
}

/** Read-only production Git eligibility and tree binding used by the aggregate verifier. */
export function readFoundationVerificationRepositoryTree(
  repositoryRoot: string,
  commitSha: string,
): string {
  const graftsPath = resolve(
    repositoryRoot,
    gitText(repositoryRoot, ["rev-parse", "--git-path", "info/grafts"]).trim(),
  );
  if (
    gitText(repositoryRoot, ["for-each-ref", "--format=%(refname)", "refs/replace"]).trim() !==
      "" ||
    existsSync(graftsPath) ||
    gitText(repositoryRoot, ["rev-parse", "--is-shallow-repository"]).trim() !== "false"
  ) {
    fail("REPOSITORY_STATE", "Foundation verification Git history is ambiguous");
  }
  if (
    gitText(repositoryRoot, ["status", "--porcelain=v1"]) !== "" ||
    gitText(repositoryRoot, ["branch", "--show-current"]).trim() !== "main" ||
    gitText(repositoryRoot, ["rev-parse", "HEAD"]).trim() !== commitSha ||
    gitText(repositoryRoot, ["rev-parse", "refs/remotes/origin/main"]).trim() !== commitSha ||
    !hasApprovedRawOrigin(repositoryRoot)
  ) {
    fail("REPOSITORY_STATE", "Foundation verification repository identity is ineligible");
  }
  return validateGitHash(
    gitText(repositoryRoot, ["rev-parse", `${commitSha}^{tree}`]).trim(),
    "Foundation verification repository Git tree",
  );
}

function hasApprovedRawOrigin(repositoryRoot: string): boolean {
  const configured = gitText(repositoryRoot, [
    "config",
    "--local",
    "--no-includes",
    "--get-all",
    "remote.origin.url",
  ]);
  return configured === `${APPROVED_REMOTE}\n` || configured === `${APPROVED_SSH_REMOTE}\n`;
}

function gitText(repositoryRoot: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", [...HARDENED_GIT_OPTIONS, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: HARDENED_GIT_ENV,
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    fail("REPOSITORY_STATE", "Foundation verification Git inspection failed");
  }
  return result.stdout;
}

function assertEqual(actual: string, expected: string, label: string): void {
  if (actual !== expected) {
    fail("VERIFICATION_FAILED", `Foundation ${label} binding is invalid`);
  }
}
