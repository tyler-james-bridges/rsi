import { timingSafeEqual } from "node:crypto";

import {
  createSignedReleaseBundle,
  verifySignedReleaseBundle,
  type ReleaseBundleReceiptV1,
} from "@rsi/release-bundle";

import { canonicalJson, exactObject, sha256, validateGitHash } from "./canonical.js";
import { fail } from "./errors.js";
import { createFoundationSignedTagArtifact } from "./foundation-tag.js";
import {
  createFoundationStageAReadinessConclusion,
  encodeFoundationStageAReadinessConclusion,
  foundationStageAReadinessConclusionSha256,
  verifyFoundationBuiltReadinessConclusion,
  type FoundationStageAReadinessBindingsV1,
} from "./readiness-conclusion.js";
import {
  FOUNDATION_CEREMONY_REPORT_TYPE,
  FOUNDATION_CEREMONY_REPORT_VERSION,
  FOUNDATION_RELEASE_VERSION,
  FOUNDATION_TAG,
  type FoundationCeremonyDependencies,
  type FoundationCeremonyOptions,
  type FoundationCeremonyReportV2,
  type FoundationCeremonySignersV1,
  type FoundationOutputReservation,
} from "./types.js";

export async function runFoundationCeremony(
  optionsValue: FoundationCeremonyOptions,
  dependencies: FoundationCeremonyDependencies,
): Promise<FoundationCeremonyReportV2> {
  const options = parseOptions(optionsValue);
  assertDistinctPaths(options);
  const model = await dependencies.platformModel();
  if (model !== "MacBook") {
    fail("HOST_REFUSED", "Foundation release signing is restricted to the MacBook");
  }
  await dependencies.assertHostOffline();
  const [retained, reviewed] = await Promise.all([
    dependencies.readCiEvidence(options.ciEvidencePath),
    dependencies.readReviewEvidence(options.reviewEvidencePath),
  ]);
  if (retained.evidence.commitSha !== options.confirmCommit) {
    fail("CI_EVIDENCE_INVALID", "Foundation commit confirmation does not match CI evidence");
  }
  const now = dependencies.now();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    fail("INPUT_INVALID", "Foundation ceremony clock is invalid");
  }
  const createdAt = now.toISOString();
  const completedAt = new Date(retained.evidence.completedAt).getTime();
  const reviewedAt = new Date(reviewed.evidence.reviewedAt).getTime();
  if (
    completedAt > now.getTime() + 5 * 60 * 1_000 ||
    now.getTime() - completedAt > 7 * 24 * 60 * 60 * 1_000
  ) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI evidence is outside the ceremony window");
  }
  if (
    reviewedAt > now.getTime() + 5 * 60 * 1_000 ||
    now.getTime() - reviewedAt > 7 * 24 * 60 * 60 * 1_000 ||
    reviewedAt < completedAt ||
    reviewed.evidence.commitSha !== options.confirmCommit
  ) {
    fail("VERIFICATION_FAILED", "Foundation independent-review evidence is stale or mismatched");
  }
  const inventory = await dependencies.collectInventory(retained.evidence, createdAt);
  if (
    inventory.release.commitSha !== options.confirmCommit ||
    inventory.release.releaseVersion !== FOUNDATION_RELEASE_VERSION ||
    inventory.report.commitSha !== options.confirmCommit
  ) {
    fail("VERIFICATION_FAILED", "Foundation inventory identity does not match the ceremony");
  }
  if (reviewed.evidence.gitTreeSha !== inventory.release.gitTreeSha) {
    fail("VERIFICATION_FAILED", "Foundation independent review does not bind the release tree");
  }
  const identity = await dependencies.readPinnedIdentity(options.confirmCommit);
  if ((await dependencies.platformIdentitySha256()) !== identity.platformIdentitySha256) {
    fail("HOST_REFUSED", "Foundation release identity is pinned to a different MacBook");
  }
  const reservations = await reserveCeremonyOutputs(options, dependencies);
  try {
    await dependencies.assertHostOffline();
    const revalidatedIdentity = await dependencies.readPinnedIdentity(options.confirmCommit);
    assertPinnedIdentityStable(identity, revalidatedIdentity);
    const pending = await dependencies.custody.withSigners(identity, async (signers) => {
      assertSignerIdentity(signers, identity);
      const receipt = await createSignedReleaseBundle({
        artifacts: inventory.artifacts,
        destinationPath: options.destinationPath,
        release: inventory.release,
        signer: signers.releaseSigner,
      });
      const verified = await verifySignedReleaseBundle({
        archivePath: options.destinationPath,
        trust: {
          receipt,
          releasePublicKeySpkiDer: identity.publicKeySpkiDer,
        },
      });
      assertVerified(receipt, verified, inventory.release.commitSha);

      const readinessBindings: FoundationStageAReadinessBindingsV1 = Object.freeze({
        archiveSha256: receipt.archiveSha256,
        artifactSetSha256: verified.artifactSetSha256,
        ciEvidenceSha256: retained.sha256,
        commitSha: verified.commitSha,
        configSetSha256: verified.configSetSha256,
        gitTreeSha: verified.gitTreeSha,
        helperCompatibilityEvidenceSha256: identity.helperCompatibilityEvidenceSha256,
        helperCompatibilityTestedCommitSha: identity.helperCompatibilityTestedCommitSha,
        identitySha256: identity.identitySha256,
        independentReviewEvidenceSha256: reviewed.sha256,
        lockfileSha256: verified.lockfileSha256,
        manifestSha256: verified.manifestSha256,
        platformIdentitySha256: identity.platformIdentitySha256,
        provisioningReceiptSha256: identity.provisioningReceiptSha256,
        recoverySetSha256: verified.recoverySetSha256,
        runbookSetSha256: verified.runbookSetSha256,
        sbomSha256: verified.sbomSha256,
        signerFingerprintSha256: identity.signerFingerprintSha256,
        signerKeyId: identity.keyId,
        sourceTreeSha256: verified.sourceTreeSha256,
        testSummarySha256: verified.testSummarySha256,
      });
      const conclusion = createFoundationStageAReadinessConclusion({
        ...readinessBindings,
        checks: [
          { name: "release-bundle-verified", outcome: "passed" },
          { name: "retained-ci-evidence-verified", outcome: "passed" },
          { name: "commit-bindings-verified", outcome: "passed" },
          { name: "signing-identity-pinned-and-matched", outcome: "passed" },
          { name: "independent-adversarial-review-passed", outcome: "passed" },
        ],
      });
      verifyFoundationBuiltReadinessConclusion(conclusion, readinessBindings);
      const conclusionBytes = Buffer.from(
        encodeFoundationStageAReadinessConclusion(conclusion),
        "utf8",
      );
      const readinessConclusionSha256 = foundationStageAReadinessConclusionSha256(conclusion);

      const tag = await createFoundationSignedTagArtifact({
        archiveSha256: receipt.archiveSha256,
        ciEvidenceSha256: retained.sha256,
        manifestSha256: receipt.manifestSha256,
        readinessConclusionSha256,
        signer: signers.tagSigner,
        targetCommit: verified.commitSha,
      });

      const report: FoundationCeremonyReportV2 = Object.freeze({
        archiveSha256: receipt.archiveSha256,
        artifactSetSha256: verified.artifactSetSha256,
        bundleId: receipt.bundleId,
        ciEvidenceSha256: retained.sha256,
        ciRunId: retained.evidence.runId,
        commitSha: verified.commitSha,
        configSetSha256: verified.configSetSha256,
        gitTreeSha: verified.gitTreeSha,
        helperBinarySha256: identity.helperBinarySha256,
        helperCompatibilityEvidenceSha256: identity.helperCompatibilityEvidenceSha256,
        helperCompatibilityTestedCommitSha: identity.helperCompatibilityTestedCommitSha,
        helperCompilerIdentitySha256: identity.helperCompilerIdentitySha256,
        helperSourceSha256: identity.helperSourceSha256,
        identitySha256: identity.identitySha256,
        independentReviewEvidenceSha256: reviewed.sha256,
        lockfileSha256: verified.lockfileSha256,
        manifestSha256: verified.manifestSha256,
        platformIdentitySha256: identity.platformIdentitySha256,
        provisioningReceiptSha256: identity.provisioningReceiptSha256,
        readinessConclusionSha256,
        recoverySetSha256: verified.recoverySetSha256,
        releaseVersion: FOUNDATION_RELEASE_VERSION,
        reportType: FOUNDATION_CEREMONY_REPORT_TYPE,
        runbookSetSha256: verified.runbookSetSha256,
        sbomSha256: verified.sbomSha256,
        signatureCount: 2,
        signerFingerprintSha256: verified.signerFingerprintSha256,
        signerKeyId: receipt.signerKeyId,
        sourceTreeSha256: verified.sourceTreeSha256,
        status: "verified-foundation-release-and-detached-tag",
        tagGitObjectSha1: tag.verification.gitObjectSha1,
        tagName: FOUNDATION_TAG,
        tagObjectSha256: tag.verification.tagObjectSha256,
        tagUnsignedPayloadSha256: tag.verification.unsignedPayloadSha256,
        testSummarySha256: verified.testSummarySha256,
        version: FOUNDATION_CEREMONY_REPORT_VERSION,
      });
      return Object.freeze({ conclusionBytes, receipt, report, tag });
    });

    const receiptBytes = Buffer.from(canonicalJson(pending.receipt), "utf8");
    const reportBytes = Buffer.from(canonicalJson(pending.report), "utf8");
    try {
      // The conclusion is the final commit marker. Its presence therefore
      // implies that the detached tag, receipt, and full report were all
      // durably published after custody completed and cleaned up.
      await reservations.tagObject.publish(pending.tag.tagObjectBytes);
      await reservations.receipt.publish(receiptBytes);
      await reservations.report.publish(reportBytes);
      await reservations.conclusion.publish(pending.conclusionBytes);
      return pending.report;
    } finally {
      receiptBytes.fill(0);
      reportBytes.fill(0);
      pending.conclusionBytes.fill(0);
      pending.tag.tagObjectBytes.fill(0);
    }
  } finally {
    await preserveCeremonyOutputs(reservations);
  }
}

interface FoundationCeremonyOutputReservations {
  readonly conclusion: FoundationOutputReservation;
  readonly receipt: FoundationOutputReservation;
  readonly report: FoundationOutputReservation;
  readonly tagObject: FoundationOutputReservation;
}

async function reserveCeremonyOutputs(
  options: FoundationCeremonyOptions,
  dependencies: FoundationCeremonyDependencies,
): Promise<FoundationCeremonyOutputReservations> {
  const reserved: FoundationOutputReservation[] = [];
  try {
    const receipt = await dependencies.reserveOutput(options.receiptPath, ".receipt.json");
    reserved.push(receipt);
    const conclusion = await dependencies.reserveOutput(
      options.conclusionPath,
      ".readiness-conclusion.json",
    );
    reserved.push(conclusion);
    const tagObject = await dependencies.reserveOutput(options.tagObjectPath, ".foundation-tag");
    reserved.push(tagObject);
    const report = await dependencies.reserveOutput(options.reportPath, ".ceremony-report.json");
    reserved.push(report);
    return Object.freeze({ conclusion, receipt, report, tagObject });
  } catch (error) {
    await Promise.allSettled(reserved.map(async (reservation) => reservation.preserve()));
    throw error;
  }
}

async function preserveCeremonyOutputs(
  reservations: FoundationCeremonyOutputReservations,
): Promise<void> {
  await Promise.allSettled(
    Object.values(reservations).map(async (reservation) => reservation.preserve()),
  );
}

function parseOptions(value: FoundationCeremonyOptions): FoundationCeremonyOptions {
  const record = exactObject(
    value,
    [
      "ciEvidencePath",
      "conclusionPath",
      "confirmCommit",
      "confirmReleaseVersion",
      "destinationPath",
      "reportPath",
      "receiptPath",
      "reviewEvidencePath",
      "tagObjectPath",
    ],
    "Foundation ceremony options",
  );
  if (
    typeof record.ciEvidencePath !== "string" ||
    typeof record.conclusionPath !== "string" ||
    typeof record.destinationPath !== "string" ||
    typeof record.reportPath !== "string" ||
    typeof record.receiptPath !== "string" ||
    typeof record.reviewEvidencePath !== "string" ||
    typeof record.tagObjectPath !== "string" ||
    record.confirmReleaseVersion !== FOUNDATION_RELEASE_VERSION
  ) {
    fail("INPUT_INVALID", "Foundation ceremony options are invalid");
  }
  return Object.freeze({
    ciEvidencePath: record.ciEvidencePath,
    conclusionPath: record.conclusionPath,
    confirmCommit: validateGitHash(record.confirmCommit, "Confirmed foundation commit"),
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    destinationPath: record.destinationPath,
    reportPath: record.reportPath,
    receiptPath: record.receiptPath,
    reviewEvidencePath: record.reviewEvidencePath,
    tagObjectPath: record.tagObjectPath,
  });
}

function assertDistinctPaths(options: FoundationCeremonyOptions): void {
  const paths = [
    options.ciEvidencePath,
    options.conclusionPath,
    options.destinationPath,
    options.reportPath,
    options.receiptPath,
    options.reviewEvidencePath,
    options.tagObjectPath,
  ];
  if (new Set(paths).size !== paths.length) {
    fail("INPUT_INVALID", "Foundation ceremony input and output paths must be distinct");
  }
}

function assertSignerIdentity(
  signers: FoundationCeremonySignersV1,
  identity: Parameters<FoundationCeremonyDependencies["custody"]["withSigners"]>[0],
): void {
  for (const signer of [signers.releaseSigner, signers.tagSigner]) {
    if (
      signer.keyId !== identity.keyId ||
      !(signer.publicKeySpkiDer instanceof Uint8Array) ||
      signer.publicKeySpkiDer.byteLength !== identity.publicKeySpkiDer.byteLength ||
      !timingSafeEqual(signer.publicKeySpkiDer, identity.publicKeySpkiDer) ||
      sha256(signer.publicKeySpkiDer) !== identity.signerFingerprintSha256
    ) {
      fail("CUSTODY_FAILED", "Foundation signer does not match the repository-pinned identity");
    }
  }
}

function assertPinnedIdentityStable(
  initial: Parameters<FoundationCeremonyDependencies["custody"]["withSigners"]>[0],
  revalidated: Parameters<FoundationCeremonyDependencies["custody"]["withSigners"]>[0],
): void {
  if (
    initial.identitySha256 !== revalidated.identitySha256 ||
    initial.provisioningReceiptSha256 !== revalidated.provisioningReceiptSha256 ||
    initial.helperCompatibilityEvidenceSha256 !== revalidated.helperCompatibilityEvidenceSha256 ||
    initial.helperCompatibilityTestedCommitSha !== revalidated.helperCompatibilityTestedCommitSha ||
    initial.helperBinarySha256 !== revalidated.helperBinarySha256 ||
    initial.helperCompilerIdentitySha256 !== revalidated.helperCompilerIdentitySha256 ||
    initial.helperSourceSha256 !== revalidated.helperSourceSha256 ||
    initial.keyId !== revalidated.keyId ||
    initial.platformIdentitySha256 !== revalidated.platformIdentitySha256 ||
    initial.pinningRepositoryCommitSha !== revalidated.pinningRepositoryCommitSha ||
    initial.provisioningRepositoryCommitSha !== revalidated.provisioningRepositoryCommitSha ||
    initial.signerFingerprintSha256 !== revalidated.signerFingerprintSha256 ||
    initial.publicKeySpkiDer.byteLength !== revalidated.publicKeySpkiDer.byteLength ||
    !timingSafeEqual(initial.publicKeySpkiDer, revalidated.publicKeySpkiDer)
  ) {
    fail("CUSTODY_FAILED", "Foundation pinned signing identity changed before custody");
  }
}

function assertVerified(
  receipt: ReleaseBundleReceiptV1,
  report: Awaited<ReturnType<typeof verifySignedReleaseBundle>>,
  commitSha: string,
): void {
  if (
    report.status !== "verified-restorable-release-component" ||
    report.commitSha !== commitSha ||
    report.releaseVersion !== FOUNDATION_RELEASE_VERSION ||
    report.archiveSha256 !== receipt.archiveSha256 ||
    report.manifestSha256 !== receipt.manifestSha256 ||
    report.bundleId !== receipt.bundleId ||
    report.signerFingerprintSha256 !== receipt.signerFingerprintSha256
  ) {
    fail("VERIFICATION_FAILED", "Foundation release did not verify against its receipt");
  }
}
