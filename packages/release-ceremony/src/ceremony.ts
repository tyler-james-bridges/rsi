import {
  createSignedReleaseBundle,
  verifySignedReleaseBundle,
  type ReleaseBundleReceiptV1,
} from "@rsi/release-bundle";

import { exactObject, validateGitHash } from "./canonical.js";
import { fail } from "./errors.js";
import {
  FOUNDATION_CEREMONY_REPORT_TYPE,
  FOUNDATION_CEREMONY_REPORT_VERSION,
  FOUNDATION_RELEASE_VERSION,
  type FoundationCeremonyDependencies,
  type FoundationCeremonyOptions,
  type FoundationCeremonyReportV1,
} from "./types.js";

export async function runFoundationCeremony(
  optionsValue: FoundationCeremonyOptions,
  dependencies: FoundationCeremonyDependencies,
): Promise<FoundationCeremonyReportV1> {
  const options = parseOptions(optionsValue);
  if (options.destinationPath === options.receiptPath) {
    fail("INPUT_INVALID", "Foundation bundle and receipt paths must differ");
  }
  const model = await dependencies.platformModel();
  if (model !== "MacBook") {
    fail("HOST_REFUSED", "Foundation release signing is restricted to the MacBook");
  }
  const retained = await dependencies.readCiEvidence(options.ciEvidencePath);
  if (retained.evidence.commitSha !== options.confirmCommit) {
    fail("CI_EVIDENCE_INVALID", "Foundation commit confirmation does not match CI evidence");
  }
  const now = dependencies.now();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    fail("INPUT_INVALID", "Foundation ceremony clock is invalid");
  }
  const createdAt = now.toISOString();
  const completedAt = new Date(retained.evidence.completedAt).getTime();
  if (
    completedAt > now.getTime() + 5 * 60 * 1_000 ||
    now.getTime() - completedAt > 7 * 24 * 60 * 60 * 1_000
  ) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI evidence is outside the ceremony window");
  }
  const inventory = await dependencies.collectInventory(retained.evidence, createdAt);
  if (
    inventory.release.commitSha !== options.confirmCommit ||
    inventory.release.releaseVersion !== FOUNDATION_RELEASE_VERSION ||
    inventory.report.commitSha !== options.confirmCommit
  ) {
    fail("VERIFICATION_FAILED", "Foundation inventory identity does not match the ceremony");
  }

  let createdReceipt: ReleaseBundleReceiptV1 | undefined;
  try {
    return await dependencies.custody.withSigner(async (signer) => {
      const receipt = await createSignedReleaseBundle({
        artifacts: inventory.artifacts,
        destinationPath: options.destinationPath,
        release: inventory.release,
        signer,
      });
      createdReceipt = receipt;
      const verified = await verifySignedReleaseBundle({
        archivePath: options.destinationPath,
        trust: {
          receipt,
          releasePublicKeySpkiDer: signer.publicKeySpkiDer,
        },
      });
      assertVerified(receipt, verified, inventory.release.commitSha);
      await dependencies.writeReceipt(options.receiptPath, receipt);
      return Object.freeze({
        archiveSha256: receipt.archiveSha256,
        artifactSetSha256: verified.artifactSetSha256,
        bundleId: receipt.bundleId,
        ciEvidenceSha256: retained.sha256,
        ciRunId: retained.evidence.runId,
        commitSha: verified.commitSha,
        configSetSha256: verified.configSetSha256,
        gitTreeSha: verified.gitTreeSha,
        lockfileSha256: verified.lockfileSha256,
        manifestSha256: verified.manifestSha256,
        recoverySetSha256: verified.recoverySetSha256,
        releaseVersion: FOUNDATION_RELEASE_VERSION,
        reportType: FOUNDATION_CEREMONY_REPORT_TYPE,
        runbookSetSha256: verified.runbookSetSha256,
        sbomSha256: verified.sbomSha256,
        signerFingerprintSha256: verified.signerFingerprintSha256,
        signerKeyId: receipt.signerKeyId,
        sourceTreeSha256: verified.sourceTreeSha256,
        status: "verified-foundation-release",
        testSummarySha256: verified.testSummarySha256,
        version: FOUNDATION_CEREMONY_REPORT_VERSION,
      });
    });
  } catch (error) {
    if (createdReceipt !== undefined) {
      await dependencies.removeOwnOutput(options.destinationPath, createdReceipt);
    }
    throw error;
  }
}

function parseOptions(value: FoundationCeremonyOptions): FoundationCeremonyOptions {
  const record = exactObject(
    value,
    ["ciEvidencePath", "confirmCommit", "confirmReleaseVersion", "destinationPath", "receiptPath"],
    "Foundation ceremony options",
  );
  if (
    typeof record.ciEvidencePath !== "string" ||
    typeof record.destinationPath !== "string" ||
    typeof record.receiptPath !== "string" ||
    record.confirmReleaseVersion !== FOUNDATION_RELEASE_VERSION
  ) {
    fail("INPUT_INVALID", "Foundation ceremony options are invalid");
  }
  return Object.freeze({
    ciEvidencePath: record.ciEvidencePath,
    confirmCommit: validateGitHash(record.confirmCommit, "Confirmed foundation commit"),
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    destinationPath: record.destinationPath,
    receiptPath: record.receiptPath,
  });
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
