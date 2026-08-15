import {
  encodeSignedReleaseArchive,
  normalizeReleaseIdentity,
  normalizeSigner,
  verifyReleaseArchiveBytes,
} from "./archive.js";
import { normalizeReleaseArtifacts } from "./artifacts.js";
import { exactObject } from "./canonical.js";
import {
  publishBundleCreateOnly,
  readBundleFile,
  restoreVerifiedReleaseArchive,
} from "./filesystem.js";
import type {
  CreateSignedReleaseBundleOptions,
  ReleaseBundleReceiptV1,
  ReleaseBundleRestoreReportV1,
  ReleaseBundleVerificationReportV1,
  RestoreSignedReleaseBundleOptions,
  VerifySignedReleaseBundleOptions,
} from "./types.js";

export async function createSignedReleaseBundle(
  optionsValue: CreateSignedReleaseBundleOptions,
): Promise<ReleaseBundleReceiptV1> {
  const options = exactObject(
    optionsValue,
    ["artifacts", "destinationPath", "release", "signer"],
    "Create-release-bundle options",
  );
  const artifacts = normalizeReleaseArtifacts(options.artifacts);
  const release = normalizeReleaseIdentity(options.release, artifacts);
  const signer = normalizeSigner(options.signer);
  const encoded = await encodeSignedReleaseArchive(artifacts, release, signer);
  await publishBundleCreateOnly(options.destinationPath, encoded.bytes);
  return encoded.receipt;
}

export async function verifySignedReleaseBundle(
  optionsValue: VerifySignedReleaseBundleOptions,
): Promise<ReleaseBundleVerificationReportV1> {
  const options = exactObject(
    optionsValue,
    ["archivePath", "trust"],
    "Verify-release-bundle options",
  );
  const bytes = await readBundleFile(options.archivePath);
  return verifyReleaseArchiveBytes(bytes, options.trust).report;
}

export async function restoreSignedReleaseBundle(
  optionsValue: RestoreSignedReleaseBundleOptions,
): Promise<ReleaseBundleRestoreReportV1> {
  const options = exactObject(
    optionsValue,
    ["archivePath", "destinationDirectory", "trust"],
    "Restore-release-bundle options",
  );
  // The destination is not touched until the complete archive, retained
  // receipt, release signature, policy, secret scan, and every binding pass.
  const bytes = await readBundleFile(options.archivePath);
  const verified = verifyReleaseArchiveBytes(bytes, options.trust);
  const restoredFileCount = await restoreVerifiedReleaseArchive(
    options.destinationDirectory,
    verified,
  );
  return Object.freeze({ ...verified.report, restoredFileCount });
}
