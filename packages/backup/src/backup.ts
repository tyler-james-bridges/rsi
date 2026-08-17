import { Buffer } from "node:buffer";

import {
  encodeSignedArchive,
  normalizeSigner,
  verifyArchiveBytes,
  type VerifiedArchive,
} from "./archive.js";
import { exactObject } from "./canonical.js";
import { publishArchiveCreateOnly, readArchiveFile, restoreVerifiedArchive } from "./filesystem.js";
import { sanitizeSnapshot } from "./schema.js";
import type {
  StateEvidenceReceiptV1,
  StateEvidenceRestoreReportV1,
  StateEvidenceVerificationReportV1,
  CreateSanitizedStateEvidenceOptions,
  RestoreSanitizedStateEvidenceOptions,
  VerifySanitizedStateEvidenceOptions,
} from "./types.js";

/**
 * Creates one immutable sanitized state-evidence component. The returned receipt
 * must be retained independently to make later rollback/truncation detectable.
 * This does not create the sanitized event archive or signed release bundle
 * required to satisfy complete OBS-REC-003 recovery.
 */
export async function createSanitizedStateEvidence(
  optionsValue: CreateSanitizedStateEvidenceOptions,
): Promise<StateEvidenceReceiptV1> {
  const options = exactObject(
    optionsValue,
    ["destinationPath", "signer", "snapshot"],
    "Create-backup options",
  );
  const snapshot = sanitizeSnapshot(options.snapshot);
  const signer = normalizeSigner(options.signer);
  const encoded = await encodeSignedArchive(snapshot, signer);
  const trust = Object.freeze({
    checkpointPublicKeySpkiDer: Buffer.from(
      snapshot.checkpointPublicKey.spkiDerBase64url,
      "base64url",
    ),
    receipt: encoded.receipt,
    releasePublicKeySpkiDer: Buffer.from(snapshot.releasePublicKey.spkiDerBase64url, "base64url"),
  });
  verifyArchiveBytes(encoded.bytes, trust);
  await publishArchiveCreateOnly(options.destinationPath, encoded.bytes);
  const persisted = await readArchiveFile(options.destinationPath);
  verifyArchiveBytes(persisted, trust);
  return encoded.receipt;
}

/** Verifies the exact archive pinned by an independently retained receipt. */
export async function verifySanitizedStateEvidence(
  optionsValue: VerifySanitizedStateEvidenceOptions,
): Promise<StateEvidenceVerificationReportV1> {
  const options = exactObject(optionsValue, ["archivePath", "trust"], "Verify-backup options");
  return verifyFromPath(options.archivePath, options.trust).then(({ report }) => report);
}

/**
 * Verifies and buffers the complete component before creating the restore
 * directory. The destination must not exist; restoration never merges or
 * overwrites. This restores evidence files, not accepted event state; both
 * companion artifacts remain required.
 */
export async function restoreSanitizedStateEvidence(
  optionsValue: RestoreSanitizedStateEvidenceOptions,
): Promise<StateEvidenceRestoreReportV1> {
  const options = exactObject(
    optionsValue,
    ["archivePath", "destinationDirectory", "trust"],
    "Restore-backup options",
  );
  const verified = await verifyFromPath(options.archivePath, options.trust);
  await restoreVerifiedArchive(options.destinationDirectory, verified);
  return Object.freeze({ ...verified.report, restoredFileCount: 8 as const });
}

async function verifyFromPath(archivePath: unknown, trust: unknown): Promise<VerifiedArchive> {
  const bytes = await readArchiveFile(archivePath);
  return verifyArchiveBytes(bytes, trust);
}
