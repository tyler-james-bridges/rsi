import { SqliteCaptureRegistry, isSqliteCaptureRegistry } from "@rsi/capture-registry";
import { CanonicalTimestampSchema, parseWithSchema } from "@rsi/operations";
import {
  SnapshotIntegrityError,
  SnapshotNotFoundError,
  isSnapshotVault,
  type SnapshotVault,
} from "@rsi/vault";
import { z } from "zod";

export interface RecoverCaptureStorageInput {
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly limit?: number;
  readonly recoveredAt: string;
  readonly vault: SnapshotVault;
}

export interface CaptureStorageRecoverySummaryV1 {
  readonly reconciledBatches: number;
  readonly registryDeletionRepairs: number;
  readonly removedOrphanBodies: number;
  readonly removedOrphanCaptures: number;
  readonly removedPendingAttempts: number;
  readonly removedTemporaryFiles: number;
  readonly resumedVaultDeletions: number;
  readonly schemaVersion: 1;
}

const RecoverCaptureStorageInputSchema = z.strictObject({
  captureRegistry: z.custom<SqliteCaptureRegistry>(
    isSqliteCaptureRegistry,
    "an authenticated capture registry is required",
  ),
  limit: z.number().int().min(1).max(1_000).optional(),
  recoveredAt: CanonicalTimestampSchema,
  vault: z.custom<SnapshotVault>(isSnapshotVault, "an authenticated SnapshotVault is required"),
});

function assertCommittedCaptureMetadata(
  reference: ReturnType<SqliteCaptureRegistry["getAttempt"]>,
  verification: Awaited<ReturnType<SnapshotVault["verify"]>>,
): void {
  if (
    reference?.state !== "committed" ||
    verification.metadata.schemaVersion !== 1 ||
    verification.metadata.source !== reference.source ||
    verification.metadata.expiresAt !== reference.expiresAt ||
    Date.parse(verification.metadata.acquiredAt) < Date.parse(reference.acquiredAt) ||
    Date.parse(verification.metadata.acquiredAt) > Date.parse(reference.committedAt) ||
    Date.parse(verification.metadata.acquiredAt) > Date.parse(reference.expiresAt)
  ) {
    throw new SnapshotIntegrityError();
  }
}

/**
 * Mandatory startup repair for the registry/Vault crash seam. The returned
 * value contains counts only; opaque capture and attempt handles never escape.
 */
export async function recoverCaptureStorage(
  input: Readonly<RecoverCaptureStorageInput>,
): Promise<Readonly<CaptureStorageRecoverySummaryV1>> {
  const parsed = parseWithSchema(
    RecoverCaptureStorageInputSchema,
    input,
    "capture storage recovery input",
  );
  const { captureRegistry, limit, recoveredAt, vault } = parsed;
  const vaultRecovery = await vault.recover({ recoveredAt });

  let removedPendingAttempts = 0;
  let pendingTruncated = true;
  while (pendingTruncated) {
    const recovery = captureRegistry.recoverPendingAttempts(
      limit === undefined ? { recoveredAt } : { limit, recoveredAt },
    );
    removedPendingAttempts += recovery.removed;
    pendingTruncated = recovery.truncated;
  }

  let registryDeletionRepairs = 0;
  const referencesByCapture = new Map(
    captureRegistry.listCommittedCaptures().map((reference) => [reference.captureId, reference]),
  );
  for (const receipt of vaultRecovery.resumedDeletionReceipts) {
    const reference = referencesByCapture.get(receipt.captureId);
    if (reference !== undefined) {
      captureRegistry.recordVerifiedDeletion({
        attemptId: reference.attemptId,
        deletionReceipt: receipt,
      });
      registryDeletionRepairs += 1;
      referencesByCapture.delete(receipt.captureId);
    }
  }

  for (const reference of captureRegistry.listCommittedCaptures()) {
    const attempt = captureRegistry.getAttempt(reference.attemptId);
    try {
      const verification = await vault.verify(reference.captureId);
      assertCommittedCaptureMetadata(attempt, verification);
    } catch (error) {
      if (!(error instanceof SnapshotNotFoundError)) throw error;
      let receipt;
      try {
        receipt = await vault.delete(reference.captureId, {
          deletedAt: recoveredAt,
          reason: "explicit",
        });
      } catch (deletionError) {
        if (deletionError instanceof SnapshotNotFoundError) throw new SnapshotIntegrityError();
        throw deletionError;
      }
      captureRegistry.recordVerifiedDeletion({
        attemptId: reference.attemptId,
        deletionReceipt: receipt,
      });
      registryDeletionRepairs += 1;
    }
  }

  let reconciledBatches = 0;
  let removedOrphanCaptures = 0;
  let reconciliationTruncated = true;
  while (reconciliationTruncated) {
    const registeredCaptureIds = captureRegistry.listCommittedCaptureIds();
    const reconciliation = await vault.reconcileRegisteredCaptures(
      limit === undefined
        ? { reconciledAt: recoveredAt, registeredCaptureIds }
        : { limit, reconciledAt: recoveredAt, registeredCaptureIds },
    );
    reconciledBatches += 1;
    removedOrphanCaptures += reconciliation.removedOrphanCaptures;
    reconciliationTruncated = reconciliation.truncated;
  }

  return Object.freeze({
    reconciledBatches,
    registryDeletionRepairs,
    removedOrphanBodies: vaultRecovery.removedOrphanBodies,
    removedOrphanCaptures,
    removedPendingAttempts,
    removedTemporaryFiles: vaultRecovery.removedTemporaryFiles,
    resumedVaultDeletions: vaultRecovery.resumedDeletionReceipts.length,
    schemaVersion: 1 as const,
  });
}
