export type CaptureId = string & { readonly __captureId: unique symbol };

export type CaptureSource = "alchemy" | "fixture" | "opensea" | "x";

/**
 * The complete, closed metadata schema encrypted alongside every capture.
 * Unknown fields and non-canonical timestamps are rejected.
 */
export interface CaptureMetadataV1 {
  readonly schemaVersion: 1;
  readonly source: CaptureSource;
  readonly acquiredAt: string;
  readonly expiresAt: string;
  readonly mediaType: string;
}

export interface SnapshotVaultOptions {
  /** A dedicated directory. It is created if absent and restricted to mode 0700. */
  readonly directory: string;
  /** Exactly 32 caller-owned bytes. It wraps random per-capture DEKs and is never persisted. */
  readonly wrappingKey: Uint8Array;
  /** Per-instance limit, from 1 byte through HARD_MAX_CAPTURE_BYTES. Zero-byte captures remain valid. */
  readonly maxCaptureBytes?: number;
  /** Canonical metadata limit, from 129 bytes through HARD_MAX_METADATA_BYTES. */
  readonly maxMetadataBytes?: number;
}

export interface CaptureOptions {
  readonly metadata: CaptureMetadataV1;
}

export interface CaptureDescriptor {
  readonly captureId: CaptureId;
  readonly metadata: CaptureMetadataV1;
  readonly size: number;
}

export interface Capture extends CaptureDescriptor {
  /** A fresh defensive copy. Mutating it cannot alter the stored capture. */
  readonly bytes: Uint8Array;
}

export interface CaptureVerification extends CaptureDescriptor {
  readonly valid: true;
}

export type CaptureDeletionReason = "expired" | "explicit";

export interface DeleteCaptureOptions {
  readonly deletedAt: string;
  readonly reason: CaptureDeletionReason;
}

/** Contains lifecycle facts only: never content, provider identifiers, sizes, or hashes. */
export interface CaptureDeletionReceiptV1 {
  readonly schemaVersion: 1;
  readonly captureId: CaptureId;
  readonly deletedAt: string;
  readonly keyDestroyed: true;
  readonly reason: CaptureDeletionReason;
  readonly state: "deleted";
}

export interface SweepExpiredOptions {
  /** Canonical UTC instant used for both expiry comparison and deletion receipts. */
  readonly now: string;
  /** Maximum captures deleted in one sweep. Defaults to DEFAULT_EXPIRY_SWEEP_LIMIT. */
  readonly limit?: number;
}

export interface CaptureExpirySweepResultV1 {
  readonly schemaVersion: 1;
  readonly sweptAt: string;
  readonly examined: number;
  readonly receipts: readonly CaptureDeletionReceiptV1[];
  readonly truncated: boolean;
}

export interface RecoverCaptureVaultOptions {
  /** Canonical UTC instant recorded for the recovery operation. */
  readonly recoveredAt: string;
}

export interface CaptureRecoveryResultV1 {
  readonly schemaVersion: 1;
  readonly recoveredAt: string;
  readonly removedOrphanBodies: number;
  readonly removedTemporaryFiles: number;
  readonly resumedDeletionReceipts: readonly CaptureDeletionReceiptV1[];
}

export interface ReconcileRegisteredCapturesOptions {
  /** The complete active set from the authenticated encrypted capture registry. */
  readonly registeredCaptureIds: readonly string[];
  /** Canonical UTC instant used for orphan crypto-shredding receipts. */
  readonly reconciledAt: string;
  /** Maximum orphan captures destroyed in one call. */
  readonly limit?: number;
}

/** Aggregate-only result. It never exposes opaque capture handles. */
export interface CaptureReconciliationResultV1 {
  readonly examined: number;
  readonly reconciledAt: string;
  readonly removedOrphanCaptures: number;
  readonly retainedRegisteredCaptures: number;
  readonly schemaVersion: 1;
  readonly truncated: boolean;
}
