export type SnapshotMetadataPrimitive = boolean | number | string | null;

export type SnapshotMetadataValue =
  | SnapshotMetadataPrimitive
  | readonly SnapshotMetadataValue[]
  | Readonly<{ [key: string]: SnapshotMetadataValue }>;

export type SnapshotMetadata = Readonly<Record<string, SnapshotMetadataValue>>;

export type SnapshotAddress = string & { readonly __snapshotAddress: unique symbol };

export interface SnapshotVaultOptions {
  /** A dedicated directory. It is created if absent and restricted to mode 0700. */
  readonly directory: string;
  /** Exactly 32 caller-owned bytes. The vault copies the key and never persists it. */
  readonly key: Uint8Array;
  /** Per-instance limit, from 1 byte through HARD_MAX_SNAPSHOT_BYTES. */
  readonly maxSnapshotBytes?: number;
  /** Per-instance canonical JSON limit, from 2 bytes through HARD_MAX_METADATA_BYTES. */
  readonly maxMetadataBytes?: number;
}

export interface PutSnapshotOptions {
  /** Authenticated, encrypted canonical JSON metadata. */
  readonly metadata?: SnapshotMetadata;
}

export interface SnapshotDescriptor {
  readonly address: SnapshotAddress;
  readonly metadata: SnapshotMetadata;
  readonly size: number;
}

export interface PutSnapshotResult extends SnapshotDescriptor {
  /** True only for the caller that atomically published the object. */
  readonly created: boolean;
}

export interface Snapshot extends SnapshotDescriptor {
  /** A fresh defensive copy. Mutating it cannot alter the stored snapshot. */
  readonly bytes: Uint8Array;
}

export interface SnapshotVerification extends SnapshotDescriptor {
  readonly valid: true;
}
