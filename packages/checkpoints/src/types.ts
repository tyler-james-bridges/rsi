import type {
  BinaryLike,
  JsonWebKeyInput,
  KeyObject,
  PrivateKeyInput,
  PublicKeyInput,
  RawPrivateKeyInput,
  RawPublicKeyInput,
} from "node:crypto";

export const CHECKPOINT_PAYLOAD_VERSION = 1 as const;
export const CHECKPOINT_TYPE = "rsi.store.head" as const;
export const CHECKPOINT_JOURNAL_GENESIS_HASH = "0".repeat(64);

/** Private key material accepted by node:crypto.createPrivateKey(). */
export type Ed25519PrivateKeyMaterial =
  BinaryLike | JsonWebKeyInput | KeyObject | PrivateKeyInput | RawPrivateKeyInput;

/** Public key material accepted by node:crypto.createPublicKey(). */
export type Ed25519PublicKeyMaterial =
  BinaryLike | JsonWebKeyInput | KeyObject | PublicKeyInput | RawPublicKeyInput;

export interface CheckpointPayloadV1 {
  readonly checkpointType: typeof CHECKPOINT_TYPE;
  readonly createdAt: string;
  readonly journalSequence: number;
  readonly keyId: string;
  readonly previousCheckpointHash: string;
  readonly storeHeadHash: string;
  readonly storeHeadSequence: number;
  readonly storeId: string;
  readonly version: typeof CHECKPOINT_PAYLOAD_VERSION;
}

export type CheckpointPayload = CheckpointPayloadV1;

export interface SignedCheckpoint {
  readonly checkpointHash: string;
  readonly payload: CheckpointPayload;
  /** Unpadded RFC 4648 base64url Ed25519 signature. */
  readonly signature: string;
}

/** A value retained outside the journal to detect journal rollback/truncation. */
export interface CheckpointJournalHead {
  readonly checkpointHash: string;
  readonly journalSequence: number;
}

export interface StoreIntegrityIssueLike {
  readonly code: string;
  readonly message: string;
  readonly sequence: number | null;
}

export interface StoreIntegrityReportLike {
  readonly errors: readonly StoreIntegrityIssueLike[];
  readonly eventCount: number;
  readonly headHash: string;
  readonly headSequence: number;
  readonly valid: boolean;
}

export interface StoredEventHeadLike {
  readonly eventHash: string;
  readonly sequence: number;
}

/**
 * The subset of @rsi/store's SqliteEventStore used by this package. Keeping it
 * structural lets callers wrap the store without exposing its SQLite handle.
 */
export interface CheckpointStore {
  readonly path: string;
  list(filters?: {
    readonly afterSequence?: number;
    readonly beforeSequence?: number;
    readonly limit?: number;
    readonly order?: "asc" | "desc";
  }): readonly StoredEventHeadLike[];
  verifyIntegrity(): StoreIntegrityReportLike;
  withExclusiveTransaction<T>(operation: () => T): T;
}

export type CheckpointJournalIssueCode =
  | "CHECKPOINT_HASH_MISMATCH"
  | "EMPTY_STORE_ANCHOR"
  | "INVALID_ENTRY"
  | "INVALID_JOURNAL_ENCODING"
  | "INVALID_SIGNATURE"
  | "JOURNAL_READ_ERROR"
  | "JOURNAL_SEQUENCE_GAP"
  | "JOURNAL_TOO_LARGE"
  | "NON_CANONICAL_ENTRY"
  | "PREVIOUS_CHECKPOINT_HASH_MISMATCH"
  | "STORE_SEQUENCE_NOT_INCREASING"
  | "TIMESTAMP_REGRESSION"
  | "TRUSTED_CHECKPOINT_MISSING"
  | "TRUSTED_CHECKPOINT_MISMATCH"
  | "UNSAFE_JOURNAL_PATH"
  | "WRONG_KEY_ID"
  | "WRONG_STORE_ID";

export interface CheckpointJournalIssue {
  readonly code: CheckpointJournalIssueCode;
  readonly journalSequence: number | null;
  readonly line: number | null;
  readonly message: string;
}

export interface CheckpointJournalVerificationReport {
  readonly entries: readonly SignedCheckpoint[];
  readonly issues: readonly CheckpointJournalIssue[];
  readonly journalExists: boolean;
  readonly journalHead: CheckpointJournalHead | null;
  /** The externally retained position checked during this verification. */
  readonly truncationProtectedThrough: CheckpointJournalHead | null;
  readonly valid: boolean;
}

export type CheckpointStoreIssueCode =
  | "ANCHORED_EVENT_MISSING"
  | "ANCHORED_HASH_MISMATCH"
  | "EMPTY_STORE_ANCHOR"
  | "INVALID_STORE_REPORT"
  | "NO_CHECKPOINT"
  | "STORE_INTEGRITY_INVALID";

export interface CheckpointStoreIssue {
  readonly code: CheckpointStoreIssueCode;
  readonly journalSequence: number | null;
  readonly message: string;
  readonly storeSequence: number | null;
}

export type CheckpointVerificationStatus = "ANCHORED" | "INVALID" | "UNANCHORED";

export interface CheckpointVerificationReport {
  /** Sequence through which the current store was cryptographically matched. */
  readonly anchoredThroughSequence: number | null;
  readonly journal: CheckpointJournalVerificationReport;
  readonly latestCheckpoint: SignedCheckpoint | null;
  /** Anchor claimed by the latest authenticated journal entry, even if the store differs. */
  readonly recordedAnchorSequence: number | null;
  readonly status: CheckpointVerificationStatus;
  readonly storeHeadHash: string;
  readonly storeHeadSequence: number;
  readonly storeIssues: readonly CheckpointStoreIssue[];
  /** All unanchored events, or null when invalid data prevents a reliable count. */
  readonly unanchoredEventCount: number | null;
  readonly valid: boolean;
}

export interface CheckpointSignerOptions {
  /** Must be null only when creating a genuinely empty journal. */
  readonly expectedJournalHead: CheckpointJournalHead | null;
  readonly journalPath: string;
  readonly keyId: string;
  readonly privateKey: Ed25519PrivateKeyMaterial;
  readonly storeId: string;
}

export interface AppendCheckpointOptions {
  /** Defaults to the current time and must already be canonical ISO UTC. */
  readonly createdAt?: string;
}

export interface CheckpointVerifierOptions {
  readonly expectedKeyId: string;
  readonly expectedPublicKey: Ed25519PublicKeyMaterial;
  readonly expectedStoreId: string;
  readonly journalPath: string;
  /**
   * An externally retained checkpoint that must still occur in the journal.
   * Update this to the newest observed journalHead to detect later suffix loss.
   */
  readonly trustedJournalHead?: CheckpointJournalHead;
}
