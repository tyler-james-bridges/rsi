export type CaptureRegistrySource = "alchemy" | "fixture" | "opensea" | "x";
export type CaptureRegistryProfile = "canary" | "dev" | "production-observer";
export type CaptureRegistryLane =
  "contract" | "discovery" | "marketplace" | "official" | "security";

export interface OpenSeaSourceIdentifier {
  readonly kind: "asset_id" | "collection_slug" | "next_cursor";
  readonly value: string;
}

export interface AlchemySourceIdentifier {
  readonly kind: "block_number" | "page_key" | "transaction_hash";
  readonly value: string;
}

export interface FixtureSourceIdentifier {
  readonly kind: "fixture_id";
  readonly value: string;
}

export type CaptureSourceIdentifiers =
  | Readonly<{
      identifiers: readonly AlchemySourceIdentifier[];
      source: "alchemy";
    }>
  | Readonly<{
      identifiers: readonly FixtureSourceIdentifier[];
      source: "fixture";
    }>
  | Readonly<{
      identifiers: readonly OpenSeaSourceIdentifier[];
      source: "opensea";
    }>
  | Readonly<{
      /** Every accepted 10-result X page fits: 10 posts, 10 users, and 100 edits per post. */
      editIds: readonly string[];
      nextToken: string | null;
      postIds: readonly string[];
      source: "x";
      userIds: readonly string[];
    }>;

export interface OpenCaptureRegistryOptions {
  /** A dedicated 32-byte key. It is copied, derived, and never persisted. */
  readonly registryKey: Uint8Array;
  /** Binds the database and key-check sentinel to exactly one runtime profile. */
  readonly expectedProfile: CaptureRegistryProfile;
  /** SQLite file path inside a caller-owned 0700 directory. */
  readonly path: string;
}

export interface BeginCaptureAttemptInput {
  readonly acquiredAt: string;
  readonly attemptId: string;
  readonly expiresAt: string;
  readonly lane: CaptureRegistryLane;
  readonly profile: CaptureRegistryProfile;
  readonly requestFingerprint: `sha256:${string}`;
  readonly sessionId: string;
  readonly source: CaptureRegistrySource;
}

export interface CommitCaptureInput {
  readonly attemptId: string;
  readonly captureId: string;
  readonly committedAt: string;
  readonly sourceIdentifiers: CaptureSourceIdentifiers;
}

export interface CaptureDeletionReceiptV1 {
  readonly captureId: string;
  readonly deletedAt: string;
  readonly keyDestroyed: true;
  readonly reason: "expired" | "explicit";
  readonly schemaVersion: 1;
  readonly state: "deleted";
}

export interface RecordVerifiedCaptureDeletionInput {
  readonly attemptId: string;
  /** The exact content-free receipt returned after Vault v2 has destroyed the capture DEK. */
  readonly deletionReceipt: CaptureDeletionReceiptV1;
}

export interface PendingCaptureAttempt extends BeginCaptureAttemptInput {
  readonly schemaVersion: 1;
  readonly state: "pending";
}

export interface CommittedCaptureAttempt extends BeginCaptureAttemptInput {
  readonly captureId: string;
  readonly committedAt: string;
  readonly schemaVersion: 1;
  readonly sourceIdentifiers: CaptureSourceIdentifiers;
  readonly state: "committed";
}

export interface RemovedCaptureAttempt {
  /** Reconstructed from the caller's keyed lookup; never retained in tombstone plaintext. */
  readonly attemptId: string;
  readonly keyDestroyed: true;
  readonly removalReason:
    | "capture_deleted_expired"
    | "capture_deleted_explicit"
    | "pending_explicit"
    | "pending_recovery";
  readonly removedAt: string;
  readonly schemaVersion: 1;
  readonly state: "removed";
}

export type CaptureRegistryAttempt =
  PendingCaptureAttempt | CommittedCaptureAttempt | RemovedCaptureAttempt;

export interface RemovePendingCaptureAttemptInput {
  readonly attemptId: string;
  readonly removedAt: string;
}

export interface RecoverPendingCaptureAttemptsInput {
  readonly limit?: number;
  readonly recoveredAt: string;
}

export interface PendingCaptureRecoveryResultV1 {
  readonly recoveredAt: string;
  readonly removed: number;
  readonly schemaVersion: 1;
  readonly truncated: boolean;
}

export interface PurgeRemovedCaptureAttemptsInput {
  readonly before: string;
  readonly limit?: number;
}

export interface RemovedCapturePurgeResultV1 {
  readonly before: string;
  readonly purged: number;
  readonly schemaVersion: 1;
  readonly truncated: boolean;
}

export interface CaptureRegistryIntegrityReportV1 {
  readonly keyDestroyedTombstones: number;
  readonly nextSequence: number;
  readonly recordCount: number;
  readonly schemaVersion: 1;
  readonly valid: true;
}

/** Private lifecycle-integration reference. It must never enter public projections or logs. */
export interface CommittedCaptureReference {
  readonly attemptId: string;
  readonly captureId: string;
}

export interface SessionRemovalSummaryV1 {
  readonly counts: Readonly<{
    readonly captureDeletedExpired: number;
    readonly captureDeletedExplicit: number;
    readonly pendingExplicit: number;
    readonly pendingRecovery: number;
  }>;
  readonly schemaVersion: 1;
  readonly total: number;
}

/** Aggregate-only active/removed state for a supervised session. */
export interface SessionCaptureStateSummaryV1 {
  readonly schemaVersion: 1;
  readonly profile: CaptureRegistryProfile;
  readonly sessionId: string;
  readonly pending: number;
  readonly committed: number;
  readonly removed: number;
  readonly total: number;
}
