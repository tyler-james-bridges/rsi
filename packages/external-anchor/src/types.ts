import type { KeyObject, PublicKeyInput, JsonWebKeyInput } from "node:crypto";

import type { Ed25519PrivateKeyMaterial, SignedCheckpoint } from "@rsi/checkpoints";

export const EXTERNAL_ANCHOR_VERSION = 1 as const;
export const EXTERNAL_ANCHOR_TYPE = "rsi.external-checkpoint" as const;
export const EXTERNAL_ANCHOR_AUTHORIZATION_VERSION = 1 as const;
export const EXTERNAL_ANCHOR_AUTHORIZATION_TYPE = "rsi.external-anchor-authorization" as const;
export const EXTERNAL_ANCHOR_CONTENT_TYPE = "application/json" as const;
export const EXTERNAL_ANCHOR_MAX_BYTES = 4 * 1_024;
export const EXTERNAL_ANCHOR_MAX_ATTEMPTS = 2 as const;

export type AnchorProfile = "canary" | "production-observer";
export type AnchorRetentionMode = "compliance" | "governance";
export type AnchorRetentionDays = 30 | 365;

export type Ed25519PublicKeyMaterial =
  string | Buffer | JsonWebKeyInput | KeyObject | PublicKeyInput;

export interface ExternalAnchorEnvelopeV1 {
  readonly anchorType: typeof EXTERNAL_ANCHOR_TYPE;
  readonly authorization: SignedExternalAnchorAuthorization;
  readonly checkpoint: SignedCheckpoint;
  readonly version: typeof EXTERNAL_ANCHOR_VERSION;
}

export type ExternalAnchorEnvelope = ExternalAnchorEnvelopeV1;

export interface AnchorRetentionPolicy {
  readonly days: AnchorRetentionDays;
  readonly mode: AnchorRetentionMode;
}

export interface ExternalAnchorAuthorizationPayloadV1 {
  readonly authorizationType: typeof EXTERNAL_ANCHOR_AUTHORIZATION_TYPE;
  readonly checkpointHash: string;
  readonly keyId: string;
  readonly profile: AnchorProfile;
  readonly retention: AnchorRetentionPolicy;
  readonly storeId: string;
  readonly version: typeof EXTERNAL_ANCHOR_AUTHORIZATION_VERSION;
}

export type ExternalAnchorAuthorizationPayload = ExternalAnchorAuthorizationPayloadV1;

export interface SignedExternalAnchorAuthorization {
  readonly payload: ExternalAnchorAuthorizationPayload;
  /** Unpadded RFC 4648 base64url Ed25519 signature. */
  readonly signature: string;
}

export interface SignExternalAnchorAuthorizationInput {
  readonly checkpoint: SignedCheckpoint;
  readonly privateKey: Ed25519PrivateKeyMaterial;
  readonly profile: AnchorProfile;
  readonly retentionMode: AnchorRetentionMode;
}

export interface PreparedExternalAnchorObject {
  /** Canonical JSON. Strings keep caller-visible prepared content immutable. */
  readonly body: string;
  readonly checkpointHash: string;
  readonly contentSha256: string;
  readonly journalSequence: number;
  readonly objectKey: string;
  readonly profile: AnchorProfile;
  readonly retention: AnchorRetentionPolicy;
  readonly sizeBytes: number;
  readonly storeHeadSequence: number;
}

export interface PrepareExternalAnchorInput {
  readonly authorization: SignedExternalAnchorAuthorization;
  readonly checkpoint: SignedCheckpoint;
}

export interface ExternalAnchorProtocolOptions {
  readonly expectedKeyId: string;
  readonly expectedPublicKey: Ed25519PublicKeyMaterial;
  readonly expectedStoreId: string;
}

export interface CreateAnchorObjectRequest {
  readonly body: string;
  readonly contentSha256: string;
  readonly contentType: typeof EXTERNAL_ANCHOR_CONTENT_TYPE;
  readonly idempotencyKey: string;
  readonly objectKey: string;
  readonly retention: AnchorRetentionPolicy;
  readonly sizeBytes: number;
}

export type AnchorCreateDisposition = "already_exists" | "created";

export interface CreateAnchorObjectResult {
  readonly contentSha256: string;
  readonly disposition: AnchorCreateDisposition;
  readonly objectKey: string;
  readonly retainedUntil: string;
  readonly retentionMode: AnchorRetentionMode;
  readonly sizeBytes: number;
  readonly storedAt: string;
}

export interface AnchorObjectSummary {
  readonly contentSha256: string;
  readonly objectKey: string;
  readonly retainedUntil: string;
  readonly retentionMode: AnchorRetentionMode;
  readonly sizeBytes: number;
  readonly storedAt: string;
}

export interface ReadAnchorObjectResult extends AnchorObjectSummary {
  readonly body: string;
}

export interface AnchorPublisherTransport {
  readonly create: (request: CreateAnchorObjectRequest) => Promise<CreateAnchorObjectResult>;
}

export interface AnchorVerifierTransport {
  readonly list: (input: Readonly<{ prefix: string }>) => Promise<readonly AnchorObjectSummary[]>;
  readonly read: (
    input: Readonly<{ objectKey: string }>,
  ) => Promise<ReadAnchorObjectResult | undefined>;
}

export interface ExternalAnchorHead {
  readonly checkpointCreatedAt: string;
  readonly checkpointHash: string;
  readonly contentSha256: string;
  readonly journalSequence: number;
  readonly objectKey: string;
  readonly retainedUntil: string;
  readonly retentionMode: AnchorRetentionMode;
  readonly sizeBytes: number;
  readonly storedAt: string;
  readonly storeHeadSequence: number;
}

export type ExternalAnchorIssueCode =
  | "COMPLIANCE_DOWNGRADE"
  | "CONTENT_HASH_MISMATCH"
  | "EMPTY_ANCHOR_SET"
  | "FORK_DETECTED"
  | "INVALID_CHECKPOINT_HASH"
  | "INVALID_ENVELOPE"
  | "INVALID_LIST_RESULT"
  | "INVALID_OBJECT_METADATA"
  | "INVALID_SIGNATURE"
  | "JOURNAL_SEQUENCE_GAP"
  | "NON_CANONICAL_BODY"
  | "OBJECT_KEY_MISMATCH"
  | "OBJECT_READ_MISSING"
  | "OBJECT_TOO_LARGE"
  | "PINNED_HEAD_MISMATCH"
  | "PINNED_HEAD_MISSING"
  | "PREVIOUS_HASH_MISMATCH"
  | "RETENTION_EXPIRED"
  | "RETENTION_POLICY_MISMATCH"
  | "RETENTION_TOO_SHORT"
  | "ROLLBACK_DETECTED"
  | "STORE_SEQUENCE_NOT_INCREASING"
  | "SUMMARY_READ_MISMATCH"
  | "TIMESTAMP_REGRESSION"
  | "TIMESTAMP_IN_FUTURE"
  | "WRONG_KEY_ID"
  | "WRONG_PROFILE"
  | "WRONG_STORE_ID";

export interface ExternalAnchorIssue {
  readonly code: ExternalAnchorIssueCode;
  readonly journalSequence: number | null;
  readonly message: string;
}

export interface ExternalAnchorVerificationReport {
  readonly anchorCount: number;
  readonly head: ExternalAnchorHead | null;
  readonly issues: readonly ExternalAnchorIssue[];
  readonly pinnedHeadMatched: boolean;
  readonly valid: boolean;
  readonly verifiedAt: string;
}

export interface ExternalAnchorVerifierOptions extends ExternalAnchorProtocolOptions {
  readonly expectedProfile: AnchorProfile;
  readonly minimumHeadRetentionMode: AnchorRetentionMode;
  readonly pinnedHead: ExternalAnchorHead | null;
  readonly transport: AnchorVerifierTransport;
}

export interface VerifyExternalAnchorsInput {
  readonly verifiedAt: string;
}

export type AnchorOutboxState = "failed" | "in_flight" | "pending" | "published";

export interface OpenExternalAnchorOutboxOptions extends ExternalAnchorProtocolOptions {
  readonly databasePath: string;
  readonly profile: AnchorProfile;
  readonly stateKey: Uint8Array;
}

export interface EnqueueExternalAnchorInput {
  readonly authorization: SignedExternalAnchorAuthorization;
  readonly checkpoint: SignedCheckpoint;
  readonly queuedAt: string;
}

export interface ExternalAnchorQueueReceipt {
  readonly attemptCount: number;
  readonly checkpointHash: string;
  readonly journalSequence: number;
  readonly objectKey: string;
  readonly profile: AnchorProfile;
  readonly queuedAt: string;
  readonly retentionMode: AnchorRetentionMode;
  readonly state: AnchorOutboxState;
  readonly storeHeadSequence: number;
  readonly updatedAt: string;
}

export interface ClaimExternalAnchorInput {
  readonly claimedAt: string;
}

export interface ExternalAnchorPublishClaim extends ExternalAnchorQueueReceipt {
  readonly attempt: 1 | 2;
  readonly request: CreateAnchorObjectRequest;
}

export interface CompleteExternalAnchorInput {
  readonly attempt: 1 | 2;
  readonly completedAt: string;
  readonly objectKey: string;
  readonly result: CreateAnchorObjectResult;
}

export interface FailExternalAnchorInput {
  readonly attempt: 1 | 2;
  readonly failedAt: string;
  readonly objectKey: string;
  readonly retryable: boolean;
}

export interface RecoverExternalAnchorsInput {
  readonly recoveredAt: string;
}

export interface ExternalAnchorRecoveryReceipt {
  readonly failed: number;
  readonly recoveredAt: string;
  readonly requeued: number;
}

export interface ExternalAnchorPublicationReceipt extends ExternalAnchorQueueReceipt {
  readonly disposition: AnchorCreateDisposition;
  readonly retainedUntil: string;
  readonly storedAt: string;
}

export interface ExternalAnchorOutboxIntegrityReport {
  readonly errors: readonly string[];
  readonly failedCount: number;
  readonly inFlightCount: number;
  readonly pendingCount: number;
  readonly profile: AnchorProfile;
  readonly publishedCount: number;
  readonly rowCount: number;
  readonly valid: boolean;
}

export interface ExternalAnchorPublisherOptions {
  readonly clock: () => string;
  readonly outbox: ExternalAnchorOutboxPort;
  readonly transport: AnchorPublisherTransport;
}

export interface ExternalAnchorOutboxPort {
  claim(input: ClaimExternalAnchorInput): ExternalAnchorPublishClaim | undefined;
  complete(input: CompleteExternalAnchorInput): ExternalAnchorPublicationReceipt;
  fail(input: FailExternalAnchorInput): ExternalAnchorQueueReceipt;
}
