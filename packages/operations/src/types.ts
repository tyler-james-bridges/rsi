export type OperationsProfile = "canary" | "dev" | "production-observer";

export type SourcePlane = "canonical_chain" | "marketplace" | "social";

export type ResearchLane = "contract" | "discovery" | "marketplace" | "official" | "security";

export type ResearchOperation =
  "alchemy.json-rpc.v1" | "opensea.rest.v1" | "opensea.stream.v1" | "x.recent-search.v1";

export type AtomicAmount = string & { readonly __atomicAmount: unique symbol };

export type AttemptPermitToken = string & { readonly __attemptPermitToken: unique symbol };

export interface AttemptPermit {
  readonly attemptId: string;
  readonly token: AttemptPermitToken;
}

export interface NetworkAttemptBinding {
  readonly attemptId: string;
  readonly authorizationExpiresAt: string;
  readonly lane: ResearchLane;
  readonly operation: ResearchOperation;
  readonly profile: OperationsProfile;
  readonly reservedAtomic: AtomicAmount;
  readonly sessionId: string;
  readonly sourcePlane: SourcePlane;
}

/** Read-only authenticated attempt facts; never contains the one-shot permit token. */
export interface DurableNetworkAttemptBinding extends NetworkAttemptBinding {
  readonly dispatchedAt: string | null;
  readonly state: AttemptState;
}

export interface CreateBudgetInput {
  readonly budgetId: string;
  readonly createdAt: string;
  readonly currency: "USD_MICRO";
  readonly endsAt: string;
  readonly maxAtomic: string;
  readonly maxAttempts: number;
  readonly profile: OperationsProfile;
  readonly startsAt: string;
}

export interface BudgetRecord extends CreateBudgetInput {
  readonly maxAtomic: AtomicAmount;
}

export interface BudgetSummary extends BudgetRecord {
  readonly attemptedCount: number;
  readonly remainingAtomic: AtomicAmount;
  readonly reservedAtomic: AtomicAmount;
}

export interface ReserveAttemptInput {
  readonly attemptId: string;
  readonly authorizationExpiresAt: string;
  readonly budgetId: string;
  readonly createdAt: string;
  readonly idempotencyKey: string;
  readonly lane: ResearchLane;
  readonly operation: ResearchOperation;
  readonly permitToken: string;
  readonly reservedAtomic: string;
  readonly sessionId: string;
  readonly sourcePlane: SourcePlane;
}

export type AttemptState = "closed" | "dispatched" | "reserved";

export type AttemptOutcome = "aborted" | "empty" | "failed" | "succeeded";

export interface AttemptRecord {
  readonly attemptId: string;
  readonly authorizationExpiresAt: string;
  readonly budgetId: string;
  readonly closedAt: string | null;
  readonly createdAt: string;
  readonly dispatchedAt: string | null;
  readonly idempotencyKey: string;
  readonly lane: ResearchLane;
  readonly operation: ResearchOperation;
  readonly outcome: AttemptOutcome | null;
  readonly reservedAtomic: AtomicAmount;
  readonly sessionId: string;
  readonly sourcePlane: SourcePlane;
  readonly state: AttemptState;
}

export interface SourceAttemptGroupSummaryV1 {
  readonly abortedCount: number;
  readonly attemptCount: number;
  readonly closedCount: number;
  readonly emptyCount: number;
  readonly failedCount: number;
  readonly reservedAtomic: AtomicAmount;
  readonly succeededCount: number;
}

/** Content-free, authenticated session closure facts for lifecycle composition. */
export interface SessionAttemptSummaryV1 {
  readonly schemaVersion: 1;
  readonly profile: Exclude<OperationsProfile, "dev">;
  readonly sessionId: string;
  readonly attemptCount: number;
  readonly crossProfileAttemptCount: number;
  readonly allAttemptsClosed: boolean;
  readonly reservedAtomic: AtomicAmount;
  readonly xLanes: Readonly<Record<ResearchLane, Readonly<SourceAttemptGroupSummaryV1>>>;
  readonly openSea: Readonly<{
    rest: Readonly<SourceAttemptGroupSummaryV1>;
    stream: Readonly<SourceAttemptGroupSummaryV1>;
  }>;
  readonly canonicalChain: Readonly<SourceAttemptGroupSummaryV1>;
}

export interface CursorIdentity {
  readonly lane: ResearchLane;
  readonly profile: OperationsProfile;
  readonly sourcePlane: SourcePlane;
}

export interface CursorState extends CursorIdentity {
  readonly lineageId: string;
  readonly revision: number;
  readonly updatedAt: string;
  readonly value: string | null;
}

export interface CursorCommitReceipt extends CursorIdentity {
  readonly advanceId: string;
  readonly committedAt: string;
  readonly lineageId: string;
  readonly revision: number;
  readonly state: "committed";
}

export interface InitializeCursorLineageInput extends CursorIdentity {
  readonly initializedAt: string;
  readonly lineageId: string;
}

export interface StageCursorAdvanceInput extends CursorIdentity {
  readonly advanceId: string;
  readonly attemptId: string;
  readonly candidateCursor: string;
  readonly expectedRevision: number;
  readonly lineageId: string;
  readonly stagedAt: string;
}

export type CursorAdvanceState =
  | "aborted"
  | "anchor_published"
  | "checkpointed"
  | "committed"
  | "event_persisted"
  | "externally_verified"
  | "staged"
  | "validated";

export interface CursorAdvanceRecord extends CursorIdentity {
  readonly advanceId: string;
  readonly attemptId: string;
  readonly baseRevision: number;
  readonly lineageId: string;
  readonly state: CursorAdvanceState;
  readonly stagedAt: string;
}

export interface SafeEventReceipt {
  readonly eventHash: string;
  readonly eventId: string;
  readonly eventSequence: number;
  readonly persistedAt: string;
}

export interface LocalCheckpointReceipt {
  readonly anchoredThroughSequence: number;
  readonly checkpointHead: string;
  readonly checkpointedAt: string;
}

export interface ExternalAnchorReceipt {
  readonly anchorHead: string;
  readonly anchorId: string;
  readonly publishedAt: string;
}

export interface ExternalVerificationReceipt {
  readonly anchorHead: string;
  readonly anchorId: string;
  readonly verifiedAt: string;
}

export interface OperationsIntegrityReport {
  readonly attemptCount: number;
  readonly budgetCount: number;
  readonly cursorAdvanceCount: number;
  readonly cursorCount: number;
  readonly errors: readonly string[];
  readonly eventCount: number;
  readonly headMac: string;
  readonly headSequence: number;
  readonly valid: boolean;
}
