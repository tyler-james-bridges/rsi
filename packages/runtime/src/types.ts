import type {
  RuntimeBoundaryEventPayload,
  RuntimeStopEventPayload,
  RuntimeTransitionEventPayload,
} from "./schemas.js";

export type RuntimeMode = "PROPOSE_ONLY" | "RESEARCH" | "STOPPED";

export type RuntimeBoundary =
  | "execution_adapter"
  | "external_publish"
  | "paid_read"
  | "policy_approval"
  | "proposal_persist"
  | "research_collection"
  | "transaction_broadcast"
  | "wallet_sign";

export type RuntimeBoundaryDecisionReason =
  | "ALLOWED"
  | "EXPIRED"
  | "MODE_NOT_ALLOWED"
  | "PERMANENTLY_FORBIDDEN"
  | "PROCESS_SUPERSEDED"
  | "STALE_REVISION";

export interface OpenRuntimeInput {
  readonly openedAt: string;
  readonly path: string;
  readonly processInstanceId: string;
}

export interface RuntimeOpenOptions {
  readonly clock?: () => string;
  readonly monotonicClock?: () => number;
}

export interface RuntimeTransitionInput {
  readonly expectedMode: RuntimeMode;
  readonly expectedRevision: number;
  readonly occurredAt: string;
  readonly requestId: string;
  readonly targetMode: Exclude<RuntimeMode, "STOPPED">;
}

export interface RuntimeStopInput {
  readonly occurredAt: string;
  readonly requestId: string;
}

export interface RuntimeBoundaryAuthorizationInput {
  readonly actionId: string;
  readonly authorizationId: string;
  readonly boundary: RuntimeBoundary;
}

export interface RuntimeCapabilitiesV1 {
  readonly executionAdapter: false;
  readonly externalPublish: false;
  readonly paidRead: false;
  readonly policyApproval: false;
  readonly proposalPersistence: boolean;
  readonly researchCollection: boolean;
  readonly transactionBroadcast: false;
  readonly walletSign: false;
}

export interface RuntimeSnapshotV1 {
  readonly schemaVersion: 1;
  readonly auditHead: Readonly<{
    readonly hash: string;
    readonly sequence: number;
  }>;
  readonly capabilities: Readonly<RuntimeCapabilitiesV1>;
  readonly mode: RuntimeMode;
  readonly modeChangedAt: string;
  readonly processInstanceId: string;
  readonly revision: number;
}

export interface RuntimeBoundaryReceipt {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly authorizationId: string;
  readonly boundary: RuntimeBoundary;
  readonly checkedAt: string;
  readonly decision: "allowed" | "denied";
  readonly eventHash: string;
  readonly eventSequence: number;
  readonly mode: RuntimeMode;
  readonly modeRevision: number;
  readonly processInstanceId: string;
  readonly reason: RuntimeBoundaryDecisionReason;
}

/**
 * Current authority facts sampled while the runtime write lock is held for a
 * network completion checkpoint. This intentionally carries no external
 * content and is not itself a new authority grant.
 */
export interface RuntimeBoundaryCompletionFacts {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly authorizationId: string;
  readonly boundary: "research_collection";
  readonly checkedAt: string;
  readonly decision: "allowed" | "denied";
  readonly mode: RuntimeMode;
  readonly modeRevision: number;
  readonly processInstanceId: string;
  readonly reason: RuntimeBoundaryDecisionReason;
}

interface RuntimeBoundaryAuthorizationBase<TBoundary extends RuntimeBoundary> {
  readonly kind: "rsi.runtime-boundary.v1";
  readonly actionId: string;
  readonly authorizationId: string;
  readonly boundary: TBoundary;
  readonly expiresAt: string;
  readonly processInstanceId: string;
  readonly requestedAt: string;
  readonly requestedMode: RuntimeMode;
  readonly requestedRevision: number;
}

export type RuntimeBoundaryDispatch = (receipt: Readonly<RuntimeBoundaryReceipt>) => void;
export type RuntimeBoundaryCompletion = (facts: Readonly<RuntimeBoundaryCompletionFacts>) => void;

type RuntimeBoundaryAuthorizationMethods<TBoundary extends RuntimeBoundary> =
  TBoundary extends "research_collection"
    ? Readonly<{
        consumeAndDispatch(dispatch: RuntimeBoundaryDispatch): Readonly<RuntimeBoundaryReceipt>;
        guardCompletion(
          completion: RuntimeBoundaryCompletion,
        ): Readonly<RuntimeBoundaryCompletionFacts>;
      }>
    : Readonly<{
        consume(): Readonly<RuntimeBoundaryReceipt>;
      }>;

/**
 * Network collection authority can only be consumed around a synchronous
 * dispatch invocation. Non-network boundaries retain the ordinary one-shot
 * consume method.
 */
export type RuntimeBoundaryAuthorization<TBoundary extends RuntimeBoundary = RuntimeBoundary> =
  TBoundary extends RuntimeBoundary
    ? RuntimeBoundaryAuthorizationBase<TBoundary> & RuntimeBoundaryAuthorizationMethods<TBoundary>
    : never;

interface RuntimeAuditEventBase {
  readonly aggregateId: "runtime:authority";
  readonly eventHash: string;
  readonly eventId: string;
  readonly occurredAt: string;
  readonly previousHash: string;
  readonly sequence: number;
}

/** Closed runtime-only audit data. No external content field can be represented. */
export type RuntimeAuditEvent =
  | (RuntimeAuditEventBase &
      Readonly<{
        idempotencyKey: `runtime-stop-v1:${string}`;
        payload: Readonly<RuntimeStopEventPayload>;
        type: "runtime.stop.enforced.v1";
      }>)
  | (RuntimeAuditEventBase &
      Readonly<{
        idempotencyKey: `runtime-transition-v1:${string}`;
        payload: Readonly<RuntimeTransitionEventPayload>;
        type: "runtime.mode.transitioned.v1";
      }>)
  | (RuntimeAuditEventBase &
      Readonly<{
        idempotencyKey: `runtime-boundary-v1:${string}`;
        payload: Readonly<RuntimeBoundaryEventPayload>;
        type: "runtime.boundary.checked.v1";
      }>);
