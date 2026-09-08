import { types as utilTypes } from "node:util";

import { SqliteCaptureRegistry, isSqliteCaptureRegistry } from "@rsi/capture-registry";
import {
  recoverBaseRpcAnchor,
  type BaseRpcAnchorIngestionResult,
} from "@rsi/ingestion/base-rpc-anchor-recovery";
import { recoverCaptureStorage } from "@rsi/ingestion/capture-storage-recovery";
import {
  CAPTURE_RECORDED_EVENT_TYPE,
  OperationsConflictError,
  SqliteOperationsStore,
  isSqliteOperationsStore,
  parseCaptureRecordedEventPayload,
  type AttemptOutcome,
  type DurableNetworkAttemptBinding,
} from "@rsi/operations";
import {
  SqliteRuntimeController,
  isSqliteRuntimeController,
  type RuntimeBoundaryAuthorization,
  type RuntimeAuditEvent,
} from "@rsi/runtime";
import { SqliteEventStore, isSqliteEventStore, type JsonValue, type StoredEvent } from "@rsi/store";
import { SnapshotVault, isSnapshotVault } from "@rsi/vault";

import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS,
  BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS,
  BASE_RPC_READ_CANARY_OPERATION,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_PROVIDER_ID,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  BASE_RPC_READ_CANARY_RPC_METHODS,
  baseRpcReadCanaryRuntimeActionId,
} from "./base-rpc-constants.js";
import {
  BaseRpcReadCanaryConflictError,
  BaseRpcReadCanaryValidationError,
} from "./base-rpc-errors.js";
import {
  BaseRpcReadCanaryDurableReceiptSchema,
  BaseRpcReadCanaryFailureEventPayloadSchema,
  BaseRpcReadCanaryPlanSchema,
  BaseRpcReadCanaryPreparedEventPayloadSchema,
  BaseRpcReadCanaryProjectionSchema,
  BaseRpcReadCanaryReceiptSchema,
  BaseRpcReadCanaryResultEventPayloadSchema,
  parseBaseRpcReadCanaryInput,
} from "./base-rpc-schemas.js";
import type {
  BaseRpcReadCanaryDurableReceiptV1,
  BaseRpcReadCanaryFailureCode,
  BaseRpcReadCanaryFailureEventPayloadV1,
  BaseRpcReadCanaryPlanV1,
  BaseRpcReadCanaryProjectionV1,
  BaseRpcReadCanaryReceiptV1,
  BaseRpcReadCanaryResultEventPayloadV1,
} from "./base-rpc-types.js";

export const PREPARED_EVENT_TYPE = "base-rpc.read-canary.prepared.v1" as const;
const RESULT_EVENT_TYPE = "base-rpc.read-canary.result.v1" as const;
const FAILURE_EVENT_TYPE = "base-rpc.read-canary.failure.v1" as const;
const RECEIPT_EVENT_TYPE = "base-rpc.read-canary.receipt.v1" as const;
export const AGGREGATE_ID = "read-canary:base-rpc" as const;
type CredentialStatus = BaseRpcReadCanaryProjectionV1["credentialStatus"];
export type PreparedPayload = ReturnType<typeof BaseRpcReadCanaryPreparedEventPayloadSchema.parse>;

export interface BaseRpcReadCanaryRecoveryOptions {
  readonly runtime: SqliteRuntimeController;
  readonly operationsStore: SqliteOperationsStore;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly eventStore: SqliteEventStore;
  readonly vault: SnapshotVault;
}

export const PREPARED_KEY = "base-rpc-read-canary-prepared-v1:singleton" as const;

export function receiptKey(requestId: string): string {
  return `base-rpc-read-canary-receipt-v1:${requestId}`;
}

function resultKey(requestId: string): string {
  return `base-rpc-read-canary-result-v1:${requestId}`;
}

function failureKey(requestId: string): string {
  return `base-rpc-read-canary-failure-v1:${requestId}`;
}

export function jsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

export function now(): string {
  return new Date().toISOString();
}

function exactRecoveryOptions(
  value: BaseRpcReadCanaryRecoveryOptions,
): BaseRpcReadCanaryRecoveryOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new BaseRpcReadCanaryValidationError("Base RPC read canary recovery options are invalid");
  }
  const expected = ["runtime", "operationsStore", "captureRegistry", "eventStore", "vault"];
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new BaseRpcReadCanaryValidationError("Base RPC read canary recovery options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new BaseRpcReadCanaryValidationError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new BaseRpcReadCanaryValidationError(
        "Base RPC read canary recovery options are invalid",
      );
    }
  }
  if (
    !isSqliteRuntimeController(value.runtime) ||
    !isSqliteOperationsStore(value.operationsStore) ||
    !isSqliteCaptureRegistry(value.captureRegistry) ||
    !isSqliteEventStore(value.eventStore) ||
    !isSnapshotVault(value.vault)
  ) {
    throw new BaseRpcReadCanaryValidationError(
      "Authentic canary recovery dependencies are required",
    );
  }
  return value;
}

const parsedPlan = BaseRpcReadCanaryPlanSchema.parse({
  schemaVersion: 1,
  planId: BASE_RPC_READ_CANARY_PLAN_ID,
  profile: "canary",
  method: "POST",
  chain: "base-mainnet",
  blockTag: "finalized",
  rpcMethods: [...BASE_RPC_READ_CANARY_RPC_METHODS],
  maximumRequests: BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS,
  maximumAnchors: BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS,
  ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  actualChargeUsdMicros: null,
  requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  rawContentDisposition: "encrypted_ephemeral",
  automaticRetries: 0,
  automaticFallback: false,
  paymentAuthority: "none",
  transactionAuthority: "none",
});
Object.freeze(parsedPlan.rpcMethods);
const PLAN: Readonly<BaseRpcReadCanaryPlanV1> = Object.freeze(parsedPlan);

export function getBaseRpcReadCanaryPlan(): Readonly<BaseRpcReadCanaryPlanV1> {
  return PLAN;
}

export function parsePreparedEvent(event: StoredEvent): PreparedPayload {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== PREPARED_EVENT_TYPE ||
    event.idempotencyKey !== PREPARED_KEY
  ) {
    throw new BaseRpcReadCanaryConflictError("Prepared canary event is invalid");
  }
  return parseBaseRpcReadCanaryInput(
    BaseRpcReadCanaryPreparedEventPayloadSchema,
    event.payload,
    "Prepared canary event",
  );
}

function parseReceiptEvent(event: StoredEvent): Readonly<BaseRpcReadCanaryDurableReceiptV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== RECEIPT_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary receipt event is invalid");
  }
  const receipt = Object.freeze(
    parseBaseRpcReadCanaryInput(
      BaseRpcReadCanaryDurableReceiptSchema,
      event.payload,
      "Canary receipt event",
    ),
  );
  if (event.idempotencyKey !== receiptKey(receipt.requestId)) {
    throw new BaseRpcReadCanaryConflictError("Canary receipt event key is invalid");
  }
  return receipt;
}

function parseResultEvent(event: StoredEvent): Readonly<BaseRpcReadCanaryResultEventPayloadV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== RESULT_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary result event is invalid");
  }
  const result = Object.freeze(
    parseBaseRpcReadCanaryInput(
      BaseRpcReadCanaryResultEventPayloadSchema,
      event.payload,
      "Canary result event",
    ),
  );
  if (event.idempotencyKey !== resultKey(result.requestId)) {
    throw new BaseRpcReadCanaryConflictError("Canary result event key is invalid");
  }
  return result;
}

function parseFailureEvent(event: StoredEvent): Readonly<BaseRpcReadCanaryFailureEventPayloadV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== FAILURE_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary failure event is invalid");
  }
  const failure = Object.freeze(
    parseBaseRpcReadCanaryInput(
      BaseRpcReadCanaryFailureEventPayloadSchema,
      event.payload,
      "Canary failure event",
    ),
  );
  if (event.idempotencyKey !== failureKey(failure.requestId)) {
    throw new BaseRpcReadCanaryConflictError("Canary failure event key is invalid");
  }
  return failure;
}

function runtimeReceipt(
  runtime: SqliteRuntimeController,
  authorizationId: string,
): BaseRpcReadCanaryDurableReceiptV1["runtime"] {
  const matching = runtime
    .listAudit()
    .filter(
      (
        event,
      ): event is Extract<RuntimeAuditEvent, { readonly type: "runtime.boundary.checked.v1" }> =>
        event.type === "runtime.boundary.checked.v1" &&
        event.payload.authorizationId === authorizationId,
    );
  if (matching.length === 0) return null;
  if (matching.length !== 1)
    throw new BaseRpcReadCanaryConflictError("Runtime receipt is ambiguous");
  const event = matching[0]!;
  if (
    event.payload.boundary !== "research_collection" ||
    event.payload.decision !== "allowed" ||
    event.payload.reason !== "ALLOWED" ||
    event.payload.requestedMode !== "RESEARCH" ||
    event.payload.checkedMode !== "RESEARCH"
  ) {
    return null;
  }
  return Object.freeze({
    authorizationId,
    eventHash: event.eventHash,
    eventSequence: event.sequence,
    modeRevision: event.payload.checkedRevision,
  });
}

function captureReceipt(
  store: SqliteEventStore,
  attemptId: string,
): NonNullable<BaseRpcReadCanaryDurableReceiptV1["capture"]> {
  const event = store.getByIdempotencyKey(`capture-recorded-v2:${attemptId}`);
  if (event === undefined || event.type !== CAPTURE_RECORDED_EVENT_TYPE) {
    throw new BaseRpcReadCanaryConflictError("Capture event receipt is unavailable");
  }
  return Object.freeze({ eventHash: event.eventHash, eventSequence: event.sequence });
}

function appendResult(
  store: SqliteEventStore,
  resultValue: BaseRpcReadCanaryResultEventPayloadV1,
): Readonly<BaseRpcReadCanaryResultEventPayloadV1> {
  const result = BaseRpcReadCanaryResultEventPayloadSchema.parse(resultValue);
  const event = store.append({
    aggregateId: AGGREGATE_ID,
    idempotencyKey: resultKey(result.requestId),
    occurredAt: result.completedAt,
    payload: jsonValue(result),
    type: RESULT_EVENT_TYPE,
  });
  return parseResultEvent(event);
}

function appendFailure(
  store: SqliteEventStore,
  failureValue: BaseRpcReadCanaryFailureEventPayloadV1,
): Readonly<BaseRpcReadCanaryFailureEventPayloadV1> {
  const failure = BaseRpcReadCanaryFailureEventPayloadSchema.parse(failureValue);
  try {
    const event = store.append({
      aggregateId: AGGREGATE_ID,
      idempotencyKey: failureKey(failure.requestId),
      occurredAt: failure.completedAt,
      payload: jsonValue(failure),
      type: FAILURE_EVENT_TYPE,
    });
    return parseFailureEvent(event);
  } catch (error) {
    const winner = store.getByIdempotencyKey(failureKey(failure.requestId));
    if (winner !== undefined) {
      const existing = parseFailureEvent(winner);
      if (JSON.stringify(existing) === JSON.stringify(failure)) return existing;
    }
    throw error;
  }
}

function completionTime(...lowerBounds: readonly string[]): string {
  return lowerBounds.reduce(
    (latest, candidate) => (Date.parse(candidate) > Date.parse(latest) ? candidate : latest),
    now(),
  );
}

function appendReceipt(
  store: SqliteEventStore,
  receiptValue: BaseRpcReadCanaryDurableReceiptV1,
): Readonly<BaseRpcReadCanaryDurableReceiptV1> {
  const receipt = BaseRpcReadCanaryDurableReceiptSchema.parse(receiptValue);
  try {
    const event = store.append({
      aggregateId: AGGREGATE_ID,
      idempotencyKey: receiptKey(receipt.requestId),
      occurredAt: receipt.completedAt,
      payload: jsonValue(receipt),
      type: RECEIPT_EVENT_TYPE,
    });
    return parseReceiptEvent(event);
  } catch (error) {
    const winner = store.getByIdempotencyKey(receiptKey(receipt.requestId));
    if (winner !== undefined) {
      const existing = parseReceiptEvent(winner);
      if (JSON.stringify(existing) === JSON.stringify(receipt)) return existing;
    }
    throw error;
  }
}

export function projectPublicReceipt(
  receipt: Readonly<BaseRpcReadCanaryDurableReceiptV1>,
): Readonly<BaseRpcReadCanaryReceiptV1> {
  const projected = BaseRpcReadCanaryReceiptSchema.parse({
    schemaVersion: 1,
    planId: receipt.planId,
    requestFingerprint: receipt.requestFingerprint,
    rpcMethods: [...BASE_RPC_READ_CANARY_RPC_METHODS],
    outcome: receipt.outcome,
    failureCode: receipt.failureCode,
    completedAt: receipt.completedAt,
    providerReportedFinalized: receipt.providerReportedFinalized,
    freshnessVerdict: receipt.freshnessVerdict,
    maximumRequests: receipt.maximumRequests,
    ledgerReserveUsdMicros: receipt.ledgerReserveUsdMicros,
    actualChargeUsdMicros: receipt.actualChargeUsdMicros,
  });
  Object.freeze(projected.rpcMethods);
  return Object.freeze(projected);
}

function assertOperationsAttemptBinding(
  binding: Readonly<DurableNetworkAttemptBinding>,
  prepared: PreparedPayload,
): void {
  if (
    binding.attemptId !== prepared.attemptId ||
    binding.authorizationExpiresAt !== prepared.expiresAt ||
    binding.budgetId !== prepared.budgetId ||
    binding.createdAt !== prepared.preparedAt ||
    binding.idempotencyKey !== `base-rpc-read-canary:${prepared.requestId}` ||
    binding.lane !== "contract" ||
    binding.operation !== BASE_RPC_READ_CANARY_OPERATION ||
    binding.profile !== "canary" ||
    binding.reservedAtomic !== BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO ||
    binding.sessionId !== prepared.requestId ||
    binding.sourcePlane !== "canonical_chain"
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary network attempt binding is rebound");
  }
}

function assertFailureCheckpointBinding(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failure: Readonly<BaseRpcReadCanaryFailureEventPayloadV1>,
): void {
  if (
    failure.requestId !== prepared.requestId ||
    failure.attemptId !== prepared.attemptId ||
    failure.requestFingerprint !== prepared.requestFingerprint
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary failure checkpoint is rebound");
  }
  let binding: Readonly<DurableNetworkAttemptBinding> | null;
  try {
    binding = dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  } catch (error) {
    if (error instanceof OperationsConflictError && error.code === "ATTEMPT_CONFLICT") {
      binding = null;
    } else {
      throw error;
    }
  }
  if (binding === null) {
    if (failure.attemptOutcome !== null || failure.completedAt !== prepared.preparedAt) {
      throw new BaseRpcReadCanaryConflictError(
        "No-binding failure checkpoint has invalid closure facts",
      );
    }
  } else {
    assertOperationsAttemptBinding(binding, prepared);
    const expectedCompletedAt =
      failure.attemptOutcome === "aborted" ? prepared.preparedAt : binding.dispatchedAt;
    if (
      failure.attemptOutcome === null ||
      expectedCompletedAt === null ||
      failure.completedAt !== expectedCompletedAt ||
      (binding.state === "reserved" && failure.attemptOutcome !== "aborted") ||
      (binding.state === "dispatched" && failure.attemptOutcome !== "failed") ||
      (binding.state === "closed" &&
        (binding.closedAt !== failure.completedAt || binding.outcome !== failure.attemptOutcome))
    ) {
      throw new BaseRpcReadCanaryConflictError("Canary failure closure evidence disagrees");
    }
  }
  const expectedRuntime = runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId);
  if (JSON.stringify(failure.runtime) !== JSON.stringify(expectedRuntime)) {
    throw new BaseRpcReadCanaryConflictError("Canary failure runtime evidence disagrees");
  }
  if (failure.runtime !== null) {
    assertRuntimeEvidence(dependencies.runtime, prepared, failure.runtime);
  }
  if (
    dependencies.eventStore.getByIdempotencyKey(resultKey(prepared.requestId)) !== undefined ||
    dependencies.eventStore.getByIdempotencyKey(`capture-recorded-v2:${prepared.attemptId}`) !==
      undefined ||
    dependencies.captureRegistry.getAttempt(prepared.attemptId)?.state === "committed"
  ) {
    throw new BaseRpcReadCanaryConflictError(
      "Canary failure checkpoint conflicts with captured result evidence",
    );
  }
}

function removePendingCaptureAfterFailure(
  captureRegistry: SqliteCaptureRegistry,
  attemptId: string,
  removedAt?: string,
): void {
  const attempt = captureRegistry.getAttempt(attemptId);
  if (attempt?.state !== "pending") return;
  const exactRemovedAt =
    removedAt === undefined || Date.parse(removedAt) < Date.parse(attempt.acquiredAt)
      ? attempt.acquiredAt
      : removedAt;
  captureRegistry.removePendingAttempt({
    attemptId,
    removedAt: exactRemovedAt,
  });
}

function assertRuntimeEvidence(
  runtime: SqliteRuntimeController,
  prepared: PreparedPayload,
  receipt: NonNullable<BaseRpcReadCanaryDurableReceiptV1["runtime"]>,
): void {
  const matching = runtime
    .listAudit()
    .filter(
      (
        event,
      ): event is Extract<RuntimeAuditEvent, { readonly type: "runtime.boundary.checked.v1" }> =>
        event.type === "runtime.boundary.checked.v1" &&
        event.payload.authorizationId === prepared.runtimeAuthorizationId,
    );
  if (matching.length !== 1) {
    throw new BaseRpcReadCanaryConflictError("Runtime authorization evidence is ambiguous");
  }
  const event = matching[0]!;
  const expectedActionId = baseRpcReadCanaryRuntimeActionId(prepared.attemptId);
  if (
    receipt.authorizationId !== prepared.runtimeAuthorizationId ||
    receipt.eventHash !== event.eventHash ||
    receipt.eventSequence !== event.sequence ||
    receipt.modeRevision !== event.payload.checkedRevision ||
    event.idempotencyKey !== `runtime-boundary-v1:${prepared.runtimeAuthorizationId}` ||
    event.payload.actionId !== expectedActionId ||
    event.payload.boundary !== "research_collection" ||
    event.payload.decision !== "allowed" ||
    event.payload.reason !== "ALLOWED" ||
    event.payload.requestedAt !== prepared.preparedAt ||
    event.payload.expiresAt !== prepared.expiresAt ||
    event.payload.requestedMode !== "RESEARCH" ||
    event.payload.checkedMode !== "RESEARCH" ||
    event.payload.requestedProcessInstanceId !== prepared.runtimeProcessInstanceId ||
    event.payload.checkedProcessInstanceId !== prepared.runtimeProcessInstanceId ||
    event.payload.requestedRevision !== prepared.expectedRuntimeRevision ||
    event.payload.checkedRevision !== prepared.expectedRuntimeRevision ||
    Date.parse(event.occurredAt) < Date.parse(prepared.preparedAt)
  ) {
    throw new BaseRpcReadCanaryConflictError("Runtime authorization evidence is rebound");
  }
}

function assertCaptureEvidence(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<BaseRpcReadCanaryResultEventPayloadV1>,
): void {
  const event = dependencies.eventStore.getByIdempotencyKey(
    `capture-recorded-v2:${prepared.attemptId}`,
  );
  if (
    event === undefined ||
    event.aggregateId !== `session:${prepared.requestId}` ||
    event.type !== CAPTURE_RECORDED_EVENT_TYPE ||
    event.eventHash !== result.capture.eventHash ||
    event.sequence !== result.capture.eventSequence
  ) {
    throw new BaseRpcReadCanaryConflictError("Capture event evidence is unavailable");
  }
  const { capture } = parseCaptureRecordedEventPayload(event.payload);
  if (
    capture.attemptId !== prepared.attemptId ||
    capture.sessionId !== prepared.requestId ||
    capture.expiresAt !== prepared.expiresAt ||
    capture.lane !== "contract" ||
    capture.profile !== "canary" ||
    capture.sourcePlane !== "canonical_chain" ||
    capture.rawDisposition !== "encrypted_ephemeral" ||
    capture.acquiredAt !== result.acquiredAt ||
    capture.byteLength !== result.byteLength ||
    event.occurredAt !== result.acquiredAt
  ) {
    throw new BaseRpcReadCanaryConflictError("Capture event evidence is rebound");
  }
  const captureIsAccepted =
    capture.status === "accepted" &&
    capture.failureCode === null &&
    capture.counts?.actorCount === 0 &&
    capture.counts.editedRecordCount === 0 &&
    capture.counts.recordCount === 1;
  const captureIsRejected =
    capture.status === "rejected" &&
    capture.failureCode === "INVALID_RESPONSE_SCHEMA" &&
    capture.counts === null;
  if (!captureIsAccepted && !captureIsRejected) {
    throw new BaseRpcReadCanaryConflictError("Capture projection evidence is invalid");
  }
  if (
    result.failureCode !== "RUNTIME_DENIED" &&
    (result.outcome === "accepted"
      ? capture.status !== "accepted" ||
        capture.failureCode !== null ||
        capture.counts?.recordCount !== result.anchorCount
      : capture.status !== "rejected" || capture.failureCode !== result.failureCode)
  ) {
    throw new BaseRpcReadCanaryConflictError("Capture projection evidence disagrees");
  }

  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state === "committed") {
    if (
      attempt.requestFingerprint !== prepared.requestFingerprint ||
      attempt.sessionId !== prepared.requestId ||
      attempt.expiresAt !== prepared.expiresAt ||
      attempt.lane !== "contract" ||
      attempt.profile !== "canary" ||
      attempt.source !== "alchemy" ||
      attempt.sourceIdentifiers.source !== "alchemy" ||
      Date.parse(result.completedAt) < Date.parse(attempt.committedAt) ||
      (capture.status === "accepted" &&
        (capture.counts?.recordCount !== attempt.sourceIdentifiers.identifiers.length ||
          attempt.sourceIdentifiers.identifiers.some(
            (identifier) => identifier.kind !== "block_number",
          ))) ||
      (capture.status === "rejected" && attempt.sourceIdentifiers.identifiers.length !== 0)
    ) {
      throw new BaseRpcReadCanaryConflictError("Capture registry evidence disagrees");
    }
    return;
  }
  if (
    attempt?.state !== "removed" ||
    !attempt.keyDestroyed ||
    Date.parse(attempt.removedAt) < Date.parse(result.completedAt) ||
    (attempt.removalReason !== "capture_deleted_explicit" &&
      attempt.removalReason !== "capture_deleted_expired")
  ) {
    throw new BaseRpcReadCanaryConflictError("Capture registry evidence is unavailable");
  }
}

function assertResultBinding(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<BaseRpcReadCanaryResultEventPayloadV1>,
): void {
  if (
    result.requestId !== prepared.requestId ||
    result.attemptId !== prepared.attemptId ||
    result.requestFingerprint !== prepared.requestFingerprint
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary result is rebound");
  }
  assertOperationsAttemptBinding(
    dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
  assertRuntimeEvidence(dependencies.runtime, prepared, result.runtime);
  assertCaptureEvidence(dependencies, prepared, result);
}

function resultAttemptOutcome(result: BaseRpcReadCanaryResultEventPayloadV1): AttemptOutcome {
  return result.outcome === "accepted" ? "succeeded" : "failed";
}

function closeAttemptForResult(
  operationsStore: SqliteOperationsStore,
  prepared: PreparedPayload,
  result: Readonly<BaseRpcReadCanaryResultEventPayloadV1>,
): void {
  const expected = Object.freeze({
    closedAt: result.completedAt,
    outcome: resultAttemptOutcome(result),
  });
  const binding = operationsStore.readNetworkAttemptBinding(result.attemptId);
  assertOperationsAttemptBinding(binding, prepared);
  if (
    binding.dispatchedAt === null ||
    Date.parse(binding.dispatchedAt) > Date.parse(result.acquiredAt) ||
    Date.parse(binding.dispatchedAt) > Date.parse(result.completedAt)
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary result predates its network dispatch");
  }
  if (binding.state === "closed") {
    if (binding.closedAt !== expected.closedAt || binding.outcome !== expected.outcome) {
      throw new BaseRpcReadCanaryConflictError(
        "Canary network attempt closed with different facts",
      );
    }
    operationsStore.closeAttempt(result.attemptId, expected);
    const closed = operationsStore.readNetworkAttemptBinding(result.attemptId);
    assertOperationsAttemptBinding(closed, prepared);
    if (
      closed.state !== "closed" ||
      closed.closedAt !== expected.closedAt ||
      closed.outcome !== expected.outcome
    ) {
      throw new BaseRpcReadCanaryConflictError(
        "Canary network attempt closure was not authenticated",
      );
    }
    return;
  }
  if (binding.state !== "dispatched") {
    throw new BaseRpcReadCanaryConflictError("Projected canary request was not dispatched");
  }
  operationsStore.closeAttempt(result.attemptId, expected);
  const closed = operationsStore.readNetworkAttemptBinding(result.attemptId);
  assertOperationsAttemptBinding(closed, prepared);
  if (
    closed.state !== "closed" ||
    closed.closedAt !== expected.closedAt ||
    closed.outcome !== expected.outcome
  ) {
    throw new BaseRpcReadCanaryConflictError(
      "Canary network attempt closure was not authenticated",
    );
  }
}

async function destroyResultCapture(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  result: Readonly<BaseRpcReadCanaryResultEventPayloadV1>,
): Promise<void> {
  const attempt = dependencies.captureRegistry.getAttempt(result.attemptId);
  if (attempt?.state === "removed") {
    if (
      !attempt.keyDestroyed ||
      (attempt.removalReason !== "capture_deleted_explicit" &&
        attempt.removalReason !== "capture_deleted_expired")
    ) {
      throw new BaseRpcReadCanaryConflictError("Canary capture has an invalid terminal state");
    }
    return;
  }
  if (attempt?.state !== "committed") {
    throw new BaseRpcReadCanaryConflictError("Committed canary capture is unavailable");
  }
  const deletionReceipt = await dependencies.vault.delete(attempt.captureId, {
    deletedAt: result.completedAt,
    reason: "explicit",
  });
  dependencies.captureRegistry.recordVerifiedDeletion({
    attemptId: result.attemptId,
    deletionReceipt,
  });
  const removed = dependencies.captureRegistry.getAttempt(result.attemptId);
  if (removed?.state !== "removed" || !removed.keyDestroyed) {
    throw new BaseRpcReadCanaryConflictError("Canary capture deletion was not authenticated");
  }
}

function receiptFromResult(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<BaseRpcReadCanaryResultEventPayloadV1>,
): BaseRpcReadCanaryDurableReceiptV1 {
  assertResultBinding(dependencies, prepared, result);
  return {
    schemaVersion: 1,
    receiptId: `base-rpc-read-canary:${prepared.requestId}`,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    providerId: BASE_RPC_READ_CANARY_PROVIDER_ID,
    requestId: prepared.requestId,
    requestFingerprint: prepared.requestFingerprint,
    outcome: result.outcome,
    failureCode: result.failureCode,
    acquiredAt: result.acquiredAt,
    completedAt: result.completedAt,
    anchorCount: result.anchorCount,
    byteLength: result.byteLength,
    providerReportedFinalized: result.providerReportedFinalized,
    freshnessVerdict: result.freshnessVerdict,
    maximumRequests: 1,
    maximumAnchors: 1,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: result.runtime,
    capture: result.capture,
  };
}

export async function finalizeResult(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<BaseRpcReadCanaryResultEventPayloadV1>,
): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
  if (dependencies.eventStore.getByIdempotencyKey(failureKey(prepared.requestId)) !== undefined) {
    throw new BaseRpcReadCanaryConflictError(
      "Captured result conflicts with durable failure evidence",
    );
  }
  assertResultBinding(dependencies, prepared, result);
  closeAttemptForResult(dependencies.operationsStore, prepared, result);
  await destroyResultCapture(dependencies, result);
  return appendReceipt(dependencies.eventStore, receiptFromResult(dependencies, prepared, result));
}

export function loadResult(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Readonly<BaseRpcReadCanaryResultEventPayloadV1> | null {
  const event = dependencies.eventStore.getByIdempotencyKey(resultKey(prepared.requestId));
  if (event === undefined) return null;
  const result = parseResultEvent(event);
  assertResultBinding(dependencies, prepared, result);
  return result;
}

function loadFailure(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Readonly<BaseRpcReadCanaryFailureEventPayloadV1> | null {
  const event = dependencies.eventStore.getByIdempotencyKey(failureKey(prepared.requestId));
  if (event === undefined) return null;
  const failure = parseFailureEvent(event);
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  return failure;
}

function resultCandidate(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<BaseRpcAnchorIngestionResult>,
  runtimeDenied: boolean,
): BaseRpcReadCanaryResultEventPayloadV1 {
  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state !== "committed") {
    throw new BaseRpcReadCanaryConflictError("Committed capture is unavailable");
  }
  assertOperationsAttemptBinding(
    dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
  const runtime = runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId);
  if (runtime === null) throw new BaseRpcReadCanaryConflictError("Runtime receipt is unavailable");
  const outcome = runtimeDenied
    ? ("rejected" as const)
    : ingestion.status === "rejected"
      ? ("rejected" as const)
      : ("accepted" as const);
  return BaseRpcReadCanaryResultEventPayloadSchema.parse({
    schemaVersion: 1,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    outcome,
    failureCode: runtimeDenied
      ? "RUNTIME_DENIED"
      : ingestion.status === "rejected"
        ? (ingestion.failureCode as BaseRpcReadCanaryFailureCode)
        : null,
    acquiredAt: ingestion.acquiredAt,
    completedAt: completionTime(ingestion.acquiredAt, attempt.committedAt),
    anchorCount: !runtimeDenied && ingestion.status === "accepted" ? ingestion.anchorCount : null,
    byteLength: ingestion.byteLength,
    providerReportedFinalized:
      !runtimeDenied && ingestion.status === "accepted"
        ? ingestion.providerReportedFinalized
        : null,
    freshnessVerdict: !runtimeDenied && ingestion.status === "accepted" ? "fresh" : null,
    runtime,
    capture: captureReceipt(dependencies.eventStore, prepared.attemptId),
  });
}

function persistRecoveryResult(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<BaseRpcAnchorIngestionResult>,
): Readonly<BaseRpcReadCanaryResultEventPayloadV1> {
  const existing = loadResult(dependencies, prepared);
  if (existing !== null) return existing;
  const candidate = resultCandidate(dependencies, prepared, ingestion, true);
  try {
    const persisted = appendResult(dependencies.eventStore, candidate);
    assertResultBinding(dependencies, prepared, persisted);
    return persisted;
  } catch (error) {
    const winner = loadResult(dependencies, prepared);
    if (winner !== null) return winner;
    throw error;
  }
}

export function persistLiveResult(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<BaseRpcAnchorIngestionResult>,
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">,
): Readonly<BaseRpcReadCanaryResultEventPayloadV1> {
  const candidate = resultCandidate(dependencies, prepared, ingestion, false);
  let persisted: Readonly<BaseRpcReadCanaryResultEventPayloadV1> | undefined;
  const completion = runtimeAuthorization.guardCompletion(() => {
    persisted = appendResult(dependencies.eventStore, candidate);
  });
  if (completion.decision !== "allowed" || persisted === undefined) {
    return persistRecoveryResult(dependencies, prepared, ingestion);
  }
  assertResultBinding(dependencies, prepared, persisted);
  return persisted;
}

function failureCandidate(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failureCode: BaseRpcReadCanaryFailureCode,
): BaseRpcReadCanaryFailureEventPayloadV1 {
  let binding: Readonly<DurableNetworkAttemptBinding> | null;
  try {
    binding = dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  } catch (bindingError) {
    if (
      bindingError instanceof OperationsConflictError &&
      bindingError.code === "ATTEMPT_CONFLICT"
    ) {
      binding = null;
    } else {
      throw bindingError;
    }
  }
  if (binding !== null) assertOperationsAttemptBinding(binding, prepared);
  const attemptOutcome =
    binding === null
      ? null
      : binding.state === "closed"
        ? binding.outcome
        : binding.state === "reserved"
          ? ("aborted" as const)
          : ("failed" as const);
  if (attemptOutcome !== null && attemptOutcome !== "aborted" && attemptOutcome !== "failed") {
    throw new BaseRpcReadCanaryConflictError(
      "Successful attempt cannot become a failure checkpoint",
    );
  }
  const completedAt =
    binding === null
      ? prepared.preparedAt
      : binding.state === "closed"
        ? binding.closedAt
        : attemptOutcome === "aborted"
          ? prepared.preparedAt
          : binding.dispatchedAt;
  if (completedAt === null) {
    throw new BaseRpcReadCanaryConflictError("Failure checkpoint time is unavailable");
  }
  return BaseRpcReadCanaryFailureEventPayloadSchema.parse({
    schemaVersion: 1,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    failureCode,
    completedAt,
    attemptOutcome,
    runtime: runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId),
  });
}

function persistFailureCheckpoint(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failureCode: BaseRpcReadCanaryFailureCode,
): Readonly<BaseRpcReadCanaryFailureEventPayloadV1> {
  const existing = loadFailure(dependencies, prepared);
  if (existing !== null) return existing;
  const candidate = failureCandidate(dependencies, prepared, failureCode);
  try {
    const persisted = appendFailure(dependencies.eventStore, candidate);
    assertFailureCheckpointBinding(dependencies, prepared, persisted);
    return persisted;
  } catch (failureError) {
    const winner = loadFailure(dependencies, prepared);
    if (winner !== null) return winner;
    throw failureError;
  }
}

function failedReceiptFromCheckpoint(
  prepared: PreparedPayload,
  failure: Readonly<BaseRpcReadCanaryFailureEventPayloadV1>,
): BaseRpcReadCanaryDurableReceiptV1 {
  return {
    schemaVersion: 1,
    receiptId: `base-rpc-read-canary:${prepared.requestId}`,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    providerId: BASE_RPC_READ_CANARY_PROVIDER_ID,
    requestId: prepared.requestId,
    requestFingerprint: prepared.requestFingerprint,
    outcome: "failed",
    failureCode: failure.failureCode,
    acquiredAt: null,
    completedAt: failure.completedAt,
    anchorCount: null,
    byteLength: null,
    providerReportedFinalized: null,
    freshnessVerdict: null,
    maximumRequests: 1,
    maximumAnchors: 1,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: failure.runtime,
    capture: null,
  };
}

function closeAttemptForFailure(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failure: Readonly<BaseRpcReadCanaryFailureEventPayloadV1>,
): void {
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  if (failure.attemptOutcome === null) return;
  const binding = dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  if (binding.state !== "closed") {
    dependencies.operationsStore.closeAttempt(prepared.attemptId, {
      closedAt: failure.completedAt,
      outcome: failure.attemptOutcome,
    });
  }
  const closed = dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  assertOperationsAttemptBinding(closed, prepared);
  if (
    closed.state !== "closed" ||
    closed.closedAt !== failure.completedAt ||
    closed.outcome !== failure.attemptOutcome
  ) {
    throw new BaseRpcReadCanaryConflictError("Failure closure could not be authenticated");
  }
}

async function finalizeFailureCheckpoint(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failure: Readonly<BaseRpcReadCanaryFailureEventPayloadV1>,
): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  await recoverCaptureStorage({
    captureRegistry: dependencies.captureRegistry,
    recoveredAt: completionTime(prepared.preparedAt, failure.completedAt),
    vault: dependencies.vault,
  });
  // Re-authenticate after full registry/Vault reconciliation. A recoverable
  // orphan may otherwise outlive a failure receipt when capture succeeded but
  // the registry commit and immediate crypto-shredding both failed.
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  closeAttemptForFailure(dependencies, prepared, failure);
  removePendingCaptureAfterFailure(
    dependencies.captureRegistry,
    prepared.attemptId,
    failure.completedAt,
  );
  const captureAttempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (captureAttempt?.state === "pending" || captureAttempt?.state === "committed") {
    throw new BaseRpcReadCanaryConflictError("Failure checkpoint left active capture state");
  }
  // Re-authenticate after cleanup so a no-binding checkpoint cannot publish if
  // an ambiguous or competing reservation became visible in the meantime.
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  return appendReceipt(dependencies.eventStore, failedReceiptFromCheckpoint(prepared, failure));
}

export async function terminalizeFailure(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failureCode: BaseRpcReadCanaryFailureCode,
): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
  const failure = persistFailureCheckpoint(dependencies, prepared, failureCode);
  return finalizeFailureCheckpoint(dependencies, prepared, failure);
}

function assertFailureReceiptBinding(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  receipt: Readonly<BaseRpcReadCanaryDurableReceiptV1>,
  failure: Readonly<BaseRpcReadCanaryFailureEventPayloadV1>,
): void {
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  const expected = BaseRpcReadCanaryDurableReceiptSchema.parse(
    failedReceiptFromCheckpoint(prepared, failure),
  );
  if (JSON.stringify(receipt) !== JSON.stringify(expected)) {
    throw new BaseRpcReadCanaryConflictError("Failure receipt is rebound");
  }
  const captureAttempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (captureAttempt?.state === "pending" || captureAttempt?.state === "committed") {
    throw new BaseRpcReadCanaryConflictError("Failure receipt left active capture state");
  }
}

export async function recoverPreparedCanary(
  dependencies: Readonly<BaseRpcReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Promise<Readonly<BaseRpcReadCanaryDurableReceiptV1>> {
  const existingReceipt = dependencies.eventStore.getByIdempotencyKey(
    receiptKey(prepared.requestId),
  );
  if (existingReceipt !== undefined) {
    const receipt = parseReceiptEvent(existingReceipt);
    const durableResult = loadResult(dependencies, prepared);
    const durableFailure = loadFailure(dependencies, prepared);
    if (receipt.capture !== null) {
      if (durableResult === null || durableFailure !== null) {
        throw new BaseRpcReadCanaryConflictError("Captured receipt has no durable result evidence");
      }
      return finalizeResult(dependencies, prepared, durableResult);
    }
    if (durableResult !== null || durableFailure === null) {
      throw new BaseRpcReadCanaryConflictError(
        "Failure receipt conflicts with durable checkpoint evidence",
      );
    }
    assertFailureReceiptBinding(dependencies, prepared, receipt, durableFailure);
    return finalizeFailureCheckpoint(dependencies, prepared, durableFailure);
  }
  const durableResult = loadResult(dependencies, prepared);
  const durableFailure = loadFailure(dependencies, prepared);
  if (durableResult !== null && durableFailure !== null) {
    throw new BaseRpcReadCanaryConflictError(
      "Canary has conflicting durable result and failure checkpoints",
    );
  }
  if (durableResult !== null) return finalizeResult(dependencies, prepared, durableResult);
  if (durableFailure !== null) {
    return finalizeFailureCheckpoint(dependencies, prepared, durableFailure);
  }

  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state === "committed") {
    const ingestion = await recoverBaseRpcAnchor(
      {
        captureRegistry: dependencies.captureRegistry,
        operationsStore: dependencies.operationsStore,
        store: dependencies.eventStore,
        vault: dependencies.vault,
      },
      {
        attemptId: prepared.attemptId,
        expiresAt: prepared.expiresAt,
        lane: "contract",
        profile: "canary",
        sessionId: prepared.requestId,
      },
    );
    return finalizeResult(
      dependencies,
      prepared,
      persistRecoveryResult(dependencies, prepared, ingestion),
    );
  }

  return terminalizeFailure(dependencies, prepared, "INTERRUPTED");
}

/**
 * Completes an already-claimed canary exclusively from authenticated local
 * state. This function has no credential or transport dependency and cannot
 * issue another provider request.
 */
export async function recoverBaseRpcReadCanary(
  optionsValue: BaseRpcReadCanaryRecoveryOptions,
): Promise<Readonly<BaseRpcReadCanaryReceiptV1> | null> {
  const dependencies = exactRecoveryOptions(optionsValue);
  const preparedEvent = dependencies.eventStore.getByIdempotencyKey(PREPARED_KEY);
  if (preparedEvent === undefined) return null;
  const prepared = parsePreparedEvent(preparedEvent);
  if (dependencies.runtime.getSnapshot().processInstanceId === prepared.runtimeProcessInstanceId) {
    throw new BaseRpcReadCanaryConflictError(
      "The claimed canary still belongs to the active runtime process",
    );
  }
  return projectPublicReceipt(await recoverPreparedCanary(dependencies, prepared));
}

export function readBaseRpcReadCanaryProjection(
  store: SqliteEventStore,
  credentialStatus: CredentialStatus,
  running = false,
): Readonly<BaseRpcReadCanaryProjectionV1> {
  if (!isSqliteEventStore(store)) {
    throw new BaseRpcReadCanaryValidationError("An authentic event store is required");
  }
  const receiptEvents = store.list({ type: RECEIPT_EVENT_TYPE, order: "desc", limit: 2 });
  if (receiptEvents.length > 1) {
    throw new BaseRpcReadCanaryConflictError("Multiple canary receipts are not allowed");
  }
  const durableReceipt =
    receiptEvents[0] === undefined ? null : parseReceiptEvent(receiptEvents[0]);
  const preparedEvents = store.list({ type: PREPARED_EVENT_TYPE, order: "desc", limit: 2 });
  if (preparedEvents.length > 1) {
    throw new BaseRpcReadCanaryConflictError("Multiple prepared canary claims are not allowed");
  }
  const prepared = preparedEvents[0] === undefined ? null : parsePreparedEvent(preparedEvents[0]);
  if (
    durableReceipt !== null &&
    (prepared === null ||
      durableReceipt.requestId !== prepared.requestId ||
      durableReceipt.requestFingerprint !== prepared.requestFingerprint)
  ) {
    throw new BaseRpcReadCanaryConflictError("Canary receipt does not match its prepared claim");
  }
  const hasPrepared = preparedEvents[0] !== undefined;
  const lastReceipt = durableReceipt === null ? null : projectPublicReceipt(durableReceipt);
  const status = running
    ? "running"
    : durableReceipt !== null
      ? durableReceipt.outcome === "accepted"
        ? "completed"
        : "failed"
      : hasPrepared
        ? "interrupted"
        : credentialStatus === "configured"
          ? "ready"
          : "uncommissioned";
  const projection = BaseRpcReadCanaryProjectionSchema.parse({
    schemaVersion: 1,
    status,
    credentialStatus,
    plan: PLAN,
    lastReceipt,
  });
  Object.freeze(projection.plan.rpcMethods);
  Object.freeze(projection.plan);
  if (projection.lastReceipt !== null) {
    Object.freeze(projection.lastReceipt.rpcMethods);
    Object.freeze(projection.lastReceipt);
  }
  return Object.freeze(projection);
}
