import { randomUUID } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  SqliteCaptureRegistry,
  isSqliteCaptureRegistry,
  type CommittedCaptureAttempt,
} from "@rsi/capture-registry";
import { ingestXRecentSearch, type XIngestionResult } from "@rsi/ingestion";
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
  RuntimeBoundaryDeniedError,
  SqliteRuntimeController,
  isSqliteRuntimeController,
  type RuntimeBoundaryAuthorization,
  type RuntimeAuditEvent,
} from "@rsi/runtime";
import { SqliteEventStore, isSqliteEventStore, type JsonValue, type StoredEvent } from "@rsi/store";
import { SnapshotVault, isSnapshotVault } from "@rsi/vault";
import {
  X_RECENT_SEARCH_RESERVED_USD_MICRO,
  createXRecentSearchCollector,
  isXCollectorError,
  prepareRecentSearchRequest,
  xRecentSearchRuntimeActionId,
  type XRateLimitReceipt,
} from "@rsi/x-collector";

import {
  X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO,
  X_READ_CANARY_MAXIMUM_REQUESTS,
  X_READ_CANARY_MAXIMUM_RESULTS,
  X_READ_CANARY_OPERATION,
  X_READ_CANARY_PLAN_ID,
  X_READ_CANARY_PROVIDER_ID,
  X_READ_CANARY_REQUEST_FINGERPRINT,
  xReadCanaryQuery,
} from "./constants.js";
import { XReadCanaryConflictError, XReadCanaryValidationError } from "./errors.js";
import {
  XReadCanaryPlanSchema,
  XReadCanaryPreparedEventPayloadSchema,
  XReadCanaryProjectionSchema,
  XReadCanaryReceiptSchema,
  XReadCanaryResultEventPayloadSchema,
  XReadCanaryRunCommandSchema,
  parseXReadCanaryInput,
} from "./schemas.js";
import type {
  XReadCanaryFailureCode,
  XReadCanaryPlanV1,
  XReadCanaryProjectionV1,
  XReadCanaryReceiptV1,
  XReadCanaryResultEventPayloadV1,
  XReadCanaryRunCommand,
} from "./types.js";

const PREPARED_EVENT_TYPE = "x.read-canary.prepared.v1" as const;
const RESULT_EVENT_TYPE = "x.read-canary.result.v1" as const;
const RECEIPT_EVENT_TYPE = "x.read-canary.receipt.v1" as const;
const AGGREGATE_ID = "read-canary:x" as const;
const AUTHENTIC_CONTROLLERS = new WeakSet<object>();

type CredentialStatus = XReadCanaryProjectionV1["credentialStatus"];
type PreparedPayload = ReturnType<typeof XReadCanaryPreparedEventPayloadSchema.parse>;

export interface XReadCanaryControllerOptions {
  readonly runtime: SqliteRuntimeController;
  readonly operationsStore: SqliteOperationsStore;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly eventStore: SqliteEventStore;
  readonly vault: SnapshotVault;
  readonly bearerToken: string;
}

export interface XReadCanaryRecoveryOptions {
  readonly runtime: SqliteRuntimeController;
  readonly operationsStore: SqliteOperationsStore;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly eventStore: SqliteEventStore;
  readonly vault: SnapshotVault;
}

const PREPARED_KEY = "x-read-canary-prepared-v1:singleton" as const;

function receiptKey(requestId: string): string {
  return `x-read-canary-receipt-v1:${requestId}`;
}

function resultKey(requestId: string): string {
  return `x-read-canary-result-v1:${requestId}`;
}

function jsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function now(): string {
  return new Date().toISOString();
}

function exactOptions(value: XReadCanaryControllerOptions): XReadCanaryControllerOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new XReadCanaryValidationError("X read canary options are invalid");
  }
  const expected = [
    "runtime",
    "operationsStore",
    "captureRegistry",
    "eventStore",
    "vault",
    "bearerToken",
  ];
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new XReadCanaryValidationError("X read canary options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new XReadCanaryValidationError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new XReadCanaryValidationError("X read canary options are invalid");
    }
  }
  if (
    !isSqliteRuntimeController(value.runtime) ||
    !isSqliteOperationsStore(value.operationsStore) ||
    !isSqliteCaptureRegistry(value.captureRegistry) ||
    !isSqliteEventStore(value.eventStore) ||
    !isSnapshotVault(value.vault) ||
    typeof value.bearerToken !== "string"
  ) {
    throw new XReadCanaryValidationError("Authentic canary dependencies are required");
  }
  return value;
}

function exactRecoveryOptions(value: XReadCanaryRecoveryOptions): XReadCanaryRecoveryOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new XReadCanaryValidationError("X read canary recovery options are invalid");
  }
  const expected = ["runtime", "operationsStore", "captureRegistry", "eventStore", "vault"];
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new XReadCanaryValidationError("X read canary recovery options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new XReadCanaryValidationError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new XReadCanaryValidationError("X read canary recovery options are invalid");
    }
  }
  if (
    !isSqliteRuntimeController(value.runtime) ||
    !isSqliteOperationsStore(value.operationsStore) ||
    !isSqliteCaptureRegistry(value.captureRegistry) ||
    !isSqliteEventStore(value.eventStore) ||
    !isSnapshotVault(value.vault)
  ) {
    throw new XReadCanaryValidationError("Authentic canary recovery dependencies are required");
  }
  return value;
}

const PLAN: Readonly<XReadCanaryPlanV1> = Object.freeze(
  XReadCanaryPlanSchema.parse({
    schemaVersion: 1,
    planId: X_READ_CANARY_PLAN_ID,
    providerId: X_READ_CANARY_PROVIDER_ID,
    operation: X_READ_CANARY_OPERATION,
    endpoint: "https://api.x.com/2/tweets/search/recent",
    method: "GET",
    sortOrder: "recency",
    maximumRequests: X_READ_CANARY_MAXIMUM_REQUESTS,
    maximumResults: X_READ_CANARY_MAXIMUM_RESULTS,
    maximumChargeUsdMicros: X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO,
    requestFingerprint: X_READ_CANARY_REQUEST_FINGERPRINT,
    rawContentDisposition: "encrypted_ephemeral",
    automaticRetries: 0,
  }),
);

export function getXReadCanaryPlan(): Readonly<XReadCanaryPlanV1> {
  return PLAN;
}

function parsePreparedEvent(event: StoredEvent): PreparedPayload {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== PREPARED_EVENT_TYPE ||
    event.idempotencyKey !== PREPARED_KEY
  ) {
    throw new XReadCanaryConflictError("Prepared canary event is invalid");
  }
  return parseXReadCanaryInput(
    XReadCanaryPreparedEventPayloadSchema,
    event.payload,
    "Prepared canary event",
  );
}

function parseReceiptEvent(event: StoredEvent): Readonly<XReadCanaryReceiptV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== RECEIPT_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new XReadCanaryConflictError("Canary receipt event is invalid");
  }
  const receipt = Object.freeze(
    parseXReadCanaryInput(XReadCanaryReceiptSchema, event.payload, "Canary receipt event"),
  );
  if (event.idempotencyKey !== receiptKey(receipt.requestId)) {
    throw new XReadCanaryConflictError("Canary receipt event key is invalid");
  }
  return receipt;
}

function parseResultEvent(event: StoredEvent): Readonly<XReadCanaryResultEventPayloadV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== RESULT_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new XReadCanaryConflictError("Canary result event is invalid");
  }
  const result = Object.freeze(
    parseXReadCanaryInput(
      XReadCanaryResultEventPayloadSchema,
      event.payload,
      "Canary result event",
    ),
  );
  if (event.idempotencyKey !== resultKey(result.requestId)) {
    throw new XReadCanaryConflictError("Canary result event key is invalid");
  }
  return result;
}

function runtimeReceipt(
  runtime: SqliteRuntimeController,
  authorizationId: string,
): XReadCanaryReceiptV1["runtime"] {
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
  if (matching.length !== 1) throw new XReadCanaryConflictError("Runtime receipt is ambiguous");
  const event = matching[0]!;
  if (
    event.payload.boundary !== "research_collection" ||
    event.payload.decision !== "allowed" ||
    event.payload.reason !== "ALLOWED"
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

function captureReceipt(result: XIngestionResult): NonNullable<XReadCanaryReceiptV1["capture"]> {
  return Object.freeze({ eventHash: result.eventHash, eventSequence: result.eventSequence });
}

function appendResult(
  store: SqliteEventStore,
  resultValue: XReadCanaryResultEventPayloadV1,
): Readonly<XReadCanaryResultEventPayloadV1> {
  const result = XReadCanaryResultEventPayloadSchema.parse(resultValue);
  const event = store.append({
    aggregateId: AGGREGATE_ID,
    idempotencyKey: resultKey(result.requestId),
    occurredAt: result.completedAt,
    payload: jsonValue(result),
    type: RESULT_EVENT_TYPE,
  });
  return parseResultEvent(event);
}

function sourceHasNextPage(attempt: CommittedCaptureAttempt): boolean {
  return attempt.sourceIdentifiers.source === "x" && attempt.sourceIdentifiers.nextToken !== null;
}

function safeFailureCode(error: unknown): XReadCanaryFailureCode {
  if (isXCollectorError(error)) return error.code;
  if (error instanceof RuntimeBoundaryDeniedError) return "RUNTIME_DENIED";
  return "UNKNOWN_FAILURE";
}

function rateLimitFrom(error: unknown): XRateLimitReceipt | null {
  if (!isXCollectorError(error)) return null;
  return error.details?.rateLimit ?? null;
}

function completionTime(...lowerBounds: readonly string[]): string {
  return lowerBounds.reduce(
    (latest, candidate) => (Date.parse(candidate) > Date.parse(latest) ? candidate : latest),
    now(),
  );
}

function appendReceipt(
  store: SqliteEventStore,
  receiptValue: XReadCanaryReceiptV1,
): Readonly<XReadCanaryReceiptV1> {
  const receipt = XReadCanaryReceiptSchema.parse(receiptValue);
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

function closeAttemptAfterFailure(
  operationsStore: SqliteOperationsStore,
  prepared: PreparedPayload,
  fallbackClosedAt: string,
): Readonly<{ closedAt: string; outcome: AttemptOutcome }> | null {
  let binding;
  try {
    binding = operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  } catch (error) {
    if (error instanceof OperationsConflictError && error.code === "ATTEMPT_CONFLICT") {
      return null;
    }
    throw error;
  }
  assertOperationsAttemptBinding(binding, prepared);
  if (binding.state === "closed") {
    if (binding.closedAt === null || binding.outcome === null) {
      throw new XReadCanaryConflictError("Closed network attempt facts are unavailable");
    }
    return Object.freeze({ closedAt: binding.closedAt, outcome: binding.outcome });
  }
  const closure = Object.freeze({
    closedAt: binding.dispatchedAt ?? fallbackClosedAt,
    outcome: binding.state === "reserved" ? ("aborted" as const) : ("failed" as const),
  });
  operationsStore.closeAttempt(prepared.attemptId, closure);
  const closed = operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  assertOperationsAttemptBinding(closed, prepared);
  if (
    closed.state !== "closed" ||
    closed.closedAt !== closure.closedAt ||
    closed.outcome !== closure.outcome
  ) {
    throw new XReadCanaryConflictError("Network attempt closure could not be authenticated");
  }
  return closure;
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
    binding.idempotencyKey !== `x-read-canary:${prepared.requestId}` ||
    binding.lane !== "discovery" ||
    binding.operation !== X_READ_CANARY_OPERATION ||
    binding.profile !== "canary" ||
    binding.reservedAtomic !== X_RECENT_SEARCH_RESERVED_USD_MICRO ||
    binding.sessionId !== prepared.requestId ||
    binding.sourcePlane !== "social"
  ) {
    throw new XReadCanaryConflictError("Canary network attempt binding is rebound");
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
  receipt: NonNullable<XReadCanaryReceiptV1["runtime"]>,
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
    throw new XReadCanaryConflictError("Runtime authorization evidence is ambiguous");
  }
  const event = matching[0]!;
  const expectedActionId = xRecentSearchRuntimeActionId(
    prepared.attemptId,
    prepared.requestFingerprint,
  );
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
    event.payload.requestedMode === "STOPPED" ||
    event.payload.requestedProcessInstanceId !== prepared.runtimeProcessInstanceId ||
    event.payload.checkedProcessInstanceId !== prepared.runtimeProcessInstanceId ||
    event.payload.requestedRevision !== prepared.expectedRuntimeRevision ||
    event.payload.checkedRevision !== prepared.expectedRuntimeRevision ||
    Date.parse(event.occurredAt) < Date.parse(prepared.preparedAt)
  ) {
    throw new XReadCanaryConflictError("Runtime authorization evidence is rebound");
  }
}

function assertCaptureEvidence(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<XReadCanaryResultEventPayloadV1>,
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
    throw new XReadCanaryConflictError("Capture event evidence is unavailable");
  }
  const { capture } = parseCaptureRecordedEventPayload(event.payload);
  if (
    capture.attemptId !== prepared.attemptId ||
    capture.sessionId !== prepared.requestId ||
    capture.expiresAt !== prepared.expiresAt ||
    capture.lane !== "discovery" ||
    capture.profile !== "canary" ||
    capture.sourcePlane !== "social" ||
    capture.rawDisposition !== "encrypted_ephemeral" ||
    capture.acquiredAt !== result.acquiredAt ||
    capture.byteLength !== result.byteLength ||
    event.occurredAt !== result.acquiredAt
  ) {
    throw new XReadCanaryConflictError("Capture event evidence is rebound");
  }
  if (
    result.failureCode !== "RUNTIME_DENIED" &&
    (result.outcome === "accepted" || result.outcome === "empty"
      ? capture.status !== "accepted" ||
        capture.failureCode !== null ||
        capture.counts?.recordCount !== result.postCount
      : capture.status !== "rejected" || capture.failureCode !== result.failureCode)
  ) {
    throw new XReadCanaryConflictError("Capture projection evidence disagrees");
  }

  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state === "committed") {
    if (
      attempt.requestFingerprint !== prepared.requestFingerprint ||
      attempt.sessionId !== prepared.requestId ||
      attempt.expiresAt !== prepared.expiresAt ||
      attempt.lane !== "discovery" ||
      attempt.profile !== "canary" ||
      attempt.source !== "x" ||
      attempt.sourceIdentifiers.source !== "x" ||
      Date.parse(result.completedAt) < Date.parse(attempt.committedAt) ||
      (capture.status === "accepted" &&
        (capture.counts?.recordCount !== attempt.sourceIdentifiers.postIds.length ||
          (result.failureCode !== "RUNTIME_DENIED" &&
            result.hasNextPage !== (attempt.sourceIdentifiers.nextToken !== null)))) ||
      (capture.status === "rejected" &&
        (attempt.sourceIdentifiers.postIds.length !== 0 ||
          attempt.sourceIdentifiers.nextToken !== null))
    ) {
      throw new XReadCanaryConflictError("Capture registry evidence disagrees");
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
    throw new XReadCanaryConflictError("Capture registry evidence is unavailable");
  }
}

function assertResultBinding(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<XReadCanaryResultEventPayloadV1>,
): void {
  if (
    result.requestId !== prepared.requestId ||
    result.attemptId !== prepared.attemptId ||
    result.requestFingerprint !== prepared.requestFingerprint
  ) {
    throw new XReadCanaryConflictError("Canary result is rebound");
  }
  assertOperationsAttemptBinding(
    dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
  assertRuntimeEvidence(dependencies.runtime, prepared, result.runtime);
  assertCaptureEvidence(dependencies, prepared, result);
}

function resultAttemptOutcome(result: XReadCanaryResultEventPayloadV1): AttemptOutcome {
  return result.outcome === "accepted"
    ? "succeeded"
    : result.outcome === "empty"
      ? "empty"
      : "failed";
}

function closeAttemptForResult(
  operationsStore: SqliteOperationsStore,
  prepared: PreparedPayload,
  result: Readonly<XReadCanaryResultEventPayloadV1>,
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
    throw new XReadCanaryConflictError("Canary result predates its network dispatch");
  }
  if (binding.state === "closed") {
    if (binding.closedAt !== expected.closedAt || binding.outcome !== expected.outcome) {
      throw new XReadCanaryConflictError("Canary network attempt closed with different facts");
    }
    operationsStore.closeAttempt(result.attemptId, expected);
    const closed = operationsStore.readNetworkAttemptBinding(result.attemptId);
    assertOperationsAttemptBinding(closed, prepared);
    if (
      closed.state !== "closed" ||
      closed.closedAt !== expected.closedAt ||
      closed.outcome !== expected.outcome
    ) {
      throw new XReadCanaryConflictError("Canary network attempt closure was not authenticated");
    }
    return;
  }
  if (binding.state !== "dispatched") {
    throw new XReadCanaryConflictError("Projected canary request was not dispatched");
  }
  operationsStore.closeAttempt(result.attemptId, expected);
  const closed = operationsStore.readNetworkAttemptBinding(result.attemptId);
  assertOperationsAttemptBinding(closed, prepared);
  if (
    closed.state !== "closed" ||
    closed.closedAt !== expected.closedAt ||
    closed.outcome !== expected.outcome
  ) {
    throw new XReadCanaryConflictError("Canary network attempt closure was not authenticated");
  }
}

async function destroyResultCapture(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  result: Readonly<XReadCanaryResultEventPayloadV1>,
): Promise<void> {
  const attempt = dependencies.captureRegistry.getAttempt(result.attemptId);
  if (attempt?.state === "removed") {
    if (
      !attempt.keyDestroyed ||
      (attempt.removalReason !== "capture_deleted_explicit" &&
        attempt.removalReason !== "capture_deleted_expired")
    ) {
      throw new XReadCanaryConflictError("Canary capture has an invalid terminal state");
    }
    return;
  }
  if (attempt?.state !== "committed") {
    throw new XReadCanaryConflictError("Committed canary capture is unavailable");
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
    throw new XReadCanaryConflictError("Canary capture deletion was not authenticated");
  }
}

function receiptFromResult(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<XReadCanaryResultEventPayloadV1>,
): XReadCanaryReceiptV1 {
  assertResultBinding(dependencies, prepared, result);
  return {
    schemaVersion: 1,
    receiptId: `x-read-canary:${prepared.requestId}`,
    planId: X_READ_CANARY_PLAN_ID,
    providerId: X_READ_CANARY_PROVIDER_ID,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    outcome: result.outcome,
    failureCode: result.failureCode,
    acquiredAt: result.acquiredAt,
    completedAt: result.completedAt,
    postCount: result.postCount,
    byteLength: result.byteLength,
    hasNextPage: result.hasNextPage,
    rateLimit: result.rateLimit,
    maximumRequests: 1,
    maximumResults: 10,
    maximumChargeUsdMicros: X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: result.runtime,
    capture: result.capture,
  };
}

async function finalizeResult(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<XReadCanaryResultEventPayloadV1>,
): Promise<Readonly<XReadCanaryReceiptV1>> {
  assertResultBinding(dependencies, prepared, result);
  closeAttemptForResult(dependencies.operationsStore, prepared, result);
  await destroyResultCapture(dependencies, result);
  return appendReceipt(dependencies.eventStore, receiptFromResult(dependencies, prepared, result));
}

function loadResult(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Readonly<XReadCanaryResultEventPayloadV1> | null {
  const event = dependencies.eventStore.getByIdempotencyKey(resultKey(prepared.requestId));
  if (event === undefined) return null;
  const result = parseResultEvent(event);
  assertResultBinding(dependencies, prepared, result);
  return result;
}

function resultCandidate(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<XIngestionResult>,
  runtimeDenied: boolean,
): XReadCanaryResultEventPayloadV1 {
  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state !== "committed") {
    throw new XReadCanaryConflictError("Committed capture is unavailable");
  }
  assertOperationsAttemptBinding(
    dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
  const runtime = runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId);
  if (runtime === null) throw new XReadCanaryConflictError("Runtime receipt is unavailable");
  const outcome = runtimeDenied
    ? ("rejected" as const)
    : ingestion.status === "rejected"
      ? ("rejected" as const)
      : ingestion.postCount === 0
        ? ("empty" as const)
        : ("accepted" as const);
  return XReadCanaryResultEventPayloadSchema.parse({
    schemaVersion: 1,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    outcome,
    failureCode: runtimeDenied
      ? "RUNTIME_DENIED"
      : ingestion.status === "rejected"
        ? (ingestion.failureCode as XReadCanaryFailureCode)
        : null,
    acquiredAt: ingestion.acquiredAt,
    completedAt: completionTime(ingestion.acquiredAt, attempt.committedAt),
    postCount: !runtimeDenied && ingestion.status === "accepted" ? ingestion.postCount : null,
    byteLength: ingestion.byteLength,
    hasNextPage:
      !runtimeDenied && ingestion.status === "accepted" ? sourceHasNextPage(attempt) : null,
    rateLimit: ingestion.rateLimit ?? null,
    runtime,
    capture: captureReceipt(ingestion),
  });
}

function persistRecoveryResult(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<XIngestionResult>,
): Readonly<XReadCanaryResultEventPayloadV1> {
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

function persistLiveResult(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<XIngestionResult>,
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">,
): Readonly<XReadCanaryResultEventPayloadV1> {
  const candidate = resultCandidate(dependencies, prepared, ingestion, false);
  let persisted: Readonly<XReadCanaryResultEventPayloadV1> | undefined;
  const completion = runtimeAuthorization.guardCompletion(() => {
    persisted = appendResult(dependencies.eventStore, candidate);
  });
  if (completion.decision !== "allowed" || persisted === undefined) {
    return persistRecoveryResult(dependencies, prepared, ingestion);
  }
  assertResultBinding(dependencies, prepared, persisted);
  return persisted;
}

function failedReceipt(
  dependencies: Pick<XReadCanaryRecoveryOptions, "runtime">,
  prepared: PreparedPayload,
  error: unknown,
  overrideCode?: XReadCanaryFailureCode,
  completedAt = completionTime(),
): XReadCanaryReceiptV1 {
  return {
    schemaVersion: 1,
    receiptId: `x-read-canary:${prepared.requestId}`,
    planId: X_READ_CANARY_PLAN_ID,
    providerId: X_READ_CANARY_PROVIDER_ID,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    outcome: "failed",
    failureCode: overrideCode ?? safeFailureCode(error),
    acquiredAt: null,
    completedAt,
    postCount: null,
    byteLength: null,
    hasNextPage: null,
    rateLimit: rateLimitFrom(error),
    maximumRequests: 1,
    maximumResults: 10,
    maximumChargeUsdMicros: X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId),
    capture: null,
  };
}

function terminalizeFailure(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  error: unknown,
  overrideCode?: XReadCanaryFailureCode,
): Readonly<XReadCanaryReceiptV1> {
  const closure = closeAttemptAfterFailure(
    dependencies.operationsStore,
    prepared,
    prepared.preparedAt,
  );
  const completedAt = closure?.closedAt ?? prepared.preparedAt;
  removePendingCaptureAfterFailure(dependencies.captureRegistry, prepared.attemptId, completedAt);
  return appendReceipt(
    dependencies.eventStore,
    failedReceipt(dependencies, prepared, error, overrideCode, completedAt),
  );
}

function assertFailureReceiptBinding(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  receipt: Readonly<XReadCanaryReceiptV1>,
): void {
  if (
    receipt.requestId !== prepared.requestId ||
    receipt.attemptId !== prepared.attemptId ||
    receipt.requestFingerprint !== prepared.requestFingerprint ||
    receipt.outcome !== "failed" ||
    receipt.capture !== null ||
    Date.parse(receipt.completedAt) < Date.parse(prepared.preparedAt)
  ) {
    throw new XReadCanaryConflictError("Failure receipt is rebound");
  }
  if (receipt.runtime !== null) {
    assertRuntimeEvidence(dependencies.runtime, prepared, receipt.runtime);
  }
  let binding;
  try {
    binding = dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  } catch (error) {
    if (!(error instanceof OperationsConflictError && error.code === "ATTEMPT_CONFLICT")) {
      throw error;
    }
  }
  if (binding !== undefined) {
    assertOperationsAttemptBinding(binding, prepared);
    if (
      binding.state !== "closed" ||
      binding.closedAt !== receipt.completedAt ||
      (binding.outcome !== "aborted" && binding.outcome !== "failed")
    ) {
      throw new XReadCanaryConflictError("Failure receipt closure evidence disagrees");
    }
  }
  const captureAttempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (captureAttempt?.state === "pending" || captureAttempt?.state === "committed") {
    throw new XReadCanaryConflictError("Failure receipt left active capture state");
  }
}

async function recoverPreparedCanary(
  dependencies: Readonly<XReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Promise<Readonly<XReadCanaryReceiptV1>> {
  const existingReceipt = dependencies.eventStore.getByIdempotencyKey(
    receiptKey(prepared.requestId),
  );
  if (existingReceipt !== undefined) {
    const receipt = parseReceiptEvent(existingReceipt);
    const durableResult = loadResult(dependencies, prepared);
    if (receipt.capture !== null) {
      if (durableResult === null) {
        throw new XReadCanaryConflictError("Captured receipt has no durable result evidence");
      }
      return finalizeResult(dependencies, prepared, durableResult);
    }
    if (durableResult !== null) {
      throw new XReadCanaryConflictError("Failure receipt conflicts with captured result evidence");
    }
    assertFailureReceiptBinding(dependencies, prepared, receipt);
    return receipt;
  }
  const durableResult = loadResult(dependencies, prepared);
  if (durableResult !== null) return finalizeResult(dependencies, prepared, durableResult);

  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state === "committed") {
    const ingestion = await ingestXRecentSearch(
      {
        captureRegistry: dependencies.captureRegistry,
        operationsStore: dependencies.operationsStore,
        store: dependencies.eventStore,
        vault: dependencies.vault,
      },
      {
        attemptId: prepared.attemptId,
        expiresAt: prepared.expiresAt,
        lane: "discovery",
        profile: "canary",
        sessionId: prepared.requestId,
      },
      xReadCanaryQuery(),
    );
    return finalizeResult(
      dependencies,
      prepared,
      persistRecoveryResult(dependencies, prepared, ingestion),
    );
  }

  return terminalizeFailure(
    dependencies,
    prepared,
    new XReadCanaryConflictError("Interrupted canary"),
    "INTERRUPTED",
  );
}

/**
 * Completes an already-claimed canary exclusively from authenticated local
 * state. This function has no credential or transport dependency and cannot
 * issue another provider request.
 */
export async function recoverXReadCanary(
  optionsValue: XReadCanaryRecoveryOptions,
): Promise<Readonly<XReadCanaryReceiptV1> | null> {
  const dependencies = exactRecoveryOptions(optionsValue);
  const preparedEvent = dependencies.eventStore.getByIdempotencyKey(PREPARED_KEY);
  if (preparedEvent === undefined) return null;
  const prepared = parsePreparedEvent(preparedEvent);
  if (dependencies.runtime.getSnapshot().processInstanceId === prepared.runtimeProcessInstanceId) {
    throw new XReadCanaryConflictError(
      "The claimed canary still belongs to the active runtime process",
    );
  }
  return recoverPreparedCanary(dependencies, prepared);
}

export function readXReadCanaryProjection(
  store: SqliteEventStore,
  credentialStatus: CredentialStatus,
  running = false,
): Readonly<XReadCanaryProjectionV1> {
  if (!isSqliteEventStore(store)) {
    throw new XReadCanaryValidationError("An authentic event store is required");
  }
  const receiptEvents = store.list({ type: RECEIPT_EVENT_TYPE, order: "desc", limit: 2 });
  if (receiptEvents.length > 1) {
    throw new XReadCanaryConflictError("Multiple canary receipts are not allowed");
  }
  const lastReceipt = receiptEvents[0] === undefined ? null : parseReceiptEvent(receiptEvents[0]);
  const preparedEvents = store.list({ type: PREPARED_EVENT_TYPE, order: "desc", limit: 2 });
  if (preparedEvents.length > 1) {
    throw new XReadCanaryConflictError("Multiple prepared canary claims are not allowed");
  }
  const prepared = preparedEvents[0] === undefined ? null : parsePreparedEvent(preparedEvents[0]);
  if (
    lastReceipt !== null &&
    (prepared === null ||
      lastReceipt.requestId !== prepared.requestId ||
      lastReceipt.attemptId !== prepared.attemptId ||
      lastReceipt.requestFingerprint !== prepared.requestFingerprint)
  ) {
    throw new XReadCanaryConflictError("Canary receipt does not match its prepared claim");
  }
  const hasPrepared = preparedEvents[0] !== undefined;
  const status = running
    ? "running"
    : lastReceipt !== null
      ? lastReceipt.outcome === "accepted" || lastReceipt.outcome === "empty"
        ? "completed"
        : "failed"
      : hasPrepared
        ? "interrupted"
        : credentialStatus === "configured"
          ? "ready"
          : "uncommissioned";
  return Object.freeze(
    XReadCanaryProjectionSchema.parse({
      schemaVersion: 1,
      status,
      credentialStatus,
      plan: PLAN,
      lastReceipt,
    }),
  );
}

export class XReadCanaryController {
  readonly #runtime: SqliteRuntimeController;
  readonly #operationsStore: SqliteOperationsStore;
  readonly #captureRegistry: SqliteCaptureRegistry;
  readonly #eventStore: SqliteEventStore;
  readonly #vault: SnapshotVault;
  #bearerToken: string | null;
  #activeAbort: AbortController | null = null;
  #used = false;

  constructor(optionsValue: XReadCanaryControllerOptions) {
    const options = exactOptions(optionsValue);
    this.#runtime = options.runtime;
    this.#operationsStore = options.operationsStore;
    this.#captureRegistry = options.captureRegistry;
    this.#eventStore = options.eventStore;
    this.#vault = options.vault;
    this.#bearerToken = options.bearerToken;
    AUTHENTIC_CONTROLLERS.add(this);
  }

  get running(): boolean {
    this.#assertAuthentic();
    return this.#activeAbort !== null;
  }

  getProjection(): Readonly<XReadCanaryProjectionV1> {
    this.#assertAuthentic();
    return readXReadCanaryProjection(this.#eventStore, "configured", this.running);
  }

  abortActive(): void {
    this.#assertAuthentic();
    this.#activeAbort?.abort();
  }

  async execute(commandValue: unknown): Promise<Readonly<XReadCanaryReceiptV1>> {
    this.#assertAuthentic();
    const command = parseXReadCanaryInput(
      XReadCanaryRunCommandSchema,
      commandValue,
      "X read canary command",
    );
    const preparedEvent = this.#eventStore.getByIdempotencyKey(PREPARED_KEY);
    if (preparedEvent !== undefined) {
      const prepared = parsePreparedEvent(preparedEvent);
      if (
        prepared.requestId !== command.requestId ||
        prepared.expectedRuntimeRevision !== command.expectedRuntimeRevision
      ) {
        throw new XReadCanaryConflictError("The one-shot X read canary is already claimed");
      }
      const existingReceipt = this.#eventStore.getByIdempotencyKey(receiptKey(command.requestId));
      if (existingReceipt !== undefined) {
        return recoverPreparedCanary(this.#recoveryDependencies(), prepared);
      }
      if (this.#activeAbort !== null) {
        throw new XReadCanaryConflictError("An X read canary is already running");
      }
      if (this.#used || this.#bearerToken === null) {
        throw new XReadCanaryConflictError("This canary controller is one-shot");
      }
      this.#activeAbort = new AbortController();
      try {
        return await this.#resume(command, prepared);
      } finally {
        this.#bearerToken = null;
        this.#used = true;
        this.#activeAbort = null;
      }
    }
    if (this.#activeAbort !== null) {
      throw new XReadCanaryConflictError("An X read canary is already running");
    }
    if (this.#used || this.#bearerToken === null) {
      throw new XReadCanaryConflictError("This canary controller is one-shot");
    }

    this.#activeAbort = new AbortController();
    try {
      return await this.#run(command, this.#activeAbort.signal);
    } finally {
      this.#bearerToken = null;
      this.#used = true;
      this.#activeAbort = null;
    }
  }

  close(): void {
    this.#assertAuthentic();
    this.#activeAbort?.abort();
    this.#bearerToken = null;
    this.#used = true;
  }

  async #run(
    command: XReadCanaryRunCommand,
    signal: AbortSignal,
  ): Promise<Readonly<XReadCanaryReceiptV1>> {
    const snapshot = this.#runtime.getSnapshot();
    if (snapshot.mode === "STOPPED" || snapshot.revision !== command.expectedRuntimeRevision) {
      throw new XReadCanaryConflictError("Runtime state changed before canary preparation");
    }

    const request = prepareRecentSearchRequest(xReadCanaryQuery());
    if (request.fingerprint !== X_READ_CANARY_REQUEST_FINGERPRINT) {
      throw new XReadCanaryConflictError("Canary request fingerprint changed");
    }
    const permit = SqliteOperationsStore.createAttemptPermit();
    const runtimeAuthorization = this.#runtime.requestBoundaryAuthorization({
      actionId: xRecentSearchRuntimeActionId(permit.attemptId, request.fingerprint),
      authorizationId: randomUUID(),
      boundary: "research_collection",
    });
    if (
      runtimeAuthorization.requestedRevision !== command.expectedRuntimeRevision ||
      runtimeAuthorization.requestedMode === "STOPPED"
    ) {
      throw new XReadCanaryConflictError("Runtime state changed before canary authorization");
    }

    const budgetId = randomUUID();
    const prepared = XReadCanaryPreparedEventPayloadSchema.parse({
      schemaVersion: 1,
      planId: X_READ_CANARY_PLAN_ID,
      providerId: X_READ_CANARY_PROVIDER_ID,
      requestId: command.requestId,
      attemptId: permit.attemptId,
      budgetId,
      expectedRuntimeRevision: command.expectedRuntimeRevision,
      runtimeAuthorizationId: runtimeAuthorization.authorizationId,
      runtimeProcessInstanceId: runtimeAuthorization.processInstanceId,
      requestFingerprint: request.fingerprint,
      preparedAt: runtimeAuthorization.requestedAt,
      expiresAt: runtimeAuthorization.expiresAt,
      maximumRequests: 1,
      maximumResults: 10,
      maximumChargeUsdMicros: X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO,
    });
    try {
      this.#eventStore.append({
        aggregateId: AGGREGATE_ID,
        idempotencyKey: PREPARED_KEY,
        occurredAt: prepared.preparedAt,
        payload: jsonValue(prepared),
        type: PREPARED_EVENT_TYPE,
      });
    } catch {
      throw new XReadCanaryConflictError("The one-shot X read canary was claimed concurrently");
    }

    try {
      this.#operationsStore.createBudget({
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        currency: "USD_MICRO",
        endsAt: runtimeAuthorization.expiresAt,
        maxAtomic: X_RECENT_SEARCH_RESERVED_USD_MICRO,
        maxAttempts: 1,
        profile: "canary",
        startsAt: runtimeAuthorization.requestedAt,
      });
      this.#operationsStore.reserveAttempt({
        attemptId: permit.attemptId,
        authorizationExpiresAt: runtimeAuthorization.expiresAt,
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        idempotencyKey: `x-read-canary:${command.requestId}`,
        lane: "discovery",
        operation: "x.recent-search.v1",
        permitToken: permit.token,
        reservedAtomic: X_RECENT_SEARCH_RESERVED_USD_MICRO,
        sessionId: command.requestId,
        sourcePlane: "social",
      });
      const networkAuthorization = this.#operationsStore.createNetworkAttemptAuthorization(permit);
      const bearerToken = this.#bearerToken;
      if (bearerToken === null)
        throw new XReadCanaryConflictError("Canary credential is unavailable");
      const collector = createXRecentSearchCollector({
        attemptAuthorization: networkAuthorization,
        bearerToken,
        runtimeAuthorization,
      });
      const result = await ingestXRecentSearch(
        {
          captureRegistry: this.#captureRegistry,
          collector,
          now,
          operationsStore: this.#operationsStore,
          signal,
          store: this.#eventStore,
          vault: this.#vault,
        },
        {
          attemptId: permit.attemptId,
          expiresAt: runtimeAuthorization.expiresAt,
          lane: "discovery",
          profile: "canary",
          sessionId: command.requestId,
        },
        xReadCanaryQuery(),
      );
      return await this.#complete(prepared, result, runtimeAuthorization);
    } catch (error) {
      const dependencies = this.#recoveryDependencies();
      const durableResult = loadResult(dependencies, prepared);
      const attempt = this.#captureRegistry.getAttempt(prepared.attemptId);
      if (durableResult !== null || attempt?.state === "committed") {
        try {
          return await recoverPreparedCanary(dependencies, prepared);
        } catch (recoveryError) {
          throw new AggregateError(
            [error, recoveryError],
            "Canary execution failed and its durable capture requires restart recovery",
          );
        }
      }
      return terminalizeFailure(dependencies, prepared, error);
    }
  }

  async #resume(
    command: XReadCanaryRunCommand,
    prepared: PreparedPayload,
  ): Promise<Readonly<XReadCanaryReceiptV1>> {
    if (
      prepared.requestId !== command.requestId ||
      prepared.expectedRuntimeRevision !== command.expectedRuntimeRevision
    ) {
      throw new XReadCanaryConflictError("Canary command is rebound");
    }
    if (this.#runtime.getSnapshot().processInstanceId === prepared.runtimeProcessInstanceId) {
      throw new XReadCanaryConflictError("The claimed canary is still owned by this runtime");
    }
    return recoverPreparedCanary(this.#recoveryDependencies(), prepared);
  }

  async #complete(
    prepared: PreparedPayload,
    result: Readonly<XIngestionResult>,
    runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">,
  ): Promise<Readonly<XReadCanaryReceiptV1>> {
    const dependencies = this.#recoveryDependencies();
    return finalizeResult(
      dependencies,
      prepared,
      persistLiveResult(dependencies, prepared, result, runtimeAuthorization),
    );
  }

  #recoveryDependencies(): XReadCanaryRecoveryOptions {
    return {
      runtime: this.#runtime,
      operationsStore: this.#operationsStore,
      captureRegistry: this.#captureRegistry,
      eventStore: this.#eventStore,
      vault: this.#vault,
    };
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_CONTROLLERS.has(this) ||
      Object.getPrototypeOf(this) !== XReadCanaryController.prototype
    ) {
      throw new XReadCanaryConflictError("X read canary controller is not authentic");
    }
  }
}

Object.freeze(XReadCanaryController.prototype);
Object.freeze(XReadCanaryController);

export function isXReadCanaryController(value: unknown): value is XReadCanaryController {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_CONTROLLERS.has(value) &&
    Object.getPrototypeOf(value) === XReadCanaryController.prototype
  );
}
