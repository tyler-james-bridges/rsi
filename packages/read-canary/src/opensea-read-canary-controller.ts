import { randomUUID } from "node:crypto";
import { types as utilTypes } from "node:util";

import { SqliteCaptureRegistry, isSqliteCaptureRegistry } from "@rsi/capture-registry";
import {
  ingestOpenSeaTrending,
  type OpenSeaTrendingIngestionResult,
} from "@rsi/ingestion/opensea-trending";
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
  RuntimeBoundaryDeniedError,
  SqliteRuntimeController,
  isSqliteRuntimeController,
  type RuntimeBoundaryAuthorization,
  type RuntimeAuditEvent,
} from "@rsi/runtime";
import { SqliteEventStore, isSqliteEventStore, type JsonValue, type StoredEvent } from "@rsi/store";
import { SnapshotVault, isSnapshotVault } from "@rsi/vault";
import {
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  createOpenSeaTrendingCollector,
  isOpenSeaCollectorError,
  prepareOpenSeaTrendingCollectorRequest,
  openSeaTrendingRuntimeActionId,
  type OpenSeaRateLimitReceipt,
} from "@rsi/opensea-collector";

import {
  OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  OPENSEA_READ_CANARY_ENDPOINT,
  OPENSEA_READ_CANARY_MAXIMUM_REQUESTS,
  OPENSEA_READ_CANARY_MAXIMUM_RESULTS,
  OPENSEA_READ_CANARY_OPERATION,
  OPENSEA_READ_CANARY_PLAN_ID,
  OPENSEA_READ_CANARY_PROVIDER_ID,
  OPENSEA_READ_CANARY_REQUEST_FINGERPRINT,
} from "./opensea-constants.js";
import {
  OpenSeaReadCanaryConflictError,
  OpenSeaReadCanaryValidationError,
} from "./opensea-errors.js";
import {
  OpenSeaReadCanaryPlanSchema,
  OpenSeaReadCanaryFailureEventPayloadSchema,
  OpenSeaReadCanaryPreparedEventPayloadSchema,
  OpenSeaReadCanaryProjectionSchema,
  OpenSeaReadCanaryReceiptSchema,
  OpenSeaReadCanaryResultEventPayloadSchema,
  OpenSeaReadCanaryRunCommandSchema,
  parseOpenSeaReadCanaryInput,
} from "./opensea-schemas.js";
import type {
  OpenSeaReadCanaryFailureCode,
  OpenSeaReadCanaryFailureEventPayloadV1,
  OpenSeaReadCanaryPlanV1,
  OpenSeaReadCanaryProjectionV1,
  OpenSeaReadCanaryReceiptV1,
  OpenSeaReadCanaryResultEventPayloadV1,
  OpenSeaReadCanaryRunCommand,
} from "./opensea-types.js";

const PREPARED_EVENT_TYPE = "opensea.read-canary.prepared.v1" as const;
const RESULT_EVENT_TYPE = "opensea.read-canary.result.v1" as const;
const FAILURE_EVENT_TYPE = "opensea.read-canary.failure.v1" as const;
const RECEIPT_EVENT_TYPE = "opensea.read-canary.receipt.v1" as const;
const AGGREGATE_ID = "read-canary:opensea" as const;
const AUTHENTIC_CONTROLLERS = new WeakSet<object>();

type CredentialStatus = OpenSeaReadCanaryProjectionV1["credentialStatus"];
type PreparedPayload = ReturnType<typeof OpenSeaReadCanaryPreparedEventPayloadSchema.parse>;

export interface OpenSeaReadCanaryControllerOptions {
  readonly runtime: SqliteRuntimeController;
  readonly operationsStore: SqliteOperationsStore;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly eventStore: SqliteEventStore;
  readonly vault: SnapshotVault;
  readonly apiKey: string;
}

export interface OpenSeaReadCanaryRecoveryOptions {
  readonly runtime: SqliteRuntimeController;
  readonly operationsStore: SqliteOperationsStore;
  readonly captureRegistry: SqliteCaptureRegistry;
  readonly eventStore: SqliteEventStore;
  readonly vault: SnapshotVault;
}

const PREPARED_KEY = "opensea-read-canary-prepared-v1:singleton" as const;

function receiptKey(requestId: string): string {
  return `opensea-read-canary-receipt-v1:${requestId}`;
}

function resultKey(requestId: string): string {
  return `opensea-read-canary-result-v1:${requestId}`;
}

function failureKey(requestId: string): string {
  return `opensea-read-canary-failure-v1:${requestId}`;
}

function jsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function now(): string {
  return new Date().toISOString();
}

function exactOptions(
  value: OpenSeaReadCanaryControllerOptions,
): OpenSeaReadCanaryControllerOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new OpenSeaReadCanaryValidationError("OpenSea read canary options are invalid");
  }
  const expected = [
    "runtime",
    "operationsStore",
    "captureRegistry",
    "eventStore",
    "vault",
    "apiKey",
  ];
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new OpenSeaReadCanaryValidationError("OpenSea read canary options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new OpenSeaReadCanaryValidationError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new OpenSeaReadCanaryValidationError("OpenSea read canary options are invalid");
    }
  }
  if (
    !isSqliteRuntimeController(value.runtime) ||
    !isSqliteOperationsStore(value.operationsStore) ||
    !isSqliteCaptureRegistry(value.captureRegistry) ||
    !isSqliteEventStore(value.eventStore) ||
    !isSnapshotVault(value.vault) ||
    typeof value.apiKey !== "string"
  ) {
    throw new OpenSeaReadCanaryValidationError("Authentic canary dependencies are required");
  }
  return value;
}

function exactRecoveryOptions(
  value: OpenSeaReadCanaryRecoveryOptions,
): OpenSeaReadCanaryRecoveryOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new OpenSeaReadCanaryValidationError("OpenSea read canary recovery options are invalid");
  }
  const expected = ["runtime", "operationsStore", "captureRegistry", "eventStore", "vault"];
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new OpenSeaReadCanaryValidationError("OpenSea read canary recovery options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new OpenSeaReadCanaryValidationError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new OpenSeaReadCanaryValidationError(
        "OpenSea read canary recovery options are invalid",
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
    throw new OpenSeaReadCanaryValidationError(
      "Authentic canary recovery dependencies are required",
    );
  }
  return value;
}

const PLAN: Readonly<OpenSeaReadCanaryPlanV1> = Object.freeze(
  OpenSeaReadCanaryPlanSchema.parse({
    schemaVersion: 1,
    planId: OPENSEA_READ_CANARY_PLAN_ID,
    providerId: OPENSEA_READ_CANARY_PROVIDER_ID,
    operation: OPENSEA_READ_CANARY_OPERATION,
    profile: "canary",
    endpoint: OPENSEA_READ_CANARY_ENDPOINT,
    method: "GET",
    chain: "base",
    timeframe: "one_day",
    maximumRequests: OPENSEA_READ_CANARY_MAXIMUM_REQUESTS,
    maximumResults: OPENSEA_READ_CANARY_MAXIMUM_RESULTS,
    ledgerReserveUsdMicros: OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    requestFingerprint: OPENSEA_READ_CANARY_REQUEST_FINGERPRINT,
    rawContentDisposition: "encrypted_ephemeral",
    automaticRetries: 0,
    automaticPagination: false,
  }),
);

export function getOpenSeaReadCanaryPlan(): Readonly<OpenSeaReadCanaryPlanV1> {
  return PLAN;
}

function parsePreparedEvent(event: StoredEvent): PreparedPayload {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== PREPARED_EVENT_TYPE ||
    event.idempotencyKey !== PREPARED_KEY
  ) {
    throw new OpenSeaReadCanaryConflictError("Prepared canary event is invalid");
  }
  return parseOpenSeaReadCanaryInput(
    OpenSeaReadCanaryPreparedEventPayloadSchema,
    event.payload,
    "Prepared canary event",
  );
}

function parseReceiptEvent(event: StoredEvent): Readonly<OpenSeaReadCanaryReceiptV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== RECEIPT_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary receipt event is invalid");
  }
  const receipt = Object.freeze(
    parseOpenSeaReadCanaryInput(
      OpenSeaReadCanaryReceiptSchema,
      event.payload,
      "Canary receipt event",
    ),
  );
  if (event.idempotencyKey !== receiptKey(receipt.requestId)) {
    throw new OpenSeaReadCanaryConflictError("Canary receipt event key is invalid");
  }
  return receipt;
}

function parseResultEvent(event: StoredEvent): Readonly<OpenSeaReadCanaryResultEventPayloadV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== RESULT_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary result event is invalid");
  }
  const result = Object.freeze(
    parseOpenSeaReadCanaryInput(
      OpenSeaReadCanaryResultEventPayloadSchema,
      event.payload,
      "Canary result event",
    ),
  );
  if (event.idempotencyKey !== resultKey(result.requestId)) {
    throw new OpenSeaReadCanaryConflictError("Canary result event key is invalid");
  }
  return result;
}

function parseFailureEvent(event: StoredEvent): Readonly<OpenSeaReadCanaryFailureEventPayloadV1> {
  if (
    event.aggregateId !== AGGREGATE_ID ||
    event.type !== FAILURE_EVENT_TYPE ||
    event.idempotencyKey === null
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary failure event is invalid");
  }
  const failure = Object.freeze(
    parseOpenSeaReadCanaryInput(
      OpenSeaReadCanaryFailureEventPayloadSchema,
      event.payload,
      "Canary failure event",
    ),
  );
  if (event.idempotencyKey !== failureKey(failure.requestId)) {
    throw new OpenSeaReadCanaryConflictError("Canary failure event key is invalid");
  }
  return failure;
}

function runtimeReceipt(
  runtime: SqliteRuntimeController,
  authorizationId: string,
): OpenSeaReadCanaryReceiptV1["runtime"] {
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
    throw new OpenSeaReadCanaryConflictError("Runtime receipt is ambiguous");
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

function captureReceipt(
  store: SqliteEventStore,
  attemptId: string,
): NonNullable<OpenSeaReadCanaryReceiptV1["capture"]> {
  const event = store.getByIdempotencyKey(`capture-recorded-v2:${attemptId}`);
  if (event === undefined || event.type !== CAPTURE_RECORDED_EVENT_TYPE) {
    throw new OpenSeaReadCanaryConflictError("Capture event receipt is unavailable");
  }
  return Object.freeze({ eventHash: event.eventHash, eventSequence: event.sequence });
}

function appendResult(
  store: SqliteEventStore,
  resultValue: OpenSeaReadCanaryResultEventPayloadV1,
): Readonly<OpenSeaReadCanaryResultEventPayloadV1> {
  const result = OpenSeaReadCanaryResultEventPayloadSchema.parse(resultValue);
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
  failureValue: OpenSeaReadCanaryFailureEventPayloadV1,
): Readonly<OpenSeaReadCanaryFailureEventPayloadV1> {
  const failure = OpenSeaReadCanaryFailureEventPayloadSchema.parse(failureValue);
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

function safeFailureCode(error: unknown): OpenSeaReadCanaryFailureCode {
  if (isOpenSeaCollectorError(error)) return error.code;
  if (error instanceof RuntimeBoundaryDeniedError) return "RUNTIME_DENIED";
  return "UNKNOWN_FAILURE";
}

function rateLimitFrom(error: unknown): OpenSeaRateLimitReceipt | null {
  if (!isOpenSeaCollectorError(error)) return null;
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
  receiptValue: OpenSeaReadCanaryReceiptV1,
): Readonly<OpenSeaReadCanaryReceiptV1> {
  const receipt = OpenSeaReadCanaryReceiptSchema.parse(receiptValue);
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

function assertOperationsAttemptBinding(
  binding: Readonly<DurableNetworkAttemptBinding>,
  prepared: PreparedPayload,
): void {
  if (
    binding.attemptId !== prepared.attemptId ||
    binding.authorizationExpiresAt !== prepared.expiresAt ||
    binding.budgetId !== prepared.budgetId ||
    binding.createdAt !== prepared.preparedAt ||
    binding.idempotencyKey !== `opensea-read-canary:${prepared.requestId}` ||
    binding.lane !== "marketplace" ||
    binding.operation !== OPENSEA_READ_CANARY_OPERATION ||
    binding.profile !== "canary" ||
    binding.reservedAtomic !== OPENSEA_TRENDING_RESERVED_ATOMIC ||
    binding.sessionId !== prepared.requestId ||
    binding.sourcePlane !== "marketplace"
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary network attempt binding is rebound");
  }
}

function assertFailureCheckpointBinding(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failure: Readonly<OpenSeaReadCanaryFailureEventPayloadV1>,
): void {
  if (
    failure.requestId !== prepared.requestId ||
    failure.attemptId !== prepared.attemptId ||
    failure.requestFingerprint !== prepared.requestFingerprint
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary failure checkpoint is rebound");
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
      throw new OpenSeaReadCanaryConflictError(
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
      throw new OpenSeaReadCanaryConflictError("Canary failure closure evidence disagrees");
    }
  }
  const expectedRuntime = runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId);
  if (JSON.stringify(failure.runtime) !== JSON.stringify(expectedRuntime)) {
    throw new OpenSeaReadCanaryConflictError("Canary failure runtime evidence disagrees");
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
    throw new OpenSeaReadCanaryConflictError(
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
  receipt: NonNullable<OpenSeaReadCanaryReceiptV1["runtime"]>,
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
    throw new OpenSeaReadCanaryConflictError("Runtime authorization evidence is ambiguous");
  }
  const event = matching[0]!;
  const expectedActionId = openSeaTrendingRuntimeActionId(
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
    throw new OpenSeaReadCanaryConflictError("Runtime authorization evidence is rebound");
  }
}

function assertCaptureEvidence(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<OpenSeaReadCanaryResultEventPayloadV1>,
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
    throw new OpenSeaReadCanaryConflictError("Capture event evidence is unavailable");
  }
  const { capture } = parseCaptureRecordedEventPayload(event.payload);
  if (
    capture.attemptId !== prepared.attemptId ||
    capture.sessionId !== prepared.requestId ||
    capture.expiresAt !== prepared.expiresAt ||
    capture.lane !== "marketplace" ||
    capture.profile !== "canary" ||
    capture.sourcePlane !== "marketplace" ||
    capture.rawDisposition !== "encrypted_ephemeral" ||
    capture.acquiredAt !== result.acquiredAt ||
    capture.byteLength !== result.byteLength ||
    event.occurredAt !== result.acquiredAt
  ) {
    throw new OpenSeaReadCanaryConflictError("Capture event evidence is rebound");
  }
  if (
    result.failureCode !== "RUNTIME_DENIED" &&
    (result.outcome === "accepted" || result.outcome === "empty"
      ? capture.status !== "accepted" ||
        capture.failureCode !== null ||
        capture.counts?.recordCount !== result.collectionCount
      : capture.status !== "rejected" || capture.failureCode !== result.failureCode)
  ) {
    throw new OpenSeaReadCanaryConflictError("Capture projection evidence disagrees");
  }

  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state === "committed") {
    if (
      attempt.requestFingerprint !== prepared.requestFingerprint ||
      attempt.sessionId !== prepared.requestId ||
      attempt.expiresAt !== prepared.expiresAt ||
      attempt.lane !== "marketplace" ||
      attempt.profile !== "canary" ||
      attempt.source !== "opensea" ||
      attempt.sourceIdentifiers.source !== "opensea" ||
      Date.parse(result.completedAt) < Date.parse(attempt.committedAt) ||
      (capture.status === "accepted" &&
        (capture.counts?.recordCount !== attempt.sourceIdentifiers.identifiers.length ||
          attempt.sourceIdentifiers.identifiers.some(
            (identifier) => identifier.kind !== "collection_slug",
          ))) ||
      (capture.status === "rejected" && attempt.sourceIdentifiers.identifiers.length !== 0)
    ) {
      throw new OpenSeaReadCanaryConflictError("Capture registry evidence disagrees");
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
    throw new OpenSeaReadCanaryConflictError("Capture registry evidence is unavailable");
  }
}

function assertResultBinding(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<OpenSeaReadCanaryResultEventPayloadV1>,
): void {
  if (
    result.requestId !== prepared.requestId ||
    result.attemptId !== prepared.attemptId ||
    result.requestFingerprint !== prepared.requestFingerprint
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary result is rebound");
  }
  assertOperationsAttemptBinding(
    dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
  assertRuntimeEvidence(dependencies.runtime, prepared, result.runtime);
  assertCaptureEvidence(dependencies, prepared, result);
}

function resultAttemptOutcome(result: OpenSeaReadCanaryResultEventPayloadV1): AttemptOutcome {
  return result.outcome === "accepted"
    ? "succeeded"
    : result.outcome === "empty"
      ? "empty"
      : "failed";
}

function closeAttemptForResult(
  operationsStore: SqliteOperationsStore,
  prepared: PreparedPayload,
  result: Readonly<OpenSeaReadCanaryResultEventPayloadV1>,
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
    throw new OpenSeaReadCanaryConflictError("Canary result predates its network dispatch");
  }
  if (binding.state === "closed") {
    if (binding.closedAt !== expected.closedAt || binding.outcome !== expected.outcome) {
      throw new OpenSeaReadCanaryConflictError(
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
      throw new OpenSeaReadCanaryConflictError(
        "Canary network attempt closure was not authenticated",
      );
    }
    return;
  }
  if (binding.state !== "dispatched") {
    throw new OpenSeaReadCanaryConflictError("Projected canary request was not dispatched");
  }
  operationsStore.closeAttempt(result.attemptId, expected);
  const closed = operationsStore.readNetworkAttemptBinding(result.attemptId);
  assertOperationsAttemptBinding(closed, prepared);
  if (
    closed.state !== "closed" ||
    closed.closedAt !== expected.closedAt ||
    closed.outcome !== expected.outcome
  ) {
    throw new OpenSeaReadCanaryConflictError(
      "Canary network attempt closure was not authenticated",
    );
  }
}

async function destroyResultCapture(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  result: Readonly<OpenSeaReadCanaryResultEventPayloadV1>,
): Promise<void> {
  const attempt = dependencies.captureRegistry.getAttempt(result.attemptId);
  if (attempt?.state === "removed") {
    if (
      !attempt.keyDestroyed ||
      (attempt.removalReason !== "capture_deleted_explicit" &&
        attempt.removalReason !== "capture_deleted_expired")
    ) {
      throw new OpenSeaReadCanaryConflictError("Canary capture has an invalid terminal state");
    }
    return;
  }
  if (attempt?.state !== "committed") {
    throw new OpenSeaReadCanaryConflictError("Committed canary capture is unavailable");
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
    throw new OpenSeaReadCanaryConflictError("Canary capture deletion was not authenticated");
  }
}

function receiptFromResult(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<OpenSeaReadCanaryResultEventPayloadV1>,
): OpenSeaReadCanaryReceiptV1 {
  assertResultBinding(dependencies, prepared, result);
  return {
    schemaVersion: 1,
    receiptId: `opensea-read-canary:${prepared.requestId}`,
    planId: OPENSEA_READ_CANARY_PLAN_ID,
    providerId: OPENSEA_READ_CANARY_PROVIDER_ID,
    requestId: prepared.requestId,
    requestFingerprint: prepared.requestFingerprint,
    outcome: result.outcome,
    failureCode: result.failureCode,
    acquiredAt: result.acquiredAt,
    completedAt: result.completedAt,
    collectionCount: result.collectionCount,
    byteLength: result.byteLength,
    hasNextPage: result.hasNextPage,
    rateLimit: result.rateLimit,
    maximumRequests: 1,
    maximumResults: 10,
    ledgerReserveUsdMicros: OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: result.runtime,
    capture: result.capture,
  };
}

async function finalizeResult(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  result: Readonly<OpenSeaReadCanaryResultEventPayloadV1>,
): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
  if (dependencies.eventStore.getByIdempotencyKey(failureKey(prepared.requestId)) !== undefined) {
    throw new OpenSeaReadCanaryConflictError(
      "Captured result conflicts with durable failure evidence",
    );
  }
  assertResultBinding(dependencies, prepared, result);
  closeAttemptForResult(dependencies.operationsStore, prepared, result);
  await destroyResultCapture(dependencies, result);
  return appendReceipt(dependencies.eventStore, receiptFromResult(dependencies, prepared, result));
}

function loadResult(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Readonly<OpenSeaReadCanaryResultEventPayloadV1> | null {
  const event = dependencies.eventStore.getByIdempotencyKey(resultKey(prepared.requestId));
  if (event === undefined) return null;
  const result = parseResultEvent(event);
  assertResultBinding(dependencies, prepared, result);
  return result;
}

function loadFailure(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Readonly<OpenSeaReadCanaryFailureEventPayloadV1> | null {
  const event = dependencies.eventStore.getByIdempotencyKey(failureKey(prepared.requestId));
  if (event === undefined) return null;
  const failure = parseFailureEvent(event);
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  return failure;
}

function resultCandidate(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<OpenSeaTrendingIngestionResult>,
  runtimeDenied: boolean,
): OpenSeaReadCanaryResultEventPayloadV1 {
  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state !== "committed") {
    throw new OpenSeaReadCanaryConflictError("Committed capture is unavailable");
  }
  assertOperationsAttemptBinding(
    dependencies.operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
  const runtime = runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId);
  if (runtime === null) throw new OpenSeaReadCanaryConflictError("Runtime receipt is unavailable");
  const outcome = runtimeDenied
    ? ("rejected" as const)
    : ingestion.status === "rejected"
      ? ("rejected" as const)
      : ingestion.collectionCount === 0
        ? ("empty" as const)
        : ("accepted" as const);
  return OpenSeaReadCanaryResultEventPayloadSchema.parse({
    schemaVersion: 1,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    outcome,
    failureCode: runtimeDenied
      ? "RUNTIME_DENIED"
      : ingestion.status === "rejected"
        ? (ingestion.failureCode as OpenSeaReadCanaryFailureCode)
        : null,
    acquiredAt: ingestion.acquiredAt,
    completedAt: completionTime(ingestion.acquiredAt, attempt.committedAt),
    collectionCount:
      !runtimeDenied && ingestion.status === "accepted" ? ingestion.collectionCount : null,
    byteLength: ingestion.byteLength,
    hasNextPage: !runtimeDenied && ingestion.status === "accepted" ? ingestion.hasNextPage : null,
    rateLimit: ingestion.rateLimit ?? null,
    runtime,
    capture: captureReceipt(dependencies.eventStore, prepared.attemptId),
  });
}

function persistRecoveryResult(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<OpenSeaTrendingIngestionResult>,
): Readonly<OpenSeaReadCanaryResultEventPayloadV1> {
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
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  ingestion: Readonly<OpenSeaTrendingIngestionResult>,
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">,
): Readonly<OpenSeaReadCanaryResultEventPayloadV1> {
  const candidate = resultCandidate(dependencies, prepared, ingestion, false);
  let persisted: Readonly<OpenSeaReadCanaryResultEventPayloadV1> | undefined;
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
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  error: unknown,
  overrideCode?: OpenSeaReadCanaryFailureCode,
): OpenSeaReadCanaryFailureEventPayloadV1 {
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
    throw new OpenSeaReadCanaryConflictError(
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
    throw new OpenSeaReadCanaryConflictError("Failure checkpoint time is unavailable");
  }
  return OpenSeaReadCanaryFailureEventPayloadSchema.parse({
    schemaVersion: 1,
    requestId: prepared.requestId,
    attemptId: prepared.attemptId,
    requestFingerprint: prepared.requestFingerprint,
    failureCode: overrideCode ?? safeFailureCode(error),
    completedAt,
    attemptOutcome,
    rateLimit: rateLimitFrom(error),
    runtime: runtimeReceipt(dependencies.runtime, prepared.runtimeAuthorizationId),
  });
}

function persistFailureCheckpoint(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  error: unknown,
  overrideCode?: OpenSeaReadCanaryFailureCode,
): Readonly<OpenSeaReadCanaryFailureEventPayloadV1> {
  const existing = loadFailure(dependencies, prepared);
  if (existing !== null) return existing;
  const candidate = failureCandidate(dependencies, prepared, error, overrideCode);
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
  failure: Readonly<OpenSeaReadCanaryFailureEventPayloadV1>,
): OpenSeaReadCanaryReceiptV1 {
  return {
    schemaVersion: 1,
    receiptId: `opensea-read-canary:${prepared.requestId}`,
    planId: OPENSEA_READ_CANARY_PLAN_ID,
    providerId: OPENSEA_READ_CANARY_PROVIDER_ID,
    requestId: prepared.requestId,
    requestFingerprint: prepared.requestFingerprint,
    outcome: "failed",
    failureCode: failure.failureCode,
    acquiredAt: null,
    completedAt: failure.completedAt,
    collectionCount: null,
    byteLength: null,
    hasNextPage: null,
    rateLimit: failure.rateLimit,
    maximumRequests: 1,
    maximumResults: 10,
    ledgerReserveUsdMicros: OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: failure.runtime,
    capture: null,
  };
}

function closeAttemptForFailure(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failure: Readonly<OpenSeaReadCanaryFailureEventPayloadV1>,
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
    throw new OpenSeaReadCanaryConflictError("Failure closure could not be authenticated");
  }
}

async function finalizeFailureCheckpoint(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  failure: Readonly<OpenSeaReadCanaryFailureEventPayloadV1>,
): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
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
    throw new OpenSeaReadCanaryConflictError("Failure checkpoint left active capture state");
  }
  // Re-authenticate after cleanup so a no-binding checkpoint cannot publish if
  // an ambiguous or competing reservation became visible in the meantime.
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  return appendReceipt(dependencies.eventStore, failedReceiptFromCheckpoint(prepared, failure));
}

async function terminalizeFailure(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  error: unknown,
  overrideCode?: OpenSeaReadCanaryFailureCode,
): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
  const failure = persistFailureCheckpoint(dependencies, prepared, error, overrideCode);
  return finalizeFailureCheckpoint(dependencies, prepared, failure);
}

function assertFailureReceiptBinding(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
  receipt: Readonly<OpenSeaReadCanaryReceiptV1>,
  failure: Readonly<OpenSeaReadCanaryFailureEventPayloadV1>,
): void {
  assertFailureCheckpointBinding(dependencies, prepared, failure);
  const expected = OpenSeaReadCanaryReceiptSchema.parse(
    failedReceiptFromCheckpoint(prepared, failure),
  );
  if (JSON.stringify(receipt) !== JSON.stringify(expected)) {
    throw new OpenSeaReadCanaryConflictError("Failure receipt is rebound");
  }
  const captureAttempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (captureAttempt?.state === "pending" || captureAttempt?.state === "committed") {
    throw new OpenSeaReadCanaryConflictError("Failure receipt left active capture state");
  }
}

async function recoverPreparedCanary(
  dependencies: Readonly<OpenSeaReadCanaryRecoveryOptions>,
  prepared: PreparedPayload,
): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
  const existingReceipt = dependencies.eventStore.getByIdempotencyKey(
    receiptKey(prepared.requestId),
  );
  if (existingReceipt !== undefined) {
    const receipt = parseReceiptEvent(existingReceipt);
    const durableResult = loadResult(dependencies, prepared);
    const durableFailure = loadFailure(dependencies, prepared);
    if (receipt.capture !== null) {
      if (durableResult === null || durableFailure !== null) {
        throw new OpenSeaReadCanaryConflictError("Captured receipt has no durable result evidence");
      }
      return finalizeResult(dependencies, prepared, durableResult);
    }
    if (durableResult !== null || durableFailure === null) {
      throw new OpenSeaReadCanaryConflictError(
        "Failure receipt conflicts with durable checkpoint evidence",
      );
    }
    assertFailureReceiptBinding(dependencies, prepared, receipt, durableFailure);
    return finalizeFailureCheckpoint(dependencies, prepared, durableFailure);
  }
  const durableResult = loadResult(dependencies, prepared);
  const durableFailure = loadFailure(dependencies, prepared);
  if (durableResult !== null && durableFailure !== null) {
    throw new OpenSeaReadCanaryConflictError(
      "Canary has conflicting durable result and failure checkpoints",
    );
  }
  if (durableResult !== null) return finalizeResult(dependencies, prepared, durableResult);
  if (durableFailure !== null) {
    return finalizeFailureCheckpoint(dependencies, prepared, durableFailure);
  }

  const attempt = dependencies.captureRegistry.getAttempt(prepared.attemptId);
  if (attempt?.state === "committed") {
    const ingestion = await ingestOpenSeaTrending(
      {
        captureRegistry: dependencies.captureRegistry,
        operationsStore: dependencies.operationsStore,
        store: dependencies.eventStore,
        vault: dependencies.vault,
      },
      {
        attemptId: prepared.attemptId,
        expiresAt: prepared.expiresAt,
        lane: "marketplace",
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

  return terminalizeFailure(
    dependencies,
    prepared,
    new OpenSeaReadCanaryConflictError("Interrupted canary"),
    "INTERRUPTED",
  );
}

/**
 * Completes an already-claimed canary exclusively from authenticated local
 * state. This function has no credential or transport dependency and cannot
 * issue another provider request.
 */
export async function recoverOpenSeaReadCanary(
  optionsValue: OpenSeaReadCanaryRecoveryOptions,
): Promise<Readonly<OpenSeaReadCanaryReceiptV1> | null> {
  const dependencies = exactRecoveryOptions(optionsValue);
  const preparedEvent = dependencies.eventStore.getByIdempotencyKey(PREPARED_KEY);
  if (preparedEvent === undefined) return null;
  const prepared = parsePreparedEvent(preparedEvent);
  if (dependencies.runtime.getSnapshot().processInstanceId === prepared.runtimeProcessInstanceId) {
    throw new OpenSeaReadCanaryConflictError(
      "The claimed canary still belongs to the active runtime process",
    );
  }
  return recoverPreparedCanary(dependencies, prepared);
}

export function readOpenSeaReadCanaryProjection(
  store: SqliteEventStore,
  credentialStatus: CredentialStatus,
  running = false,
): Readonly<OpenSeaReadCanaryProjectionV1> {
  if (!isSqliteEventStore(store)) {
    throw new OpenSeaReadCanaryValidationError("An authentic event store is required");
  }
  const receiptEvents = store.list({ type: RECEIPT_EVENT_TYPE, order: "desc", limit: 2 });
  if (receiptEvents.length > 1) {
    throw new OpenSeaReadCanaryConflictError("Multiple canary receipts are not allowed");
  }
  const lastReceipt = receiptEvents[0] === undefined ? null : parseReceiptEvent(receiptEvents[0]);
  const preparedEvents = store.list({ type: PREPARED_EVENT_TYPE, order: "desc", limit: 2 });
  if (preparedEvents.length > 1) {
    throw new OpenSeaReadCanaryConflictError("Multiple prepared canary claims are not allowed");
  }
  const prepared = preparedEvents[0] === undefined ? null : parsePreparedEvent(preparedEvents[0]);
  if (
    lastReceipt !== null &&
    (prepared === null ||
      lastReceipt.requestId !== prepared.requestId ||
      lastReceipt.requestFingerprint !== prepared.requestFingerprint)
  ) {
    throw new OpenSeaReadCanaryConflictError("Canary receipt does not match its prepared claim");
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
    OpenSeaReadCanaryProjectionSchema.parse({
      schemaVersion: 1,
      status,
      credentialStatus,
      plan: PLAN,
      lastReceipt,
    }),
  );
}

export class OpenSeaReadCanaryController {
  readonly #runtime: SqliteRuntimeController;
  readonly #operationsStore: SqliteOperationsStore;
  readonly #captureRegistry: SqliteCaptureRegistry;
  readonly #eventStore: SqliteEventStore;
  readonly #vault: SnapshotVault;
  #apiKey: string | null;
  #activeAbort: AbortController | null = null;
  #used = false;

  constructor(optionsValue: OpenSeaReadCanaryControllerOptions) {
    const options = exactOptions(optionsValue);
    this.#runtime = options.runtime;
    this.#operationsStore = options.operationsStore;
    this.#captureRegistry = options.captureRegistry;
    this.#eventStore = options.eventStore;
    this.#vault = options.vault;
    this.#apiKey = options.apiKey;
    AUTHENTIC_CONTROLLERS.add(this);
  }

  get running(): boolean {
    this.#assertAuthentic();
    return this.#activeAbort !== null;
  }

  getProjection(): Readonly<OpenSeaReadCanaryProjectionV1> {
    this.#assertAuthentic();
    return readOpenSeaReadCanaryProjection(this.#eventStore, "configured", this.running);
  }

  abortActive(): void {
    this.#assertAuthentic();
    this.#activeAbort?.abort();
  }

  async execute(commandValue: unknown): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    this.#assertAuthentic();
    const command = parseOpenSeaReadCanaryInput(
      OpenSeaReadCanaryRunCommandSchema,
      commandValue,
      "OpenSea read canary command",
    );
    const preparedEvent = this.#eventStore.getByIdempotencyKey(PREPARED_KEY);
    if (preparedEvent !== undefined) {
      const prepared = parsePreparedEvent(preparedEvent);
      if (
        prepared.requestId !== command.requestId ||
        prepared.expectedRuntimeRevision !== command.expectedRuntimeRevision
      ) {
        throw new OpenSeaReadCanaryConflictError(
          "The one-shot OpenSea read canary is already claimed",
        );
      }
      const existingReceipt = this.#eventStore.getByIdempotencyKey(receiptKey(command.requestId));
      if (existingReceipt !== undefined) {
        return recoverPreparedCanary(this.#recoveryDependencies(), prepared);
      }
      if (this.#activeAbort !== null) {
        throw new OpenSeaReadCanaryConflictError("An OpenSea read canary is already running");
      }
      if (this.#used || this.#apiKey === null) {
        throw new OpenSeaReadCanaryConflictError("This canary controller is one-shot");
      }
      this.#activeAbort = new AbortController();
      try {
        return await this.#resume(command, prepared);
      } finally {
        this.#apiKey = null;
        this.#used = true;
        this.#activeAbort = null;
      }
    }
    if (this.#activeAbort !== null) {
      throw new OpenSeaReadCanaryConflictError("An OpenSea read canary is already running");
    }
    if (this.#used || this.#apiKey === null) {
      throw new OpenSeaReadCanaryConflictError("This canary controller is one-shot");
    }

    this.#activeAbort = new AbortController();
    try {
      return await this.#run(command, this.#activeAbort.signal);
    } finally {
      this.#apiKey = null;
      this.#used = true;
      this.#activeAbort = null;
    }
  }

  close(): void {
    this.#assertAuthentic();
    this.#activeAbort?.abort();
    this.#apiKey = null;
    this.#used = true;
  }

  async #run(
    command: OpenSeaReadCanaryRunCommand,
    signal: AbortSignal,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    const snapshot = this.#runtime.getSnapshot();
    if (snapshot.mode === "STOPPED" || snapshot.revision !== command.expectedRuntimeRevision) {
      throw new OpenSeaReadCanaryConflictError("Runtime state changed before canary preparation");
    }

    const request = prepareOpenSeaTrendingCollectorRequest();
    if (request.fingerprint !== OPENSEA_READ_CANARY_REQUEST_FINGERPRINT) {
      throw new OpenSeaReadCanaryConflictError("Canary request fingerprint changed");
    }
    const permit = SqliteOperationsStore.createAttemptPermit();
    const runtimeAuthorization = this.#runtime.requestBoundaryAuthorization({
      actionId: openSeaTrendingRuntimeActionId(permit.attemptId, request.fingerprint),
      authorizationId: randomUUID(),
      boundary: "research_collection",
    });
    if (
      runtimeAuthorization.requestedRevision !== command.expectedRuntimeRevision ||
      runtimeAuthorization.requestedMode === "STOPPED"
    ) {
      throw new OpenSeaReadCanaryConflictError("Runtime state changed before canary authorization");
    }

    const budgetId = randomUUID();
    const prepared = OpenSeaReadCanaryPreparedEventPayloadSchema.parse({
      schemaVersion: 1,
      planId: OPENSEA_READ_CANARY_PLAN_ID,
      providerId: OPENSEA_READ_CANARY_PROVIDER_ID,
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
      ledgerReserveUsdMicros: OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
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
      throw new OpenSeaReadCanaryConflictError(
        "The one-shot OpenSea read canary was claimed concurrently",
      );
    }

    try {
      this.#operationsStore.createBudget({
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        currency: "USD_MICRO",
        endsAt: runtimeAuthorization.expiresAt,
        maxAtomic: OPENSEA_TRENDING_RESERVED_ATOMIC,
        maxAttempts: 1,
        profile: "canary",
        startsAt: runtimeAuthorization.requestedAt,
      });
      this.#operationsStore.reserveAttempt({
        attemptId: permit.attemptId,
        authorizationExpiresAt: runtimeAuthorization.expiresAt,
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        idempotencyKey: `opensea-read-canary:${command.requestId}`,
        lane: "marketplace",
        operation: "opensea.trending-collections.v1",
        permitToken: permit.token,
        reservedAtomic: OPENSEA_TRENDING_RESERVED_ATOMIC,
        sessionId: command.requestId,
        sourcePlane: "marketplace",
      });
      const networkAuthorization = this.#operationsStore.createNetworkAttemptAuthorization(permit);
      const apiKey = this.#apiKey;
      if (apiKey === null)
        throw new OpenSeaReadCanaryConflictError("Canary credential is unavailable");
      const collector = createOpenSeaTrendingCollector({
        attemptAuthorization: networkAuthorization,
        apiKey,
        runtimeAuthorization,
      });
      const result = await ingestOpenSeaTrending(
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
          lane: "marketplace",
          profile: "canary",
          sessionId: command.requestId,
        },
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
    command: OpenSeaReadCanaryRunCommand,
    prepared: PreparedPayload,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    if (
      prepared.requestId !== command.requestId ||
      prepared.expectedRuntimeRevision !== command.expectedRuntimeRevision
    ) {
      throw new OpenSeaReadCanaryConflictError("Canary command is rebound");
    }
    if (this.#runtime.getSnapshot().processInstanceId === prepared.runtimeProcessInstanceId) {
      throw new OpenSeaReadCanaryConflictError("The claimed canary is still owned by this runtime");
    }
    return recoverPreparedCanary(this.#recoveryDependencies(), prepared);
  }

  async #complete(
    prepared: PreparedPayload,
    result: Readonly<OpenSeaTrendingIngestionResult>,
    runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    const dependencies = this.#recoveryDependencies();
    return finalizeResult(
      dependencies,
      prepared,
      persistLiveResult(dependencies, prepared, result, runtimeAuthorization),
    );
  }

  #recoveryDependencies(): OpenSeaReadCanaryRecoveryOptions {
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
      Object.getPrototypeOf(this) !== OpenSeaReadCanaryController.prototype
    ) {
      throw new OpenSeaReadCanaryConflictError("OpenSea read canary controller is not authentic");
    }
  }
}

Object.freeze(OpenSeaReadCanaryController.prototype);
Object.freeze(OpenSeaReadCanaryController);

export function isOpenSeaReadCanaryController(
  value: unknown,
): value is OpenSeaReadCanaryController {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_CONTROLLERS.has(value) &&
    Object.getPrototypeOf(value) === OpenSeaReadCanaryController.prototype
  );
}
