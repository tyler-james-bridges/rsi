import { types as utilTypes } from "node:util";

import type {
  XReadCanaryProjectionV1,
  XReadCanaryReceiptV1,
  XReadCanaryRunCommand,
} from "@rsi/read-canary";

export const OPERATOR_X_READ_CANARY_PLAN_ID = "x-nft-market-pulse-v1" as const;
export const OPERATOR_X_READ_CANARY_MAXIMUM_REQUESTS = 1 as const;
export const OPERATOR_X_READ_CANARY_MAXIMUM_RESULTS = 10 as const;
export const OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS = "50000" as const;

const PROVIDER_ID = "x-api-v2" as const;
const OPERATION = "x.recent-search.v1" as const;
const ENDPOINT = "https://api.x.com/2/tweets/search/recent" as const;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const FAILURE_CODES = new Set([
  "INVALID_CONFIGURATION",
  "INVALID_CREDENTIAL",
  "INVALID_QUERY",
  "RUNTIME_AUTHORIZATION_FAILED",
  "ATTEMPT_AUTHORIZATION_FAILED",
  "CLOCK_REGRESSION",
  "ABORTED",
  "TIMEOUT",
  "TRANSPORT_FAILURE",
  "REDIRECT_REFUSED",
  "HTTP_STATUS",
  "UNSUPPORTED_CONTENT_ENCODING",
  "UNSUPPORTED_CONTENT_TYPE",
  "RESPONSE_TOO_LARGE",
  "CONTENT_LENGTH_MISMATCH",
  "CREDENTIAL_IN_REQUEST",
  "CREDENTIAL_IN_RESPONSE",
  "MALFORMED_JSON",
  "INVALID_RESPONSE_SCHEMA",
  "PARTIAL_RESPONSE",
  "INVALID_RATE_LIMIT_METADATA",
  "CASSETTE_MISS",
  "INVALID_CASSETTE",
  "CASSETTE_STORAGE_FAILURE",
  "CAPTURE_REJECTED",
  "CREDENTIAL_UNAVAILABLE",
  "DURABLE_STATE_FAILURE",
  "INTERRUPTED",
  "RUNTIME_DENIED",
  "UNKNOWN_FAILURE",
]);

export interface OperatorReadCanaryProvider {
  /** Returns only the closed, content-free Stage 1 projection. */
  getReadCanaryProjection():
    Promise<Readonly<XReadCanaryProjectionV1>> | Readonly<XReadCanaryProjectionV1>;
  /** Executes the one-shot canary. Credentials remain behind the provider boundary. */
  executeReadCanary(
    command: Readonly<XReadCanaryRunCommand>,
  ): Promise<Readonly<XReadCanaryReceiptV1>> | Readonly<XReadCanaryReceiptV1>;
  /** Synchronous best-effort interruption used before the runtime persists STOPPED. */
  abortActive(): void;
}

function strictRecord(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError(`${label} is invalid`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`${label} is invalid`);
    }
    record[key] = descriptor.value;
  }
  return record;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_TIMESTAMP.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function integerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}

function parsePlan(value: unknown): XReadCanaryProjectionV1["plan"] {
  const plan = strictRecord(
    value,
    [
      "schemaVersion",
      "planId",
      "providerId",
      "operation",
      "endpoint",
      "method",
      "sortOrder",
      "maximumRequests",
      "maximumResults",
      "maximumChargeUsdMicros",
      "requestFingerprint",
      "rawContentDisposition",
      "automaticRetries",
    ],
    "Read canary plan",
  );
  if (
    plan.schemaVersion !== 1 ||
    plan.planId !== OPERATOR_X_READ_CANARY_PLAN_ID ||
    plan.providerId !== PROVIDER_ID ||
    plan.operation !== OPERATION ||
    plan.endpoint !== ENDPOINT ||
    plan.method !== "GET" ||
    plan.sortOrder !== "recency" ||
    plan.maximumRequests !== OPERATOR_X_READ_CANARY_MAXIMUM_REQUESTS ||
    plan.maximumResults !== OPERATOR_X_READ_CANARY_MAXIMUM_RESULTS ||
    plan.maximumChargeUsdMicros !== OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS ||
    typeof plan.requestFingerprint !== "string" ||
    !SHA256.test(plan.requestFingerprint) ||
    plan.rawContentDisposition !== "encrypted_ephemeral" ||
    plan.automaticRetries !== 0
  ) {
    throw new TypeError("Read canary plan is invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    planId: OPERATOR_X_READ_CANARY_PLAN_ID,
    providerId: PROVIDER_ID,
    operation: OPERATION,
    endpoint: ENDPOINT,
    method: "GET",
    sortOrder: "recency",
    maximumRequests: OPERATOR_X_READ_CANARY_MAXIMUM_REQUESTS,
    maximumResults: OPERATOR_X_READ_CANARY_MAXIMUM_RESULTS,
    maximumChargeUsdMicros: OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS,
    requestFingerprint: plan.requestFingerprint as `sha256:${string}`,
    rawContentDisposition: "encrypted_ephemeral",
    automaticRetries: 0,
  });
}

function parseRateLimit(value: unknown): XReadCanaryReceiptV1["rateLimit"] {
  if (value === null) return null;
  const rateLimit = strictRecord(
    value,
    ["limit", "remaining", "resetAtUnixSeconds"],
    "Read canary rate limit",
  );
  if (
    !integerInRange(rateLimit.limit, 1, Number.MAX_SAFE_INTEGER) ||
    !integerInRange(rateLimit.remaining, 0, Number.MAX_SAFE_INTEGER) ||
    Number(rateLimit.remaining) > Number(rateLimit.limit) ||
    !integerInRange(rateLimit.resetAtUnixSeconds, 0, Number.MAX_SAFE_INTEGER)
  ) {
    throw new TypeError("Read canary rate limit is invalid");
  }
  return Object.freeze({
    limit: Number(rateLimit.limit),
    remaining: Number(rateLimit.remaining),
    resetAtUnixSeconds: Number(rateLimit.resetAtUnixSeconds),
  });
}

function parseRuntimeReceipt(value: unknown): XReadCanaryReceiptV1["runtime"] {
  if (value === null) return null;
  const runtime = strictRecord(
    value,
    ["authorizationId", "eventHash", "eventSequence", "modeRevision"],
    "Read canary runtime receipt",
  );
  if (
    typeof runtime.authorizationId !== "string" ||
    !UUID_V4.test(runtime.authorizationId) ||
    typeof runtime.eventHash !== "string" ||
    !LOWER_HEX_64.test(runtime.eventHash) ||
    !integerInRange(runtime.eventSequence, 1, Number.MAX_SAFE_INTEGER) ||
    !integerInRange(runtime.modeRevision, 1, Number.MAX_SAFE_INTEGER)
  ) {
    throw new TypeError("Read canary runtime receipt is invalid");
  }
  return Object.freeze({
    authorizationId: runtime.authorizationId,
    eventHash: runtime.eventHash,
    eventSequence: Number(runtime.eventSequence),
    modeRevision: Number(runtime.modeRevision),
  });
}

function parseCaptureReceipt(value: unknown): XReadCanaryReceiptV1["capture"] {
  if (value === null) return null;
  const capture = strictRecord(
    value,
    ["eventHash", "eventSequence"],
    "Read canary capture receipt",
  );
  if (
    typeof capture.eventHash !== "string" ||
    !LOWER_HEX_64.test(capture.eventHash) ||
    !integerInRange(capture.eventSequence, 1, Number.MAX_SAFE_INTEGER)
  ) {
    throw new TypeError("Read canary capture receipt is invalid");
  }
  return Object.freeze({
    eventHash: capture.eventHash,
    eventSequence: Number(capture.eventSequence),
  });
}

export function parseOperatorReadCanaryReceipt(value: unknown): Readonly<XReadCanaryReceiptV1> {
  const receipt = strictRecord(
    value,
    [
      "schemaVersion",
      "receiptId",
      "planId",
      "providerId",
      "requestId",
      "attemptId",
      "requestFingerprint",
      "outcome",
      "failureCode",
      "acquiredAt",
      "completedAt",
      "postCount",
      "byteLength",
      "hasNextPage",
      "rateLimit",
      "maximumRequests",
      "maximumResults",
      "maximumChargeUsdMicros",
      "actualChargeUsdMicros",
      "runtime",
      "capture",
    ],
    "Read canary receipt",
  );
  const outcomes = new Set(["accepted", "empty", "failed", "rejected"]);
  const succeeded = receipt.outcome === "accepted" || receipt.outcome === "empty";
  const captured = succeeded || receipt.outcome === "rejected";
  if (
    receipt.schemaVersion !== 1 ||
    typeof receipt.requestId !== "string" ||
    !UUID_V4.test(receipt.requestId) ||
    receipt.receiptId !== `x-read-canary:${receipt.requestId}` ||
    receipt.planId !== OPERATOR_X_READ_CANARY_PLAN_ID ||
    receipt.providerId !== PROVIDER_ID ||
    typeof receipt.attemptId !== "string" ||
    !UUID_V4.test(receipt.attemptId) ||
    typeof receipt.requestFingerprint !== "string" ||
    !SHA256.test(receipt.requestFingerprint) ||
    typeof receipt.outcome !== "string" ||
    !outcomes.has(receipt.outcome) ||
    (receipt.failureCode !== null &&
      (typeof receipt.failureCode !== "string" || !FAILURE_CODES.has(receipt.failureCode))) ||
    (receipt.acquiredAt !== null && !canonicalTimestamp(receipt.acquiredAt)) ||
    !canonicalTimestamp(receipt.completedAt) ||
    (receipt.postCount !== null &&
      !integerInRange(receipt.postCount, 0, OPERATOR_X_READ_CANARY_MAXIMUM_RESULTS)) ||
    (receipt.byteLength !== null && !integerInRange(receipt.byteLength, 0, 1_048_576)) ||
    (receipt.hasNextPage !== null && typeof receipt.hasNextPage !== "boolean") ||
    receipt.maximumRequests !== OPERATOR_X_READ_CANARY_MAXIMUM_REQUESTS ||
    receipt.maximumResults !== OPERATOR_X_READ_CANARY_MAXIMUM_RESULTS ||
    receipt.maximumChargeUsdMicros !== OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS ||
    receipt.actualChargeUsdMicros !== null ||
    succeeded !== (receipt.failureCode === null) ||
    captured !== (receipt.acquiredAt !== null) ||
    captured !== (receipt.byteLength !== null) ||
    (succeeded && receipt.postCount === null) ||
    (!succeeded && receipt.postCount !== null) ||
    (succeeded && receipt.hasNextPage === null) ||
    (!succeeded && receipt.hasNextPage !== null) ||
    (receipt.outcome === "empty" && receipt.postCount !== 0) ||
    (receipt.outcome === "accepted" && Number(receipt.postCount) < 1) ||
    (receipt.acquiredAt !== null &&
      Date.parse(receipt.completedAt) < Date.parse(receipt.acquiredAt))
  ) {
    throw new TypeError("Read canary receipt is invalid");
  }

  const runtime = parseRuntimeReceipt(receipt.runtime);
  const capture = parseCaptureReceipt(receipt.capture);
  if (captured !== (capture !== null) || (captured && runtime === null)) {
    throw new TypeError("Read canary receipt is invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    receiptId: receipt.receiptId as string,
    planId: OPERATOR_X_READ_CANARY_PLAN_ID,
    providerId: PROVIDER_ID,
    requestId: receipt.requestId,
    attemptId: receipt.attemptId,
    requestFingerprint: receipt.requestFingerprint as `sha256:${string}`,
    outcome: receipt.outcome as XReadCanaryReceiptV1["outcome"],
    failureCode: receipt.failureCode as XReadCanaryReceiptV1["failureCode"],
    acquiredAt: receipt.acquiredAt as string | null,
    completedAt: receipt.completedAt,
    postCount: receipt.postCount as number | null,
    byteLength: receipt.byteLength as number | null,
    hasNextPage: receipt.hasNextPage as boolean | null,
    rateLimit: parseRateLimit(receipt.rateLimit),
    maximumRequests: OPERATOR_X_READ_CANARY_MAXIMUM_REQUESTS,
    maximumResults: OPERATOR_X_READ_CANARY_MAXIMUM_RESULTS,
    maximumChargeUsdMicros: OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS,
    actualChargeUsdMicros: null,
    runtime,
    capture,
  });
}

export function parseOperatorReadCanaryProjection(
  value: unknown,
): Readonly<XReadCanaryProjectionV1> {
  const projection = strictRecord(
    value,
    ["schemaVersion", "status", "credentialStatus", "plan", "lastReceipt"],
    "Read canary projection",
  );
  const statuses = new Set([
    "uncommissioned",
    "ready",
    "running",
    "completed",
    "failed",
    "interrupted",
  ]);
  const credentialStatuses = new Set(["configured", "missing", "unknown"]);
  if (
    projection.schemaVersion !== 1 ||
    typeof projection.status !== "string" ||
    !statuses.has(projection.status) ||
    typeof projection.credentialStatus !== "string" ||
    !credentialStatuses.has(projection.credentialStatus)
  ) {
    throw new TypeError("Read canary projection is invalid");
  }
  const plan = parsePlan(projection.plan);
  const lastReceipt =
    projection.lastReceipt === null ? null : parseOperatorReadCanaryReceipt(projection.lastReceipt);
  if (lastReceipt !== null && lastReceipt.requestFingerprint !== plan.requestFingerprint) {
    throw new TypeError("Read canary projection is invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    status: projection.status as XReadCanaryProjectionV1["status"],
    credentialStatus: projection.credentialStatus as XReadCanaryProjectionV1["credentialStatus"],
    plan,
    lastReceipt,
  });
}

export function parseOperatorReadCanaryCommand(value: unknown): Readonly<XReadCanaryRunCommand> {
  const command = strictRecord(
    value,
    [
      "schemaVersion",
      "planId",
      "expectedRuntimeRevision",
      "requestId",
      "typedPlanIdAcknowledgement",
      "oneRequestAcknowledgement",
      "maximumChargeUsdMicrosAcknowledgement",
    ],
    "Read canary command",
  );
  if (
    command.schemaVersion !== 1 ||
    command.planId !== OPERATOR_X_READ_CANARY_PLAN_ID ||
    !integerInRange(command.expectedRuntimeRevision, 1, Number.MAX_SAFE_INTEGER) ||
    typeof command.requestId !== "string" ||
    !UUID_V4.test(command.requestId) ||
    command.typedPlanIdAcknowledgement !== OPERATOR_X_READ_CANARY_PLAN_ID ||
    command.oneRequestAcknowledgement !== true ||
    command.maximumChargeUsdMicrosAcknowledgement !==
      OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS
  ) {
    throw new TypeError("Read canary command is invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    planId: OPERATOR_X_READ_CANARY_PLAN_ID,
    expectedRuntimeRevision: Number(command.expectedRuntimeRevision),
    requestId: command.requestId,
    typedPlanIdAcknowledgement: OPERATOR_X_READ_CANARY_PLAN_ID,
    oneRequestAcknowledgement: true,
    maximumChargeUsdMicrosAcknowledgement: OPERATOR_X_READ_CANARY_MAXIMUM_CHARGE_USD_MICROS,
  });
}
