import { types as utilTypes } from "node:util";

import { z } from "zod";

import {
  X_READ_CANARY_ENDPOINT,
  X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO,
  X_READ_CANARY_MAXIMUM_REQUESTS,
  X_READ_CANARY_MAXIMUM_RESULTS,
  X_READ_CANARY_OPERATION,
  X_READ_CANARY_PLAN_ID,
  X_READ_CANARY_PROVIDER_ID,
  X_READ_CANARY_REQUEST_FINGERPRINT,
  X_READ_CANARY_SORT_ORDER,
} from "./constants.js";

const CanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  });
const UuidSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const LowerHex64Schema = z.string().regex(/^[0-9a-f]{64}$/);

export const XReadCanaryPlanSchema = z.strictObject({
  schemaVersion: z.literal(1),
  planId: z.literal(X_READ_CANARY_PLAN_ID),
  providerId: z.literal(X_READ_CANARY_PROVIDER_ID),
  operation: z.literal(X_READ_CANARY_OPERATION),
  endpoint: z.literal(X_READ_CANARY_ENDPOINT),
  method: z.literal("GET"),
  sortOrder: z.literal(X_READ_CANARY_SORT_ORDER),
  maximumRequests: z.literal(X_READ_CANARY_MAXIMUM_REQUESTS),
  maximumResults: z.literal(X_READ_CANARY_MAXIMUM_RESULTS),
  maximumChargeUsdMicros: z.literal(X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO),
  requestFingerprint: z.literal(X_READ_CANARY_REQUEST_FINGERPRINT),
  rawContentDisposition: z.literal("encrypted_ephemeral"),
  automaticRetries: z.literal(0),
});

export const XReadCanaryRunCommandSchema = z.strictObject({
  schemaVersion: z.literal(1),
  planId: z.literal(X_READ_CANARY_PLAN_ID),
  expectedRuntimeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  requestId: UuidSchema,
  typedPlanIdAcknowledgement: z.literal(X_READ_CANARY_PLAN_ID),
  oneRequestAcknowledgement: z.literal(true),
  maximumChargeUsdMicrosAcknowledgement: z.literal(X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO),
});

export const XReadCanaryPreparedEventPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    planId: z.literal(X_READ_CANARY_PLAN_ID),
    providerId: z.literal(X_READ_CANARY_PROVIDER_ID),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    budgetId: UuidSchema,
    expectedRuntimeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    runtimeAuthorizationId: UuidSchema,
    runtimeProcessInstanceId: UuidSchema,
    requestFingerprint: z.literal(X_READ_CANARY_REQUEST_FINGERPRINT),
    preparedAt: CanonicalTimestampSchema,
    expiresAt: CanonicalTimestampSchema,
    maximumRequests: z.literal(X_READ_CANARY_MAXIMUM_REQUESTS),
    maximumResults: z.literal(X_READ_CANARY_MAXIMUM_RESULTS),
    maximumChargeUsdMicros: z.literal(X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO),
  })
  .refine((value) => Date.parse(value.expiresAt) > Date.parse(value.preparedAt), {
    message: "canary authorization must expire after preparation",
  });

const RateLimitSchema = z
  .strictObject({
    limit: z.number().int().min(1),
    remaining: z.number().int().nonnegative(),
    resetAtUnixSeconds: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  })
  .refine((value) => value.remaining <= value.limit, {
    message: "rate-limit remaining cannot exceed limit",
  });

const RuntimeReceiptSchema = z.strictObject({
  authorizationId: UuidSchema,
  eventHash: LowerHex64Schema,
  eventSequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  modeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
});

const CaptureReceiptSchema = z.strictObject({
  eventHash: LowerHex64Schema,
  eventSequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
});

export const XReadCanaryFailureCodeSchema = z.enum([
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

export const XReadCanaryReceiptSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    receiptId: z.string().regex(/^x-read-canary:[0-9a-f-]{36}$/),
    planId: z.literal(X_READ_CANARY_PLAN_ID),
    providerId: z.literal(X_READ_CANARY_PROVIDER_ID),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    requestFingerprint: z.literal(X_READ_CANARY_REQUEST_FINGERPRINT),
    outcome: z.enum(["accepted", "empty", "failed", "rejected"]),
    failureCode: XReadCanaryFailureCodeSchema.nullable(),
    acquiredAt: CanonicalTimestampSchema.nullable(),
    completedAt: CanonicalTimestampSchema,
    postCount: z.number().int().min(0).max(X_READ_CANARY_MAXIMUM_RESULTS).nullable(),
    byteLength: z.number().int().nonnegative().max(1_048_576).nullable(),
    hasNextPage: z.boolean().nullable(),
    rateLimit: RateLimitSchema.nullable(),
    maximumRequests: z.literal(X_READ_CANARY_MAXIMUM_REQUESTS),
    maximumResults: z.literal(X_READ_CANARY_MAXIMUM_RESULTS),
    maximumChargeUsdMicros: z.literal(X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO),
    actualChargeUsdMicros: z.null(),
    runtime: RuntimeReceiptSchema.nullable(),
    capture: CaptureReceiptSchema.nullable(),
  })
  .superRefine((receipt, context) => {
    const succeeded = receipt.outcome === "accepted" || receipt.outcome === "empty";
    const captured = succeeded || receipt.outcome === "rejected";
    if (
      succeeded !== (receipt.failureCode === null) ||
      captured !== (receipt.acquiredAt !== null) ||
      captured !== (receipt.byteLength !== null) ||
      captured !== (receipt.capture !== null) ||
      (succeeded && receipt.postCount === null) ||
      (!succeeded && receipt.postCount !== null) ||
      (succeeded && receipt.hasNextPage === null) ||
      (!succeeded && receipt.hasNextPage !== null) ||
      (captured && receipt.runtime === null) ||
      (receipt.outcome === "empty" && receipt.postCount !== 0) ||
      (receipt.outcome === "accepted" && (receipt.postCount ?? 0) < 1) ||
      (receipt.outcome === "rejected" && receipt.failureCode === null) ||
      (receipt.outcome === "failed" && receipt.failureCode === null) ||
      receipt.receiptId !== `x-read-canary:${receipt.requestId}`
    ) {
      context.addIssue({ code: "custom", message: "canary receipt fields disagree" });
    }
    if (
      receipt.acquiredAt !== null &&
      Date.parse(receipt.completedAt) < Date.parse(receipt.acquiredAt)
    ) {
      context.addIssue({ code: "custom", message: "completedAt predates acquiredAt" });
    }
  });

/**
 * Durable, content-free checkpoint written after projection and before raw-capture
 * destruction. It contains every fact needed to finish the one-shot lifecycle
 * after a process crash without another provider request.
 */
export const XReadCanaryResultEventPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    requestFingerprint: z.literal(X_READ_CANARY_REQUEST_FINGERPRINT),
    outcome: z.enum(["accepted", "empty", "rejected"]),
    failureCode: XReadCanaryFailureCodeSchema.nullable(),
    acquiredAt: CanonicalTimestampSchema,
    completedAt: CanonicalTimestampSchema,
    postCount: z.number().int().min(0).max(X_READ_CANARY_MAXIMUM_RESULTS).nullable(),
    byteLength: z.number().int().nonnegative().max(1_048_576),
    hasNextPage: z.boolean().nullable(),
    rateLimit: RateLimitSchema.nullable(),
    runtime: RuntimeReceiptSchema,
    capture: CaptureReceiptSchema,
  })
  .superRefine((result, context) => {
    const succeeded = result.outcome === "accepted" || result.outcome === "empty";
    if (
      succeeded !== (result.failureCode === null) ||
      (succeeded && (result.postCount === null || result.hasNextPage === null)) ||
      (!succeeded && (result.postCount !== null || result.hasNextPage !== null)) ||
      (result.outcome === "empty" && result.postCount !== 0) ||
      (result.outcome === "accepted" && (result.postCount ?? 0) < 1) ||
      Date.parse(result.completedAt) < Date.parse(result.acquiredAt)
    ) {
      context.addIssue({ code: "custom", message: "canary result fields disagree" });
    }
  });

export const XReadCanaryProjectionSchema = z.strictObject({
  schemaVersion: z.literal(1),
  status: z.enum(["uncommissioned", "ready", "running", "completed", "failed", "interrupted"]),
  credentialStatus: z.enum(["configured", "missing", "unknown"]),
  plan: XReadCanaryPlanSchema,
  lastReceipt: XReadCanaryReceiptSchema.nullable(),
});

export function parseXReadCanaryInput<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    assertPlainData(value, new WeakSet<object>());
    const result = schema.safeParse(value);
    if (!result.success) throw new TypeError(`${label} is invalid`);
    return result.data;
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`${label} is invalid`);
  }
}

function assertPlainData(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value) || ancestors.has(value)) throw new TypeError();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== (Array.isArray(value) ? Array.prototype : Object.prototype)) {
    throw new TypeError();
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.length !== value.length + 1 ||
        keys.at(-1) !== "length" ||
        keys.slice(0, -1).some((key, index) => key !== String(index))
      ) {
        throw new TypeError();
      }
      for (const item of value) assertPlainData(item, ancestors);
      return;
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new TypeError();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError();
      }
      assertPlainData(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}
