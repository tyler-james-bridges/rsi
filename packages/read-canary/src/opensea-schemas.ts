import { types as utilTypes } from "node:util";

import { OPENSEA_TRENDING_MAXIMUM_BYTES } from "@rsi/opensea-collector";
import { z } from "zod";

import {
  OPENSEA_READ_CANARY_ENDPOINT,
  OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  OPENSEA_READ_CANARY_MAXIMUM_REQUESTS,
  OPENSEA_READ_CANARY_MAXIMUM_RESULTS,
  OPENSEA_READ_CANARY_OPERATION,
  OPENSEA_READ_CANARY_PLAN_ID,
  OPENSEA_READ_CANARY_PROFILE,
  OPENSEA_READ_CANARY_PROVIDER_ID,
  OPENSEA_READ_CANARY_REQUEST_FINGERPRINT,
} from "./opensea-constants.js";

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

export const OpenSeaReadCanaryPlanSchema = z.strictObject({
  schemaVersion: z.literal(1),
  planId: z.literal(OPENSEA_READ_CANARY_PLAN_ID),
  providerId: z.literal(OPENSEA_READ_CANARY_PROVIDER_ID),
  operation: z.literal(OPENSEA_READ_CANARY_OPERATION),
  profile: z.literal(OPENSEA_READ_CANARY_PROFILE),
  endpoint: z.literal(OPENSEA_READ_CANARY_ENDPOINT),
  method: z.literal("GET"),
  chain: z.literal("base"),
  timeframe: z.literal("one_day"),
  maximumRequests: z.literal(OPENSEA_READ_CANARY_MAXIMUM_REQUESTS),
  maximumResults: z.literal(OPENSEA_READ_CANARY_MAXIMUM_RESULTS),
  ledgerReserveUsdMicros: z.literal(OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
  actualChargeUsdMicros: z.null(),
  requestFingerprint: z.literal(OPENSEA_READ_CANARY_REQUEST_FINGERPRINT),
  rawContentDisposition: z.literal("encrypted_ephemeral"),
  automaticRetries: z.literal(0),
  automaticPagination: z.literal(false),
});

export const OpenSeaReadCanaryRunCommandSchema = z.strictObject({
  schemaVersion: z.literal(1),
  planId: z.literal(OPENSEA_READ_CANARY_PLAN_ID),
  expectedRuntimeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  requestId: UuidSchema,
  typedPlanIdAcknowledgement: z.literal(OPENSEA_READ_CANARY_PLAN_ID),
  oneRequestAcknowledgement: z.literal(true),
  nonPaymentReadAcknowledgement: z.literal(true),
  ledgerReserveUsdMicrosAcknowledgement: z.literal(OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
});

export const OpenSeaReadCanaryPreparedEventPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    planId: z.literal(OPENSEA_READ_CANARY_PLAN_ID),
    providerId: z.literal(OPENSEA_READ_CANARY_PROVIDER_ID),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    budgetId: UuidSchema,
    expectedRuntimeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    runtimeAuthorizationId: UuidSchema,
    runtimeProcessInstanceId: UuidSchema,
    requestFingerprint: z.literal(OPENSEA_READ_CANARY_REQUEST_FINGERPRINT),
    preparedAt: CanonicalTimestampSchema,
    expiresAt: CanonicalTimestampSchema,
    maximumRequests: z.literal(OPENSEA_READ_CANARY_MAXIMUM_REQUESTS),
    maximumResults: z.literal(OPENSEA_READ_CANARY_MAXIMUM_RESULTS),
    ledgerReserveUsdMicros: z.literal(OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
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

export const OpenSeaReadCanaryFailureCodeSchema = z.enum([
  "INVALID_CONFIGURATION",
  "INVALID_CREDENTIAL",
  "RUNTIME_AUTHORIZATION_FAILED",
  "ATTEMPT_AUTHORIZATION_FAILED",
  "CLOCK_REGRESSION",
  "ABORTED",
  "TIMEOUT",
  "TRANSPORT_FAILURE",
  "REDIRECT_REFUSED",
  "PAYMENT_REQUIRED",
  "HTTP_STATUS",
  "UNSUPPORTED_CONTENT_ENCODING",
  "UNSUPPORTED_CONTENT_TYPE",
  "INVALID_RATE_LIMIT_METADATA",
  "RESPONSE_TOO_LARGE",
  "CONTENT_LENGTH_MISMATCH",
  "CREDENTIAL_IN_REQUEST",
  "CREDENTIAL_IN_RESPONSE",
  "INVALID_RESPONSE_SCHEMA",
  "CAPTURE_REJECTED",
  "CREDENTIAL_UNAVAILABLE",
  "DURABLE_STATE_FAILURE",
  "INTERRUPTED",
  "RUNTIME_DENIED",
  "UNKNOWN_FAILURE",
]);

export const OpenSeaReadCanaryReceiptSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    receiptId: z.string().regex(/^opensea-read-canary:[0-9a-f-]{36}$/),
    planId: z.literal(OPENSEA_READ_CANARY_PLAN_ID),
    providerId: z.literal(OPENSEA_READ_CANARY_PROVIDER_ID),
    requestId: UuidSchema,
    requestFingerprint: z.literal(OPENSEA_READ_CANARY_REQUEST_FINGERPRINT),
    outcome: z.enum(["accepted", "empty", "failed", "rejected"]),
    failureCode: OpenSeaReadCanaryFailureCodeSchema.nullable(),
    acquiredAt: CanonicalTimestampSchema.nullable(),
    completedAt: CanonicalTimestampSchema,
    collectionCount: z.number().int().min(0).max(OPENSEA_READ_CANARY_MAXIMUM_RESULTS).nullable(),
    byteLength: z.number().int().nonnegative().max(OPENSEA_TRENDING_MAXIMUM_BYTES).nullable(),
    hasNextPage: z.boolean().nullable(),
    rateLimit: RateLimitSchema.nullable(),
    maximumRequests: z.literal(OPENSEA_READ_CANARY_MAXIMUM_REQUESTS),
    maximumResults: z.literal(OPENSEA_READ_CANARY_MAXIMUM_RESULTS),
    ledgerReserveUsdMicros: z.literal(OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
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
      (succeeded && receipt.collectionCount === null) ||
      (!succeeded && receipt.collectionCount !== null) ||
      (succeeded && receipt.hasNextPage === null) ||
      (!succeeded && receipt.hasNextPage !== null) ||
      (captured && receipt.runtime === null) ||
      (receipt.outcome === "empty" && receipt.collectionCount !== 0) ||
      (receipt.outcome === "accepted" && (receipt.collectionCount ?? 0) < 1) ||
      (receipt.outcome === "rejected" && receipt.failureCode === null) ||
      (receipt.outcome === "failed" && receipt.failureCode === null) ||
      receipt.receiptId !== `opensea-read-canary:${receipt.requestId}`
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

/** Internal content-free checkpoint; it contains no provider identifiers or Vault capture ID. */
export const OpenSeaReadCanaryResultEventPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    requestFingerprint: z.literal(OPENSEA_READ_CANARY_REQUEST_FINGERPRINT),
    outcome: z.enum(["accepted", "empty", "rejected"]),
    failureCode: OpenSeaReadCanaryFailureCodeSchema.nullable(),
    acquiredAt: CanonicalTimestampSchema,
    completedAt: CanonicalTimestampSchema,
    collectionCount: z.number().int().min(0).max(OPENSEA_READ_CANARY_MAXIMUM_RESULTS).nullable(),
    byteLength: z.number().int().nonnegative().max(OPENSEA_TRENDING_MAXIMUM_BYTES),
    hasNextPage: z.boolean().nullable(),
    rateLimit: RateLimitSchema.nullable(),
    runtime: RuntimeReceiptSchema,
    capture: CaptureReceiptSchema,
  })
  .superRefine((result, context) => {
    const succeeded = result.outcome === "accepted" || result.outcome === "empty";
    if (
      succeeded !== (result.failureCode === null) ||
      (succeeded && (result.collectionCount === null || result.hasNextPage === null)) ||
      (!succeeded && (result.collectionCount !== null || result.hasNextPage !== null)) ||
      (result.outcome === "empty" && result.collectionCount !== 0) ||
      (result.outcome === "accepted" && (result.collectionCount ?? 0) < 1) ||
      Date.parse(result.completedAt) < Date.parse(result.acquiredAt)
    ) {
      context.addIssue({ code: "custom", message: "canary result fields disagree" });
    }
  });

/**
 * Internal content-free checkpoint for a request that produced no committed
 * capture. It preserves only the closed failure classification and sanitized
 * rate-limit/runtime evidence needed for exact restart recovery.
 */
export const OpenSeaReadCanaryFailureEventPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  requestId: UuidSchema,
  attemptId: UuidSchema,
  requestFingerprint: z.literal(OPENSEA_READ_CANARY_REQUEST_FINGERPRINT),
  failureCode: OpenSeaReadCanaryFailureCodeSchema,
  completedAt: CanonicalTimestampSchema,
  attemptOutcome: z.enum(["aborted", "failed"]).nullable(),
  rateLimit: RateLimitSchema.nullable(),
  runtime: RuntimeReceiptSchema.nullable(),
});

export const OpenSeaReadCanaryProjectionSchema = z.strictObject({
  schemaVersion: z.literal(1),
  status: z.enum(["uncommissioned", "ready", "running", "completed", "failed", "interrupted"]),
  credentialStatus: z.enum(["configured", "missing", "unknown"]),
  plan: OpenSeaReadCanaryPlanSchema,
  lastReceipt: OpenSeaReadCanaryReceiptSchema.nullable(),
});

export function parseOpenSeaReadCanaryInput<T>(
  schema: z.ZodType<T>,
  value: unknown,
  label: string,
): T {
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
