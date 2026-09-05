import { types as utilTypes } from "node:util";

import { z } from "zod";

import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS,
  BASE_RPC_READ_CANARY_MAXIMUM_BYTES,
  BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_PROFILE,
  BASE_RPC_READ_CANARY_PROVIDER_ID,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  BASE_RPC_READ_CANARY_RPC_METHODS,
} from "./base-rpc-constants.js";

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
const RpcMethodsSchema = z.tuple([
  z.literal(BASE_RPC_READ_CANARY_RPC_METHODS[0]),
  z.literal(BASE_RPC_READ_CANARY_RPC_METHODS[1]),
]);

/** Public, code-owned review plan. It intentionally contains no provider or operational IDs. */
export const BaseRpcReadCanaryPlanSchema = z.strictObject({
  schemaVersion: z.literal(1),
  planId: z.literal(BASE_RPC_READ_CANARY_PLAN_ID),
  profile: z.literal(BASE_RPC_READ_CANARY_PROFILE),
  method: z.literal("POST"),
  chain: z.literal("base-mainnet"),
  blockTag: z.literal("finalized"),
  rpcMethods: RpcMethodsSchema,
  maximumRequests: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS),
  maximumAnchors: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS),
  ledgerReserveUsdMicros: z.literal(BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
  actualChargeUsdMicros: z.null(),
  requestFingerprint: z.literal(BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT),
  rawContentDisposition: z.literal("encrypted_ephemeral"),
  automaticRetries: z.literal(0),
  automaticFallback: z.literal(false),
  paymentAuthority: z.literal("none"),
  transactionAuthority: z.literal("none"),
});

export const BaseRpcReadCanaryRunCommandSchema = z.strictObject({
  schemaVersion: z.literal(1),
  planId: z.literal(BASE_RPC_READ_CANARY_PLAN_ID),
  expectedRuntimeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  requestId: UuidSchema,
  typedPlanIdAcknowledgement: z.literal(BASE_RPC_READ_CANARY_PLAN_ID),
  oneRequestAcknowledgement: z.literal(true),
  nonPaymentReadAcknowledgement: z.literal(true),
  noTransactionAuthorityAcknowledgement: z.literal(true),
  finalizedAnchorAcknowledgement: z.literal(true),
  methodSetAcknowledgement: z.literal(BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT),
  ledgerReserveUsdMicrosAcknowledgement: z.literal(BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
});

export const BaseRpcReadCanaryPreparedEventPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    planId: z.literal(BASE_RPC_READ_CANARY_PLAN_ID),
    providerId: z.literal(BASE_RPC_READ_CANARY_PROVIDER_ID),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    budgetId: UuidSchema,
    expectedRuntimeRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    runtimeAuthorizationId: UuidSchema,
    runtimeProcessInstanceId: UuidSchema,
    requestFingerprint: z.literal(BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT),
    rpcMethods: RpcMethodsSchema,
    blockTag: z.literal("finalized"),
    preparedAt: CanonicalTimestampSchema,
    expiresAt: CanonicalTimestampSchema,
    maximumRequests: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS),
    maximumAnchors: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS),
    ledgerReserveUsdMicros: z.literal(BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
  })
  .refine((value) => Date.parse(value.expiresAt) > Date.parse(value.preparedAt), {
    message: "canary authorization must expire after preparation",
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

export const BaseRpcReadCanaryFailureCodeSchema = z.enum([
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
  "RATE_LIMITED",
  "HTTP_STATUS",
  "UNSUPPORTED_CONTENT_ENCODING",
  "UNSUPPORTED_CONTENT_TYPE",
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

/** Authenticated internal event payload. Never return it from the public API. */
export const BaseRpcReadCanaryDurableReceiptSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    receiptId: z.string().regex(/^base-rpc-read-canary:[0-9a-f-]{36}$/),
    planId: z.literal(BASE_RPC_READ_CANARY_PLAN_ID),
    providerId: z.literal(BASE_RPC_READ_CANARY_PROVIDER_ID),
    requestId: UuidSchema,
    requestFingerprint: z.literal(BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT),
    outcome: z.enum(["accepted", "failed", "rejected"]),
    failureCode: BaseRpcReadCanaryFailureCodeSchema.nullable(),
    acquiredAt: CanonicalTimestampSchema.nullable(),
    completedAt: CanonicalTimestampSchema,
    anchorCount: z.literal(1).nullable(),
    byteLength: z.number().int().nonnegative().max(BASE_RPC_READ_CANARY_MAXIMUM_BYTES).nullable(),
    providerReportedFinalized: z.literal(true).nullable(),
    freshnessVerdict: z.literal("fresh").nullable(),
    maximumRequests: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS),
    maximumAnchors: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS),
    ledgerReserveUsdMicros: z.literal(BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
    actualChargeUsdMicros: z.null(),
    runtime: RuntimeReceiptSchema.nullable(),
    capture: CaptureReceiptSchema.nullable(),
  })
  .superRefine((receipt, context) => {
    const accepted = receipt.outcome === "accepted";
    const captured = receipt.outcome !== "failed";
    if (
      accepted !== (receipt.failureCode === null) ||
      captured !== (receipt.acquiredAt !== null) ||
      captured !== (receipt.byteLength !== null) ||
      captured !== (receipt.capture !== null) ||
      accepted !== (receipt.anchorCount === 1) ||
      accepted !== (receipt.providerReportedFinalized === true) ||
      accepted !== (receipt.freshnessVerdict === "fresh") ||
      (captured && receipt.runtime === null) ||
      (receipt.outcome !== "accepted" && receipt.failureCode === null) ||
      receipt.receiptId !== `base-rpc-read-canary:${receipt.requestId}`
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

/** Sanitized public DTO with no provider, request, capture, attempt, event, or block identifiers. */
export const BaseRpcReadCanaryReceiptSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    planId: z.literal(BASE_RPC_READ_CANARY_PLAN_ID),
    requestFingerprint: z.literal(BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT),
    rpcMethods: RpcMethodsSchema,
    outcome: z.enum(["accepted", "failed", "rejected"]),
    failureCode: BaseRpcReadCanaryFailureCodeSchema.nullable(),
    completedAt: CanonicalTimestampSchema,
    providerReportedFinalized: z.literal(true).nullable(),
    freshnessVerdict: z.literal("fresh").nullable(),
    maximumRequests: z.literal(BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS),
    ledgerReserveUsdMicros: z.literal(BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO),
    actualChargeUsdMicros: z.null(),
  })
  .superRefine((receipt, context) => {
    const accepted = receipt.outcome === "accepted";
    if (
      accepted !== (receipt.failureCode === null) ||
      accepted !== (receipt.providerReportedFinalized === true) ||
      accepted !== (receipt.freshnessVerdict === "fresh")
    ) {
      context.addIssue({ code: "custom", message: "public canary receipt fields disagree" });
    }
  });

/** Internal content-free checkpoint for a committed encrypted capture. */
export const BaseRpcReadCanaryResultEventPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    requestId: UuidSchema,
    attemptId: UuidSchema,
    requestFingerprint: z.literal(BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT),
    outcome: z.enum(["accepted", "rejected"]),
    failureCode: BaseRpcReadCanaryFailureCodeSchema.nullable(),
    acquiredAt: CanonicalTimestampSchema,
    completedAt: CanonicalTimestampSchema,
    anchorCount: z.literal(1).nullable(),
    byteLength: z.number().int().nonnegative().max(BASE_RPC_READ_CANARY_MAXIMUM_BYTES),
    providerReportedFinalized: z.literal(true).nullable(),
    freshnessVerdict: z.literal("fresh").nullable(),
    runtime: RuntimeReceiptSchema,
    capture: CaptureReceiptSchema,
  })
  .superRefine((result, context) => {
    const accepted = result.outcome === "accepted";
    if (
      accepted !== (result.failureCode === null) ||
      accepted !== (result.anchorCount === 1) ||
      accepted !== (result.providerReportedFinalized === true) ||
      accepted !== (result.freshnessVerdict === "fresh") ||
      Date.parse(result.completedAt) < Date.parse(result.acquiredAt)
    ) {
      context.addIssue({ code: "custom", message: "canary result fields disagree" });
    }
  });

/** Internal checkpoint for an attempt that produced no committed capture. */
export const BaseRpcReadCanaryFailureEventPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  requestId: UuidSchema,
  attemptId: UuidSchema,
  requestFingerprint: z.literal(BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT),
  failureCode: BaseRpcReadCanaryFailureCodeSchema,
  completedAt: CanonicalTimestampSchema,
  attemptOutcome: z.enum(["aborted", "failed"]).nullable(),
  runtime: RuntimeReceiptSchema.nullable(),
});

export const BaseRpcReadCanaryProjectionSchema = z.strictObject({
  schemaVersion: z.literal(1),
  status: z.enum(["uncommissioned", "ready", "running", "completed", "failed", "interrupted"]),
  credentialStatus: z.enum(["configured", "missing", "unknown"]),
  plan: BaseRpcReadCanaryPlanSchema,
  lastReceipt: BaseRpcReadCanaryReceiptSchema.nullable(),
});

export function parseBaseRpcReadCanaryInput<T>(
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
