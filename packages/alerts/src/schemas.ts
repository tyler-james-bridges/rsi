import { types as utilTypes } from "node:util";

import { z } from "zod";

import { AlertValidationError } from "./errors.js";

export const CanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const time = Date.parse(value);
    return Number.isFinite(time) && new Date(time).toISOString() === value;
  }, "must be a canonical UTC timestamp with milliseconds");

export const AlertProfileSchema = z.enum(["dev", "canary", "production-observer"]);

export const AlertPlaneSchema = z.enum(["healthchecks", "resend"]);

const CanonicalUuidV4Schema = z
  .string()
  .length(36)
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    "must be a canonical lowercase UUIDv4",
  );

const AuthenticatedHexSchema = z
  .string()
  .length(64)
  .regex(/^[0-9a-f]{64}$/);

export const IncidentCodeSchema = z.enum([
  "ALERT_DELIVERY_FAILURE",
  "ALERT_PATH_CANARY",
  "ANCHOR_FAILURE",
  "BACKUP_FAILURE",
  "CLOCK_FAILURE",
  "CONFIGURATION_DRIFT",
  "COST_ANOMALY",
  "CREDENTIAL_COMPROMISE",
  "CROSS_PROFILE_CONTAMINATION",
  "CURSOR_FAILURE",
  "DATA_LEAK",
  "FINANCIAL_ADAPTER_REACHABLE",
  "HOST_SECURITY_FAILURE",
  "INCIDENT_LATCH_BYPASS",
  "INTEGRITY_MISMATCH",
  "NETWORK_BOUNDARY_ESCAPE",
  "POLICY_BOUNDARY_ESCAPE",
  "PREFLIGHT_FAILURE",
  "PROVIDER_OUTAGE",
  "PROVIDER_SCHEMA_DRIFT",
  "PUBLICATION_FAILURE",
  "PURGE_FAILURE",
  "RELEASE_FAILURE",
  "RESOURCE_BOUND_EXCEEDED",
  "RUNTIME_CRASH",
  "SECOND_WRITER",
  "SESSION_SUPERVISION_FAILURE",
  "SIGNING_KEY_COMPROMISE",
  "TERMS_OR_PRICE_DRIFT",
]);

export const IncidentAlertV1Schema = z.strictObject({
  schemaVersion: z.literal("incident-alert.v1"),
  incidentId: CanonicalUuidV4Schema,
  incidentCode: IncidentCodeSchema,
  severity: z.literal("critical"),
  occurredAt: CanonicalTimestampSchema,
  profile: AlertProfileSchema,
  sessionId: CanonicalUuidV4Schema,
  templateRevision: z.literal(1),
  instruction: z.literal("OPEN_LOCAL_RSI_CONSOLE"),
});

export const DeliveryIdSchema = AuthenticatedHexSchema;

export const AlertTrustedHeadV1Schema = z.strictObject({
  schemaVersion: z.literal("alert-trusted-head.v1"),
  profile: AlertProfileSchema,
  auditSequence: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  auditMac: AuthenticatedHexSchema,
  schemaMac: AuthenticatedHexSchema,
  headMac: AuthenticatedHexSchema,
});

export const ProviderMessageIdSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9._:-]+$/);

export const EnqueueAlertInputSchema = z.strictObject({
  alert: IncidentAlertV1Schema,
  plane: AlertPlaneSchema,
  queuedAt: CanonicalTimestampSchema,
});

export const ClaimDeliveryInputSchema = z.strictObject({
  claimedAt: CanonicalTimestampSchema,
  plane: AlertPlaneSchema,
});

export const CompleteDeliveryInputSchema = z.strictObject({
  attempt: z.union([z.literal(1), z.literal(2)]),
  completedAt: CanonicalTimestampSchema,
  deliveryId: DeliveryIdSchema,
  providerMessageId: ProviderMessageIdSchema.optional(),
});

export const FailDeliveryInputSchema = z.strictObject({
  attempt: z.union([z.literal(1), z.literal(2)]),
  deliveryId: DeliveryIdSchema,
  failedAt: CanonicalTimestampSchema,
  retryable: z.boolean(),
});

export const RecoverDeliveriesInputSchema = z.strictObject({
  recoveredAt: CanonicalTimestampSchema,
});

export function parseWithSchema<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  let parsed: ReturnType<typeof schema.safeParse>;
  try {
    assertPlainDataGraph(value, new WeakSet<object>());
    parsed = schema.safeParse(value);
  } catch (error) {
    if (error instanceof AlertValidationError) throw error;
    throw new AlertValidationError(`${label}: input must contain plain data only`);
  }
  if (!parsed.success) {
    throw new AlertValidationError(`${label}: ${z.prettifyError(parsed.error)}`);
  }
  return parsed.data;
}

function assertPlainDataGraph(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value)) throw new AlertValidationError("input may not contain proxies");
  if (value instanceof Uint8Array) {
    if (
      Object.getPrototypeOf(value) !== Uint8Array.prototype ||
      !(value.buffer instanceof ArrayBuffer) ||
      Object.getPrototypeOf(value.buffer) !== ArrayBuffer.prototype
    ) {
      throw new AlertValidationError("byte inputs must use an ordinary private Uint8Array");
    }
    return;
  }
  if (ancestors.has(value)) throw new AlertValidationError("input may not be cyclic");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.some(
          (key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
        )
      ) {
        throw new AlertValidationError("arrays must be dense and field-free");
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new AlertValidationError("arrays may not contain holes or accessors");
        }
        assertPlainDataGraph(descriptor.value, ancestors);
      }
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new AlertValidationError("input records must have a plain prototype");
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        throw new AlertValidationError("input records may not contain symbols");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new AlertValidationError("input records may not contain accessors");
      }
      assertPlainDataGraph(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}
