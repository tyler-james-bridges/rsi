import { types as utilTypes } from "node:util";

import { z } from "zod";

import { RuntimeValidationError } from "./errors.js";

export const RuntimeCanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  }, "must be a canonical UTC timestamp with milliseconds");

export const RuntimeUuidSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

export const RuntimeSafeIdentifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);

export const RuntimeModeSchema = z.enum(["STOPPED", "RESEARCH", "PROPOSE_ONLY"]);

export const RuntimeBoundarySchema = z.enum([
  "research_collection",
  "proposal_persist",
  "policy_approval",
  "paid_read",
  "wallet_sign",
  "execution_adapter",
  "transaction_broadcast",
  "external_publish",
]);

export const RuntimeBoundaryDecisionReasonSchema = z.enum([
  "ALLOWED",
  "EXPIRED",
  "MODE_NOT_ALLOWED",
  "PERMANENTLY_FORBIDDEN",
  "PROCESS_SUPERSEDED",
  "STALE_REVISION",
]);

export const OpenRuntimeInputSchema = z.strictObject({
  openedAt: RuntimeCanonicalTimestampSchema,
  path: z.string().min(1).max(4_096),
  processInstanceId: RuntimeUuidSchema,
});

export const RuntimeTransitionInputSchema = z.strictObject({
  expectedMode: RuntimeModeSchema,
  expectedRevision: z
    .number()
    .int()
    .min(1)
    .max(Number.MAX_SAFE_INTEGER - 1),
  occurredAt: RuntimeCanonicalTimestampSchema,
  requestId: RuntimeUuidSchema,
  targetMode: z.enum(["RESEARCH", "PROPOSE_ONLY"]),
});

export const RuntimeStopInputSchema = z.strictObject({
  occurredAt: RuntimeCanonicalTimestampSchema,
  requestId: RuntimeUuidSchema,
});

export const RuntimeBoundaryAuthorizationInputSchema = z.strictObject({
  actionId: RuntimeSafeIdentifierSchema,
  authorizationId: RuntimeUuidSchema,
  boundary: RuntimeBoundarySchema,
});

const RuntimeRevisionSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const RuntimePreviousRevisionSchema = z
  .number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER - 1);

export const RuntimeStopEventPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  cause: z.enum(["operator", "startup"]),
  from: RuntimeModeSchema.nullable(),
  previousRevision: RuntimePreviousRevisionSchema,
  processInstanceId: RuntimeUuidSchema,
  requestId: RuntimeUuidSchema,
  revision: RuntimeRevisionSchema,
  to: z.literal("STOPPED"),
});

export const RuntimeTransitionEventPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  expectedMode: RuntimeModeSchema,
  expectedRevision: RuntimeRevisionSchema,
  from: RuntimeModeSchema,
  previousRevision: RuntimeRevisionSchema,
  processInstanceId: RuntimeUuidSchema,
  requestId: RuntimeUuidSchema,
  revision: RuntimeRevisionSchema,
  to: z.enum(["RESEARCH", "PROPOSE_ONLY"]),
});

export const RuntimeBoundaryEventPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  actionId: RuntimeSafeIdentifierSchema,
  authorizationId: RuntimeUuidSchema,
  boundary: RuntimeBoundarySchema,
  checkedMode: RuntimeModeSchema,
  checkedProcessInstanceId: RuntimeUuidSchema,
  checkedRevision: RuntimeRevisionSchema,
  decision: z.enum(["allowed", "denied"]),
  expiresAt: RuntimeCanonicalTimestampSchema,
  reason: RuntimeBoundaryDecisionReasonSchema,
  requestedAt: RuntimeCanonicalTimestampSchema,
  requestedMode: RuntimeModeSchema,
  requestedProcessInstanceId: RuntimeUuidSchema,
  requestedRevision: RuntimeRevisionSchema,
});

export const RuntimeBoundaryReceiptSchema = z.strictObject({
  schemaVersion: z.literal(1),
  actionId: RuntimeSafeIdentifierSchema,
  authorizationId: RuntimeUuidSchema,
  boundary: RuntimeBoundarySchema,
  checkedAt: RuntimeCanonicalTimestampSchema,
  decision: z.enum(["allowed", "denied"]),
  eventHash: z.string().regex(/^[0-9a-f]{64}$/),
  eventSequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  mode: RuntimeModeSchema,
  modeRevision: RuntimeRevisionSchema,
  processInstanceId: RuntimeUuidSchema,
  reason: RuntimeBoundaryDecisionReasonSchema,
});

export type RuntimeStopEventPayload = z.infer<typeof RuntimeStopEventPayloadSchema>;
export type RuntimeTransitionEventPayload = z.infer<typeof RuntimeTransitionEventPayloadSchema>;
export type RuntimeBoundaryEventPayload = z.infer<typeof RuntimeBoundaryEventPayloadSchema>;

export function parseRuntimeInput<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    assertPlainData(value, new WeakSet<object>());
    const result = schema.safeParse(value);
    if (!result.success)
      throw new RuntimeValidationError(`${label}: ${z.prettifyError(result.error)}`);
    return result.data;
  } catch (error) {
    if (error instanceof RuntimeValidationError) throw error;
    throw new RuntimeValidationError(`${label}: invalid plain data`);
  }
}

function assertPlainData(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value) || ancestors.has(value)) throw new RuntimeValidationError();
  if (Array.isArray(value)) {
    throw new RuntimeValidationError("Runtime inputs do not accept arrays");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new RuntimeValidationError();
  ancestors.add(value);
  try {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new RuntimeValidationError();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new RuntimeValidationError();
      }
      assertPlainData(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}
