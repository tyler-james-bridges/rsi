import { z } from "zod";

import { CaptureRegistryValidationError } from "./errors.js";

export const MAX_CAPTURE_REGISTRY_RECORDS = 1_000;
export const MAX_SOURCE_IDENTIFIERS = 16;
export const MAX_SOURCE_IDENTIFIER_BYTES = 512;
export const MAX_X_POST_IDS = 10;
export const MAX_X_USER_IDS = 10;
export const MAX_X_EDIT_IDS = 1_000;
export const MAX_X_NEXT_TOKEN_CHARACTERS = 2_048;
export const DEFAULT_REGISTRY_OPERATION_LIMIT = 100;
export const MAX_REGISTRY_OPERATION_LIMIT = 1_000;

export const CanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  }, "must be a canonical UTC timestamp with milliseconds");

export const UuidSchema = z.string().uuid().max(36);
export const CaptureIdSchema = z.string().regex(/^[0-9a-f]{32}$/);
export const RequestFingerprintSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/);
export const CaptureRegistrySourceSchema = z.enum(["alchemy", "fixture", "opensea", "x"]);
export const CaptureRegistryProfileSchema = z.enum(["canary", "dev", "production-observer"]);
export const CaptureRegistryLaneSchema = z.enum([
  "contract",
  "discovery",
  "marketplace",
  "official",
  "security",
]);

const IdentifierValueSchema = z
  .string()
  .min(1)
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= MAX_SOURCE_IDENTIFIER_BYTES,
    `must be at most ${MAX_SOURCE_IDENTIFIER_BYTES} UTF-8 bytes`,
  )
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), "must not contain control bytes");

function identifiersSchema<const K extends readonly [string, ...string[]]>(kinds: K) {
  return z
    .array(
      z.strictObject({
        kind: z.enum(kinds),
        value: IdentifierValueSchema,
      }),
    )
    .max(MAX_SOURCE_IDENTIFIERS)
    .superRefine((identifiers, context) => {
      const seen = new Set<string>();
      for (const [index, identifier] of identifiers.entries()) {
        const identity = `${identifier.kind}\0${identifier.value}`;
        if (seen.has(identity)) {
          context.addIssue({
            code: "custom",
            message: "source identifiers must be unique",
            path: [index],
          });
        }
        seen.add(identity);
      }
    });
}

function uniqueXIds(maximum: number) {
  return z
    .array(z.string().regex(/^[1-9][0-9]{0,18}$/))
    .max(maximum)
    .refine((values) => new Set(values).size === values.length, "X IDs must be unique");
}

export const CaptureSourceIdentifiersSchema = z.discriminatedUnion("source", [
  z.strictObject({
    identifiers: identifiersSchema(["block_number", "page_key", "transaction_hash"]),
    source: z.literal("alchemy"),
  }),
  z.strictObject({
    identifiers: identifiersSchema(["fixture_id"]),
    source: z.literal("fixture"),
  }),
  z.strictObject({
    identifiers: identifiersSchema(["asset_id", "collection_slug", "next_cursor"]),
    source: z.literal("opensea"),
  }),
  z.strictObject({
    editIds: uniqueXIds(MAX_X_EDIT_IDS),
    nextToken: z
      .string()
      .min(1)
      .max(MAX_X_NEXT_TOKEN_CHARACTERS)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .nullable(),
    postIds: uniqueXIds(MAX_X_POST_IDS),
    source: z.literal("x"),
    userIds: uniqueXIds(MAX_X_USER_IDS),
  }),
]);

export const OpenCaptureRegistryOptionsSchema = z.strictObject({
  expectedProfile: CaptureRegistryProfileSchema,
  path: z.string().min(1).max(4_096),
  registryKey: z.instanceof(Uint8Array).refine((key) => key.byteLength === 32),
});

export const BeginCaptureAttemptInputSchema = z.strictObject({
  acquiredAt: CanonicalTimestampSchema,
  attemptId: UuidSchema,
  expiresAt: CanonicalTimestampSchema,
  lane: CaptureRegistryLaneSchema,
  profile: CaptureRegistryProfileSchema,
  requestFingerprint: RequestFingerprintSchema,
  sessionId: UuidSchema,
  source: CaptureRegistrySourceSchema,
});

export const CommitCaptureInputSchema = z.strictObject({
  attemptId: UuidSchema,
  captureId: CaptureIdSchema,
  committedAt: CanonicalTimestampSchema,
  sourceIdentifiers: CaptureSourceIdentifiersSchema,
});

export const CaptureDeletionReceiptSchema = z.strictObject({
  captureId: CaptureIdSchema,
  deletedAt: CanonicalTimestampSchema,
  keyDestroyed: z.literal(true),
  reason: z.enum(["expired", "explicit"]),
  schemaVersion: z.literal(1),
  state: z.literal("deleted"),
});

export const RecordVerifiedCaptureDeletionInputSchema = z.strictObject({
  attemptId: UuidSchema,
  deletionReceipt: CaptureDeletionReceiptSchema,
});

export const RemovePendingCaptureAttemptInputSchema = z.strictObject({
  attemptId: UuidSchema,
  removedAt: CanonicalTimestampSchema,
});

export const RecoverPendingCaptureAttemptsInputSchema = z.strictObject({
  limit: z.number().int().min(1).max(MAX_REGISTRY_OPERATION_LIMIT).optional(),
  recoveredAt: CanonicalTimestampSchema,
});

export const PurgeRemovedCaptureAttemptsInputSchema = z.strictObject({
  before: CanonicalTimestampSchema,
  limit: z.number().int().min(1).max(MAX_REGISTRY_OPERATION_LIMIT).optional(),
});

const AttemptBaseSchema = z.strictObject({
  acquiredAt: CanonicalTimestampSchema,
  attemptId: UuidSchema,
  expiresAt: CanonicalTimestampSchema,
  lane: CaptureRegistryLaneSchema,
  profile: CaptureRegistryProfileSchema,
  requestFingerprint: RequestFingerprintSchema,
  schemaVersion: z.literal(1),
  sessionId: UuidSchema,
  source: CaptureRegistrySourceSchema,
});

export const PendingCaptureAttemptSchema = AttemptBaseSchema.extend({
  state: z.literal("pending"),
}).strict();

export const CommittedCaptureAttemptSchema = AttemptBaseSchema.extend({
  captureId: CaptureIdSchema,
  committedAt: CanonicalTimestampSchema,
  sourceIdentifiers: CaptureSourceIdentifiersSchema,
  state: z.literal("committed"),
}).strict();

export const RemovedCaptureAttemptSchema = z.strictObject({
  attemptId: UuidSchema,
  keyDestroyed: z.literal(true),
  removalReason: z.enum([
    "capture_deleted_expired",
    "capture_deleted_explicit",
    "pending_explicit",
    "pending_recovery",
  ]),
  removedAt: CanonicalTimestampSchema,
  schemaVersion: z.literal(1),
  state: z.literal("removed"),
});

export const StoredCaptureTombstoneSchema = z.strictObject({
  keyDestroyed: z.literal(true),
  removalReason: z.enum([
    "capture_deleted_expired",
    "capture_deleted_explicit",
    "pending_explicit",
    "pending_recovery",
  ]),
  removedAt: CanonicalTimestampSchema,
  schemaVersion: z.literal(1),
  state: z.literal("removed"),
});

export const CaptureRegistryAttemptSchema = z.discriminatedUnion("state", [
  PendingCaptureAttemptSchema,
  CommittedCaptureAttemptSchema,
  RemovedCaptureAttemptSchema,
]);

export function parseRegistryInput<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  let result: ReturnType<typeof schema.safeParse>;
  try {
    assertPlainDataGraph(value, new WeakSet<object>(), label);
    result = schema.safeParse(value);
  } catch (error) {
    if (error instanceof CaptureRegistryValidationError) throw error;
    throw new CaptureRegistryValidationError(`${label} does not match its exact schema`);
  }
  if (!result.success) {
    throw new CaptureRegistryValidationError(`${label} does not match its exact schema`);
  }
  return result.data;
}

function assertPlainDataGraph(value: unknown, ancestors: WeakSet<object>, label: string): void {
  if (value === null || typeof value !== "object" || value instanceof Uint8Array) return;
  if (ancestors.has(value)) {
    throw new CaptureRegistryValidationError(`${label} must not contain cycles`);
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.some(
          (key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
        )
      ) {
        throw new CaptureRegistryValidationError(`${label} must contain plain data only`);
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new CaptureRegistryValidationError(`${label} arrays must be dense data arrays`);
        }
        assertPlainDataGraph(descriptor.value, ancestors, label);
      }
      return;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CaptureRegistryValidationError(`${label} must contain plain objects only`);
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        throw new CaptureRegistryValidationError(`${label} must not contain symbol properties`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new CaptureRegistryValidationError(
          `${label} must contain enumerable data properties`,
        );
      }
      assertPlainDataGraph(descriptor.value, ancestors, label);
    }
  } finally {
    ancestors.delete(value);
  }
}

export function validateAttemptWindow(acquiredAt: string, expiresAt: string): void {
  const acquired = Date.parse(acquiredAt);
  const expires = Date.parse(expiresAt);
  if (expires < acquired || expires - acquired > 2 * 60 * 60 * 1_000) {
    throw new CaptureRegistryValidationError(
      "expiresAt must be between acquiredAt and two hours after acquiredAt",
    );
  }
}
