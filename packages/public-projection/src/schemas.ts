import { z } from "zod";

import { PublicProjectionError } from "./errors.js";
import { assertPlainData } from "./portable.js";

const Timestamp = z
  .string()
  .max(32)
  .refine((value) => {
    const time = Date.parse(value);
    return Number.isFinite(time) && new Date(time).toISOString() === value;
  });
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const Uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const Identifier = z.string().regex(/^[a-z0-9][a-z0-9._:-]{0,127}$/);
const Atomic = z.string().regex(/^(0|[1-9][0-9]{0,29})$/);
const Profile = z.enum(["canary", "production-observer"]);
const Reason = z.enum(["integrity", "legal", "provider-terms", "privacy"]);

export const PublicReceiptCandidateSchema = z.strictObject({
  candidateType: z.literal("rsi.public-receipt-candidate"),
  version: z.literal(1),
  candidateId: Uuid,
  profile: Profile,
  acceptedAt: Timestamp,
  createdAt: Timestamp,
  eligibleAt: Timestamp,
  releaseManifestSha256: Hash,
  counts: z.strictObject({
    requestCount: z.number().int().min(0).max(100_000),
    laneCount: z.number().int().min(0).max(10_000),
    findingCount: z.number().int().min(0).max(100_000),
    abstentionCount: z.number().int().min(0).max(100_000),
  }),
  costs: z.strictObject({
    currency: z.literal("USD_MICRO"),
    reservedAtomic: Atomic,
    reconciledAtomic: Atomic,
  }),
  status: z.strictObject({
    alert: z.literal("healthy"),
    anchor: z.literal("verified"),
    backup: z.literal("verified"),
    deletion: z.literal("verified"),
    digest: z.literal("verified"),
    eventIntegrity: z.literal("verified"),
  }),
  qualification: z.strictObject({
    acceptedSessions: z.number().int().min(0).max(10),
    requiredSessions: z.literal(10),
  }),
});

export const PublicReceiptPayloadSchema = PublicReceiptCandidateSchema.extend({
  artifactType: z.literal("rsi.public-receipt"),
  receiptId: Uuid,
  reviewedAt: Timestamp,
  publishedAt: Timestamp,
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  predecessorSha256: Hash.nullable(),
}).strict();

export const PublicCorrectionPayloadSchema = z.strictObject({
  artifactType: z.literal("rsi.public-correction"),
  version: z.literal(1),
  correctionId: Uuid,
  effectiveAt: Timestamp,
  predecessorSha256: Hash,
  profile: Profile,
  reason: Reason,
  replacementArtifactSha256: Hash.nullable(),
  sequence: z.number().int().min(2).max(Number.MAX_SAFE_INTEGER),
  targetArtifactSha256: Hash,
});

export const PublicTombstonePayloadSchema = z.strictObject({
  artifactType: z.literal("rsi.public-tombstone"),
  version: z.literal(1),
  predecessorSha256: Hash,
  profile: Profile,
  reason: Reason,
  removedAt: Timestamp,
  sequence: z.number().int().min(2).max(Number.MAX_SAFE_INTEGER),
  targetArtifactSha256: Hash,
  tombstoneId: Uuid,
});

export const PublicArtifactPayloadSchema = z.discriminatedUnion("artifactType", [
  PublicReceiptPayloadSchema,
  PublicCorrectionPayloadSchema,
  PublicTombstonePayloadSchema,
]);

export const SignedPublicArtifactSchema = z.strictObject({
  schemaVersion: z.literal(1),
  artifactSha256: Hash,
  payload: PublicArtifactPayloadSchema,
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  signerFingerprintSha256: Hash,
  signerKeyId: Identifier,
});

export const PublicArtifactHeadSchema = z.strictObject({
  artifactSha256: Hash,
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
});

export function parseSchema<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    assertPlainData(value);
    const result = schema.safeParse(value);
    if (!result.success) throw new PublicProjectionError("INPUT_INVALID");
    return result.data;
  } catch (error) {
    if (error instanceof PublicProjectionError) throw error;
    throw new PublicProjectionError("INPUT_INVALID");
  }
}
