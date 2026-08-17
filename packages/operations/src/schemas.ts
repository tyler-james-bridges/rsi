import { z } from "zod";

import { OperationsValidationError } from "./errors.js";

const MAX_UINT128 = (1n << 128n) - 1n;

export const CanonicalTimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const time = Date.parse(value);
    return Number.isFinite(time) && new Date(time).toISOString() === value;
  }, "must be a canonical UTC timestamp with milliseconds");

export const UuidSchema = z.string().uuid().max(36);

export const HashSchema = z.string().regex(/^[0-9a-f]{64}$/);

export const IdentifierSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9._:-]+$/);

export const OperationsProfileSchema = z.enum(["dev", "canary", "production-observer"]);

export const SourcePlaneSchema = z.enum(["social", "marketplace", "canonical_chain"]);

export const ResearchLaneSchema = z.enum([
  "official",
  "contract",
  "marketplace",
  "security",
  "discovery",
]);

export const ResearchOperationSchema = z.enum([
  "alchemy.json-rpc.v1",
  "opensea.rest.v1",
  "opensea.stream.v1",
  "x.recent-search.v1",
]);

export const AtomicAmountSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,38})$/)
  .refine((value) => BigInt(value) <= MAX_UINT128, "must fit in uint128");

export const PositiveAtomicAmountSchema = AtomicAmountSchema.refine(
  (value) => BigInt(value) > 0n,
  "must be greater than zero",
);

export const AttemptPermitTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export const OpaqueCursorSchema = z
  .string()
  .min(1)
  .max(2_048)
  .regex(/^[A-Za-z0-9._~-]+$/);

export function parseWithSchema<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new OperationsValidationError(`${label}: ${z.prettifyError(parsed.error)}`);
  }
  return parsed.data;
}
