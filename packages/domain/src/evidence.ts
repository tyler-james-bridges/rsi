import { z } from "zod";

export const EvmAddressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, "expected a 20-byte EVM address");

export const Bytes32Schema = z.string().regex(/^0x[0-9a-fA-F]{64}$/, "expected 32-byte hex data");

export const Sha256IdSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, "expected a sha256:<lowercase hex> identifier");

export const XStableIdSchema = z
  .string()
  .regex(/^\d{1,32}$/, "expected a decimal X stable identifier");

const MAX_UINT256 = (1n << 256n) - 1n;

export const AtomicAmountSchema = z
  .string()
  .max(78, "atomic amount exceeds uint256")
  .regex(/^(0|[1-9][0-9]*)$/, "expected an unsigned atomic-unit integer")
  .refine(
    (value) =>
      value.length <= 78 && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= MAX_UINT256,
    "atomic amount exceeds uint256",
  );

export const TimestampSchema = z.string().datetime({ offset: true });

export const HttpsOriginSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === ""
    );
  }, "expected a credential-free HTTPS origin");

export const SafeLabelSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);

export const MediaTypeSchema = z
  .string()
  .max(128)
  .regex(
    /^[A-Za-z0-9!#$&^_.+-]{1,64}\/[A-Za-z0-9!#$&^_.+-]{1,64}(?:;\s*charset=[A-Za-z0-9._-]{1,32})?$/,
    "expected a bounded media type",
  );

export const AssetContractSchema = z
  .object({
    chainId: z.number().int().positive(),
    address: EvmAddressSchema,
  })
  .strict();

export const NftAssetSchema = AssetContractSchema.extend({
  tokenId: AtomicAmountSchema,
}).strict();

export const ObservationSourceKindSchema = z.enum([
  "x",
  "x402",
  "opensea",
  "onchain",
  "robinhood",
  "manual",
]);

export const EvidenceClaimSchema = z
  .object({
    type: z.enum([
      "collection_identity",
      "ownership",
      "listing",
      "executable_bid",
      "market_momentum",
      "risk_indicator",
    ]),
    asset: NftAssetSchema,
    confidence: z.number().min(0).max(1),
  })
  .strict();

export const ObservationSchema = z
  .object({
    observationId: Sha256IdSchema,
    source: z
      .object({
        kind: ObservationSourceKindSchema,
        providerId: SafeLabelSchema,
        providerOrigin: HttpsOriginSchema.optional(),
      })
      .strict(),
    acquiredAt: TimestampSchema,
    observedAt: TimestampSchema,
    validUntil: TimestampSchema,
    raw: z
      .object({
        contentHash: Sha256IdSchema,
        contentType: MediaTypeSchema,
        byteLength: z.number().int().nonnegative().max(5_000_000),
      })
      .strict(),
    origin: z
      .object({
        xPostId: XStableIdSchema.optional(),
        authorId: XStableIdSchema.optional(),
        editHistoryIds: z.array(XStableIdSchema).max(100).default([]),
        capturedVersionHash: Sha256IdSchema.optional(),
      })
      .strict()
      .optional(),
    order: z
      .object({
        marketplace: z.literal("opensea"),
        orderHash: Bytes32Schema,
      })
      .strict()
      .optional(),
    claims: z.array(EvidenceClaimSchema).min(1).max(100),
    integrity: z
      .object({
        coordinationClusterId: SafeLabelSchema,
        accountAnomalyScore: z.number().min(0).max(1),
        homographFlags: z.array(SafeLabelSchema).max(50),
        injectionFlags: z.array(SafeLabelSchema).max(50),
        independentEvidenceIds: z.array(Sha256IdSchema).max(100),
      })
      .strict(),
  })
  .strict();

export type AssetContract = z.infer<typeof AssetContractSchema>;
export type EvidenceClaim = z.infer<typeof EvidenceClaimSchema>;
export type Observation = z.infer<typeof ObservationSchema>;

export function assetKey(chainId: number, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}
