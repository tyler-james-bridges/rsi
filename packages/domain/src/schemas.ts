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

export const PositiveAtomicAmountSchema = AtomicAmountSchema.refine(
  (value) => /^[1-9][0-9]{0,77}$/.test(value),
  "amount must be positive",
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

export const NftPurchaseActionSchema = z
  .object({
    kind: z.literal("nft.purchase"),
    adapterId: z.literal("opensea.seaport"),
    chainId: z.number().int().positive(),
    marketplace: z.literal("opensea"),
    targetContract: EvmAddressSchema,
    collectionContract: EvmAddressSchema,
    tokenId: AtomicAmountSchema,
    paymentAsset: EvmAddressSchema,
    maxTotalSpend: PositiveAtomicAmountSchema,
    recipient: EvmAddressSchema,
    orderHash: Bytes32Schema,
    nonce: Bytes32Schema,
  })
  .strict();

export const ExecutionIntentSchema = z
  .object({
    intentId: z.string().regex(/^rsi-intent:[a-zA-Z0-9._-]{1,96}$/),
    strategyVersion: z.string().regex(/^rsi-[a-zA-Z0-9._-]{1,64}$/),
    policyVersion: z.string().regex(/^kernel-[a-zA-Z0-9._-]{1,64}$/),
    policyHash: Bytes32Schema,
    evidenceIds: z.array(Sha256IdSchema).min(1).max(100),
    createdAt: TimestampSchema,
    expiresAt: TimestampSchema,
    action: NftPurchaseActionSchema,
  })
  .strict();

export const PolicyConfigSchema = z
  .object({
    policyVersion: z.string().regex(/^kernel-[a-zA-Z0-9._-]{1,64}$/),
    allowedChains: z.array(z.number().int().positive()).min(1),
    allowedMarketplaceTargets: z.array(AssetContractSchema).min(1),
    allowedCollections: z.array(AssetContractSchema).min(1),
    allowedPaymentAssets: z.array(AssetContractSchema).min(1),
    allowedRecipients: z.array(AssetContractSchema).min(1),
    maxPerTransactionByAsset: z.record(
      z.string().regex(/^\d+:0x[0-9a-f]{40}$/),
      PositiveAtomicAmountSchema,
    ),
    maxDailySpendByAsset: z.record(
      z.string().regex(/^\d+:0x[0-9a-f]{40}$/),
      PositiveAtomicAmountSchema,
    ),
    maxEvidenceAgeSeconds: z.number().int().positive().max(86_400),
    maxClockSkewSeconds: z.number().int().nonnegative().max(300),
    minIndependentEvidenceClusters: z.number().int().min(2).max(10),
    requireCanonicalMarketplaceEvidence: z.boolean(),
  })
  .strict();

export const SourceWeightsSchema = z
  .object({
    x: z.number().min(0).max(1),
    x402: z.number().min(0).max(1),
    opensea: z.number().min(0).max(1),
    onchain: z.number().min(0).max(1),
  })
  .strict();

export const StrategySchema = z
  .object({
    version: z.string().regex(/^rsi-[a-zA-Z0-9._-]{1,64}$/),
    sourceWeights: SourceWeightsSchema,
    opportunityThreshold: z.number().min(0).max(1),
    maxHoldSeconds: z.number().int().min(60).max(31_536_000),
    exitLossBps: z.number().int().min(1).max(5_000),
    exitGainBps: z.number().int().min(1).max(100_000),
    queryTerms: z.array(z.string().min(1).max(80)).min(1).max(50),
  })
  .strict();

export const StrategyPatchSchema = z
  .object({
    sourceWeights: SourceWeightsSchema.partial().strict().optional(),
    opportunityThreshold: z.number().min(0).max(1).optional(),
    maxHoldSeconds: z.number().int().min(60).max(31_536_000).optional(),
    exitLossBps: z.number().int().min(1).max(5_000).optional(),
    exitGainBps: z.number().int().min(1).max(100_000).optional(),
    queryTerms: z.array(z.string().min(1).max(80)).min(1).max(50).optional(),
  })
  .strict();

export type AssetContract = z.infer<typeof AssetContractSchema>;
export type EvidenceClaim = z.infer<typeof EvidenceClaimSchema>;
export type Observation = z.infer<typeof ObservationSchema>;
export type ExecutionIntent = z.infer<typeof ExecutionIntentSchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type Strategy = z.infer<typeof StrategySchema>;
export type StrategyPatch = z.infer<typeof StrategyPatchSchema>;

export function assetKey(chainId: number, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}
