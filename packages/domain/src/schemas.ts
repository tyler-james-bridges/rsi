import { z } from "zod";
import {
  AssetContractSchema,
  AtomicAmountSchema,
  Bytes32Schema,
  EvmAddressSchema,
  Sha256IdSchema,
  TimestampSchema,
} from "./evidence.js";

export * from "./evidence.js";

export const PositiveAtomicAmountSchema = AtomicAmountSchema.refine(
  (value) => /^[1-9][0-9]{0,77}$/.test(value),
  "amount must be positive",
);

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

export type ExecutionIntent = z.infer<typeof ExecutionIntentSchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type Strategy = z.infer<typeof StrategySchema>;
export type StrategyPatch = z.infer<typeof StrategyPatchSchema>;
