import { z } from "zod";

// This module is a deliberately isolated, signer-blind package subpath. Keep
// its minimal primitives local so importing @rsi/domain/proposals never
// evaluates the executable-intent or EIP-712 modules from the domain root.
const SafeLabelSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
const Sha256IdSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, "expected a sha256:<lowercase hex> identifier");
const TimestampSchema = z.string().datetime({ offset: true });
const ObservationSourceKindSchema = z.enum([
  "x",
  "x402",
  "opensea",
  "onchain",
  "robinhood",
  "manual",
]);
const MAX_UINT256 = (1n << 256n) - 1n;
const NftAssetSchema = z.strictObject({
  chainId: z.number().int().positive(),
  address: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "expected a 20-byte EVM address"),
  tokenId: z
    .string()
    .max(78, "token identifier exceeds uint256")
    .regex(/^(0|[1-9][0-9]*)$/, "expected an unsigned integer")
    .refine((value) => BigInt(value) <= MAX_UINT256, "token identifier exceeds uint256"),
});

const uniqueValues = <T>(values: readonly T[]): boolean => new Set(values).size === values.length;

const UniqueSafeLabelsSchema = z
  .array(SafeLabelSchema)
  .max(100)
  .refine(uniqueValues, "duplicate labels are not allowed");

const UnitScoreSchema = z.number().finite().min(0).max(1);

export const ResearchProposalAbstentionReasonSchema = z.enum([
  "identity_ambiguity",
  "insufficient_evidence",
  "integrity_risk",
  "market_uncertainty",
  "policy_out_of_scope",
  "stale_evidence",
]);

export const ResearchProposalDispositionSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("candidate") }),
  z.strictObject({
    kind: z.literal("abstain"),
    reason: ResearchProposalAbstentionReasonSchema,
  }),
]);

/**
 * A content-free research artifact. It deliberately cannot represent an
 * executable action, payment, approval, wallet request, or transaction.
 */
export const ResearchProposalV1Schema = z
  .strictObject({
    schemaVersion: z.literal(1),
    proposalId: z.string().regex(/^rsi-proposal:[A-Za-z0-9._-]{1,96}$/),
    strategyVersion: z.string().regex(/^rsi-[A-Za-z0-9._-]{1,64}$/),
    createdAt: TimestampSchema,
    expiresAt: TimestampSchema,
    asset: NftAssetSchema,
    evidenceIds: z
      .array(Sha256IdSchema)
      .min(1)
      .max(100)
      .refine(uniqueValues, "duplicate evidence identifiers are not allowed"),
    provenance: z.strictObject({
      providerIds: z
        .array(SafeLabelSchema)
        .min(1)
        .max(50)
        .refine(uniqueValues, "duplicate provider identifiers are not allowed"),
      sourceKinds: z
        .array(ObservationSourceKindSchema)
        .min(1)
        .max(6)
        .refine(uniqueValues, "duplicate source kinds are not allowed"),
      independentClusterCount: z.number().int().min(0).max(100),
    }),
    flags: z.strictObject({
      scam: UniqueSafeLabelsSchema,
      injection: UniqueSafeLabelsSchema,
      homograph: UniqueSafeLabelsSchema,
    }),
    scorecard: z.strictObject({
      confidence: UnitScoreSchema,
      marketSupport: UnitScoreSchema,
      opportunity: UnitScoreSchema,
      provenanceQuality: UnitScoreSchema,
      risk: UnitScoreSchema,
    }),
    disposition: ResearchProposalDispositionSchema,
  })
  .superRefine((proposal, context) => {
    if (Date.parse(proposal.expiresAt) <= Date.parse(proposal.createdAt)) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "must be later than createdAt",
      });
    }
    if (proposal.provenance.independentClusterCount > proposal.evidenceIds.length) {
      context.addIssue({
        code: "custom",
        path: ["provenance", "independentClusterCount"],
        message: "cannot exceed the number of evidence identifiers",
      });
    }
  });

export type ResearchProposalAbstentionReason = z.infer<
  typeof ResearchProposalAbstentionReasonSchema
>;
export type ResearchProposalDisposition = z.infer<typeof ResearchProposalDispositionSchema>;
export type ResearchProposalV1 = z.infer<typeof ResearchProposalV1Schema>;
