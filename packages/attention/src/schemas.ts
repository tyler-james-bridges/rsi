import { types as utilTypes } from "node:util";

import { z } from "zod";

import { hashCanonical } from "./hash.js";
import { compareStrings, toJsonValue } from "./json-types.js";

export const ATTENTION_POLICY_VERSION = "attention-v2" as const;
export const RECORDED_ATTENTION_STREAM_ID = "recorded-base-v1" as const;
export const BASE_CHAIN_ID = "8453" as const;
export const MARKETPLACE_VALIDITY_MS = 120_000;
export const SOCIAL_VALIDITY_MS = 7_200_000;
export const BASE_CONTEXT_VALIDITY_MS = 120_000;
export const MAX_BASE_BLOCK_AGE_MS = 7_200_000;
export const MAX_RETAINED_ATTENTION_FACTS = 1_000;
export const MAX_CANONICAL_TIME_MILLISECONDS = 8_640_000_000_000_000;

const MAX_PLAIN_ATTENTION_OBJECTS = MAX_RETAINED_ATTENTION_FACTS * 4 + 256;

export const HARD_REASONS = [
  "POST_CONTENT_CONFLICT",
  "SOCIAL_TIME_REGRESSION",
  "UNSUPPORTED_CHAIN",
  "ZERO_CONTRACT",
  "DUPLICATE_CONTRACT",
  "OVERLAPPING_CONTRACT_GROUPS",
  "SLUG_REBOUND",
  "IDENTITY_CONTINUITY_CONFLICT",
  "AMBIGUOUS_SOCIAL_IDENTITY",
  "SOCIAL_ADDRESS_CONFLICT",
  "INSTRUCTION_CONTENT",
  "WALLET_CONNECTION_SOLICITATION",
  "UNLIMITED_APPROVAL_SOLICITATION",
  "GUARANTEED_RETURN_CLAIM",
  "DECEPTIVE_LINK_INDICATOR",
  "MARKETPLACE_TIME_INVALID",
  "MARKETPLACE_FUTURE",
  "MARKETPLACE_STALE",
  "SOCIAL_FUTURE",
] as const;

export const WATCH_REASONS = [
  "ASSESSMENT_EXPIRED",
  "LEFT_WINDOW",
  "IDENTITY_CHANGED",
  "MISSING_X",
  "NO_BOUND_X",
  "STALE_X",
  "LINKS_UNCHECKED",
  "ATTENTION_BELOW_THRESHOLD",
] as const;

export const MISSING_CHECKS = [
  "authenticated_provenance",
  "independent_x_authors",
  "x_post_creation_times",
  "collection_contract_checks",
  "collection_security_review",
  "token_order_checks",
  "base_head_context",
  "link_destination_checks",
] as const;

export const NEXT_ACTIONS = [
  "resolve_collection_identity",
  "inspect_quarantined_indicators_offline",
  "supply_new_recorded_rank_window",
  "supply_bounded_social_evidence",
  "supply_fresh_social_evidence",
  "review_recorded_links_offline",
  "continue_recorded_observation",
  "manually_review_identity_and_sources",
] as const;

export const ATTENTION_NOTES = [
  "PARTIAL_MARKETPLACE_WINDOW",
  "PARTIAL_X_WINDOW",
  "COPIES_CAPPED",
  "AUTHORS_UNKNOWN",
  "BASE_CONTEXT_ONLY",
  "BASE_CONTEXT_STALE",
  "SLUG_CHANGED",
  "NO_SAFE_VERDICT",
] as const;

export const DIAGNOSTIC_CODES = [
  "UNBOUND_SOCIAL",
  "HOSTILE_UNBOUND_SOCIAL",
  "INVALID_BASE_CONTEXT",
  "STALE_BASE_CONTEXT",
] as const;

export const HardReasonSchema = z.enum(HARD_REASONS);
export const WatchReasonSchema = z.enum(WATCH_REASONS);
export const MissingCheckSchema = z.enum(MISSING_CHECKS);
export const NextActionSchema = z.enum(NEXT_ACTIONS);
export const AttentionNoteSchema = z.enum(ATTENTION_NOTES);
export const DiagnosticCodeSchema = z.enum(DIAGNOSTIC_CODES);

export type HardReason = z.infer<typeof HardReasonSchema>;
export type WatchReason = z.infer<typeof WatchReasonSchema>;
export type MissingCheck = z.infer<typeof MissingCheckSchema>;
export type NextAction = z.infer<typeof NextActionSchema>;
export type AttentionNote = z.infer<typeof AttentionNoteSchema>;
export type DiagnosticCode = z.infer<typeof DiagnosticCodeSchema>;

export const HashSchema = z.string().regex(/^[0-9a-f]{64}$/);
export const CollectionIdSchema = HashSchema.brand<"AttentionCollectionId">();
export const CandidateIdSchema = HashSchema.brand<"AttentionCandidateId">();
export const BundleIdSchema = HashSchema.brand<"AttentionBundleId">();
export const RefreshIdSchema = HashSchema.brand<"AttentionRefreshId">();
export const EvidenceIdSchema = HashSchema.brand<"AttentionEvidenceId">();
export const ContentClusterIdSchema = HashSchema.brand<"AttentionContentClusterId">();
export const PostIdHashSchema = HashSchema.brand<"AttentionPostIdHash">();

export const CanonicalTimeSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  }, "expected canonical UTC milliseconds");
const MarketplaceSourceTimeSchema = sourceTimeSchema(MARKETPLACE_VALIDITY_MS);
const SocialSourceTimeSchema = sourceTimeSchema(SOCIAL_VALIDITY_MS);
const BaseSourceTimeSchema = sourceTimeSchema(BASE_CONTEXT_VALIDITY_MS);
export const AddressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
export const LowerAddressSchema = z.string().regex(/^0x[0-9a-f]{40}$/);
export const ChainIdSchema = z.string().regex(/^(0|[1-9][0-9]{0,9})$/);
export const SlugSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/);
export const PostIdSchema = z.string().regex(/^[0-9]{1,32}$/);

export type CollectionId = z.infer<typeof CollectionIdSchema>;
export type CandidateId = z.infer<typeof CandidateIdSchema>;
export type BundleId = z.infer<typeof BundleIdSchema>;
export type RefreshId = z.infer<typeof RefreshIdSchema>;
export type EvidenceId = z.infer<typeof EvidenceIdSchema>;
export type ContentClusterId = z.infer<typeof ContentClusterIdSchema>;
export type PostIdHash = z.infer<typeof PostIdHashSchema>;

const RecordedMarketplaceCandidateSchema = z.strictObject({
  rank: z.number().int().min(1).max(10),
  slug: SlugSchema,
  contracts: z
    .array(
      z.strictObject({
        chainId: ChainIdSchema,
        address: AddressSchema,
      }),
    )
    .min(1)
    .max(16),
});

export const RecordedSocialPostSchema = z.strictObject({
  id: PostIdSchema,
  text: z.string().min(1).max(4_096),
});

const RecordedXSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("absent") }),
  z.strictObject({
    kind: z.literal("recorded_posts"),
    acquiredAt: SocialSourceTimeSchema,
    hasNextPage: z.boolean(),
    posts: z.array(RecordedSocialPostSchema).max(10),
  }),
]);

const RecordedBaseSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("absent") }),
  z.strictObject({
    kind: z.literal("reported_finalized_head"),
    chainId: ChainIdSchema,
    acquiredAt: BaseSourceTimeSchema,
    blockTimestamp: CanonicalTimeSchema,
  }),
]);

export const RecordedAttentionBundleSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    kind: z.literal("recorded_collection_attention"),
    marketplace: z.strictObject({
      kind: z.literal("recorded_rank_window"),
      acquiredAt: MarketplaceSourceTimeSchema,
      validUntil: CanonicalTimeSchema,
      hasNextPage: z.boolean(),
      candidates: z.array(RecordedMarketplaceCandidateSchema).max(10),
    }),
    x: RecordedXSchema,
    base: RecordedBaseSchema,
  })
  .superRefine((bundle, context) => {
    if (
      Date.parse(bundle.marketplace.validUntil) - Date.parse(bundle.marketplace.acquiredAt) !==
      MARKETPLACE_VALIDITY_MS
    ) {
      context.addIssue({
        code: "custom",
        path: ["marketplace", "validUntil"],
        message: "marketplace validity must be exactly 120 seconds",
      });
    }
    const ranks = bundle.marketplace.candidates.map((candidate) => candidate.rank);
    if (!isUniqueSorted(ranks, (left, right) => left - right)) {
      context.addIssue({
        code: "custom",
        path: ["marketplace", "candidates"],
        message: "marketplace ranks must be ordered and unique",
      });
    }
    const candidateKeys = bundle.marketplace.candidates.map((candidate) =>
      canonicalCandidateKey(candidate),
    );
    if (new Set(candidateKeys).size !== candidateKeys.length) {
      context.addIssue({
        code: "custom",
        path: ["marketplace", "candidates"],
        message: "marketplace candidates must not repeat exact rows",
      });
    }
    if (bundle.x.kind === "recorded_posts") {
      const ids = bundle.x.posts.map((post) => post.id);
      if (new Set(ids).size !== ids.length) {
        context.addIssue({
          code: "custom",
          path: ["x", "posts"],
          message: "post identifiers must be unique within a bundle",
        });
      }
    }
  });

export type RecordedAttentionBundleV1 = z.infer<typeof RecordedAttentionBundleSchema>;

const SanitizedContractSchema = z.strictObject({
  chainId: ChainIdSchema,
  address: LowerAddressSchema,
});

const SanitizedCandidateSchema = z.strictObject({
  rank: z.number().int().min(1).max(10),
  slug: SlugSchema,
  contracts: z.array(SanitizedContractSchema).min(1).max(16),
});

const SanitizedPostSchema = z.strictObject({
  postIdHash: PostIdHashSchema,
  contentClusterId: ContentClusterIdSchema,
  mentionedAddresses: z.array(LowerAddressSchema).max(97),
  detectedHardReasons: z.array(HardReasonSchema).max(5),
  detectedWatchReasons: z.array(WatchReasonSchema).max(1),
});

export const SanitizedRecordedBundleSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    kind: z.literal("sanitized_recorded_collection_attention"),
    marketplace: z.strictObject({
      kind: z.literal("recorded_rank_window"),
      acquiredAt: MarketplaceSourceTimeSchema,
      validUntil: CanonicalTimeSchema,
      hasNextPage: z.boolean(),
      candidates: z.array(SanitizedCandidateSchema).max(10),
    }),
    x: z.discriminatedUnion("kind", [
      z.strictObject({ kind: z.literal("absent") }),
      z.strictObject({
        kind: z.literal("recorded_posts"),
        acquiredAt: SocialSourceTimeSchema,
        hasNextPage: z.boolean(),
        posts: z.array(SanitizedPostSchema).max(10),
      }),
    ]),
    base: RecordedBaseSchema,
  })
  .superRefine((bundle, context) => {
    if (
      Date.parse(bundle.marketplace.validUntil) - Date.parse(bundle.marketplace.acquiredAt) !==
      MARKETPLACE_VALIDITY_MS
    ) {
      addCustomIssue(context, ["marketplace", "validUntil"]);
    }
    const ranks = bundle.marketplace.candidates.map((candidate) => candidate.rank);
    if (!isUniqueSorted(ranks, (left, right) => left - right)) {
      addCustomIssue(context, ["marketplace", "candidates"]);
    }
    bundle.marketplace.candidates.forEach((candidate, candidateIndex) => {
      if (!isSorted(candidate.contracts, compareContractFacts)) {
        addCustomIssue(context, ["marketplace", "candidates", candidateIndex, "contracts"]);
      }
    });
    const candidateKeys = bundle.marketplace.candidates.map((candidate) =>
      canonicalCandidateKey(candidate),
    );
    if (new Set(candidateKeys).size !== candidateKeys.length) {
      addCustomIssue(context, ["marketplace", "candidates"]);
    }
    if (bundle.x.kind === "recorded_posts") {
      if (
        !isUniqueSorted(
          bundle.x.posts.map((post) => post.postIdHash),
          compareStrings,
        )
      ) {
        addCustomIssue(context, ["x", "posts"]);
      }
      bundle.x.posts.forEach((post, postIndex) => {
        if (!isUniqueSortedStrings(post.mentionedAddresses)) {
          addCustomIssue(context, ["x", "posts", postIndex, "mentionedAddresses"]);
        }
        if (!isEnumOrdered(post.detectedHardReasons, HARD_REASONS)) {
          addCustomIssue(context, ["x", "posts", postIndex, "detectedHardReasons"]);
        }
        if (!isEnumOrdered(post.detectedWatchReasons, WATCH_REASONS)) {
          addCustomIssue(context, ["x", "posts", postIndex, "detectedWatchReasons"]);
        }
      });
    }
  });

export type SanitizedRecordedBundleV1 = z.infer<typeof SanitizedRecordedBundleSchema>;

export const BaseCollectionIdentitySchema = z
  .strictObject({
    kind: z.literal("base_collection"),
    chainId: z.literal(BASE_CHAIN_ID),
    collectionId: CollectionIdSchema,
    contracts: z.array(LowerAddressSchema).min(1).max(16),
  })
  .superRefine((identity, context) => {
    if (!isUniqueSortedStrings(identity.contracts)) {
      addCustomIssue(context, ["contracts"]);
    }
    const expected = hashCanonical(
      "rsi-attention-base-collection-v1\0",
      toJsonValue({ chainId: BASE_CHAIN_ID, contracts: identity.contracts }),
    );
    if (identity.collectionId !== expected) addCustomIssue(context, ["collectionId"]);
  });

export type BaseCollectionIdentityV1 = z.infer<typeof BaseCollectionIdentitySchema>;

export const SubjectSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("resolved"), identity: BaseCollectionIdentitySchema }),
  z.strictObject({ kind: z.literal("unresolved"), candidateId: CandidateIdSchema }),
]);

export const RecordedProvenanceSchema = z.strictObject({
  kind: z.literal("operator_supplied_unverified"),
  streamId: z.literal(RECORDED_ATTENTION_STREAM_ID),
  bundleId: BundleIdSchema,
});

export const ScorecardSchema = z
  .strictObject({
    rank: z.number().int().min(0).max(40),
    upwardMovement: z.number().int().min(0).max(10),
    socialPresence: z.number().int().min(0).max(10),
    total: z.number().int().min(0).max(60),
    observedContentClusters: z.number().int().min(0).max(10),
    countedContentClusters: z.number().int().min(0).max(2),
  })
  .refine(
    (scorecard) =>
      scorecard.total === scorecard.rank + scorecard.upwardMovement + scorecard.socialPresence,
    "scorecard total must equal its components",
  );

export const OutcomeSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("review"),
    priority: z.number().int().min(36).max(60),
  }),
  z.strictObject({
    kind: z.literal("watch"),
    reasons: z.array(WatchReasonSchema).min(1).max(WATCH_REASONS.length),
    priority: z.number().int().min(0).max(60),
  }),
  z.strictObject({
    kind: z.literal("rejected"),
    reasons: z.array(HardReasonSchema).min(1).max(HARD_REASONS.length),
    priority: z.null(),
  }),
]);

export const PresenceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("observed"),
    rank: z.number().int().min(1).max(10),
  }),
  z.strictObject({
    kind: z.literal("left_window"),
    previousRank: z.number().int().min(1).max(10),
  }),
]);

export const RankComparisonSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("not_observed") }),
  z.strictObject({
    kind: z.literal("not_comparable"),
    reason: z.enum([
      "first_observation",
      "predecessor_expired",
      "different_stream",
      "identity_unresolved",
    ]),
  }),
  z.strictObject({
    kind: z.literal("comparable"),
    previousRank: z.number().int().min(1).max(10),
    delta: z.number().int().min(-9).max(9),
  }),
]);

const RESOLVED_IDENTITY_CONFLICT_REASONS = new Set<HardReason>([
  "OVERLAPPING_CONTRACT_GROUPS",
  "SLUG_REBOUND",
  "IDENTITY_CONTINUITY_CONFLICT",
]);

export const AssessmentRowSchema = z
  .strictObject({
    rowId: z.union([CollectionIdSchema, CandidateIdSchema]),
    subject: SubjectSchema,
    slug: SlugSchema,
    presence: PresenceSchema,
    comparison: RankComparisonSchema,
    scorecard: ScorecardSchema.nullable(),
    evidenceIds: z.array(EvidenceIdSchema).max(11),
    assessedAt: CanonicalTimeSchema,
    expiresAt: CanonicalTimeSchema,
    provenance: RecordedProvenanceSchema,
    missingChecks: z.array(MissingCheckSchema).max(MISSING_CHECKS.length),
    notes: z.array(AttentionNoteSchema).max(ATTENTION_NOTES.length),
    outcome: OutcomeSchema,
    nextAction: NextActionSchema,
  })
  .superRefine((row, context) => {
    const resolvedIdentityConflict =
      row.subject.kind === "resolved" &&
      row.outcome.kind === "rejected" &&
      row.outcome.reasons.some((reason) => RESOLVED_IDENTITY_CONFLICT_REASONS.has(reason));
    const expectedRowId =
      row.subject.kind === "unresolved"
        ? row.subject.candidateId
        : resolvedIdentityConflict
          ? hashCanonical(
              "rsi-attention-candidate-v1\0",
              toJsonValue({
                slug: row.slug,
                contracts: row.subject.identity.contracts.map((address) => ({
                  chainId: BASE_CHAIN_ID,
                  address,
                })),
              }),
            )
          : row.subject.identity.collectionId;
    if (row.rowId !== expectedRowId) {
      addCustomIssue(context, ["rowId"]);
    }
    if (!isUniqueSortedStrings(row.evidenceIds)) {
      addCustomIssue(context, ["evidenceIds"]);
    }
    if (!isEnumOrdered(row.missingChecks, MISSING_CHECKS)) {
      addCustomIssue(context, ["missingChecks"]);
    }
    if (!isEnumOrdered(row.notes, ATTENTION_NOTES)) {
      addCustomIssue(context, ["notes"]);
    }
    if (row.outcome.kind === "rejected" && !isEnumOrdered(row.outcome.reasons, HARD_REASONS)) {
      addCustomIssue(context, ["outcome", "reasons"]);
    }
    if (row.outcome.kind === "watch" && !isEnumOrdered(row.outcome.reasons, WATCH_REASONS)) {
      addCustomIssue(context, ["outcome", "reasons"]);
    }
    if (row.subject.kind === "unresolved" && row.outcome.kind !== "rejected") {
      context.addIssue({ code: "custom", path: ["outcome"], message: "unresolved rows reject" });
    }
    if (row.presence.kind === "left_window") {
      if (row.scorecard !== null || row.comparison.kind !== "not_observed") {
        context.addIssue({
          code: "custom",
          path: ["presence"],
          message: "left-window rows have no current score or comparison",
        });
      }
      if (
        row.outcome.kind !== "watch" ||
        row.outcome.priority !== 0 ||
        row.outcome.reasons.length !== 1 ||
        row.outcome.reasons[0] !== "LEFT_WINDOW"
      ) {
        context.addIssue({
          code: "custom",
          path: ["outcome"],
          message: "departures are closed left-window observations",
        });
      }
    } else if (row.scorecard === null) {
      context.addIssue({
        code: "custom",
        path: ["scorecard"],
        message: "observed rows require a scorecard",
      });
    } else {
      const expectedRankScore = 4 * (11 - row.presence.rank);
      const expectedMovement =
        row.comparison.kind === "comparable"
          ? Math.min(10, 2 * Math.max(0, row.comparison.delta))
          : 0;
      if (
        row.scorecard.rank !== expectedRankScore ||
        row.scorecard.upwardMovement !== expectedMovement ||
        row.scorecard.socialPresence !== row.scorecard.countedContentClusters * 5 ||
        row.scorecard.countedContentClusters > row.scorecard.observedContentClusters
      ) {
        addCustomIssue(context, ["scorecard"]);
      }
      if (
        row.comparison.kind === "not_observed" ||
        (row.comparison.kind === "comparable" &&
          row.comparison.delta !== row.comparison.previousRank - row.presence.rank)
      ) {
        addCustomIssue(context, ["comparison"]);
      }
      if (row.outcome.kind === "watch" && row.outcome.reasons.includes("LEFT_WINDOW")) {
        addCustomIssue(context, ["outcome", "reasons"]);
      }
    }
    if (row.outcome.kind === "review") {
      if (
        row.scorecard?.total !== row.outcome.priority ||
        row.scorecard.socialPresence === 0 ||
        row.scorecard.countedContentClusters === 0
      ) {
        context.addIssue({
          code: "custom",
          path: ["outcome"],
          message: "review requires fresh bound social evidence and exact priority",
        });
      }
    }
    if (
      row.outcome.kind === "watch" &&
      row.presence.kind === "observed" &&
      !row.outcome.reasons.includes("ASSESSMENT_EXPIRED") &&
      row.outcome.priority !== row.scorecard?.total
    ) {
      context.addIssue({
        code: "custom",
        path: ["outcome", "priority"],
        message: "watch priority must equal the current score",
      });
    }
    if (
      row.outcome.kind === "watch" &&
      row.outcome.reasons.includes("ASSESSMENT_EXPIRED") &&
      row.outcome.priority !== 0
    ) {
      addCustomIssue(context, ["outcome", "priority"]);
    }
    if (
      Date.parse(row.expiresAt) <= Date.parse(row.assessedAt) &&
      row.presence.kind !== "left_window" &&
      (row.outcome.kind !== "rejected" || !row.outcome.reasons.includes("MARKETPLACE_STALE"))
    ) {
      addCustomIssue(context, ["expiresAt"]);
    }
  });

export type CollectionAttentionRowV1 = z.infer<typeof AssessmentRowSchema>;

export const SourceSummarySchema = z.strictObject({
  marketplace: z.strictObject({
    acquiredAt: MarketplaceSourceTimeSchema,
    validUntil: CanonicalTimeSchema,
    candidateCount: z.number().int().min(0).max(10),
    hasNextPage: z.boolean(),
    usable: z.boolean(),
    priorUsableWindowId: EvidenceIdSchema.nullable(),
  }),
  x: z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("absent") }),
    z.strictObject({
      kind: z.literal("observed"),
      acquiredAt: SocialSourceTimeSchema,
      validUntil: CanonicalTimeSchema,
      postCount: z.number().int().min(0).max(10),
      usableBoundClusterCount: z.number().int().min(0).max(10),
      hasNextPage: z.boolean(),
    }),
  ]),
  base: z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("absent") }),
    z.strictObject({ kind: z.literal("invalid") }),
    z.strictObject({
      kind: z.literal("usable"),
      acquiredAt: BaseSourceTimeSchema,
      validUntil: CanonicalTimeSchema,
      blockTimestamp: CanonicalTimeSchema,
    }),
    z.strictObject({
      kind: z.literal("stale"),
      acquiredAt: BaseSourceTimeSchema,
      validUntil: CanonicalTimeSchema,
      blockTimestamp: CanonicalTimeSchema,
    }),
  ]),
});

export const DiagnosticSchema = z.strictObject({
  evidenceId: EvidenceIdSchema,
  code: DiagnosticCodeSchema,
});

export const CollectionAttentionAssessmentSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    kind: z.literal("collection_attention_assessment"),
    policyVersion: z.literal(ATTENTION_POLICY_VERSION),
    streamId: z.literal(RECORDED_ATTENTION_STREAM_ID),
    bundleId: BundleIdSchema,
    refreshId: RefreshIdSchema,
    predecessorId: RefreshIdSchema.nullable(),
    evaluatedAt: CanonicalTimeSchema,
    rows: z.array(AssessmentRowSchema).max(20),
    sourceSummary: SourceSummarySchema,
    diagnostics: z.array(DiagnosticSchema).max(10),
  })
  .superRefine((assessment, context) => {
    if (new Set(assessment.rows.map((row) => row.rowId)).size !== assessment.rows.length) {
      addCustomIssue(context, ["rows"]);
    }
    assessment.rows.forEach((row, index) => {
      if (
        row.assessedAt !== assessment.evaluatedAt ||
        row.provenance.bundleId !== assessment.bundleId
      ) {
        addCustomIssue(context, ["rows", index]);
      }
    });
    const diagnosticKeys = assessment.diagnostics.map(
      (diagnostic) => `${diagnostic.code}\0${diagnostic.evidenceId}`,
    );
    if (
      new Set(diagnosticKeys).size !== diagnosticKeys.length ||
      !isSorted(
        assessment.diagnostics,
        (left, right) =>
          DIAGNOSTIC_CODES.indexOf(left.code) - DIAGNOSTIC_CODES.indexOf(right.code) ||
          compareStrings(left.evidenceId, right.evidenceId),
      )
    ) {
      addCustomIssue(context, ["diagnostics"]);
    }
  });

export type CollectionAttentionAssessmentV1 = z.infer<typeof CollectionAttentionAssessmentSchema>;

const KnownCollectionSchema = z.strictObject({
  identity: BaseCollectionIdentitySchema,
  latestSlug: SlugSchema,
});

const SlugAssociationSchema = z.strictObject({
  slug: SlugSchema,
  collectionId: CollectionIdSchema,
});

const PriorRankRowSchema = z.strictObject({
  identity: BaseCollectionIdentitySchema,
  slug: SlugSchema,
  rank: z.number().int().min(1).max(10),
  evidenceId: EvidenceIdSchema,
});

const PriorUsableRankWindowSchema = z.strictObject({
  evidenceId: EvidenceIdSchema,
  acquiredAt: MarketplaceSourceTimeSchema,
  validUntil: CanonicalTimeSchema,
  rows: z.array(PriorRankRowSchema).max(10),
});

const PostBindingSchema = z.strictObject({
  postIdHash: PostIdHashSchema,
  contentClusterId: ContentClusterIdSchema,
});

const ClusterFirstSeenSchema = z.strictObject({
  contentClusterId: ContentClusterIdSchema,
  firstSeenAt: SocialSourceTimeSchema,
});

const ConflictingClusterFirstSeenSchema = ClusterFirstSeenSchema.extend({
  conflictingPostIdHash: PostIdHashSchema,
});

export const RecordedAttentionFactsSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    streamId: z.literal(RECORDED_ATTENTION_STREAM_ID),
    headRefreshId: RefreshIdSchema.nullable(),
    latestUsableRankWindow: PriorUsableRankWindowSchema.nullable(),
    latestAdmittedXAcquiredAt: SocialSourceTimeSchema.nullable(),
    knownCollections: z.array(KnownCollectionSchema).max(MAX_RETAINED_ATTENTION_FACTS),
    slugAssociations: z.array(SlugAssociationSchema).max(MAX_RETAINED_ATTENTION_FACTS),
    postBindings: z.array(PostBindingSchema).max(MAX_RETAINED_ATTENTION_FACTS),
    clusterFirstSeen: z.array(ClusterFirstSeenSchema).max(MAX_RETAINED_ATTENTION_FACTS),
    conflictingClusterFirstSeen: z
      .array(ConflictingClusterFirstSeenSchema)
      .max(MAX_RETAINED_ATTENTION_FACTS),
  })
  .superRefine((facts, context) => {
    const retainedFactCount =
      facts.knownCollections.length +
      facts.slugAssociations.length +
      facts.postBindings.length +
      facts.clusterFirstSeen.length +
      facts.conflictingClusterFirstSeen.length;
    if (retainedFactCount > MAX_RETAINED_ATTENTION_FACTS) {
      addCustomIssue(context, []);
    }
    const knownIds = facts.knownCollections.map((known) => known.identity.collectionId);
    if (!isUniqueSortedStrings(knownIds)) addCustomIssue(context, ["knownCollections"]);
    const knownSet = new Set(knownIds);
    const associationKeys = facts.slugAssociations.map(
      (association) => `${association.slug}\0${association.collectionId}`,
    );
    if (
      !isUniqueSortedStrings(associationKeys) ||
      facts.slugAssociations.some((association) => !knownSet.has(association.collectionId))
    ) {
      addCustomIssue(context, ["slugAssociations"]);
    }
    const postIds = facts.postBindings.map((binding) => binding.postIdHash);
    if (!isUniqueSortedStrings(postIds)) addCustomIssue(context, ["postBindings"]);
    const postBindingsById = new Map(
      facts.postBindings.map((binding) => [binding.postIdHash, binding]),
    );
    const clusterIds = facts.clusterFirstSeen.map((cluster) => cluster.contentClusterId);
    if (!isUniqueSortedStrings(clusterIds)) addCustomIssue(context, ["clusterFirstSeen"]);
    const conflictingClusterIds = facts.conflictingClusterFirstSeen.map(
      (cluster) => cluster.contentClusterId,
    );
    if (!isUniqueSortedStrings(conflictingClusterIds)) {
      addCustomIssue(context, ["conflictingClusterFirstSeen"]);
    }
    const retainedClusterIds = new Set([...clusterIds, ...conflictingClusterIds]);
    if (retainedClusterIds.size !== clusterIds.length + conflictingClusterIds.length) {
      addCustomIssue(context, ["conflictingClusterFirstSeen"]);
    }
    const ordinaryClusterIds = new Set(clusterIds);
    const conflictingClustersById = new Map(
      facts.conflictingClusterFirstSeen.map((cluster) => [cluster.contentClusterId, cluster]),
    );
    const firstSeenByClusterId = new Map(
      [...facts.clusterFirstSeen, ...facts.conflictingClusterFirstSeen].map((cluster) => [
        cluster.contentClusterId,
        cluster.firstSeenAt,
      ]),
    );
    const referencedClusterIds = new Set(
      facts.postBindings.map((binding) => binding.contentClusterId),
    );
    facts.postBindings.forEach((binding, index) => {
      if (!retainedClusterIds.has(binding.contentClusterId)) {
        addCustomIssue(context, ["postBindings", index, "contentClusterId"]);
      }
    });
    facts.clusterFirstSeen.forEach((cluster, index) => {
      if (!referencedClusterIds.has(cluster.contentClusterId)) {
        addCustomIssue(context, ["clusterFirstSeen", index, "contentClusterId"]);
      }
    });
    facts.conflictingClusterFirstSeen.forEach((cluster, index) => {
      const binding = postBindingsById.get(cluster.conflictingPostIdHash);
      if (
        binding === undefined ||
        binding.contentClusterId === cluster.contentClusterId ||
        !conflictChainReachesOrdinaryCluster({
          firstPredecessorId: binding.contentClusterId,
          initialClusterId: cluster.contentClusterId,
          initialFirstSeenAt: cluster.firstSeenAt,
          ordinaryClusterIds,
          conflictingClustersById,
          firstSeenByClusterId,
          postBindingsById,
        })
      ) {
        addCustomIssue(context, ["conflictingClusterFirstSeen", index]);
      }
    });
    const hasSocialIntegrityFacts =
      facts.postBindings.length > 0 ||
      facts.clusterFirstSeen.length > 0 ||
      facts.conflictingClusterFirstSeen.length > 0;
    if (facts.latestAdmittedXAcquiredAt === null && hasSocialIntegrityFacts) {
      addCustomIssue(context, ["latestAdmittedXAcquiredAt"]);
    }
    if (facts.latestAdmittedXAcquiredAt !== null) {
      const latestAdmittedXMilliseconds = Date.parse(facts.latestAdmittedXAcquiredAt);
      facts.clusterFirstSeen.forEach((cluster, index) => {
        if (Date.parse(cluster.firstSeenAt) > latestAdmittedXMilliseconds) {
          addCustomIssue(context, ["clusterFirstSeen", index, "firstSeenAt"]);
        }
      });
      facts.conflictingClusterFirstSeen.forEach((cluster, index) => {
        if (Date.parse(cluster.firstSeenAt) > latestAdmittedXMilliseconds) {
          addCustomIssue(context, ["conflictingClusterFirstSeen", index, "firstSeenAt"]);
        }
      });
    }
    if (facts.latestUsableRankWindow !== null) {
      const window = facts.latestUsableRankWindow;
      if (
        Date.parse(window.validUntil) - Date.parse(window.acquiredAt) !==
        MARKETPLACE_VALIDITY_MS
      ) {
        addCustomIssue(context, ["latestUsableRankWindow", "validUntil"]);
      }
      const rowIds = window.rows.map((row) => row.identity.collectionId);
      if (
        new Set(rowIds).size !== rowIds.length ||
        window.rows.some((row) => !knownSet.has(row.identity.collectionId))
      ) {
        addCustomIssue(context, ["latestUsableRankWindow", "rows"]);
      }
    }
  });

export type RecordedAttentionFactsV1 = z.infer<typeof RecordedAttentionFactsSchema>;

export const AssessRecordedAttentionInputSchema = z.strictObject({
  recordedBundle: RecordedAttentionBundleSchema,
  evaluatedAt: CanonicalTimeSchema,
  priorFacts: RecordedAttentionFactsSchema.optional(),
});
export type AssessRecordedAttentionInputV1 = z.infer<typeof AssessRecordedAttentionInputSchema>;

export const AssessStoredRecordedAttentionInputSchema = z.strictObject({
  sourceFacts: SanitizedRecordedBundleSchema,
  evaluatedAt: CanonicalTimeSchema,
  priorFacts: RecordedAttentionFactsSchema.optional(),
});
export type AssessStoredRecordedAttentionInputV1 = z.infer<
  typeof AssessStoredRecordedAttentionInputSchema
>;

export const RecordedAttentionAssessmentResultSchema = z.strictObject({
  assessment: CollectionAttentionAssessmentSchema,
  nextFacts: RecordedAttentionFactsSchema,
});

export type RecordedAttentionAssessmentResultV1 = z.infer<
  typeof RecordedAttentionAssessmentResultSchema
>;

export class AttentionInputError extends TypeError {
  readonly code = "attention_input_invalid";

  constructor() {
    super("attention_input_invalid");
    this.name = "AttentionInputError";
  }
}

export function assertPlainAttentionData(value: unknown): void {
  const seen = new WeakSet<object>();
  let objectCount = 0;

  const visit = (current: unknown, depth: number): void => {
    if (depth > 12) throw new AttentionInputError();
    if (current === null || typeof current !== "object") return;
    if (utilTypes.isProxy(current) || seen.has(current)) throw new AttentionInputError();
    seen.add(current);
    objectCount += 1;
    if (objectCount > MAX_PLAIN_ATTENTION_OBJECTS) throw new AttentionInputError();

    const isArray = Array.isArray(current);
    const expectedPrototype = isArray ? Array.prototype : Object.prototype;
    const prototype = Object.getPrototypeOf(current);
    if (prototype !== expectedPrototype && !(prototype === null && !isArray)) {
      throw new AttentionInputError();
    }

    const keys = Reflect.ownKeys(current);
    if (
      isArray &&
      (current.length > MAX_RETAINED_ATTENTION_FACTS || keys.length !== current.length + 1)
    ) {
      throw new AttentionInputError();
    }
    for (const key of keys) {
      if (isArray && key === "length") continue;
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (
        typeof key !== "string" ||
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable ||
        (isArray && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= current.length))
      ) {
        throw new AttentionInputError();
      }
      visit(descriptor.value, depth + 1);
    }
  };

  visit(value, 0);
}

export function parseRecordedAttentionBundle(input: unknown): RecordedAttentionBundleV1 {
  assertPlainAttentionData(input);
  const parsed = RecordedAttentionBundleSchema.safeParse(input);
  if (!parsed.success) throw new AttentionInputError();
  return deepFreeze(parsed.data);
}

export function parseCanonicalTime(input: unknown): string {
  const parsed = CanonicalTimeSchema.safeParse(input);
  if (!parsed.success) throw new AttentionInputError();
  return parsed.data;
}

export function emptyRecordedAttentionFacts(): RecordedAttentionFactsV1 {
  return deepFreeze(
    RecordedAttentionFactsSchema.parse({
      schemaVersion: 1,
      streamId: RECORDED_ATTENTION_STREAM_ID,
      headRefreshId: null,
      latestUsableRankWindow: null,
      latestAdmittedXAcquiredAt: null,
      knownCollections: [],
      slugAssociations: [],
      postBindings: [],
      clusterFirstSeen: [],
      conflictingClusterFirstSeen: [],
    }),
  );
}

export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function compareContractFacts(
  left: { readonly chainId: string; readonly address: string },
  right: { readonly chainId: string; readonly address: string },
): number {
  return (
    Number(left.chainId) - Number(right.chainId) || compareStrings(left.address, right.address)
  );
}

function canonicalCandidateKey(candidate: {
  readonly slug: string;
  readonly contracts: readonly { readonly chainId: string; readonly address: string }[];
}): string {
  const contracts = candidate.contracts
    .map((contract) => `${contract.chainId}:${contract.address.toLowerCase()}`)
    .sort()
    .join(",");
  return `${candidate.slug}\0${contracts}`;
}

function isSorted<T>(values: readonly T[], compare: (left: T, right: T) => number): boolean {
  return values.every((value, index) => index === 0 || compare(values[index - 1]!, value) <= 0);
}

function isUniqueSorted<T>(values: readonly T[], compare: (left: T, right: T) => number): boolean {
  return values.every((value, index) => index === 0 || compare(values[index - 1]!, value) < 0);
}

function isUniqueSortedStrings(values: readonly string[]): boolean {
  return isUniqueSorted(values, compareStrings);
}

function isEnumOrdered<T extends string>(values: readonly T[], order: readonly T[]): boolean {
  const positions = values.map((value) => order.indexOf(value));
  return positions.every(
    (position, index) => position >= 0 && (index === 0 || positions[index - 1]! < position),
  );
}

function sourceTimeSchema(maximumAdditionMilliseconds: number) {
  return CanonicalTimeSchema.refine(
    (value) => Date.parse(value) <= MAX_CANONICAL_TIME_MILLISECONDS - maximumAdditionMilliseconds,
    "source timestamp exceeds derivation range",
  );
}

function conflictChainReachesOrdinaryCluster(input: {
  readonly firstPredecessorId: ContentClusterId;
  readonly initialClusterId: ContentClusterId;
  readonly initialFirstSeenAt: string;
  readonly ordinaryClusterIds: ReadonlySet<ContentClusterId>;
  readonly conflictingClustersById: ReadonlyMap<
    ContentClusterId,
    z.infer<typeof ConflictingClusterFirstSeenSchema>
  >;
  readonly firstSeenByClusterId: ReadonlyMap<ContentClusterId, string>;
  readonly postBindingsById: ReadonlyMap<PostIdHash, z.infer<typeof PostBindingSchema>>;
}): boolean {
  const visited = new Set<ContentClusterId>([input.initialClusterId]);
  let descendantFirstSeenMilliseconds = Date.parse(input.initialFirstSeenAt);
  let predecessorId = input.firstPredecessorId;
  while (true) {
    if (visited.has(predecessorId)) return false;
    visited.add(predecessorId);
    const predecessorFirstSeenAt = input.firstSeenByClusterId.get(predecessorId);
    if (predecessorFirstSeenAt === undefined) return false;
    const predecessorFirstSeenMilliseconds = Date.parse(predecessorFirstSeenAt);
    if (descendantFirstSeenMilliseconds < predecessorFirstSeenMilliseconds) return false;
    if (input.ordinaryClusterIds.has(predecessorId)) return true;
    const predecessor = input.conflictingClustersById.get(predecessorId);
    if (predecessor === undefined) return false;
    const witness = input.postBindingsById.get(predecessor.conflictingPostIdHash);
    if (witness === undefined) return false;
    descendantFirstSeenMilliseconds = predecessorFirstSeenMilliseconds;
    predecessorId = witness.contentClusterId;
  }
}

function addCustomIssue(context: z.RefinementCtx, path: readonly PropertyKey[]): void {
  context.addIssue({
    code: "custom",
    path: [...path],
    message: "attention canonical invariant failed",
  });
}
