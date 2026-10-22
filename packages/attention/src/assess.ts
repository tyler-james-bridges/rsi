import { hashCanonical } from "./hash.js";
import { contractsOverlap, deriveCandidateIdentity, type SanitizedCandidate } from "./identity.js";
import { compareStrings, toJsonValue } from "./json-types.js";
import { recordedBundleId, recordedRefreshId } from "./sanitize.js";
import {
  ATTENTION_NOTES,
  ATTENTION_POLICY_VERSION,
  BASE_CHAIN_ID,
  BASE_CONTEXT_VALIDITY_MS,
  CollectionAttentionAssessmentSchema,
  DIAGNOSTIC_CODES,
  EvidenceIdSchema,
  HARD_REASONS,
  MAX_BASE_BLOCK_AGE_MS,
  MISSING_CHECKS,
  RECORDED_ATTENTION_STREAM_ID,
  RecordedAttentionAssessmentResultSchema,
  RecordedAttentionFactsSchema,
  SOCIAL_VALIDITY_MS,
  WATCH_REASONS,
  AssessRecordedAttentionInputSchema,
  AttentionInputError,
  assertPlainAttentionData,
  deepFreeze,
  emptyRecordedAttentionFacts,
  type AttentionNote,
  type BaseCollectionIdentityV1,
  type CollectionAttentionAssessmentV1,
  type CollectionAttentionRowV1,
  type CollectionId,
  type DiagnosticCode,
  type EvidenceId,
  type HardReason,
  type MissingCheck,
  type NextAction,
  type RecordedAttentionAssessmentResultV1,
  type RecordedAttentionFactsV1,
  type SanitizedRecordedBundleV1,
  type WatchReason,
} from "./schemas.js";

const IDENTITY_HARD_REASONS = new Set<HardReason>([
  "UNSUPPORTED_CHAIN",
  "ZERO_CONTRACT",
  "DUPLICATE_CONTRACT",
  "OVERLAPPING_CONTRACT_GROUPS",
  "SLUG_REBOUND",
  "IDENTITY_CONTINUITY_CONFLICT",
]);

interface CandidateState {
  readonly candidate: SanitizedCandidate;
  readonly candidateId: ReturnType<typeof deriveCandidateIdentity>["candidateId"];
  readonly identity: BaseCollectionIdentityV1 | null;
  readonly hardReasons: Set<HardReason>;
  readonly watchReasons: Set<WatchReason>;
  readonly notes: Set<AttentionNote>;
  readonly matchedPosts: SocialState[];
  readonly observedClusters: Set<string>;
  readonly freshClusters: Map<string, string>;
  readonly evidenceIds: Set<EvidenceId>;
}

interface SocialState {
  readonly post: Extract<
    SanitizedRecordedBundleV1["x"],
    { kind: "recorded_posts" }
  >["posts"][number];
  readonly matchedCollectionIds: readonly CollectionId[];
  readonly attributableCollectionId: CollectionId | null;
  readonly contentConflict: boolean;
  readonly timeRegression: boolean;
  readonly future: boolean;
  readonly firstSeenAt: string;
  readonly validUntil: string;
  readonly evidenceId: EvidenceId;
}

interface BaseContextResult {
  readonly summary: CollectionAttentionAssessmentV1["sourceSummary"]["base"];
  readonly diagnostic: CollectionAttentionAssessmentV1["diagnostics"][number] | null;
  readonly usable: boolean;
}

export interface AssessRecordedAttentionInput {
  readonly sourceFacts: SanitizedRecordedBundleV1;
  readonly evaluatedAt: string;
  readonly priorFacts?: RecordedAttentionFactsV1;
}

export function assessRecordedAttention(
  input: AssessRecordedAttentionInput,
): RecordedAttentionAssessmentResultV1 {
  assertPlainAttentionData(input);
  const parsedInput = AssessRecordedAttentionInputSchema.safeParse(input);
  if (!parsedInput.success) throw new AttentionInputError();
  const sourceFacts = parsedInput.data.sourceFacts;
  const priorFacts = parsedInput.data.priorFacts ?? emptyRecordedAttentionFacts();
  const evaluatedAt = parsedInput.data.evaluatedAt;
  const evaluatedMilliseconds = Date.parse(evaluatedAt);
  const bundleId = recordedBundleId(sourceFacts);
  const refreshId = recordedRefreshId(bundleId);
  const provenance = {
    kind: "operator_supplied_unverified" as const,
    streamId: RECORDED_ATTENTION_STREAM_ID,
    bundleId,
  };
  const rankEvidenceId = evidenceId("rsi-attention-rank-window-evidence-v1\0", {
    schemaVersion: 1,
    kind: "rank_window",
    acquiredAt: sourceFacts.marketplace.acquiredAt,
    validUntil: sourceFacts.marketplace.validUntil,
    hasNextPage: sourceFacts.marketplace.hasNextPage,
    candidates: sourceFacts.marketplace.candidates,
    provenance,
  });
  const states = sourceFacts.marketplace.candidates.map((candidate): CandidateState => {
    const identity = deriveCandidateIdentity(candidate);
    return {
      candidate,
      candidateId: identity.candidateId,
      identity: identity.identity,
      hardReasons: new Set(identity.reasons),
      watchReasons: new Set<WatchReason>(),
      notes: new Set<AttentionNote>(["NO_SAFE_VERDICT"]),
      matchedPosts: [],
      observedClusters: new Set<string>(),
      freshClusters: new Map<string, string>(),
      evidenceIds: new Set<EvidenceId>([rankEvidenceId]),
    };
  });

  applyCurrentIdentityConflicts(states);
  applyHistoricalIdentityFacts(states, priorFacts);

  const marketplaceTimeReasons = marketplaceHardReasons(
    sourceFacts,
    priorFacts,
    evaluatedMilliseconds,
  );
  for (const state of states) {
    for (const reason of marketplaceTimeReasons) state.hardReasons.add(reason);
    if (sourceFacts.marketplace.hasNextPage) state.notes.add("PARTIAL_MARKETPLACE_WINDOW");
  }
  const marketplaceUsable = marketplaceTimeReasons.length === 0;

  const social = analyzeSocial({
    sourceFacts,
    states,
    priorFacts,
    evaluatedAt,
    bundleId,
    provenance,
  });
  const base = analyzeBaseContext(sourceFacts, evaluatedMilliseconds, bundleId);
  for (const state of states) {
    if (sourceFacts.x.kind === "recorded_posts" && sourceFacts.x.hasNextPage) {
      state.notes.add("PARTIAL_X_WINDOW");
    }
    if (base.summary.kind === "usable") state.notes.add("BASE_CONTEXT_ONLY");
    if (base.summary.kind === "stale") state.notes.add("BASE_CONTEXT_STALE");
  }

  const rows = states.map((state) =>
    buildObservedRow({
      state,
      sourceFacts,
      priorFacts,
      evaluatedAt,
      provenance,
      baseUsable: base.usable,
    }),
  );
  if (marketplaceUsable) {
    rows.push(
      ...buildDepartureRows({
        states,
        sourceFacts,
        priorFacts,
        evaluatedAt,
        provenance,
        baseUsable: base.usable,
      }),
    );
  }
  rows.sort(compareRows);

  const diagnostics = [...social.diagnostics];
  if (base.diagnostic !== null) diagnostics.push(base.diagnostic);
  diagnostics.sort(
    (left, right) =>
      DIAGNOSTIC_CODES.indexOf(left.code) - DIAGNOSTIC_CODES.indexOf(right.code) ||
      compareStrings(left.evidenceId, right.evidenceId),
  );

  const assessment = CollectionAttentionAssessmentSchema.parse({
    schemaVersion: 1,
    kind: "collection_attention_assessment",
    policyVersion: ATTENTION_POLICY_VERSION,
    streamId: RECORDED_ATTENTION_STREAM_ID,
    bundleId,
    refreshId,
    predecessorId: priorFacts.headRefreshId,
    evaluatedAt,
    rows,
    sourceSummary: {
      marketplace: {
        acquiredAt: sourceFacts.marketplace.acquiredAt,
        validUntil: sourceFacts.marketplace.validUntil,
        candidateCount: sourceFacts.marketplace.candidates.length,
        hasNextPage: sourceFacts.marketplace.hasNextPage,
        usable: marketplaceUsable,
        priorUsableWindowId: priorFacts.latestUsableRankWindow?.evidenceId ?? null,
      },
      x: social.summary,
      base: base.summary,
    },
    diagnostics: diagnostics.slice(0, 10),
  });
  const nextFacts = advanceFacts({
    sourceFacts,
    states,
    socialStates: social.states,
    priorFacts,
    assessment,
    rankEvidenceId,
    marketplaceUsable,
  });
  return deepFreeze(RecordedAttentionAssessmentResultSchema.parse({ assessment, nextFacts }));
}

function applyCurrentIdentityConflicts(states: readonly CandidateState[]): void {
  const addressOwners = new Map<string, CandidateState[]>();
  const slugOwners = new Map<string, CandidateState[]>();
  for (const state of states) {
    for (const contract of state.candidate.contracts) {
      if (contract.chainId !== BASE_CHAIN_ID) continue;
      const owners = addressOwners.get(contract.address) ?? [];
      if (!owners.includes(state)) owners.push(state);
      addressOwners.set(contract.address, owners);
    }
    const owners = slugOwners.get(state.candidate.slug) ?? [];
    owners.push(state);
    slugOwners.set(state.candidate.slug, owners);
  }
  for (const owners of addressOwners.values()) {
    if (owners.length < 2) continue;
    for (const owner of owners) owner.hardReasons.add("OVERLAPPING_CONTRACT_GROUPS");
  }
  for (const owners of slugOwners.values()) {
    const identities = new Set(
      owners.map((owner) =>
        owner.identity === null ? owner.candidateId : owner.identity.collectionId,
      ),
    );
    if (identities.size < 2) continue;
    for (const owner of owners) owner.hardReasons.add("SLUG_REBOUND");
  }
}

function applyHistoricalIdentityFacts(
  states: readonly CandidateState[],
  priorFacts: RecordedAttentionFactsV1,
): void {
  const knownById = new Map(
    priorFacts.knownCollections.map((known) => [known.identity.collectionId, known]),
  );
  const slugAssociations = new Map<string, Set<CollectionId>>();
  for (const association of priorFacts.slugAssociations) {
    const collectionIds = slugAssociations.get(association.slug) ?? new Set<CollectionId>();
    collectionIds.add(association.collectionId);
    slugAssociations.set(association.slug, collectionIds);
  }

  for (const state of states) {
    if (state.identity === null) continue;
    const known = knownById.get(state.identity.collectionId);
    if (known !== undefined && known.latestSlug !== state.candidate.slug) {
      state.notes.add("SLUG_CHANGED");
    }
    for (const historical of priorFacts.knownCollections) {
      if (historical.identity.collectionId === state.identity.collectionId) continue;
      if (contractsOverlap(historical.identity, state.identity)) {
        state.hardReasons.add("IDENTITY_CONTINUITY_CONFLICT");
      }
    }
    const associatedIds = slugAssociations.get(state.candidate.slug);
    if (associatedIds !== undefined && !associatedIds.has(state.identity.collectionId)) {
      state.watchReasons.add("IDENTITY_CHANGED");
    }
  }
}

function marketplaceHardReasons(
  sourceFacts: SanitizedRecordedBundleV1,
  priorFacts: RecordedAttentionFactsV1,
  evaluatedMilliseconds: number,
): HardReason[] {
  const reasons: HardReason[] = [];
  const acquired = Date.parse(sourceFacts.marketplace.acquiredAt);
  const validUntil = Date.parse(sourceFacts.marketplace.validUntil);
  if (
    priorFacts.latestUsableRankWindow !== null &&
    acquired <= Date.parse(priorFacts.latestUsableRankWindow.acquiredAt)
  ) {
    reasons.push("MARKETPLACE_TIME_INVALID");
  }
  if (acquired > evaluatedMilliseconds) reasons.push("MARKETPLACE_FUTURE");
  if (evaluatedMilliseconds >= validUntil) reasons.push("MARKETPLACE_STALE");
  return ordered(reasons, HARD_REASONS);
}

function analyzeSocial(input: {
  readonly sourceFacts: SanitizedRecordedBundleV1;
  readonly states: readonly CandidateState[];
  readonly priorFacts: RecordedAttentionFactsV1;
  readonly evaluatedAt: string;
  readonly bundleId: string;
  readonly provenance: object;
}): {
  readonly states: readonly SocialState[];
  readonly diagnostics: readonly CollectionAttentionAssessmentV1["diagnostics"][number][];
  readonly summary: CollectionAttentionAssessmentV1["sourceSummary"]["x"];
} {
  if (input.sourceFacts.x.kind === "absent") {
    for (const state of input.states) state.watchReasons.add("MISSING_X");
    return { states: [], diagnostics: [], summary: { kind: "absent" } };
  }

  const x = input.sourceFacts.x;
  const evaluatedMilliseconds = Date.parse(input.evaluatedAt);
  const latestX = input.priorFacts.latestAdmittedXAcquiredAt;
  const timeRegression = latestX !== null && Date.parse(x.acquiredAt) < Date.parse(latestX);
  const future = Date.parse(x.acquiredAt) > evaluatedMilliseconds;
  const currentById = new Map<CollectionId, CandidateState>();
  for (const state of input.states) {
    if (state.identity !== null) currentById.set(state.identity.collectionId, state);
  }
  const addressOwners = new Map<string, Set<CollectionId>>();
  for (const state of input.states) {
    if (state.identity === null) continue;
    for (const address of state.identity.contracts) {
      const owners = addressOwners.get(address) ?? new Set<CollectionId>();
      owners.add(state.identity.collectionId);
      addressOwners.set(address, owners);
    }
  }
  const priorPostBindings = new Map(
    input.priorFacts.postBindings.map((binding) => [binding.postIdHash, binding]),
  );
  const priorFirstSeen = new Map(
    input.priorFacts.clusterFirstSeen.map((cluster) => [
      cluster.contentClusterId,
      cluster.firstSeenAt,
    ]),
  );
  const socialStates: SocialState[] = [];
  const diagnostics: CollectionAttentionAssessmentV1["diagnostics"][number][] = [];
  const summaryFreshClusters = new Set<string>();
  const summaryExpiries: number[] = [];

  for (const post of x.posts) {
    const matchedIds = new Set<CollectionId>();
    const unknownAddresses: string[] = [];
    for (const address of post.mentionedAddresses) {
      const owners = addressOwners.get(address);
      if (owners === undefined) {
        unknownAddresses.push(address);
        continue;
      }
      for (const owner of owners) matchedIds.add(owner);
    }
    const matchedCollectionIds = [...matchedIds].sort();
    const attributableCollectionId =
      matchedCollectionIds.length === 1 && unknownAddresses.length === 0
        ? (matchedCollectionIds[0] ?? null)
        : null;
    const priorBinding = priorPostBindings.get(post.postIdHash);
    const contentConflict =
      priorBinding !== undefined && priorBinding.contentClusterId !== post.contentClusterId;
    const firstSeenAt = priorFirstSeen.get(post.contentClusterId) ?? x.acquiredAt;
    const validUntil = addMilliseconds(firstSeenAt, SOCIAL_VALIDITY_MS);
    summaryExpiries.push(Date.parse(validUntil));

    const affectedIds = new Set<CollectionId>(matchedCollectionIds);
    if (contentConflict && priorBinding !== undefined) {
      for (const collectionId of priorBinding.matchedCollectionIds) affectedIds.add(collectionId);
    }
    for (const collectionId of affectedIds) {
      const state = currentById.get(collectionId);
      if (state === undefined) continue;
      if (contentConflict) state.hardReasons.add("POST_CONTENT_CONFLICT");
      if (timeRegression) state.hardReasons.add("SOCIAL_TIME_REGRESSION");
      if (future) state.hardReasons.add("SOCIAL_FUTURE");
    }
    if (matchedCollectionIds.length > 1) {
      for (const collectionId of matchedCollectionIds) {
        currentById.get(collectionId)?.hardReasons.add("AMBIGUOUS_SOCIAL_IDENTITY");
      }
    } else if (matchedCollectionIds.length === 1 && unknownAddresses.length > 0) {
      const collectionId = matchedCollectionIds[0];
      if (collectionId !== undefined) {
        currentById.get(collectionId)?.hardReasons.add("SOCIAL_ADDRESS_CONFLICT");
      }
    }
    for (const collectionId of matchedCollectionIds) {
      const state = currentById.get(collectionId);
      if (state === undefined) continue;
      for (const reason of post.detectedHardReasons) state.hardReasons.add(reason);
      for (const reason of post.detectedWatchReasons) state.watchReasons.add(reason);
    }

    const socialEvidenceId = evidenceId("rsi-attention-social-post-evidence-v1\0", {
      schemaVersion: 1,
      kind: "social_post",
      acquiredAt: x.acquiredAt,
      validUntil,
      postIdHash: post.postIdHash,
      contentClusterId: post.contentClusterId,
      matchedCollectionIds,
      integrityReasons: ordered(
        [
          ...(contentConflict ? (["POST_CONTENT_CONFLICT"] as const) : []),
          ...(timeRegression ? (["SOCIAL_TIME_REGRESSION"] as const) : []),
          ...(future ? (["SOCIAL_FUTURE"] as const) : []),
          ...post.detectedHardReasons,
        ],
        HARD_REASONS,
      ),
      cautionReasons: post.detectedWatchReasons,
      provenance: input.provenance,
    });
    const socialState: SocialState = {
      post,
      matchedCollectionIds,
      attributableCollectionId,
      contentConflict,
      timeRegression,
      future,
      firstSeenAt,
      validUntil,
      evidenceId: socialEvidenceId,
    };
    socialStates.push(socialState);

    for (const collectionId of matchedCollectionIds) {
      const state = currentById.get(collectionId);
      if (state === undefined) continue;
      state.matchedPosts.push(socialState);
      state.evidenceIds.add(socialEvidenceId);
    }
    if (attributableCollectionId !== null) {
      const state = currentById.get(attributableCollectionId);
      if (state !== undefined) {
        state.observedClusters.add(post.contentClusterId);
        const usable =
          !contentConflict &&
          !timeRegression &&
          !future &&
          post.detectedHardReasons.length === 0 &&
          Date.parse(validUntil) > evaluatedMilliseconds;
        if (usable) {
          state.freshClusters.set(post.contentClusterId, validUntil);
          summaryFreshClusters.add(post.contentClusterId);
        }
      }
    }

    if (matchedCollectionIds.length === 0) {
      const code: DiagnosticCode =
        post.detectedHardReasons.length > 0 ? "HOSTILE_UNBOUND_SOCIAL" : "UNBOUND_SOCIAL";
      diagnostics.push({
        evidenceId: evidenceId("rsi-attention-social-diagnostic-v1\0", {
          bundleId: input.bundleId,
          postIdHash: post.postIdHash,
          contentClusterId: post.contentClusterId,
          code,
        }),
        code,
      });
    }
  }

  for (const state of input.states) {
    if (state.identity === null) continue;
    if (state.matchedPosts.length === 0) {
      state.watchReasons.add("NO_BOUND_X");
    } else if (state.freshClusters.size === 0 && !state.hardReasons.has("SOCIAL_FUTURE")) {
      state.watchReasons.add("STALE_X");
    }
    if (state.matchedPosts.length > 0) state.notes.add("AUTHORS_UNKNOWN");
    const uniquePostIds = new Set(state.matchedPosts.map((post) => post.post.postIdHash));
    if (state.observedClusters.size < uniquePostIds.size || state.observedClusters.size > 2) {
      state.notes.add("COPIES_CAPPED");
    }
  }

  const fallbackExpiry = Date.parse(x.acquiredAt) + SOCIAL_VALIDITY_MS;
  const summaryExpiry = Math.min(fallbackExpiry, ...summaryExpiries);
  return {
    states: socialStates,
    diagnostics,
    summary: {
      kind: "observed",
      acquiredAt: x.acquiredAt,
      validUntil: new Date(summaryExpiry).toISOString(),
      postCount: x.posts.length,
      usableBoundClusterCount: summaryFreshClusters.size,
      hasNextPage: x.hasNextPage,
    },
  };
}

function analyzeBaseContext(
  sourceFacts: SanitizedRecordedBundleV1,
  evaluatedMilliseconds: number,
  bundleId: string,
): BaseContextResult {
  if (sourceFacts.base.kind === "absent") {
    return { summary: { kind: "absent" }, diagnostic: null, usable: false };
  }
  const base = sourceFacts.base;
  const acquired = Date.parse(base.acquiredAt);
  const blockTimestamp = Date.parse(base.blockTimestamp);
  const validUntil = acquired + BASE_CONTEXT_VALIDITY_MS;
  const invalid =
    base.chainId !== BASE_CHAIN_ID ||
    acquired > evaluatedMilliseconds ||
    blockTimestamp > acquired ||
    acquired - blockTimestamp > MAX_BASE_BLOCK_AGE_MS;
  if (invalid) {
    return {
      summary: { kind: "invalid" },
      diagnostic: {
        evidenceId: evidenceId("rsi-attention-base-diagnostic-v1\0", {
          bundleId,
          code: "INVALID_BASE_CONTEXT",
          chainId: base.chainId,
          acquiredAt: base.acquiredAt,
          blockTimestamp: base.blockTimestamp,
        }),
        code: "INVALID_BASE_CONTEXT",
      },
      usable: false,
    };
  }
  if (evaluatedMilliseconds >= validUntil) {
    return {
      summary: {
        kind: "stale",
        acquiredAt: base.acquiredAt,
        validUntil: new Date(validUntil).toISOString(),
        blockTimestamp: base.blockTimestamp,
      },
      diagnostic: {
        evidenceId: evidenceId("rsi-attention-base-diagnostic-v1\0", {
          bundleId,
          code: "STALE_BASE_CONTEXT",
          acquiredAt: base.acquiredAt,
          validUntil: new Date(validUntil).toISOString(),
          blockTimestamp: base.blockTimestamp,
        }),
        code: "STALE_BASE_CONTEXT",
      },
      usable: false,
    };
  }
  return {
    summary: {
      kind: "usable",
      acquiredAt: base.acquiredAt,
      validUntil: new Date(validUntil).toISOString(),
      blockTimestamp: base.blockTimestamp,
    },
    diagnostic: null,
    usable: true,
  };
}

function buildObservedRow(input: {
  readonly state: CandidateState;
  readonly sourceFacts: SanitizedRecordedBundleV1;
  readonly priorFacts: RecordedAttentionFactsV1;
  readonly evaluatedAt: string;
  readonly provenance: {
    readonly kind: "operator_supplied_unverified";
    readonly streamId: "recorded-base-v1";
    readonly bundleId: ReturnType<typeof recordedBundleId>;
  };
  readonly baseUsable: boolean;
}): CollectionAttentionRowV1 {
  const { state } = input;
  const comparison = rankComparison(
    state,
    input.priorFacts,
    input.sourceFacts.marketplace.acquiredAt,
  );
  const rankScore = 4 * (11 - state.candidate.rank);
  const upwardMovement =
    comparison.kind === "comparable" ? Math.min(10, 2 * Math.max(0, comparison.delta)) : 0;
  const observedContentClusters = state.observedClusters.size;
  const countedContentClusters = Math.min(2, state.freshClusters.size);
  const socialPresence = countedContentClusters * 5;
  const total = rankScore + upwardMovement + socialPresence;
  const scorecard = {
    rank: rankScore,
    upwardMovement,
    socialPresence,
    total,
    observedContentClusters,
    countedContentClusters,
  };
  const hardReasons = ordered([...state.hardReasons], HARD_REASONS);
  const watchReasons = new Set(state.watchReasons);
  if (hardReasons.length === 0 && watchReasons.size === 0 && total < 36) {
    watchReasons.add("ATTENTION_BELOW_THRESHOLD");
  }
  const orderedWatchReasons = ordered([...watchReasons], WATCH_REASONS);
  const outcome =
    hardReasons.length > 0
      ? { kind: "rejected" as const, reasons: hardReasons, priority: null }
      : orderedWatchReasons.length > 0
        ? { kind: "watch" as const, reasons: orderedWatchReasons, priority: total }
        : { kind: "review" as const, priority: total };
  const freshExpiries = [...state.freshClusters.values()].map(Date.parse);
  const expiresAt = new Date(
    Math.min(Date.parse(input.sourceFacts.marketplace.validUntil), ...freshExpiries),
  ).toISOString();
  const missingChecks = baselineMissingChecks(
    input.baseUsable,
    state.watchReasons.has("LINKS_UNCHECKED") || state.hardReasons.has("DECEPTIVE_LINK_INDICATOR"),
  );
  const subject =
    state.identity === null
      ? { kind: "unresolved" as const, candidateId: state.candidateId }
      : { kind: "resolved" as const, identity: state.identity };
  const hasIdentityConflict = [...state.hardReasons].some((reason) =>
    IDENTITY_HARD_REASONS.has(reason),
  );

  return CollectionAttentionAssessmentSchema.shape.rows.element.parse({
    rowId:
      state.identity === null || hasIdentityConflict
        ? state.candidateId
        : state.identity.collectionId,
    subject,
    slug: state.candidate.slug,
    presence: { kind: "observed", rank: state.candidate.rank },
    comparison,
    scorecard,
    evidenceIds: [...state.evidenceIds].sort(),
    assessedAt: input.evaluatedAt,
    expiresAt,
    provenance: input.provenance,
    missingChecks,
    notes: ordered([...state.notes], ATTENTION_NOTES),
    outcome,
    nextAction: chooseNextAction(outcome),
  });
}

function buildDepartureRows(input: {
  readonly states: readonly CandidateState[];
  readonly sourceFacts: SanitizedRecordedBundleV1;
  readonly priorFacts: RecordedAttentionFactsV1;
  readonly evaluatedAt: string;
  readonly provenance: {
    readonly kind: "operator_supplied_unverified";
    readonly streamId: "recorded-base-v1";
    readonly bundleId: ReturnType<typeof recordedBundleId>;
  };
  readonly baseUsable: boolean;
}): CollectionAttentionRowV1[] {
  const previous = input.priorFacts.latestUsableRankWindow;
  if (previous === null) return [];
  const currentIds = new Set(
    input.states
      .map((state) => state.identity?.collectionId)
      .filter((collectionId) => collectionId !== undefined),
  );
  return previous.rows
    .filter((row) => !currentIds.has(row.identity.collectionId))
    .map((row) => {
      const hardReasons = ordered(row.hardReasons, HARD_REASONS);
      const outcome =
        hardReasons.length > 0
          ? { kind: "rejected" as const, reasons: hardReasons, priority: null }
          : { kind: "watch" as const, reasons: ["LEFT_WINDOW" as const], priority: 0 };
      const notes = new Set<AttentionNote>(["NO_SAFE_VERDICT"]);
      if (input.sourceFacts.marketplace.hasNextPage) notes.add("PARTIAL_MARKETPLACE_WINDOW");
      if (input.sourceFacts.x.kind === "recorded_posts" && input.sourceFacts.x.hasNextPage) {
        notes.add("PARTIAL_X_WINDOW");
      }
      if (input.baseUsable) notes.add("BASE_CONTEXT_ONLY");
      return CollectionAttentionAssessmentSchema.shape.rows.element.parse({
        rowId: row.identity.collectionId,
        subject: { kind: "resolved", identity: row.identity },
        slug: row.slug,
        presence: { kind: "left_window", previousRank: row.rank },
        comparison: { kind: "not_observed" },
        scorecard: null,
        evidenceIds: [row.evidenceId],
        assessedAt: input.evaluatedAt,
        expiresAt: input.sourceFacts.marketplace.validUntil,
        provenance: input.provenance,
        missingChecks: baselineMissingChecks(input.baseUsable, false),
        notes: ordered([...notes], ATTENTION_NOTES),
        outcome,
        nextAction: chooseNextAction(outcome),
      });
    });
}

function rankComparison(
  state: CandidateState,
  priorFacts: RecordedAttentionFactsV1,
  currentAcquiredAt: string,
): CollectionAttentionRowV1["comparison"] {
  if (state.identity === null) {
    return { kind: "not_comparable", reason: "identity_unresolved" };
  }
  const previousWindow = priorFacts.latestUsableRankWindow;
  const previous = previousWindow?.rows.find(
    (row) => row.identity.collectionId === state.identity?.collectionId,
  );
  if (previousWindow === null || previous === undefined) {
    return { kind: "not_comparable", reason: "first_observation" };
  }
  if (Date.parse(currentAcquiredAt) >= Date.parse(previousWindow.validUntil)) {
    return { kind: "not_comparable", reason: "predecessor_expired" };
  }
  if (Date.parse(currentAcquiredAt) <= Date.parse(previousWindow.acquiredAt)) {
    return { kind: "not_comparable", reason: "first_observation" };
  }
  return {
    kind: "comparable",
    previousRank: previous.rank,
    delta: previous.rank - state.candidate.rank,
  };
}

function advanceFacts(input: {
  readonly sourceFacts: SanitizedRecordedBundleV1;
  readonly states: readonly CandidateState[];
  readonly socialStates: readonly SocialState[];
  readonly priorFacts: RecordedAttentionFactsV1;
  readonly assessment: CollectionAttentionAssessmentV1;
  readonly rankEvidenceId: EvidenceId;
  readonly marketplaceUsable: boolean;
}): RecordedAttentionFactsV1 {
  const knownCollections = new Map(
    input.priorFacts.knownCollections.map((known) => [known.identity.collectionId, known]),
  );
  const slugAssociations = new Map(
    input.priorFacts.slugAssociations.map((association) => [
      `${association.slug}\0${association.collectionId}`,
      association,
    ]),
  );
  const postBindings = new Map(
    input.priorFacts.postBindings.map((binding) => [binding.postIdHash, binding]),
  );
  const clusterFirstSeen = new Map(
    input.priorFacts.clusterFirstSeen.map((cluster) => [cluster.contentClusterId, cluster]),
  );
  let latestUsableRankWindow = input.priorFacts.latestUsableRankWindow;
  let latestAdmittedXAcquiredAt = input.priorFacts.latestAdmittedXAcquiredAt;

  if (input.marketplaceUsable) {
    const usableStates = input.states.filter(
      (state) =>
        state.identity !== null &&
        ![...state.hardReasons].some((reason) => IDENTITY_HARD_REASONS.has(reason)),
    );
    for (const state of usableStates) {
      if (state.identity === null) continue;
      knownCollections.set(state.identity.collectionId, {
        identity: state.identity,
        latestSlug: state.candidate.slug,
      });
      const association = { slug: state.candidate.slug, collectionId: state.identity.collectionId };
      slugAssociations.set(`${association.slug}\0${association.collectionId}`, association);
    }
    latestUsableRankWindow = {
      evidenceId: input.rankEvidenceId,
      acquiredAt: input.sourceFacts.marketplace.acquiredAt,
      validUntil: input.sourceFacts.marketplace.validUntil,
      rows: usableStates.map((state) => {
        if (state.identity === null) throw new TypeError("attention_identity_invariant_failed");
        return {
          identity: state.identity,
          slug: state.candidate.slug,
          rank: state.candidate.rank,
          evidenceId: input.rankEvidenceId,
          hardReasons: ordered([...state.hardReasons], HARD_REASONS),
        };
      }),
    };

    if (
      input.sourceFacts.x.kind === "recorded_posts" &&
      Date.parse(input.sourceFacts.x.acquiredAt) <= Date.parse(input.assessment.evaluatedAt) &&
      (latestAdmittedXAcquiredAt === null ||
        Date.parse(input.sourceFacts.x.acquiredAt) >= Date.parse(latestAdmittedXAcquiredAt))
    ) {
      const usableIds = new Set(
        usableStates
          .map((state) => state.identity?.collectionId)
          .filter((collectionId) => collectionId !== undefined),
      );
      for (const social of input.socialStates) {
        if (
          social.attributableCollectionId === null ||
          !usableIds.has(social.attributableCollectionId) ||
          social.contentConflict
        ) {
          continue;
        }
        if (!postBindings.has(social.post.postIdHash)) {
          postBindings.set(social.post.postIdHash, {
            postIdHash: social.post.postIdHash,
            contentClusterId: social.post.contentClusterId,
            matchedCollectionIds: [social.attributableCollectionId],
          });
        }
        if (!clusterFirstSeen.has(social.post.contentClusterId)) {
          clusterFirstSeen.set(social.post.contentClusterId, {
            contentClusterId: social.post.contentClusterId,
            firstSeenAt: social.firstSeenAt,
          });
        }
      }
      latestAdmittedXAcquiredAt = input.sourceFacts.x.acquiredAt;
    }
  }

  return RecordedAttentionFactsSchema.parse({
    schemaVersion: 1,
    streamId: RECORDED_ATTENTION_STREAM_ID,
    headRefreshId: input.assessment.refreshId,
    latestUsableRankWindow,
    latestAdmittedXAcquiredAt,
    knownCollections: [...knownCollections.values()].sort((left, right) =>
      compareStrings(left.identity.collectionId, right.identity.collectionId),
    ),
    slugAssociations: [...slugAssociations.values()].sort(
      (left, right) =>
        compareStrings(left.slug, right.slug) ||
        compareStrings(left.collectionId, right.collectionId),
    ),
    postBindings: [...postBindings.values()].sort((left, right) =>
      compareStrings(left.postIdHash, right.postIdHash),
    ),
    clusterFirstSeen: [...clusterFirstSeen.values()].sort((left, right) =>
      compareStrings(left.contentClusterId, right.contentClusterId),
    ),
  });
}

function baselineMissingChecks(baseUsable: boolean, hasLink: boolean): MissingCheck[] {
  const values = new Set<MissingCheck>([
    "authenticated_provenance",
    "independent_x_authors",
    "x_post_creation_times",
    "collection_contract_checks",
    "collection_security_review",
    "token_order_checks",
  ]);
  if (!baseUsable) values.add("base_head_context");
  if (hasLink) values.add("link_destination_checks");
  return ordered([...values], MISSING_CHECKS);
}

function chooseNextAction(outcome: CollectionAttentionRowV1["outcome"]): NextAction {
  if (outcome.kind === "review") return "manually_review_identity_and_sources";
  const primary = outcome.reasons[0];
  if (primary === undefined) throw new TypeError("attention_reason_invariant_failed");
  if (outcome.kind === "rejected") {
    if (
      primary === "POST_CONTENT_CONFLICT" ||
      primary === "INSTRUCTION_CONTENT" ||
      primary === "WALLET_CONNECTION_SOLICITATION" ||
      primary === "UNLIMITED_APPROVAL_SOLICITATION" ||
      primary === "GUARANTEED_RETURN_CLAIM" ||
      primary === "DECEPTIVE_LINK_INDICATOR"
    ) {
      return "inspect_quarantined_indicators_offline";
    }
    if (primary === "SOCIAL_TIME_REGRESSION" || primary === "SOCIAL_FUTURE") {
      return "supply_fresh_social_evidence";
    }
    if (
      primary === "MARKETPLACE_TIME_INVALID" ||
      primary === "MARKETPLACE_FUTURE" ||
      primary === "MARKETPLACE_STALE"
    ) {
      return "supply_new_recorded_rank_window";
    }
    return "resolve_collection_identity";
  }
  if (primary === "ASSESSMENT_EXPIRED") return "supply_new_recorded_rank_window";
  if (primary === "IDENTITY_CHANGED") return "resolve_collection_identity";
  if (primary === "MISSING_X" || primary === "NO_BOUND_X") {
    return "supply_bounded_social_evidence";
  }
  if (primary === "STALE_X") return "supply_fresh_social_evidence";
  if (primary === "LINKS_UNCHECKED") return "review_recorded_links_offline";
  return "continue_recorded_observation";
}

function compareRows(left: CollectionAttentionRowV1, right: CollectionAttentionRowV1): number {
  const kindOrder = { review: 0, watch: 1, rejected: 2 } as const;
  const kindDifference = kindOrder[left.outcome.kind] - kindOrder[right.outcome.kind];
  if (kindDifference !== 0) return kindDifference;
  if (left.outcome.kind === "rejected" && right.outcome.kind === "rejected") {
    const leftReason = left.outcome.reasons[0];
    const rightReason = right.outcome.reasons[0];
    if (leftReason === undefined || rightReason === undefined) {
      throw new TypeError("attention_reason_invariant_failed");
    }
    const reasonDifference = HARD_REASONS.indexOf(leftReason) - HARD_REASONS.indexOf(rightReason);
    return reasonDifference || compareStrings(left.rowId, right.rowId);
  }
  const leftPriority = left.outcome.kind === "rejected" ? -1 : left.outcome.priority;
  const rightPriority = right.outcome.kind === "rejected" ? -1 : right.outcome.priority;
  const rankDifference =
    (left.presence.kind === "observed" ? left.presence.rank : Number.MAX_SAFE_INTEGER) -
    (right.presence.kind === "observed" ? right.presence.rank : Number.MAX_SAFE_INTEGER);
  return rightPriority - leftPriority || rankDifference || compareStrings(left.rowId, right.rowId);
}

function evidenceId(domain: string, value: unknown): EvidenceId {
  return EvidenceIdSchema.parse(hashCanonical(domain, toJsonValue(value)));
}

function addMilliseconds(timestamp: string, milliseconds: number): string {
  return new Date(Date.parse(timestamp) + milliseconds).toISOString();
}

function ordered<T extends string>(values: readonly T[], order: readonly T[]): T[] {
  const unique = new Set(values);
  return order.filter((value) => unique.has(value));
}
