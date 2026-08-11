import {
  NftAssetSchema,
  ObservationSchema,
  type EvidenceClaim,
  type Observation,
} from "@rsi/domain";

const CANONICAL_CLAIM_TYPES = new Set<EvidenceClaim["type"]>([
  "collection_identity",
  "ownership",
  "listing",
  "executable_bid",
]);

export interface CorrelationSummary {
  expectedAsset: EvidenceClaim["asset"];
  observationCount: number;
  matchingObservationIds: readonly string[];
  assetMismatchObservationIds: readonly string[];
  staleObservationIds: readonly string[];
  futureObservationIds: readonly string[];
  independentClusterCount: number;
  freshIndependentClusterCount: number;
  canonicalEvidenceCount: number;
  freshCanonicalEvidenceCount: number;
  canonicalClusterCount: number;
  canonicalEvidenceIds: readonly string[];
}

function sameAsset(left: EvidenceClaim["asset"], right: EvidenceClaim["asset"]): boolean {
  return (
    left.chainId === right.chainId &&
    left.address.toLowerCase() === right.address.toLowerCase() &&
    left.tokenId === right.tokenId
  );
}

function isCanonicalEvidence(observation: Observation): boolean {
  return (
    (observation.source.kind === "opensea" || observation.source.kind === "onchain") &&
    observation.claims.some(({ type }) => CANONICAL_CLAIM_TYPES.has(type))
  );
}

/**
 * Correlates one candidate asset by the exact (chainId, contract, tokenId)
 * tuple. "Canonical" here means source-typed marketplace/onchain evidence; it
 * is a count, not a truth or trust verdict.
 */
export function summarizeCorrelation(
  rawObservations: readonly unknown[],
  rawExpectedAsset: unknown,
  at = new Date(),
): CorrelationSummary {
  if (!Number.isFinite(at.getTime())) throw new Error("correlation time must be valid");

  const expectedAsset = NftAssetSchema.parse(rawExpectedAsset);
  const observations = [
    ...new Map(
      rawObservations.map((raw) => {
        const observation = ObservationSchema.parse(raw);
        return [observation.observationId, observation] as const;
      }),
    ).values(),
  ];
  const matching = observations.filter((observation) =>
    observation.claims.some(({ asset }) => sameAsset(asset, expectedAsset)),
  );
  const mismatched = observations.filter(
    (observation) =>
      !matching.some(({ observationId }) => observationId === observation.observationId),
  );
  const future = matching.filter(
    (observation) =>
      Date.parse(observation.acquiredAt) > at.getTime() ||
      Date.parse(observation.observedAt) > at.getTime(),
  );
  const stale = matching.filter(
    (observation) => Date.parse(observation.validUntil) <= at.getTime(),
  );
  const fresh = matching.filter(
    (observation) =>
      Date.parse(observation.acquiredAt) <= at.getTime() &&
      Date.parse(observation.observedAt) <= at.getTime() &&
      Date.parse(observation.validUntil) > at.getTime(),
  );
  const canonical = matching.filter(isCanonicalEvidence);
  const freshCanonical = fresh.filter(isCanonicalEvidence);

  return {
    expectedAsset: {
      ...expectedAsset,
      address: expectedAsset.address.toLowerCase(),
    },
    observationCount: observations.length,
    matchingObservationIds: matching.map(({ observationId }) => observationId).sort(),
    assetMismatchObservationIds: mismatched.map(({ observationId }) => observationId).sort(),
    staleObservationIds: stale.map(({ observationId }) => observationId).sort(),
    futureObservationIds: future.map(({ observationId }) => observationId).sort(),
    independentClusterCount: new Set(
      matching.map(({ integrity }) => integrity.coordinationClusterId),
    ).size,
    freshIndependentClusterCount: new Set(
      fresh.map(({ integrity }) => integrity.coordinationClusterId),
    ).size,
    canonicalEvidenceCount: canonical.length,
    freshCanonicalEvidenceCount: freshCanonical.length,
    canonicalClusterCount: new Set(
      canonical.map(({ integrity }) => integrity.coordinationClusterId),
    ).size,
    canonicalEvidenceIds: canonical.map(({ observationId }) => observationId).sort(),
  };
}
