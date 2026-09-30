import { readFileSync } from "node:fs";

import { NftAssetSchema, TimestampSchema, type EvidenceClaim } from "@rsi/domain/evidence";
import {
  ResearchProposalAbstentionReasonSchema,
  ResearchProposalV1Schema,
  type ResearchProposalAbstentionReason,
  type ResearchProposalV1,
} from "@rsi/domain/proposals";
import { z } from "zod";

import { captureRawFixture } from "./capture.js";
import { summarizeCorrelation } from "./correlation.js";
import { extractResearchBatch, type ResearchBatch } from "./pipeline.js";
import {
  RECORDED_FIXTURE_SCENARIOS,
  RECORDED_REPLAY_FIXTURE_SCENARIOS,
  RecordedReplayScenarioSchema,
  type RecordedReplayScenario,
} from "./recorded-scenarios.js";

export { RecordedReplayScenarioSchema } from "./recorded-scenarios.js";
export type { RecordedReplayScenario } from "./recorded-scenarios.js";

export const RECORDED_REPLAY_EVALUATED_AT = "2026-08-11T12:00:00.000Z" as const;

const REPLAY_AT = new Date(RECORDED_REPLAY_EVALUATED_AT);
const REPLAY_STRATEGY_VERSION = "rsi-recorded-replay-v1";
const EXPECTED_ASSET = Object.freeze(
  NftAssetSchema.parse({
    chainId: 4663,
    address: "0x1111111111111111111111111111111111111111",
    tokenId: "7",
  }),
);

const AssessmentScorecardSchema = z
  .strictObject({
    confidence: ResearchProposalV1Schema.shape.scorecard.shape.confidence,
    marketSupport: ResearchProposalV1Schema.shape.scorecard.shape.marketSupport,
    opportunity: z.literal(0),
    provenanceQuality: ResearchProposalV1Schema.shape.scorecard.shape.provenanceQuality,
    risk: ResearchProposalV1Schema.shape.scorecard.shape.risk,
  })
  .readonly();

const AssessmentProvenanceSchema = z
  .strictObject({
    providerIds: ResearchProposalV1Schema.shape.provenance.shape.providerIds.readonly(),
    sourceKinds: ResearchProposalV1Schema.shape.provenance.shape.sourceKinds.readonly(),
    independentClusterCount:
      ResearchProposalV1Schema.shape.provenance.shape.independentClusterCount,
  })
  .readonly();

const AssessmentFlagsSchema = z
  .strictObject({
    scam: ResearchProposalV1Schema.shape.flags.shape.scam.readonly(),
    injection: ResearchProposalV1Schema.shape.flags.shape.injection.readonly(),
    homograph: ResearchProposalV1Schema.shape.flags.shape.homograph.readonly(),
  })
  .readonly();

const AssessmentDispositionSchema = z
  .strictObject({
    kind: z.literal("abstain"),
    reason: ResearchProposalAbstentionReasonSchema,
  })
  .readonly();

export const RecordedReplayDispositionEvidenceSchema = z
  .strictObject({
    assetMismatchCount: z.number().int().min(0).max(100),
    integrityFlagCount: z.number().int().min(0).max(300),
    staleEvidenceCount: z.number().int().min(0).max(100),
    futureEvidenceCount: z.number().int().min(0).max(100),
    freshIndependentClusterCount: z.number().int().min(0).max(100),
    freshCanonicalEvidenceCount: z.number().int().min(0).max(100),
  })
  .readonly();

export type RecordedReplayDispositionEvidence = z.infer<
  typeof RecordedReplayDispositionEvidenceSchema
>;

const ASSESSMENT_COMMON_SHAPE = {
  strategyVersion: z.literal(REPLAY_STRATEGY_VERSION),
  asset: ResearchProposalV1Schema.shape.asset.readonly(),
  evidenceIds: ResearchProposalV1Schema.shape.evidenceIds.readonly(),
  provenance: AssessmentProvenanceSchema,
  flags: AssessmentFlagsSchema,
  scorecard: AssessmentScorecardSchema,
};

export const RecordedReplayAssessmentSchema = z
  .strictObject({
    ...ASSESSMENT_COMMON_SHAPE,
    scenario: RecordedReplayScenarioSchema,
    disposition: AssessmentDispositionSchema,
  })
  .readonly();

export type RecordedReplayAssessment = z.infer<typeof RecordedReplayAssessmentSchema>;

const BuildRecordedReplayProposalInputSchema = z.strictObject({
  assessment: RecordedReplayAssessmentSchema,
  requestId: z.string().uuid().max(36),
  createdAt: TimestampSchema,
});

export type BuildRecordedReplayProposalInput = Readonly<
  z.input<typeof BuildRecordedReplayProposalInputSchema>
>;

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function sameAsset(left: EvidenceClaim["asset"], right: EvidenceClaim["asset"]): boolean {
  return (
    left.chainId === right.chainId &&
    left.address.toLowerCase() === right.address.toLowerCase() &&
    left.tokenId === right.tokenId
  );
}

function roundScore(value: number): number {
  return Number(Math.min(1, Math.max(0, value)).toFixed(4));
}

function loadReplayBatch(scenario: RecordedReplayScenario): ResearchBatch {
  const captures = RECORDED_REPLAY_FIXTURE_SCENARIOS[scenario].map((fixtureScenario) => {
    const { file } = RECORDED_FIXTURE_SCENARIOS[fixtureScenario];
    return captureRawFixture(readFileSync(new URL(`../fixtures/${file}`, import.meta.url)));
  });
  return extractResearchBatch(captures);
}

export function deriveRecordedReplayDisposition(
  rawEvidence: RecordedReplayDispositionEvidence,
): Readonly<{ kind: "abstain"; reason: ResearchProposalAbstentionReason }> {
  const evidence = RecordedReplayDispositionEvidenceSchema.parse(rawEvidence);
  let reason: ResearchProposalAbstentionReason;

  if (evidence.assetMismatchCount > 0) reason = "identity_ambiguity";
  else if (evidence.integrityFlagCount > 0) reason = "integrity_risk";
  else if (evidence.staleEvidenceCount > 0 || evidence.futureEvidenceCount > 0) {
    reason = "stale_evidence";
  } else if (
    evidence.freshIndependentClusterCount < 2 ||
    evidence.freshCanonicalEvidenceCount < 1
  ) {
    reason = "insufficient_evidence";
  } else reason = "market_uncertainty";

  return AssessmentDispositionSchema.parse({ kind: "abstain", reason });
}

export function assessRecordedReplay(
  scenarioInput: RecordedReplayScenario,
): RecordedReplayAssessment {
  const scenario = RecordedReplayScenarioSchema.parse(scenarioInput);
  const batch = loadReplayBatch(scenario);
  const correlation = summarizeCorrelation(batch.observations, EXPECTED_ASSET, REPLAY_AT);
  const matchingClaims = batch.observations
    .flatMap(({ claims }) => claims)
    .filter(({ asset }) => sameAsset(asset, EXPECTED_ASSET));
  const evidenceIds = batch.observations.map(({ observationId }) => observationId).sort();
  const providerIds = uniqueSorted(batch.observations.map(({ source }) => source.providerId));
  const sourceKinds = uniqueSorted(batch.observations.map(({ source }) => source.kind));
  const scam = uniqueSorted(
    batch.analyses.flatMap(({ accountSignals, coordinationSignals, identityFlags }) => [
      ...accountSignals,
      ...coordinationSignals,
      ...identityFlags,
    ]),
  );
  const injection = uniqueSorted(
    batch.analyses.flatMap(({ instructionFlags }) => instructionFlags),
  );
  const homograph = uniqueSorted(
    batch.observations.flatMap(({ integrity }) => integrity.homographFlags),
  );
  const confidence =
    matchingClaims.length === 0
      ? 0
      : matchingClaims.reduce((sum, { confidence: claimConfidence }) => sum + claimConfidence, 0) /
        matchingClaims.length;
  const maximumAccountAnomaly = Math.max(
    0,
    ...batch.observations.map(({ integrity }) => integrity.accountAnomalyScore),
  );
  const hasExplicitIntegrityRisk = scam.length + injection.length + homograph.length > 0;
  const disposition = deriveRecordedReplayDisposition({
    assetMismatchCount: correlation.assetMismatchObservationIds.length,
    integrityFlagCount: scam.length + injection.length + homograph.length,
    staleEvidenceCount: correlation.staleObservationIds.length,
    futureEvidenceCount: correlation.futureObservationIds.length,
    freshIndependentClusterCount: correlation.freshIndependentClusterCount,
    freshCanonicalEvidenceCount: correlation.freshCanonicalEvidenceCount,
  });

  return RecordedReplayAssessmentSchema.parse({
    scenario,
    strategyVersion: REPLAY_STRATEGY_VERSION,
    asset: EXPECTED_ASSET,
    evidenceIds,
    provenance: {
      providerIds,
      sourceKinds,
      independentClusterCount: correlation.freshIndependentClusterCount,
    },
    flags: { scam, injection, homograph },
    scorecard: {
      confidence: roundScore(confidence),
      marketSupport: roundScore(
        matchingClaims.length === 0
          ? 0
          : correlation.freshCanonicalEvidenceCount / matchingClaims.length,
      ),
      opportunity: 0,
      provenanceQuality: roundScore(correlation.freshIndependentClusterCount / 3),
      risk:
        hasExplicitIntegrityRisk || correlation.assetMismatchObservationIds.length > 0
          ? 1
          : roundScore(maximumAccountAnomaly),
    },
    disposition,
  });
}

export function buildRecordedReplayProposal(
  input: BuildRecordedReplayProposalInput,
): ResearchProposalV1 {
  const { assessment, requestId, createdAt } = BuildRecordedReplayProposalInputSchema.parse(input);
  const expiresAt = new Date(Date.parse(createdAt) + 5 * 60 * 1_000).toISOString();

  return ResearchProposalV1Schema.parse({
    schemaVersion: 1,
    proposalId: `rsi-proposal:${assessment.scenario}-${requestId}`,
    strategyVersion: assessment.strategyVersion,
    createdAt,
    expiresAt,
    asset: assessment.asset,
    evidenceIds: assessment.evidenceIds,
    provenance: assessment.provenance,
    flags: assessment.flags,
    scorecard: assessment.scorecard,
    disposition: assessment.disposition,
  });
}
