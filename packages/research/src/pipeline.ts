import { createHash } from "node:crypto";

import { ObservationSchema, type EvidenceClaim, type Observation } from "@rsi/domain";

import { MAX_RAW_FIXTURE_BYTES, sha256Id, type RawFixtureCapture } from "./capture.js";
import {
  clusterSocialFixtures,
  type CoordinationAssignment,
  type CoordinationSignal,
} from "./coordination.js";
import {
  ResearchFixtureSchema,
  type RecordedLink,
  type ResearchFixture,
  type XPostFixture,
} from "./schemas.js";
import {
  analyzeRecordedLink,
  flagAssetIdentityConflicts,
  flagUntrustedInstructions,
  type IdentityFlag,
  type InstructionFlag,
  type NormalizedUrlTrace,
} from "./signals.js";

export const MAX_FIXTURES_PER_BATCH = 256;

export type AccountSignal =
  | "account:created-after-post"
  | "account:handle-churn"
  | "account:low-history"
  | "account:new"
  | "account:very-new"
  | "account:following-imbalance"
  | "account:coordinated-cluster";

export interface FixtureAnalysis {
  observationId: string;
  fixtureType: ResearchFixture["fixtureType"];
  contentHash: string;
  instructionFlags: readonly InstructionFlag[];
  identityFlags: readonly IdentityFlag[];
  accountSignals: readonly AccountSignal[];
  coordinationSignals: readonly CoordinationSignal[];
  urls: readonly NormalizedUrlTrace[];
}

export interface ResearchBatch {
  observations: readonly Observation[];
  analyses: readonly FixtureAnalysis[];
}

interface PreparedFixture {
  capture: RawFixtureCapture;
  fixture: ResearchFixture;
  observationId: `sha256:${string}`;
  instructionFlags: InstructionFlag[];
  identityFlags: IdentityFlag[];
  urls: NormalizedUrlTrace[];
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 32);
}

function uniqueSorted<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)].sort() as T[];
}

const OBSERVATION_URL_INTEGRITY_FLAGS = new Set([
  "url:embedded-userinfo",
  "url:https-downgrade",
  "url:mixed-script-label",
  "url:redirect-loop",
]);

export function parseCapturedFixture(capture: RawFixtureCapture): ResearchFixture {
  if (!/^application\/json(?:;\s*charset=utf-8)?$/iu.test(capture.metadata.contentType)) {
    throw new Error("fixture contentType must be application/json");
  }

  const bytes = capture.copyBytes();
  if (
    bytes.byteLength === 0 ||
    bytes.byteLength > MAX_RAW_FIXTURE_BYTES ||
    bytes.byteLength !== capture.metadata.byteLength ||
    sha256Id(bytes) !== capture.metadata.contentHash
  ) {
    throw new Error("raw capture bytes do not match their SHA-256 metadata");
  }

  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch (error) {
    throw new Error("fixture is not valid JSON", { cause: error });
  }
  return ResearchFixtureSchema.parse(decoded);
}

function observationIdFor(capture: RawFixtureCapture): `sha256:${string}` {
  return sha256Id(new TextEncoder().encode(`rsi-observation-v1:${capture.metadata.contentHash}`));
}

function fixtureLinks(fixture: ResearchFixture): readonly RecordedLink[] {
  switch (fixture.fixtureType) {
    case "x-post":
      return fixture.post.links;
    case "opensea-record":
      return fixture.record.links;
    case "onchain-record":
      return [];
  }
}

function prepare(capture: RawFixtureCapture): PreparedFixture {
  const fixture = parseCapturedFixture(capture);
  const urls = fixtureLinks(fixture).map(analyzeRecordedLink);
  const instructionFlags =
    fixture.fixtureType === "x-post" ? flagUntrustedInstructions(fixture.post.text) : [];
  const identityFlags =
    fixture.fixtureType === "x-post"
      ? flagAssetIdentityConflicts(fixture.post.text, fixture.claim.asset.address)
      : [];

  return {
    capture,
    fixture,
    observationId: observationIdFor(capture),
    instructionFlags,
    identityFlags,
    urls,
  };
}

function accountRisk(
  fixture: XPostFixture,
  coordination: CoordinationAssignment,
): { score: number; signals: AccountSignal[] } {
  const signals: AccountSignal[] = [];
  let score = 0;
  const ageMs =
    Date.parse(fixture.post.createdAt) - Date.parse(fixture.post.author.accountCreatedAt);
  const ageDays = ageMs / 86_400_000;
  const { followersCount, followingCount, postsCount, previousHandles } = fixture.post.author;

  if (ageMs < 0) {
    signals.push("account:created-after-post");
    score += 0.4;
  } else if (ageDays < 7) {
    signals.push("account:very-new");
    score += 0.4;
  } else if (ageDays < 30) {
    signals.push("account:new");
    score += 0.25;
  }
  if (followersCount !== null && followersCount <= 5) {
    signals.push("account:low-history");
    score += 0.1;
  }
  if (postsCount !== null && postsCount < 10) {
    signals.push("account:low-history");
    score += 0.1;
  }
  if (
    followersCount !== null &&
    followingCount !== null &&
    followingCount >= 50 &&
    followingCount / Math.max(1, followersCount) >= 20
  ) {
    signals.push("account:following-imbalance");
    score += 0.15;
  }
  if (previousHandles.length >= 2) {
    signals.push("account:handle-churn");
    score += 0.1;
  }
  if (coordination.memberCount > 1) {
    signals.push("account:coordinated-cluster");
    score += Math.min(0.4, 0.2 + (coordination.memberCount - 1) * 0.05);
  }

  return {
    score: Math.min(1, Number(score.toFixed(2))),
    signals: uniqueSorted(signals),
  };
}

function claimFor(fixture: ResearchFixture): EvidenceClaim {
  const claim = fixture.fixtureType === "x-post" ? fixture.claim : fixture.record.claim;
  return {
    ...claim,
    asset: {
      chainId: claim.asset.chainId,
      address: claim.asset.address.toLowerCase(),
      tokenId: claim.asset.tokenId,
    },
  };
}

function observedAtFor(fixture: ResearchFixture): string {
  if (fixture.fixtureType === "x-post") return fixture.post.createdAt;
  if (fixture.fixtureType === "opensea-record") return fixture.record.observedAt;
  return fixture.record.blockTimestamp;
}

function canonicalClusterId(fixture: Exclude<ResearchFixture, XPostFixture>): string {
  const claim = fixture.record.claim;
  // Multiple records from one canonical surface are corroborating facts, but
  // not independent sources. Cluster by surface and exact asset rather than by
  // order, block, provider, or polling attempt.
  return `canonical:${shortHash(
    [
      fixture.source.kind,
      claim.asset.chainId,
      claim.asset.address.toLowerCase(),
      claim.asset.tokenId,
    ].join(":"),
  )}`;
}

function sameAsset(left: EvidenceClaim["asset"], right: EvidenceClaim["asset"]): boolean {
  return (
    left.chainId === right.chainId &&
    left.address.toLowerCase() === right.address.toLowerCase() &&
    left.tokenId === right.tokenId
  );
}

export function extractResearchBatch(
  captures: readonly RawFixtureCapture[],
  options: { synchronizationWindowSeconds?: number } = {},
): ResearchBatch {
  if (captures.length > MAX_FIXTURES_PER_BATCH) {
    throw new Error(`research batch exceeds ${MAX_FIXTURES_PER_BATCH} fixture limit`);
  }

  const uniquePrepared = new Map<string, PreparedFixture>();
  for (const capture of captures) {
    const prepared = prepare(capture);
    uniquePrepared.set(prepared.observationId, prepared);
  }
  const prepared = [...uniquePrepared.values()];
  const socialInputs = prepared
    .filter(
      (item): item is PreparedFixture & { fixture: XPostFixture } =>
        item.fixture.fixtureType === "x-post",
    )
    .map((item) => ({
      observationId: item.observationId,
      fixture: item.fixture,
      urls: item.urls,
    }));
  const socialClusters = clusterSocialFixtures(socialInputs, options.synchronizationWindowSeconds);

  const observations: Observation[] = [];
  const analyses: FixtureAnalysis[] = [];

  for (const item of prepared) {
    const { fixture } = item;
    // Unicode, punycode, HTTP, and cross-origin redirects are diagnostics, not
    // proof of deception. Only stronger integrity conditions cross into the
    // domain field that the policy kernel treats as a hard rejection.
    const homographFlags = uniqueSorted(
      item.urls.flatMap(({ flags }) =>
        flags.filter((flag) => OBSERVATION_URL_INTEGRITY_FLAGS.has(flag)),
      ),
    );
    let clusterId: string;
    let anomalyScore = 0;
    let accountSignals: AccountSignal[] = [];
    let coordinationSignals: readonly CoordinationSignal[] = [];

    if (fixture.fixtureType === "x-post") {
      const coordination = socialClusters.get(item.observationId);
      if (coordination === undefined) throw new Error("missing social cluster assignment");
      clusterId = coordination.coordinationClusterId;
      const account = accountRisk(fixture, coordination);
      anomalyScore = account.score;
      accountSignals = account.signals;
      coordinationSignals = coordination.signals;
    } else {
      clusterId = canonicalClusterId(fixture);
    }

    const source = {
      kind: fixture.source.kind,
      providerId: fixture.source.providerId,
      ...(fixture.source.providerOrigin === undefined
        ? {}
        : { providerOrigin: fixture.source.providerOrigin }),
    };
    const origin =
      fixture.fixtureType === "x-post"
        ? {
            xPostId: fixture.post.postId,
            authorId: fixture.post.author.authorId,
            editHistoryIds: fixture.post.editHistoryIds,
            capturedVersionHash: item.capture.metadata.contentHash,
          }
        : undefined;
    const order =
      fixture.fixtureType === "opensea-record" && fixture.record.orderHash !== undefined
        ? { marketplace: "opensea" as const, orderHash: fixture.record.orderHash }
        : undefined;

    observations.push(
      ObservationSchema.parse({
        observationId: item.observationId,
        source,
        acquiredAt: fixture.acquiredAt,
        observedAt: observedAtFor(fixture),
        validUntil: fixture.validUntil,
        raw: item.capture.metadata,
        ...(origin === undefined ? {} : { origin }),
        ...(order === undefined ? {} : { order }),
        claims: [claimFor(fixture)],
        integrity: {
          coordinationClusterId: clusterId,
          accountAnomalyScore: anomalyScore,
          homographFlags,
          injectionFlags: uniqueSorted([...item.instructionFlags, ...item.identityFlags]),
          independentEvidenceIds: [],
        },
      }),
    );
    analyses.push({
      observationId: item.observationId,
      fixtureType: fixture.fixtureType,
      contentHash: item.capture.metadata.contentHash,
      instructionFlags: item.instructionFlags,
      identityFlags: item.identityFlags,
      accountSignals,
      coordinationSignals,
      urls: item.urls,
    });
  }

  const correlated = observations.map((observation) =>
    ObservationSchema.parse({
      ...observation,
      integrity: {
        ...observation.integrity,
        independentEvidenceIds: observations
          .filter(
            (candidate) =>
              candidate.observationId !== observation.observationId &&
              candidate.integrity.coordinationClusterId !==
                observation.integrity.coordinationClusterId &&
              candidate.claims.some((candidateClaim) =>
                observation.claims.some((claim) => sameAsset(claim.asset, candidateClaim.asset)),
              ),
          )
          .map(({ observationId }) => observationId)
          .sort(),
      },
    }),
  );

  return { observations: correlated, analyses };
}
