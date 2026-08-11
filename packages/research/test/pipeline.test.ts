import { ObservationSchema } from "@rsi/domain";
import { describe, expect, it } from "vitest";

import {
  captureRawFixture,
  extractResearchBatch,
  loadRecordedFixture,
  loadRecordedFixtures,
  parseCapturedFixture,
  summarizeCorrelation,
} from "../src/index.js";

const EXPECTED_ASSET = {
  chainId: 4663,
  address: "0x1111111111111111111111111111111111111111",
  tokenId: "7",
} as const;

describe("hostile-content research pipeline", () => {
  it("extracts safe social and canonical evidence without carrying raw text", async () => {
    const captures = await loadRecordedFixtures(["safeSocial", "safeMarketplace", "safeOnchain"]);
    const batch = extractResearchBatch(captures);

    expect(batch.observations).toHaveLength(3);
    for (const observation of batch.observations) {
      expect(ObservationSchema.safeParse(observation).success).toBe(true);
      expect(observation.claims[0]?.asset).toEqual(EXPECTED_ASSET);
      expect(observation.integrity.independentEvidenceIds).toHaveLength(2);
      expect(JSON.stringify(observation)).not.toContain("executable bids");
      expect(JSON.stringify(observation)).not.toContain("text");
    }

    const social = batch.observations.find(({ source }) => source.kind === "x");
    expect(social?.observedAt).toBe("2026-08-11T11:58:30.000Z");
    expect(social?.integrity.injectionFlags).toEqual([]);
    expect(social?.integrity.homographFlags).toEqual([]);
    expect(social?.integrity.accountAnomalyScore).toBe(0);
    const marketplace = batch.observations.find(({ source }) => source.kind === "opensea");
    expect(marketplace?.order?.orderHash).toBe(`0x${"2".repeat(64)}`);

    const socialAnalysis = batch.analyses.find(({ fixtureType }) => fixtureType === "x-post");
    expect(socialAnalysis?.urls[0]?.initial.normalizedUrl).toBe(
      "https://opensea.io/assets/robinhood/0x1111111111111111111111111111111111111111/7?view=orders",
    );

    const summary = summarizeCorrelation(
      batch.observations,
      EXPECTED_ASSET,
      new Date("2026-08-11T12:00:00.000Z"),
    );
    expect(summary).toMatchObject({
      observationCount: 3,
      independentClusterCount: 3,
      freshIndependentClusterCount: 3,
      canonicalEvidenceCount: 2,
      freshCanonicalEvidenceCount: 2,
      canonicalClusterCount: 2,
      assetMismatchObservationIds: [],
      staleObservationIds: [],
    });
  });

  it("places duplicated and synchronized shills in one cluster", async () => {
    const batch = extractResearchBatch(
      await loadRecordedFixtures(["coordinatedShillA", "coordinatedShillB"]),
    );
    const [first, second] = batch.observations;

    expect(first?.integrity.coordinationClusterId).toBe(second?.integrity.coordinationClusterId);
    expect(first?.integrity.accountAnomalyScore).toBeGreaterThanOrEqual(0.9);
    expect(second?.integrity.accountAnomalyScore).toBeGreaterThanOrEqual(0.9);
    for (const analysis of batch.analyses) {
      expect(analysis.coordinationSignals).toContain("coordination:duplicate-content");
      expect(analysis.coordinationSignals).toContain("coordination:synchronized-destination");
      expect(analysis.accountSignals).toContain("account:coordinated-cluster");
      expect(analysis.instructionFlags).toContain("prompt:financial-action");
    }

    const redirected = batch.analyses.find(
      ({ observationId }) => observationId === first?.observationId,
    );
    expect(redirected?.urls[0]?.flags).toEqual(
      expect.arrayContaining([
        "url:cross-origin-redirect",
        "url:mixed-script-label",
        "url:punycode-hostname",
        "url:unicode-hostname",
      ]),
    );
    expect(first?.integrity.homographFlags).toContain("url:mixed-script-label");
    expect(first?.integrity.homographFlags).not.toContain("url:cross-origin-redirect");

    const summary = summarizeCorrelation(
      batch.observations,
      EXPECTED_ASSET,
      new Date("2026-08-11T12:00:00.000Z"),
    );
    expect(summary.independentClusterCount).toBe(1);
  });

  it("never counts two posts from the same stable author as independent", async () => {
    const first = await loadRecordedFixture("safeSocial");
    const secondFixture = structuredClone(parseCapturedFixture(first));
    if (secondFixture.fixtureType !== "x-post") throw new Error("unexpected fixture");
    secondFixture.post.postId = "1002";
    secondFixture.post.editHistoryIds = ["1002"];
    secondFixture.post.createdAt = "2026-08-11T11:58:45.000Z";
    secondFixture.post.text = "A distinct observation from the same account.";
    secondFixture.post.links = [];
    const batch = extractResearchBatch([first, captureRawFixture(JSON.stringify(secondFixture))]);

    expect(batch.observations[0]?.integrity.coordinationClusterId).toBe(
      batch.observations[1]?.integrity.coordinationClusterId,
    );
    for (const analysis of batch.analyses) {
      expect(analysis.coordinationSignals).toContain("coordination:same-author");
    }
  });

  it("carries the source-observed time instead of laundering it as capture time", async () => {
    const capture = await loadRecordedFixture("safeMarketplace");
    const fixture = structuredClone(parseCapturedFixture(capture));
    if (fixture.fixtureType !== "opensea-record") throw new Error("unexpected fixture");
    fixture.record.observedAt = "2020-01-01T00:00:00.000Z";

    const batch = extractResearchBatch([captureRawFixture(JSON.stringify(fixture))]);

    expect(batch.observations[0]?.acquiredAt).toBe("2026-08-11T11:59:10.000Z");
    expect(batch.observations[0]?.observedAt).toBe("2020-01-01T00:00:00.000Z");
  });

  it("flags prompt injection and emits only typed integrity labels", async () => {
    const batch = extractResearchBatch([await loadRecordedFixture("promptInjection")]);
    const observation = batch.observations[0]!;
    const analysis = batch.analyses[0]!;

    expect(analysis.instructionFlags).toEqual(
      expect.arrayContaining([
        "prompt:financial-action",
        "prompt:instruction-override",
        "prompt:policy-disable",
        "prompt:role-spoofing",
        "prompt:secret-exfiltration",
        "prompt:tool-invocation",
      ]),
    );
    expect(observation.integrity.injectionFlags).toEqual(analysis.instructionFlags);
    expect(JSON.stringify(observation)).not.toContain("private key");
    expect(JSON.stringify(analysis)).not.toContain("private key");
  });

  it("reports stale evidence without silently dropping its provenance", async () => {
    const batch = extractResearchBatch([await loadRecordedFixture("staleSocial")]);
    const observation = batch.observations[0]!;
    const summary = summarizeCorrelation(
      batch.observations,
      EXPECTED_ASSET,
      new Date("2026-08-11T12:00:00.000Z"),
    );

    expect(observation.validUntil).toBe("2026-08-11T10:05:00.000Z");
    expect(summary.staleObservationIds).toEqual([observation.observationId]);
    expect(summary.freshIndependentClusterCount).toBe(0);
  });

  it("keeps a substituted contract distinct from the expected asset", async () => {
    const batch = extractResearchBatch([await loadRecordedFixture("contractSubstitution")]);
    const observation = batch.observations[0]!;
    const analysis = batch.analyses[0]!;

    expect(observation.claims[0]?.asset).toEqual({
      ...EXPECTED_ASSET,
      address: "0x9999999999999999999999999999999999999999",
    });
    expect(analysis.identityFlags).toEqual([
      "identity:declared-address-conflict",
      "identity:multiple-contract-addresses",
    ]);
    expect(observation.integrity.injectionFlags).toEqual(
      expect.arrayContaining([...analysis.identityFlags]),
    );

    const summary = summarizeCorrelation(
      batch.observations,
      EXPECTED_ASSET,
      new Date("2026-08-11T12:00:00.000Z"),
    );
    expect(summary.matchingObservationIds).toEqual([]);
    expect(summary.assetMismatchObservationIds).toEqual([observation.observationId]);
    expect(summary.canonicalEvidenceCount).toBe(0);
  });

  it("deduplicates an identical captured payload instead of manufacturing independence", async () => {
    const capture = await loadRecordedFixture("safeSocial");
    const batch = extractResearchBatch([capture, capture]);

    expect(batch.observations).toHaveLength(1);
    expect(batch.analyses).toHaveLength(1);
  });

  it("does not count repeated marketplace records as independent sources", async () => {
    const first = await loadRecordedFixture("safeMarketplace");
    const secondFixture = structuredClone(parseCapturedFixture(first));
    if (secondFixture.fixtureType !== "opensea-record") throw new Error("unexpected fixture");
    secondFixture.record.recordId = "listing:fixture-order-7-second-poll";
    secondFixture.record.orderHash = `0x${"6".repeat(64)}`;
    const second = captureRawFixture(JSON.stringify(secondFixture));
    const batch = extractResearchBatch([first, second]);

    expect(batch.observations[0]?.integrity.coordinationClusterId).toBe(
      batch.observations[1]?.integrity.coordinationClusterId,
    );
    const summary = summarizeCorrelation(
      batch.observations,
      EXPECTED_ASSET,
      new Date("2026-08-11T12:00:00.000Z"),
    );
    expect(summary.canonicalEvidenceCount).toBe(2);
    expect(summary.canonicalClusterCount).toBe(1);
    expect(summary.independentClusterCount).toBe(1);
  });
});
