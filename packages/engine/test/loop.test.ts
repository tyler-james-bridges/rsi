import { describe, expect, it } from "vitest";

import type { Strategy } from "@rsi/domain";

import { RecursiveImprovementLoop } from "../src/index.js";

const champion: Strategy = {
  version: "rsi-v0",
  sourceWeights: { x: 0.15, x402: 0.2, opensea: 0.3, onchain: 0.35 },
  opportunityThreshold: 0.75,
  maxHoldSeconds: 86_400,
  exitLossBps: 1_000,
  exitGainBps: 2_500,
  queryTerms: ["base nft"],
};

describe("RecursiveImprovementLoop", () => {
  it("promotes only after attack testing, a live canary, and evaluation", () => {
    const loop = new RecursiveImprovementLoop(champion, {
      minEvaluationSampleSize: 2,
    });
    const candidate = loop.propose("rsi-v1", { opportunityThreshold: 0.8 }, `0x${"a".repeat(64)}`);

    expect(() => loop.promote(candidate.candidateId)).toThrow(/expected evaluated/);
    loop.recordAttackResult(candidate.candidateId, {
      passed: true,
      hardInvariantEscapes: 0,
      notes: "all adversarial fixtures blocked",
    });
    loop.startLiveCanary(candidate.candidateId, 50);
    loop.recordCanaryResult(candidate.candidateId, {
      hardInvariantEscapes: 0,
      maxDrawdownBps: 100,
      notes: "bounded live allocation completed",
    });
    loop.recordEvaluation(candidate.candidateId, {
      sampleSize: 2,
      recommendPromotion: true,
      notes: "safety preserved and calibration improved",
    });

    const promoted = loop.promote(candidate.candidateId);

    expect(promoted.version).toBe("rsi-v1");
    expect(promoted.opportunityThreshold).toBe(0.8);
  });

  it("does not allow a strategy patch to modify policy fields", () => {
    const loop = new RecursiveImprovementLoop(champion);

    expect(() =>
      loop.propose("rsi-v1", { policyVersion: "kernel-owned-by-strategy" }, `0x${"b".repeat(64)}`),
    ).toThrow();
  });

  it("rejects a candidate after any hard-invariant escape", () => {
    const loop = new RecursiveImprovementLoop(champion);
    const candidate = loop.propose("rsi-v1", { sourceWeights: { x: 0.2 } }, `0x${"c".repeat(64)}`);

    const result = loop.recordAttackResult(candidate.candidateId, {
      passed: false,
      hardInvariantEscapes: 1,
      notes: "hostile manifest reached the decision layer",
    });

    expect(result.stage).toBe("rejected");
    expect(() => loop.startLiveCanary(candidate.candidateId, 10)).toThrow();
  });
});
