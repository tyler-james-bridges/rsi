import { ObservationSchema as RootObservationSchema } from "@rsi/domain";
import { ObservationSchema as EvidenceObservationSchema } from "@rsi/domain/evidence";
import { ResearchProposalV1Schema } from "@rsi/domain/proposals";
import { describe, expect, it } from "vitest";

import { assessRecordedReplay as assessRecordedReplayFromRoot } from "../src/index.js";
import {
  RECORDED_REPLAY_EVALUATED_AT,
  RecordedReplayScenarioSchema,
  assessRecordedReplay,
  buildRecordedReplayProposal,
  deriveRecordedReplayDisposition,
  type RecordedReplayScenario,
} from "../src/replay.js";

const EXPECTED_ASSET = Object.freeze({
  chainId: 4663,
  address: "0x1111111111111111111111111111111111111111",
  tokenId: "7",
});

const EXPECTED_ASSESSMENTS: Record<RecordedReplayScenario, unknown> = {
  safe: {
    scenario: "safe",
    strategyVersion: "rsi-recorded-replay-v1",
    asset: EXPECTED_ASSET,
    evidenceIds: [
      "sha256:1dcad684e85b86f721cc6d36dba4edf12392bb56ed3ada99686d4894eba2ba46",
      "sha256:28d5dd84f508c1b51cdc0aa405be1d30564152f5ef471ab8bd99d49d103c433b",
      "sha256:d5c4263e4faaff87656a15b1b59360a93345806c5d0d289a06b8d80149e71810",
    ],
    provenance: {
      providerIds: ["fixture.opensea.archive", "fixture.rpc.archive", "fixture.x.archive"],
      sourceKinds: ["onchain", "opensea", "x"],
      independentClusterCount: 3,
    },
    flags: { scam: [], injection: [], homograph: [] },
    scorecard: {
      confidence: 0.8,
      marketSupport: 0.6667,
      opportunity: 0,
      provenanceQuality: 1,
      risk: 0,
    },
    disposition: { kind: "abstain", reason: "market_uncertainty" },
  },
  "coordinated-shill": {
    scenario: "coordinated-shill",
    strategyVersion: "rsi-recorded-replay-v1",
    asset: EXPECTED_ASSET,
    evidenceIds: [
      "sha256:1525407ea181be35494e79410b4f833be736e5af92a8bdaaf852f348dd7a0b24",
      "sha256:28d5dd84f508c1b51cdc0aa405be1d30564152f5ef471ab8bd99d49d103c433b",
      "sha256:45072991163b3e95f3a5676a93620f76e8ed747f4cd973691f008469f71d4314",
    ],
    provenance: {
      providerIds: ["fixture.opensea.archive", "fixture.x.archive"],
      sourceKinds: ["opensea", "x"],
      independentClusterCount: 2,
    },
    flags: {
      scam: [
        "account:coordinated-cluster",
        "account:following-imbalance",
        "account:handle-churn",
        "account:low-history",
        "account:very-new",
        "coordination:duplicate-content",
        "coordination:synchronized-destination",
      ],
      injection: ["prompt:financial-action"],
      homograph: ["url:mixed-script-label"],
    },
    scorecard: {
      confidence: 0.9867,
      marketSupport: 0.3333,
      opportunity: 0,
      provenanceQuality: 0.6667,
      risk: 1,
    },
    disposition: { kind: "abstain", reason: "integrity_risk" },
  },
  "prompt-injection": {
    scenario: "prompt-injection",
    strategyVersion: "rsi-recorded-replay-v1",
    asset: EXPECTED_ASSET,
    evidenceIds: [
      "sha256:1dcad684e85b86f721cc6d36dba4edf12392bb56ed3ada99686d4894eba2ba46",
      "sha256:28d5dd84f508c1b51cdc0aa405be1d30564152f5ef471ab8bd99d49d103c433b",
      "sha256:8a6c625aeec6ce749fc4976ba6c89629e03a959781b0aa8563904b9ac5f828ba",
    ],
    provenance: {
      providerIds: ["fixture.opensea.archive", "fixture.rpc.archive", "fixture.x.archive"],
      sourceKinds: ["onchain", "opensea", "x"],
      independentClusterCount: 3,
    },
    flags: {
      scam: [],
      injection: [
        "prompt:financial-action",
        "prompt:instruction-override",
        "prompt:policy-disable",
        "prompt:role-spoofing",
        "prompt:secret-exfiltration",
        "prompt:tool-invocation",
      ],
      homograph: [],
    },
    scorecard: {
      confidence: 0.9767,
      marketSupport: 0.6667,
      opportunity: 0,
      provenanceQuality: 1,
      risk: 1,
    },
    disposition: { kind: "abstain", reason: "integrity_risk" },
  },
  "stale-evidence": {
    scenario: "stale-evidence",
    strategyVersion: "rsi-recorded-replay-v1",
    asset: EXPECTED_ASSET,
    evidenceIds: [
      "sha256:1dcad684e85b86f721cc6d36dba4edf12392bb56ed3ada99686d4894eba2ba46",
      "sha256:28d5dd84f508c1b51cdc0aa405be1d30564152f5ef471ab8bd99d49d103c433b",
      "sha256:80cb0699bface40b342e199afd17922bba98be6c9c95ab04cdbbbb28e62c2a1d",
    ],
    provenance: {
      providerIds: ["fixture.opensea.archive", "fixture.rpc.archive", "fixture.x.archive"],
      sourceKinds: ["onchain", "opensea", "x"],
      independentClusterCount: 2,
    },
    flags: { scam: [], injection: [], homograph: [] },
    scorecard: {
      confidence: 0.7267,
      marketSupport: 0.6667,
      opportunity: 0,
      provenanceQuality: 0.6667,
      risk: 0,
    },
    disposition: { kind: "abstain", reason: "stale_evidence" },
  },
  "contract-substitution": {
    scenario: "contract-substitution",
    strategyVersion: "rsi-recorded-replay-v1",
    asset: EXPECTED_ASSET,
    evidenceIds: [
      "sha256:1dcad684e85b86f721cc6d36dba4edf12392bb56ed3ada99686d4894eba2ba46",
      "sha256:28d5dd84f508c1b51cdc0aa405be1d30564152f5ef471ab8bd99d49d103c433b",
      "sha256:fe74982221ea5f69b1b41d7986c6cc82f57b2b7f880b3b894208fe6bcacfbcf1",
    ],
    provenance: {
      providerIds: ["fixture.opensea.archive", "fixture.rpc.archive", "fixture.x.archive"],
      sourceKinds: ["onchain", "opensea", "x"],
      independentClusterCount: 2,
    },
    flags: {
      scam: [
        "account:following-imbalance",
        "account:handle-churn",
        "account:low-history",
        "account:very-new",
        "identity:declared-address-conflict",
        "identity:multiple-contract-addresses",
      ],
      injection: ["prompt:financial-action"],
      homograph: [],
    },
    scorecard: {
      confidence: 0.99,
      marketSupport: 1,
      opportunity: 0,
      provenanceQuality: 0.6667,
      risk: 1,
    },
    disposition: { kind: "abstain", reason: "identity_ambiguity" },
  },
};

function expectDeeplyFrozen(value: unknown): void {
  if (typeof value !== "object" || value === null) return;
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectDeeplyFrozen(child);
}

describe("recorded research replay", () => {
  it("keeps the research evidence schema compatible with the domain root export", () => {
    expect(EvidenceObservationSchema).toBe(RootObservationSchema);
    expect(assessRecordedReplayFromRoot).toBe(assessRecordedReplay);
  });

  it("accepts only the five code-owned replay scenarios", () => {
    expect(RECORDED_REPLAY_EVALUATED_AT).toBe("2026-08-11T12:00:00.000Z");
    expect(RecordedReplayScenarioSchema.options).toEqual([
      "safe",
      "coordinated-shill",
      "prompt-injection",
      "stale-evidence",
      "contract-substitution",
    ]);
    expect(RecordedReplayScenarioSchema.safeParse("../safe-social.json").success).toBe(false);
    expect(RecordedReplayScenarioSchema.safeParse("https://example.invalid/replay").success).toBe(
      false,
    );
  });

  it.each(RecordedReplayScenarioSchema.options)(
    "returns the exact deterministic, content-free %s assessment",
    (scenario) => {
      const first = assessRecordedReplay(scenario);
      const second = assessRecordedReplay(scenario);

      expect(first).toEqual(EXPECTED_ASSESSMENTS[scenario]);
      expect(second).toEqual(first);
      expect(first.scorecard.opportunity).toBe(0);
      expect(JSON.stringify(first)).not.toMatch(
        /BUY NFT NOW|private key|https?:\/\/|campaign\.example\.invalid|view=orders/iu,
      );
      expectDeeplyFrozen(first);
    },
  );

  it.each([
    [
      "identity mismatch",
      { assetMismatchCount: 1, integrityFlagCount: 1, staleEvidenceCount: 1 },
      "identity_ambiguity",
    ],
    ["integrity flag", { integrityFlagCount: 1, staleEvidenceCount: 1 }, "integrity_risk"],
    ["stale evidence", { staleEvidenceCount: 1 }, "stale_evidence"],
    ["future evidence", { futureEvidenceCount: 1 }, "stale_evidence"],
    ["weak provenance", { freshIndependentClusterCount: 1 }, "insufficient_evidence"],
    ["no canonical source", { freshCanonicalEvidenceCount: 0 }, "insufficient_evidence"],
    ["adequate bounded evidence", {}, "market_uncertainty"],
  ] as const)(
    "derives %s from evidence rather than the scenario label",
    (_label, overrides, reason) => {
      const disposition = deriveRecordedReplayDisposition({
        assetMismatchCount: 0,
        integrityFlagCount: 0,
        staleEvidenceCount: 0,
        futureEvidenceCount: 0,
        freshIndependentClusterCount: 2,
        freshCanonicalEvidenceCount: 1,
        ...overrides,
      });

      expect(disposition).toEqual({ kind: "abstain", reason });
      expect(Object.isFrozen(disposition)).toBe(true);
    },
  );

  it("rejects scenario labels at the disposition boundary", () => {
    expect(() =>
      Reflect.apply(deriveRecordedReplayDisposition, undefined, [
        {
          assetMismatchCount: 0,
          integrityFlagCount: 0,
          staleEvidenceCount: 0,
          futureEvidenceCount: 0,
          freshIndependentClusterCount: 2,
          freshCanonicalEvidenceCount: 1,
          scenario: "prompt-injection",
        },
      ]),
    ).toThrow();
  });

  it("builds a strict five-minute proposal envelope without leaking the scenario field", () => {
    const assessment = assessRecordedReplay("safe");
    const proposal = buildRecordedReplayProposal({
      assessment,
      requestId: "00000000-0000-4000-8000-000000000001",
      createdAt: "2026-09-29T20:00:00.000Z",
    });

    expect(proposal).toEqual({
      schemaVersion: 1,
      proposalId: "rsi-proposal:safe-00000000-0000-4000-8000-000000000001",
      strategyVersion: "rsi-recorded-replay-v1",
      createdAt: "2026-09-29T20:00:00.000Z",
      expiresAt: "2026-09-29T20:05:00.000Z",
      asset: assessment.asset,
      evidenceIds: assessment.evidenceIds,
      provenance: assessment.provenance,
      flags: assessment.flags,
      scorecard: assessment.scorecard,
      disposition: assessment.disposition,
    });
    expect(ResearchProposalV1Schema.safeParse(proposal).success).toBe(true);
    expect("scenario" in proposal).toBe(false);
  });

  it("rejects a nonzero opportunity at the public boundary", () => {
    const validAssessment = assessRecordedReplay("safe");
    const assessment = {
      ...validAssessment,
      scorecard: { ...validAssessment.scorecard, opportunity: 1 },
    };

    expect(() =>
      Reflect.apply(buildRecordedReplayProposal, undefined, [
        {
          assessment,
          requestId: "00000000-0000-4000-8000-000000000001",
          createdAt: "2026-09-29T20:00:00.000Z",
        },
      ]),
    ).toThrow();
  });

  it.each([
    ["not-a-uuid", "2026-09-29T20:00:00.000Z"],
    ["00000000-0000-4000-8000-000000000001", "not-a-time"],
  ])("rejects invalid envelope identity or time", (requestId, createdAt) => {
    expect(() =>
      Reflect.apply(buildRecordedReplayProposal, undefined, [
        {
          assessment: assessRecordedReplay("safe"),
          requestId,
          createdAt,
        },
      ]),
    ).toThrow();
  });
});
