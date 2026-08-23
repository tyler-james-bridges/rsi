import { describe, expect, it } from "vitest";

import { ResearchProposalV1Schema } from "../src/index.js";

const proposal = {
  schemaVersion: 1,
  proposalId: "rsi-proposal:fixture-001",
  strategyVersion: "rsi-v0",
  createdAt: "2026-08-23T12:00:00.000Z",
  expiresAt: "2026-08-23T12:05:00.000Z",
  asset: {
    chainId: 8453,
    address: `0x${"1".repeat(40)}`,
    tokenId: "7",
  },
  evidenceIds: [`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`],
  provenance: {
    providerIds: ["fixture-x", "fixture-market"],
    sourceKinds: ["x", "opensea"],
    independentClusterCount: 2,
  },
  flags: {
    scam: ["impersonation-risk"],
    injection: [],
    homograph: [],
  },
  scorecard: {
    confidence: 0.72,
    marketSupport: 0.68,
    opportunity: 0.61,
    provenanceQuality: 0.8,
    risk: 0.35,
  },
  disposition: { kind: "candidate" },
} as const;

describe("ResearchProposalV1Schema", () => {
  it("accepts a content-free, non-executable candidate", () => {
    expect(ResearchProposalV1Schema.parse(proposal)).toEqual(proposal);
  });

  it("accepts only closed abstention reasons", () => {
    expect(
      ResearchProposalV1Schema.parse({
        ...proposal,
        disposition: { kind: "abstain", reason: "integrity_risk" },
      }).disposition,
    ).toEqual({ kind: "abstain", reason: "integrity_risk" });
    expect(() =>
      ResearchProposalV1Schema.parse({
        ...proposal,
        disposition: { kind: "abstain", reason: "poster_said_buy_now" },
      }),
    ).toThrow();
  });

  it.each([
    "action",
    "adapterId",
    "target",
    "targetContract",
    "selector",
    "calldata",
    "recipient",
    "payment",
    "paymentAsset",
    "spend",
    "maxTotalSpend",
    "order",
    "orderHash",
    "nonce",
    "wallet",
    "signature",
  ])("rejects the executable field %s", (field) => {
    expect(ResearchProposalV1Schema.safeParse({ ...proposal, [field]: "hostile" }).success).toBe(
      false,
    );
  });

  it("rejects duplicate provenance and impossible time or cluster claims", () => {
    expect(
      ResearchProposalV1Schema.safeParse({
        ...proposal,
        evidenceIds: [proposal.evidenceIds[0], proposal.evidenceIds[0]],
      }).success,
    ).toBe(false);
    expect(
      ResearchProposalV1Schema.safeParse({
        ...proposal,
        expiresAt: proposal.createdAt,
      }).success,
    ).toBe(false);
    expect(
      ResearchProposalV1Schema.safeParse({
        ...proposal,
        provenance: { ...proposal.provenance, independentClusterCount: 3 },
      }).success,
    ).toBe(false);
  });
});
