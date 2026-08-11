import { assetKey, type ExecutionIntent, type Observation, type PolicyConfig } from "@rsi/domain";

import { PolicyKernel } from "../src/index.js";

export const MARKETPLACE = `0x${"1".repeat(40)}`;
export const COLLECTION = `0x${"2".repeat(40)}`;
export const PAYMENT_ASSET = `0x${"3".repeat(40)}`;
export const RECIPIENT = `0x${"4".repeat(40)}`;

export function makeFixture() {
  const now = new Date("2026-08-11T12:00:00.000Z");
  const policy: PolicyConfig = {
    policyVersion: "kernel-v0",
    allowedChains: [4663],
    allowedMarketplaceTargets: [{ chainId: 4663, address: MARKETPLACE }],
    allowedCollections: [{ chainId: 4663, address: COLLECTION }],
    allowedPaymentAssets: [{ chainId: 4663, address: PAYMENT_ASSET }],
    maxPerTransactionByAsset: {
      [assetKey(4663, PAYMENT_ASSET)]: "10000000",
    },
    maxDailySpendByAsset: {
      [assetKey(4663, PAYMENT_ASSET)]: "15000000",
    },
    maxEvidenceAgeSeconds: 300,
    maxClockSkewSeconds: 30,
    minIndependentEvidenceClusters: 2,
    requireCanonicalMarketplaceEvidence: true,
  };
  const kernel = new PolicyKernel(policy);

  const observation = (
    idCharacter: string,
    source: Observation["source"]["kind"],
    cluster: string,
    claimType: Observation["claims"][number]["type"],
  ): Observation => ({
    observationId: `sha256:${idCharacter.repeat(64)}`,
    source: { kind: source, providerId: `fixture-${source}` },
    acquiredAt: "2026-08-11T11:59:00.000Z",
    validUntil: "2026-08-11T12:01:00.000Z",
    raw: {
      contentHash: `sha256:${idCharacter.repeat(64)}`,
      contentType: "application/json",
      byteLength: 512,
    },
    claims: [
      {
        type: claimType,
        asset: { chainId: 4663, address: COLLECTION, tokenId: "7" },
        confidence: 0.9,
      },
    ],
    integrity: {
      coordinationClusterId: cluster,
      accountAnomalyScore: 0,
      homographFlags: [],
      injectionFlags: [],
      independentEvidenceIds: [],
    },
  });

  const observations = [
    observation("a", "x", "social-cluster", "market_momentum"),
    observation("b", "opensea", "market-cluster", "listing"),
  ];

  const intent: ExecutionIntent = {
    intentId: "rsi-intent:test-001",
    strategyVersion: "rsi-v0",
    policyVersion: policy.policyVersion,
    policyHash: kernel.policyHash,
    evidenceIds: observations.map(({ observationId }) => observationId),
    createdAt: "2026-08-11T11:59:45.000Z",
    expiresAt: "2026-08-11T12:00:45.000Z",
    action: {
      kind: "nft.purchase",
      adapterId: "opensea.seaport",
      chainId: 4663,
      marketplace: "opensea",
      targetContract: MARKETPLACE,
      collectionContract: COLLECTION,
      tokenId: "7",
      paymentAsset: PAYMENT_ASSET,
      maxTotalSpend: "5000000",
      recipient: RECIPIENT,
      orderHash: `0x${"5".repeat(64)}`,
      nonce: `0x${"6".repeat(64)}`,
    },
  };

  return { intent, kernel, now, observations, policy };
}
