import { assetKey, type ExecutionIntent, type Observation, type PolicyConfig } from "@rsi/domain";
import { PolicyKernel } from "@rsi/policy";

// These addresses are deliberately fictional local-demo values.
const MARKETPLACE = `0x${"1".repeat(40)}`;
const COLLECTION = `0x${"2".repeat(40)}`;
const PAYMENT_ASSET = `0x${"3".repeat(40)}`;
const RECIPIENT = `0x${"4".repeat(40)}`;

const now = new Date();
const acquiredAt = new Date(now.getTime() - 30_000).toISOString();
const validUntil = new Date(now.getTime() + 60_000).toISOString();

const policy: PolicyConfig = {
  policyVersion: "kernel-v0",
  allowedChains: [4663],
  allowedMarketplaceTargets: [{ chainId: 4663, address: MARKETPLACE }],
  allowedCollections: [{ chainId: 4663, address: COLLECTION }],
  allowedPaymentAssets: [{ chainId: 4663, address: PAYMENT_ASSET }],
  allowedRecipients: [{ chainId: 4663, address: RECIPIENT }],
  maxPerTransactionByAsset: {
    [assetKey(4663, PAYMENT_ASSET)]: "10000000",
  },
  maxDailySpendByAsset: {
    [assetKey(4663, PAYMENT_ASSET)]: "25000000",
  },
  maxEvidenceAgeSeconds: 300,
  maxClockSkewSeconds: 30,
  minIndependentEvidenceClusters: 2,
  requireCanonicalMarketplaceEvidence: true,
};

const kernel = new PolicyKernel(policy);

function observation(
  idCharacter: string,
  source: Observation["source"]["kind"],
  cluster: string,
  claimType: Observation["claims"][number]["type"],
): Observation {
  const order =
    source === "opensea"
      ? { marketplace: "opensea" as const, orderHash: `0x${"5".repeat(64)}` }
      : undefined;
  return {
    observationId: `sha256:${idCharacter.repeat(64)}`,
    source: { kind: source, providerId: `demo-${source}` },
    acquiredAt,
    observedAt: acquiredAt,
    validUntil,
    ...(order === undefined ? {} : { order }),
    raw: {
      contentHash: `sha256:${idCharacter.repeat(64)}`,
      contentType: "application/json",
      byteLength: 128,
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
  };
}

const observations = [
  observation("a", "x", "social-cluster-1", "market_momentum"),
  observation("b", "opensea", "market-source-1", "listing"),
];

const intent: ExecutionIntent = {
  intentId: "rsi-intent:demo-001",
  strategyVersion: "rsi-v0",
  policyVersion: policy.policyVersion,
  policyHash: kernel.policyHash,
  evidenceIds: observations.map(({ observationId }) => observationId),
  createdAt: now.toISOString(),
  expiresAt: new Date(now.getTime() + 45_000).toISOString(),
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

const decision = kernel.authorize(intent, observations, now);
console.log(JSON.stringify(decision, null, 2));
