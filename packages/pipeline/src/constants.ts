import { assetKey, type PolicyConfig } from "@rsi/domain";

// Deliberately fictional values used only by the recorded-fixture pipeline.
export const FIXTURE_CHAIN_ID = 4_663;
export const FIXTURE_COLLECTION = `0x${"1".repeat(40)}`;
export const FIXTURE_ORDER_HASH = `0x${"2".repeat(64)}`;
export const FIXTURE_MARKETPLACE_TARGET = `0x${"7".repeat(40)}`;
export const FIXTURE_PAYMENT_ASSET = `0x${"8".repeat(40)}`;
export const FIXTURE_RECIPIENT = `0x${"a".repeat(40)}`;

export function createFixturePolicy(): PolicyConfig {
  return {
    policyVersion: "kernel-fixture-v1",
    allowedChains: [FIXTURE_CHAIN_ID],
    allowedMarketplaceTargets: [{ chainId: FIXTURE_CHAIN_ID, address: FIXTURE_MARKETPLACE_TARGET }],
    allowedCollections: [{ chainId: FIXTURE_CHAIN_ID, address: FIXTURE_COLLECTION }],
    allowedPaymentAssets: [{ chainId: FIXTURE_CHAIN_ID, address: FIXTURE_PAYMENT_ASSET }],
    allowedRecipients: [{ chainId: FIXTURE_CHAIN_ID, address: FIXTURE_RECIPIENT }],
    maxPerTransactionByAsset: {
      [assetKey(FIXTURE_CHAIN_ID, FIXTURE_PAYMENT_ASSET)]: "10000000",
    },
    maxDailySpendByAsset: {
      [assetKey(FIXTURE_CHAIN_ID, FIXTURE_PAYMENT_ASSET)]: "15000000",
    },
    maxEvidenceAgeSeconds: 300,
    maxClockSkewSeconds: 30,
    minIndependentEvidenceClusters: 3,
    requireCanonicalMarketplaceEvidence: true,
  };
}
