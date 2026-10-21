import { OPENSEA_TRENDING_CONTRACT_VERSION } from "@rsi/source-contracts/opensea-trending";

export function fixture() {
  return {
    schemaVersion: 1,
    kind: "offline_opensea_trending",
    sourceContractVersion: OPENSEA_TRENDING_CONTRACT_VERSION,
    acquiredAt: "2026-10-20T00:00:00.000Z",
    validUntil: "2026-10-20T00:02:00.000Z",
    hasNextPage: false,
    collections: [
      { rank: 1, slug: "alpha", baseAddresses: ["0x" + "ab".repeat(20), "0x" + "cd".repeat(20)] },
    ],
  };
}
