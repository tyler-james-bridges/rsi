import { describe, expect, it } from "vitest";

import * as rootExports from "@rsi/source-contracts";
import * as baseRpcAnchorExports from "@rsi/source-contracts/base-rpc-anchor";
import * as legacyExports from "@rsi/source-contracts/legacy-opensea-fixtures";
import * as trendingExports from "@rsi/source-contracts/opensea-trending";

describe("source-contract package export boundaries", () => {
  it("keeps both OpenSea contracts off the package root", () => {
    for (const name of [
      "OPENSEA_CONTRACT_REVIEW_DATE",
      "OPENSEA_LEGACY_FIXTURES_STATUS",
      "OPENSEA_TRENDING_CONTRACT_VERSION",
      "prepareOpenSeaRestRequest",
      "prepareOpenSeaStreamSubscription",
      "parseOpenSeaRestFixture",
      "parseOpenSeaStreamFixture",
      "corroborateOpenSeaListing",
      "prepareOpenSeaTrendingRequest",
      "parseOpenSeaTrendingResponse",
      "BASE_RPC_ANCHOR_CONTRACT_VERSION",
      "prepareBaseRpcAnchorRequest",
      "parseBaseRpcFinalizedAnchor",
      "BaseRpcFinalizedAnchor",
    ]) {
      expect(rootExports).not.toHaveProperty(name);
    }
  });

  it("exposes the Base RPC anchor only through its isolated subpath", () => {
    expect(baseRpcAnchorExports.BASE_RPC_ANCHOR_CONTRACT_VERSION).toContain("2026-09-05");
    expect(baseRpcAnchorExports.prepareBaseRpcAnchorRequest).toBeTypeOf("function");
    expect(baseRpcAnchorExports.parseBaseRpcFinalizedAnchor).toBeTypeOf("function");
    expect(baseRpcAnchorExports).not.toHaveProperty("prepareFinalizedBlockRequest");
    expect(baseRpcAnchorExports).not.toHaveProperty("prepareCanonicalAssetRequest");
    expect(baseRpcAnchorExports).not.toHaveProperty("prepareOpenSeaTrendingRequest");
  });

  it("exposes legacy fixtures and live trending through distinct explicit subpaths", () => {
    expect(legacyExports.OPENSEA_LEGACY_FIXTURES_STATUS).toBe("legacy-synthetic-non-live");
    expect(legacyExports.prepareOpenSeaRestRequest).toBeTypeOf("function");
    expect(legacyExports).not.toHaveProperty("prepareOpenSeaTrendingRequest");

    expect(trendingExports.OPENSEA_TRENDING_CONTRACT_VERSION).toContain("2026-09-05");
    expect(trendingExports.prepareOpenSeaTrendingRequest).toBeTypeOf("function");
    expect(trendingExports.parseOpenSeaTrendingResponse).toBeTypeOf("function");
    expect(trendingExports).not.toHaveProperty("prepareOpenSeaRestRequest");
    expect(trendingExports).not.toHaveProperty("prepareOpenSeaStreamSubscription");
  });
});
