import { describe, expect, it } from "vitest";

import * as rootExports from "@rsi/source-contracts";
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
    ]) {
      expect(rootExports).not.toHaveProperty(name);
    }
  });

  it("exposes legacy fixtures and live trending through distinct explicit subpaths", () => {
    expect(legacyExports.OPENSEA_LEGACY_FIXTURES_STATUS).toBe("legacy-synthetic-non-live");
    expect(legacyExports.prepareOpenSeaRestRequest).toBeTypeOf("function");
    expect(legacyExports).not.toHaveProperty("prepareOpenSeaTrendingRequest");

    expect(trendingExports.OPENSEA_TRENDING_CONTRACT_VERSION).toContain("2026-08-25");
    expect(trendingExports.prepareOpenSeaTrendingRequest).toBeTypeOf("function");
    expect(trendingExports.parseOpenSeaTrendingResponse).toBeTypeOf("function");
    expect(trendingExports).not.toHaveProperty("prepareOpenSeaRestRequest");
    expect(trendingExports).not.toHaveProperty("prepareOpenSeaStreamSubscription");
  });
});
