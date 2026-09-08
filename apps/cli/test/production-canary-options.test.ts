import { describe, expect, it } from "vitest";

import {
  baseRpcCanaryOperatorUsage,
  parseBaseRpcCanaryOperatorOptions,
} from "../src/base-rpc-canary-operator-options.js";

import {
  openSeaCanaryOperatorUsage,
  parseOpenSeaCanaryOperatorOptions,
} from "../src/opensea-canary-operator-options.js";
import {
  productionOpenSeaCanaryHostOptions,
  productionXCanaryHostOptions,
} from "../src/production-canary-config.js";
import {
  parseXCanaryOperatorOptions,
  xCanaryOperatorUsage,
} from "../src/x-canary-operator-options.js";

describe("production canary command options", () => {
  it("returns only code-owned X and OpenSea options", () => {
    expect(parseBaseRpcCanaryOperatorOptions(["--", "--"])).toBe(true);
    expect(parseXCanaryOperatorOptions(["--", "--"])).toEqual(productionXCanaryHostOptions());
    expect(parseOpenSeaCanaryOperatorOptions([])).toEqual(productionOpenSeaCanaryHostOptions());
  });

  it("keeps help available without accepting a production override", () => {
    expect(parseXCanaryOperatorOptions(["--help"])).toBeNull();
    expect(parseOpenSeaCanaryOperatorOptions(["-h"])).toBeNull();
    expect(xCanaryOperatorUsage()).not.toContain("--db");
    expect(xCanaryOperatorUsage()).not.toContain("--port");
    expect(openSeaCanaryOperatorUsage()).not.toContain("--db");
    expect(openSeaCanaryOperatorUsage()).not.toContain("--port");
    expect(baseRpcCanaryOperatorUsage()).not.toContain("--db");
    expect(baseRpcCanaryOperatorUsage()).not.toContain("--port");
    expect(parseBaseRpcCanaryOperatorOptions(["--help"])).toBeNull();
  });

  it.each([
    ["X database", parseXCanaryOperatorOptions, ["--db", "alternate.sqlite"]],
    ["X research database", parseXCanaryOperatorOptions, ["--research-db", "alternate.sqlite"]],
    ["X port", parseXCanaryOperatorOptions, ["--port", "0"]],
    ["OpenSea database", parseOpenSeaCanaryOperatorOptions, ["--db", "alternate.sqlite"]],
    [
      "OpenSea research database",
      parseOpenSeaCanaryOperatorOptions,
      ["--research-db", "alternate.sqlite"],
    ],
    ["OpenSea port", parseOpenSeaCanaryOperatorOptions, ["--port", "0"]],
    ["Base RPC database", parseBaseRpcCanaryOperatorOptions, ["--db", "alternate.sqlite"]],
    ["Base RPC port", parseBaseRpcCanaryOperatorOptions, ["--port", "0"]],
  ] as const)("rejects the %s override", (_label, parse, args) => {
    expect(() => parse(args)).toThrow("production options are fixed");
  });
});
