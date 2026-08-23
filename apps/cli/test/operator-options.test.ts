import { describe, expect, it } from "vitest";

import { operatorUsage, parseOperatorOptions } from "../src/operator-options.js";

describe("operator command options", () => {
  it("accepts pnpm separators and explicit safe options", () => {
    expect(
      parseOperatorOptions([
        "--",
        "--db",
        ":memory:",
        "--research-db",
        "research.sqlite",
        "--",
        "--port",
        "0",
      ]),
    ).toEqual({ databasePath: ":memory:", port: 0, researchDatabasePath: "research.sqlite" });
  });

  it("uses loopback-service defaults", () => {
    expect(parseOperatorOptions([])).toEqual({
      databasePath: ".local/rsi-runtime.sqlite",
      port: 8_787,
      researchDatabasePath: ".local/rsi-research.sqlite",
    });
  });

  it("returns help without starting a service", () => {
    expect(parseOperatorOptions(["--help"])).toBeNull();
    expect(operatorUsage()).toContain("signer-blind Stage 0 runtime");
    expect(operatorUsage()).toContain("begins in STOPPED");
  });

  it.each<[string, string[]]>([
    ["unknown argument", ["--public"]],
    ["retired fixture seed", ["--seed"]],
    ["missing database path", ["--db"]],
    ["missing research database path", ["--research-db"]],
    ["shared database", ["--db", "same.sqlite", "--research-db", "same.sqlite"]],
    ["non-integer port", ["--port", "12.5"]],
    ["out-of-range port", ["--port", "65536"]],
  ])("rejects %s", (_label, args) => {
    expect(() => parseOperatorOptions(args)).toThrow();
  });
});
