import { describe, expect, it } from "vitest";

import { operatorUsage, parseOperatorOptions } from "../src/operator-options.js";

describe("operator command options", () => {
  it("accepts pnpm separators and explicit safe options", () => {
    expect(parseOperatorOptions(["--", "--seed", "--", "--db", ":memory:", "--port", "0"])).toEqual(
      { databasePath: ":memory:", port: 0, seed: true },
    );
  });

  it("uses loopback-service defaults", () => {
    expect(parseOperatorOptions([])).toEqual({
      databasePath: ".local/rsi.sqlite",
      port: 8_787,
      seed: false,
    });
  });

  it("returns help without starting a service", () => {
    expect(parseOperatorOptions(["--help"])).toBeNull();
    expect(operatorUsage()).toContain("read-only operator API");
  });

  it.each<[string, string[]]>([
    ["unknown argument", ["--public"]],
    ["missing database path", ["--db"]],
    ["non-integer port", ["--port", "12.5"]],
    ["out-of-range port", ["--port", "65536"]],
  ])("rejects %s", (_label, args) => {
    expect(() => parseOperatorOptions(args)).toThrow();
  });
});
