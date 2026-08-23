import { describe, expect, it } from "vitest";

import { parseCiRetentionCliOptions } from "../src/ci-retention-cli.js";

const COMMIT = "d3f1e81183cc13fe51ea85ad21bcc71d31866dee";
const VALID = [
  "--run-id",
  "32219360003",
  "--output",
  "/private/tmp/rsi-foundation-ci.json",
  "--confirm-commit",
  COMMIT,
];

describe("foundation CI retention CLI", () => {
  it("accepts exactly run-id, output, and commit confirmation", () => {
    expect(parseCiRetentionCliOptions(VALID)).toEqual({
      confirmCommit: COMMIT,
      outputPath: "/private/tmp/rsi-foundation-ci.json",
      runId: "32219360003",
    });
    expect(
      parseCiRetentionCliOptions([
        "--confirm-commit",
        COMMIT,
        "--run-id",
        "32219360003",
        "--output",
        "/private/tmp/rsi-foundation-ci.json",
      ]),
    ).toEqual(parseCiRetentionCliOptions(VALID));
    expect(parseCiRetentionCliOptions(["--", ...VALID])).toEqual(parseCiRetentionCliOptions(VALID));
  });

  it.each([
    ["token", [...VALID.slice(0, 4), "--token", "secret"]],
    ["repository", [...VALID.slice(0, 4), "--repository", "attacker/rsi"]],
    ["API URL", [...VALID.slice(0, 4), "--api-url", "https://attacker.invalid"]],
    ["duplicate", [...VALID.slice(0, 4), "--output", "/tmp/again.json"]],
    ["missing", VALID.slice(0, 4)],
    ["separator", ["--", ...VALID.slice(0, 5)]],
    ["positional", ["run", ...VALID.slice(1)]],
  ])("rejects a %s argument", (_label, args) => {
    expect(() => parseCiRetentionCliOptions(args)).toThrow();
  });

  it("supports help without requiring or inspecting retention state", () => {
    expect(parseCiRetentionCliOptions(["--help"])).toBe("help");
    expect(parseCiRetentionCliOptions(["-h"])).toBe("help");
    expect(parseCiRetentionCliOptions(["--", "--help"])).toBe("help");
  });

  it.each(["0", "01", "-1", "1.5", "9007199254740992", "1e3", "abc"])(
    "rejects invalid run id %s",
    (runId) => {
      expect(() => parseCiRetentionCliOptions(["--run-id", runId, ...VALID.slice(2)])).toThrow();
    },
  );

  it("rejects malformed commits and values that look like flags", () => {
    expect(() => parseCiRetentionCliOptions([...VALID.slice(0, 5), "A".repeat(40)])).toThrow();
    expect(() =>
      parseCiRetentionCliOptions([...VALID.slice(0, 3), "--not-a-path", ...VALID.slice(4)]),
    ).toThrow();
  });

  it("rejects hostile argument arrays without invoking accessors", () => {
    const property = [...VALID];
    Object.defineProperty(property, "hidden", { value: "ignored" });
    expect(() => parseCiRetentionCliOptions(property)).toThrow();

    const accessor = [...VALID];
    Object.defineProperty(accessor, "0", {
      configurable: true,
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    expect(() => parseCiRetentionCliOptions(accessor)).toThrowError(
      expect.not.objectContaining({ message: "accessed" }),
    );
    expect(() => parseCiRetentionCliOptions(new Proxy(VALID, {}))).toThrow();
  });
});
