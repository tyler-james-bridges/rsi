import { describe, expect, it } from "vitest";

import { FOUNDATION_RELEASE_VERSION } from "../src/types.js";
import { parseCliOptions } from "../src/cli.js";
import { COMMIT } from "./helpers.js";

const valid = [
  "--ci-evidence",
  "/private/tmp/evidence.json",
  "--output",
  "/private/tmp/foundation.rsi-release",
  "--receipt",
  "/private/tmp/foundation.receipt.json",
  "--confirm-commit",
  COMMIT,
  "--confirm-release",
  FOUNDATION_RELEASE_VERSION,
];

describe("foundation ceremony CLI", () => {
  it("parses only the closed ceremony arguments", () => {
    expect(parseCliOptions(valid)).toEqual({
      ciEvidencePath: "/private/tmp/evidence.json",
      confirmCommit: COMMIT,
      confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
      destinationPath: "/private/tmp/foundation.rsi-release",
      receiptPath: "/private/tmp/foundation.receipt.json",
    });
  });

  it.each([
    ["private key", ["--private-key", "/tmp/key"]],
    ["keychain selector", ["--keychain-service", "other"]],
    ["signer command", ["--signer-command", "/tmp/helper"]],
    ["duplicate", ["--output", "/tmp/again.rsi-release"]],
    ["wrong release", ["--confirm-release", "0.1.0"]],
  ])("rejects a %s argument", (_label, addition) => {
    expect(() => parseCliOptions([...valid, ...addition])).toThrow();
  });

  it("rejects missing arguments and supports help without state access", () => {
    expect(() => parseCliOptions(valid.slice(0, -2))).toThrow();
    expect(parseCliOptions(["--help"])).toBe("help");
  });
});
