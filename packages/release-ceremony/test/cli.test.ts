import { describe, expect, it } from "vitest";

import { parseCliOptions } from "../src/cli.js";
import { FOUNDATION_RELEASE_VERSION } from "../src/types.js";
import { COMMIT } from "./helpers.js";

const valid = [
  "--ci-evidence",
  "/private/tmp/evidence.json",
  "--review-evidence",
  "/private/tmp/foundation.review-evidence.json",
  "--output",
  "/private/tmp/foundation.rsi-release",
  "--receipt",
  "/private/tmp/foundation.receipt.json",
  "--conclusion",
  "/private/tmp/foundation.readiness-conclusion.json",
  "--tag-object",
  "/private/tmp/foundation.foundation-tag",
  "--report",
  "/private/tmp/foundation.ceremony-report.json",
  "--confirm-commit",
  COMMIT,
  "--confirm-release",
  FOUNDATION_RELEASE_VERSION,
];

describe("foundation ceremony CLI v2", () => {
  it("parses the complete closed ceremony argument set", () => {
    expect(parseCliOptions(valid)).toEqual({
      ciEvidencePath: "/private/tmp/evidence.json",
      conclusionPath: "/private/tmp/foundation.readiness-conclusion.json",
      confirmCommit: COMMIT,
      confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
      destinationPath: "/private/tmp/foundation.rsi-release",
      receiptPath: "/private/tmp/foundation.receipt.json",
      reportPath: "/private/tmp/foundation.ceremony-report.json",
      reviewEvidencePath: "/private/tmp/foundation.review-evidence.json",
      tagObjectPath: "/private/tmp/foundation.foundation-tag",
    });
  });

  it("accepts the package-runner separator without changing the result", () => {
    expect(parseCliOptions(["--", ...valid])).toEqual(parseCliOptions(valid));
  });

  it.each([
    ["private key", ["--private-key", "/tmp/key"]],
    ["keychain selector", ["--keychain-service", "other"]],
    ["signer command", ["--signer-command", "/tmp/helper"]],
    ["publication flag", ["--publish-tag", "true"]],
    ["duplicate", ["--output", "/tmp/again.rsi-release"]],
    ["wrong release", ["--confirm-release", "0.1.0"]],
  ])("rejects a %s argument", (_label, addition) => {
    expect(() => parseCliOptions([...valid, ...addition])).toThrow();
  });

  it.each([
    "--ci-evidence",
    "--review-evidence",
    "--output",
    "--receipt",
    "--conclusion",
    "--tag-object",
    "--report",
    "--confirm-commit",
    "--confirm-release",
  ])("requires %s", (flag) => {
    const index = valid.indexOf(flag);
    expect(index).toBeGreaterThanOrEqual(0);
    expect(() => parseCliOptions([...valid.slice(0, index), ...valid.slice(index + 2)])).toThrow();
  });

  it("supports help without requiring or inspecting ceremony state", () => {
    expect(parseCliOptions(["--help"])).toBe("help");
    expect(parseCliOptions(["-h"])).toBe("help");
  });
});
