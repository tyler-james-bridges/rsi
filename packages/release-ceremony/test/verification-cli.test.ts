import { describe, expect, it } from "vitest";

import { parseFoundationVerificationCliOptions } from "../src/verification-cli.js";
import { FOUNDATION_RELEASE_VERSION } from "../src/types.js";
import { COMMIT } from "./helpers.js";

const VALID = [
  "--bundle",
  "/private/tmp/foundation.rsi-release",
  "--receipt",
  "/private/tmp/foundation.receipt.json",
  "--conclusion",
  "/private/tmp/foundation.readiness-conclusion.json",
  "--tag-object",
  "/private/tmp/foundation.foundation-tag",
  "--report",
  "/private/tmp/foundation.ceremony-report.json",
  "--ci-evidence",
  "/private/tmp/foundation-ci.json",
  "--review-evidence",
  "/private/tmp/foundation.review-evidence.json",
  "--confirm-commit",
  COMMIT,
  "--confirm-release",
  FOUNDATION_RELEASE_VERSION,
];

describe("foundation ceremony verification CLI", () => {
  it("accepts only the complete absolute read-only verification set", () => {
    expect(parseFoundationVerificationCliOptions(VALID)).toEqual({
      archivePath: "/private/tmp/foundation.rsi-release",
      ciEvidencePath: "/private/tmp/foundation-ci.json",
      conclusionPath: "/private/tmp/foundation.readiness-conclusion.json",
      confirmCommit: COMMIT,
      confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
      receiptPath: "/private/tmp/foundation.receipt.json",
      reportPath: "/private/tmp/foundation.ceremony-report.json",
      reviewEvidencePath: "/private/tmp/foundation.review-evidence.json",
      tagObjectPath: "/private/tmp/foundation.foundation-tag",
    });
    expect(parseFoundationVerificationCliOptions(["--", ...VALID])).toEqual(
      parseFoundationVerificationCliOptions(VALID),
    );
  });

  it("supports help without requiring or reading ceremony outputs", () => {
    expect(parseFoundationVerificationCliOptions(["--help"])).toBe("help");
    expect(parseFoundationVerificationCliOptions(["-h"])).toBe("help");
    expect(parseFoundationVerificationCliOptions(["--", "--help"])).toBe("help");
  });

  it.each([
    ["relative path", replaceValue("--bundle", "foundation.rsi-release")],
    ["noncanonical path", replaceValue("--bundle", "/private/tmp/../tmp/foundation.rsi-release")],
    ["duplicate path", replaceValue("--receipt", "/private/tmp/foundation.rsi-release")],
    ["wrong release", replaceValue("--confirm-release", "0.1.0")],
    ["short commit", replaceValue("--confirm-commit", "a".repeat(39))],
    ["missing argument", VALID.slice(0, -2)],
    ["signing option", [...VALID.slice(0, -2), "--private-key", "/tmp/key"]],
    ["publication option", [...VALID.slice(0, -2), "--publish-tag", "true"]],
  ])("rejects %s", (_label, args) => {
    expect(() => parseFoundationVerificationCliOptions(args)).toThrow();
  });

  it("rejects hostile argument containers without invoking accessors", () => {
    const property = [...VALID];
    Object.defineProperty(property, "hidden", { value: "ignored" });
    expect(() => parseFoundationVerificationCliOptions(property)).toThrow();

    const accessor = [...VALID];
    Object.defineProperty(accessor, "0", {
      configurable: true,
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    expect(() => parseFoundationVerificationCliOptions(accessor)).toThrowError(
      expect.not.objectContaining({ message: "accessed" }),
    );
    expect(() => parseFoundationVerificationCliOptions(new Proxy(VALID, {}))).toThrow();
  });
});

function replaceValue(flag: string, value: string): string[] {
  const args = [...VALID];
  const index = args.indexOf(flag);
  args[index + 1] = value;
  return args;
}
