import { describe, expect, it } from "vitest";

import { FoundationCeremonyError } from "../src/errors.js";
import { classifyFoundationTrackedPath } from "../src/inventory.js";

describe("foundation release inventory classification", () => {
  it.each([
    [
      "config/foundation-independent-reviewer-identity.v1.json",
      "source/config/foundation-independent-reviewer-identity.v1.json",
    ],
    [
      "config/foundation-release-identity.v1.json",
      "source/config/foundation-release-identity.v1.json",
    ],
    [
      "config/foundation-release-key-helper-compatibility.v1.json",
      "source/config/foundation-release-key-helper-compatibility.v1.json",
    ],
    [
      "config/foundation-release-key-provisioning-receipt.v1.json",
      "source/config/foundation-release-key-provisioning-receipt.v1.json",
    ],
  ] as const)("classifies the exact public record %s", (trackedPath, releasePath) => {
    expect(classifyFoundationTrackedPath(trackedPath)).toEqual([releasePath, "source"]);
  });

  it("does not broaden the allowlist to arbitrary config files", () => {
    expect(() => classifyFoundationTrackedPath("config/unreviewed.json")).toThrowError(
      FoundationCeremonyError,
    );
  });
});
