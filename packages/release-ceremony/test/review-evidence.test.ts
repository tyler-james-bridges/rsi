import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import {
  decodeFoundationIndependentReviewEvidence,
  encodeFoundationIndependentReviewEvidence,
  foundationIndependentReviewEvidenceSha256,
  parseFoundationIndependentReviewEvidence,
  type FoundationIndependentReviewEvidenceV1,
} from "../src/review-evidence.js";

const evidence = (): FoundationIndependentReviewEvidenceV1 => ({
  commitSha: "a".repeat(40),
  evidenceType: "rsi.foundation-independent-review-evidence",
  findings: [
    {
      findingId: "review-001",
      findingSha256: "b".repeat(64),
      resolutionSha256: "c".repeat(64),
      severity: "high",
      status: "resolved",
    },
  ],
  gitTreeSha: "d".repeat(40),
  releaseVersion: "0.1.0-foundation.1",
  repository: "tyler-james-bridges/rsi",
  reviewedAt: "2026-08-23T08:00:00.000Z",
  reviewerId: "codex-independent-review-1",
  reviewerRole: "independent-non-authoring-agent",
  scopes: [
    { name: "repository-diff", outcome: "passed" },
    { name: "release-key-provisioning", outcome: "passed" },
    { name: "release-ceremony-and-tag", outcome: "passed" },
    { name: "failure-and-recovery-controls", outcome: "passed" },
    { name: "tests-and-documentation", outcome: "passed" },
  ],
  verdict: "approved",
  version: 1,
});

describe("foundation independent-review evidence", () => {
  it("accepts and hashes only the canonical exact-commit approval record", () => {
    const value = evidence();
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    expect(decodeFoundationIndependentReviewEvidence(bytes)).toEqual(value);
    expect(Buffer.from(encodeFoundationIndependentReviewEvidence(value))).toEqual(bytes);
    expect(foundationIndependentReviewEvidenceSha256(value)).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  it("rejects noncanonical, incomplete, failed, duplicate, or unresolved evidence", () => {
    const value = evidence();
    expect(() =>
      decodeFoundationIndependentReviewEvidence(Buffer.from(`${canonicalJson(value)}\n`)),
    ).toThrow(/canonical/u);
    expect(() =>
      parseFoundationIndependentReviewEvidence({
        ...value,
        scopes: value.scopes.slice(0, -1),
      }),
    ).toThrow(/incomplete/u);
    expect(() =>
      parseFoundationIndependentReviewEvidence({
        ...value,
        scopes: value.scopes.map((scope, index) =>
          index === 0 ? { ...scope, outcome: "failed" } : scope,
        ),
      }),
    ).toThrow(/did not pass/u);
    expect(() =>
      parseFoundationIndependentReviewEvidence({
        ...value,
        findings: [value.findings[0], value.findings[0]],
      }),
    ).toThrow(/unresolved or invalid/u);
    expect(() =>
      parseFoundationIndependentReviewEvidence({
        ...value,
        findings: [{ ...value.findings[0], status: "open" }],
      }),
    ).toThrow(/unresolved or invalid/u);
  });
});
