import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createFoundationStageAReadinessConclusion,
  decodeFoundationStageAReadinessConclusion,
  encodeFoundationStageAReadinessConclusion,
  foundationStageAReadinessConclusionSha256,
  parseFoundationStageAReadinessConclusion,
  verifyFoundationBuiltReadinessConclusion,
  type FoundationStageAReadinessAssessmentV1,
  type FoundationStageAReadinessBindingsV1,
} from "../src/readiness-conclusion.js";

const ARCHIVE_SHA256 = "a".repeat(64);
const CI_EVIDENCE_SHA256 = "b".repeat(64);
const COMMIT_SHA = "d3f1e81183cc13fe51ea85ad21bcc71d31866dee";
const MANIFEST_SHA256 = "c".repeat(64);
const SIGNER_FINGERPRINT_SHA256 = "d".repeat(64);
const SIGNER_KEY_ID = `rsi-release-${SIGNER_FINGERPRINT_SHA256.slice(0, 16)}`;

describe("Foundation Stage A readiness conclusion", () => {
  it("derives FOUNDATION_BUILT only when every mandatory check passed", () => {
    const conclusion = createFoundationStageAReadinessConclusion(assessment());

    expect(conclusion).toMatchObject({
      archiveSha256: ARCHIVE_SHA256,
      ciEvidenceSha256: CI_EVIDENCE_SHA256,
      commitSha: COMMIT_SHA,
      conclusionType: "rsi.foundation-stage-a-readiness-conclusion",
      manifestSha256: MANIFEST_SHA256,
      objectiveEvidenceState: "FOUNDATION_BUILT",
      outcome: "passed",
      releaseVersion: "0.1.0-foundation.1",
      signerFingerprintSha256: SIGNER_FINGERPRINT_SHA256,
      signerKeyId: SIGNER_KEY_ID,
      version: 1,
    });
    expect(Object.isFrozen(conclusion)).toBe(true);
    expect(Object.isFrozen(conclusion.checks)).toBe(true);

    const canonical = encodeFoundationStageAReadinessConclusion(conclusion);
    expect(canonical.endsWith("\n")).toBe(false);
    expect(decodeFoundationStageAReadinessConclusion(canonical)).toEqual(conclusion);
    expect(decodeFoundationStageAReadinessConclusion(Buffer.from(canonical, "utf8"))).toEqual(
      conclusion,
    );
    expect(foundationStageAReadinessConclusionSha256(conclusion)).toBe(
      createHash("sha256").update(canonical).digest("hex"),
    );
  });

  it("derives a truthful failed conclusion when any mandatory check failed", () => {
    const input = assessment();
    const conclusion = createFoundationStageAReadinessConclusion({
      ...input,
      checks: [
        input.checks[0],
        { name: "retained-ci-evidence-verified", outcome: "failed" },
        input.checks[2],
        input.checks[3],
        input.checks[4],
      ],
    });

    expect(conclusion.outcome).toBe("failed");
    expect(conclusion.objectiveEvidenceState).toBe("FOUNDATION_NOT_BUILT");
    expect(() => verifyFoundationBuiltReadinessConclusion(conclusion, bindings())).toThrow(
      /has not reached FOUNDATION_BUILT/u,
    );
  });

  it("rejects contradictory success and failure claims", () => {
    const passed = createFoundationStageAReadinessConclusion(assessment());
    const failedCheck = passed.checks.map((check, index) =>
      index === 0 ? { ...check, outcome: "failed" as const } : check,
    );
    expect(() =>
      parseFoundationStageAReadinessConclusion({ ...passed, checks: failedCheck }),
    ).toThrow(/contradicts its checks/u);
    expect(() =>
      parseFoundationStageAReadinessConclusion({
        ...passed,
        objectiveEvidenceState: "FOUNDATION_NOT_BUILT",
        outcome: "failed",
      }),
    ).toThrow(/contradicts its checks/u);
  });

  it("requires the fixed complete check order and rejects unknown fields", () => {
    const passed = createFoundationStageAReadinessConclusion(assessment());
    expect(() =>
      parseFoundationStageAReadinessConclusion({
        ...passed,
        checks: [
          passed.checks[1],
          passed.checks[0],
          passed.checks[2],
          passed.checks[3],
          passed.checks[4],
        ],
      }),
    ).toThrow(/invalid or out of order/u);
    expect(() => parseFoundationStageAReadinessConclusion({ ...passed, surprise: true })).toThrow(
      /unsupported fields/u,
    );
    expect(() =>
      createFoundationStageAReadinessConclusion({
        ...assessment(),
        signerKeyId: "rsi-release-wrong",
      }),
    ).toThrow(/does not match its fingerprint/u);
  });

  it("accepts only byte-for-byte canonical JSON", () => {
    const conclusion = createFoundationStageAReadinessConclusion(assessment());
    const canonical = encodeFoundationStageAReadinessConclusion(conclusion);

    expect(() => decodeFoundationStageAReadinessConclusion(`${canonical}\n`)).toThrow(
      /not canonical JSON/u,
    );
    expect(() =>
      decodeFoundationStageAReadinessConclusion(JSON.stringify(conclusion, null, 2)),
    ).toThrow(/not canonical JSON/u);
    expect(() => decodeFoundationStageAReadinessConclusion(new Uint8Array([0xc3, 0x28]))).toThrow(
      /not valid UTF-8/u,
    );
    expect(() => decodeFoundationStageAReadinessConclusion("{".repeat(16_385))).toThrow(
      /size is invalid/u,
    );
  });

  it("requires exact passed bindings before signed-tag creation", () => {
    const conclusion = createFoundationStageAReadinessConclusion(assessment());

    expect(verifyFoundationBuiltReadinessConclusion(conclusion, bindings())).toEqual(conclusion);
    expect(() =>
      verifyFoundationBuiltReadinessConclusion(conclusion, {
        ...bindings(),
        ciEvidenceSha256: "e".repeat(64),
      }),
    ).toThrow(/ciEvidenceSha256 binding is invalid/u);
  });
});

function assessment(): FoundationStageAReadinessAssessmentV1 {
  return {
    ...bindings(),
    checks: [
      { name: "release-bundle-verified", outcome: "passed" },
      { name: "retained-ci-evidence-verified", outcome: "passed" },
      { name: "commit-bindings-verified", outcome: "passed" },
      { name: "signing-identity-pinned-and-matched", outcome: "passed" },
      { name: "independent-adversarial-review-passed", outcome: "passed" },
    ],
  };
}

function bindings(): FoundationStageAReadinessBindingsV1 {
  return {
    archiveSha256: ARCHIVE_SHA256,
    artifactSetSha256: "1".repeat(64),
    ciEvidenceSha256: CI_EVIDENCE_SHA256,
    commitSha: COMMIT_SHA,
    configSetSha256: "2".repeat(64),
    gitTreeSha: "e".repeat(40),
    helperCompatibilityEvidenceSha256: "b".repeat(64),
    helperCompatibilityTestedCommitSha: "c".repeat(40),
    identitySha256: "3".repeat(64),
    independentReviewEvidenceSha256: "f".repeat(64),
    lockfileSha256: "4".repeat(64),
    manifestSha256: MANIFEST_SHA256,
    platformIdentitySha256: "a".repeat(64),
    provisioningReceiptSha256: "5".repeat(64),
    recoverySetSha256: "6".repeat(64),
    runbookSetSha256: "7".repeat(64),
    sbomSha256: "8".repeat(64),
    signerFingerprintSha256: SIGNER_FINGERPRINT_SHA256,
    signerKeyId: SIGNER_KEY_ID,
    sourceTreeSha256: "9".repeat(64),
    testSummarySha256: "0".repeat(64),
  };
}
