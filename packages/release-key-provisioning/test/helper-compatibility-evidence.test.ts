import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import {
  assertReleaseKeyHelperCompatibilityRepositoryBindings,
  assertReleaseKeyHelperCompatibilityRuntimeBindings,
  decodeReleaseKeyHelperCompatibilityEvidence,
  parseReleaseKeyHelperCompatibilityEvidence,
  releaseKeyHelperCompatibilityEvidenceSha256,
  type ReleaseKeyHelperCompatibilityEvidenceV1,
} from "../src/helper-compatibility-evidence.js";

const evidence = (): ReleaseKeyHelperCompatibilityEvidenceV1 => ({
  cleanup: {
    evidenceSha256: "a".repeat(64),
    keychainItem: "deleted-and-absence-verified",
    outcome: "passed",
    temporaryArtifacts: "removed-and-absence-verified",
    testPrivateMaterial: "destroyed-and-absence-verified",
  },
  completedAt: "2026-08-23T09:00:00.000Z",
  drillId: "throwaway-macbook-helper-2026-08-23",
  drillOperatorId: "drill-operator-1",
  environment: {
    architecture: "arm64",
    hardwareClass: "MacBook",
    macosBuildVersion: "25A354",
    macosProductVersion: "26.0",
    nodeVersion: "v24.19.0",
    pnpmVersion: "11.20.0",
  },
  evidencePath: "config/foundation-release-key-helper-compatibility.v1.json",
  evidenceType: "rsi.release-key-helper-compatibility-evidence",
  helper: {
    binarySha256: "b".repeat(64),
    compilerIdentitySha256: "c".repeat(64),
    sourceSha256: "d".repeat(64),
  },
  helperPath: "packages/release-key-provisioning/native/keychain-helper.swift",
  independentApproval: {
    approvedAt: "2026-08-23T10:00:00.000Z",
    approvalEvidenceSha256: "e".repeat(64),
    authorship: "did-not-author-tested-helper-or-evidence",
    drillParticipation: "did-not-operate-drill",
    reviewerId: "independent-reviewer-1",
    reviewerRole: "independent-non-authoring-reviewer",
    verdict: "approved",
  },
  keychainControls: {
    accessibility: "when-unlocked-this-device-only",
    dataProtectionKeychain: "verified",
    evidenceSha256: "f".repeat(64),
    persistentApproval: "not-granted",
    synchronizable: "disabled",
    unauthorizedAlternateClientAccess: "refused",
    userPresence: "required",
  },
  privateMaterialLeakScan: {
    evidenceSha256: "1".repeat(64),
    outcome: "passed",
    scopes: [
      { name: "process-arguments", outcome: "passed" },
      { name: "process-environment", outcome: "passed" },
      { name: "standard-output", outcome: "passed" },
      { name: "standard-error", outcome: "passed" },
      { name: "logs-and-diagnostics", outcome: "passed" },
      { name: "filesystem-artifacts", outcome: "passed" },
    ],
  },
  prompts: [
    {
      attempt: 1,
      evidenceSha256: "2".repeat(64),
      freshHelperProcess: "verified",
      outcome: "user-presence-prompt-observed-and-approved-once",
      scenario: "first-fresh-helper-invocation",
      signatureVerification: "passed",
    },
    {
      attempt: 2,
      evidenceSha256: "3".repeat(64),
      freshHelperProcess: "verified",
      outcome: "user-presence-prompt-observed-and-approved-once",
      scenario: "second-fresh-helper-invocation-after-first-completed",
      signatureVerification: "passed",
    },
  ],
  repository: "tyler-james-bridges/rsi",
  repositoryVisibility: "public",
  testedCommitSha: "4".repeat(40),
  verdict: "passed",
  version: 1,
});

describe("release-key helper compatibility evidence", () => {
  it("accepts and hashes the exact canonical public drill record", () => {
    const value = evidence();
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    expect(decodeReleaseKeyHelperCompatibilityEvidence(bytes)).toEqual(value);
    expect(releaseKeyHelperCompatibilityEvidenceSha256(value)).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  it("accepts only an ancestor commit with unchanged current helper source", () => {
    const value = evidence();
    expect(() =>
      assertReleaseKeyHelperCompatibilityRepositoryBindings(value, {
        currentHelperSourceSha256: value.helper.sourceSha256,
        testedCommitIsAncestorOfCurrentCommit: true,
        testedHelperSourceSha256: value.helper.sourceSha256,
      }),
    ).not.toThrow();

    for (const bindings of [
      {
        currentHelperSourceSha256: value.helper.sourceSha256,
        testedCommitIsAncestorOfCurrentCommit: false,
        testedHelperSourceSha256: value.helper.sourceSha256,
      },
      {
        currentHelperSourceSha256: "9".repeat(64),
        testedCommitIsAncestorOfCurrentCommit: true,
        testedHelperSourceSha256: value.helper.sourceSha256,
      },
      {
        currentHelperSourceSha256: value.helper.sourceSha256,
        testedCommitIsAncestorOfCurrentCommit: true,
        testedHelperSourceSha256: "9".repeat(64),
      },
    ]) {
      expect(() => assertReleaseKeyHelperCompatibilityRepositoryBindings(value, bindings)).toThrow(
        /not descended/u,
      );
    }
  });

  it("requires the actual helper and exact runtime build used by the drill", () => {
    const value = evidence();
    const bindings = {
      architecture: "arm64" as const,
      helper: value.helper,
      macosBuildVersion: "25A354",
      macosProductVersion: "26.0",
      nodeVersion: "v24.19.0",
      pnpmVersion: "11.20.0",
    };
    expect(() => assertReleaseKeyHelperCompatibilityRuntimeBindings(value, bindings)).not.toThrow();

    for (const changed of [
      { ...bindings, helper: { ...bindings.helper, binarySha256: "9".repeat(64) } },
      { ...bindings, helper: { ...bindings.helper, compilerIdentitySha256: "9".repeat(64) } },
      { ...bindings, helper: { ...bindings.helper, sourceSha256: "9".repeat(64) } },
      { ...bindings, architecture: "x64" as const },
      { ...bindings, macosBuildVersion: "25A355" },
      { ...bindings, macosProductVersion: "26.0.1" },
      { ...bindings, nodeVersion: "v24.19.1" },
      { ...bindings, pnpmVersion: "11.20.1" },
    ]) {
      expect(() => assertReleaseKeyHelperCompatibilityRuntimeBindings(value, changed)).toThrow(
        /does not match/u,
      );
    }
  });

  it("rejects noncanonical, incomplete, failed, or non-independent evidence", () => {
    const value = evidence();
    expect(() =>
      decodeReleaseKeyHelperCompatibilityEvidence(Buffer.from(`${canonicalJson(value)}\n`)),
    ).toThrow(/canonical/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        prompts: [value.prompts[0]],
      }),
    ).toThrow(/Exactly two/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        prompts: [value.prompts[0], { ...value.prompts[1], evidenceSha256: "2".repeat(64) }],
      }),
    ).toThrow(/not distinct/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        keychainControls: { ...value.keychainControls, persistentApproval: "granted" },
      }),
    ).toThrow(/did not pass/u);
    for (const keychainControls of [
      { ...value.keychainControls, dataProtectionKeychain: "not-verified" },
      { ...value.keychainControls, accessibility: "after-first-unlock" },
      { ...value.keychainControls, synchronizable: "enabled" },
      { ...value.keychainControls, unauthorizedAlternateClientAccess: "allowed" },
      { ...value.keychainControls, userPresence: "optional" },
    ]) {
      expect(() =>
        parseReleaseKeyHelperCompatibilityEvidence({ ...value, keychainControls }),
      ).toThrow(/did not pass/u);
    }
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        privateMaterialLeakScan: {
          ...value.privateMaterialLeakScan,
          scopes: value.privateMaterialLeakScan.scopes.slice(0, -1),
        },
      }),
    ).toThrow(/incomplete/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        cleanup: { ...value.cleanup, outcome: "failed" },
      }),
    ).toThrow(/did not pass/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        independentApproval: {
          ...value.independentApproval,
          reviewerId: value.drillOperatorId,
        },
      }),
    ).toThrow(/not independent/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        independentApproval: {
          ...value.independentApproval,
          authorship: "authored-helper",
        },
      }),
    ).toThrow(/approval is invalid/u);
  });

  it("rejects unsupported fields before trusting a passing verdict", () => {
    const value = evidence();
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({ ...value, notes: "trust me" }),
    ).toThrow(/unsupported fields/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({
        ...value,
        environment: { ...value.environment, nodeVersion: "v26.0.0" },
      }),
    ).toThrow(/approved exact build/u);
    expect(() =>
      parseReleaseKeyHelperCompatibilityEvidence({ ...value, verdict: "failed" }),
    ).toThrow(/verdict is invalid/u);
  });
});
