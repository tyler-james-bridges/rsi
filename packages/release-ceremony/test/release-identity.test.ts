import { createHash, generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { parseFoundationPinnedReleaseIdentity } from "../src/release-identity.js";

const COMMIT = "a".repeat(40);
const PROVISIONING_COMMIT = "9".repeat(40);
const TESTED_COMMIT = "8".repeat(40);
const HASHES = ["b", "c", "d", "e", "f", "1", "2", "3", "4", "5"].map((value) => value.repeat(64));

describe("pinned foundation release identity", () => {
  it("binds canonical SPKI, helper, repository, provisioning, and two recovery copies", () => {
    const fixture = makePinnedFixture();
    const parsed = parseFoundationPinnedReleaseIdentity(
      fixture.identityBytes,
      fixture.receiptBytes,
      fixture.compatibilityBytes,
      COMMIT,
    );
    expect(parsed).toMatchObject({
      identitySha256: createHash("sha256").update(fixture.identityBytes).digest("hex"),
      keyId: fixture.identity.keyId,
      provisioningReceiptSha256: createHash("sha256").update(fixture.receiptBytes).digest("hex"),
      pinningRepositoryCommitSha: COMMIT,
      provisioningRepositoryCommitSha: PROVISIONING_COMMIT,
      signerFingerprintSha256: fixture.identity.signerFingerprintSha256,
    });
    expect(parsed.publicKeySpkiDer).toEqual(
      Uint8Array.from(Buffer.from(fixture.identity.publicKeySpkiDerBase64url, "base64url")),
    );
  });

  it("rejects noncanonical bytes and every critical cross-binding mismatch", () => {
    const fixture = makePinnedFixture();
    expect(() =>
      parseFoundationPinnedReleaseIdentity(
        Buffer.from(`${fixture.identityBytes.toString("utf8")}\n`),
        fixture.receiptBytes,
        fixture.compatibilityBytes,
        COMMIT,
      ),
    ).toThrow(/canonical/u);
    expect(() =>
      parseFoundationPinnedReleaseIdentity(
        fixture.identityBytes,
        Buffer.from(canonicalJson({ ...fixture.receipt, repositoryCommitSha: "not-a-commit" })),
        fixture.compatibilityBytes,
        COMMIT,
      ),
    ).toThrow(/repository commit/u);
    expect(() =>
      parseFoundationPinnedReleaseIdentity(
        fixture.identityBytes,
        Buffer.from(
          canonicalJson({
            ...fixture.receipt,
            recoveryCopies: [fixture.receipt.recoveryCopies[0], fixture.receipt.recoveryCopies[0]],
          }),
        ),
        fixture.compatibilityBytes,
        COMMIT,
      ),
    ).toThrow();
  });
});

function makePinnedFixture() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const fingerprint = createHash("sha256").update(spki).digest("hex");
  const compatibility = makeCompatibilityEvidence();
  const compatibilityBytes = Buffer.from(canonicalJson(compatibility));
  const identity = {
    account: "release-ed25519-v1",
    algorithm: "Ed25519",
    candidateType: "rsi.release-public-identity-candidate",
    createdAt: "2026-08-23T06:00:00.000Z",
    helperBinarySha256: HASHES[0]!,
    helperCompatibilityEvidenceSha256: createHash("sha256")
      .update(compatibilityBytes)
      .digest("hex"),
    helperCompatibilityTestedCommitSha: TESTED_COMMIT,
    helperCompilerIdentitySha256: HASHES[1]!,
    helperSourceSha256: HASHES[2]!,
    keyId: `rsi-release-${fingerprint.slice(0, 16)}`,
    keychainProtection: "data-protection-when-unlocked-this-device-only-user-presence",
    platformIdentitySha256: HASHES[3]!,
    publicKeySpkiDerBase64url: spki.toString("base64url"),
    service: "dev.rsi.macbook.release-signing",
    signerFingerprintSha256: fingerprint,
    version: 1,
  } as const;
  const identityBytes = Buffer.from(canonicalJson(identity));
  const receipt = {
    account: identity.account,
    copyCount: 2,
    createdAt: identity.createdAt,
    helperBinarySha256: identity.helperBinarySha256,
    helperCompatibilityEvidenceSha256: identity.helperCompatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: identity.helperCompatibilityTestedCommitSha,
    helperCompilerIdentitySha256: identity.helperCompilerIdentitySha256,
    helperSourceSha256: identity.helperSourceSha256,
    keyId: identity.keyId,
    keychainProtection: identity.keychainProtection,
    keychainStatus: "identity-verified",
    platformIdentitySha256: identity.platformIdentitySha256,
    provisioningIntentSha256: HASHES[4]!,
    publicIdentitySha256: createHash("sha256").update(identityBytes).digest("hex"),
    recoveryCopies: [
      {
        copyIndex: 1,
        envelopeSha256: HASHES[5]!,
        physicalStoreIdentitySha256: HASHES[6]!,
        restoredAt: "2026-08-23T06:05:00.000Z",
        restoreStatus: "restore-verified",
        volumeIdentitySha256: HASHES[7]!,
      },
      {
        copyIndex: 2,
        envelopeSha256: HASHES[8]!,
        physicalStoreIdentitySha256: HASHES[9]!,
        restoredAt: "2026-08-23T06:10:00.000Z",
        restoreStatus: "restore-verified",
        volumeIdentitySha256: "6".repeat(64),
      },
    ],
    receiptType: "rsi.release-key-provisioning-receipt",
    repositoryCommitSha: PROVISIONING_COMMIT,
    service: identity.service,
    signerFingerprintSha256: fingerprint,
    status: "verified-keychain-and-two-recovery-copies",
    version: 1,
  } as const;
  return {
    compatibilityBytes,
    identity,
    identityBytes,
    receipt,
    receiptBytes: Buffer.from(canonicalJson(receipt)),
  };
}

function makeCompatibilityEvidence() {
  return {
    cleanup: {
      evidenceSha256: "7".repeat(64),
      keychainItem: "deleted-and-absence-verified",
      outcome: "passed",
      temporaryArtifacts: "removed-and-absence-verified",
      testPrivateMaterial: "destroyed-and-absence-verified",
    },
    completedAt: "2026-08-22T22:00:00.000Z",
    drillId: "throwaway-macbook-helper-drill",
    drillOperatorId: "physical-drill-operator",
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
      binarySha256: HASHES[0]!,
      compilerIdentitySha256: HASHES[1]!,
      sourceSha256: HASHES[2]!,
    },
    helperPath: "packages/release-key-provisioning/native/keychain-helper.swift",
    independentApproval: {
      approvedAt: "2026-08-22T23:00:00.000Z",
      approvalEvidenceSha256: "6".repeat(64),
      authorship: "did-not-author-tested-helper-or-evidence",
      drillParticipation: "did-not-operate-drill",
      reviewerId: "independent-helper-reviewer",
      reviewerRole: "independent-non-authoring-reviewer",
      verdict: "approved",
    },
    keychainControls: {
      accessibility: "when-unlocked-this-device-only",
      dataProtectionKeychain: "verified",
      evidenceSha256: "5".repeat(64),
      persistentApproval: "not-granted",
      synchronizable: "disabled",
      unauthorizedAlternateClientAccess: "refused",
      userPresence: "required",
    },
    privateMaterialLeakScan: {
      evidenceSha256: "4".repeat(64),
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
        evidenceSha256: "3".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "first-fresh-helper-invocation",
        signatureVerification: "passed",
      },
      {
        attempt: 2,
        evidenceSha256: "2".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "second-fresh-helper-invocation-after-first-completed",
        signatureVerification: "passed",
      },
    ],
    repository: "tyler-james-bridges/rsi",
    repositoryVisibility: "public",
    testedCommitSha: TESTED_COMMIT,
    verdict: "passed",
    version: 1,
  } as const;
}
