import { createHash, generateKeyPairSync, sign } from "node:crypto";

import {
  REQUIRED_CONFIG_SCHEMA_NAMES,
  REQUIRED_TEST_CHECKS,
  deriveReleaseArtifactBindings,
  type ReleaseArtifactInputV1,
  type ReleaseBundleSignerV1,
} from "@rsi/release-bundle";

import { canonicalJson } from "../src/canonical.js";
import {
  FOUNDATION_REVIEW_EVIDENCE_TYPE,
  FOUNDATION_REVIEW_SCOPE_NAMES,
  type FoundationIndependentReviewEvidenceV1,
} from "../src/review-evidence.js";
import {
  FOUNDATION_CI_EVIDENCE_TYPE,
  FOUNDATION_RELEASE_VERSION,
  type FoundationCeremonyCustody,
  type FoundationCeremonySignersV1,
  type FoundationCiEvidenceV1,
  type FoundationReleaseInventory,
} from "../src/types.js";
import type { FoundationPinnedReleaseIdentityV1 } from "../src/release-identity.js";

export const COMMIT = "a".repeat(40);
export const PROVISIONING_COMMIT = "9".repeat(40);
export const HELPER_TESTED_COMMIT = "8".repeat(40);
export const TREE = "b".repeat(40);
export const CI_COMPLETED_AT = "2026-08-18T00:00:00.000Z";
export const CEREMONY_AT = "2026-08-18T01:00:00.000Z";
export const REVIEWED_AT = "2026-08-18T00:30:00.000Z";
export const PLATFORM_IDENTITY_SHA256 = "7".repeat(64);
const encoder = new TextEncoder();

export function makeCiEvidence(
  overrides: Partial<FoundationCiEvidenceV1> = {},
): FoundationCiEvidenceV1 {
  return {
    branch: "main",
    commitSha: COMMIT,
    completedAt: CI_COMPLETED_AT,
    evidenceType: FOUNDATION_CI_EVIDENCE_TYPE,
    event: "push",
    jobs: [
      { conclusion: "success", name: "gitleaks-history" },
      { conclusion: "success", name: "quality" },
    ],
    repository: "tyler-james-bridges/rsi",
    requiredChecks: REQUIRED_TEST_CHECKS.map((name) => ({ name, outcome: "passed" })),
    runId: "32034831276",
    runUrl: "https://github.com/tyler-james-bridges/rsi/actions/runs/32034831276",
    version: 1,
    workflow: "ci",
    ...overrides,
  } as FoundationCiEvidenceV1;
}

export function makeInventory(createdAt = CEREMONY_AT): FoundationReleaseInventory {
  const artifacts = makeArtifacts(createdAt);
  const bindings = deriveReleaseArtifactBindings(artifacts);
  return Object.freeze({
    artifacts,
    release: Object.freeze({
      ...bindings,
      commitSha: COMMIT,
      createdAt,
      gitTreeSha: TREE,
      nodeVersion: "24.19.0",
      pnpmVersion: "11.20.0",
      predecessorManifestSha256: null,
      releaseVersion: FOUNDATION_RELEASE_VERSION,
    }),
    report: Object.freeze({
      ...bindings,
      artifactCount: artifacts.length,
      commitSha: COMMIT,
      gitTreeSha: TREE,
      releaseVersion: FOUNDATION_RELEASE_VERSION,
      sourceTreeSha256: bindings.sourceTreeSha256,
      trackedFileCount: 5,
    }),
  });
}

export function makeReviewEvidence(
  overrides: Partial<FoundationIndependentReviewEvidenceV1> = {},
): FoundationIndependentReviewEvidenceV1 {
  return {
    commitSha: COMMIT,
    evidenceType: FOUNDATION_REVIEW_EVIDENCE_TYPE,
    findings: [],
    gitTreeSha: TREE,
    releaseVersion: FOUNDATION_RELEASE_VERSION,
    repository: "tyler-james-bridges/rsi",
    reviewedAt: REVIEWED_AT,
    reviewerId: "rsi-independent-review-agent",
    reviewerRole: "independent-non-authoring-agent",
    scopes: FOUNDATION_REVIEW_SCOPE_NAMES.map((name) => ({ name, outcome: "passed" })),
    verdict: "approved",
    version: 1,
    ...overrides,
  } as FoundationIndependentReviewEvidenceV1;
}

export function makeCustodyFixture(counter: { value: number; signatures: number }): {
  readonly custody: FoundationCeremonyCustody;
  readonly identity: FoundationPinnedReleaseIdentityV1;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = Uint8Array.from(publicKey.export({ format: "der", type: "spki" }));
  const fingerprint = createHash("sha256").update(publicKeySpkiDer).digest("hex");
  const keyId = `rsi-release-${fingerprint.slice(0, 16)}`;
  const helperCompatibilityEvidence = makeHelperCompatibilityEvidence();
  const identity: FoundationPinnedReleaseIdentityV1 = Object.freeze({
    account: "release-ed25519-v1",
    createdAt: "2026-08-17T00:00:00.000Z",
    helperBinarySha256: "1".repeat(64),
    helperCompatibilityEvidence,
    helperCompatibilityEvidenceSha256: createHash("sha256")
      .update(canonicalJson(helperCompatibilityEvidence))
      .digest("hex"),
    helperCompatibilityTestedCommitSha: HELPER_TESTED_COMMIT,
    helperCompilerIdentitySha256: "2".repeat(64),
    helperSourceSha256: "3".repeat(64),
    identitySha256: "4".repeat(64),
    keyId,
    platformIdentitySha256: PLATFORM_IDENTITY_SHA256,
    provisioningIntentSha256: "5".repeat(64),
    provisioningReceiptSha256: "6".repeat(64),
    publicKeySpkiDer,
    pinningRepositoryCommitSha: COMMIT,
    provisioningRepositoryCommitSha: PROVISIONING_COMMIT,
    service: "dev.rsi.macbook.release-signing",
    signerFingerprintSha256: fingerprint,
  });
  const custody: FoundationCeremonyCustody = Object.freeze({
    async withSigners<T>(
      pinned: FoundationPinnedReleaseIdentityV1,
      operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
    ): Promise<T> {
      counter.value += 1;
      if (pinned.keyId !== identity.keyId) throw new Error("identity mismatch");
      let phase = 0;
      const signer = (expected: number): ReleaseBundleSignerV1 =>
        Object.freeze({
          keyId,
          publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
          sign(message: Uint8Array) {
            if (phase !== expected) throw new Error("signature order");
            phase += 1;
            counter.signatures += 1;
            return Uint8Array.from(sign(null, Uint8Array.from(message), privateKey));
          },
        });
      const result = await operation(
        Object.freeze({ releaseSigner: signer(0), tagSigner: signer(1) }),
      );
      if (phase !== 2) throw new Error("incomplete signatures");
      return result;
    },
  });
  return Object.freeze({ custody, identity });
}

function makeHelperCompatibilityEvidence() {
  return {
    cleanup: {
      evidenceSha256: "a".repeat(64),
      keychainItem: "deleted-and-absence-verified",
      outcome: "passed",
      temporaryArtifacts: "removed-and-absence-verified",
      testPrivateMaterial: "destroyed-and-absence-verified",
    },
    completedAt: "2026-08-17T22:00:00.000Z",
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
      binarySha256: "1".repeat(64),
      compilerIdentitySha256: "2".repeat(64),
      sourceSha256: "3".repeat(64),
    },
    helperPath: "packages/release-key-provisioning/native/keychain-helper.swift",
    independentApproval: {
      approvedAt: "2026-08-17T23:00:00.000Z",
      approvalEvidenceSha256: "b".repeat(64),
      authorship: "did-not-author-tested-helper-or-evidence",
      drillParticipation: "did-not-operate-drill",
      reviewerId: "independent-helper-reviewer",
      reviewerRole: "independent-non-authoring-reviewer",
      verdict: "approved",
    },
    keychainControls: {
      accessibility: "when-unlocked-this-device-only",
      dataProtectionKeychain: "verified",
      evidenceSha256: "c".repeat(64),
      persistentApproval: "not-granted",
      synchronizable: "disabled",
      unauthorizedAlternateClientAccess: "refused",
      userPresence: "required",
    },
    privateMaterialLeakScan: {
      evidenceSha256: "d".repeat(64),
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
        evidenceSha256: "e".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "first-fresh-helper-invocation",
        signatureVerification: "passed",
      },
      {
        attempt: 2,
        evidenceSha256: "f".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "second-fresh-helper-invocation-after-first-completed",
        signatureVerification: "passed",
      },
    ],
    repository: "tyler-james-bridges/rsi",
    repositoryVisibility: "public",
    testedCommitSha: HELPER_TESTED_COMMIT,
    verdict: "passed",
    version: 1,
  } as const;
}

function makeArtifacts(completedAt: string): readonly ReleaseArtifactInputV1[] {
  const artifacts: ReleaseArtifactInputV1[] = [
    artifact(
      "source/package.json",
      "source",
      "application/json",
      canonicalJson({
        engines: { node: "24.19.0", pnpm: "11.20.0" },
        name: "rsi",
        packageManager: "pnpm@11.20.0",
        private: true,
        type: "module",
        version: FOUNDATION_RELEASE_VERSION,
      }),
    ),
    artifact(
      "source/pnpm-workspace.yaml",
      "source",
      "application/yaml",
      "packages:\n  - packages/*\n",
    ),
    artifact(
      "source/tsconfig.json",
      "source",
      "application/json",
      canonicalJson({ compilerOptions: { strict: true } }),
    ),
    artifact(
      "source/packages/observer/src/index.ts",
      "source",
      "text/typescript",
      "export const observer = true;\n",
    ),
    artifact("source/pnpm-lock.yaml", "lockfile", "application/yaml", "lockfileVersion: '9.0'\n"),
  ];
  for (const name of REQUIRED_CONFIG_SCHEMA_NAMES) {
    artifacts.push(
      artifact(
        `config-schemas/${name}.schema.json`,
        "config-schema",
        "application/json",
        canonicalJson({
          name,
          schema: { additionalProperties: false, type: "object" },
          schemaType: "rsi.versioned-config-schema",
          schemaVersion: 1,
        }),
      ),
    );
  }
  artifacts.push(
    artifact(
      "runbooks/README.md",
      "runbook",
      "text/markdown",
      `# Observer runbooks\n\n${Array.from({ length: 19 }, (_, index) => `RB-${String(index + 1).padStart(2, "0")}: sanitized procedure`).join("\n")}\n`,
    ),
    artifact(
      "recovery/observer-restore.md",
      "recovery-procedure",
      "text/markdown",
      "# Observer restore\n\nRSI-RECOVERY-PROCEDURE-V1\nVERIFY-BEFORE-RESTORE\nNO-SECRET-RESTORE\nNEW-LINEAGE-REQUIRED\n",
    ),
    artifact(
      "release/sbom.cdx.json",
      "sbom",
      "application/json",
      canonicalJson({
        bomFormat: "CycloneDX",
        metadata: {
          component: { name: "rsi", type: "application", version: FOUNDATION_RELEASE_VERSION },
        },
        specVersion: "1.6",
        version: 1,
      }),
    ),
    artifact(
      "release/test-summary.v1.json",
      "test-summary",
      "application/json",
      canonicalJson({
        commitSha: COMMIT,
        completedAt,
        requiredChecks: REQUIRED_TEST_CHECKS.map((name) => ({
          name,
          outcome: "passed",
          resultSha256: createHash("sha256").update(`result:${name}`).digest("hex"),
        })),
        summaryType: "rsi.release.test-summary",
        version: 1,
      }),
    ),
  );
  return Object.freeze(artifacts);
}

function artifact(
  path: string,
  role: ReleaseArtifactInputV1["role"],
  mediaType: ReleaseArtifactInputV1["mediaType"],
  text: string,
): ReleaseArtifactInputV1 {
  return Object.freeze({ bytes: encoder.encode(text), mediaType, path, role });
}
