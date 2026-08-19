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
  FOUNDATION_CI_EVIDENCE_TYPE,
  FOUNDATION_RELEASE_VERSION,
  type FoundationCeremonyCustody,
  type FoundationCiEvidenceV1,
  type FoundationReleaseInventory,
} from "../src/types.js";

export const COMMIT = "a".repeat(40);
export const TREE = "b".repeat(40);
export const CI_COMPLETED_AT = "2026-08-18T00:00:00.000Z";
export const CEREMONY_AT = "2026-08-18T01:00:00.000Z";
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

export function makeCustody(counter: { value: number }): FoundationCeremonyCustody {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = Uint8Array.from(publicKey.export({ format: "der", type: "spki" }));
  const signer: ReleaseBundleSignerV1 = Object.freeze({
    keyId: "rsi-release-test-key",
    publicKeySpkiDer,
    sign(message: Uint8Array) {
      return Uint8Array.from(sign(null, Uint8Array.from(message), privateKey));
    },
  });
  return Object.freeze({
    async withSigner<T>(operation: (value: ReleaseBundleSignerV1) => Promise<T>): Promise<T> {
      counter.value += 1;
      return operation(signer);
    },
  });
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
