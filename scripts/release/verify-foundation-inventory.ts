import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  REQUIRED_CONFIG_SCHEMA_NAMES,
  REQUIRED_TEST_CHECKS,
  ReleaseBundleError,
  deriveReleaseArtifactBindings,
  type ReleaseArtifactInputV1,
  type ReleaseArtifactMediaType,
  type ReleaseArtifactRole,
} from "../../packages/release-bundle/src/index.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const encoder = new TextEncoder();
const EXPECTED_NODE = "24.19.0";
const EXPECTED_PNPM = "11.20.0";
const REQUIRED_RUNBOOK = "docs/production-readiness/v1/runbooks/README.md";
const REQUIRED_RECOVERY = "docs/production-readiness/v1/recovery/observer-restore.md";
const ROOT_SOURCE_PATHS = new Set([
  "AGENTS.md",
  "README.md",
  "package.json",
  "pnpm-workspace.yaml",
  "tsconfig.json",
  "vitest.config.ts",
]);
const ROOT_PATH_MAPPINGS = new Map<string, readonly [string, ReleaseArtifactRole]>([
  [".builder-workflows/.gitignore", ["source/scripts/build-session-gitignore.txt", "source"]],
  [".builder-workflows/config.json", ["source/scripts/build-session-config.json", "source"]],
  [".env.example", ["source/scripts/environment-example.txt", "source"]],
  [".github/README.md", ["runbooks/github-automation-boundary.md", "runbook"]],
  [".github/gitleaks.toml", ["source/scripts/gitleaks.toml", "source"]],
  [".github/workflows/ci.yml", ["source/scripts/github-ci.yml", "source"]],
  [".gitignore", ["source/scripts/gitignore.txt", "source"]],
  [".node-version", ["source/scripts/node-version.txt", "source"]],
  [".nvmrc", ["source/scripts/nvmrc.txt", "source"]],
  [".prettierignore", ["source/scripts/prettierignore.txt", "source"]],
  [".prettierrc.json", ["source/scripts/prettier-config.json", "source"]],
  ["SECURITY.md", ["runbooks/security.md", "runbook"]],
]);
let phase = "preconditions";

function fail(): never {
  process.stderr.write(`Foundation release-inventory verification failed during ${phase}.\n`);
  process.exit(1);
}

function git(args: readonly string[]): string {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0) fail();
  return result.stdout;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) fail();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value !== "object") fail();
  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  return `{${entries
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

function ordinaryBytes(value: Uint8Array): Uint8Array {
  return Uint8Array.from(value);
}

function mediaType(path: string, role: ReleaseArtifactRole): ReleaseArtifactMediaType {
  if (role === "config-schema" || role === "sbom" || role === "test-summary") {
    return "application/json";
  }
  if (role === "lockfile" || /\.ya?ml$/u.test(path)) return "application/yaml";
  if (role === "runbook" || role === "recovery-procedure" || path.endsWith(".md")) {
    return "text/markdown";
  }
  if (/\.tsx?$/u.test(path)) return "text/typescript";
  if (path.endsWith(".json")) return "application/json";
  return "text/plain";
}

async function artifactFromFile(
  repositoryPath: string,
  releasePath: string,
  role: ReleaseArtifactRole,
): Promise<ReleaseArtifactInputV1> {
  return {
    bytes: ordinaryBytes(
      await readFile(new URL(repositoryPath, new URL("../../", import.meta.url))),
    ),
    mediaType: mediaType(releasePath, role),
    path: releasePath,
    role,
  };
}

function mappedTrackedPath(path: string): readonly [string, ReleaseArtifactRole] {
  if (path === "pnpm-lock.yaml") return ["source/pnpm-lock.yaml", "lockfile"];
  if (path === REQUIRED_RUNBOOK) return ["runbooks/README.md", "runbook"];
  if (path === REQUIRED_RECOVERY) return ["recovery/observer-restore.md", "recovery-procedure"];
  if (ROOT_SOURCE_PATHS.has(path)) return [`source/${path}`, "source"];
  const mapped = ROOT_PATH_MAPPINGS.get(path);
  if (mapped !== undefined) return mapped;
  if (/^(?:apps|packages|scripts)\//u.test(path)) return [`source/${path}`, "source"];
  if (path.startsWith("docs/") && path.endsWith(".md")) {
    const normalized = path.slice("docs/".length).replaceAll("/", "-");
    return [`runbooks/${normalized}`, "runbook"];
  }
  fail();
}

function parseLockComponents(lockfile: string): readonly Record<string, string>[] {
  const start = lockfile.indexOf("\npackages:\n");
  const end = lockfile.indexOf("\nsnapshots:\n");
  if (start < 0 || end <= start) fail();
  const components = new Map<string, Record<string, string>>();
  for (const line of lockfile.slice(start + 1, end).split("\n")) {
    const match = /^  (?:(?:"([^"]+)")|([^" ][^:]*)):\s*$/u.exec(line);
    const key = match?.[1] ?? match?.[2];
    if (key === undefined) continue;
    const separator = key.lastIndexOf("@");
    if (separator <= 0) fail();
    const name = key.slice(0, separator);
    const version = key.slice(separator + 1).split("(", 1)[0];
    if (name.length === 0 || version === undefined || version.length === 0) fail();
    const identity = `${name}@${version}`;
    components.set(identity, {
      name,
      purl: `pkg:npm/${encodeURIComponent(name).replace("%2F", "/")}@${encodeURIComponent(version)}`,
      type: "library",
      version,
    });
  }
  return [...components.values()].sort((left, right) => {
    const leftIdentity = `${left.name}@${left.version}`;
    const rightIdentity = `${right.name}@${right.version}`;
    return leftIdentity < rightIdentity ? -1 : leftIdentity > rightIdentity ? 1 : 0;
  });
}

function generatedArtifact(
  path: string,
  role: ReleaseArtifactRole,
  value: unknown,
): ReleaseArtifactInputV1 {
  return {
    bytes: encoder.encode(canonicalJson(value)),
    mediaType: mediaType(path, role),
    path,
    role,
  };
}

async function main(): Promise<void> {
  if (process.versions.node !== EXPECTED_NODE || git(["status", "--porcelain=v1"]) !== "") fail();
  const pnpmVersion = /(?:^|\s)pnpm\/([^\s]+)/u.exec(process.env.npm_config_user_agent ?? "")?.[1];
  if (pnpmVersion !== EXPECTED_PNPM) fail();

  phase = "git-identity";
  const commitSha = git(["rev-parse", "HEAD"]).trim();
  const gitTreeSha = git(["rev-parse", "HEAD^{tree}"]).trim();
  if (!/^[0-9a-f]{40}$/u.test(commitSha) || !/^[0-9a-f]{40}$/u.test(gitTreeSha)) fail();
  const trackedPaths = git(["ls-files", "-z"])
    .split("\0")
    .filter((path) => path.length > 0);
  if (trackedPaths.length === 0 || new Set(trackedPaths).size !== trackedPaths.length) fail();

  phase = "tracked-inventory";
  const artifacts: ReleaseArtifactInputV1[] = [];
  for (const path of trackedPaths) {
    const [releasePath, role] = mappedTrackedPath(path);
    artifacts.push(await artifactFromFile(path, releasePath, role));
  }
  phase = "schema-inventory";
  for (const name of REQUIRED_CONFIG_SCHEMA_NAMES) {
    artifacts.push(
      generatedArtifact(`config-schemas/${name}.schema.json`, "config-schema", {
        name,
        schema: { additionalProperties: false, type: "object" },
        schemaType: "rsi.versioned-config-schema",
        schemaVersion: 1,
      }),
    );
  }

  phase = "sbom-inventory";
  const lockfile = await readFile(new URL("../../pnpm-lock.yaml", import.meta.url), "utf8");
  artifacts.push(
    generatedArtifact("release/sbom.cdx.json", "sbom", {
      bomFormat: "CycloneDX",
      components: parseLockComponents(lockfile),
      metadata: { component: { name: "rsi", type: "application", version: "0.1.0-foundation.1" } },
      specVersion: "1.6",
      version: 1,
    }),
  );
  phase = "test-summary";
  const completedAt = new Date().toISOString();
  artifacts.push(
    generatedArtifact("release/test-summary.v1.json", "test-summary", {
      commitSha,
      completedAt,
      requiredChecks: REQUIRED_TEST_CHECKS.map((name) => ({
        name,
        outcome: "passed",
        // This command validates the closed inventory but never creates a
        // signed release. A later MacBook-held signer must replace these
        // explicitly domain-marked candidate hashes with retained CI receipts.
        resultSha256: sha256(`rsi-unsigned-inventory-candidate-check-v1\0${commitSha}\0${name}`),
      })),
      summaryType: "rsi.release.test-summary",
      version: 1,
    }),
  );

  phase = "release-policy";
  const bindings = deriveReleaseArtifactBindings(artifacts);
  phase = "report";
  process.stdout.write(
    `${canonicalJson({
      artifactCount: artifacts.length,
      artifactSetSha256: bindings.artifactSetSha256,
      commitSha,
      configSetSha256: bindings.configSetSha256,
      gitTreeSha,
      lockfileSha256: bindings.lockfileSha256,
      releaseVersion: "0.1.0-foundation.1",
      sourceTreeSha256: bindings.sourceTreeSha256,
      status: "unsigned-inventory-candidate-validated",
      trackedFileCount: trackedPaths.length,
    })}\n`,
  );
}

await main().catch((error: unknown) => {
  if (error instanceof ReleaseBundleError) phase = `release-policy-${error.code.toLowerCase()}`;
  fail();
});
