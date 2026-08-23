import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

import {
  REQUIRED_CONFIG_SCHEMA_NAMES,
  REQUIRED_TEST_CHECKS,
  deriveReleaseArtifactBindings,
  type ReleaseArtifactInputV1,
  type ReleaseArtifactMediaType,
  type ReleaseArtifactRole,
} from "@rsi/release-bundle";

import { canonicalJson, validateCanonicalTimestamp, validateGitHash } from "./canonical.js";
import { deriveCiCheckResultSha256 } from "./ci-evidence.js";
import { fail } from "./errors.js";
import {
  FOUNDATION_RELEASE_VERSION,
  FOUNDATION_TAG,
  type FoundationCiEvidenceV1,
  type FoundationReleaseInventory,
  type FoundationRequiredCheckName,
} from "./types.js";

const EXPECTED_NODE = "24.19.0";
const EXPECTED_PNPM = "11.20.0";
const APPROVED_REMOTE = "https://github.com/tyler-james-bridges/rsi.git";
const APPROVED_SSH_REMOTE = "git@github.com:tyler-james-bridges/rsi.git";
const HARDENED_GIT_OPTIONS = Object.freeze([
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
] as const);
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
  [
    "config/foundation-independent-reviewer-identity.v1.json",
    ["source/config/foundation-independent-reviewer-identity.v1.json", "source"],
  ],
  [
    "config/foundation-release-identity.v1.json",
    ["source/config/foundation-release-identity.v1.json", "source"],
  ],
  [
    "config/foundation-release-key-helper-compatibility.v1.json",
    ["source/config/foundation-release-key-helper-compatibility.v1.json", "source"],
  ],
  [
    "config/foundation-release-key-provisioning-receipt.v1.json",
    ["source/config/foundation-release-key-provisioning-receipt.v1.json", "source"],
  ],
  ["SECURITY.md", ["runbooks/security.md", "runbook"]],
]);
const encoder = new TextEncoder();

export interface CollectFoundationInventoryOptions {
  readonly ciEvidence?: FoundationCiEvidenceV1;
  readonly createdAt?: string;
  readonly mode: "candidate" | "ceremony";
  readonly repositoryRoot: string;
}

interface FoundationTrackedBlob {
  readonly mode: "100644" | "100755";
  readonly objectId: string;
  readonly path: string;
}

export async function collectFoundationReleaseInventory(
  options: CollectFoundationInventoryOptions,
): Promise<FoundationReleaseInventory> {
  const root = resolve(options.repositoryRoot);
  const snapshot = inspectRepository(root, options);
  const completedAt =
    options.mode === "candidate"
      ? snapshot.commitTimestamp
      : validateCeremonyTime(options.createdAt, options.ciEvidence, snapshot.commitTimestamp);
  const artifacts = collectArtifacts(root, snapshot.trackedBlobs, {
    ...(options.ciEvidence === undefined ? {} : { ciEvidence: options.ciEvidence }),
    commitSha: snapshot.commitSha,
    completedAt,
    mode: options.mode,
  });
  assertRepositorySnapshotStable(root, snapshot, options);
  const bindings = deriveReleaseArtifactBindings(artifacts);
  const release = Object.freeze({
    ...bindings,
    commitSha: snapshot.commitSha,
    createdAt: completedAt,
    gitTreeSha: snapshot.gitTreeSha,
    nodeVersion: EXPECTED_NODE,
    pnpmVersion: EXPECTED_PNPM,
    predecessorManifestSha256: null,
    releaseVersion: FOUNDATION_RELEASE_VERSION,
  });
  return Object.freeze({
    artifacts: Object.freeze(artifacts),
    release,
    report: Object.freeze({
      ...bindings,
      artifactCount: artifacts.length,
      commitSha: snapshot.commitSha,
      gitTreeSha: snapshot.gitTreeSha,
      releaseVersion: FOUNDATION_RELEASE_VERSION,
      sourceTreeSha256: bindings.sourceTreeSha256,
      trackedFileCount: snapshot.trackedBlobs.length,
    }),
  });
}

function inspectRepository(
  root: string,
  options: CollectFoundationInventoryOptions,
): {
  readonly commitSha: string;
  readonly commitTimestamp: string;
  readonly gitTreeSha: string;
  readonly trackedBlobs: readonly FoundationTrackedBlob[];
} {
  if (process.versions.node !== EXPECTED_NODE || pnpmVersion() !== EXPECTED_PNPM) {
    fail("REPOSITORY_STATE", "Foundation release runtime does not match the exact pins");
  }
  assertUnambiguousGitHistory(root);
  assertCleanRepository(root);
  const commitSha = validateGitHash(git(root, ["rev-parse", "HEAD"]).trim(), "Release commit");
  const gitTreeSha = validateGitHash(
    git(root, ["rev-parse", "HEAD^{tree}"]).trim(),
    "Release Git tree",
  );
  const commitTimestampRaw = git(root, ["show", "-s", "--format=%cI", commitSha]).trim();
  const parsedCommitTimestamp = new Date(commitTimestampRaw);
  if (Number.isNaN(parsedCommitTimestamp.getTime())) {
    fail("REPOSITORY_STATE", "Foundation release commit timestamp is invalid");
  }
  const commitTimestamp = parsedCommitTimestamp.toISOString();
  if (options.mode === "ceremony")
    assertCeremonyRepositoryIdentity(root, commitSha, options.ciEvidence);
  const trackedBlobs = readTrackedTree(root, commitSha);
  assertIndexFlagsAreOrdinary(root, trackedBlobs);
  return Object.freeze({
    commitSha,
    commitTimestamp,
    gitTreeSha,
    trackedBlobs,
  });
}

function assertUnambiguousGitHistory(root: string): void {
  const graftsPath = resolve(root, git(root, ["rev-parse", "--git-path", "info/grafts"]).trim());
  if (
    git(root, ["for-each-ref", "--format=%(refname)", "refs/replace"]).trim() !== "" ||
    existsSync(graftsPath) ||
    git(root, ["rev-parse", "--is-shallow-repository"]).trim() !== "false"
  ) {
    fail("REPOSITORY_STATE", "Foundation release Git history is replaced, grafted, or shallow");
  }
}

function assertCleanRepository(root: string): void {
  if (git(root, ["status", "--porcelain=v1", "--untracked-files=all"]) !== "") {
    fail("REPOSITORY_STATE", "Foundation release repository is not clean");
  }
}

function assertIndexFlagsAreOrdinary(
  root: string,
  trackedBlobs: readonly FoundationTrackedBlob[],
): void {
  const records = nulRecords(gitBytes(root, ["ls-files", "-v", "-z"]));
  if (
    records.length !== trackedBlobs.length ||
    records.some((record, index) => record !== `H ${trackedBlobs[index]!.path}`)
  ) {
    fail(
      "REPOSITORY_STATE",
      "Foundation release index uses hidden-change flags or differs from the release tree",
    );
  }
}

function assertCeremonyRepositoryIdentity(
  root: string,
  commitSha: string,
  ciEvidence: FoundationCiEvidenceV1 | undefined,
): void {
  if (ciEvidence === undefined || ciEvidence.commitSha !== commitSha) {
    fail("REPOSITORY_STATE", "Foundation CI evidence does not match repository HEAD");
  }
  if (
    git(root, ["branch", "--show-current"]).trim() !== "main" ||
    git(root, ["rev-parse", "refs/remotes/origin/main"]).trim() !== commitSha ||
    !hasApprovedRawOrigin(root) ||
    git(root, ["tag", "--list", FOUNDATION_TAG]).trim() !== ""
  ) {
    fail("REPOSITORY_STATE", "Foundation ceremony repository identity is not eligible");
  }
}

function assertRepositorySnapshotStable(
  root: string,
  snapshot: {
    readonly commitSha: string;
    readonly gitTreeSha: string;
    readonly trackedBlobs: readonly FoundationTrackedBlob[];
  },
  options: CollectFoundationInventoryOptions,
): void {
  assertUnambiguousGitHistory(root);
  assertCleanRepository(root);
  assertIndexFlagsAreOrdinary(root, snapshot.trackedBlobs);
  if (
    git(root, ["rev-parse", "HEAD"]).trim() !== snapshot.commitSha ||
    git(root, ["rev-parse", "HEAD^{tree}"]).trim() !== snapshot.gitTreeSha
  ) {
    fail("REPOSITORY_STATE", "Foundation release repository changed during inventory collection");
  }
  if (options.mode === "ceremony") {
    assertCeremonyRepositoryIdentity(root, snapshot.commitSha, options.ciEvidence);
  }
}

function readTrackedTree(root: string, commitSha: string): readonly FoundationTrackedBlob[] {
  const records = nulRecords(gitBytes(root, ["ls-tree", "-r", "-z", "--full-tree", commitSha]));
  const trackedBlobs = records.map((record) => {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(record);
    if (match === null) {
      fail("REPOSITORY_STATE", "Foundation release tree contains an unsupported entry");
    }
    return Object.freeze({
      mode: match[1] as "100644" | "100755",
      objectId: match[2]!,
      path: match[3]!,
    });
  });
  if (
    trackedBlobs.length === 0 ||
    new Set(trackedBlobs.map(({ path }) => path)).size !== trackedBlobs.length
  ) {
    fail("REPOSITORY_STATE", "Foundation release tracked inventory is invalid");
  }
  return Object.freeze(trackedBlobs);
}

function nulRecords(bytes: Uint8Array): readonly string[] {
  let value: string;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("REPOSITORY_STATE", "Foundation release Git output is not canonical UTF-8");
  }
  if (!value.endsWith("\0")) {
    fail("REPOSITORY_STATE", "Foundation release Git output is incomplete");
  }
  return Object.freeze(value.slice(0, -1).split("\0"));
}

function git(root: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", [...HARDENED_GIT_OPTIONS, ...args], {
    cwd: root,
    encoding: "utf8",
    env: gitEnvironment(),
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    fail("REPOSITORY_STATE", "Foundation release Git inspection failed");
  }
  return result.stdout;
}

function gitBytes(root: string, args: readonly string[]): Uint8Array {
  const result = spawnSync("/usr/bin/git", [...HARDENED_GIT_OPTIONS, ...args], {
    cwd: root,
    env: gitEnvironment(),
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    fail("REPOSITORY_STATE", "Foundation release Git inspection failed");
  }
  return Uint8Array.from(result.stdout);
}

function gitEnvironment(): NodeJS.ProcessEnv {
  return {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    LANG: "C",
    LC_ALL: "C",
    PATH: process.env.PATH ?? "/usr/bin:/bin",
  };
}

function pnpmVersion(): string | null {
  return /(?:^|\s)pnpm\/([^\s]+)/u.exec(process.env.npm_config_user_agent ?? "")?.[1] ?? null;
}

function hasApprovedRawOrigin(root: string): boolean {
  const configured = git(root, [
    "config",
    "--local",
    "--no-includes",
    "--get-all",
    "remote.origin.url",
  ]);
  return configured === `${APPROVED_REMOTE}\n` || configured === `${APPROVED_SSH_REMOTE}\n`;
}

function validateCeremonyTime(
  createdAtValue: string | undefined,
  evidence: FoundationCiEvidenceV1 | undefined,
  commitTimestamp: string,
): string {
  if (createdAtValue === undefined || evidence === undefined) {
    fail("INPUT_INVALID", "Foundation ceremony time or CI evidence is missing");
  }
  const createdAt = validateCanonicalTimestamp(createdAtValue, "Foundation ceremony time");
  if (
    createdAt < evidence.completedAt ||
    evidence.completedAt < commitTimestamp ||
    new Date(createdAt).getTime() - new Date(evidence.completedAt).getTime() >
      7 * 24 * 60 * 60 * 1_000
  ) {
    fail("CI_EVIDENCE_INVALID", "Foundation ceremony timeline is invalid");
  }
  return createdAt;
}

function collectArtifacts(
  root: string,
  trackedBlobs: readonly FoundationTrackedBlob[],
  context: {
    readonly ciEvidence?: FoundationCiEvidenceV1;
    readonly commitSha: string;
    readonly completedAt: string;
    readonly mode: "candidate" | "ceremony";
  },
): ReleaseArtifactInputV1[] {
  const artifacts: ReleaseArtifactInputV1[] = [];
  for (const trackedBlob of trackedBlobs) {
    const { path } = trackedBlob;
    const [releasePath, role] = classifyFoundationTrackedPath(path);
    artifacts.push({
      bytes: readTrackedBlob(root, trackedBlob),
      mediaType: mediaType(releasePath, role),
      path: releasePath,
      role,
    });
  }
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
  const lockfileEntry = trackedBlobs.find(({ path }) => path === "pnpm-lock.yaml");
  if (lockfileEntry === undefined) {
    fail("REPOSITORY_STATE", "Foundation release lockfile is not tracked");
  }
  const lockfile = readTrackedBlob(root, lockfileEntry);
  artifacts.push(
    generatedArtifact("release/sbom.cdx.json", "sbom", {
      bomFormat: "CycloneDX",
      components: parseLockComponents(new TextDecoder().decode(lockfile)),
      metadata: {
        component: { name: "rsi", type: "application", version: FOUNDATION_RELEASE_VERSION },
      },
      specVersion: "1.6",
      version: 1,
    }),
  );
  artifacts.push(
    generatedArtifact("release/test-summary.v1.json", "test-summary", {
      commitSha: context.commitSha,
      completedAt: context.completedAt,
      requiredChecks: REQUIRED_TEST_CHECKS.map((name) => ({
        name,
        outcome: "passed",
        resultSha256:
          context.mode === "candidate"
            ? sha256(`rsi-unsigned-inventory-candidate-check-v1\0${context.commitSha}\0${name}`)
            : deriveCiCheckResultSha256(
                requiredEvidence(context.ciEvidence),
                name as FoundationRequiredCheckName,
              ),
      })),
      summaryType: "rsi.release.test-summary",
      version: 1,
    }),
  );
  return artifacts;
}

function requiredEvidence(value: FoundationCiEvidenceV1 | undefined): FoundationCiEvidenceV1 {
  if (value === undefined) fail("CI_EVIDENCE_INVALID", "Foundation CI evidence is missing");
  return value;
}

function readTrackedBlob(root: string, trackedBlob: FoundationTrackedBlob): Uint8Array {
  const bytes = gitBytes(root, ["cat-file", "blob", trackedBlob.objectId]);
  const objectId = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
  if (objectId !== trackedBlob.objectId) {
    bytes.fill(0);
    fail("REPOSITORY_STATE", "Foundation release Git blob failed object verification");
  }
  return bytes;
}

export function classifyFoundationTrackedPath(
  path: string,
): readonly [string, ReleaseArtifactRole] {
  if (path === "pnpm-lock.yaml") return ["source/pnpm-lock.yaml", "lockfile"];
  if (path === REQUIRED_RUNBOOK) return ["runbooks/README.md", "runbook"];
  if (path === REQUIRED_RECOVERY) return ["recovery/observer-restore.md", "recovery-procedure"];
  if (ROOT_SOURCE_PATHS.has(path)) return [`source/${path}`, "source"];
  const mapped = ROOT_PATH_MAPPINGS.get(path);
  if (mapped !== undefined) return mapped;
  if (/^(?:apps|packages|scripts)\//u.test(path)) return [`source/${path}`, "source"];
  if (path.startsWith("docs/") && path.endsWith(".md")) {
    return [`runbooks/${path.slice("docs/".length).replaceAll("/", "-")}`, "runbook"];
  }
  fail("REPOSITORY_STATE", "Foundation tracked path is not release-classified");
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
  if (path.endsWith(".swift")) return "text/x-swift";
  if (path.endsWith(".json")) return "application/json";
  return "text/plain";
}

function generatedArtifact(
  path: string,
  role: ReleaseArtifactRole,
  value: unknown,
): ReleaseArtifactInputV1 {
  return Object.freeze({
    bytes: encoder.encode(canonicalJson(value)),
    mediaType: mediaType(path, role),
    path,
    role,
  });
}

function parseLockComponents(lockfile: string): readonly Record<string, string>[] {
  const start = lockfile.indexOf("\npackages:\n");
  const end = lockfile.indexOf("\nsnapshots:\n");
  if (start < 0 || end <= start) {
    fail("REPOSITORY_STATE", "Foundation lockfile package graph is invalid");
  }
  const components = new Map<string, Record<string, string>>();
  for (const line of lockfile.slice(start + 1, end).split("\n")) {
    const match = /^  (?:(?:"([^"]+)")|([^" ][^:]*)):\s*$/u.exec(line);
    const key = match?.[1] ?? match?.[2];
    if (key === undefined) continue;
    const separator = key.lastIndexOf("@");
    if (separator <= 0) fail("REPOSITORY_STATE", "Foundation lockfile identity is invalid");
    const name = key.slice(0, separator);
    const version = key.slice(separator + 1).split("(", 1)[0];
    if (name.length === 0 || version === undefined || version.length === 0) {
      fail("REPOSITORY_STATE", "Foundation lockfile identity is invalid");
    }
    components.set(`${name}@${version}`, {
      name,
      purl: `pkg:npm/${encodeURIComponent(name).replace("%2F", "/")}@${encodeURIComponent(version)}`,
      type: "library",
      version,
    });
  }
  return Object.freeze(
    [...components.values()].sort((left, right) =>
      `${left.name}@${left.version}` < `${right.name}@${right.version}` ? -1 : 1,
    ),
  );
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
