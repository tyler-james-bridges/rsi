import { spawnSync } from "node:child_process";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, extname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const contractPath = resolve(root, "docs/production-readiness/README.md");
const packageManifestPath = resolve(root, "package.json");
const verifierRelativePath = "scripts/ci/verify-production-contract.mjs";
const activeDocumentPaths = [
  resolve(root, "README.md"),
  resolve(root, "docs/architecture.md"),
  resolve(root, "docs/live-capital-charter.md"),
  resolve(root, "docs/roadmap.md"),
  resolve(root, "docs/standards.md"),
  resolve(root, "docs/threat-model.md"),
  contractPath,
];

const requiredContractText = [
  "Status: **active single-machine contract**",
  "No additional\nphysical hardware is required.",
  "## Current authority",
  "## Staged activation",
  "`LOCAL_VERIFIED`",
  "`READ_CANARY`",
  "`PAID_READ_CANARY`",
  "`HUMAN_CONFIRMED_EXECUTION`",
  "`BOUNDED_AUTOMATION`",
  "## Single-machine controls",
  "## Recovery and releases",
  "## Compatibility components are not gates",
  "## Standards order",
  "## Volatile integration rule",
  "## Next build target",
  "zero custom contracts",
];

const retiredMarkers = [
  { label: "foundation ceremony command", pattern: /\bfoundation:ceremony\b/iu },
  { label: "release-ceremony package", pattern: /\bpackages\/release-ceremony\b/iu },
  {
    label: "retired production-readiness path",
    pattern: /\bdocs\/production-readiness\/v1\b/iu,
  },
  { label: "retired readiness label", pattern: /\bFOUNDATION_BUILT\b/u },
  { label: "retired Observer v1 name", pattern: /\bObserver v1\b/iu },
  { label: "retired Observer requirement", pattern: /\bOBS-[A-Z0-9]+(?:-[A-Z0-9]+)+\b/u },
  { label: "retired Stage A name", pattern: /\bStage A\b/u },
  { label: "MacBook hardware role", pattern: /\bMacBook\b/iu },
  { label: "two-device verification", pattern: /\btwo-device verification\b/iu },
  {
    label: "physical-copy requirement",
    pattern: /\b(?:physical two-copy|both physical copies)\b/iu,
  },
  {
    label: "spare-hardware requirement",
    pattern: /\b(?:spare|throwaway) (?:computer|device|laptop|Mac|MacBook)\b/iu,
  },
];
const retiredPaths = ["docs/production-readiness/v1", "packages/release-ceremony"];
const relevantTextExtensions = new Set([
  ".cjs",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
]);
const contractRetirementExplanation =
  "This contract supersedes the retired Observer v1 readiness design.";

function fail(message) {
  process.stderr.write(`Single-machine production-contract verification failed: ${message}\n`);
  process.exit(1);
}

function gitListedPaths() {
  const result = spawnSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    {
      cwd: root,
      encoding: "buffer",
      env: process.env,
      maxBuffer: 64 * 1024 * 1024,
      shell: false,
      timeout: 30_000,
    },
  );
  if (result.status !== 0 || result.signal !== null || !Buffer.isBuffer(result.stdout)) {
    fail("unable to enumerate non-ignored repository files");
  }
  if (result.stdout.length === 0) return [];
  if (result.stdout[result.stdout.length - 1] !== 0) fail("Git path output is not NUL terminated");
  return result.stdout.subarray(0, -1).toString("utf8").split("\0");
}

async function existingListedPaths() {
  const existing = [];
  for (const listedPath of gitListedPaths()) {
    try {
      const status = await lstat(resolve(root, listedPath));
      existing.push({ listedPath, status });
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") continue;
      throw error;
    }
  }
  return existing;
}

function isWithin(base, candidate) {
  const fromBase = relative(base, candidate);
  return (
    fromBase === "" ||
    (fromBase !== ".." && !fromBase.startsWith(`..${sep}`) && !isAbsolute(fromBase))
  );
}

function isWindowsAbsolute(path) {
  return /^[a-z]:[\\/]/iu.test(path) || path.startsWith("\\\\");
}

function isAtOrBelow(path, directory) {
  return path === directory || path.startsWith(`${directory}/`);
}

async function pathResolvesInsideRepository(path, repositoryRealPath) {
  try {
    const resolvedPath = await realpath(path);
    return isWithin(repositoryRealPath, resolvedPath);
  } catch {
    return false;
  }
}

async function localLinksResolve(path, markdown, repositoryRealPath) {
  for (const match of markdown.matchAll(/\[[^\]]*\]\(([^)]+)\)/gu)) {
    const target = match[1]?.trim();
    if (target === undefined || target === "" || target.startsWith("#")) continue;
    const scheme = /^([a-z][a-z0-9+.-]*):/iu.exec(target);
    if (scheme !== null && scheme[1]?.toLowerCase() === "file") return false;
    if (scheme !== null && !isWindowsAbsolute(target)) continue;
    const withoutFragment = target.split("#", 1)[0];
    if (withoutFragment === undefined || withoutFragment === "") continue;
    let decoded;
    try {
      decoded = decodeURIComponent(withoutFragment.replace(/^<|>$/gu, ""));
    } catch {
      return false;
    }
    if (isAbsolute(decoded) || isWindowsAbsolute(decoded)) return false;
    const destination = resolve(dirname(path), decoded);
    if (!isWithin(root, destination)) return false;
    if (!(await pathResolvesInsideRepository(destination, repositoryRealPath))) return false;
  }
  return true;
}

function isRelevantTextPath(listedPath) {
  if (listedPath === verifierRelativePath) return false;
  if (["README.md", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"].includes(listedPath)) {
    return true;
  }
  if (
    ![".github/", "apps/", "docs/", "packages/", "scripts/"].some((prefix) =>
      listedPath.startsWith(prefix),
    )
  ) {
    return false;
  }
  return relevantTextExtensions.has(extname(listedPath));
}

function assertNoRetiredMarkers(path, text) {
  const scanText = path === contractPath ? text.replace(contractRetirementExplanation, "") : text;
  for (const { label, pattern } of retiredMarkers) {
    if (pattern.test(scanText)) fail(`${label} remains in ${relative(root, path)}`);
  }
}

try {
  const repositoryRealPath = await realpath(root);
  const listedPaths = await existingListedPaths();
  const contract = await readFile(contractPath, "utf8");
  for (const required of requiredContractText) {
    if (!contract.includes(required)) fail(`missing required text: ${JSON.stringify(required)}`);
  }

  for (const { listedPath } of listedPaths) {
    if (retiredPaths.some((path) => isAtOrBelow(listedPath, path))) {
      fail(`retired path still contains ${listedPath}`);
    }
  }

  const packageManifest = JSON.parse(await readFile(packageManifestPath, "utf8"));
  if (
    typeof packageManifest === "object" &&
    packageManifest !== null &&
    "scripts" in packageManifest &&
    typeof packageManifest.scripts === "object" &&
    packageManifest.scripts !== null &&
    Object.hasOwn(packageManifest.scripts, "foundation:ceremony")
  ) {
    fail("root package still defines foundation:ceremony");
  }

  for (const path of activeDocumentPaths) {
    const markdown = await readFile(path, "utf8");
    if (!(await localLinksResolve(path, markdown, repositoryRealPath))) {
      fail(`broken or out-of-repository local link in ${relative(root, path)}`);
    }
  }

  for (const { listedPath, status } of listedPaths) {
    if (!status.isFile() || !isRelevantTextPath(listedPath)) continue;
    const path = resolve(root, listedPath);
    assertNoRetiredMarkers(path, await readFile(path, "utf8"));
  }

  process.stdout.write(
    `Single-machine production contract verified: ${requiredContractText.length} controls and ${activeDocumentPaths.length} active documents.\n`,
  );
} catch (error) {
  if (error instanceof Error) fail(error.message);
  fail("unknown error");
}
