import { constants as fsConstants, type BigIntStats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import { REQUIRED_TEST_CHECKS } from "@rsi/release-bundle";

import { canonicalJson, exactArray, exactObject, validateGitHash } from "./canonical.js";
import { foundationCiEvidenceSha256, parseFoundationCiEvidence } from "./ci-evidence.js";
import { FoundationCeremonyError, fail } from "./errors.js";
import { readFoundationCiEvidenceFile } from "./host.js";
import type { FoundationCiEvidenceV1 } from "./types.js";

const REPOSITORY = "tyler-james-bridges/rsi" as const;
const API_ROOT = `https://api.github.com/repos/${REPOSITORY}` as const;
const WEB_ROOT = `https://github.com/${REPOSITORY}` as const;
const MAX_API_RESPONSE_BYTES = 512 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const JOB_NAMES = ["gitleaks-history", "quality"] as const;
type FoundationCiJobName = (typeof JOB_NAMES)[number];

const REQUIRED_USER_STEP_NAMES: Readonly<Record<FoundationCiJobName, readonly string[]>> =
  Object.freeze({
    "gitleaks-history": Object.freeze([
      "Check out full history without persisted credentials",
      "Install checksum-pinned Gitleaks",
      "Prove scanner detects a synthetic credential",
      "Scan working tree and complete Git history with redaction",
    ]),
    quality: Object.freeze([
      "Check out full history without persisted credentials",
      "Install exact Node and pnpm releases",
      "Verify runtime pins",
      "Install locked dependencies",
      "Verify action pins",
      "Scan working tree and Git history for secrets",
      "Verify production contract and traceability",
      "Verify format, types, and tests",
      "Verify offline demos",
      "Run Stage A drills with external destinations denied",
      "Audit all dependencies",
      "Reject generated or dirty state",
      "Verify the closed foundation inventory candidate",
    ]),
  });

export interface FoundationCiRetentionOptions {
  readonly confirmCommit: string;
  readonly outputPath: string;
  readonly runId: string;
}

export interface FoundationCiRetentionDependencies {
  readonly fetch: typeof globalThis.fetch;
  readonly repositoryRoot: string;
}

export interface FoundationCiRetentionResult {
  readonly evidence: FoundationCiEvidenceV1;
  readonly outputPath: string;
  readonly sha256: string;
}

interface DirectoryGuard {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: number;
  readonly path: string;
  readonly uid: bigint;
}

interface RunIdentity {
  readonly runStartedAt: string;
  readonly runApiUrl: string;
  readonly runId: string;
  readonly updatedAt: string;
  readonly runWebUrl: string;
}

interface RetainedJobs {
  readonly completedAt: string;
  readonly jobs: readonly [
    { readonly conclusion: "success"; readonly name: "gitleaks-history" },
    { readonly conclusion: "success"; readonly name: "quality" },
  ];
}

/**
 * Retain the public, successful main-branch CI result after the nonsecret identity and receipt are
 * pinned and before the offline signing ceremony. The adapter is deliberately limited to two
 * fixed, unauthenticated GitHub GET requests.
 */
export async function retainFoundationCiEvidence(
  optionsValue: FoundationCiRetentionOptions,
  dependenciesValue: FoundationCiRetentionDependencies,
): Promise<FoundationCiRetentionResult> {
  const options = parseRetentionOptions(optionsValue);
  const dependencies = parseDependencies(dependenciesValue);
  const runApiUrl = `${API_ROOT}/actions/runs/${options.runId}`;
  const runValue = await fetchPublicGithubJson(runApiUrl, dependencies.fetch);
  const run = parseRun(runValue, options);
  const jobsValue = await fetchPublicGithubJson(
    `${runApiUrl}/jobs?filter=latest&per_page=100`,
    dependencies.fetch,
  );
  const retainedJobs = parseJobs(jobsValue, run, options.confirmCommit);
  const evidence = parseFoundationCiEvidence({
    branch: "main",
    commitSha: options.confirmCommit,
    // A workflow run's updated_at can change for metadata reasons after its checks finish.
    // The last required job completion is the precise instant at which all evidence passed.
    completedAt: retainedJobs.completedAt,
    evidenceType: "rsi.foundation-ci-evidence",
    event: "push",
    jobs: retainedJobs.jobs,
    repository: REPOSITORY,
    requiredChecks: REQUIRED_TEST_CHECKS.map((name) => ({ name, outcome: "passed" as const })),
    runId: options.runId,
    runUrl: run.runWebUrl,
    version: 1,
    workflow: "ci",
  });
  return writeAndVerifyEvidence(evidence, options.outputPath, dependencies.repositoryRoot);
}

export function parseFoundationCiRunId(value: unknown): string {
  if (typeof value !== "string" || !/^[1-9]\d{0,15}$/u.test(value)) {
    fail("INPUT_INVALID", "Foundation CI run identifier is invalid");
  }
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0 || String(numeric) !== value) {
    fail("INPUT_INVALID", "Foundation CI run identifier is invalid");
  }
  return value;
}

function parseRetentionOptions(value: FoundationCiRetentionOptions): FoundationCiRetentionOptions {
  const record = exactObject(
    value,
    ["confirmCommit", "outputPath", "runId"],
    "Foundation CI retention options",
  );
  if (typeof record.outputPath !== "string") {
    fail("INPUT_INVALID", "Foundation CI retention output path is invalid");
  }
  return Object.freeze({
    confirmCommit: validateGitHash(record.confirmCommit, "Confirmed foundation commit"),
    outputPath: validateOutputPathShape(record.outputPath),
    runId: parseFoundationCiRunId(record.runId),
  });
}

function parseDependencies(
  value: FoundationCiRetentionDependencies,
): FoundationCiRetentionDependencies {
  const record = exactObject(
    value,
    ["fetch", "repositoryRoot"],
    "Foundation CI retention dependencies",
  );
  if (typeof record.fetch !== "function" || typeof record.repositoryRoot !== "string") {
    fail("INPUT_INVALID", "Foundation CI retention dependencies are invalid");
  }
  return Object.freeze({
    fetch: record.fetch as typeof globalThis.fetch,
    repositoryRoot: record.repositoryRoot,
  });
}

async function fetchPublicGithubJson(
  url: string,
  fetchImplementation: typeof globalThis.fetch,
): Promise<unknown> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      fetchAndReadJson(url, fetchImplementation, controller.signal),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("Foundation GitHub request timed out"));
        }, REQUEST_TIMEOUT_MS);
      }),
    ]);
  } catch (error) {
    if (error instanceof FoundationCeremonyError) throw error;
    fail("CI_EVIDENCE_INVALID", "Foundation CI evidence could not be read from GitHub");
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function fetchAndReadJson(
  url: string,
  fetchImplementation: typeof globalThis.fetch,
  signal: AbortSignal,
): Promise<unknown> {
  const response = await fetchImplementation(url, {
    cache: "no-store",
    credentials: "omit",
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "rsi-foundation-ci-retention/1",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    method: "GET",
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal,
  });
  if (!(response instanceof Response)) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub adapter returned an invalid response");
  }
  if (response.redirected || response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub response was not a direct success");
  }
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    await response.body?.cancel().catch(() => undefined);
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub response was not JSON");
  }
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d{1,9}$/u.test(declaredLength) || Number(declaredLength) > MAX_API_RESPONSE_BYTES) {
      await response.body?.cancel().catch(() => undefined);
      fail("CI_EVIDENCE_INVALID", "Foundation GitHub response was too large");
    }
  }
  const bytes = await readBoundedBody(response.body);
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text.length === 0) {
      fail("CI_EVIDENCE_INVALID", "Foundation GitHub response was empty");
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      fail("CI_EVIDENCE_INVALID", "Foundation GitHub response contained invalid JSON");
    }
  } finally {
    bytes.fill(0);
  }
}

async function readBoundedBody(body: ReadableStream<Uint8Array> | null): Promise<Buffer> {
  if (body === null) fail("CI_EVIDENCE_INVALID", "Foundation GitHub response body is missing");
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      if (!(result.value instanceof Uint8Array) || result.value.length === 0) {
        fail("CI_EVIDENCE_INVALID", "Foundation GitHub response body is invalid");
      }
      size += result.value.length;
      if (size > MAX_API_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        fail("CI_EVIDENCE_INVALID", "Foundation GitHub response was too large");
      }
      chunks.push(result.value);
    }
    if (size === 0) fail("CI_EVIDENCE_INVALID", "Foundation GitHub response was empty");
    return Buffer.concat(chunks, size);
  } finally {
    reader.releaseLock();
  }
}

function parseRun(value: unknown, options: FoundationCiRetentionOptions): RunIdentity {
  const record = jsonObject(value, "Foundation GitHub workflow run");
  const runId = apiIdentifier(field(record, "id"), "Foundation GitHub workflow run identifier");
  const runApiUrl = `${API_ROOT}/actions/runs/${options.runId}`;
  const runWebUrl = `${WEB_ROOT}/actions/runs/${options.runId}`;
  const repository = jsonObject(
    field(record, "repository"),
    "Foundation GitHub workflow repository",
  );
  const headRepository = jsonObject(
    field(record, "head_repository"),
    "Foundation GitHub workflow head repository",
  );
  const repositoryId = apiIdentifier(
    field(repository, "id"),
    "Foundation GitHub workflow repository identifier",
  );
  const headRepositoryId = apiIdentifier(
    field(headRepository, "id"),
    "Foundation GitHub workflow head repository identifier",
  );
  const repositoryApiUrl = `${API_ROOT}`;
  const repositoryWebUrl = `${WEB_ROOT}`;
  const runStartedAt = githubTimestamp(
    field(record, "run_started_at"),
    "Foundation GitHub workflow start time",
  );
  const updatedAt = githubTimestamp(
    field(record, "updated_at"),
    "Foundation GitHub workflow update time",
  );
  if (
    runId !== options.runId ||
    field(record, "url") !== runApiUrl ||
    field(record, "html_url") !== runWebUrl ||
    field(record, "name") !== "ci" ||
    field(record, "path") !== ".github/workflows/ci.yml" ||
    field(record, "event") !== "push" ||
    field(record, "head_branch") !== "main" ||
    field(record, "head_sha") !== options.confirmCommit ||
    field(record, "run_attempt") !== 1 ||
    field(record, "status") !== "completed" ||
    field(record, "conclusion") !== "success" ||
    repositoryId !== headRepositoryId ||
    field(repository, "full_name") !== REPOSITORY ||
    field(repository, "private") !== false ||
    field(repository, "url") !== repositoryApiUrl ||
    field(repository, "html_url") !== repositoryWebUrl ||
    field(headRepository, "full_name") !== REPOSITORY ||
    field(headRepository, "private") !== false ||
    field(headRepository, "url") !== repositoryApiUrl ||
    field(headRepository, "html_url") !== repositoryWebUrl ||
    runStartedAt > updatedAt
  ) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow run identity is invalid");
  }
  return Object.freeze({
    runStartedAt,
    runApiUrl,
    runId,
    updatedAt,
    runWebUrl,
  });
}

function parseJobs(value: unknown, run: RunIdentity, confirmCommit: string): RetainedJobs {
  const record = jsonObject(value, "Foundation GitHub workflow jobs response");
  if (field(record, "total_count") !== JOB_NAMES.length) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow job set is incomplete");
  }
  const values = exactArray(field(record, "jobs"), "Foundation GitHub workflow jobs", 2);
  if (values.length !== JOB_NAMES.length) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow job set is incomplete");
  }
  const names = new Set<string>();
  const identifiers = new Set<string>();
  const completionTimes: string[] = [];
  for (const value of values) {
    const job = jsonObject(value, "Foundation GitHub workflow job");
    const name = field(job, "name");
    if (name !== "gitleaks-history" && name !== "quality") {
      fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow job identity is invalid");
    }
    const identifier = apiIdentifier(field(job, "id"), "Foundation GitHub workflow job identifier");
    const startedAt = githubTimestamp(
      field(job, "started_at"),
      "Foundation GitHub workflow job start time",
    );
    const completedAt = githubTimestamp(
      field(job, "completed_at"),
      "Foundation GitHub workflow job completion time",
    );
    const jobApiUrl = `${API_ROOT}/actions/jobs/${identifier}`;
    const jobWebUrl = `${run.runWebUrl}/job/${identifier}`;
    if (
      identifiers.has(identifier) ||
      names.has(name) ||
      apiIdentifier(field(job, "run_id"), "Foundation GitHub job run identifier") !== run.runId ||
      field(job, "run_url") !== run.runApiUrl ||
      field(job, "url") !== jobApiUrl ||
      field(job, "html_url") !== jobWebUrl ||
      field(job, "run_attempt") !== 1 ||
      field(job, "workflow_name") !== "ci" ||
      field(job, "head_branch") !== "main" ||
      field(job, "head_sha") !== confirmCommit ||
      field(job, "status") !== "completed" ||
      field(job, "conclusion") !== "success" ||
      startedAt < run.runStartedAt ||
      completedAt < startedAt ||
      completedAt > run.updatedAt
    ) {
      fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow job identity is invalid");
    }
    assertRequiredUserStepsPassed(field(job, "steps"), name);
    identifiers.add(identifier);
    names.add(name);
    completionTimes.push(completedAt);
  }
  if (names.size !== JOB_NAMES.length || JOB_NAMES.some((name) => !names.has(name))) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow job set is incomplete");
  }
  const completedAt = completionTimes.sort().at(-1);
  if (completedAt === undefined) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub workflow job set is incomplete");
  }
  return Object.freeze({
    completedAt,
    jobs: Object.freeze([
      Object.freeze({ conclusion: "success" as const, name: "gitleaks-history" as const }),
      Object.freeze({ conclusion: "success" as const, name: "quality" as const }),
    ]) as RetainedJobs["jobs"],
  });
}

function assertRequiredUserStepsPassed(value: unknown, jobName: FoundationCiJobName): void {
  const steps = exactArray(value, `Foundation GitHub ${jobName} job steps`, 64);
  const requiredNames = REQUIRED_USER_STEP_NAMES[jobName];
  const requiredNameSet = new Set<string>(requiredNames);
  const observed = new Set<string>();

  for (const value of steps) {
    const step = jsonObject(value, `Foundation GitHub ${jobName} job step`);
    const name = field(step, "name");
    if (typeof name !== "string" || name.length === 0 || name.length > 256) {
      fail("CI_EVIDENCE_INVALID", `Foundation GitHub ${jobName} job step name is invalid`);
    }
    if (!requiredNameSet.has(name)) continue;
    if (
      observed.has(name) ||
      field(step, "status") !== "completed" ||
      field(step, "conclusion") !== "success"
    ) {
      fail("CI_EVIDENCE_INVALID", `Foundation GitHub ${jobName} required step did not pass once`);
    }
    observed.add(name);
  }

  if (requiredNames.some((name) => !observed.has(name))) {
    fail("CI_EVIDENCE_INVALID", `Foundation GitHub ${jobName} required step set is incomplete`);
  }
}

function jsonObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("CI_EVIDENCE_INVALID", `${label} must be an object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    fail("CI_EVIDENCE_INVALID", `${label} has an invalid prototype`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length > 256 || keys.some((key) => typeof key !== "string")) {
    fail("CI_EVIDENCE_INVALID", `${label} has invalid fields`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      fail("CI_EVIDENCE_INVALID", `${label} contains an accessor`);
    }
  }
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    fail("CI_EVIDENCE_INVALID", "Foundation GitHub response is missing a required field");
  }
  return descriptor.value;
}

function apiIdentifier(value: unknown, label: string): string {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value <= 0) {
    fail("CI_EVIDENCE_INVALID", `${label} is invalid`);
  }
  return String(value);
}

function githubTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") {
    fail("CI_EVIDENCE_INVALID", `${label} is invalid`);
  }
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/u.exec(value);
  if (match === null) fail("CI_EVIDENCE_INVALID", `${label} is invalid`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) fail("CI_EVIDENCE_INVALID", `${label} is invalid`);
  const normalized = parsed.toISOString();
  const expected = `${match[1]}.${(match[2] ?? "").padEnd(3, "0")}Z`;
  if (normalized !== expected) fail("CI_EVIDENCE_INVALID", `${label} is invalid`);
  return normalized;
}

async function writeAndVerifyEvidence(
  evidence: FoundationCiEvidenceV1,
  outputPath: string,
  repositoryRootValue: string,
): Promise<FoundationCiRetentionResult> {
  const repositoryRoot = await canonicalRepositoryRoot(repositoryRootValue);
  const absolute = validateExternalOutputPath(outputPath, repositoryRoot);
  const parent = await guardCanonicalDirectory(dirname(absolute));
  if ((await lstat(absolute).catch(() => null)) !== null) {
    fail("OUTPUT_FAILED", "Foundation CI evidence output already exists");
  }
  const bytes = Buffer.from(canonicalJson(evidence), "utf8");
  if (bytes.length <= 0 || bytes.length > MAX_OUTPUT_BYTES) {
    bytes.fill(0);
    fail("OUTPUT_FAILED", "Foundation CI evidence output size is invalid");
  }
  let handle: FileHandle | undefined;
  let opened: BigIntStats | undefined;
  try {
    handle = await open(
      absolute,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.nlink !== 1n ||
      opened.uid !== currentUserId(opened.uid) ||
      (Number(opened.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation CI evidence output is unsafe");
    }
    await handle.writeFile(bytes);
    await handle.sync();
    const written = await handle.stat({ bigint: true });
    const pathStats = await lstat(absolute, { bigint: true }).catch(() => undefined);
    if (
      pathStats === undefined ||
      !sameFile(opened, written) ||
      !sameFile(written, pathStats) ||
      written.nlink !== 1n ||
      pathStats.nlink !== 1n ||
      written.size !== BigInt(bytes.length) ||
      pathStats.size !== written.size ||
      (Number(written.mode) & 0o777) !== 0o600 ||
      (Number(pathStats.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation CI evidence changed during publication");
    }
    await assertDirectoryGuard(parent);
    await handle.close();
    handle = undefined;
    await syncDirectory(parent.path);
    await assertDirectoryGuard(parent);

    const retained = await readFoundationCiEvidenceFile(absolute, repositoryRoot);
    const expectedSha256 = foundationCiEvidenceSha256(evidence);
    if (
      retained.sha256 !== expectedSha256 ||
      canonicalJson(retained.evidence) !== canonicalJson(evidence)
    ) {
      fail("OUTPUT_FAILED", "Foundation CI evidence did not verify after publication");
    }
    return Object.freeze({
      evidence: retained.evidence,
      outputPath: absolute,
      sha256: retained.sha256,
    });
  } catch {
    await handle?.close().catch(() => undefined);
    handle = undefined;
    // Once O_EXCL succeeds, retain the inode even if later verification fails. A crash or
    // ambiguous fsync must never be converted into an apparently unused destination.
    return fail("OUTPUT_FAILED", "Foundation CI evidence could not be retained");
  } finally {
    bytes.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

async function canonicalRepositoryRoot(value: string): Promise<string> {
  if (value.length === 0 || value.length > 1_024 || /[\u0000-\u001f\u007f]/u.test(value)) {
    fail("INPUT_INVALID", "Foundation repository root is invalid");
  }
  const root = await realpath(resolve(value)).catch(() => "");
  const stats = root === "" ? null : await lstat(root).catch(() => null);
  if (root === "" || stats === null || !stats.isDirectory() || stats.isSymbolicLink()) {
    fail("INPUT_INVALID", "Foundation repository root is invalid");
  }
  return root;
}

function validateExternalOutputPath(path: string, repositoryRoot: string): string {
  validateOutputPathShape(path);
  const within = relative(repositoryRoot, path);
  if (within === "" || (!within.startsWith(`..${sep}`) && within !== ".." && !isAbsolute(within))) {
    fail("INPUT_INVALID", "Foundation CI evidence output must remain outside the repository");
  }
  return path;
}

function validateOutputPathShape(path: string): string {
  if (
    path.length === 0 ||
    path.length > 1_024 ||
    !isAbsolute(path) ||
    resolve(path) !== path ||
    !path.endsWith(".json") ||
    /[\u0000-\u001f\u007f]/u.test(path)
  ) {
    fail("INPUT_INVALID", "Foundation CI evidence output path is invalid");
  }
  return path;
}

async function guardCanonicalDirectory(path: string): Promise<DirectoryGuard> {
  const stats = await lstat(path, { bigint: true }).catch(() => null);
  const uid =
    stats === null || typeof process.getuid !== "function" ? stats?.uid : BigInt(process.getuid());
  if (
    stats === null ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.uid !== uid ||
    (Number(stats.mode) & 0o077) !== 0 ||
    (await realpath(path).catch(() => "")) !== path
  ) {
    fail("INPUT_INVALID", "Foundation CI evidence parent is not an owner-only canonical directory");
  }
  return Object.freeze({
    device: stats.dev,
    inode: stats.ino,
    mode: Number(stats.mode) & 0o777,
    path,
    uid: stats.uid,
  });
}

async function assertDirectoryGuard(guard: DirectoryGuard): Promise<void> {
  const stats = await lstat(guard.path, { bigint: true }).catch(() => undefined);
  if (
    stats === undefined ||
    !stats.isDirectory() ||
    stats.dev !== guard.device ||
    stats.ino !== guard.inode ||
    stats.uid !== guard.uid ||
    (Number(stats.mode) & 0o777) !== guard.mode ||
    (await realpath(guard.path).catch(() => "")) !== guard.path
  ) {
    fail("INPUT_INVALID", "Foundation CI evidence directory changed during publication");
  }
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.isFile() && right.isFile() && left.dev === right.dev && left.ino === right.ino;
}

function currentUserId(fallback: bigint): bigint {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : fallback;
}

async function syncDirectory(path: string): Promise<void> {
  let directory: FileHandle | undefined;
  try {
    directory = await open(
      path,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    await directory.sync();
  } catch {
    fail("OUTPUT_FAILED", "Foundation CI evidence directory sync failed");
  } finally {
    await directory?.close().catch(() => undefined);
  }
}
