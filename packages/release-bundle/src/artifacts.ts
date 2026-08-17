import { Buffer } from "node:buffer";

import {
  canonicalJson,
  copyInputBytes,
  exactArray,
  exactObject,
  sha256,
  validateGitHash,
  validateHash,
  validateSafeInteger,
  validateTimestamp,
} from "./canonical.js";
import { fail } from "./errors.js";
import type {
  ReleaseArtifactBindingsV1,
  ReleaseArtifactDescriptorV1,
  ReleaseArtifactInputV1,
  ReleaseArtifactMediaType,
  ReleaseArtifactRole,
} from "./types.js";

export const MAX_ARTIFACT_COUNT = 2_048;
export const MAX_TOTAL_ARTIFACT_BYTES = 32 * 1024 * 1024;

const ROLE_LIMITS: Readonly<Record<ReleaseArtifactRole, number>> = Object.freeze({
  "config-schema": 512 * 1024,
  lockfile: 4 * 1024 * 1024,
  "recovery-procedure": 512 * 1024,
  runbook: 512 * 1024,
  sbom: 4 * 1024 * 1024,
  source: 1024 * 1024,
  "test-summary": 1024 * 1024,
});

export const REQUIRED_CONFIG_SCHEMA_NAMES = Object.freeze([
  "alert-outbox",
  "backup-manifest",
  "capture-registry",
  "checkpoint-journal",
  "event-state",
  "external-anchor-outbox",
  "observer-config",
  "operations-state",
  "preflight-report",
  "public-projection",
  "sanitized-event-archive",
  "sanitized-state-evidence",
  "session-controller",
  "session-lifecycle",
  "source-contracts",
  "vault",
] as const);

export const REQUIRED_TEST_CHECKS = Object.freeze([
  "actions-pinned",
  "contract-traceability",
  "dependency-audit",
  "format",
  "full-history-secret-scan",
  "generated-files",
  "offline-drills",
  "offline-demos",
  "release-inventory",
  "test",
  "typecheck",
  "working-tree-clean",
] as const);

const REQUIRED_SOURCE_PATHS = Object.freeze([
  "source/package.json",
  "source/pnpm-workspace.yaml",
  "source/tsconfig.json",
] as const);
const REQUIRED_RUNBOOK_PATH = "runbooks/README.md";
const REQUIRED_RECOVERY_PATH = "recovery/observer-restore.md";
const LOCKFILE_PATH = "source/pnpm-lock.yaml";
const SBOM_PATH = "release/sbom.cdx.json";
const TEST_SUMMARY_PATH = "release/test-summary.v1.json";
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FORBIDDEN_SOURCE_SEGMENTS = new Set([
  "build",
  "coverage",
  "dist",
  "node_modules",
  "temp",
  "tmp",
]);
const SOURCE_ROOT_PATHS = new Set([
  "source/AGENTS.md",
  "source/LICENSE",
  "source/README.md",
  "source/package.json",
  "source/pnpm-workspace.yaml",
  "source/tsconfig.json",
  "source/vitest.config.ts",
]);
const SOURCE_EXTENSION_PATTERN = /\.(?:cjs|css|html|js|json|md|mjs|sql|toml|ts|tsx|txt|yaml|yml)$/;
const RUNTIME_SOURCE_PATTERN =
  /^source\/(?:apps|packages)\/[a-z0-9][a-z0-9-]{0,62}\/.+\.(?:cjs|js|mjs|ts|tsx)$/;
const SECRET_PATTERNS = Object.freeze([
  /-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u,
  /\bAIza[0-9A-Za-z_-]{30,}\b/u,
  /\bsk-[A-Za-z0-9_-]{20,}\b/u,
  /https?:\/\/[^\s/@:]+:[^\s/@]+@[^\s/]+/iu,
  new RegExp(["LS0tLS1CRUdJTi", "BQUklWQVRFIEtFWS0tLS0t"].join(""), "u"),
  /LS0tLS1CRUdJTi[A-Za-z0-9+/_=-]{0,32}UFJJVkFURSBLRVk/u,
  /\b(?:password|passphrase|privateKey|apiKey|accessToken|refreshToken|mnemonic|seedPhrase)\s*[:=]\s*["'][^"']{8,}["']/iu,
]);
const SENSITIVE_JSON_KEY =
  /^(?:api[-_]?key|access[-_]?token|credential|mnemonic|password|passphrase|private[-_]?key|refresh[-_]?token|secret|seed[-_]?phrase)$/i;

export interface NormalizedReleaseArtifact {
  readonly bytes: Buffer;
  readonly descriptor: ReleaseArtifactDescriptorV1;
}

export interface NormalizedArtifactSet {
  readonly artifacts: readonly NormalizedReleaseArtifact[];
  readonly bindings: ReleaseArtifactBindingsV1;
  readonly totalArtifactBytes: number;
}

export function deriveReleaseArtifactBindings(artifactsValue: unknown): ReleaseArtifactBindingsV1 {
  return normalizeReleaseArtifacts(artifactsValue).bindings;
}

export function normalizeReleaseArtifacts(artifactsValue: unknown): NormalizedArtifactSet {
  const values = exactArray(artifactsValue, "Release artifacts");
  if (values.length === 0 || values.length > MAX_ARTIFACT_COUNT) {
    fail("POLICY_VIOLATION", "Release artifact count is outside its bound");
  }
  const normalized = values.map((value) => normalizeArtifact(value));
  normalized.sort((left, right) => compareAscii(left.descriptor.path, right.descriptor.path));
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1]!.descriptor.path === normalized[index]!.descriptor.path) {
      fail("POLICY_VIOLATION", "Release artifact paths must be unique");
    }
  }
  const totalArtifactBytes = normalized.reduce((total, artifact) => {
    const next = total + artifact.bytes.length;
    if (!Number.isSafeInteger(next) || next > MAX_TOTAL_ARTIFACT_BYTES) {
      fail("ARCHIVE_BOUNDS", "Release artifact total exceeds its bound");
    }
    return next;
  }, 0);
  assertClosedArtifactPolicy(normalized);
  const descriptors = normalized.map(({ descriptor }) => descriptor);
  const bindings = bindingsFor(descriptors);
  return Object.freeze({
    artifacts: Object.freeze(normalized),
    bindings,
    totalArtifactBytes,
  });
}

function normalizeArtifact(value: unknown): NormalizedReleaseArtifact {
  const record = exactObject(value, ["bytes", "mediaType", "path", "role"], "Release artifact");
  const role = validateRole(record.role);
  const path = validateArtifactPath(record.path, role);
  const mediaType = validateMediaType(record.mediaType, role, path);
  const bytes = copyInputBytes(record.bytes, "Release artifact bytes", ROLE_LIMITS[role]);
  const text = validateText(bytes);
  scanContent(path, text);
  validateRoleContent(role, path, text);
  return Object.freeze({
    bytes,
    descriptor: Object.freeze({
      mediaType,
      path,
      role,
      sha256: sha256(bytes),
      sizeBytes: bytes.length,
    }),
  });
}

function validateRole(value: unknown): ReleaseArtifactRole {
  const roles: readonly ReleaseArtifactRole[] = [
    "config-schema",
    "lockfile",
    "recovery-procedure",
    "runbook",
    "sbom",
    "source",
    "test-summary",
  ];
  if (typeof value !== "string" || !roles.includes(value as ReleaseArtifactRole)) {
    fail("INPUT_INVALID", "Release artifact role is unsupported");
  }
  return value as ReleaseArtifactRole;
}

function validateArtifactPath(value: unknown, role: ReleaseArtifactRole): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 240 ||
    value.normalize("NFC") !== value ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail("POLICY_VIOLATION", "Release artifact path is unsafe");
  }
  const segments = value.split("/");
  if (
    segments.length < 2 ||
    segments.some(
      (segment) =>
        segment === "." ||
        segment === ".." ||
        segment.startsWith(".") ||
        (role === "source" && FORBIDDEN_SOURCE_SEGMENTS.has(segment)) ||
        !PATH_SEGMENT_PATTERN.test(segment),
    )
  ) {
    fail("POLICY_VIOLATION", "Release artifact path is unsafe");
  }
  if (!pathAllowedForRole(value, role)) {
    fail("POLICY_VIOLATION", "Release artifact path is not allowlisted for its role");
  }
  return value;
}

function pathAllowedForRole(path: string, role: ReleaseArtifactRole): boolean {
  switch (role) {
    case "lockfile":
      return path === LOCKFILE_PATH;
    case "config-schema":
      return REQUIRED_CONFIG_SCHEMA_NAMES.some(
        (name) => path === `config-schemas/${name}.schema.json`,
      );
    case "runbook":
      return (
        path === REQUIRED_RUNBOOK_PATH ||
        /^runbooks\/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.md$/.test(path)
      );
    case "recovery-procedure":
      return (
        path === REQUIRED_RECOVERY_PATH || /^recovery\/[a-z0-9][a-z0-9-]{0,62}\.md$/.test(path)
      );
    case "sbom":
      return path === SBOM_PATH;
    case "test-summary":
      return path === TEST_SUMMARY_PATH;
    case "source":
      if (path === LOCKFILE_PATH || !SOURCE_EXTENSION_PATTERN.test(path)) return false;
      if (SOURCE_ROOT_PATHS.has(path)) return true;
      return /^(?:source\/(?:apps|packages)\/[a-z0-9][a-z0-9-]{0,62}|source\/scripts)\/.+/.test(
        path,
      );
  }
}

function validateMediaType(
  value: unknown,
  role: ReleaseArtifactRole,
  path: string,
): ReleaseArtifactMediaType {
  const expected = expectedMediaType(role, path);
  if (value !== expected) fail("POLICY_VIOLATION", "Release artifact media type is invalid");
  return expected;
}

function expectedMediaType(role: ReleaseArtifactRole, path: string): ReleaseArtifactMediaType {
  if (role === "config-schema" || role === "sbom" || role === "test-summary") {
    return "application/json";
  }
  if (role === "lockfile" || /\.ya?ml$/.test(path)) return "application/yaml";
  if (role === "runbook" || role === "recovery-procedure" || path.endsWith(".md")) {
    return "text/markdown";
  }
  if (/\.tsx?$/.test(path)) return "text/typescript";
  if (path.endsWith(".json")) return "application/json";
  return "text/plain";
}

function validateText(bytes: Buffer): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("POLICY_VIOLATION", "Release artifacts must contain valid UTF-8 text");
  }
  if (
    text.length === 0 ||
    text.normalize("NFC") !== text ||
    text.includes("\r") ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)
  ) {
    fail("POLICY_VIOLATION", "Release artifact text is not canonical sanitized text");
  }
  return text;
}

function validateRoleContent(role: ReleaseArtifactRole, path: string, text: string): void {
  if (role === "source" && path.endsWith(".json")) parseJson(text, false);
  if (role === "config-schema") validateConfigSchema(path, text);
  if (role === "sbom") validateSbom(text);
  if (role === "test-summary") validateTestSummary(text);
  if (role === "runbook" && path === REQUIRED_RUNBOOK_PATH) {
    for (let index = 1; index <= 19; index += 1) {
      const marker = `RB-${String(index).padStart(2, "0")}`;
      if (!text.includes(marker))
        fail("POLICY_VIOLATION", "Required recovery runbook is incomplete");
    }
  }
  if (role === "recovery-procedure" && path === REQUIRED_RECOVERY_PATH) {
    for (const marker of [
      "RSI-RECOVERY-PROCEDURE-V1",
      "VERIFY-BEFORE-RESTORE",
      "NO-SECRET-RESTORE",
      "NEW-LINEAGE-REQUIRED",
    ]) {
      if (!text.includes(marker)) {
        fail("POLICY_VIOLATION", "Required observer recovery procedure is incomplete");
      }
    }
  }
}

function validateConfigSchema(path: string, text: string): void {
  const value = parseJson(text, true);
  const record = exactObject(
    value,
    ["name", "schema", "schemaType", "schemaVersion"],
    "Versioned configuration schema",
  );
  const expectedName = path.slice("config-schemas/".length, -".schema.json".length);
  if (
    record.schemaType !== "rsi.versioned-config-schema" ||
    record.name !== expectedName ||
    record.schemaVersion !== 1
  ) {
    fail("POLICY_VIOLATION", "Versioned configuration schema identity is invalid");
  }
  if (record.schema === null || typeof record.schema !== "object" || Array.isArray(record.schema)) {
    fail("POLICY_VIOLATION", "Versioned configuration schema body is invalid");
  }
}

function validateSbom(text: string): void {
  const value = parseJson(text, true);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("POLICY_VIOLATION", "Release SBOM identity is invalid");
  }
  const record = value as Record<string, unknown>;
  if (
    record.bomFormat !== "CycloneDX" ||
    (record.specVersion !== "1.5" && record.specVersion !== "1.6") ||
    record.version !== 1
  ) {
    fail("POLICY_VIOLATION", "Release SBOM identity is invalid");
  }
}

function validateTestSummary(text: string): void {
  const value = parseJson(text, true);
  const record = exactObject(
    value,
    ["commitSha", "completedAt", "requiredChecks", "summaryType", "version"],
    "Release test summary",
  );
  if (record.summaryType !== "rsi.release.test-summary" || record.version !== 1) {
    fail("POLICY_VIOLATION", "Release test summary identity is invalid");
  }
  validateGitHash(record.commitSha, "Test-summary commit");
  validateTimestamp(record.completedAt, "Test-summary completion time");
  const checks = exactArray(record.requiredChecks, "Required test checks");
  if (checks.length !== REQUIRED_TEST_CHECKS.length) {
    fail("POLICY_VIOLATION", "Release test summary check set is incomplete");
  }
  for (let index = 0; index < REQUIRED_TEST_CHECKS.length; index += 1) {
    const check = exactObject(checks[index], ["name", "outcome", "resultSha256"], "Test check");
    if (check.name !== REQUIRED_TEST_CHECKS[index] || check.outcome !== "passed") {
      fail("POLICY_VIOLATION", "Release test summary contains a failed or unknown check");
    }
    validateHash(check.resultSha256, "Test-check result hash");
  }
}

function parseJson(text: string, requireCanonical: boolean): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    fail("POLICY_VIOLATION", "Release JSON artifact is invalid");
  }
  if (requireCanonical && canonicalJson(value) !== text) {
    fail("POLICY_VIOLATION", "Release JSON artifact must use canonical JSON");
  }
  scanJsonKeys(value, 0);
  return value;
}

function scanJsonKeys(value: unknown, depth: number): void {
  if (depth > 32) fail("POLICY_VIOLATION", "Release JSON artifact is too deeply nested");
  if (Array.isArray(value)) {
    for (const entry of value) scanJsonKeys(entry, depth + 1);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_JSON_KEY.test(key)) {
      fail("SECRET_DETECTED", "Release artifact contains a forbidden secret-bearing field");
    }
    scanJsonKeys(entry, depth + 1);
  }
}

function scanContent(path: string, text: string): void {
  if (
    path
      .split("/")
      .some((segment) =>
        /^(?:\.env(?:\..+)?|id_ed25519|id_rsa|.*\.(?:key|keystore|p12|pem|pfx))$/i.test(segment),
      ) ||
    SECRET_PATTERNS.some((pattern) => pattern.test(text))
  ) {
    fail("SECRET_DETECTED", "Release artifact failed the embedded secret scan");
  }
}

function assertClosedArtifactPolicy(artifacts: readonly NormalizedReleaseArtifact[]): void {
  const byPath = new Map(artifacts.map((artifact) => [artifact.descriptor.path, artifact]));
  for (const path of [
    ...REQUIRED_SOURCE_PATHS,
    LOCKFILE_PATH,
    REQUIRED_RUNBOOK_PATH,
    REQUIRED_RECOVERY_PATH,
    SBOM_PATH,
    TEST_SUMMARY_PATH,
  ]) {
    if (!byPath.has(path)) fail("POLICY_VIOLATION", "Release artifact set is incomplete");
  }
  for (const name of REQUIRED_CONFIG_SCHEMA_NAMES) {
    if (!byPath.has(`config-schemas/${name}.schema.json`)) {
      fail("POLICY_VIOLATION", "Release configuration-schema set is incomplete");
    }
  }
  if (
    !artifacts.some(
      ({ descriptor }) =>
        descriptor.role === "source" && RUNTIME_SOURCE_PATTERN.test(descriptor.path),
    )
  ) {
    fail("POLICY_VIOLATION", "Release artifact set has no runtime source file");
  }
  const singletonRoles: readonly ReleaseArtifactRole[] = ["lockfile", "sbom", "test-summary"];
  for (const role of singletonRoles) {
    if (artifacts.filter(({ descriptor }) => descriptor.role === role).length !== 1) {
      fail("POLICY_VIOLATION", "Release singleton artifact role is invalid");
    }
  }
}

function bindingsFor(
  descriptors: readonly ReleaseArtifactDescriptorV1[],
): ReleaseArtifactBindingsV1 {
  const forRoles = (domain: string, roles: readonly ReleaseArtifactRole[]): string =>
    sha256(
      `${domain}\0${canonicalJson(descriptors.filter((descriptor) => roles.includes(descriptor.role)))}`,
    );
  const findOne = (role: ReleaseArtifactRole): ReleaseArtifactDescriptorV1 => {
    const matches = descriptors.filter((descriptor) => descriptor.role === role);
    if (matches.length !== 1) fail("POLICY_VIOLATION", "Release singleton binding is invalid");
    return matches[0]!;
  };
  const configSchemas = descriptors
    .filter((descriptor) => descriptor.role === "config-schema")
    .map((descriptor) =>
      Object.freeze({
        name: descriptor.path.slice("config-schemas/".length, -".schema.json".length),
        schemaSha256: descriptor.sha256,
        version: 1,
      }),
    );
  const backupCompatibleConfigArtifact = Object.freeze({
    configSchemaHashesType: "rsi.backup.config-schema-hashes",
    schemas: Object.freeze(configSchemas),
    version: 1,
  });
  return Object.freeze({
    artifactSetSha256: sha256(`rsi-release-artifact-set-v1\0${canonicalJson(descriptors)}`),
    configSetSha256: sha256(canonicalJson(backupCompatibleConfigArtifact)),
    lockfileSha256: findOne("lockfile").sha256,
    recoverySetSha256: forRoles("rsi-release-recovery-set-v1", ["recovery-procedure"]),
    runbookSetSha256: forRoles("rsi-release-runbook-set-v1", ["runbook"]),
    sbomSha256: findOne("sbom").sha256,
    sourceTreeSha256: forRoles("rsi-release-source-tree-v1", ["lockfile", "source"]),
    testSummarySha256: findOne("test-summary").sha256,
  });
}

export function parseArtifactDescriptors(value: unknown): readonly ReleaseArtifactDescriptorV1[] {
  const values = exactArray(value, "Release artifact descriptors");
  if (values.length === 0 || values.length > MAX_ARTIFACT_COUNT) {
    fail("ARCHIVE_BOUNDS", "Release artifact descriptor count is outside its bound");
  }
  const descriptors = values.map((entry) => {
    const record = exactObject(
      entry,
      ["mediaType", "path", "role", "sha256", "sizeBytes"],
      "Release artifact descriptor",
    );
    const role = validateRole(record.role);
    const path = validateArtifactPath(record.path, role);
    const mediaType = validateMediaType(record.mediaType, role, path);
    return Object.freeze({
      mediaType,
      path,
      role,
      sha256: validateHash(record.sha256, "Release artifact hash"),
      sizeBytes: validateSafeInteger(
        record.sizeBytes,
        "Release artifact size",
        1,
        ROLE_LIMITS[role],
      ),
    });
  });
  const sorted = [...descriptors].sort((left, right) => compareAscii(left.path, right.path));
  if (sorted.some((descriptor, index) => descriptor.path !== descriptors[index]!.path)) {
    fail("ARCHIVE_FORMAT", "Release artifact descriptors are not canonically ordered");
  }
  if (
    descriptors.some(
      (descriptor, index) => index > 0 && descriptors[index - 1]!.path === descriptor.path,
    )
  ) {
    fail("ARCHIVE_FORMAT", "Release artifact descriptor paths are duplicated");
  }
  let total = 0;
  for (const descriptor of descriptors) {
    total += descriptor.sizeBytes;
    if (!Number.isSafeInteger(total) || total > MAX_TOTAL_ARTIFACT_BYTES) {
      fail("ARCHIVE_BOUNDS", "Release artifact descriptor total exceeds its bound");
    }
  }
  return Object.freeze(descriptors);
}

export function validateDecodedArtifactSet(
  descriptors: readonly ReleaseArtifactDescriptorV1[],
  bytesByPath: ReadonlyMap<string, Buffer>,
): NormalizedArtifactSet {
  const inputs: ReleaseArtifactInputV1[] = descriptors.map((descriptor) => {
    const bytes = bytesByPath.get(descriptor.path);
    if (bytes === undefined) fail("ARCHIVE_FORMAT", "Release artifact is missing");
    return {
      bytes: new Uint8Array(bytes),
      mediaType: descriptor.mediaType,
      path: descriptor.path,
      role: descriptor.role,
    };
  });
  const normalized = normalizeReleaseArtifacts(inputs);
  if (
    normalized.artifacts.some(
      (artifact, index) => canonicalJson(artifact.descriptor) !== canonicalJson(descriptors[index]),
    )
  ) {
    fail("INTEGRITY_MISMATCH", "Release artifact descriptors do not match decoded bytes");
  }
  return normalized;
}

export function validateReleaseArtifactSemantics(
  artifacts: readonly NormalizedReleaseArtifact[],
  release: {
    readonly commitSha: string;
    readonly createdAt: string;
    readonly nodeVersion: string;
    readonly pnpmVersion: string;
    readonly releaseVersion: string;
  },
): void {
  const getText = (path: string): string => {
    const artifact = artifacts.find(({ descriptor }) => descriptor.path === path);
    if (artifact === undefined) fail("POLICY_VIOLATION", "Required release artifact is missing");
    return artifact.bytes.toString("utf8");
  };
  const packageValue = parseJson(getText("source/package.json"), false);
  if (packageValue === null || typeof packageValue !== "object" || Array.isArray(packageValue)) {
    fail("POLICY_VIOLATION", "Root package metadata is invalid");
  }
  const packageRecord = packageValue as Record<string, unknown>;
  const engines = packageRecord.engines;
  if (
    packageRecord.name !== "rsi" ||
    packageRecord.private !== true ||
    packageRecord.type !== "module" ||
    packageRecord.version !== release.releaseVersion ||
    packageRecord.packageManager !== `pnpm@${release.pnpmVersion}` ||
    engines === null ||
    typeof engines !== "object" ||
    Array.isArray(engines) ||
    (engines as Record<string, unknown>).node !== release.nodeVersion ||
    (engines as Record<string, unknown>).pnpm !== release.pnpmVersion
  ) {
    fail("POLICY_VIOLATION", "Root package runtime binding is invalid");
  }
  const summary = parseJson(getText(TEST_SUMMARY_PATH), true) as Record<string, unknown>;
  if (
    summary.commitSha !== release.commitSha ||
    (summary.completedAt as string) > release.createdAt
  ) {
    fail("POLICY_VIOLATION", "Test summary is not bound to the release identity");
  }
  const sbom = parseJson(getText(SBOM_PATH), true) as Record<string, unknown>;
  const metadata = sbom.metadata;
  const component =
    metadata !== null && typeof metadata === "object" && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>).component
      : undefined;
  if (
    component === null ||
    typeof component !== "object" ||
    Array.isArray(component) ||
    (component as Record<string, unknown>).name !== "rsi" ||
    (component as Record<string, unknown>).type !== "application" ||
    (component as Record<string, unknown>).version !== release.releaseVersion
  ) {
    fail("POLICY_VIOLATION", "SBOM is not bound to the release version");
  }
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
