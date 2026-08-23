import { types as utilTypes } from "node:util";

import {
  canonicalJson,
  exactArray,
  exactObject,
  sha256,
  validateCanonicalTimestamp,
  validateGitHash,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";
import type { KeychainHelperEvidenceV1 } from "./types.js";

/**
 * Historical v1 evidence remains parseable for audit and lineage inspection.
 * Its assertions do not confer provisioning or custody authority; every
 * production secret path independently hard-refuses this helper generation.
 */
export const RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH =
  "config/foundation-release-key-helper-compatibility.v1.json" as const;
export const RELEASE_KEY_HELPER_PATH =
  "packages/release-key-provisioning/native/keychain-helper.swift" as const;
export const RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_TYPE =
  "rsi.release-key-helper-compatibility-evidence" as const;
export const RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_VERSION = 1 as const;
export const RELEASE_KEY_HELPER_COMPATIBILITY_NODE_VERSION = "v24.19.0" as const;
export const RELEASE_KEY_HELPER_COMPATIBILITY_PNPM_VERSION = "11.20.0" as const;

const MAX_EVIDENCE_BYTES = 64 * 1024;
const MACOS_BUILD_PATTERN = /^\d{2}[A-Z]\d{1,6}[a-z]?$/u;
const MACOS_PRODUCT_VERSION_PATTERN = /^\d{1,2}\.\d{1,2}(?:\.\d{1,2})?$/u;

export const RELEASE_KEY_HELPER_PRIVATE_LEAK_SCAN_SCOPES = Object.freeze([
  "process-arguments",
  "process-environment",
  "standard-output",
  "standard-error",
  "logs-and-diagnostics",
  "filesystem-artifacts",
] as const);

export type ReleaseKeyHelperPrivateLeakScanScopeName =
  (typeof RELEASE_KEY_HELPER_PRIVATE_LEAK_SCAN_SCOPES)[number];

export interface ReleaseKeyHelperCompatibilityEnvironmentV1 {
  readonly architecture: "arm64" | "x64";
  readonly hardwareClass: "MacBook";
  readonly macosBuildVersion: string;
  readonly macosProductVersion: string;
  readonly nodeVersion: typeof RELEASE_KEY_HELPER_COMPATIBILITY_NODE_VERSION;
  readonly pnpmVersion: typeof RELEASE_KEY_HELPER_COMPATIBILITY_PNPM_VERSION;
}

export interface ReleaseKeyHelperCompatibilityPromptV1 {
  readonly attempt: 1 | 2;
  readonly evidenceSha256: string;
  readonly freshHelperProcess: "verified";
  readonly outcome: "user-presence-prompt-observed-and-approved-once";
  readonly scenario:
    "first-fresh-helper-invocation" | "second-fresh-helper-invocation-after-first-completed";
  readonly signatureVerification: "passed";
}

export interface ReleaseKeyHelperKeychainControlsV1 {
  readonly accessibility: "when-unlocked-this-device-only";
  readonly dataProtectionKeychain: "verified";
  readonly evidenceSha256: string;
  readonly persistentApproval: "not-granted";
  readonly synchronizable: "disabled";
  readonly unauthorizedAlternateClientAccess: "refused";
  readonly userPresence: "required";
}

export interface ReleaseKeyHelperPrivateLeakScanScopeV1 {
  readonly name: ReleaseKeyHelperPrivateLeakScanScopeName;
  readonly outcome: "passed";
}

export interface ReleaseKeyHelperPrivateLeakScanV1 {
  readonly evidenceSha256: string;
  readonly outcome: "passed";
  readonly scopes: readonly ReleaseKeyHelperPrivateLeakScanScopeV1[];
}

export interface ReleaseKeyHelperCleanupV1 {
  readonly evidenceSha256: string;
  readonly keychainItem: "deleted-and-absence-verified";
  readonly outcome: "passed";
  readonly temporaryArtifacts: "removed-and-absence-verified";
  readonly testPrivateMaterial: "destroyed-and-absence-verified";
}

export interface ReleaseKeyHelperIndependentApprovalV1 {
  readonly approvedAt: string;
  readonly approvalEvidenceSha256: string;
  readonly authorship: "did-not-author-tested-helper-or-evidence";
  readonly drillParticipation: "did-not-operate-drill";
  readonly reviewerId: string;
  readonly reviewerRole: "independent-non-authoring-reviewer";
  readonly verdict: "approved";
}

export interface ReleaseKeyHelperCompatibilityEvidenceV1 {
  readonly cleanup: ReleaseKeyHelperCleanupV1;
  readonly completedAt: string;
  readonly drillId: string;
  readonly drillOperatorId: string;
  readonly environment: ReleaseKeyHelperCompatibilityEnvironmentV1;
  readonly evidencePath: typeof RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH;
  readonly evidenceType: typeof RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_TYPE;
  readonly helper: KeychainHelperEvidenceV1;
  readonly helperPath: typeof RELEASE_KEY_HELPER_PATH;
  readonly independentApproval: ReleaseKeyHelperIndependentApprovalV1;
  readonly keychainControls: ReleaseKeyHelperKeychainControlsV1;
  readonly privateMaterialLeakScan: ReleaseKeyHelperPrivateLeakScanV1;
  readonly prompts: readonly [
    ReleaseKeyHelperCompatibilityPromptV1,
    ReleaseKeyHelperCompatibilityPromptV1,
  ];
  readonly repository: "tyler-james-bridges/rsi";
  readonly repositoryVisibility: "public";
  readonly testedCommitSha: string;
  readonly verdict: "passed";
  readonly version: typeof RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_VERSION;
}

export interface ReleaseKeyHelperCompatibilityRepositoryBindings {
  /** Calculated by the host with Git's ancestry rules, never inferred from evidence content. */
  readonly testedCommitIsAncestorOfCurrentCommit: boolean;
  /** SHA-256 of the helper source blob at the current repository commit. */
  readonly currentHelperSourceSha256: string;
  /** SHA-256 of the helper source blob at the commit on which the drill ran. */
  readonly testedHelperSourceSha256: string;
}

export interface ReleaseKeyHelperCompatibilityRuntimeBindings {
  /** Evidence captured from the exact helper executable about to be used. */
  readonly helper: KeychainHelperEvidenceV1;
  readonly architecture: "arm64" | "x64";
  readonly macosBuildVersion: string;
  readonly macosProductVersion: string;
  readonly nodeVersion: string;
  readonly pnpmVersion: string;
}

export function parseReleaseKeyHelperCompatibilityEvidence(
  value: unknown,
): ReleaseKeyHelperCompatibilityEvidenceV1 {
  const record = exactObject(
    value,
    [
      "cleanup",
      "completedAt",
      "drillId",
      "drillOperatorId",
      "environment",
      "evidencePath",
      "evidenceType",
      "helper",
      "helperPath",
      "independentApproval",
      "keychainControls",
      "privateMaterialLeakScan",
      "prompts",
      "repository",
      "repositoryVisibility",
      "testedCommitSha",
      "verdict",
      "version",
    ],
    "Release-key helper compatibility evidence",
  );
  if (
    record.evidencePath !== RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH ||
    record.evidenceType !== RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_TYPE ||
    record.helperPath !== RELEASE_KEY_HELPER_PATH ||
    record.repository !== "tyler-james-bridges/rsi" ||
    record.repositoryVisibility !== "public" ||
    record.verdict !== "passed" ||
    record.version !== RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_VERSION
  ) {
    fail("VERIFICATION_FAILED", "Release-key helper compatibility verdict is invalid");
  }

  const completedAt = validateCanonicalTimestamp(
    record.completedAt,
    "Compatibility completion time",
  );
  const drillOperatorId = validateIdentifier(
    record.drillOperatorId,
    "Compatibility drill operator ID",
  );
  const independentApproval = parseIndependentApproval(record.independentApproval);
  if (independentApproval.reviewerId === drillOperatorId) {
    fail("VERIFICATION_FAILED", "Compatibility approval is not independent of the drill operator");
  }
  if (Date.parse(independentApproval.approvedAt) < Date.parse(completedAt)) {
    fail("VERIFICATION_FAILED", "Compatibility approval predates drill completion");
  }

  return Object.freeze({
    cleanup: parseCleanup(record.cleanup),
    completedAt,
    drillId: validateIdentifier(record.drillId, "Compatibility drill ID"),
    drillOperatorId,
    environment: parseEnvironment(record.environment),
    evidencePath: RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
    evidenceType: RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_TYPE,
    helper: parseHelperEvidence(record.helper),
    helperPath: RELEASE_KEY_HELPER_PATH,
    independentApproval,
    keychainControls: parseKeychainControls(record.keychainControls),
    privateMaterialLeakScan: parsePrivateMaterialLeakScan(record.privateMaterialLeakScan),
    prompts: parsePrompts(record.prompts),
    repository: "tyler-james-bridges/rsi",
    repositoryVisibility: "public",
    testedCommitSha: validateGitHash(record.testedCommitSha, "Compatibility tested commit"),
    verdict: "passed",
    version: RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_VERSION,
  });
}

export function decodeReleaseKeyHelperCompatibilityEvidence(
  value: Uint8Array,
): ReleaseKeyHelperCompatibilityEvidenceV1 {
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_EVIDENCE_BYTES
  ) {
    fail("INPUT_INVALID", "Release-key helper compatibility evidence bytes are invalid");
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", "Release-key helper compatibility evidence is not valid JSON");
  }
  const evidence = parseReleaseKeyHelperCompatibilityEvidence(parsed);
  if (canonicalJson(evidence) !== text) {
    fail("INPUT_INVALID", "Release-key helper compatibility evidence is not canonical JSON");
  }
  return evidence;
}

export function releaseKeyHelperCompatibilityEvidenceSha256(
  value: ReleaseKeyHelperCompatibilityEvidenceV1,
): string {
  return sha256(canonicalJson(parseReleaseKeyHelperCompatibilityEvidence(value)));
}

export function assertReleaseKeyHelperCompatibilityRepositoryBindings(
  evidence: ReleaseKeyHelperCompatibilityEvidenceV1,
  bindings: ReleaseKeyHelperCompatibilityRepositoryBindings,
): void {
  const parsed = parseReleaseKeyHelperCompatibilityEvidence(evidence);
  const bindingRecord = exactObject(
    bindings,
    [
      "currentHelperSourceSha256",
      "testedCommitIsAncestorOfCurrentCommit",
      "testedHelperSourceSha256",
    ],
    "Compatibility repository bindings",
  );
  const actualSource = validateHash(
    bindingRecord.currentHelperSourceSha256,
    "Current helper source hash",
  );
  const testedSource = validateHash(
    bindingRecord.testedHelperSourceSha256,
    "Tested helper source hash",
  );
  if (
    bindingRecord.testedCommitIsAncestorOfCurrentCommit !== true ||
    actualSource !== parsed.helper.sourceSha256 ||
    testedSource !== parsed.helper.sourceSha256
  ) {
    fail("REPOSITORY_STATE", "Repository is not descended from the tested helper source");
  }
}

export function assertReleaseKeyHelperCompatibilityRuntimeBindings(
  evidence: ReleaseKeyHelperCompatibilityEvidenceV1,
  bindings: ReleaseKeyHelperCompatibilityRuntimeBindings,
): void {
  const parsed = parseReleaseKeyHelperCompatibilityEvidence(evidence);
  const bindingRecord = exactObject(
    bindings,
    [
      "architecture",
      "helper",
      "macosBuildVersion",
      "macosProductVersion",
      "nodeVersion",
      "pnpmVersion",
    ],
    "Compatibility runtime bindings",
  );
  const helper = parseHelperEvidence(bindingRecord.helper);
  const environment = parsed.environment;
  if (
    helper.binarySha256 !== parsed.helper.binarySha256 ||
    helper.compilerIdentitySha256 !== parsed.helper.compilerIdentitySha256 ||
    helper.sourceSha256 !== parsed.helper.sourceSha256 ||
    bindingRecord.architecture !== environment.architecture ||
    bindingRecord.macosBuildVersion !== environment.macosBuildVersion ||
    bindingRecord.macosProductVersion !== environment.macosProductVersion ||
    bindingRecord.nodeVersion !== environment.nodeVersion ||
    bindingRecord.pnpmVersion !== environment.pnpmVersion
  ) {
    fail("VERIFICATION_FAILED", "Runtime does not match the tested helper compatibility build");
  }
}

function parseEnvironment(value: unknown): ReleaseKeyHelperCompatibilityEnvironmentV1 {
  const record = exactObject(
    value,
    [
      "architecture",
      "hardwareClass",
      "macosBuildVersion",
      "macosProductVersion",
      "nodeVersion",
      "pnpmVersion",
    ],
    "Compatibility environment",
  );
  if (
    (record.architecture !== "arm64" && record.architecture !== "x64") ||
    record.hardwareClass !== "MacBook" ||
    record.nodeVersion !== RELEASE_KEY_HELPER_COMPATIBILITY_NODE_VERSION ||
    record.pnpmVersion !== RELEASE_KEY_HELPER_COMPATIBILITY_PNPM_VERSION ||
    typeof record.macosBuildVersion !== "string" ||
    !MACOS_BUILD_PATTERN.test(record.macosBuildVersion) ||
    typeof record.macosProductVersion !== "string" ||
    !MACOS_PRODUCT_VERSION_PATTERN.test(record.macosProductVersion)
  ) {
    fail("VERIFICATION_FAILED", "Compatibility environment is not an approved exact build");
  }
  return Object.freeze({
    architecture: record.architecture,
    hardwareClass: "MacBook",
    macosBuildVersion: record.macosBuildVersion,
    macosProductVersion: record.macosProductVersion,
    nodeVersion: RELEASE_KEY_HELPER_COMPATIBILITY_NODE_VERSION,
    pnpmVersion: RELEASE_KEY_HELPER_COMPATIBILITY_PNPM_VERSION,
  });
}

function parseHelperEvidence(value: unknown): KeychainHelperEvidenceV1 {
  const record = exactObject(
    value,
    ["binarySha256", "compilerIdentitySha256", "sourceSha256"],
    "Compatibility helper evidence",
  );
  return Object.freeze({
    binarySha256: validateHash(record.binarySha256, "Compatibility helper binary hash"),
    compilerIdentitySha256: validateHash(
      record.compilerIdentitySha256,
      "Compatibility helper compiler identity hash",
    ),
    sourceSha256: validateHash(record.sourceSha256, "Compatibility helper source hash"),
  });
}

function parsePrompts(
  value: unknown,
): readonly [ReleaseKeyHelperCompatibilityPromptV1, ReleaseKeyHelperCompatibilityPromptV1] {
  const prompts = exactArray(value, "Compatibility user-presence prompts", 2);
  if (prompts.length !== 2) {
    fail("VERIFICATION_FAILED", "Exactly two user-presence prompts are required");
  }
  const parsed = [
    parsePrompt(prompts[0], 1, "first-fresh-helper-invocation"),
    parsePrompt(prompts[1], 2, "second-fresh-helper-invocation-after-first-completed"),
  ] as const;
  if (parsed[0].evidenceSha256 === parsed[1].evidenceSha256) {
    fail("VERIFICATION_FAILED", "User-presence prompt observations are not distinct");
  }
  return Object.freeze(parsed);
}

function parsePrompt(
  value: unknown,
  attempt: 1 | 2,
  scenario:
    "first-fresh-helper-invocation" | "second-fresh-helper-invocation-after-first-completed",
): ReleaseKeyHelperCompatibilityPromptV1 {
  const record = exactObject(
    value,
    [
      "attempt",
      "evidenceSha256",
      "freshHelperProcess",
      "outcome",
      "scenario",
      "signatureVerification",
    ],
    "Compatibility user-presence prompt",
  );
  if (
    record.attempt !== attempt ||
    record.freshHelperProcess !== "verified" ||
    record.outcome !== "user-presence-prompt-observed-and-approved-once" ||
    record.scenario !== scenario ||
    record.signatureVerification !== "passed"
  ) {
    fail("VERIFICATION_FAILED", "User-presence prompt verification did not pass");
  }
  return Object.freeze({
    attempt,
    evidenceSha256: validateHash(record.evidenceSha256, "User-presence prompt evidence hash"),
    freshHelperProcess: "verified",
    outcome: "user-presence-prompt-observed-and-approved-once",
    scenario,
    signatureVerification: "passed",
  });
}

function parseKeychainControls(value: unknown): ReleaseKeyHelperKeychainControlsV1 {
  const record = exactObject(
    value,
    [
      "accessibility",
      "dataProtectionKeychain",
      "evidenceSha256",
      "persistentApproval",
      "synchronizable",
      "unauthorizedAlternateClientAccess",
      "userPresence",
    ],
    "Compatibility Keychain controls",
  );
  if (
    record.accessibility !== "when-unlocked-this-device-only" ||
    record.dataProtectionKeychain !== "verified" ||
    record.persistentApproval !== "not-granted" ||
    record.synchronizable !== "disabled" ||
    record.unauthorizedAlternateClientAccess !== "refused" ||
    record.userPresence !== "required"
  ) {
    fail("VERIFICATION_FAILED", "Compatibility Keychain controls did not pass");
  }
  return Object.freeze({
    accessibility: "when-unlocked-this-device-only",
    dataProtectionKeychain: "verified",
    evidenceSha256: validateHash(record.evidenceSha256, "Keychain controls evidence hash"),
    persistentApproval: "not-granted",
    synchronizable: "disabled",
    unauthorizedAlternateClientAccess: "refused",
    userPresence: "required",
  });
}

function parsePrivateMaterialLeakScan(value: unknown): ReleaseKeyHelperPrivateLeakScanV1 {
  const record = exactObject(
    value,
    ["evidenceSha256", "outcome", "scopes"],
    "Private-material leak scan",
  );
  if (record.outcome !== "passed") {
    fail("VERIFICATION_FAILED", "Private-material leak scan did not pass");
  }
  const scopes = exactArray(
    record.scopes,
    "Private-material leak scan scopes",
    RELEASE_KEY_HELPER_PRIVATE_LEAK_SCAN_SCOPES.length,
  );
  if (scopes.length !== RELEASE_KEY_HELPER_PRIVATE_LEAK_SCAN_SCOPES.length) {
    fail("VERIFICATION_FAILED", "Private-material leak scan scope is incomplete");
  }
  return Object.freeze({
    evidenceSha256: validateHash(record.evidenceSha256, "Private-material leak scan evidence hash"),
    outcome: "passed",
    scopes: Object.freeze(
      RELEASE_KEY_HELPER_PRIVATE_LEAK_SCAN_SCOPES.map((name, index) => {
        const scope = exactObject(
          scopes[index],
          ["name", "outcome"],
          "Private-material leak scan scope",
        );
        if (scope.name !== name || scope.outcome !== "passed") {
          fail("VERIFICATION_FAILED", "Private-material leak scan scope did not pass");
        }
        return Object.freeze({ name, outcome: "passed" as const });
      }),
    ),
  });
}

function parseCleanup(value: unknown): ReleaseKeyHelperCleanupV1 {
  const record = exactObject(
    value,
    ["evidenceSha256", "keychainItem", "outcome", "temporaryArtifacts", "testPrivateMaterial"],
    "Compatibility cleanup",
  );
  if (
    record.keychainItem !== "deleted-and-absence-verified" ||
    record.outcome !== "passed" ||
    record.temporaryArtifacts !== "removed-and-absence-verified" ||
    record.testPrivateMaterial !== "destroyed-and-absence-verified"
  ) {
    fail("VERIFICATION_FAILED", "Compatibility cleanup did not pass");
  }
  return Object.freeze({
    evidenceSha256: validateHash(record.evidenceSha256, "Compatibility cleanup evidence hash"),
    keychainItem: "deleted-and-absence-verified",
    outcome: "passed",
    temporaryArtifacts: "removed-and-absence-verified",
    testPrivateMaterial: "destroyed-and-absence-verified",
  });
}

function parseIndependentApproval(value: unknown): ReleaseKeyHelperIndependentApprovalV1 {
  const record = exactObject(
    value,
    [
      "approvedAt",
      "approvalEvidenceSha256",
      "authorship",
      "drillParticipation",
      "reviewerId",
      "reviewerRole",
      "verdict",
    ],
    "Compatibility independent approval",
  );
  if (
    record.authorship !== "did-not-author-tested-helper-or-evidence" ||
    record.drillParticipation !== "did-not-operate-drill" ||
    record.reviewerRole !== "independent-non-authoring-reviewer" ||
    record.verdict !== "approved"
  ) {
    fail("VERIFICATION_FAILED", "Compatibility independent approval is invalid");
  }
  return Object.freeze({
    approvedAt: validateCanonicalTimestamp(record.approvedAt, "Compatibility approval time"),
    approvalEvidenceSha256: validateHash(
      record.approvalEvidenceSha256,
      "Compatibility approval evidence hash",
    ),
    authorship: "did-not-author-tested-helper-or-evidence",
    drillParticipation: "did-not-operate-drill",
    reviewerId: validateIdentifier(record.reviewerId, "Compatibility reviewer ID"),
    reviewerRole: "independent-non-authoring-reviewer",
    verdict: "approved",
  });
}
