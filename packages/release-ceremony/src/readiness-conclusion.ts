import { types as utilTypes } from "node:util";

import type { ReleaseArtifactBindingsV1 } from "@rsi/release-bundle";

import {
  canonicalJson,
  exactArray,
  exactObject,
  sha256,
  validateGitHash,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";
import { FOUNDATION_RELEASE_VERSION } from "./types.js";

export const FOUNDATION_STAGE_A_READINESS_CONCLUSION_TYPE =
  "rsi.foundation-stage-a-readiness-conclusion" as const;
export const FOUNDATION_STAGE_A_READINESS_CONCLUSION_VERSION = 1 as const;
export const FOUNDATION_STAGE_A_BUILT_STATE = "FOUNDATION_BUILT" as const;
export const FOUNDATION_STAGE_A_NOT_BUILT_STATE = "FOUNDATION_NOT_BUILT" as const;

export const FOUNDATION_STAGE_A_READINESS_CHECK_NAMES = Object.freeze([
  "release-bundle-verified",
  "retained-ci-evidence-verified",
  "commit-bindings-verified",
  "signing-identity-pinned-and-matched",
  "independent-adversarial-review-passed",
] as const);

const MAX_CANONICAL_CONCLUSION_BYTES = 16 * 1024;

export type FoundationStageAReadinessCheckName =
  (typeof FOUNDATION_STAGE_A_READINESS_CHECK_NAMES)[number];
export type FoundationStageAReadinessOutcome = "failed" | "passed";
export type FoundationStageAObjectiveEvidenceState =
  typeof FOUNDATION_STAGE_A_BUILT_STATE | typeof FOUNDATION_STAGE_A_NOT_BUILT_STATE;

export interface FoundationStageAReadinessCheckV1 {
  readonly name: FoundationStageAReadinessCheckName;
  readonly outcome: FoundationStageAReadinessOutcome;
}

export type FoundationStageAReadinessChecksV1 = readonly [
  FoundationStageAReadinessCheckV1,
  FoundationStageAReadinessCheckV1,
  FoundationStageAReadinessCheckV1,
  FoundationStageAReadinessCheckV1,
  FoundationStageAReadinessCheckV1,
];

/**
 * The immutable evidence bindings shared with the `foundation-v1` annotated tag.
 * The signer fingerprint is the SHA-256 of canonical Ed25519 SPKI DER.
 */
export interface FoundationStageAReadinessBindingsV1 extends ReleaseArtifactBindingsV1 {
  readonly archiveSha256: string;
  readonly ciEvidenceSha256: string;
  readonly commitSha: string;
  readonly gitTreeSha: string;
  readonly helperCompatibilityEvidenceSha256: string;
  readonly helperCompatibilityTestedCommitSha: string;
  readonly identitySha256: string;
  readonly independentReviewEvidenceSha256: string;
  readonly manifestSha256: string;
  readonly platformIdentitySha256: string;
  readonly provisioningReceiptSha256: string;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
}

export interface FoundationStageAReadinessAssessmentV1 extends FoundationStageAReadinessBindingsV1 {
  readonly checks: FoundationStageAReadinessChecksV1;
}

export interface FoundationStageAReadinessConclusionV1 extends FoundationStageAReadinessAssessmentV1 {
  readonly conclusionType: typeof FOUNDATION_STAGE_A_READINESS_CONCLUSION_TYPE;
  readonly objectiveEvidenceState: FoundationStageAObjectiveEvidenceState;
  readonly outcome: FoundationStageAReadinessOutcome;
  readonly releaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly version: typeof FOUNDATION_STAGE_A_READINESS_CONCLUSION_VERSION;
}

/** Build a conclusion whose outcome and objective state are derived from every mandatory check. */
export function createFoundationStageAReadinessConclusion(
  assessmentValue: FoundationStageAReadinessAssessmentV1,
): FoundationStageAReadinessConclusionV1 {
  const assessment = parseAssessment(assessmentValue);
  const outcome = assessment.checks.every((check) => check.outcome === "passed")
    ? "passed"
    : "failed";
  return parseFoundationStageAReadinessConclusion({
    ...assessment,
    conclusionType: FOUNDATION_STAGE_A_READINESS_CONCLUSION_TYPE,
    objectiveEvidenceState:
      outcome === "passed" ? FOUNDATION_STAGE_A_BUILT_STATE : FOUNDATION_STAGE_A_NOT_BUILT_STATE,
    outcome,
    releaseVersion: FOUNDATION_RELEASE_VERSION,
    version: FOUNDATION_STAGE_A_READINESS_CONCLUSION_VERSION,
  });
}

/** Strict structural parser. Unknown fields, reordered checks, and inconsistent claims fail closed. */
export function parseFoundationStageAReadinessConclusion(
  value: unknown,
): FoundationStageAReadinessConclusionV1 {
  const record = exactObject(
    value,
    [
      "archiveSha256",
      "artifactSetSha256",
      "checks",
      "ciEvidenceSha256",
      "commitSha",
      "configSetSha256",
      "conclusionType",
      "gitTreeSha",
      "helperCompatibilityEvidenceSha256",
      "helperCompatibilityTestedCommitSha",
      "identitySha256",
      "independentReviewEvidenceSha256",
      "lockfileSha256",
      "manifestSha256",
      "objectiveEvidenceState",
      "outcome",
      "platformIdentitySha256",
      "provisioningReceiptSha256",
      "recoverySetSha256",
      "releaseVersion",
      "runbookSetSha256",
      "sbomSha256",
      "signerFingerprintSha256",
      "signerKeyId",
      "sourceTreeSha256",
      "testSummarySha256",
      "version",
    ],
    "Foundation Stage A readiness conclusion",
  );
  if (
    record.conclusionType !== FOUNDATION_STAGE_A_READINESS_CONCLUSION_TYPE ||
    record.releaseVersion !== FOUNDATION_RELEASE_VERSION ||
    record.version !== FOUNDATION_STAGE_A_READINESS_CONCLUSION_VERSION
  ) {
    fail("INPUT_INVALID", "Foundation Stage A readiness conclusion identity is invalid");
  }
  const bindings = parseBindings(record);
  const checks = parseChecks(record.checks);
  const derivedOutcome: FoundationStageAReadinessOutcome = checks.every(
    (check) => check.outcome === "passed",
  )
    ? "passed"
    : "failed";
  const derivedState: FoundationStageAObjectiveEvidenceState =
    derivedOutcome === "passed"
      ? FOUNDATION_STAGE_A_BUILT_STATE
      : FOUNDATION_STAGE_A_NOT_BUILT_STATE;
  if (record.outcome !== derivedOutcome || record.objectiveEvidenceState !== derivedState) {
    fail("VERIFICATION_FAILED", "Foundation Stage A readiness claim contradicts its checks");
  }
  return Object.freeze({
    ...bindings,
    checks,
    conclusionType: FOUNDATION_STAGE_A_READINESS_CONCLUSION_TYPE,
    objectiveEvidenceState: derivedState,
    outcome: derivedOutcome,
    releaseVersion: FOUNDATION_RELEASE_VERSION,
    version: FOUNDATION_STAGE_A_READINESS_CONCLUSION_VERSION,
  });
}

/** Encode without insignificant whitespace or a trailing newline. */
export function encodeFoundationStageAReadinessConclusion(
  value: FoundationStageAReadinessConclusionV1,
): string {
  return canonicalJson(parseFoundationStageAReadinessConclusion(value));
}

/** Decode only byte-for-byte canonical JSON; permissive JSON spellings are deliberately rejected. */
export function decodeFoundationStageAReadinessConclusion(
  value: string | Uint8Array,
): FoundationStageAReadinessConclusionV1 {
  const text = decodeBoundedText(value);
  let decoded: unknown;
  try {
    decoded = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", "Foundation Stage A readiness conclusion is not valid JSON");
  }
  const conclusion = parseFoundationStageAReadinessConclusion(decoded);
  if (canonicalJson(conclusion) !== text) {
    fail("INPUT_INVALID", "Foundation Stage A readiness conclusion is not canonical JSON");
  }
  return conclusion;
}

/** SHA-256 of the exact canonical conclusion bytes intended to be bound by `foundation-v1`. */
export function foundationStageAReadinessConclusionSha256(
  value: FoundationStageAReadinessConclusionV1,
): string {
  return sha256(encodeFoundationStageAReadinessConclusion(value));
}

/**
 * Require a passed conclusion and exact evidence bindings before it may drive signed-tag creation.
 */
export function verifyFoundationBuiltReadinessConclusion(
  conclusionValue: FoundationStageAReadinessConclusionV1,
  expectedBindingsValue: FoundationStageAReadinessBindingsV1,
): FoundationStageAReadinessConclusionV1 {
  const conclusion = parseFoundationStageAReadinessConclusion(conclusionValue);
  const expected = parseBindings(
    exactObject(
      expectedBindingsValue,
      [
        "archiveSha256",
        "artifactSetSha256",
        "ciEvidenceSha256",
        "commitSha",
        "configSetSha256",
        "gitTreeSha",
        "helperCompatibilityEvidenceSha256",
        "helperCompatibilityTestedCommitSha",
        "identitySha256",
        "independentReviewEvidenceSha256",
        "lockfileSha256",
        "manifestSha256",
        "platformIdentitySha256",
        "provisioningReceiptSha256",
        "recoverySetSha256",
        "runbookSetSha256",
        "sbomSha256",
        "signerFingerprintSha256",
        "signerKeyId",
        "sourceTreeSha256",
        "testSummarySha256",
      ],
      "Expected Foundation Stage A readiness bindings",
    ),
  );
  if (
    conclusion.outcome !== "passed" ||
    conclusion.objectiveEvidenceState !== FOUNDATION_STAGE_A_BUILT_STATE
  ) {
    fail("VERIFICATION_FAILED", "Foundation Stage A has not reached FOUNDATION_BUILT");
  }
  for (const key of Object.keys(
    expected,
  ) as readonly (keyof FoundationStageAReadinessBindingsV1)[]) {
    if (conclusion[key] !== expected[key]) {
      fail("VERIFICATION_FAILED", `Foundation Stage A ${key} binding is invalid`);
    }
  }
  return conclusion;
}

function parseAssessment(value: unknown): FoundationStageAReadinessAssessmentV1 {
  const record = exactObject(
    value,
    [
      "archiveSha256",
      "artifactSetSha256",
      "checks",
      "ciEvidenceSha256",
      "commitSha",
      "configSetSha256",
      "gitTreeSha",
      "helperCompatibilityEvidenceSha256",
      "helperCompatibilityTestedCommitSha",
      "identitySha256",
      "independentReviewEvidenceSha256",
      "lockfileSha256",
      "manifestSha256",
      "platformIdentitySha256",
      "provisioningReceiptSha256",
      "recoverySetSha256",
      "runbookSetSha256",
      "sbomSha256",
      "signerFingerprintSha256",
      "signerKeyId",
      "sourceTreeSha256",
      "testSummarySha256",
    ],
    "Foundation Stage A readiness assessment",
  );
  return Object.freeze({
    ...parseBindings(record),
    checks: parseChecks(record.checks),
  });
}

function parseBindings(record: Record<string, unknown>): FoundationStageAReadinessBindingsV1 {
  const signerFingerprintSha256 = validateHash(
    record.signerFingerprintSha256,
    "Foundation Stage A signer fingerprint",
  );
  const signerKeyId = validateIdentifier(record.signerKeyId, "Foundation Stage A signer key ID");
  if (signerKeyId !== `rsi-release-${signerFingerprintSha256.slice(0, 16)}`) {
    fail("INPUT_INVALID", "Foundation Stage A signer key ID does not match its fingerprint");
  }
  return Object.freeze({
    archiveSha256: validateHash(record.archiveSha256, "Foundation Stage A archive SHA-256"),
    artifactSetSha256: validateHash(
      record.artifactSetSha256,
      "Foundation Stage A artifact-set SHA-256",
    ),
    ciEvidenceSha256: validateHash(
      record.ciEvidenceSha256,
      "Foundation Stage A CI evidence SHA-256",
    ),
    commitSha: validateGitHash(record.commitSha, "Foundation Stage A commit"),
    configSetSha256: validateHash(
      record.configSetSha256,
      "Foundation Stage A configuration-set SHA-256",
    ),
    gitTreeSha: validateGitHash(record.gitTreeSha, "Foundation Stage A Git tree"),
    helperCompatibilityEvidenceSha256: validateHash(
      record.helperCompatibilityEvidenceSha256,
      "Foundation Stage A helper compatibility evidence SHA-256",
    ),
    helperCompatibilityTestedCommitSha: validateGitHash(
      record.helperCompatibilityTestedCommitSha,
      "Foundation Stage A helper compatibility tested commit",
    ),
    identitySha256: validateHash(record.identitySha256, "Foundation Stage A identity SHA-256"),
    independentReviewEvidenceSha256: validateHash(
      record.independentReviewEvidenceSha256,
      "Foundation Stage A independent-review evidence SHA-256",
    ),
    lockfileSha256: validateHash(record.lockfileSha256, "Foundation Stage A lockfile SHA-256"),
    manifestSha256: validateHash(record.manifestSha256, "Foundation Stage A manifest SHA-256"),
    platformIdentitySha256: validateHash(
      record.platformIdentitySha256,
      "Foundation Stage A platform identity SHA-256",
    ),
    provisioningReceiptSha256: validateHash(
      record.provisioningReceiptSha256,
      "Foundation Stage A provisioning receipt SHA-256",
    ),
    recoverySetSha256: validateHash(
      record.recoverySetSha256,
      "Foundation Stage A recovery-set SHA-256",
    ),
    runbookSetSha256: validateHash(
      record.runbookSetSha256,
      "Foundation Stage A runbook-set SHA-256",
    ),
    sbomSha256: validateHash(record.sbomSha256, "Foundation Stage A SBOM SHA-256"),
    signerFingerprintSha256,
    signerKeyId,
    sourceTreeSha256: validateHash(
      record.sourceTreeSha256,
      "Foundation Stage A source-tree SHA-256",
    ),
    testSummarySha256: validateHash(
      record.testSummarySha256,
      "Foundation Stage A test-summary SHA-256",
    ),
  });
}

function parseChecks(value: unknown): FoundationStageAReadinessChecksV1 {
  const values = exactArray(
    value,
    "Foundation Stage A readiness checks",
    FOUNDATION_STAGE_A_READINESS_CHECK_NAMES.length,
  );
  if (values.length !== FOUNDATION_STAGE_A_READINESS_CHECK_NAMES.length) {
    fail("INPUT_INVALID", "Foundation Stage A readiness check set is incomplete");
  }
  const checks = FOUNDATION_STAGE_A_READINESS_CHECK_NAMES.map((expectedName, index) => {
    const record = exactObject(
      values[index],
      ["name", "outcome"],
      "Foundation Stage A readiness check",
    );
    if (
      record.name !== expectedName ||
      (record.outcome !== "passed" && record.outcome !== "failed")
    ) {
      fail("INPUT_INVALID", "Foundation Stage A readiness check set is invalid or out of order");
    }
    return Object.freeze({ name: expectedName, outcome: record.outcome });
  });
  return Object.freeze(checks) as FoundationStageAReadinessChecksV1;
}

function decodeBoundedText(value: string | Uint8Array): string {
  if (typeof value === "string") {
    if (
      Buffer.byteLength(value, "utf8") === 0 ||
      Buffer.byteLength(value, "utf8") > MAX_CANONICAL_CONCLUSION_BYTES
    ) {
      fail("INPUT_INVALID", "Foundation Stage A readiness conclusion size is invalid");
    }
    return value;
  }
  if (!(value instanceof Uint8Array) || utilTypes.isProxy(value)) {
    fail("INPUT_INVALID", "Foundation Stage A readiness conclusion bytes are invalid");
  }
  if (value.byteLength === 0 || value.byteLength > MAX_CANONICAL_CONCLUSION_BYTES) {
    fail("INPUT_INVALID", "Foundation Stage A readiness conclusion size is invalid");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    fail("INPUT_INVALID", "Foundation Stage A readiness conclusion is not valid UTF-8");
  }
}
