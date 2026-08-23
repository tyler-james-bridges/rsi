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
import { FOUNDATION_RELEASE_VERSION } from "./types.js";

export const FOUNDATION_REVIEW_EVIDENCE_TYPE =
  "rsi.foundation-independent-review-evidence" as const;
export const FOUNDATION_REVIEW_EVIDENCE_VERSION = 1 as const;
export const FOUNDATION_REVIEW_SCOPE_NAMES = Object.freeze([
  "repository-diff",
  "release-key-provisioning",
  "release-ceremony-and-tag",
  "failure-and-recovery-controls",
  "tests-and-documentation",
] as const);

const MAX_REVIEW_BYTES = 64 * 1024;
const MAX_FINDINGS = 64;

export type FoundationReviewScopeName = (typeof FOUNDATION_REVIEW_SCOPE_NAMES)[number];
export type FoundationReviewFindingSeverity =
  "critical" | "high" | "informational" | "low" | "medium";

export interface FoundationReviewScopeV1 {
  readonly name: FoundationReviewScopeName;
  readonly outcome: "passed";
}

export interface FoundationResolvedReviewFindingV1 {
  readonly findingId: string;
  readonly findingSha256: string;
  readonly resolutionSha256: string;
  readonly severity: FoundationReviewFindingSeverity;
  readonly status: "resolved";
}

export interface FoundationIndependentReviewEvidenceV1 {
  readonly commitSha: string;
  readonly evidenceType: typeof FOUNDATION_REVIEW_EVIDENCE_TYPE;
  readonly findings: readonly FoundationResolvedReviewFindingV1[];
  readonly gitTreeSha: string;
  readonly releaseVersion: typeof FOUNDATION_RELEASE_VERSION;
  readonly repository: "tyler-james-bridges/rsi";
  readonly reviewedAt: string;
  readonly reviewerId: string;
  readonly reviewerRole: "independent-non-authoring-agent";
  readonly scopes: readonly FoundationReviewScopeV1[];
  readonly verdict: "approved";
  readonly version: typeof FOUNDATION_REVIEW_EVIDENCE_VERSION;
}

export function parseFoundationIndependentReviewEvidence(
  value: unknown,
): FoundationIndependentReviewEvidenceV1 {
  const record = exactObject(
    value,
    [
      "commitSha",
      "evidenceType",
      "findings",
      "gitTreeSha",
      "releaseVersion",
      "repository",
      "reviewedAt",
      "reviewerId",
      "reviewerRole",
      "scopes",
      "verdict",
      "version",
    ],
    "Foundation independent-review evidence",
  );
  if (
    record.evidenceType !== FOUNDATION_REVIEW_EVIDENCE_TYPE ||
    record.releaseVersion !== FOUNDATION_RELEASE_VERSION ||
    record.repository !== "tyler-james-bridges/rsi" ||
    record.reviewerRole !== "independent-non-authoring-agent" ||
    record.verdict !== "approved" ||
    record.version !== FOUNDATION_REVIEW_EVIDENCE_VERSION
  ) {
    fail("VERIFICATION_FAILED", "Foundation independent-review verdict is invalid");
  }
  return Object.freeze({
    commitSha: validateGitHash(record.commitSha, "Independent-review commit"),
    evidenceType: FOUNDATION_REVIEW_EVIDENCE_TYPE,
    findings: parseFindings(record.findings),
    gitTreeSha: validateGitHash(record.gitTreeSha, "Independent-review Git tree"),
    releaseVersion: FOUNDATION_RELEASE_VERSION,
    repository: "tyler-james-bridges/rsi",
    reviewedAt: validateCanonicalTimestamp(record.reviewedAt, "Independent-review time"),
    reviewerId: validateIdentifier(record.reviewerId, "Independent reviewer ID"),
    reviewerRole: "independent-non-authoring-agent",
    scopes: parseScopes(record.scopes),
    verdict: "approved",
    version: FOUNDATION_REVIEW_EVIDENCE_VERSION,
  });
}

export function decodeFoundationIndependentReviewEvidence(
  value: Uint8Array,
): FoundationIndependentReviewEvidenceV1 {
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_REVIEW_BYTES
  ) {
    fail("INPUT_INVALID", "Foundation independent-review evidence bytes are invalid");
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", "Foundation independent-review evidence is not valid JSON");
  }
  const evidence = parseFoundationIndependentReviewEvidence(parsed);
  if (canonicalJson(evidence) !== text) {
    fail("INPUT_INVALID", "Foundation independent-review evidence is not canonical JSON");
  }
  return evidence;
}

/**
 * Encodes the canonical inner review body. Production file ingestion requires
 * the authenticated envelope from `authenticated-review.ts`; this helper stays
 * available for deterministic review fixtures and signature construction.
 */
export function encodeFoundationIndependentReviewEvidence(
  value: FoundationIndependentReviewEvidenceV1,
): Uint8Array {
  return new TextEncoder().encode(canonicalJson(parseFoundationIndependentReviewEvidence(value)));
}

export function foundationIndependentReviewEvidenceSha256(
  value: FoundationIndependentReviewEvidenceV1,
): string {
  return sha256(canonicalJson(parseFoundationIndependentReviewEvidence(value)));
}

function parseScopes(value: unknown): readonly FoundationReviewScopeV1[] {
  const scopes = exactArray(
    value,
    "Foundation independent-review scopes",
    FOUNDATION_REVIEW_SCOPE_NAMES.length,
  );
  if (scopes.length !== FOUNDATION_REVIEW_SCOPE_NAMES.length) {
    fail("VERIFICATION_FAILED", "Foundation independent-review scope is incomplete");
  }
  return Object.freeze(
    FOUNDATION_REVIEW_SCOPE_NAMES.map((name, index) => {
      const record = exactObject(
        scopes[index],
        ["name", "outcome"],
        "Foundation independent-review scope",
      );
      if (record.name !== name || record.outcome !== "passed") {
        fail("VERIFICATION_FAILED", "Foundation independent-review scope did not pass");
      }
      return Object.freeze({ name, outcome: "passed" as const });
    }),
  );
}

function parseFindings(value: unknown): readonly FoundationResolvedReviewFindingV1[] {
  const findings = exactArray(value, "Foundation independent-review findings", MAX_FINDINGS);
  const identifiers = new Set<string>();
  const parsed = findings.map((entry) => {
    const record = exactObject(
      entry,
      ["findingId", "findingSha256", "resolutionSha256", "severity", "status"],
      "Foundation independent-review finding",
    );
    const findingId = validateIdentifier(record.findingId, "Independent-review finding ID");
    if (
      identifiers.has(findingId) ||
      record.status !== "resolved" ||
      !isSeverity(record.severity)
    ) {
      fail("VERIFICATION_FAILED", "Foundation independent-review finding is unresolved or invalid");
    }
    identifiers.add(findingId);
    return Object.freeze({
      findingId,
      findingSha256: validateHash(record.findingSha256, "Independent-review finding hash"),
      resolutionSha256: validateHash(record.resolutionSha256, "Independent-review resolution hash"),
      severity: record.severity,
      status: "resolved" as const,
    });
  });
  return Object.freeze(parsed);
}

function isSeverity(value: unknown): value is FoundationReviewFindingSeverity {
  return (
    value === "critical" ||
    value === "high" ||
    value === "informational" ||
    value === "low" ||
    value === "medium"
  );
}
