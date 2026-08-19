import { REQUIRED_TEST_CHECKS } from "@rsi/release-bundle";

import {
  canonicalJson,
  exactArray,
  exactObject,
  sha256,
  validateCanonicalTimestamp,
  validateGitHash,
} from "./canonical.js";
import { fail } from "./errors.js";
import {
  FOUNDATION_CI_EVIDENCE_TYPE,
  FOUNDATION_CI_EVIDENCE_VERSION,
  type FoundationCiCheckV1,
  type FoundationCiEvidenceV1,
  type FoundationCiJobV1,
  type FoundationRequiredCheckName,
} from "./types.js";

const REPOSITORY = "tyler-james-bridges/rsi" as const;
const JOB_NAMES = ["gitleaks-history", "quality"] as const;

export function parseFoundationCiEvidence(value: unknown): FoundationCiEvidenceV1 {
  const record = exactObject(
    value,
    [
      "branch",
      "commitSha",
      "completedAt",
      "evidenceType",
      "event",
      "jobs",
      "repository",
      "requiredChecks",
      "runId",
      "runUrl",
      "version",
      "workflow",
    ],
    "Foundation CI evidence",
  );
  if (
    record.evidenceType !== FOUNDATION_CI_EVIDENCE_TYPE ||
    record.version !== FOUNDATION_CI_EVIDENCE_VERSION ||
    record.repository !== REPOSITORY ||
    record.branch !== "main" ||
    record.workflow !== "ci" ||
    record.event !== "push"
  ) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI evidence identity is invalid");
  }
  const commitSha = validateGitHash(record.commitSha, "CI evidence commit");
  const completedAt = validateCanonicalTimestamp(record.completedAt, "CI completion time");
  const runId = parseRunId(record.runId);
  const expectedUrl = `https://github.com/${REPOSITORY}/actions/runs/${runId}`;
  if (record.runUrl !== expectedUrl) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI run URL is invalid");
  }
  const jobs = parseJobs(record.jobs);
  const requiredChecks = parseChecks(record.requiredChecks);
  return Object.freeze({
    branch: "main",
    commitSha,
    completedAt,
    evidenceType: FOUNDATION_CI_EVIDENCE_TYPE,
    event: "push",
    jobs,
    repository: REPOSITORY,
    requiredChecks,
    runId,
    runUrl: expectedUrl,
    version: FOUNDATION_CI_EVIDENCE_VERSION,
    workflow: "ci",
  });
}

export function deriveCiCheckResultSha256(
  evidenceValue: FoundationCiEvidenceV1,
  checkName: FoundationRequiredCheckName,
): string {
  const evidence = parseFoundationCiEvidence(evidenceValue);
  if (!REQUIRED_TEST_CHECKS.includes(checkName)) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI check name is invalid");
  }
  return sha256(`rsi-foundation-retained-ci-check-v1\0${canonicalJson(evidence)}\0${checkName}`);
}

export function foundationCiEvidenceSha256(evidenceValue: FoundationCiEvidenceV1): string {
  return sha256(canonicalJson(parseFoundationCiEvidence(evidenceValue)));
}

function parseRunId(value: unknown): string {
  if (typeof value !== "string" || !/^[1-9]\d{0,19}$/u.test(value)) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI run identifier is invalid");
  }
  return value;
}

function parseJobs(value: unknown): readonly [FoundationCiJobV1, FoundationCiJobV1] {
  const values = exactArray(value, "Foundation CI jobs", 2);
  if (values.length !== JOB_NAMES.length) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI job set is incomplete");
  }
  const jobs = JOB_NAMES.map((expectedName, index) => {
    const record = exactObject(values[index], ["conclusion", "name"], "Foundation CI job");
    if (record.name !== expectedName || record.conclusion !== "success") {
      fail("CI_EVIDENCE_INVALID", "Foundation CI job failed or is out of order");
    }
    return Object.freeze({ conclusion: "success" as const, name: expectedName });
  });
  return Object.freeze(jobs) as readonly [FoundationCiJobV1, FoundationCiJobV1];
}

function parseChecks(value: unknown): readonly FoundationCiCheckV1[] {
  const values = exactArray(value, "Foundation CI required checks", REQUIRED_TEST_CHECKS.length);
  if (values.length !== REQUIRED_TEST_CHECKS.length) {
    fail("CI_EVIDENCE_INVALID", "Foundation CI required-check set is incomplete");
  }
  return Object.freeze(
    REQUIRED_TEST_CHECKS.map((expectedName, index) => {
      const record = exactObject(
        values[index],
        ["name", "outcome"],
        "Foundation CI required check",
      );
      if (record.name !== expectedName || record.outcome !== "passed") {
        fail("CI_EVIDENCE_INVALID", "Foundation CI required check failed or is out of order");
      }
      return Object.freeze({
        name: expectedName as FoundationRequiredCheckName,
        outcome: "passed" as const,
      });
    }),
  );
}
