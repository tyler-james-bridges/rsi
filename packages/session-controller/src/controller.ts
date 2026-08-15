import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import { verifySanitizedStateEvidence } from "@rsi/backup";
import { verifySanitizedEventArchive } from "@rsi/event-archive";
import { verifySignedReleaseBundle } from "@rsi/release-bundle";
import {
  isSqliteSessionCoordinator,
  parseSessionLocalVerificationEvidence,
} from "@rsi/session-lifecycle";
import { canonicalJson, type JsonValue } from "@rsi/store";

import { SessionControllerError } from "./errors.js";
import type {
  ExpectedSessionRecoveryBindingsV1,
  RecordVerifiedLocalClosureOptions,
  RecordVerifiedLocalClosureResult,
  SessionLocalVerificationFactsV1,
  VerifiedSessionRecoveryArtifactsV1,
  VerifySessionRecoveryArtifactsOptions,
} from "./types.js";

const HASH = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOCAL_EVIDENCE_HASH_DOMAIN = Buffer.from("rsi-session-local-evidence-v1\0", "utf8");
const ZERO_HASH = "0".repeat(64);
const VERIFIED_RECOVERY_REPORTS = new WeakSet<object>();

const LOCAL_FACT_KEYS = [
  "alertCheck",
  "canonicalChain",
  "digestIntegrity",
  "eventIntegrity",
  "explicitClose",
  "incidentCount",
  "localCheckpoint",
  "openSea",
  "purge",
  "schemaVersion",
  "xLanes",
] as const;

export async function verifySessionRecoveryArtifacts(
  optionsValue: VerifySessionRecoveryArtifactsOptions,
): Promise<Readonly<VerifiedSessionRecoveryArtifactsV1>> {
  const options = exactDataObject(
    optionsValue,
    ["eventArchive", "expected", "releaseBundle", "stateEvidence"],
    "verification options",
  );
  const expected = parseExpectedBindings(options.expected);
  let stateEvidence;
  let eventArchive;
  let releaseBundle;
  try {
    stateEvidence = await verifySanitizedStateEvidence(
      options.stateEvidence as VerifySessionRecoveryArtifactsOptions["stateEvidence"],
    );
    eventArchive = await verifySanitizedEventArchive(
      options.eventArchive as VerifySessionRecoveryArtifactsOptions["eventArchive"],
    );
    releaseBundle = await verifySignedReleaseBundle(
      options.releaseBundle as VerifySessionRecoveryArtifactsOptions["releaseBundle"],
    );
  } catch {
    throw new SessionControllerError("COMPONENT_VERIFICATION_FAILED");
  }

  if (
    stateEvidence.profile !== expected.profile ||
    eventArchive.profile !== expected.profile ||
    stateEvidence.sessionId !== expected.sessionId ||
    eventArchive.sessionId !== expected.sessionId ||
    stateEvidence.releaseManifestSha256 !== expected.releaseManifestSha256 ||
    eventArchive.releaseManifestSha256 !== expected.releaseManifestSha256 ||
    releaseBundle.manifestSha256 !== expected.releaseManifestSha256 ||
    eventArchive.stateEvidenceBackupId !== stateEvidence.backupId ||
    stateEvidence.signerFingerprintSha256 !== eventArchive.signerFingerprintSha256 ||
    stateEvidence.signerFingerprintSha256 !== releaseBundle.signerFingerprintSha256
  ) {
    throw new SessionControllerError("RECOVERY_BINDING_MISMATCH");
  }

  const report: VerifiedSessionRecoveryArtifactsV1 = Object.freeze({
    schemaVersion: 1,
    profile: expected.profile,
    releaseManifestSha256: expected.releaseManifestSha256,
    sessionId: expected.sessionId,
    signerFingerprintSha256: stateEvidence.signerFingerprintSha256,
    stateEvidence: Object.freeze({
      archiveSha256: stateEvidence.archiveSha256,
      backupId: stateEvidence.backupId,
      manifestSha256: stateEvidence.manifestSha256,
      status: stateEvidence.status,
    }),
    eventArchive: Object.freeze({
      archiveSha256: eventArchive.archiveSha256,
      eventCount: eventArchive.eventCount,
      headHash: eventArchive.headHash,
      headSequence: eventArchive.headSequence,
      manifestSha256: eventArchive.manifestSha256,
      status: eventArchive.status,
      storeId: eventArchive.storeId,
    }),
    releaseBundle: Object.freeze({
      archiveSha256: releaseBundle.archiveSha256,
      commitSha: releaseBundle.commitSha,
      manifestSha256: releaseBundle.manifestSha256,
      releaseVersion: releaseBundle.releaseVersion,
      status: releaseBundle.status,
    }),
  });
  VERIFIED_RECOVERY_REPORTS.add(report);
  return report;
}

export function isVerifiedSessionRecoveryArtifacts(
  value: unknown,
): value is VerifiedSessionRecoveryArtifactsV1 {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === Object.prototype &&
    VERIFIED_RECOVERY_REPORTS.has(value)
  );
}

export function toSessionRecoveryArtifactEvidence(
  report: VerifiedSessionRecoveryArtifactsV1,
): Readonly<{
  sanitizedStateEvidence: Readonly<{
    archiveSha256: string;
    status: "verified-evidence-component";
  }>;
  sanitizedEventArchive: Readonly<{
    archiveSha256: string;
    status: "verified-restorable-event-archive";
  }>;
  signedReleaseBundle: Readonly<{
    archiveSha256: string;
    status: "verified-restorable-release-component";
  }>;
}> {
  requireVerifiedReport(report);
  return Object.freeze({
    sanitizedStateEvidence: Object.freeze({
      archiveSha256: report.stateEvidence.archiveSha256,
      status: report.stateEvidence.status,
    }),
    sanitizedEventArchive: Object.freeze({
      archiveSha256: report.eventArchive.archiveSha256,
      status: report.eventArchive.status,
    }),
    signedReleaseBundle: Object.freeze({
      archiveSha256: report.releaseBundle.archiveSha256,
      status: report.releaseBundle.status,
    }),
  });
}

export function recordVerifiedLocalClosure(
  optionsValue: RecordVerifiedLocalClosureOptions,
): RecordVerifiedLocalClosureResult {
  const options = exactDataObject(
    optionsValue,
    ["coordinator", "facts", "recovery", "sessionId", "verifiedAt"],
    "local closure options",
  );
  if (!isSqliteSessionCoordinator(options.coordinator)) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  if (!isVerifiedSessionRecoveryArtifacts(options.recovery)) {
    throw new SessionControllerError("UNAUTHENTICATED_REPORT");
  }
  if (typeof options.sessionId !== "string" || typeof options.verifiedAt !== "string") {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const sessionId = options.sessionId;
  const verifiedAt = options.verifiedAt;
  if (
    options.coordinator.profile !== options.recovery.profile ||
    sessionId !== options.recovery.sessionId
  ) {
    throw new SessionControllerError("RECOVERY_BINDING_MISMATCH");
  }
  const facts = exactDataObject(
    options.facts,
    LOCAL_FACT_KEYS,
    "local verification facts",
  ) as unknown as SessionLocalVerificationFactsV1;
  const recoveryArtifacts = toSessionRecoveryArtifactEvidence(options.recovery);
  const candidate = parseSessionLocalVerificationEvidence({
    ...facts,
    evidenceHash: ZERO_HASH,
    recoveryArtifacts,
  });
  const { evidenceHash: _ignored, ...hashInput } = candidate;
  const evidenceHash = createHash("sha256")
    .update(LOCAL_EVIDENCE_HASH_DOMAIN)
    .update(canonicalJson(hashInput as unknown as JsonValue))
    .digest("hex");
  const evidence = parseSessionLocalVerificationEvidence({ ...candidate, evidenceHash });
  return options.coordinator.recordLocalVerification({
    evidence,
    sessionId,
    verifiedAt,
  });
}

function parseExpectedBindings(value: unknown): Readonly<ExpectedSessionRecoveryBindingsV1> {
  const record = exactDataObject(
    value,
    ["profile", "releaseManifestSha256", "sessionId"],
    "expected bindings",
  );
  if (
    (record.profile !== "canary" && record.profile !== "production-observer") ||
    typeof record.releaseManifestSha256 !== "string" ||
    !HASH.test(record.releaseManifestSha256) ||
    typeof record.sessionId !== "string" ||
    !UUID_V4.test(record.sessionId)
  ) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  return Object.freeze({
    profile: record.profile,
    releaseManifestSha256: record.releaseManifestSha256,
    sessionId: record.sessionId,
  });
}

function exactDataObject(
  value: unknown,
  expectedKeys: readonly string[],
  _label: string,
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new SessionControllerError("INPUT_INVALID");
  }
  const output: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !("value" in descriptor)
    ) {
      throw new SessionControllerError("INPUT_INVALID");
    }
    output[key] = descriptor.value;
  }
  return output;
}

function requireVerifiedReport(report: VerifiedSessionRecoveryArtifactsV1): void {
  if (!isVerifiedSessionRecoveryArtifacts(report)) {
    throw new SessionControllerError("UNAUTHENTICATED_REPORT");
  }
}
