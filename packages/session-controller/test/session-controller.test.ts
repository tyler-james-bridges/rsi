import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const verifierMocks = vi.hoisted(() => ({
  eventArchive: vi.fn(),
  releaseBundle: vi.fn(),
  stateEvidence: vi.fn(),
}));

vi.mock("@rsi/backup", () => ({
  verifySanitizedStateEvidence: verifierMocks.stateEvidence,
}));
vi.mock("@rsi/event-archive", () => ({
  verifySanitizedEventArchive: verifierMocks.eventArchive,
}));
vi.mock("@rsi/release-bundle", () => ({
  verifySignedReleaseBundle: verifierMocks.releaseBundle,
}));

import { SqliteSessionCoordinator } from "@rsi/session-lifecycle";

import {
  SessionControllerError,
  isVerifiedSessionRecoveryArtifacts,
  recordVerifiedLocalClosure,
  toSessionRecoveryArtifactEvidence,
  verifySessionRecoveryArtifacts,
  type SessionLocalVerificationFactsV1,
} from "../src/index.js";

const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const RELEASE_MANIFEST = "11".repeat(32);
const SIGNER_FINGERPRINT = "22".repeat(32);
const STATE_ARCHIVE = "33".repeat(32);
const EVENT_ARCHIVE = "44".repeat(32);
const RELEASE_ARCHIVE = "55".repeat(32);
const BACKUP_ID = "33333333-3333-4333-8333-333333333333";
const T0 = "2026-08-14T15:00:00.000Z";
const directories: string[] = [];
const coordinators: SqliteSessionCoordinator[] = [];

function plus(minutes: number): string {
  return new Date(Date.parse(T0) + minutes * 60_000).toISOString();
}

function verificationOptions() {
  return {
    eventArchive: { archivePath: "/event", trust: {} as never },
    expected: {
      profile: "canary" as const,
      releaseManifestSha256: RELEASE_MANIFEST,
      sessionId: SESSION_ID,
    },
    releaseBundle: { archivePath: "/release", trust: {} as never },
    stateEvidence: { archivePath: "/state", trust: {} as never },
  };
}

function localFacts(): SessionLocalVerificationFactsV1 {
  return {
    schemaVersion: 1,
    xLanes: {
      contract: "closed",
      discovery: "closed",
      marketplace: "closed",
      official: "closed",
      security: "closed",
    },
    openSea: { rest: "closed", stream: "closed" },
    canonicalChain: "closed",
    eventIntegrity: "verified",
    digestIntegrity: "verified",
    purge: {
      captureKeys: "destroyed",
      encryptedIndexes: "clean",
      orphanScan: "clean",
      rawCaptures: "clean",
    },
    localCheckpoint: "verified",
    alertCheck: "healthy",
    explicitClose: "complete",
    incidentCount: 0,
  };
}

function stoppingCoordinator(): SqliteSessionCoordinator {
  const directory = mkdtempSync(join(tmpdir(), "rsi-session-controller-"));
  directories.push(directory);
  const opened = SqliteSessionCoordinator.open({
    expectedProfile: "canary",
    path: join(directory, "session.sqlite"),
    recoveredAt: T0,
    stateKey: Uint8Array.from(randomBytes(32)),
  });
  const coordinator = opened.coordinator;
  coordinators.push(coordinator);
  coordinator.planSession({
    plannedAt: T0,
    qualificationDate: "2026-08-14",
    sessionId: SESSION_ID,
    supervisedUntil: plus(120),
  });
  coordinator.recordPreflight({
    evidence: {
      schemaVersion: 1,
      evidenceHash: "66".repeat(32),
      profile: "canary",
      observedAt: plus(1),
      ready: true,
      checks: {
        alertPath: "pass",
        backupTarget: "pass",
        budgetReservations: "pass",
        clock: "pass",
        credentialScopes: "pass",
        databaseIntegrity: "pass",
        disk: "pass",
        externalAnchor: "pass",
        financialAdaptersDisabled: "pass",
        networkAllowlist: "pass",
        releaseConfiguration: "pass",
        runtime: "pass",
      },
    },
    recordedAt: plus(1),
    sessionId: SESSION_ID,
  });
  coordinator.startSession({
    observerOnlyAcknowledgement: true,
    sessionId: SESSION_ID,
    startedAt: plus(2),
    typedSessionIdAcknowledgement: SESSION_ID,
  });
  coordinator.recordSupervisionAcknowledgement({
    acknowledgedAt: plus(47),
    checkpoint: "minute-45",
    sessionId: SESSION_ID,
  });
  coordinator.recordSupervisionAcknowledgement({
    acknowledgedAt: plus(92),
    checkpoint: "minute-90",
    sessionId: SESSION_ID,
  });
  coordinator.stopSession({ sessionId: SESSION_ID, stoppedAt: plus(100) });
  return coordinator;
}

beforeEach(() => {
  verifierMocks.stateEvidence.mockReset().mockResolvedValue({
    archiveSha256: STATE_ARCHIVE,
    artifactCount: 7,
    backupId: BACKUP_ID,
    checkpointHash: "77".repeat(32),
    componentScope: "observer-sanitized-state-evidence",
    manifestSha256: "88".repeat(32),
    profile: "canary",
    recoveryCompleteness: "evidence-only",
    releaseManifestSha256: RELEASE_MANIFEST,
    reportType: "rsi.backup.state-evidence-report",
    requiredCompanionArtifacts: ["sanitized-event-archive", "signed-release-bundle"],
    sessionId: SESSION_ID,
    signerFingerprintSha256: SIGNER_FINGERPRINT,
    status: "verified-evidence-component",
    totalArtifactBytes: 100,
    version: 1,
  });
  verifierMocks.eventArchive.mockReset().mockResolvedValue({
    archiveId: "44444444-4444-4444-8444-444444444444",
    archiveSha256: EVENT_ARCHIVE,
    artifactCount: 1,
    componentRole: "sanitized-event-archive",
    eventCount: 2,
    headHash: "99".repeat(32),
    headSequence: 2,
    manifestSha256: "aa".repeat(32),
    profile: "canary",
    releaseManifestSha256: RELEASE_MANIFEST,
    reportType: "rsi.sanitized-event-archive-report",
    sessionId: SESSION_ID,
    signerFingerprintSha256: SIGNER_FINGERPRINT,
    stateEvidenceBackupId: BACKUP_ID,
    status: "verified-restorable-event-archive",
    storeId: "observer-store-v1",
    version: 1,
  });
  verifierMocks.releaseBundle.mockReset().mockResolvedValue({
    archiveSha256: RELEASE_ARCHIVE,
    artifactCount: 20,
    bundleId: "55555555-5555-4555-8555-555555555555",
    commitSha: "b".repeat(40),
    companionType: "signed-release-bundle",
    gitTreeSha: "c".repeat(40),
    manifestSha256: RELEASE_MANIFEST,
    recoveryCompleteness: "release-component",
    releaseVersion: "1.0.0",
    reportType: "rsi.release-bundle.verification-report",
    requiredCompanionArtifacts: ["sanitized-state-evidence", "sanitized-event-archive"],
    signerFingerprintSha256: SIGNER_FINGERPRINT,
    status: "verified-restorable-release-component",
    totalArtifactBytes: 1_000,
    version: 1,
  });
});

afterEach(() => {
  for (const coordinator of coordinators.splice(0)) coordinator.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("session recovery controller", () => {
  it("derives exact recovery evidence and records local closure", async () => {
    const recovery = await verifySessionRecoveryArtifacts(verificationOptions());
    expect(isVerifiedSessionRecoveryArtifacts(recovery)).toBe(true);
    expect(toSessionRecoveryArtifactEvidence(recovery)).toEqual({
      sanitizedStateEvidence: {
        archiveSha256: STATE_ARCHIVE,
        status: "verified-evidence-component",
      },
      sanitizedEventArchive: {
        archiveSha256: EVENT_ARCHIVE,
        status: "verified-restorable-event-archive",
      },
      signedReleaseBundle: {
        archiveSha256: RELEASE_ARCHIVE,
        status: "verified-restorable-release-component",
      },
    });

    const coordinator = stoppingCoordinator();
    const record = recordVerifiedLocalClosure({
      coordinator,
      facts: localFacts(),
      recovery,
      sessionId: SESSION_ID,
      verifiedAt: plus(101),
    });
    expect(record.state).toBe("locally_verified");
    expect(record.localEvidence?.evidenceHash).toMatch(/^[0-9a-f]{64}$/);
    expect(record.localEvidence?.evidenceHash).not.toBe("0".repeat(64));
    expect(record.localEvidence?.recoveryArtifacts.sanitizedEventArchive.archiveSha256).toBe(
      EVENT_ARCHIVE,
    );
  });

  it("rejects inconsistent component identities and unverified report copies", async () => {
    verifierMocks.eventArchive.mockResolvedValueOnce({
      ...(await verifierMocks.eventArchive()),
      releaseManifestSha256: "ff".repeat(32),
    });
    await expect(verifySessionRecoveryArtifacts(verificationOptions())).rejects.toMatchObject({
      code: "RECOVERY_BINDING_MISMATCH",
    });

    const recovery = await verifySessionRecoveryArtifacts(verificationOptions());
    const clone = structuredClone(recovery);
    expect(isVerifiedSessionRecoveryArtifacts(clone)).toBe(false);
    expect(() => toSessionRecoveryArtifactEvidence(clone)).toThrow(
      new SessionControllerError("UNAUTHENTICATED_REPORT"),
    );
  });

  it("rejects proxy input before reading it and wraps component failures", async () => {
    let reads = 0;
    const proxied = new Proxy(verificationOptions(), {
      get(target, property, receiver) {
        reads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    await expect(verifySessionRecoveryArtifacts(proxied)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    expect(reads).toBe(0);
    expect(verifierMocks.stateEvidence).not.toHaveBeenCalled();

    verifierMocks.stateEvidence.mockRejectedValueOnce(new Error("provider detail"));
    await expect(verifySessionRecoveryArtifacts(verificationOptions())).rejects.toEqual(
      new SessionControllerError("COMPONENT_VERIFICATION_FAILED"),
    );
  });
});
