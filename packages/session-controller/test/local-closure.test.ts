import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const verifierMocks = vi.hoisted(() => ({
  eventArchive: vi.fn(),
  releaseBundle: vi.fn(),
  stateEvidence: vi.fn(),
}));

vi.mock("@rsi/backup", () => ({ verifySanitizedStateEvidence: verifierMocks.stateEvidence }));
vi.mock("@rsi/event-archive", () => ({
  verifySanitizedEventArchive: verifierMocks.eventArchive,
}));
vi.mock("@rsi/release-bundle", () => ({
  verifySignedReleaseBundle: verifierMocks.releaseBundle,
}));

import { AlertOutbox } from "@rsi/alerts";
import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import { CheckpointSigner } from "@rsi/checkpoints";
import { SqliteOperationsStore } from "@rsi/operations";
import { SqliteSessionCoordinator } from "@rsi/session-lifecycle";
import { SqliteEventStore } from "@rsi/store";
import { SnapshotVault } from "@rsi/vault";

import { verifyAndRecordLocalClosure, verifySessionRecoveryArtifacts } from "../src/index.js";

const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const RELEASE_MANIFEST = "11".repeat(32);
const SIGNER_FINGERPRINT = "22".repeat(32);
const T0 = "2026-08-14T15:00:00.000Z";
const directories: string[] = [];
const closers: Array<() => void | Promise<void>> = [];

function plus(minutes: number): string {
  return new Date(Date.parse(T0) + minutes * 60_000).toISOString();
}

beforeEach(() => {
  verifierMocks.stateEvidence.mockReset().mockResolvedValue({
    archiveSha256: "33".repeat(32),
    artifactCount: 7,
    backupId: "33333333-3333-4333-8333-333333333333",
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
    archiveSha256: "44".repeat(32),
    artifactCount: 1,
    componentRole: "sanitized-event-archive",
    eventCount: 1,
    headHash: "99".repeat(32),
    headSequence: 1,
    manifestSha256: "aa".repeat(32),
    profile: "canary",
    releaseManifestSha256: RELEASE_MANIFEST,
    reportType: "rsi.sanitized-event-archive-report",
    sessionId: SESSION_ID,
    signerFingerprintSha256: SIGNER_FINGERPRINT,
    stateEvidenceBackupId: "33333333-3333-4333-8333-333333333333",
    status: "verified-restorable-event-archive",
    storeId: "observer-store-v1",
    version: 1,
  });
  verifierMocks.releaseBundle.mockReset().mockResolvedValue({
    archiveSha256: "55".repeat(32),
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

afterEach(async () => {
  for (const close of closers.splice(0).reverse()) await close();
  for (const directory of directories.splice(0))
    rmSync(directory, { force: true, recursive: true });
});

async function recoveryReport() {
  return verifySessionRecoveryArtifacts({
    eventArchive: { archivePath: "/event", trust: {} as never },
    expected: {
      profile: "canary",
      releaseManifestSha256: RELEASE_MANIFEST,
      sessionId: SESSION_ID,
    },
    releaseBundle: { archivePath: "/release", trust: {} as never },
    stateEvidence: { archivePath: "/state", trust: {} as never },
  });
}

async function localFixture(withSources: boolean) {
  const directory = mkdtempSync(join(tmpdir(), "rsi-local-closure-"));
  directories.push(directory);
  const coordinator = SqliteSessionCoordinator.open({
    expectedProfile: "canary",
    path: join(directory, "session.sqlite"),
    recoveredAt: T0,
    stateKey: Uint8Array.from(randomBytes(32)),
  }).coordinator;
  closers.push(() => coordinator.close());
  coordinator.planSession({
    plannedAt: T0,
    qualificationDate: "2026-08-14",
    sessionId: SESSION_ID,
    supervisedUntil: plus(120),
  });
  coordinator.recordPreflight({
    evidence: {
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
      evidenceHash: "66".repeat(32),
      observedAt: plus(1),
      profile: "canary",
      ready: true,
      schemaVersion: 1,
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

  const eventStore = new SqliteEventStore(join(directory, "events.sqlite"));
  closers.push(() => eventStore.close());
  eventStore.append({
    aggregateId: SESSION_ID,
    occurredAt: plus(99),
    payload: { profile: "canary", schemaVersion: 1, sessionId: SESSION_ID },
    type: "session.closed.v1",
  });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const checkpointPath = join(directory, "checkpoints.jsonl");
  const signer = new CheckpointSigner({
    expectedJournalHead: null,
    journalPath: checkpointPath,
    keyId: "canary-checkpoint-v1",
    privateKey,
    storeId: "observer-store-v1",
  });
  signer.append(eventStore, { createdAt: plus(100) });

  const operationsStore = new SqliteOperationsStore({
    path: join(directory, "operations.sqlite"),
    stateKey: Uint8Array.from(randomBytes(32)),
  });
  closers.push(() => operationsStore.close());
  const budgetId = randomUUID();
  operationsStore.createBudget({
    budgetId,
    createdAt: T0,
    currency: "USD_MICRO",
    endsAt: plus(120),
    maxAtomic: "800000",
    maxAttempts: 8,
    profile: "canary",
    startsAt: T0,
  });
  if (withSources) addClosedSources(operationsStore, budgetId);

  const captureRegistry = SqliteCaptureRegistry.open({
    expectedProfile: "canary",
    path: join(directory, "captures.sqlite"),
    registryKey: Uint8Array.from(randomBytes(32)),
  });
  closers.push(() => captureRegistry.close());
  const vault = await SnapshotVault.open({
    directory: join(directory, "vault"),
    wrappingKey: Uint8Array.from(randomBytes(32)),
  });
  closers.push(() => vault.close());
  const alertOutbox = AlertOutbox.open({
    databasePath: join(directory, "alerts.sqlite"),
    profile: "canary",
    stateKey: Uint8Array.from(randomBytes(32)),
  });
  closers.push(() => alertOutbox.close());

  return {
    alertOutbox,
    captureRegistry,
    checkpoint: {
      expectedKeyId: "canary-checkpoint-v1",
      expectedPublicKey: publicKey,
      expectedStoreId: "observer-store-v1",
      journalPath: checkpointPath,
      trustedJournalHead: signer.journalHead!,
    },
    coordinator,
    eventStore,
    operationsStore,
    vault,
  };
}

function addClosedSources(store: SqliteOperationsStore, budgetId: string): void {
  const specifications = [
    ["official", "x.recent-search.v1", "social", "succeeded", "150000"],
    ["contract", "x.recent-search.v1", "social", "empty", "150000"],
    ["marketplace", "x.recent-search.v1", "social", "succeeded", "150000"],
    ["security", "x.recent-search.v1", "social", "succeeded", "150000"],
    ["discovery", "x.recent-search.v1", "social", "empty", "150000"],
    ["marketplace", "opensea.rest.v1", "marketplace", "succeeded", "1"],
    ["marketplace", "opensea.stream.v1", "marketplace", "empty", "1"],
    ["contract", "alchemy.json-rpc.v1", "canonical_chain", "succeeded", "1"],
  ] as const;
  for (const [lane, operation, sourcePlane, outcome, reservedAtomic] of specifications) {
    const permit = SqliteOperationsStore.createAttemptPermit();
    store.reserveAttempt({
      attemptId: permit.attemptId,
      authorizationExpiresAt: plus(20),
      budgetId,
      createdAt: plus(3),
      idempotencyKey: `ticket:${permit.attemptId}`,
      lane,
      operation,
      permitToken: permit.token,
      reservedAtomic,
      sessionId: SESSION_ID,
      sourcePlane,
    });
    store.authorizeAttempt(permit, plus(4));
    store.closeAttempt(permit.attemptId, { closedAt: plus(5), outcome });
  }
}

describe("genuine local closure composition", () => {
  it("derives passing local evidence from authenticated stores", async () => {
    const target = await localFixture(true);
    const result = await verifyAndRecordLocalClosure({
      ...target,
      recovery: await recoveryReport(),
      sessionId: SESSION_ID,
      verifiedAt: plus(101),
    });

    expect(result.record.state).toBe("locally_verified");
    expect(result.record.localEvidence).toMatchObject({
      alertCheck: "healthy",
      canonicalChain: "closed",
      digestIntegrity: "verified",
      eventIntegrity: "verified",
      incidentCount: 0,
      localCheckpoint: "verified",
      openSea: { rest: "closed", stream: "closed" },
      purge: {
        captureKeys: "destroyed",
        encryptedIndexes: "clean",
        orphanScan: "clean",
        rawCaptures: "clean",
      },
      xLanes: {
        contract: "closed",
        discovery: "closed",
        marketplace: "closed",
        official: "closed",
        security: "closed",
      },
    });
    expect(result.sourceSummary?.attemptCount).toBe(8);
    expect(result.captureRecovery).toMatchObject({ schemaVersion: 1 });
  });

  it("records an invalid session when required source closure is missing", async () => {
    const target = await localFixture(false);
    const result = await verifyAndRecordLocalClosure({
      ...target,
      recovery: await recoveryReport(),
      sessionId: SESSION_ID,
      verifiedAt: plus(101),
    });

    expect(result.record).toMatchObject({
      invalidationReason: "source-incomplete",
      state: "invalid",
    });
    expect(result.record.localEvidence?.xLanes.official).toBe("failed");
  });

  it("rejects an unauthenticated dependency before cleanup or lifecycle mutation", async () => {
    const target = await localFixture(true);
    const before = target.coordinator.getSession(SESSION_ID);
    await expect(
      verifyAndRecordLocalClosure({
        ...target,
        operationsStore: Object.create(SqliteOperationsStore.prototype) as SqliteOperationsStore,
        recovery: await recoveryReport(),
        sessionId: SESSION_ID,
        verifiedAt: plus(101),
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    expect(target.coordinator.getSession(SESSION_ID)).toEqual(before);
  });
});
