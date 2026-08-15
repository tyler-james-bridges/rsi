import { randomBytes, randomUUID } from "node:crypto";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  SessionLifecycleConflictError,
  SessionLifecycleIntegrityError,
  SessionLifecycleValidationError,
  SqliteSessionCoordinator,
  isSqliteSessionCoordinator,
  type SessionCostEvidenceV1,
  type SessionExternalVerificationEvidenceV1,
  type SessionLocalVerificationEvidenceV1,
  type SessionPreflightEvidenceV1,
  type SessionRecordV1,
} from "../src/index.js";

const T0 = "2026-08-14T15:00:00.000Z";
const QUALIFICATION_DATE = "2026-08-14";
const EVIDENCE_HASH = "ab".repeat(32);
const directories: string[] = [];
const coordinators: SqliteSessionCoordinator[] = [];

afterEach(() => {
  for (const coordinator of coordinators.splice(0)) coordinator.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

function plus(timestamp: string, minutes: number): string {
  return new Date(Date.parse(timestamp) + minutes * 60_000).toISOString();
}

function timeline(base = T0) {
  return {
    plan: base,
    preflight: plus(base, 1),
    start: plus(base, 2),
    minute45: plus(base, 47),
    minute90: plus(base, 92),
    stop: plus(base, 100),
    local: plus(base, 101),
    external: plus(base, 102),
    cost: plus(base, 103),
    accept: plus(base, 104),
    supervisedUntil: plus(base, 120),
  };
}

function passingPreflight(observedAt: string): SessionPreflightEvidenceV1 {
  return {
    schemaVersion: 1,
    evidenceHash: EVIDENCE_HASH,
    profile: "canary",
    observedAt,
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
  };
}

function passingLocal(): SessionLocalVerificationEvidenceV1 {
  return {
    schemaVersion: 1,
    evidenceHash: EVIDENCE_HASH,
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
    recoveryArtifacts: {
      sanitizedStateEvidence: {
        archiveSha256: EVIDENCE_HASH,
        status: "verified-evidence-component",
      },
      sanitizedEventArchive: {
        archiveSha256: EVIDENCE_HASH,
        status: "verified-restorable-event-archive",
      },
      signedReleaseBundle: {
        archiveSha256: EVIDENCE_HASH,
        status: "verified-restorable-release-component",
      },
    },
    alertCheck: "healthy",
    explicitClose: "complete",
    incidentCount: 0,
  };
}

function passingExternal(): SessionExternalVerificationEvidenceV1 {
  return {
    schemaVersion: 1,
    evidenceHash: EVIDENCE_HASH,
    externalAnchor: "verified",
    retainedSuffix: "verified",
    macBookVerification: "verified",
  };
}

function passingCost(): SessionCostEvidenceV1 {
  return {
    schemaVersion: 1,
    evidenceHash: EVIDENCE_HASH,
    billingStatus: "complete",
    currency: "USD_MICRO",
    outstandingAtomic: "0",
    reconciledAtomic: "125000",
    reservedAtomic: "150000",
  };
}

function fixture(profile: "canary" | "production-observer" = "canary") {
  const directory = mkdtempSync(join(tmpdir(), "rsi-session-lifecycle-"));
  directories.push(directory);
  const path = join(directory, "session.sqlite");
  const stateKey = Uint8Array.from(randomBytes(32));
  const opened = SqliteSessionCoordinator.open({
    expectedProfile: profile,
    path,
    recoveredAt: T0,
    stateKey,
  });
  coordinators.push(opened.coordinator);
  return { ...opened, directory, path, stateKey };
}

function plan(
  coordinator: SqliteSessionCoordinator,
  sessionId: string = randomUUID(),
  times = timeline(),
): Readonly<SessionRecordV1> {
  return coordinator.planSession({
    plannedAt: times.plan,
    qualificationDate: QUALIFICATION_DATE,
    sessionId,
    supervisedUntil: times.supervisedUntil,
  });
}

function advanceToRunning(
  coordinator: SqliteSessionCoordinator,
  sessionId: string,
  times = timeline(),
) {
  plan(coordinator, sessionId, times);
  coordinator.recordPreflight({
    evidence: passingPreflight(times.preflight),
    recordedAt: times.preflight,
    sessionId,
  });
  return coordinator.startSession({
    observerOnlyAcknowledgement: true,
    sessionId,
    startedAt: times.start,
    typedSessionIdAcknowledgement: sessionId,
  });
}

function advanceToStopping(
  coordinator: SqliteSessionCoordinator,
  sessionId: string,
  times = timeline(),
) {
  advanceToRunning(coordinator, sessionId, times);
  coordinator.recordSupervisionAcknowledgement({
    acknowledgedAt: times.minute45,
    checkpoint: "minute-45",
    sessionId,
  });
  coordinator.recordSupervisionAcknowledgement({
    acknowledgedAt: times.minute90,
    checkpoint: "minute-90",
    sessionId,
  });
  return coordinator.stopSession({ sessionId, stoppedAt: times.stop });
}

function advanceToCostPending(
  coordinator: SqliteSessionCoordinator,
  sessionId: string,
  times = timeline(),
) {
  advanceToStopping(coordinator, sessionId, times);
  coordinator.recordLocalVerification({
    evidence: passingLocal(),
    sessionId,
    verifiedAt: times.local,
  });
  coordinator.recordExternalVerification({
    evidence: passingExternal(),
    sessionId,
    verifiedAt: times.external,
  });
  return coordinator.recordCostReconciliation({
    evidence: passingCost(),
    reconciledAt: times.cost,
    sessionId,
  });
}

function accept(
  coordinator: SqliteSessionCoordinator,
  sessionId: string = randomUUID(),
  times = timeline(),
) {
  advanceToCostPending(coordinator, sessionId, times);
  return coordinator.acceptSession({ acceptedAt: times.accept, sessionId });
}

describe("SqliteSessionCoordinator", () => {
  it("executes the complete Observer v1 lifecycle and composes only closed acceptance evidence", () => {
    const target = fixture();
    expect(target.recovery).toEqual({
      cleanupRequired: false,
      invalidatedSessionCount: 0,
      schemaVersion: 1,
    });
    expect(isSqliteSessionCoordinator(target.coordinator)).toBe(true);
    expect(isSqliteSessionCoordinator(Object.create(SqliteSessionCoordinator.prototype))).toBe(
      false,
    );

    const RuntimeCoordinator = SqliteSessionCoordinator as unknown as new (
      path: string,
      profile: "canary",
      macKey: Buffer,
      constructionToken: object,
    ) => SqliteSessionCoordinator;
    expect(
      () =>
        new RuntimeCoordinator(
          join(target.directory, "constructor-bypass.sqlite"),
          "canary",
          randomBytes(32),
          Object.freeze({}),
        ),
    ).toThrow(SessionLifecycleIntegrityError);

    const forged = Object.create(SqliteSessionCoordinator.prototype) as SqliteSessionCoordinator;
    expect(() => forged.verifyIntegrity()).toThrow(SessionLifecycleIntegrityError);
    expect(() => forged.close()).toThrow(SessionLifecycleIntegrityError);

    const sessionId = randomUUID();
    const accepted = accept(target.coordinator, sessionId);
    expect(accepted).toMatchObject({
      acceptanceEvidence: {
        evidenceHashes: {
          cost: EVIDENCE_HASH,
          external: EVIDENCE_HASH,
          local: EVIDENCE_HASH,
          preflight: EVIDENCE_HASH,
        },
        preflight: "pass",
        incidents: "zero",
        recoveryArtifacts: {
          sanitizedStateEvidence: {
            archiveSha256: EVIDENCE_HASH,
            status: "verified-evidence-component",
          },
          sanitizedEventArchive: {
            archiveSha256: EVIDENCE_HASH,
            status: "verified-restorable-event-archive",
          },
          signedReleaseBundle: {
            archiveSha256: EVIDENCE_HASH,
            status: "verified-restorable-release-component",
          },
        },
        supervision: { minute45: "acknowledged", minute90: "acknowledged" },
      },
      egressStatus: "blocked",
      qualificationDate: QUALIFICATION_DATE,
      state: "accepted",
    });
    expect(Object.isFrozen(accepted)).toBe(true);
    expect(Object.isFrozen(accepted.acceptanceEvidence)).toBe(true);
    expect(target.coordinator.getSummary()).toMatchObject({
      activeSessionCount: 0,
      auditEntryCount: 10,
      sessionCount: 1,
      states: { accepted: 1 },
    });
    expect(target.coordinator.verifyIntegrity()).toMatchObject({ valid: true });
    expect("createNetworkAttemptAuthorization" in target.coordinator).toBe(false);
    expect("commitCursor" in target.coordinator).toBe(false);

    const serialized = JSON.stringify({ accepted, summary: target.coordinator.getSummary() });
    for (const forbidden of ["providerId", "sourceId", "query", "https://", "bearer"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("requires canonical lowercase UUIDv4 session IDs and an ordinary exact Uint8Array key", () => {
    const target = fixture();
    for (const invalidSessionId of [
      "00000000-0000-0000-0000-000000000000",
      "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      randomUUID().toUpperCase(),
    ]) {
      expect(() =>
        target.coordinator.planSession({
          plannedAt: T0,
          qualificationDate: QUALIFICATION_DATE,
          sessionId: invalidSessionId,
          supervisedUntil: timeline().supervisedUntil,
        }),
      ).toThrow(SessionLifecycleValidationError);
    }
    expect(target.coordinator.getSummary().sessionCount).toBe(0);

    const directory = mkdtempSync(join(tmpdir(), "rsi-session-key-shape-"));
    directories.push(directory);
    const path = join(directory, "session.sqlite");
    const baseOptions = {
      expectedProfile: "canary" as const,
      path,
      recoveredAt: T0,
    };
    expect(() =>
      SqliteSessionCoordinator.open({ ...baseOptions, stateKey: randomBytes(32) }),
    ).toThrow(SessionLifecycleValidationError);

    class DerivedKey extends Uint8Array {}
    expect(() =>
      SqliteSessionCoordinator.open({ ...baseOptions, stateKey: new DerivedKey(32) }),
    ).toThrow(SessionLifecycleValidationError);

    const sharedKey = new Uint8Array(new SharedArrayBuffer(32)) as unknown as Uint8Array;
    expect(() => SqliteSessionCoordinator.open({ ...baseOptions, stateKey: sharedKey })).toThrow(
      SessionLifecycleValidationError,
    );
    const proxiedKey = new Proxy(new Uint8Array(32), {});
    expect(() => SqliteSessionCoordinator.open({ ...baseOptions, stateKey: proxiedKey })).toThrow(
      SessionLifecycleValidationError,
    );

    const ordinaryKey = new Uint8Array(32);
    const opened = SqliteSessionCoordinator.open({ ...baseOptions, stateKey: ordinaryKey });
    coordinators.push(opened.coordinator);
    ordinaryKey.fill(255);
    expect(opened.coordinator.verifyIntegrity().valid).toBe(true);
  });

  it("rejects skipped transitions and enforces one active session and one writer", () => {
    const target = fixture();
    const firstId = randomUUID();
    plan(target.coordinator, firstId);
    expect(() =>
      target.coordinator.startSession({
        observerOnlyAcknowledgement: true,
        sessionId: firstId,
        startedAt: timeline().start,
        typedSessionIdAcknowledgement: firstId,
      }),
    ).toThrow(SessionLifecycleConflictError);
    expect(() => plan(target.coordinator)).toThrowError(
      expect.objectContaining({ code: "ACTIVE_SESSION_CONFLICT" }),
    );
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: target.path,
        recoveredAt: timeline().start,
        stateKey: target.stateKey,
      }),
    ).toThrowError(expect.objectContaining({ code: "WRITER_CONFLICT" }));

    target.coordinator.invalidateSession({
      invalidatedAt: timeline().preflight,
      reason: "operator-abort",
      sessionId: firstId,
    });
    expect(
      plan(target.coordinator, randomUUID(), { ...timeline(), plan: timeline().start }),
    ).toMatchObject({
      state: "planned",
    });
  });

  it("returns the original result for exact retries and rejects changed retries", () => {
    const target = fixture();
    const sessionId = randomUUID();
    const input = {
      plannedAt: timeline().plan,
      qualificationDate: QUALIFICATION_DATE,
      sessionId,
      supervisedUntil: timeline().supervisedUntil,
    };
    const original = target.coordinator.planSession(input);
    expect(target.coordinator.planSession(input)).toEqual(original);
    target.coordinator.recordPreflight({
      evidence: passingPreflight(timeline().preflight),
      recordedAt: timeline().preflight,
      sessionId,
    });
    expect(target.coordinator.planSession(input)).toEqual(original);
    expect(() =>
      target.coordinator.planSession({ ...input, supervisedUntil: plus(input.supervisedUntil, 1) }),
    ).toThrowError(expect.objectContaining({ code: "RETRY_CONFLICT" }));
    expect(target.coordinator.getSummary().auditEntryCount).toBe(2);
  });

  it("requires exact start acknowledgements and fails closed on supervision bounds", () => {
    const target = fixture();
    const sessionId = randomUUID();
    plan(target.coordinator, sessionId);
    target.coordinator.recordPreflight({
      evidence: passingPreflight(timeline().preflight),
      recordedAt: timeline().preflight,
      sessionId,
    });
    expect(() =>
      target.coordinator.startSession({
        observerOnlyAcknowledgement: true,
        sessionId,
        startedAt: timeline().start,
        typedSessionIdAcknowledgement: randomUUID(),
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(target.coordinator.getSession(sessionId)?.state).toBe("preflighted");

    target.coordinator.startSession({
      observerOnlyAcknowledgement: true,
      sessionId,
      startedAt: timeline().start,
      typedSessionIdAcknowledgement: sessionId,
    });
    const beforeEarlyAcknowledgement = target.coordinator.getSummary();
    expect(() =>
      target.coordinator.recordSupervisionAcknowledgement({
        acknowledgedAt: plus(timeline().start, 44),
        checkpoint: "minute-45",
        sessionId,
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(target.coordinator.getSummary()).toEqual(beforeEarlyAcknowledgement);
    expect(() =>
      target.coordinator.recordSupervisionAcknowledgement({
        acknowledgedAt: timeline().minute90,
        checkpoint: "minute-90",
        sessionId,
      }),
    ).toThrow(SessionLifecycleConflictError);
    const invalid = target.coordinator.recordSupervisionAcknowledgement({
      acknowledgedAt: plus(timeline().supervisedUntil, 1),
      checkpoint: "minute-45",
      sessionId,
    });
    expect(invalid).toMatchObject({
      egressStatus: "blocked",
      invalidationReason: "missed-supervision-acknowledgement",
      state: "invalid",
    });
  });

  it("invalidates a stop that misses either required supervision acknowledgement", () => {
    const target = fixture();
    const sessionId = randomUUID();
    advanceToRunning(target.coordinator, sessionId);
    target.coordinator.recordSupervisionAcknowledgement({
      acknowledgedAt: timeline().minute45,
      checkpoint: "minute-45",
      sessionId,
    });
    const invalid = target.coordinator.stopSession({ sessionId, stoppedAt: timeline().stop });
    expect(invalid).toMatchObject({
      egressStatus: "blocked",
      invalidationReason: "missed-supervision-acknowledgement",
      state: "invalid",
    });
  });

  it("rejects malformed, accessor, proxy, and unknown evidence with zero mutation", () => {
    const target = fixture();
    const sessionId = randomUUID();
    plan(target.coordinator, sessionId);
    const before = target.coordinator.getSummary();
    const evidence = passingPreflight(timeline().preflight);

    expect(() =>
      target.coordinator.recordPreflight({
        evidence: { ...evidence, extra: "hostile provider text" } as never,
        recordedAt: timeline().preflight,
        sessionId,
      }),
    ).toThrow(SessionLifecycleValidationError);

    let getterCalls = 0;
    const accessor = { ...evidence } as Record<string, unknown>;
    Object.defineProperty(accessor, "ready", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return true;
      },
    });
    expect(() =>
      target.coordinator.recordPreflight({
        evidence: accessor as never,
        recordedAt: timeline().preflight,
        sessionId,
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(getterCalls).toBe(0);

    let proxyReads = 0;
    const proxy = new Proxy(evidence, {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    expect(() =>
      target.coordinator.recordPreflight({
        evidence: proxy,
        recordedAt: timeline().preflight,
        sessionId,
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(proxyReads).toBe(0);
    expect(target.coordinator.getSession(sessionId)?.state).toBe("planned");
    expect(target.coordinator.getSummary()).toEqual(before);
  });

  it("requires lowercase sanitized-evidence hashes and both bounded backup components", () => {
    const hashTarget = fixture();
    const hashId = randomUUID();
    plan(hashTarget.coordinator, hashId);
    const evidence = passingPreflight(timeline().preflight);
    expect(() =>
      hashTarget.coordinator.recordPreflight({
        evidence: { ...evidence, evidenceHash: EVIDENCE_HASH.toUpperCase() },
        recordedAt: timeline().preflight,
        sessionId: hashId,
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(() =>
      hashTarget.coordinator.recordPreflight({
        evidence: Object.fromEntries(
          Object.entries(evidence).filter(([key]) => key !== "evidenceHash"),
        ) as never,
        recordedAt: timeline().preflight,
        sessionId: hashId,
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(hashTarget.coordinator.getSession(hashId)?.state).toBe("planned");

    const backupTarget = fixture();
    const backupId = randomUUID();
    advanceToStopping(backupTarget.coordinator, backupId);
    const local = passingLocal();
    expect(() =>
      backupTarget.coordinator.recordLocalVerification({
        evidence: {
          ...local,
          sanitizedBackup: "verified",
        } as never,
        sessionId: backupId,
        verifiedAt: timeline().local,
      }),
    ).toThrow(SessionLifecycleValidationError);
    expect(backupTarget.coordinator.getSession(backupId)?.state).toBe("stopping");
    expect(
      backupTarget.coordinator.recordLocalVerification({
        evidence: {
          ...local,
          recoveryArtifacts: {
            ...local.recoveryArtifacts,
            signedReleaseBundle: { archiveSha256: null, status: "unknown" },
          },
        },
        sessionId: backupId,
        verifiedAt: timeline().local,
      }),
    ).toMatchObject({
      invalidationReason: "local-verification-failed",
      state: "invalid",
    });
  });

  it("atomically invalidates well-formed negative preflight and local evidence", () => {
    const preflightTarget = fixture();
    const preflightId = randomUUID();
    plan(preflightTarget.coordinator, preflightId);
    const failedPreflight = passingPreflight(timeline().preflight);
    const invalidPreflight = preflightTarget.coordinator.recordPreflight({
      evidence: {
        ...failedPreflight,
        ready: false,
        checks: { ...failedPreflight.checks, clock: "unknown" },
      },
      recordedAt: timeline().preflight,
      sessionId: preflightId,
    });
    expect(invalidPreflight).toMatchObject({
      invalidationReason: "preflight-failed",
      state: "invalid",
    });

    const localTarget = fixture();
    const localId = randomUUID();
    advanceToStopping(localTarget.coordinator, localId);
    const local = passingLocal();
    const invalidLocal = localTarget.coordinator.recordLocalVerification({
      evidence: { ...local, incidentCount: 1 },
      sessionId: localId,
      verifiedAt: timeline().local,
    });
    expect(invalidLocal).toMatchObject({
      invalidationReason: "incident-detected",
      state: "invalid",
    });
  });

  it("invalidates failed external verification and every unsafe cost reconciliation", () => {
    const externalTarget = fixture();
    const externalId = randomUUID();
    advanceToStopping(externalTarget.coordinator, externalId);
    externalTarget.coordinator.recordLocalVerification({
      evidence: passingLocal(),
      sessionId: externalId,
      verifiedAt: timeline().local,
    });
    expect(
      externalTarget.coordinator.recordExternalVerification({
        evidence: { ...passingExternal(), macBookVerification: "unknown" },
        sessionId: externalId,
        verifiedAt: timeline().external,
      }),
    ).toMatchObject({ invalidationReason: "external-verification-failed", state: "invalid" });

    const costTarget = fixture();
    const costId = randomUUID();
    advanceToStopping(costTarget.coordinator, costId);
    costTarget.coordinator.recordLocalVerification({
      evidence: passingLocal(),
      sessionId: costId,
      verifiedAt: timeline().local,
    });
    costTarget.coordinator.recordExternalVerification({
      evidence: passingExternal(),
      sessionId: costId,
      verifiedAt: timeline().external,
    });
    expect(
      costTarget.coordinator.recordCostReconciliation({
        evidence: { ...passingCost(), reconciledAtomic: "150001" },
        reconciledAt: timeline().cost,
        sessionId: costId,
      }),
    ).toMatchObject({ invalidationReason: "cost-over-reservation", state: "invalid" });

    const lateTarget = fixture();
    const lateId = randomUUID();
    advanceToStopping(lateTarget.coordinator, lateId);
    lateTarget.coordinator.recordLocalVerification({
      evidence: passingLocal(),
      sessionId: lateId,
      verifiedAt: timeline().local,
    });
    lateTarget.coordinator.recordExternalVerification({
      evidence: passingExternal(),
      sessionId: lateId,
      verifiedAt: timeline().external,
    });
    expect(
      lateTarget.coordinator.recordCostReconciliation({
        evidence: passingCost(),
        reconciledAt: plus(timeline().stop, 48 * 60 + 1),
        sessionId: lateId,
      }),
    ).toMatchObject({ invalidationReason: "cost-reconciliation-late", state: "invalid" });
  });

  it("requires acceptance after cost reconciliation and forbids incomplete acceptance", () => {
    const target = fixture();
    const sessionId = randomUUID();
    advanceToCostPending(target.coordinator, sessionId);
    expect(() =>
      target.coordinator.acceptSession({ acceptedAt: timeline().external, sessionId }),
    ).toThrow(SessionLifecycleValidationError);
    expect(target.coordinator.getSession(sessionId)?.state).toBe("cost_pending");

    const incompleteTarget = fixture();
    const incompleteId = randomUUID();
    advanceToStopping(incompleteTarget.coordinator, incompleteId);
    expect(() =>
      incompleteTarget.coordinator.acceptSession({
        acceptedAt: timeline().accept,
        sessionId: incompleteId,
      }),
    ).toThrow(SessionLifecycleConflictError);
  });

  it("invalidates every nonterminal session on reopen and returns an aggregate-only cleanup receipt", () => {
    const target = fixture();
    const sessionId = randomUUID();
    advanceToRunning(target.coordinator, sessionId);
    const trustedHead = target.coordinator.getTrustedHead();
    target.coordinator.close();

    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: target.path,
        recoveredAt: timeline().minute45,
        stateKey: target.stateKey,
      }),
    ).toThrow(SessionLifecycleIntegrityError);

    const reopened = SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: target.path,
      recoveredAt: timeline().minute45,
      stateKey: target.stateKey,
      trustedHead,
    });
    coordinators.push(reopened.coordinator);
    expect(reopened.recovery).toEqual({
      cleanupRequired: true,
      invalidatedSessionCount: 1,
      schemaVersion: 1,
    });
    expect(JSON.stringify(reopened.recovery)).not.toContain(sessionId);
    expect(reopened.coordinator.getSession(sessionId)).toMatchObject({
      egressStatus: "blocked",
      invalidationReason: "crash-recovery",
      state: "invalid",
    });
    expect(reopened.coordinator.getSummary().activeSessionCount).toBe(0);
  });

  it("does not partially recover under a backward restart clock", () => {
    const target = fixture();
    const sessionId = randomUUID();
    advanceToRunning(target.coordinator, sessionId);
    const trustedHead = target.coordinator.getTrustedHead();
    target.coordinator.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: target.path,
        recoveredAt: timeline().preflight,
        stateKey: target.stateKey,
        trustedHead,
      }),
    ).toThrow(SessionLifecycleValidationError);

    const reopened = SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: target.path,
      recoveredAt: timeline().minute45,
      stateKey: target.stateKey,
      trustedHead,
    });
    coordinators.push(reopened.coordinator);
    expect(reopened.recovery.invalidatedSessionCount).toBe(1);
    expect(reopened.coordinator.getSession(sessionId)?.invalidationReason).toBe("crash-recovery");
  });

  it("rejects wrong profile and key without mutating the authenticated database", () => {
    const target = fixture();
    const sessionId = randomUUID();
    plan(target.coordinator, sessionId);
    const trustedHead = target.coordinator.getTrustedHead();
    target.coordinator.close();

    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: target.path,
        recoveredAt: timeline().preflight,
        stateKey: Uint8Array.from(randomBytes(32)),
        trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "production-observer",
        path: target.path,
        recoveredAt: timeline().preflight,
        stateKey: target.stateKey,
        trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);

    const reopened = SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: target.path,
      recoveredAt: timeline().preflight,
      stateKey: target.stateKey,
      trustedHead,
    });
    coordinators.push(reopened.coordinator);
    expect(reopened.recovery.invalidatedSessionCount).toBe(1);
    expect(reopened.coordinator.getSession(sessionId)?.state).toBe("invalid");
  });

  it("binds qualification dates to America/Phoenix and permits only one accepted session per date", () => {
    const target = fixture();
    expect(() =>
      target.coordinator.planSession({
        plannedAt: T0,
        qualificationDate: "2026-08-15",
        sessionId: randomUUID(),
        supervisedUntil: timeline().supervisedUntil,
      }),
    ).toThrow(SessionLifecycleValidationError);

    accept(target.coordinator, randomUUID());
    const secondTimes = timeline(plus(T0, 105));
    const secondId = randomUUID();
    advanceToCostPending(target.coordinator, secondId, secondTimes);
    expect(
      target.coordinator.acceptSession({ acceptedAt: secondTimes.accept, sessionId: secondId }),
    ).toMatchObject({
      invalidationReason: "qualification-date-conflict",
      state: "invalid",
    });

    const thirdTimes = timeline(plus(T0, 210));
    expect(plan(target.coordinator, randomUUID(), thirdTimes).state).toBe("planned");
  });

  it("binds the qualification date to the actual Phoenix start date as well as planning", () => {
    const target = fixture();
    const sessionId = randomUUID();
    const plannedAt = "2026-08-15T06:59:00.000Z";
    const preflightAt = "2026-08-15T07:00:00.000Z";
    const startedAt = "2026-08-15T07:01:00.000Z";
    target.coordinator.planSession({
      plannedAt,
      qualificationDate: "2026-08-14",
      sessionId,
      supervisedUntil: "2026-08-15T09:00:00.000Z",
    });
    target.coordinator.recordPreflight({
      evidence: passingPreflight(preflightAt),
      recordedAt: preflightAt,
      sessionId,
    });
    expect(
      target.coordinator.startSession({
        observerOnlyAcknowledgement: true,
        sessionId,
        startedAt,
        typedSessionIdAcknowledgement: sessionId,
      }),
    ).toMatchObject({ invalidationReason: "bound-violation", state: "invalid" });
  });

  it("refuses to initialize over a prior namespace or silently replace missing metadata", () => {
    const missingMetadata = fixture();
    missingMetadata.coordinator.close();
    let database = new DatabaseSync(missingMetadata.path);
    database.exec("DELETE FROM rsi_session_lifecycle_metadata");
    database.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: missingMetadata.path,
        recoveredAt: T0,
        stateKey: missingMetadata.stateKey,
      }),
    ).toThrow(SessionLifecycleIntegrityError);

    const directory = mkdtempSync(join(tmpdir(), "rsi-session-prior-namespace-"));
    directories.push(directory);
    const path = join(directory, "session.sqlite");
    database = new DatabaseSync(path);
    database.exec("CREATE TABLE prior_state (value INTEGER)");
    database.exec(
      "CREATE TRIGGER prior_trigger AFTER INSERT ON prior_state BEGIN UPDATE prior_state SET value = value; END",
    );
    database.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path,
        recoveredAt: T0,
        stateKey: new Uint8Array(32),
      }),
    ).toThrow(SessionLifecycleIntegrityError);
    database = new DatabaseSync(path);
    const names = database
      .prepare("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
      .all() as unknown as { name: string }[];
    database.close();
    expect(names.map((row) => row.name)).toEqual(["prior_state", "prior_trigger"]);

    const emptyPath = join(directory, "empty.sqlite");
    database = new DatabaseSync(emptyPath);
    database.close();
    const initialized = SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: emptyPath,
      recoveredAt: T0,
      stateKey: new Uint8Array(32),
    });
    coordinators.push(initialized.coordinator);
    expect(initialized.coordinator.verifyIntegrity().valid).toBe(true);
  });

  it("exports a pinned trusted head that rejects rollback of an otherwise authentic whole DB", () => {
    const target = fixture();
    const sessionId = randomUUID();
    plan(target.coordinator, sessionId);
    const priorHead = target.coordinator.getTrustedHead();
    target.coordinator.close();
    const rolledBackCopy = join(target.directory, "rolled-back.sqlite");
    copyFileSync(target.path, rolledBackCopy);

    const advanced = SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: target.path,
      recoveredAt: timeline().preflight,
      stateKey: target.stateKey,
      trustedHead: priorHead,
    });
    coordinators.push(advanced.coordinator);
    const trustedHead = advanced.coordinator.getTrustedHead();
    expect(trustedHead).toMatchObject({ auditSequence: 2, profile: "canary", schemaVersion: 1 });
    expect(JSON.stringify(trustedHead)).not.toContain(sessionId);
    advanced.coordinator.close();

    const suffixAccepted = SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: target.path,
      recoveredAt: timeline().start,
      stateKey: target.stateKey,
      trustedHead: priorHead,
    });
    coordinators.push(suffixAccepted.coordinator);
    expect(suffixAccepted.recovery.invalidatedSessionCount).toBe(0);
    expect(suffixAccepted.coordinator.getTrustedHead()).toEqual(trustedHead);
    suffixAccepted.coordinator.close();

    copyFileSync(rolledBackCopy, target.path);
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: target.path,
        recoveredAt: timeline().preflight,
        stateKey: target.stateKey,
        trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);
  });

  it("detects authenticated session-row, audit-tail, metadata, and schema tampering", () => {
    const makeAcceptedDatabase = () => {
      const target = fixture();
      accept(target.coordinator);
      const trustedHead = target.coordinator.getTrustedHead();
      target.coordinator.close();
      return { ...target, trustedHead };
    };

    const rowTarget = makeAcceptedDatabase();
    let database = new DatabaseSync(rowTarget.path);
    database.prepare("UPDATE rsi_session_lifecycle_sessions SET record_json = ?").run("{}");
    database.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: rowTarget.path,
        recoveredAt: plus(T0, 200),
        stateKey: rowTarget.stateKey,
        trustedHead: rowTarget.trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);

    const tailTarget = makeAcceptedDatabase();
    database = new DatabaseSync(tailTarget.path);
    database.exec(
      "DELETE FROM rsi_session_lifecycle_audit WHERE sequence = (SELECT MAX(sequence) FROM rsi_session_lifecycle_audit)",
    );
    database.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: tailTarget.path,
        recoveredAt: plus(T0, 200),
        stateKey: tailTarget.stateKey,
        trustedHead: tailTarget.trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);

    const metadataTarget = makeAcceptedDatabase();
    database = new DatabaseSync(metadataTarget.path);
    database.exec("UPDATE rsi_session_lifecycle_metadata SET schema_version = 9");
    database.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: metadataTarget.path,
        recoveredAt: plus(T0, 200),
        stateKey: metadataTarget.stateKey,
        trustedHead: metadataTarget.trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);

    const schemaTarget = makeAcceptedDatabase();
    database = new DatabaseSync(schemaTarget.path);
    database.exec("ALTER TABLE rsi_session_lifecycle_sessions ADD COLUMN injected TEXT");
    database.close();
    expect(() =>
      SqliteSessionCoordinator.open({
        expectedProfile: "canary",
        path: schemaTarget.path,
        recoveredAt: plus(T0, 200),
        stateKey: schemaTarget.stateKey,
        trustedHead: schemaTarget.trustedHead,
      }),
    ).toThrow(SessionLifecycleIntegrityError);
  });
});
