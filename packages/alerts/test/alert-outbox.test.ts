import { randomBytes, randomUUID } from "node:crypto";
import { copyFile, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  AlertConflictError,
  AlertIntegrityError,
  AlertOutbox,
  AlertValidationError,
  IncidentCodeSchema,
  isAlertOutbox,
  type AlertProfile,
  type AlertTrustedHeadV1,
  type IncidentAlertV1,
} from "../src/index.js";

const TEMPORARY_DIRECTORIES: string[] = [];
const STATE_KEY = new Uint8Array(32).fill(0x41);
const OTHER_KEY = new Uint8Array(32).fill(0x42);
const OCCURRED_AT = "2026-08-14T12:00:00.000Z";
const QUEUED_AT = "2026-08-14T12:00:01.000Z";
const CLAIMED_AT = "2026-08-14T12:00:02.000Z";
const SESSION_ID = "c520ae5a-51cd-46b9-ad49-89679e169b70";

afterEach(async () => {
  await Promise.all(
    TEMPORARY_DIRECTORIES.splice(0).map(async (directory) => {
      await rm(directory, { force: true, recursive: true });
    }),
  );
});

async function target(profile: AlertProfile = "canary") {
  const directory = await mkdtemp(join(tmpdir(), "rsi-alerts-test-"));
  TEMPORARY_DIRECTORIES.push(directory);
  const databasePath = join(directory, "alerts.sqlite");
  const outbox = AlertOutbox.open({ databasePath, profile, stateKey: STATE_KEY });
  return { databasePath, directory, outbox };
}

function alert(
  incidentId = "9f703c65-5602-42db-b93d-73a84208869a",
  profile: AlertProfile = "canary",
  sessionId = SESSION_ID,
): IncidentAlertV1 {
  return {
    schemaVersion: "incident-alert.v1",
    incidentId,
    incidentCode: "INTEGRITY_MISMATCH",
    severity: "critical",
    occurredAt: OCCURRED_AT,
    profile,
    sessionId,
    templateRevision: 1,
    instruction: "OPEN_LOCAL_RSI_CONSOLE",
  };
}

function enqueue(outbox: AlertOutbox, incident = alert()) {
  return outbox.enqueue({ alert: incident, plane: "resend", queuedAt: QUEUED_AT });
}

describe("AlertOutbox", () => {
  it("requires the authenticated open path at runtime", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rsi-alerts-construction-test-"));
    TEMPORARY_DIRECTORIES.push(directory);
    const RuntimeAlertOutbox = AlertOutbox as unknown as new (
      options: {
        databasePath: string;
        profile: "canary";
        stateKey: Uint8Array;
      },
      databaseExisted: boolean,
      constructionToken: object,
    ) => AlertOutbox;
    expect(
      () =>
        new RuntimeAlertOutbox(
          {
            databasePath: join(directory, "direct.sqlite"),
            profile: "canary",
            stateKey: Uint8Array.from(randomBytes(32)),
          },
          false,
          Object.freeze({}),
        ),
    ).toThrow(AlertIntegrityError);

    const forged = Object.create(AlertOutbox.prototype) as AlertOutbox;
    expect(isAlertOutbox(forged)).toBe(false);
    expect(() => forged.verifyIntegrity()).toThrow(AlertIntegrityError);
    expect(() => forged.close()).toThrow(AlertIntegrityError);

    const opened = AlertOutbox.open({
      databasePath: join(directory, "opened.sqlite"),
      profile: "canary",
      stateKey: STATE_KEY,
    });
    expect(isAlertOutbox(opened)).toBe(true);
    opened.close();
  });

  it("covers the stable v1 stop and runbook categories without free-form codes", () => {
    expect([...IncidentCodeSchema.options].sort()).toEqual(
      [
        "ALERT_DELIVERY_FAILURE",
        "ALERT_PATH_CANARY",
        "ANCHOR_FAILURE",
        "BACKUP_FAILURE",
        "CLOCK_FAILURE",
        "CONFIGURATION_DRIFT",
        "COST_ANOMALY",
        "CREDENTIAL_COMPROMISE",
        "CROSS_PROFILE_CONTAMINATION",
        "CURSOR_FAILURE",
        "DATA_LEAK",
        "FINANCIAL_ADAPTER_REACHABLE",
        "HOST_SECURITY_FAILURE",
        "INCIDENT_LATCH_BYPASS",
        "INTEGRITY_MISMATCH",
        "NETWORK_BOUNDARY_ESCAPE",
        "POLICY_BOUNDARY_ESCAPE",
        "PREFLIGHT_FAILURE",
        "PROVIDER_OUTAGE",
        "PROVIDER_SCHEMA_DRIFT",
        "PUBLICATION_FAILURE",
        "PURGE_FAILURE",
        "RELEASE_FAILURE",
        "RESOURCE_BOUND_EXCEEDED",
        "RUNTIME_CRASH",
        "SECOND_WRITER",
        "SESSION_SUPERVISION_FAILURE",
        "SIGNING_KEY_COMPROMISE",
        "TERMS_OR_PRICE_DRIFT",
      ].sort(),
    );
    expect(IncidentCodeSchema.safeParse("provider said something arbitrary").success).toBe(false);
  });

  it("stores only the closed content-free alert contract and rejects hostile fields", async () => {
    const { directory, outbox } = await target();
    const hostile = "sk_live_NEVER_PERSIST_0xdeadbeef_query_payload";
    const forbiddenKeys = [
      "message",
      "content",
      "sourceId",
      "address",
      "url",
      "stack",
      "query",
      "secret",
      "recipient",
      "error",
    ];

    for (const key of forbiddenKeys) {
      const candidate = { ...alert(), [key]: hostile };
      let thrown: unknown;
      try {
        outbox.enqueue({ alert: candidate, plane: "resend", queuedAt: QUEUED_AT });
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(AlertValidationError);
      expect(String((thrown as Error).message)).not.toContain(hostile);
    }
    expect(outbox.list()).toEqual([]);

    expect(() =>
      outbox.enqueue({
        alert: alert(),
        plane: "resend",
        queuedAt: QUEUED_AT,
        message: hostile,
      } as never),
    ).toThrow(AlertValidationError);
    expect(outbox.list()).toEqual([]);
    outbox.close();
    expect(await allDatabaseBytes(directory)).not.toContain(hostile);
  });

  it("requires canonical lowercase UUIDv4 identities and rejects aliases", async () => {
    const { outbox } = await target();
    for (const invalidId of [
      "00000000-0000-0000-0000-000000000000",
      "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "9F703C65-5602-42DB-B93D-73A84208869A",
      "9f703c65-5602-42db-b93d-73a84208869a\n",
    ]) {
      expect(() => enqueue(outbox, alert(invalidId))).toThrow(AlertValidationError);
      expect(() => enqueue(outbox, alert(undefined, "canary", invalidId))).toThrow(
        AlertValidationError,
      );
    }

    const first = enqueue(outbox);
    expect(() =>
      enqueue(
        outbox,
        alert(
          "9F703C65-5602-42DB-B93D-73A84208869A",
          "canary",
          "C520AE5A-51CD-46B9-AD49-89679E169B70",
        ),
      ),
    ).toThrow(AlertValidationError);
    expect(outbox.list()).toEqual([first]);
    outbox.close();
  });

  it("derives deterministic identities and distinguishes exact replay from conflict", async () => {
    const { databasePath, outbox } = await target();
    const first = enqueue(outbox);
    const exact = enqueue(outbox);
    expect(exact).toEqual(first);
    expect(first.state).toBe("pending");

    expect(() =>
      outbox.enqueue({
        alert: { ...alert(), incidentCode: "CLOCK_FAILURE" },
        plane: "resend",
        queuedAt: QUEUED_AT,
      }),
    ).toThrowError(
      expect.objectContaining<Partial<AlertConflictError>>({ code: "ALERT_CONFLICT" }),
    );
    expect(() =>
      outbox.enqueue({
        alert: alert(),
        plane: "resend",
        queuedAt: "2026-08-14T12:00:03.000Z",
      }),
    ).toThrow(AlertConflictError);

    const otherPlane = outbox.enqueue({
      alert: alert(),
      plane: "healthchecks",
      queuedAt: QUEUED_AT,
    });
    expect(otherPlane.deliveryId).not.toBe(first.deliveryId);
    const otherSession = outbox.enqueue({
      alert: alert(undefined, "canary", "e7d34296-7498-4fef-9eb8-f40d411b861c"),
      plane: "resend",
      queuedAt: QUEUED_AT,
    });
    expect(otherSession.deliveryId).not.toBe(first.deliveryId);
    const trustedHead = outbox.getTrustedHead();
    outbox.close();

    const reopened = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead,
    });
    expect(enqueue(reopened).deliveryId).toBe(first.deliveryId);
    expect(reopened.list()).toHaveLength(3);
    reopened.close();
  });

  it("requires and advances a content-free independently retained audit-prefix head", async () => {
    const { databasePath, outbox } = await target();
    const genesisHead: AlertTrustedHeadV1 = outbox.getTrustedHead();
    expect(genesisHead.auditSequence).toBe(0);
    expect(genesisHead.auditMac).toBe("0".repeat(64));
    expect(Object.keys(genesisHead).sort()).toEqual([
      "auditMac",
      "auditSequence",
      "headMac",
      "profile",
      "schemaMac",
      "schemaVersion",
    ]);
    expect(JSON.stringify(genesisHead)).not.toContain(SESSION_ID);
    outbox.close();

    expect(() =>
      AlertOutbox.open({ databasePath, profile: "canary", stateKey: STATE_KEY }),
    ).toThrow(AlertValidationError);

    const reopened = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: genesisHead,
    });
    enqueue(reopened);
    const advancedHead = reopened.getTrustedHead();
    expect(advancedHead.auditSequence).toBeGreaterThan(genesisHead.auditSequence);
    expect(advancedHead.auditMac).not.toBe(genesisHead.auditMac);
    expect(advancedHead.headMac).not.toBe(genesisHead.headMac);
    reopened.close();

    const fromOlderPrefix = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: genesisHead,
    });
    expect(fromOlderPrefix.list()).toHaveLength(1);
    fromOlderPrefix.close();

    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "canary",
        stateKey: STATE_KEY,
        trustedHead: { ...advancedHead, auditMac: genesisHead.auditMac },
      }),
    ).toThrow(AlertIntegrityError);

    const fromCurrentPrefix = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: advancedHead,
    });
    expect(fromCurrentPrefix.list()).toHaveLength(1);
    fromCurrentPrefix.close();
  });

  it("enforces a hard one-retry ceiling with exact terminal-operation replay", async () => {
    const { outbox } = await target();
    const queued = enqueue(outbox);
    const firstClaim = outbox.claim({ claimedAt: CLAIMED_AT, plane: "resend" });
    expect(firstClaim).toMatchObject({ attempt: 1, deliveryId: queued.deliveryId });

    const firstFailure = outbox.fail({
      attempt: 1,
      deliveryId: queued.deliveryId,
      failedAt: "2026-08-14T12:00:03.000Z",
      retryable: true,
    });
    expect(firstFailure).toMatchObject({ attempts: 1, state: "pending" });
    expect(
      outbox.fail({
        attempt: 1,
        deliveryId: queued.deliveryId,
        failedAt: "2026-08-14T12:00:03.000Z",
        retryable: true,
      }),
    ).toEqual(firstFailure);
    expect(() =>
      outbox.fail({
        attempt: 1,
        deliveryId: queued.deliveryId,
        failedAt: "2026-08-14T12:00:04.000Z",
        retryable: true,
      }),
    ).toThrow(AlertConflictError);

    const secondClaim = outbox.claim({
      claimedAt: "2026-08-14T12:00:04.000Z",
      plane: "resend",
    });
    expect(secondClaim?.attempt).toBe(2);
    expect(
      outbox.fail({
        attempt: 2,
        deliveryId: queued.deliveryId,
        failedAt: "2026-08-14T12:00:05.000Z",
        retryable: true,
      }),
    ).toMatchObject({ attempts: 2, state: "exhausted" });
    expect(outbox.claim({ claimedAt: "2026-08-14T12:00:06.000Z", plane: "resend" })).toBe(
      undefined,
    );
    expect(outbox.list()[0]).toMatchObject({ attempts: 2, state: "exhausted" });
    expect(outbox.verifyIntegrity()).toMatchObject({ attempts: 2, deliveries: 1, valid: true });
    outbox.close();
  });

  it("projects aggregate-only alert health for one supervised session", async () => {
    const { outbox } = await target();
    const incident = alert();
    outbox.enqueue({ alert: incident, plane: "resend", queuedAt: QUEUED_AT });
    outbox.enqueue({ alert: incident, plane: "healthchecks", queuedAt: QUEUED_AT });
    outbox.enqueue({
      alert: alert(randomUUID(), "canary", randomUUID()),
      plane: "resend",
      queuedAt: QUEUED_AT,
    });

    const summary = outbox.getSessionSummary(SESSION_ID);
    expect(summary).toEqual({
      deliveryCount: 2,
      incidentCount: 1,
      profile: "canary",
      schemaVersion: 1,
      sessionId: SESSION_ID,
      states: { delivered: 0, exhausted: 0, in_flight: 0, pending: 2 },
    });
    expect(JSON.stringify(summary)).not.toContain(incident.incidentId);
    expect(Object.isFrozen(summary)).toBe(true);
    expect(Object.isFrozen(summary.states)).toBe(true);
    outbox.close();
  });

  it("encrypts provider IDs and returns only sanitized receipts and projections", async () => {
    const { databasePath, directory, outbox } = await target();
    const incidentId = "56e18ee8-fcd0-42e6-8b5c-9c38e23f6fb9";
    const providerMessageId = "msg_01HZZ3SAFEID";
    const queued = enqueue(outbox, alert(incidentId));
    const claim = outbox.claim({ claimedAt: CLAIMED_AT, plane: "resend" });
    expect(claim?.alert).toEqual(alert(incidentId));
    expect(Object.keys(claim?.alert ?? {}).sort()).toEqual([
      "incidentCode",
      "incidentId",
      "instruction",
      "occurredAt",
      "profile",
      "schemaVersion",
      "sessionId",
      "severity",
      "templateRevision",
    ]);

    const completed = outbox.complete({
      attempt: 1,
      completedAt: "2026-08-14T12:00:03.000Z",
      deliveryId: queued.deliveryId,
      providerMessageId,
    });
    expect(Object.keys(completed).sort()).toEqual([
      "attempts",
      "deliveryId",
      "plane",
      "profile",
      "queuedAt",
      "state",
      "updatedAt",
    ]);
    expect(JSON.stringify(completed)).not.toContain(providerMessageId);
    expect(
      outbox.complete({
        attempt: 1,
        completedAt: "2026-08-14T12:00:03.000Z",
        deliveryId: queued.deliveryId,
        providerMessageId,
      }),
    ).toEqual(completed);
    expect(() =>
      outbox.complete({
        attempt: 1,
        completedAt: "2026-08-14T12:00:03.000Z",
        deliveryId: queued.deliveryId,
        providerMessageId: "msg_CONFLICT",
      }),
    ).toThrow(AlertConflictError);
    const trustedHead = outbox.getTrustedHead();
    outbox.close();

    const bytes = await allDatabaseBytes(directory);
    expect(bytes).not.toContain(incidentId);
    expect(bytes).not.toContain(SESSION_ID);
    expect(bytes).not.toContain("INTEGRITY_MISMATCH");
    expect(bytes).not.toContain(providerMessageId);
    expect(bytes).not.toContain("OPEN_LOCAL_RSI_CONSOLE");

    const reopened = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead,
    });
    expect(reopened.list()[0]).toMatchObject({ state: "delivered" });
    expect(reopened.verifyIntegrity().valid).toBe(true);
    reopened.close();
  });

  it("recovers crashed attempts after reopen without exceeding one retry", async () => {
    const { databasePath, outbox } = await target();
    const queued = enqueue(outbox);
    expect(outbox.claim({ claimedAt: CLAIMED_AT, plane: "resend" })?.attempt).toBe(1);
    const firstTrustedHead = outbox.getTrustedHead();
    outbox.close();

    const firstReopen = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: firstTrustedHead,
    });
    expect(firstReopen.claim({ claimedAt: "2026-08-14T12:00:03.000Z", plane: "resend" })).toBe(
      undefined,
    );
    expect(firstReopen.recover({ recoveredAt: "2026-08-14T12:00:03.000Z" })).toEqual({
      exhausted: 0,
      recoveredAt: "2026-08-14T12:00:03.000Z",
      retryReady: 1,
    });
    expect(
      firstReopen.claim({ claimedAt: "2026-08-14T12:00:04.000Z", plane: "resend" }),
    ).toMatchObject({ attempt: 2, deliveryId: queued.deliveryId });
    const secondTrustedHead = firstReopen.getTrustedHead();
    firstReopen.close();

    const secondReopen = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: secondTrustedHead,
    });
    expect(secondReopen.recover({ recoveredAt: "2026-08-14T12:00:05.000Z" })).toEqual({
      exhausted: 1,
      recoveredAt: "2026-08-14T12:00:05.000Z",
      retryReady: 0,
    });
    expect(secondReopen.list()[0]).toMatchObject({ attempts: 2, state: "exhausted" });
    expect(secondReopen.claim({ claimedAt: "2026-08-14T12:00:06.000Z", plane: "resend" })).toBe(
      undefined,
    );
    secondReopen.close();
  });

  it("accepts a valid post-pin commit for crash recovery but rejects rollback before the pin", async () => {
    const { databasePath, directory, outbox } = await target();
    const genesisHead = outbox.getTrustedHead();
    outbox.close();
    const genesisSnapshotPath = join(directory, "genesis-before-retained-prefix.sqlite");
    await copyFile(databasePath, genesisSnapshotPath);

    const queuedOutbox = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: genesisHead,
    });
    const queued = enqueue(queuedOutbox);
    const retainedHead = queuedOutbox.getTrustedHead();
    queuedOutbox.close();

    const processThatCrashes = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: retainedHead,
    });
    expect(processThatCrashes.claim({ claimedAt: CLAIMED_AT, plane: "resend" })).toMatchObject({
      attempt: 1,
      deliveryId: queued.deliveryId,
    });
    processThatCrashes.close(); // Simulates a crash before a newer head was retained.

    const recovered = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: retainedHead,
    });
    expect(recovered.claim({ claimedAt: "2026-08-14T12:00:03.000Z", plane: "resend" })).toBe(
      undefined,
    );
    expect(recovered.recover({ recoveredAt: "2026-08-14T12:00:03.000Z" })).toEqual({
      exhausted: 0,
      recoveredAt: "2026-08-14T12:00:03.000Z",
      retryReady: 1,
    });
    expect(recovered.list()[0]).toMatchObject({ attempts: 1, state: "pending" });
    recovered.close();

    await copyFile(genesisSnapshotPath, databasePath);
    await rm(`${databasePath}-wal`, { force: true });
    await rm(`${databasePath}-shm`, { force: true });
    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "canary",
        stateKey: STATE_KEY,
        trustedHead: retainedHead,
      }),
    ).toThrow(AlertIntegrityError);
  });

  it("binds even an empty initialized database to its key and profile", async () => {
    const { databasePath, outbox } = await target();
    const trustedHead = outbox.getTrustedHead();
    outbox.close();
    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "canary",
        stateKey: OTHER_KEY,
        trustedHead,
      }),
    ).toThrow(AlertIntegrityError);
    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "production-observer",
        stateKey: STATE_KEY,
        trustedHead,
      }),
    ).toThrow(AlertIntegrityError);
  });

  it("does not reinitialize an existing database whose keyed metadata was deleted", async () => {
    const { databasePath, outbox } = await target();
    const trustedHead = outbox.getTrustedHead();
    outbox.close();
    const database = new DatabaseSync(databasePath);
    database.exec(`DELETE FROM rsi_alert_metadata`);
    database.close();

    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "canary",
        stateKey: STATE_KEY,
        trustedHead,
      }),
    ).toThrow(AlertIntegrityError);
    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "production-observer",
        stateKey: OTHER_KEY,
        trustedHead: { ...trustedHead, profile: "production-observer" },
      }),
    ).toThrow(AlertIntegrityError);
  });

  it("rejects cross-profile alerts and keeps canary and production identities distinct", async () => {
    const canary = await target("canary");
    const production = await target("production-observer");
    expect(() => enqueue(canary.outbox, alert(randomUUID(), "production-observer"))).toThrow(
      AlertValidationError,
    );

    const incidentId = randomUUID();
    const canaryReceipt = enqueue(canary.outbox, alert(incidentId, "canary"));
    const productionReceipt = enqueue(production.outbox, alert(incidentId, "production-observer"));
    expect(canaryReceipt.deliveryId).not.toBe(productionReceipt.deliveryId);
    canary.outbox.close();
    production.outbox.close();
  });

  it("rejects a malicious trigger before it can fake a successful enqueue", async () => {
    const { databasePath, outbox } = await target();
    const database = new DatabaseSync(databasePath);
    database.exec(`
      CREATE TRIGGER evil_drop_delivery
      BEFORE INSERT ON rsi_alert_deliveries
      BEGIN
        SELECT RAISE(IGNORE);
      END
    `);
    database.close();

    expect(() => enqueue(outbox)).toThrow(AlertIntegrityError);
    expect(outbox.verifyIntegrity().valid).toBe(false);
    outbox.close();

    const inspection = new DatabaseSync(databasePath);
    const deliveryCount = inspection
      .prepare(`SELECT count(*) AS count FROM rsi_alert_deliveries`)
      .get() as { count: number };
    const auditCount = inspection
      .prepare(`SELECT count(*) AS count FROM rsi_alert_audit`)
      .get() as { count: number };
    inspection.close();
    expect(deliveryCount.count).toBe(0);
    expect(auditCount.count).toBe(0);
  });

  it("rejects same-shape view substitution and every extra or altered schema object", async () => {
    const mutations = [
      `CREATE TABLE rsi_alert_unexpected (value TEXT) STRICT`,
      `CREATE VIEW rsi_alert_unexpected AS SELECT delivery_id FROM rsi_alert_deliveries`,
      `ALTER TABLE rsi_alert_metadata ADD COLUMN unexpected TEXT`,
      `CREATE INDEX rsi_alert_unexpected ON rsi_alert_deliveries(updated_at)`,
      `CREATE TABLE rsi_alert_delivery_shadow AS SELECT * FROM rsi_alert_deliveries;
       DROP TABLE rsi_alert_deliveries;
       CREATE VIEW rsi_alert_deliveries AS SELECT * FROM rsi_alert_delivery_shadow`,
    ];

    for (const mutation of mutations) {
      const { databasePath, outbox } = await target();
      const trustedHead = outbox.getTrustedHead();
      outbox.close();
      const database = new DatabaseSync(databasePath);
      database.exec(mutation);
      database.close();
      expect(() =>
        AlertOutbox.open({
          databasePath,
          profile: "canary",
          stateKey: STATE_KEY,
          trustedHead,
        }),
      ).toThrow(AlertIntegrityError);
    }
  });

  it("detects audit-tail rollback even when its visible head is rewound consistently", async () => {
    const { databasePath, outbox } = await target();
    enqueue(outbox);
    const trustedHead = outbox.getTrustedHead();
    outbox.close();

    const database = new DatabaseSync(databasePath);
    database.exec(`
      DELETE FROM rsi_alert_deliveries;
      DELETE FROM rsi_alert_audit;
      UPDATE rsi_alert_metadata
         SET audit_head_sequence = 0,
             audit_head_mac = lower(hex(zeroblob(32)))
       WHERE singleton = 1
    `);
    database.close();

    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "canary",
        stateKey: STATE_KEY,
        trustedHead,
      }),
    ).toThrow(AlertIntegrityError);
  });

  it("uses the independently retained head to detect a whole-file rollback", async () => {
    const { databasePath, directory, outbox } = await target();
    const genesisHead = outbox.getTrustedHead();
    outbox.close();
    const snapshotPath = join(directory, "genesis.sqlite");
    await copyFile(databasePath, snapshotPath);

    const advanced = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead: genesisHead,
    });
    enqueue(advanced);
    const advancedHead = advanced.getTrustedHead();
    advanced.close();

    await copyFile(snapshotPath, databasePath);
    await rm(`${databasePath}-wal`, { force: true });
    await rm(`${databasePath}-shm`, { force: true });
    expect(() =>
      AlertOutbox.open({
        databasePath,
        profile: "canary",
        stateKey: STATE_KEY,
        trustedHead: advancedHead,
      }),
    ).toThrow(AlertIntegrityError);
    expect(() =>
      AlertOutbox.open({ databasePath, profile: "canary", stateKey: STATE_KEY }),
    ).toThrow(AlertValidationError);
  });

  it("detects row, ciphertext, and audit tampering on reopen", async () => {
    for (const mutation of [
      `UPDATE rsi_alert_deliveries SET state = 'delivered'`,
      `UPDATE rsi_alert_deliveries SET payload_ciphertext = randomblob(length(payload_ciphertext))`,
      `UPDATE rsi_alert_audit SET occurred_at = '2026-08-14T12:00:09.000Z'`,
      `DELETE FROM rsi_alert_audit WHERE sequence = (SELECT max(sequence) FROM rsi_alert_audit)`,
    ]) {
      const { databasePath, outbox } = await target();
      enqueue(outbox);
      const trustedHead = outbox.getTrustedHead();
      outbox.close();
      const database = new DatabaseSync(databasePath);
      database.exec(mutation);
      database.close();
      expect(() =>
        AlertOutbox.open({
          databasePath,
          profile: "canary",
          stateKey: STATE_KEY,
          trustedHead,
        }),
      ).toThrow(AlertIntegrityError);
    }
  });

  it("rejects arbitrary provider/error detail and backward timestamps without persistence", async () => {
    const { outbox } = await target();
    expect(() =>
      outbox.enqueue({
        alert: { ...alert(), occurredAt: "2026-08-14T12:00:02.000Z" },
        plane: "resend",
        queuedAt: QUEUED_AT,
      }),
    ).toThrow(AlertValidationError);
    expect(outbox.list()).toEqual([]);
    const queued = enqueue(outbox);
    outbox.claim({ claimedAt: CLAIMED_AT, plane: "resend" });
    expect(() =>
      outbox.complete({
        attempt: 1,
        completedAt: "2026-08-14T12:00:03.000Z",
        deliveryId: queued.deliveryId,
        providerMessageId: "https://provider.invalid/messages/raw-secret",
      }),
    ).toThrow(AlertValidationError);
    expect(() =>
      outbox.fail({
        attempt: 1,
        deliveryId: queued.deliveryId,
        failedAt: "2026-08-14T12:00:03.000Z",
        retryable: false,
        reason: "raw provider stack and query",
      } as never),
    ).toThrow(AlertValidationError);
    expect(() =>
      outbox.fail({
        attempt: 1,
        deliveryId: queued.deliveryId,
        failedAt: "2026-08-14T12:00:00.000Z",
        retryable: true,
      }),
    ).toThrow(AlertValidationError);
    expect(outbox.list()[0]).toMatchObject({ attempts: 1, state: "in_flight" });
    expect(outbox.verifyIntegrity().valid).toBe(true);
    outbox.close();
  });

  it("rejects regression across the queue, retry, recovery, and global audit timeline", async () => {
    const { databasePath, outbox } = await target();
    const queued = enqueue(outbox);
    outbox.claim({ claimedAt: CLAIMED_AT, plane: "resend" });
    outbox.fail({
      attempt: 1,
      deliveryId: queued.deliveryId,
      failedAt: "2026-08-14T12:00:03.000Z",
      retryable: true,
    });
    expect(() => outbox.claim({ claimedAt: "2026-08-14T12:00:02.999Z", plane: "resend" })).toThrow(
      AlertValidationError,
    );
    outbox.claim({ claimedAt: "2026-08-14T12:00:04.000Z", plane: "resend" });
    expect(() => outbox.recover({ recoveredAt: "2026-08-14T12:00:03.999Z" })).toThrow(
      AlertValidationError,
    );
    expect(() =>
      outbox.complete({
        attempt: 2,
        completedAt: "2026-08-14T12:00:03.999Z",
        deliveryId: queued.deliveryId,
      }),
    ).toThrow(AlertValidationError);
    outbox.complete({
      attempt: 2,
      completedAt: "2026-08-14T12:00:05.000Z",
      deliveryId: queued.deliveryId,
    });

    expect(() =>
      outbox.enqueue({
        alert: {
          ...alert(randomUUID(), "canary", randomUUID()),
          occurredAt: "2026-08-14T12:00:00.000Z",
        },
        plane: "resend",
        queuedAt: "2026-08-14T12:00:00.500Z",
      }),
    ).toThrow(AlertValidationError);
    expect(outbox.list()).toHaveLength(1);
    expect(outbox.verifyIntegrity().valid).toBe(true);
    const trustedHead = outbox.getTrustedHead();
    outbox.close();

    const reopened = AlertOutbox.open({
      databasePath,
      profile: "canary",
      stateKey: STATE_KEY,
      trustedHead,
    });
    expect(reopened.verifyIntegrity().valid).toBe(true);
    expect(reopened.list()[0]).toMatchObject({ attempts: 2, state: "delivered" });
    reopened.close();
  });

  it("rejects malformed root inputs and use after close", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rsi-alerts-test-"));
    TEMPORARY_DIRECTORIES.push(directory);
    expect(() =>
      AlertOutbox.open({
        databasePath: join(directory, "short-key.sqlite"),
        profile: "canary",
        stateKey: randomBytes(31),
      }),
    ).toThrow(AlertValidationError);
    expect(() =>
      AlertOutbox.open({
        databasePath: join(directory, "extra.sqlite"),
        profile: "canary",
        stateKey: STATE_KEY,
        credential: "forbidden",
      } as never),
    ).toThrow(AlertValidationError);

    for (const [label, stateKey] of [
      ["buffer", Buffer.alloc(32, 0x43)],
      ["shared", new Uint8Array(new SharedArrayBuffer(32))],
    ] as const) {
      expect(() =>
        AlertOutbox.open({
          databasePath: join(directory, `unsafe-key-${label}.sqlite`),
          profile: "canary",
          stateKey,
        }),
      ).toThrow(AlertValidationError);
    }

    let accessorReads = 0;
    const accessorOptions = {
      databasePath: join(directory, "accessor.sqlite"),
      stateKey: STATE_KEY,
    } as Record<string, unknown>;
    Object.defineProperty(accessorOptions, "profile", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return "canary";
      },
    });
    expect(() => AlertOutbox.open(accessorOptions as never)).toThrow(AlertValidationError);
    expect(accessorReads).toBe(0);

    let proxyReads = 0;
    const proxyOptions = new Proxy(
      {
        databasePath: join(directory, "proxy.sqlite"),
        profile: "canary" as const,
        stateKey: STATE_KEY,
      },
      {
        get(target, property, receiver) {
          proxyReads += 1;
          return Reflect.get(target, property, receiver);
        },
      },
    );
    expect(() => AlertOutbox.open(proxyOptions)).toThrow(AlertValidationError);
    expect(proxyReads).toBe(0);

    const { outbox } = await target();
    outbox.close();
    expect(() => outbox.list()).toThrowError(expect.objectContaining({ code: "CLOSED" }));
  });
});

async function allDatabaseBytes(directory: string): Promise<string> {
  const names = await readdir(directory);
  const buffers = await Promise.all(
    names
      .filter((name) => name.startsWith("alerts.sqlite"))
      .map((name) => readFile(join(directory, name))),
  );
  return Buffer.concat(buffers).toString("latin1");
}
