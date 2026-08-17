import { mkdtempSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteSessionCoordinator } from "@rsi/session-lifecycle";
import { afterEach, describe, expect, it } from "vitest";

import {
  createSessionLifecycleOperatorControls,
  isSessionLifecycleOperatorControls,
} from "../src/index.js";

const SESSION_ID = "018f102a-8f54-4a93-8cce-2461c4f28a12";

describe("session lifecycle operator controls", () => {
  const directories: string[] = [];

  afterEach(async () => {
    await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
  });

  function openCoordinator() {
    const directory = mkdtempSync(join(tmpdir(), "rsi-operator-controls-"));
    directories.push(directory);
    return SqliteSessionCoordinator.open({
      expectedProfile: "canary",
      path: join(directory, "sessions.sqlite"),
      recoveredAt: "2026-08-15T06:00:00.000Z",
      stateKey: new Uint8Array(32).fill(7),
    }).coordinator;
  }

  it("drives the bounded lifecycle with a provider-owned clock and stable retries", () => {
    const coordinator = openCoordinator();
    let now = "2026-08-15T06:10:00.000Z";
    const controls = createSessionLifecycleOperatorControls({ coordinator, now: () => now });

    expect(isSessionLifecycleOperatorControls(controls)).toBe(true);
    expect(controls.supportedActions).toEqual(["plan", "start", "acknowledge", "abort", "close"]);

    const planned = controls.executeControl({ action: "plan", sessionId: SESSION_ID });
    expect(planned).toMatchObject({
      qualificationDate: "2026-08-14",
      sessionId: SESSION_ID,
      state: "planned",
      supervisedUntil: "2026-08-15T08:10:00.000Z",
    });
    now = "2026-08-15T06:11:00.000Z";
    expect(controls.executeControl({ action: "plan", sessionId: SESSION_ID })).toEqual(planned);

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
        evidenceHash: "11".repeat(32),
        observedAt: "2026-08-15T06:10:30.000Z",
        profile: "canary",
        ready: true,
        schemaVersion: 1,
      },
      recordedAt: "2026-08-15T06:10:30.000Z",
      sessionId: SESSION_ID,
    });

    const started = controls.executeControl({
      action: "start",
      observerOnlyAcknowledgement: true,
      sessionId: SESSION_ID,
      typedSessionIdAcknowledgement: SESSION_ID,
    });
    expect(started).toMatchObject({ startedAt: now, state: "running" });

    now = "2026-08-15T06:56:00.000Z";
    const minute45 = controls.executeControl({
      action: "acknowledge",
      checkpoint: "minute-45",
      sessionId: SESSION_ID,
    });
    expect(minute45).toMatchObject({ minute45AcknowledgedAt: now, state: "running" });
    now = "2026-08-15T07:41:00.000Z";
    const minute90 = controls.executeControl({
      action: "acknowledge",
      checkpoint: "minute-90",
      sessionId: SESSION_ID,
    });
    expect(minute90).toMatchObject({ minute90AcknowledgedAt: now, state: "running" });

    now = "2026-08-15T07:42:00.000Z";
    const stopped = controls.executeControl({ action: "close", sessionId: SESSION_ID });
    expect(stopped).toMatchObject({ egressStatus: "blocked", state: "stopping", stoppedAt: now });
    now = "2026-08-15T07:43:00.000Z";
    expect(controls.executeControl({ action: "close", sessionId: SESSION_ID })).toEqual(stopped);

    coordinator.close();
  });

  it("stops a planned session immediately and rejects unsupported control families", () => {
    const coordinator = openCoordinator();
    let now = "2026-08-15T12:00:00.000Z";
    const controls = createSessionLifecycleOperatorControls({ coordinator, now: () => now });
    controls.executeControl({ action: "plan", sessionId: SESSION_ID });
    now = "2026-08-15T12:00:01.000Z";

    const stopped = controls.executeControl({ action: "abort", sessionId: SESSION_ID });
    expect(stopped).toMatchObject({
      egressStatus: "blocked",
      invalidationReason: "operator-abort",
      state: "invalid",
    });
    expect(controls.executeControl({ action: "abort", sessionId: SESSION_ID })).toEqual(stopped);
    expect(() =>
      controls.executeControl({ action: "prepare-candidate", findingId: "finding-1" }),
    ).toThrow(/not configured/);

    coordinator.close();
  });

  it("rejects copied or structurally fabricated control providers", () => {
    const coordinator = openCoordinator();
    const controls = createSessionLifecycleOperatorControls({ coordinator });

    expect(isSessionLifecycleOperatorControls({ ...controls })).toBe(false);
    expect(isSessionLifecycleOperatorControls(Object.create(controls))).toBe(false);
    expect(() =>
      createSessionLifecycleOperatorControls({
        coordinator: Object.create(SqliteSessionCoordinator.prototype) as SqliteSessionCoordinator,
      }),
    ).toThrow(/genuine/);

    coordinator.close();
  });
});
