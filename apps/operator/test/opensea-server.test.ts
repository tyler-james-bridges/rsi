import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createConnection } from "node:net";

import {
  OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  OpenSeaReadCanaryConflictError,
  getOpenSeaReadCanaryPlan,
  type OpenSeaReadCanaryProjectionV1,
  type OpenSeaReadCanaryReceiptV1,
} from "@rsi/read-canary/opensea";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  startOpenSeaOperatorServer,
  type OpenSeaOperatorSnapshotProvider,
  type OperatorOpenSeaReadCanaryProvider,
  type OperatorRuntimeProvider,
  type RunningOpenSeaOperatorServer,
  type RuntimeOperatorControlCommand,
} from "../src/opensea.js";

const API_KEY_FIXTURE = "offline-api-key-fixture-never-return";
const HOSTILE_SLUG = "hostile-collection-slug";
const HOSTILE_ADDRESS = `0x${"a".repeat(40)}`;
const HOSTILE_RAW = "UNTRUSTED RAW OPENSEA CONTENT";

function snapshot(mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED", revision: number) {
  return {
    schemaVersion: 1 as const,
    mode,
    revision,
    modeChangedAt: "2026-08-26T12:00:00.000Z",
    processInstanceId: "11111111-1111-4111-8111-111111111111",
    auditHead: { sequence: revision, hash: "a".repeat(64) },
    capabilities: {
      researchCollection: mode !== "STOPPED",
      proposalPersistence: mode === "PROPOSE_ONLY",
      policyApproval: false as const,
      paidRead: false as const,
      transactionBroadcast: false as const,
      walletSign: false as const,
      executionAdapter: false as const,
      externalPublish: false as const,
    },
  };
}

function fullReceipt(): OpenSeaReadCanaryReceiptV1 {
  const plan = getOpenSeaReadCanaryPlan();
  const requestId = "22222222-2222-4222-8222-222222222222";
  return {
    schemaVersion: 1,
    receiptId: `opensea-read-canary:${requestId}`,
    planId: plan.planId,
    providerId: plan.providerId,
    requestId,
    requestFingerprint: plan.requestFingerprint,
    outcome: "accepted",
    failureCode: null,
    acquiredAt: "2026-08-26T12:00:01.000Z",
    completedAt: "2026-08-26T12:00:02.000Z",
    collectionCount: 2,
    byteLength: 1_024,
    hasNextPage: false,
    rateLimit: { limit: 100, remaining: 99, resetAtUnixSeconds: 1_788_000_000 },
    maximumRequests: 1,
    maximumResults: 10,
    ledgerReserveUsdMicros: OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    runtime: {
      authorizationId: "33333333-3333-4333-8333-333333333333",
      eventHash: "b".repeat(64),
      eventSequence: 4,
      modeRevision: 2,
    },
    capture: { eventHash: "c".repeat(64), eventSequence: 5 },
  };
}

function projection(
  status: OpenSeaReadCanaryProjectionV1["status"] = "ready",
): OpenSeaReadCanaryProjectionV1 {
  return {
    schemaVersion: 1,
    status,
    credentialStatus: "configured",
    plan: getOpenSeaReadCanaryPlan(),
    lastReceipt: status === "completed" ? fullReceipt() : null,
  };
}

function headers(origin: string): Record<string, string> {
  return {
    "content-type": "application/json",
    origin,
    "sec-fetch-site": "same-origin",
    "x-rsi-operator-request": "1",
  };
}

describe("dedicated OpenSea operator", () => {
  let running: RunningOpenSeaOperatorServer | undefined;

  afterEach(async () => {
    await running?.close();
    running = undefined;
  });

  function fixture() {
    let current = snapshot("STOPPED", 1);
    const executeRuntimeControl = vi.fn((command: RuntimeOperatorControlCommand) => {
      if (command.action === "runtime-stop") {
        current = snapshot("STOPPED", current.revision + 1);
      } else if (command.action === "runtime-enter-research") {
        current = snapshot("RESEARCH", current.revision + 1);
      }
      return current;
    });
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
      executeRuntimeControl,
      getRuntimeSnapshot: vi.fn(() => current),
    };
    const executeOpenSeaReadCanary = vi.fn(async () => fullReceipt());
    const getOpenSeaReadCanaryProjection = vi.fn(() => projection());
    const refreshOpenSeaCredentialStatus = vi.fn(() => projection());
    const readCanary: OperatorOpenSeaReadCanaryProvider = {
      abortActive: vi.fn(),
      executeOpenSeaReadCanary,
      getOpenSeaReadCanaryProjection,
      refreshOpenSeaCredentialStatus,
    };
    const provider: OpenSeaOperatorSnapshotProvider = {
      listEvents: vi.fn(() => ({
        items: [
          {
            sequence: current.revision,
            type: "runtime.mode.changed.v1",
            occurredAt: "2026-08-26T12:00:00.000Z",
          },
        ],
        nextCursor: null,
      })),
    };
    return {
      executeOpenSeaReadCanary,
      executeRuntimeControl,
      getOpenSeaReadCanaryProjection,
      provider,
      readCanary,
      refreshOpenSeaCredentialStatus,
      runtime,
    };
  }

  it("keeps health and idle runtime reads credential-free and exposes only OpenSea controls", async () => {
    const state = fixture();
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const health = await fetch(`${running.origin}/health`);
    const runtime = await fetch(`${running.origin}/api/runtime`);
    const capabilities = await fetch(`${running.origin}/api/control/capabilities`);

    expect(await health.json()).toEqual({ status: "ok", runtime: "persisted" });
    const runtimeBody = (await runtime.json()) as { runtime: { mode: string } };
    expect(runtimeBody.runtime.mode).toBe("STOPPED");
    expect(runtimeBody).not.toHaveProperty("runtime.processInstanceId");
    expect(runtimeBody).not.toHaveProperty("runtime.auditHead");
    expect(await capabilities.json()).toEqual({
      controls: {
        runtime: {
          actions: ["runtime-enter-research", "runtime-stop"],
          enabled: true,
        },
      },
    });
    expect(state.getOpenSeaReadCanaryProjection).not.toHaveBeenCalled();
    expect(state.executeOpenSeaReadCanary).not.toHaveBeenCalled();
  });

  it("keeps cross-site GET passive and protects explicit credential refresh", async () => {
    const state = fixture();
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const passive = await fetch(`${running.origin}/api/opensea-read-canary`, {
      headers: { origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
    });
    expect(passive.status).toBe(200);
    expect(state.getOpenSeaReadCanaryProjection).toHaveBeenCalledOnce();
    expect(state.refreshOpenSeaCredentialStatus).not.toHaveBeenCalled();

    const rejected = await fetch(
      `${running.origin}/api/opensea-read-canary/refresh-credential-status`,
      { method: "POST" },
    );
    expect(rejected.status).toBe(403);
    expect(state.refreshOpenSeaCredentialStatus).not.toHaveBeenCalled();

    const refreshed = await fetch(
      `${running.origin}/api/opensea-read-canary/refresh-credential-status`,
      { headers: { origin: running.origin, "x-rsi-operator-request": "1" }, method: "POST" },
    );
    expect(refreshed.status).toBe(200);
    expect(state.refreshOpenSeaCredentialStatus).toHaveBeenCalledOnce();
  });

  it("requires RESEARCH and the exact fixed plan before one sanitized completion", async () => {
    const state = fixture();
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });
    const plan = getOpenSeaReadCanaryPlan();
    const command = {
      schemaVersion: 1,
      planId: plan.planId,
      expectedRuntimeRevision: 1,
      requestId: randomUUID(),
      typedPlanIdAcknowledgement: plan.planId,
      oneRequestAcknowledgement: true,
      nonPaymentReadAcknowledgement: true,
      ledgerReserveUsdMicrosAcknowledgement: plan.ledgerReserveUsdMicros,
    };

    const stoppedRun = await fetch(`${running.origin}/api/opensea-read-canary/run`, {
      body: JSON.stringify(command),
      headers: headers(running.origin),
      method: "POST",
    });
    expect(stoppedRun.status).toBe(409);
    expect(state.executeOpenSeaReadCanary).not.toHaveBeenCalled();

    const transition = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: randomUUID(),
      }),
      headers: headers(running.origin),
      method: "POST",
    });
    expect(transition.status).toBe(200);

    const wrongPlan = await fetch(`${running.origin}/api/opensea-read-canary/run`, {
      body: JSON.stringify({
        ...command,
        expectedRuntimeRevision: 2,
        typedPlanIdAcknowledgement: "some-other-plan",
      }),
      headers: headers(running.origin),
      method: "POST",
    });
    expect(wrongPlan.status).toBe(400);
    expect(state.executeOpenSeaReadCanary).not.toHaveBeenCalled();

    const run = await fetch(`${running.origin}/api/opensea-read-canary/run`, {
      body: JSON.stringify({ ...command, expectedRuntimeRevision: 2 }),
      headers: headers(running.origin),
      method: "POST",
    });
    const body = await run.json();

    expect(run.status).toBe(200);
    expect(body).toEqual({
      result: {
        schemaVersion: 1,
        planId: plan.planId,
        providerId: plan.providerId,
        outcome: "accepted",
        failureCode: null,
        acquiredAt: "2026-08-26T12:00:01.000Z",
        completedAt: "2026-08-26T12:00:02.000Z",
        collectionCount: 2,
        byteLength: 1_024,
        hasNextPage: false,
        rateLimit: { limit: 100, remaining: 99, resetAtUnixSeconds: 1_788_000_000 },
        maximumRequests: 1,
        maximumResults: 10,
        ledgerReserveUsdMicros: "1",
        actualChargeUsdMicros: null,
      },
    });
    const serialized = JSON.stringify(body);
    for (const forbidden of [
      "capture",
      "authorizationId",
      "eventHash",
      "requestId",
      "receiptId",
      HOSTILE_SLUG,
      HOSTILE_ADDRESS,
      HOSTILE_RAW,
      API_KEY_FIXTURE,
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(state.executeOpenSeaReadCanary).toHaveBeenCalledOnce();
  });

  it("rejects injected collection identity and returns only an opaque error", async () => {
    const state = fixture();
    state.readCanary.getOpenSeaReadCanaryProjection = vi.fn(
      () =>
        ({
          ...projection(),
          slug: HOSTILE_SLUG,
          contractAddress: HOSTILE_ADDRESS,
          raw: HOSTILE_RAW,
          apiKey: API_KEY_FIXTURE,
        }) as never,
    );
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const response = await fetch(`${running.origin}/api/opensea-read-canary`);
    const body = await response.json();
    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: { code: "internal_error", message: "The local operator request failed." },
    });
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain(HOSTILE_SLUG);
    expect(serialized).not.toContain(HOSTILE_ADDRESS);
    expect(serialized).not.toContain(HOSTILE_RAW);
    expect(serialized).not.toContain(API_KEY_FIXTURE);
  });

  it("keeps STOP same-origin, independently available, and ahead of durable transition", async () => {
    const state = fixture();
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const rejected = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({ action: "runtime-stop", requestId: randomUUID() }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    expect(rejected.status).toBe(403);
    expect(state.readCanary.abortActive).not.toHaveBeenCalled();

    const order: string[] = [];
    vi.mocked(state.readCanary.abortActive).mockImplementation(() => order.push("abort"));
    state.executeRuntimeControl.mockImplementation((command) => {
      order.push(command.action);
      return snapshot("STOPPED", 2);
    });
    const stopped = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({ action: "runtime-stop", requestId: randomUUID() }),
      headers: headers(running.origin),
      method: "POST",
    });

    expect(stopped.status).toBe(200);
    expect(order).toEqual(["abort", "runtime-stop"]);
  });

  it("bounds shutdown with a half-open control body and aborts before waiting", async () => {
    const state = fixture();
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });
    const socket = createConnection({ host: "127.0.0.1", port: running.port });
    socket.on("error", () => undefined);
    await once(socket, "connect");
    socket.write(
      [
        "POST /api/control HTTP/1.1",
        `Host: 127.0.0.1:${running.port}`,
        `Origin: ${running.origin}`,
        "Sec-Fetch-Site: same-origin",
        "X-RSI-Operator-Request: 1",
        "Content-Type: application/json",
        "Content-Length: 200",
        "",
        '{"action":"runtime-stop",',
      ].join("\r\n"),
    );
    await new Promise<void>((resolve) => setTimeout(resolve, 25));

    const started = performance.now();
    await running.close();
    const elapsed = performance.now() - started;
    running = undefined;

    expect(state.readCanary.abortActive).toHaveBeenCalled();
    expect(elapsed).toBeLessThan(1_000);
    socket.destroy();
  });

  it("maps authentic controller conflicts to an opaque 409", async () => {
    const state = fixture();
    state.executeRuntimeControl({
      action: "runtime-enter-research",
      expectedMode: "STOPPED",
      expectedRevision: 1,
      requestId: randomUUID(),
    });
    vi.mocked(state.executeOpenSeaReadCanary).mockRejectedValue(
      new OpenSeaReadCanaryConflictError("private internal state details"),
    );
    running = await startOpenSeaOperatorServer(state.provider, {
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });
    const plan = getOpenSeaReadCanaryPlan();
    const response = await fetch(`${running.origin}/api/opensea-read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: plan.planId,
        expectedRuntimeRevision: 2,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: plan.planId,
        oneRequestAcknowledgement: true,
        nonPaymentReadAcknowledgement: true,
        ledgerReserveUsdMicrosAcknowledgement: plan.ledgerReserveUsdMicros,
      }),
      headers: headers(running.origin),
      method: "POST",
    });
    expect(response.status).toBe(409);
    expect(JSON.stringify(await response.json())).not.toContain("private internal");
  });
});
