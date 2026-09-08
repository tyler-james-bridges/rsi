import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createConnection } from "node:net";

import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  BaseRpcReadCanaryConflictError,
  type BaseRpcReadCanaryPlanV1,
  type BaseRpcReadCanaryProjectionV1,
  type BaseRpcReadCanaryReceiptV1,
  type BaseRpcReadCanaryRunCommand,
} from "@rsi/read-canary/base-rpc";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  startBaseRpcOperatorServer,
  type OperatorBaseRpcReadCanaryProvider,
  type OperatorRuntimeProvider,
  type RunningBaseRpcOperatorServer,
  type RuntimeOperatorControlCommand,
} from "../src/base-rpc.js";

const PRIVATE_PROVIDER_ID = "alchemy-base-mainnet";
const PRIVATE_RPC_ID = "rsi-base-finalized-block-v1";
const PRIVATE_BLOCK_NUMBER = "12345678";
const PRIVATE_BLOCK_HASH = `0x${"1".repeat(64)}`;
const PRIVATE_API_KEY = "offline-base-api-key-never-return";
const PRIVATE_ERROR = "private controller detail must not cross HTTP";

function snapshot(mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED", revision: number) {
  return {
    schemaVersion: 1 as const,
    mode,
    revision,
    modeChangedAt: "2026-09-05T12:00:00.000Z",
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

function plan(): BaseRpcReadCanaryPlanV1 {
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    profile: "canary",
    method: "POST",
    chain: "base-mainnet",
    blockTag: "finalized",
    rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
    maximumRequests: 1,
    maximumAnchors: 1,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
    rawContentDisposition: "encrypted_ephemeral",
    automaticRetries: 0,
    automaticFallback: false,
    paymentAuthority: "none",
    transactionAuthority: "none",
  };
}

function receipt(): BaseRpcReadCanaryReceiptV1 {
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
    rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
    outcome: "accepted",
    failureCode: null,
    completedAt: "2026-09-05T12:00:02.000Z",
    providerReportedFinalized: true,
    freshnessVerdict: "fresh",
    maximumRequests: 1,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
  };
}

function projection(
  status: BaseRpcReadCanaryProjectionV1["status"] = "ready",
): BaseRpcReadCanaryProjectionV1 {
  return {
    schemaVersion: 1,
    status,
    credentialStatus: "configured",
    plan: plan(),
    lastReceipt: status === "completed" ? receipt() : null,
  };
}

function command(expectedRuntimeRevision = 2): BaseRpcReadCanaryRunCommand {
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    expectedRuntimeRevision,
    requestId: randomUUID(),
    typedPlanIdAcknowledgement: BASE_RPC_READ_CANARY_PLAN_ID,
    oneRequestAcknowledgement: true,
    nonPaymentReadAcknowledgement: true,
    noTransactionAuthorityAcknowledgement: true,
    finalizedAnchorAcknowledgement: true,
    methodSetAcknowledgement: BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
    ledgerReserveUsdMicrosAcknowledgement: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  };
}

function controlHeaders(origin: string): Record<string, string> {
  return {
    "content-type": "application/json",
    origin,
    "sec-fetch-site": "same-origin",
    "x-rsi-operator-request": "1",
  };
}

function assertNoPrivateSurface(value: unknown): void {
  const serialized = JSON.stringify(value);
  for (const forbidden of [
    "requestFingerprint",
    BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
    "providerId",
    PRIVATE_PROVIDER_ID,
    "jsonRpcId",
    PRIVATE_RPC_ID,
    "blockNumber",
    PRIVATE_BLOCK_NUMBER,
    "blockHash",
    PRIVATE_BLOCK_HASH,
    "captureId",
    "attemptId",
    "eventHash",
    "requestId",
    "receiptId",
    "headers",
    "rateLimit",
    PRIVATE_API_KEY,
  ]) {
    expect(serialized).not.toContain(forbidden);
  }
}

describe("dedicated Base RPC loopback operator", () => {
  let running: RunningBaseRpcOperatorServer | undefined;

  afterEach(async () => {
    await running?.close();
    running = undefined;
    vi.restoreAllMocks();
  });

  function fixture() {
    let current = snapshot("STOPPED", 1);
    const executeRuntimeControl = vi.fn((runtimeCommand: RuntimeOperatorControlCommand) => {
      current =
        runtimeCommand.action === "runtime-enter-research"
          ? snapshot("RESEARCH", current.revision + 1)
          : snapshot("STOPPED", current.revision + 1);
      return current;
    });
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
      executeRuntimeControl,
      getRuntimeSnapshot: vi.fn(() => current),
    };
    const executeBaseRpcReadCanary = vi.fn(async () => receipt());
    const getBaseRpcReadCanaryProjection = vi.fn(() => projection());
    const refreshBaseRpcCredentialStatus = vi.fn(() => projection());
    const readCanary: OperatorBaseRpcReadCanaryProvider = {
      abortActive: vi.fn(),
      executeBaseRpcReadCanary,
      getBaseRpcReadCanaryProjection,
      refreshBaseRpcCredentialStatus,
    };
    return {
      executeBaseRpcReadCanary,
      executeRuntimeControl,
      getBaseRpcReadCanaryProjection,
      readCanary,
      refreshBaseRpcCredentialStatus,
      runtime,
    };
  }

  it("serves only sanitized fixed-plan, verdict, status, and runtime surfaces", async () => {
    const state = fixture();
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const health = await fetch(`${running.origin}/health`);
    const runtime = await fetch(`${running.origin}/api/runtime`);
    const capabilities = await fetch(`${running.origin}/api/control/capabilities`);
    const canary = await fetch(`${running.origin}/api/base-rpc-read-canary`);
    const events = await fetch(`${running.origin}/api/events`);

    expect(await health.json()).toEqual({ status: "ok", runtime: "persisted" });
    expect(await runtime.json()).toEqual({
      financialAuthority: false,
      runtime: { schemaVersion: 1, mode: "STOPPED", revision: 1 },
    });
    expect(await capabilities.json()).toEqual({
      controls: {
        runtime: { actions: ["runtime-enter-research", "runtime-stop"], enabled: true },
      },
      financialAuthority: false,
    });
    const canaryBody = await canary.json();
    expect(canaryBody).toMatchObject({
      baseRpcReadCanary: {
        status: "ready",
        credentialStatus: "configured",
        plan: {
          planId: BASE_RPC_READ_CANARY_PLAN_ID,
          rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
        },
      },
    });
    assertNoPrivateSurface({
      canaryBody,
      runtime: await fetch(`${running.origin}/api/runtime`).then((r) => r.json()),
    });
    expect(events.status).toBe(404);
    expect(health.headers.get("access-control-allow-origin")).toBeNull();
    expect(health.headers.get("cache-control")).toContain("no-store");

    const dashboard = await fetch(running.origin);
    expect(dashboard.headers.get("content-security-policy")).toContain("connect-src 'self'");
    expect(dashboard.headers.get("content-security-policy")).toContain("navigate-to 'none'");
    expect(dashboard.headers.get("permissions-policy")).toContain("payment=()");
  });

  it("keeps cross-site GET passive and requires exact same-origin credential refresh", async () => {
    const state = fixture();
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const passive = await fetch(`${running.origin}/api/base-rpc-read-canary`, {
      headers: { origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
    });
    expect(passive.status).toBe(200);
    expect(state.getBaseRpcReadCanaryProjection).toHaveBeenCalledOnce();
    expect(state.refreshBaseRpcCredentialStatus).not.toHaveBeenCalled();

    for (const init of [
      { method: "POST" },
      { headers: { origin: running.origin }, method: "POST" },
      {
        headers: {
          origin: running.origin,
          "sec-fetch-site": "cross-site",
          "x-rsi-operator-request": "1",
        },
        method: "POST",
      },
    ]) {
      const rejected = await fetch(
        `${running.origin}/api/base-rpc-read-canary/refresh-credential-status`,
        init,
      );
      expect(rejected.status).toBe(403);
    }
    expect(state.refreshBaseRpcCredentialStatus).not.toHaveBeenCalled();

    const refreshed = await fetch(
      `${running.origin}/api/base-rpc-read-canary/refresh-credential-status`,
      {
        headers: {
          origin: running.origin,
          "sec-fetch-site": "same-origin",
          "x-rsi-operator-request": "1",
        },
        method: "POST",
      },
    );
    expect(refreshed.status).toBe(200);
    expect(state.refreshBaseRpcCredentialStatus).toHaveBeenCalledOnce();
  });

  it("requires RESEARCH and every exact acknowledgement before one sanitized run", async () => {
    const state = fixture();
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const stoppedRun = await fetch(`${running.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command(1)),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    expect(stoppedRun.status).toBe(409);

    const transition = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: randomUUID(),
      }),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    expect(transition.status).toBe(200);

    const exact = command();
    for (const mutation of [
      { typedPlanIdAcknowledgement: "wrong-plan" },
      { oneRequestAcknowledgement: false },
      { nonPaymentReadAcknowledgement: false },
      { noTransactionAuthorityAcknowledgement: false },
      { finalizedAnchorAcknowledgement: false },
      { methodSetAcknowledgement: "eth_sendRawTransaction" },
      { ledgerReserveUsdMicrosAcknowledgement: "0" },
    ]) {
      const rejected = await fetch(`${running.origin}/api/base-rpc-read-canary/run`, {
        body: JSON.stringify({ ...exact, ...mutation }),
        headers: controlHeaders(running.origin),
        method: "POST",
      });
      expect(rejected.status).toBe(400);
    }
    expect(state.executeBaseRpcReadCanary).not.toHaveBeenCalled();

    const run = await fetch(`${running.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(exact),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    const body = await run.json();
    expect(run.status).toBe(200);
    expect(body).toEqual({
      result: {
        schemaVersion: 1,
        planId: BASE_RPC_READ_CANARY_PLAN_ID,
        outcome: "accepted",
        providerReportedFinalized: true,
        freshnessVerdict: "fresh",
      },
    });
    assertNoPrivateSurface(body);
    expect(state.executeBaseRpcReadCanary).toHaveBeenCalledWith(exact);
    expect(state.executeBaseRpcReadCanary).toHaveBeenCalledOnce();
  });

  it("rejects loose content framing, authority headers, query input, and non-loopback bind", async () => {
    const state = fixture();
    await expect(
      startBaseRpcOperatorServer({
        host: "0.0.0.0",
        port: 0,
        readCanary: state.readCanary,
        runtime: state.runtime,
      }),
    ).rejects.toThrow("loopback");
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const query = await fetch(`${running.origin}/api/base-rpc-read-canary?provider=alchemy`);
    expect(query.status).toBe(400);
    const authority = await fetch(`${running.origin}/api/runtime`, {
      headers: { authorization: `Bearer ${PRIVATE_API_KEY}` },
    });
    expect(authority.status).toBe(400);
    expect(JSON.stringify(await authority.json())).not.toContain(PRIVATE_API_KEY);

    const transition = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: randomUUID(),
      }),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    expect(transition.status).toBe(200);
    const looseContentType = await fetch(`${running.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command()),
      headers: {
        ...controlHeaders(running.origin),
        "content-type": "application/json; charset=utf-8",
      },
      method: "POST",
    });
    expect(looseContentType.status).toBe(415);
    expect(state.executeBaseRpcReadCanary).not.toHaveBeenCalled();
  });

  it("returns opaque errors and closes WebSocket upgrades without invoking the canary", async () => {
    const state = fixture();
    state.readCanary.getBaseRpcReadCanaryProjection = vi.fn(() => {
      throw new Error(PRIVATE_ERROR);
    });
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const failed = await fetch(`${running.origin}/api/base-rpc-read-canary`);
    expect(failed.status).toBe(500);
    const failedBody = await failed.json();
    expect(failedBody).toEqual({
      error: { code: "internal_error", message: "The local operator request failed." },
    });

    const socket = createConnection({ host: "127.0.0.1", port: running.port });
    socket.on("error", () => undefined);
    await once(socket, "connect");
    const closed = once(socket, "close");
    socket.write(
      [
        "GET /api/base-rpc-read-canary HTTP/1.1",
        `Host: 127.0.0.1:${running.port}`,
        "Connection: Upgrade",
        "Upgrade: websocket",
        "",
        "",
      ].join("\r\n"),
    );
    await closed;
    expect(state.executeBaseRpcReadCanary).not.toHaveBeenCalled();
    expect(JSON.stringify(failedBody)).not.toContain(PRIVATE_ERROR);
  });

  it("maps authentic canary conflicts without reflecting private details", async () => {
    const state = fixture();
    state.executeRuntimeControl({
      action: "runtime-enter-research",
      expectedMode: "STOPPED",
      expectedRevision: 1,
      requestId: randomUUID(),
    });
    vi.mocked(state.executeBaseRpcReadCanary).mockRejectedValue(
      new BaseRpcReadCanaryConflictError(PRIVATE_ERROR),
    );
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });

    const response = await fetch(`${running.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command()),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    expect(response.status).toBe(409);
    const serialized = JSON.stringify(await response.json());
    expect(serialized).not.toContain(PRIVATE_ERROR);
    expect(serialized).toContain("state changed");
  });

  it("aborts the active read before durable STOP and again during shutdown", async () => {
    const state = fixture();
    running = await startBaseRpcOperatorServer({
      port: 0,
      readCanary: state.readCanary,
      runtime: state.runtime,
    });
    const order: string[] = [];
    vi.mocked(state.readCanary.abortActive).mockImplementation(() => order.push("abort"));
    state.executeRuntimeControl.mockImplementation((runtimeCommand) => {
      order.push(runtimeCommand.action);
      return snapshot("STOPPED", 2);
    });

    const stopped = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({ action: "runtime-stop", requestId: randomUUID() }),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    expect(stopped.status).toBe(200);
    expect(order).toEqual(["abort", "runtime-stop"]);
    await running.close();
    running = undefined;
    expect(order).toEqual(["abort", "runtime-stop", "abort"]);
  });
});
