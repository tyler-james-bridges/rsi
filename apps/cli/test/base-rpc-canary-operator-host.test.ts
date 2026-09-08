import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { chmod, link, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createDarwinBaseRpcKeychainForTesting,
  type BaseRpcCredentialCommandRequest,
} from "@rsi/credential-host/base-rpc-testing";
import type { DarwinOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";
import {
  createDarwinOneShotClaimHostForTesting,
  type OneShotClaimCommandRequest,
} from "@rsi/credential-host/one-shot-claim-testing";
import {
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  getBaseRpcReadCanaryPlan,
  readBaseRpcReadCanaryProjection,
} from "@rsi/read-canary/base-rpc";
import { SqliteRuntimeController } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  pauseNextSnapshotCapture,
  probeRuntimeMutationAfterFinalStop,
} from "./canary-host-shutdown-test-helpers.js";
import {
  startBaseRpcCanaryOperatorForTesting,
  type RunningBaseRpcCanaryOperatorForTesting,
} from "../src/base-rpc-canary-operator-host.testing.js";
import { PROFILE_SERVICE_LOCK_ERROR_MESSAGES } from "../src/profile-service-lock.testing.js";
import * as productionHost from "../src/base-rpc-canary-operator-host.js";

const API_KEY = "offline-alchemy-key-for-base-rpc-host-test";
const BODY =
  '[{"id":"rsi-base-chain-id-v1","jsonrpc":"2.0","method":"eth_chainId","params":[]},{"id":"rsi-base-finalized-block-v1","jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}]';
const SERVICES = Object.freeze([
  "dev.rsi.canary.alchemy-base-read",
  "dev.rsi.canary.base-rpc-operations-state",
  "dev.rsi.canary.base-rpc-capture-registry",
  "dev.rsi.canary.base-rpc-vault-wrapping",
] as const);
const VALUES = Object.freeze([
  API_KEY,
  Buffer.alloc(32, 0x71).toString("base64url"),
  Buffer.alloc(32, 0x72).toString("base64url"),
  Buffer.alloc(32, 0x73).toString("base64url"),
] as const);

let directory: string | undefined;
let operator: RunningBaseRpcCanaryOperatorForTesting | undefined;

afterEach(async () => {
  vi.unstubAllGlobals();
  await operator?.close().catch(() => undefined);
  vi.restoreAllMocks();
  operator = undefined;
  if (directory !== undefined) await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

function credentialHost(requests: BaseRpcCredentialCommandRequest[], timeline: string[] = []) {
  return createDarwinBaseRpcKeychainForTesting({
    platform: "darwin",
    executor: vi.fn(async (request) => {
      requests.push(request);
      const service = request.args[4];
      const index = SERVICES.indexOf(service as (typeof SERVICES)[number]);
      const reveal = request.args.at(-1) === "-w";
      if (reveal) timeline.push(`credential:${service}`);
      return {
        exitCode: index < 0 ? 44 : 0,
        stdout: new TextEncoder().encode(reveal ? `${VALUES[index]!}\n` : "present\n"),
        stderr: new Uint8Array(),
        timedOut: false,
      };
    }),
  });
}

function claimHost(
  requests: OneShotClaimCommandRequest[] = [],
  timeline: string[] = [],
  options: Readonly<{ claimExitCode?: number; statusExitCode?: number }> = {},
): DarwinOneShotClaimHost {
  return createDarwinOneShotClaimHostForTesting("baseRpc", {
    executor: vi.fn(async (request) => {
      requests.push(request);
      const claiming = request.args[0] === "add-generic-password";
      timeline.push(claiming ? "claim:add" : "claim:status");
      return {
        exitCode: claiming ? (options.claimExitCode ?? 0) : (options.statusExitCode ?? 44),
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
        timedOut: false,
      };
    }),
    platform: "darwin",
  });
}

function controlHeaders(origin: string): Record<string, string> {
  return {
    "content-type": "application/json",
    origin,
    "sec-fetch-site": "same-origin",
    "x-rsi-operator-request": "1",
  };
}

function validResponse(): unknown[] {
  const root = `0x${"33".repeat(32)}`;
  const finalizedAt = new Date(Date.now() - 30 * 60 * 1_000);
  return [
    { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", result: "0x2105" },
    {
      id: "rsi-base-finalized-block-v1",
      jsonrpc: "2.0",
      result: {
        baseFeePerGas: "0x1",
        blobGasUsed: "0x0",
        difficulty: "0x0",
        excessBlobGas: "0x0",
        extraData: "0x",
        gasLimit: "0x1c9c380",
        gasUsed: "0x5208",
        hash: `0x${"11".repeat(32)}`,
        logsBloom: `0x${"00".repeat(256)}`,
        miner: `0x${"44".repeat(20)}`,
        mixHash: root,
        nonce: "0x0000000000000000",
        number: "0x1234abcd",
        parentBeaconBlockRoot: root,
        parentHash: `0x${"22".repeat(32)}`,
        receiptsRoot: root,
        requestsHash: root,
        sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        size: "0x200",
        stateRoot: root,
        timestamp: `0x${Math.floor(finalizedAt.getTime() / 1_000).toString(16)}`,
        totalDifficulty: "0x0",
        transactions: [],
        transactionsRoot: root,
        uncles: [],
        withdrawals: [],
        withdrawalsRoot: root,
      },
    },
  ];
}

function installNetwork(timeline: string[] = []) {
  const nativeFetch = globalThis.fetch;
  const network = vi.fn(async (request: Request) => {
    timeline.push("network");
    expect(request.url).toBe("https://base-mainnet.g.alchemy.com/v2");
    expect(request.method).toBe("POST");
    expect(request.redirect).toBe("error");
    expect(request.credentials).toBe("omit");
    expect(request.headers.get("authorization")).toBe(`Bearer ${API_KEY}`);
    expect(request.headers.get("accept")).toBe("application/json");
    expect(request.headers.get("accept-encoding")).toBe("identity");
    expect(request.headers.get("content-type")).toBe("application/json");
    expect(await request.text()).toBe(BODY);
    return new Response(JSON.stringify(validResponse()), {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  });
  vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
    const input = args[0];
    const value = input instanceof Request ? input : new Request(input, args[1]);
    if (value.url === "https://base-mainnet.g.alchemy.com/v2") return network(value);
    return nativeFetch(...args);
  });
  return network;
}

async function enterResearch(origin: string): Promise<number> {
  const current = (await (await fetch(`${origin}/api/runtime`)).json()) as {
    runtime: { mode: "STOPPED"; revision: number };
  };
  const response = await fetch(`${origin}/api/control`, {
    body: JSON.stringify({
      action: "runtime-enter-research",
      expectedMode: "STOPPED",
      expectedRevision: current.runtime.revision,
      requestId: randomUUID(),
    }),
    headers: controlHeaders(origin),
    method: "POST",
  });
  const body = (await response.json()) as { result: { revision: number } };
  expect(response.status).toBe(200);
  return body.result.revision;
}

function command(expectedRuntimeRevision: number): Record<string, unknown> {
  const plan = getBaseRpcReadCanaryPlan();
  return {
    schemaVersion: 1,
    planId: plan.planId,
    expectedRuntimeRevision,
    requestId: randomUUID(),
    typedPlanIdAcknowledgement: plan.planId,
    oneRequestAcknowledgement: true,
    nonPaymentReadAcknowledgement: true,
    noTransactionAuthorityAcknowledgement: true,
    finalizedAnchorAcknowledgement: true,
    methodSetAcknowledgement: BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
    ledgerReserveUsdMicrosAcknowledgement: plan.ledgerReserveUsdMicros,
  };
}

describe("Base RPC canary operator host", () => {
  it("keeps host injection behind the testing entry and production optionless", () => {
    expect(Object.keys(productionHost)).toEqual(["startBaseRpcCanaryOperator"]);
    expect(productionHost.startBaseRpcCanaryOperator).toHaveLength(0);
  });

  it("rejects a non-private directory before credential, claim, or network access", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-permissions-"));
    await chmod(directory, 0o755);
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const claims: OneShotClaimCommandRequest[] = [];
    const network = installNetwork();

    await expect(
      startBaseRpcCanaryOperatorForTesting({
        claimHost: claimHost(claims),
        credentialHost: credentialHost(credentials),
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
      }),
    ).rejects.toThrow(PROFILE_SERVICE_LOCK_ERROR_MESSAGES.unsafe);
    expect(credentials).toEqual([]);
    expect(claims).toEqual([]);
    expect(network).not.toHaveBeenCalled();
    expect(await readdir(directory)).toEqual([]);
  });

  it("rejects a hard-linked runtime database before credential, claim, or network access", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-hardlink-"));
    const sourcePath = join(directory, "linked-source.sqlite");
    const runtimePath = join(directory, "runtime.sqlite");
    await writeFile(sourcePath, "offline hard-link fixture");
    await link(sourcePath, runtimePath);
    expect((await stat(runtimePath, { bigint: true })).nlink).toBe(2n);
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const claims: OneShotClaimCommandRequest[] = [];
    const network = installNetwork();

    await expect(
      startBaseRpcCanaryOperatorForTesting({
        claimHost: claimHost(claims),
        credentialHost: credentialHost(credentials),
        databasePath: runtimePath,
        port: 0,
      }),
    ).rejects.toThrow("Base RPC canary SQLite paths must be regular files");
    expect(credentials).toEqual([]);
    expect(claims).toEqual([]);
    expect(network).not.toHaveBeenCalled();
  });

  it("boots with storage-only recovery, claims immediately before API reveal, and egresses once", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-"));
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const claims: OneShotClaimCommandRequest[] = [];
    const timeline: string[] = [];
    const network = installNetwork(timeline);
    operator = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(claims, timeline),
      credentialHost: credentialHost(credentials, timeline),
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
    });

    expect(operator.runtime.getSnapshot().mode).toBe("STOPPED");
    expect(timeline).toEqual([
      ...SERVICES.slice(1).map((service) => `credential:${service}`),
      "claim:status",
    ]);
    expect(claims).toHaveLength(1);
    expect(claims[0]!.args[0]).toBe("find-generic-password");
    expect(network).not.toHaveBeenCalled();

    const revision = await enterResearch(operator.origin);
    const firstCommand = command(revision);
    const run = await fetch(`${operator.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(firstCommand),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    const body = await run.json();
    expect(run.status).toBe(200);
    expect(body).toEqual({
      result: {
        schemaVersion: 1,
        planId: "base-mainnet-finalized-anchor-v1",
        outcome: "accepted",
        providerReportedFinalized: true,
        freshnessVerdict: "fresh",
      },
    });
    expect(network).toHaveBeenCalledOnce();
    const claimIndex = timeline.indexOf("claim:add");
    expect(claimIndex).toBeGreaterThanOrEqual(3);
    expect(timeline[claimIndex + 1]).toBe(`credential:${SERVICES[0]}`);
    expect(timeline.at(-1)).toBe("network");
    expect(claims.filter((request) => request.args[0] === "add-generic-password")).toHaveLength(1);
    expect(credentials).toHaveLength(7);

    const serialized = JSON.stringify(body);
    for (const forbidden of [API_KEY, "1234abcd", "111111", "222222", "requestId", "capture"]) {
      expect(serialized).not.toContain(forbidden);
    }

    const differentCommand = command(revision);
    expect(differentCommand.requestId).not.toBe(firstCommand.requestId);
    const repeat = await fetch(`${operator.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(differentCommand),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    expect(repeat.status).toBe(409);
    expect(network).toHaveBeenCalledOnce();
    expect(claims.filter((request) => request.args[0] === "add-generic-password")).toHaveLength(1);
  });

  it.each([
    ["duplicate", 45],
    ["unavailable", 1],
  ] as const)(
    "denies a %s permanent claim before API-key reveal or egress",
    async (_label, code) => {
      directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-claim-"));
      const credentials: BaseRpcCredentialCommandRequest[] = [];
      const claims: OneShotClaimCommandRequest[] = [];
      const network = installNetwork();
      operator = await startBaseRpcCanaryOperatorForTesting({
        claimHost: claimHost(claims, [], { claimExitCode: code }),
        credentialHost: credentialHost(credentials),
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
      });
      const revision = await enterResearch(operator.origin);

      const response = await fetch(`${operator.origin}/api/base-rpc-read-canary/run`, {
        body: JSON.stringify(command(revision)),
        headers: controlHeaders(operator.origin),
        method: "POST",
      });
      expect(response.status).toBe(500);
      expect(claims.filter((request) => request.args[0] === "add-generic-password")).toHaveLength(
        1,
      );
      expect(
        credentials.filter(
          (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
        ),
      ).toEqual([]);
      expect(network).not.toHaveBeenCalled();
    },
  );

  it("lets durable STOP cancel a delayed claim before API-key reveal or egress", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-stop-claim-"));
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const network = installNetwork();
    let finishClaim: (() => void) | undefined;
    let claimStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      claimStarted = resolve;
    });
    const claimHostWithDelay = createDarwinOneShotClaimHostForTesting("baseRpc", {
      executor: vi.fn(async (request) => {
        if (request.args[0] !== "add-generic-password") {
          return {
            exitCode: 44,
            stdout: new Uint8Array(),
            stderr: new Uint8Array(),
            timedOut: false,
          };
        }
        claimStarted();
        await new Promise<void>((resolve) => {
          finishClaim = resolve;
        });
        return {
          exitCode: 0,
          stdout: new Uint8Array(),
          stderr: new Uint8Array(),
          timedOut: false,
        };
      }),
      platform: "darwin",
    });
    operator = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHostWithDelay,
      credentialHost: credentialHost(credentials),
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
    });
    const revision = await enterResearch(operator.origin);
    const runPromise = fetch(`${operator.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command(revision)),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    await started;

    const stop = await fetch(`${operator.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-stop",
        requestId: randomUUID(),
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    finishClaim?.();
    expect(stop.status).toBe(200);
    const run = await runPromise;
    expect(run.status).toBe(409);
    expect(
      credentials.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
    expect(operator.runtime.getSnapshot().mode).toBe("STOPPED");
  });

  it("revalidates runtime after a slow body so prior STOP cannot claim or egress", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-slow-body-stop-"));
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const claims: OneShotClaimCommandRequest[] = [];
    const network = installNetwork();
    operator = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(claims),
      credentialHost: credentialHost(credentials),
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
    });
    const revision = await enterResearch(operator.origin);
    const encoded = JSON.stringify(command(revision));
    const port = Number(new URL(operator.origin).port);
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.on("error", () => undefined);
    await once(socket, "connect");
    socket.write(
      [
        "POST /api/base-rpc-read-canary/run HTTP/1.1",
        `Host: 127.0.0.1:${port}`,
        `Origin: ${operator.origin}`,
        "Sec-Fetch-Site: same-origin",
        "X-RSI-Operator-Request: 1",
        "Content-Type: application/json",
        `Content-Length: ${Buffer.byteLength(encoded)}`,
        "Connection: close",
        "",
        encoded.slice(0, -1),
      ].join("\r\n"),
    );
    await new Promise<void>((resolve) => setTimeout(resolve, 25));

    const stop = await fetch(`${operator.origin}/api/control`, {
      body: JSON.stringify({ action: "runtime-stop", requestId: randomUUID() }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    expect(stop.status).toBe(200);
    const response = new Promise<string>((resolve) => {
      let raw = "";
      socket.setEncoding("utf8");
      socket.on("data", (chunk: string) => {
        raw += chunk;
      });
      socket.on("end", () => resolve(raw));
    });
    socket.end(encoded.slice(-1));
    expect(await response).toContain("HTTP/1.1 409 Conflict");
    expect(claims.filter((request) => request.args[0] === "add-generic-password")).toEqual([]);
    expect(
      credentials.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
    expect(operator.runtime.getSnapshot().mode).toBe("STOPPED");
  });

  it("revalidates runtime after delayed storage recovery before claiming", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-recovery-transition-"));
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const claims: OneShotClaimCommandRequest[] = [];
    const network = installNetwork();
    let operationsReads = 0;
    let finishRecovery: (() => void) | undefined;
    let recoveryStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      recoveryStarted = resolve;
    });
    const recoveringCredentialHost = createDarwinBaseRpcKeychainForTesting({
      platform: "darwin",
      executor: vi.fn(async (request) => {
        credentials.push(request);
        const service = request.args[4];
        const index = SERVICES.indexOf(service as (typeof SERVICES)[number]);
        const reveal = request.args.at(-1) === "-w";
        if (reveal && service === SERVICES[1]) {
          operationsReads += 1;
          if (operationsReads === 1) {
            return {
              exitCode: 44,
              stdout: new Uint8Array(),
              stderr: new Uint8Array(),
              timedOut: false,
            };
          }
          recoveryStarted();
          await new Promise<void>((resolve) => {
            finishRecovery = resolve;
          });
        }
        return {
          exitCode: index < 0 ? 44 : 0,
          stdout: new TextEncoder().encode(reveal ? `${VALUES[index]!}\n` : "present\n"),
          stderr: new Uint8Array(),
          timedOut: false,
        };
      }),
    });
    operator = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(claims),
      credentialHost: recoveringCredentialHost,
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
    });
    expect(operationsReads).toBe(1);
    const revision = await enterResearch(operator.origin);
    const runPromise = fetch(`${operator.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command(revision)),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    await started;

    const transition = operator.runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "PROPOSE_ONLY",
    });
    finishRecovery?.();
    expect(transition.mode).toBe("PROPOSE_ONLY");
    const run = await runPromise;
    expect(run.status).toBe(409);
    expect(claims.filter((request) => request.args[0] === "add-generic-password")).toEqual([]);
    expect(
      credentials.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
    expect(operator.runtime.getSnapshot().mode).toBe("PROPOSE_ONLY");
  });

  it("blocks late runtime control while draining an active Base RPC request and persists final STOP", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-close-race-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const nativeFetch = globalThis.fetch;
    const network = vi.fn(
      async () =>
        new Response(JSON.stringify(validResponse()), {
          status: 200,
          headers: { "content-type": "application/json; charset=utf-8" },
        }),
    );
    vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
      const input = args[0];
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://base-mainnet.g.alchemy.com/v2") return network();
      return nativeFetch(...args);
    });
    const running = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: credentialHost([]),
      databasePath: runtimePath,
      port: 0,
    });
    operator = running;
    const stopped = running.runtime.getSnapshot();
    const research = running.runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const capture = pauseNextSnapshotCapture();
    const runPromise = fetch(`${running.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command(research.revision)),
      headers: controlHeaders(running.origin),
      method: "POST",
    });
    const observedRun = runPromise.catch(() => undefined);
    await capture.started;

    const finalStopProbe = probeRuntimeMutationAfterFinalStop(running.runtime);
    const closePromise = running.close();
    let closeSettled = false;
    void closePromise.then(
      () => {
        closeSettled = true;
      },
      () => {
        closeSettled = true;
      },
    );
    const stoppedDuringClose = running.runtime.getSnapshot();
    const lateControlRequestId = randomUUID();
    try {
      await Promise.resolve();
      expect(closeSettled).toBe(false);
      expect(stoppedDuringClose.mode).toBe("STOPPED");
      const lateStatus = await fetch(`${running.origin}/api/control`, {
        body: JSON.stringify({
          action: "runtime-enter-research",
          expectedMode: "STOPPED",
          expectedRevision: stoppedDuringClose.revision,
          requestId: lateControlRequestId,
        }),
        headers: controlHeaders(running.origin),
        method: "POST",
        signal: AbortSignal.timeout(1_000),
      }).then(
        (response) => response.status,
        () => "rejected" as const,
      );
      expect(lateStatus).not.toBe(200);
    } finally {
      capture.release();
    }
    await observedRun;
    await closePromise;
    expect(await finalStopProbe.attempt).toBe("rejected");
    capture.restore();
    finalStopProbe.restore();
    operator = undefined;
    expect(network).toHaveBeenCalledOnce();

    const canaryStore = new SqliteEventStore(running.paths.eventStore);
    const projection = readBaseRpcReadCanaryProjection(canaryStore, "unknown");
    expect(projection.status).not.toBe("completed");
    expect(projection.lastReceipt?.outcome).not.toBe("accepted");
    expect(
      projection.status === "interrupted" ||
        (projection.status === "failed" &&
          projection.lastReceipt?.outcome === "rejected" &&
          projection.lastReceipt.failureCode === "RUNTIME_DENIED"),
    ).toBe(true);
    canaryStore.close();

    const reopened = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    const audit = reopened.listAudit();
    expect(reopened.getSnapshot().mode).toBe("STOPPED");
    expect(audit.at(-2)).toMatchObject({
      payload: { cause: "operator", to: "STOPPED" },
      type: "runtime.stop.enforced.v1",
    });
    expect(JSON.stringify(audit)).not.toContain(lateControlRequestId);
    expect(JSON.stringify(audit)).not.toContain(finalStopProbe.requestId);
    reopened.close();
  });

  it("keeps shutdown and the profile lock pending until active credential status settles", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-status-close-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const lockPath = join(directory, ".rsi-stage1-canary.lock");
    let notifyStatusStarted!: () => void;
    const statusStarted = new Promise<void>((resolve) => {
      notifyStatusStarted = resolve;
    });
    let releaseStatus!: () => void;
    const statusRelease = new Promise<void>((resolve) => {
      releaseStatus = resolve;
    });
    let held = false;
    const delayedCredentialHost = createDarwinBaseRpcKeychainForTesting({
      platform: "darwin",
      executor: vi.fn(async (request) => {
        const service = request.args[4];
        const index = SERVICES.indexOf(service as (typeof SERVICES)[number]);
        const reveal = request.args.at(-1) === "-w";
        if (!held && service === SERVICES[0] && !reveal) {
          held = true;
          notifyStatusStarted();
          await statusRelease;
        }
        return {
          exitCode: index < 0 ? 44 : 0,
          stdout: new TextEncoder().encode(reveal ? `${VALUES[index]!}\n` : "present\n"),
          stderr: new Uint8Array(),
          timedOut: false,
        };
      }),
    });
    const running = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: delayedCredentialHost,
      databasePath: runtimePath,
      port: 0,
    });
    operator = running;
    const statusAbort = new AbortController();
    const observedStatus = fetch(
      `${running.origin}/api/base-rpc-read-canary/refresh-credential-status`,
      {
        headers: {
          origin: running.origin,
          "sec-fetch-site": "same-origin",
          "x-rsi-operator-request": "1",
        },
        method: "POST",
        signal: statusAbort.signal,
      },
    ).catch(() => undefined);
    await statusStarted;

    const closePromise = running.close();
    let closeSettled = false;
    void closePromise.then(
      () => {
        closeSettled = true;
      },
      () => {
        closeSettled = true;
      },
    );
    try {
      await Promise.resolve();
      expect(closeSettled).toBe(false);
      expect((await stat(lockPath)).isFile()).toBe(true);
    } finally {
      releaseStatus();
    }
    await closePromise;
    statusAbort.abort();
    await observedStatus;
    operator = undefined;
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("denies an admitted canary body that completes after host shutdown begins", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-admitted-body-close-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const credentialRequests: BaseRpcCredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    vi.stubGlobal("fetch", network);
    const running = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(claimRequests),
      credentialHost: credentialHost(credentialRequests),
      databasePath: runtimePath,
      port: 0,
    });
    operator = running;
    const stopped = running.runtime.getSnapshot();
    const research = running.runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const body = JSON.stringify(command(research.revision));
    const port = Number(new URL(running.origin).port);
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.on("error", () => undefined);
    await once(socket, "connect");
    socket.write(
      [
        "POST /api/base-rpc-read-canary/run HTTP/1.1",
        `Host: 127.0.0.1:${port}`,
        `Origin: ${running.origin}`,
        "Sec-Fetch-Site: same-origin",
        "X-RSI-Operator-Request: 1",
        "Content-Type: application/json",
        `Content-Length: ${Buffer.byteLength(body)}`,
        "",
        body.slice(0, -1),
      ].join("\r\n"),
    );
    await new Promise<void>((resolve) => setTimeout(resolve, 25));

    const closePromise = running.close();
    socket.end(body.slice(-1));
    await closePromise;
    operator = undefined;
    socket.destroy();

    expect(claimRequests.filter((request) => request.args[0] === "add-generic-password")).toEqual(
      [],
    );
    expect(
      credentialRequests.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
    const reopened = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    expect(reopened.getSnapshot().mode).toBe("STOPPED");
    reopened.close();
  });

  it("refuses a present marker without durable canary events", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-orphan-marker-"));
    const credentials: BaseRpcCredentialCommandRequest[] = [];
    const claims: OneShotClaimCommandRequest[] = [];
    const network = installNetwork();

    await expect(
      startBaseRpcCanaryOperatorForTesting({
        claimHost: claimHost(claims, [], { statusExitCode: 0 }),
        credentialHost: credentialHost(credentials),
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
      }),
    ).rejects.toThrow("permanent Base RPC canary marker has no durable receipt");
    expect(claims).toHaveLength(1);
    expect(claims[0]!.args[0]).toBe("find-generic-password");
    expect(
      credentials.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(
      credentials
        .filter((request) => request.args.at(-1) === "-w")
        .map((request) => request.args[4]),
    ).toEqual(SERVICES.slice(1));
    expect(network).not.toHaveBeenCalled();
  });

  it("refuses a completed durable receipt when its permanent marker is absent", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-host-marker-"));
    const databasePath = join(directory, "runtime.sqlite");
    const network = installNetwork();
    operator = await startBaseRpcCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: credentialHost([]),
      databasePath,
      port: 0,
    });
    const revision = await enterResearch(operator.origin);
    const run = await fetch(`${operator.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify(command(revision)),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    expect(run.status).toBe(200);
    expect(network).toHaveBeenCalledOnce();
    await operator.close();
    operator = undefined;

    const restartCredentials: BaseRpcCredentialCommandRequest[] = [];
    const restartClaims: OneShotClaimCommandRequest[] = [];
    await expect(
      startBaseRpcCanaryOperatorForTesting({
        claimHost: claimHost(restartClaims, [], { statusExitCode: 44 }),
        credentialHost: credentialHost(restartCredentials),
        databasePath,
        port: 0,
      }),
    ).rejects.toThrow("requires its permanent one-shot marker");
    expect(restartClaims).toHaveLength(1);
    expect(restartClaims[0]!.args[0]).toBe("find-generic-password");
    expect(
      restartCredentials.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).toHaveBeenCalledOnce();
  });
});
