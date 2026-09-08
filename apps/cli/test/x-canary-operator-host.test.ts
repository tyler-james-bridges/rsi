import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { chmod, link, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import type { DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import {
  createDarwinXReadCanaryKeychainForTesting,
  type CredentialCommandExecutor,
  type CredentialCommandRequest,
} from "@rsi/credential-host/testing";
import type { DarwinOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";
import {
  createDarwinOneShotClaimHostForTesting,
  type OneShotClaimCommandRequest,
} from "@rsi/credential-host/one-shot-claim-testing";
import {
  X_READ_CANARY_PLAN_ID,
  X_READ_CANARY_PROVIDER_ID,
  XReadCanaryController,
  readXReadCanaryProjection,
  type XReadCanaryReceiptV1,
} from "@rsi/read-canary";
import { SqliteOperationsStore } from "@rsi/operations";
import { SqliteRuntimeController } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { SnapshotVault } from "@rsi/vault";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  pauseNextSnapshotCapture,
  probeRuntimeMutationAfterFinalStop,
} from "./canary-host-shutdown-test-helpers.js";
import { PROFILE_SERVICE_LOCK_ERROR_MESSAGES } from "../src/profile-service-lock.testing.js";
import {
  startXCanaryOperatorForTesting,
  type RunningXCanaryOperatorForTesting,
} from "../src/x-canary-operator-host.testing.js";
import * as productionHost from "../src/x-canary-operator-host.js";

const TEST_TOKEN = "offline-cli-canary-token";
const SERVICES = Object.freeze([
  "dev.rsi.canary.x-read",
  "dev.rsi.canary.operations-state",
  "dev.rsi.canary.capture-registry",
  "dev.rsi.canary.vault-wrapping",
] as const);
const VALUES = Object.freeze([
  TEST_TOKEN,
  Buffer.alloc(32, 0x31).toString("base64url"),
  Buffer.alloc(32, 0x32).toString("base64url"),
  Buffer.alloc(32, 0x33).toString("base64url"),
] as const);

let directory: string | undefined;
let operator: RunningXCanaryOperatorForTesting | undefined;

afterEach(async () => {
  vi.unstubAllGlobals();
  await operator?.close().catch(() => undefined);
  vi.restoreAllMocks();
  operator = undefined;
  if (directory !== undefined) await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

function credentialHost(requests?: CredentialCommandRequest[]): DarwinXReadCanaryKeychain {
  const executor: CredentialCommandExecutor = vi.fn(async (request) => {
    requests?.push(request);
    const service = request.args[4];
    const index = SERVICES.indexOf(service as (typeof SERVICES)[number]);
    const reveal = request.args.at(-1) === "-w";
    return {
      exitCode: index < 0 ? 44 : 0,
      stdout: new TextEncoder().encode(reveal ? `${VALUES[index]!}\n` : "present\n"),
      stderr: new Uint8Array(),
      timedOut: false,
    };
  });
  return createDarwinXReadCanaryKeychainForTesting({ executor, platform: "darwin" });
}

function claimHost(
  requests?: OneShotClaimCommandRequest[],
  claimExitCode: number | null = 0,
  statusExitCode: number | null = 44,
): DarwinOneShotClaimHost {
  return createDarwinOneShotClaimHostForTesting("x", {
    executor: vi.fn(async (request) => {
      requests?.push(request);
      return {
        exitCode: request.args[0] === "add-generic-password" ? claimExitCode : statusExitCode,
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

function routeXProviderRequests(network: (...args: Parameters<typeof fetch>) => unknown): void {
  const nativeFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
    const input = args[0];
    const url = input instanceof Request ? input.url : String(input);
    if (new URL(url).hostname === "api.x.com") return (await network(...args)) as Response;
    return nativeFetch(...args);
  });
}

describe("Stage 1 X canary operator host", () => {
  it("keeps credential injection off the production host entry", () => {
    expect(Object.keys(productionHost)).toEqual(["startXCanaryOperator"]);
    expect(productionHost).not.toHaveProperty("startXCanaryOperatorWithHost");
    expect(productionHost).not.toHaveProperty("startXCanaryOperatorWithCredentialHostForTesting");
  });

  it("rejects a non-private data directory before reading credentials", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-permissions-"));
    await chmod(directory, 0o755);
    const requests: CredentialCommandRequest[] = [];

    await expect(
      startXCanaryOperatorForTesting({
        claimHost: claimHost(),
        credentialHost: credentialHost(requests),
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
        researchDatabasePath: join(directory, "research.sqlite"),
      }),
    ).rejects.toThrow(PROFILE_SERVICE_LOCK_ERROR_MESSAGES.unsafe);
    expect(requests).toEqual([]);
    expect(await readdir(directory)).toEqual([]);
  });

  it("rejects a hard-linked runtime database before credential, claim, or network access", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-hardlink-"));
    const sourcePath = join(directory, "linked-source.sqlite");
    const runtimePath = join(directory, "runtime.sqlite");
    await writeFile(sourcePath, "offline hard-link fixture");
    await link(sourcePath, runtimePath);
    expect((await stat(runtimePath, { bigint: true })).nlink).toBe(2n);
    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    routeXProviderRequests(network);

    await expect(
      startXCanaryOperatorForTesting({
        claimHost: claimHost(claimRequests),
        credentialHost: credentialHost(credentialRequests),
        databasePath: runtimePath,
        port: 0,
        researchDatabasePath: join(directory, "research.sqlite"),
      }),
    ).rejects.toThrow("Stage 1 SQLite paths must be regular files");
    expect(credentialRequests).toEqual([]);
    expect(claimRequests).toEqual([]);
    expect(network).not.toHaveBeenCalled();
  });

  it("creates an absent Stage 1 data directory with owner-only permissions", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-private-parent-"));
    const dataDirectory = join(directory, "stage1");

    operator = await startXCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: credentialHost(),
      databasePath: join(dataDirectory, "runtime.sqlite"),
      port: 0,
      researchDatabasePath: join(dataDirectory, "research.sqlite"),
    });

    expect((await stat(dataDirectory)).mode & 0o777).toBe(0o700);
  });

  it("boots STOPPED and performs one explicit local-operator canary without leaking content", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-"));
    const nativeFetch = globalThis.fetch;
    const network = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            data: [{ id: "1900000000000000001", text: "HOSTILE RAW POST TEXT" }],
            meta: {
              newest_id: "1900000000000000001",
              oldest_id: "1900000000000000001",
              result_count: 1,
            },
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
    );
    vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
      const [input] = args;
      const url = input instanceof Request ? input.url : String(input);
      if (new URL(url).hostname === "api.x.com") return network();
      return nativeFetch(...args);
    });
    operator = await startXCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: credentialHost(),
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
    });

    const runtimeResponse = await fetch(`${operator.origin}/api/runtime`);
    const runtimeBody = (await runtimeResponse.json()) as {
      runtime: { mode: string; revision: number };
    };
    expect(runtimeBody.runtime.mode).toBe("STOPPED");

    const credentialResponse = await fetch(`${operator.origin}/api/read-canary`);
    expect(await credentialResponse.json()).toMatchObject({
      readCanary: { credentialStatus: "configured", status: "ready" },
    });

    const transition = await fetch(`${operator.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: runtimeBody.runtime.revision,
        requestId: randomUUID(),
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    const transitioned = (await transition.json()) as { result: { revision: number } };
    expect(transition.status).toBe(200);

    const run = await fetch(`${operator.origin}/api/read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: X_READ_CANARY_PLAN_ID,
        expectedRuntimeRevision: transitioned.result.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    const body = await run.json();

    expect(run.status).toBe(200);
    expect(body).toMatchObject({
      result: {
        actualChargeUsdMicros: null,
        maximumChargeUsdMicros: "50000",
        outcome: "accepted",
        postCount: 1,
      },
    });
    expect(network).toHaveBeenCalledOnce();
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain(TEST_TOKEN);
    expect(serialized).not.toContain("HOSTILE RAW POST TEXT");

    const repeat = await fetch(`${operator.origin}/api/read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: X_READ_CANARY_PLAN_ID,
        expectedRuntimeRevision: transitioned.result.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    expect(repeat.status).toBe(409);
    expect(network).toHaveBeenCalledOnce();
  });

  it.each([
    ["duplicate", 45],
    ["unavailable", 1],
  ] as const)(
    "denies a %s permanent claim before provider credential reads or egress",
    async (_label, claimExitCode) => {
      directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-claim-denial-"));
      const credentialRequests: CredentialCommandRequest[] = [];
      const claimRequests: OneShotClaimCommandRequest[] = [];
      const network = vi.fn(async () => new Response(null, { status: 500 }));
      const nativeFetch = globalThis.fetch;
      vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
        const [input] = args;
        const url = input instanceof Request ? input.url : String(input);
        if (new URL(url).hostname === "api.x.com") return network();
        return nativeFetch(...args);
      });
      operator = await startXCanaryOperatorForTesting({
        claimHost: claimHost(claimRequests, claimExitCode),
        credentialHost: credentialHost(credentialRequests),
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
        researchDatabasePath: join(directory, "research.sqlite"),
      });
      const stopped = operator.runtime.getSnapshot();
      const research = operator.runtime.transition({
        expectedMode: stopped.mode,
        expectedRevision: stopped.revision,
        occurredAt: new Date().toISOString(),
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });

      const response = await fetch(`${operator.origin}/api/read-canary/run`, {
        body: JSON.stringify({
          schemaVersion: 1,
          planId: X_READ_CANARY_PLAN_ID,
          expectedRuntimeRevision: research.revision,
          requestId: randomUUID(),
          typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
          oneRequestAcknowledgement: true,
          maximumChargeUsdMicrosAcknowledgement: "50000",
        }),
        headers: controlHeaders(operator.origin),
        method: "POST",
      });

      expect(response.status).toBe(500);
      expect(
        claimRequests.filter((request) => request.args[0] === "add-generic-password"),
      ).toHaveLength(1);
      expect(
        credentialRequests.filter(
          (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
        ),
      ).toEqual([]);
      expect(network).not.toHaveBeenCalled();
    },
  );

  it("rejects STOPPED and stale-revision runs before a permanent claim", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-runtime-preflight-"));
    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    routeXProviderRequests(network);
    operator = await startXCanaryOperatorForTesting({
      claimHost: claimHost(claimRequests),
      credentialHost: credentialHost(credentialRequests),
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
    });
    const stopped = operator.runtime.getSnapshot();
    const run = (expectedRuntimeRevision: number): Promise<Response> =>
      fetch(`${operator!.origin}/api/read-canary/run`, {
        body: JSON.stringify({
          schemaVersion: 1,
          planId: X_READ_CANARY_PLAN_ID,
          expectedRuntimeRevision,
          requestId: randomUUID(),
          typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
          oneRequestAcknowledgement: true,
          maximumChargeUsdMicrosAcknowledgement: "50000",
        }),
        headers: controlHeaders(operator!.origin),
        method: "POST",
      });
    expect((await run(stopped.revision)).status).toBe(409);
    operator.runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    expect((await run(stopped.revision)).status).toBe(409);
    expect(claimRequests.filter((request) => request.args[0] === "add-generic-password")).toEqual(
      [],
    );
    expect(
      credentialRequests.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
  });

  it("stops a delayed permanent claim before any credential reveal or egress", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-claim-stop-"));
    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    routeXProviderRequests(network);
    let notifyClaimStarted!: () => void;
    const claimStarted = new Promise<void>((resolve) => {
      notifyClaimStarted = resolve;
    });
    let releaseClaim!: () => void;
    const claimRelease = new Promise<void>((resolve) => {
      releaseClaim = resolve;
    });
    const delayedClaimHost = createDarwinOneShotClaimHostForTesting("x", {
      executor: vi.fn(async (request) => {
        claimRequests.push(request);
        if (request.args[0] === "add-generic-password") {
          notifyClaimStarted();
          await claimRelease;
          return {
            exitCode: 0,
            stdout: new Uint8Array(),
            stderr: new Uint8Array(),
            timedOut: false,
          };
        }
        return {
          exitCode: 44,
          stdout: new Uint8Array(),
          stderr: new Uint8Array(),
          timedOut: false,
        };
      }),
      platform: "darwin",
    });
    operator = await startXCanaryOperatorForTesting({
      claimHost: delayedClaimHost,
      credentialHost: credentialHost(credentialRequests),
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
    });
    const stopped = operator.runtime.getSnapshot();
    const research = operator.runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const run = fetch(`${operator.origin}/api/read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: X_READ_CANARY_PLAN_ID,
        expectedRuntimeRevision: research.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    const observedRun = run.then(
      (response) => response.status,
      () => "rejected" as const,
    );
    await claimStarted;
    const stopResponse = await fetch(`${operator.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-stop",
        requestId: randomUUID(),
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });
    try {
      expect(stopResponse.status).toBe(200);
    } finally {
      releaseClaim();
    }
    expect(await observedRun).not.toBe(200);
    expect(
      credentialRequests.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
  });

  it("refuses a present marker without a durable receipt before provider credentials", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-orphan-marker-"));
    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    routeXProviderRequests(network);
    await expect(
      startXCanaryOperatorForTesting({
        claimHost: claimHost(claimRequests, 0, 0),
        credentialHost: credentialHost(credentialRequests),
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
        researchDatabasePath: join(directory, "research.sqlite"),
      }),
    ).rejects.toThrow("permanent X canary marker has no durable receipt");
    expect(
      credentialRequests.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();
  });

  it("keeps a successful claim owned when the following credential reveal fails", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-post-claim-failure-"));
    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    routeXProviderRequests(network);
    const failingCredentialHost = createDarwinXReadCanaryKeychainForTesting({
      executor: vi.fn(async (request) => {
        credentialRequests.push(request);
        const service = request.args[4];
        const index = SERVICES.indexOf(service as (typeof SERVICES)[number]);
        const reveal = request.args.at(-1) === "-w";
        const apiReveal = service === SERVICES[0] && reveal;
        return {
          exitCode: apiReveal ? 44 : index < 0 ? 44 : 0,
          stdout: new TextEncoder().encode(reveal && !apiReveal ? `${VALUES[index]!}\n` : ""),
          stderr: new Uint8Array(),
          timedOut: false,
        };
      }),
      platform: "darwin",
    });
    operator = await startXCanaryOperatorForTesting({
      claimHost: claimHost(claimRequests),
      credentialHost: failingCredentialHost,
      databasePath: join(directory, "runtime.sqlite"),
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
    });
    const stopped = operator.runtime.getSnapshot();
    const research = operator.runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const run = (): Promise<Response> =>
      fetch(`${operator!.origin}/api/read-canary/run`, {
        body: JSON.stringify({
          schemaVersion: 1,
          planId: X_READ_CANARY_PLAN_ID,
          expectedRuntimeRevision: research.revision,
          requestId: randomUUID(),
          typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
          oneRequestAcknowledgement: true,
          maximumChargeUsdMicrosAcknowledgement: "50000",
        }),
        headers: controlHeaders(operator!.origin),
        method: "POST",
      });
    expect((await run()).status).not.toBe(200);
    expect((await run()).status).not.toBe(200);
    expect(
      claimRequests.filter((request) => request.args[0] === "add-generic-password"),
    ).toHaveLength(1);
    expect(
      credentialRequests.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toHaveLength(1);
    expect(network).not.toHaveBeenCalled();
  });

  it("blocks late runtime control while draining an active X request and persists final STOP", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-close-race-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const nativeFetch = globalThis.fetch;
    const network = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            data: [{ id: "1900000000000000001", text: "OFFLINE CLOSE RACE" }],
            meta: {
              newest_id: "1900000000000000001",
              oldest_id: "1900000000000000001",
              result_count: 1,
            },
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
    );
    vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
      const input = args[0];
      const url = input instanceof Request ? input.url : String(input);
      if (new URL(url).hostname === "api.x.com") return network();
      return nativeFetch(...args);
    });
    const running = await startXCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: credentialHost(),
      databasePath: runtimePath,
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
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
    const runPromise = fetch(`${running.origin}/api/read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: X_READ_CANARY_PLAN_ID,
        expectedRuntimeRevision: research.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
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
    const projection = readXReadCanaryProjection(canaryStore, "unknown");
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

  it("keeps shutdown and the profile lock pending until an active credential projection settles", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-status-close-"));
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
    const delayedCredentialHost = createDarwinXReadCanaryKeychainForTesting({
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
      platform: "darwin",
    });
    const running = await startXCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: delayedCredentialHost,
      databasePath: runtimePath,
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
    });
    operator = running;
    const statusAbort = new AbortController();
    const observedStatus = fetch(`${running.origin}/api/read-canary`, {
      signal: statusAbort.signal,
    }).catch(() => undefined);
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
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-admitted-body-close-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    const network = vi.fn();
    vi.stubGlobal("fetch", network);
    const running = await startXCanaryOperatorForTesting({
      claimHost: claimHost(claimRequests),
      credentialHost: credentialHost(credentialRequests),
      databasePath: runtimePath,
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
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
    const body = JSON.stringify({
      schemaVersion: 1,
      planId: X_READ_CANARY_PLAN_ID,
      expectedRuntimeRevision: research.revision,
      requestId: randomUUID(),
      typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
      oneRequestAcknowledgement: true,
      maximumChargeUsdMicrosAcknowledgement: "50000",
    });
    const port = Number(new URL(running.origin).port);
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.on("error", () => undefined);
    await once(socket, "connect");
    socket.write(
      [
        "POST /api/read-canary/run HTTP/1.1",
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

  it("bounds a half-open local control request while preserving final STOP", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-half-open-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const running = await startXCanaryOperatorForTesting({
      claimHost: claimHost(),
      credentialHost: credentialHost(),
      databasePath: runtimePath,
      port: 0,
      researchDatabasePath: join(directory, "research.sqlite"),
    });
    operator = running;
    const stopped = running.runtime.getSnapshot();
    running.runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const port = Number(new URL(running.origin).port);
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.on("error", () => undefined);
    await once(socket, "connect");
    socket.write(
      [
        "POST /api/control HTTP/1.1",
        `Host: 127.0.0.1:${port}`,
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
    expect(performance.now() - started).toBeLessThan(1_000);
    operator = undefined;
    socket.destroy();

    const reopened = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    expect(reopened.getSnapshot().mode).toBe("STOPPED");
    expect(reopened.listAudit().at(-2)).toMatchObject({
      payload: { cause: "operator", to: "STOPPED" },
      type: "runtime.stop.enforced.v1",
    });
    reopened.close();
  });

  it("automatically finishes a durable result after process restart without another X request", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-recovery-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    const operationsPath = join(directory, "rsi-x-canary-operations.sqlite");
    const captureRegistryPath = join(directory, "rsi-x-canary-captures.sqlite");
    const eventStorePath = join(directory, "rsi-x-canary-events.sqlite");
    const vaultPath = join(directory, "rsi-x-canary-vault");
    const operationsKey = new Uint8Array(Buffer.from(VALUES[1], "base64url"));
    const captureRegistryKey = new Uint8Array(Buffer.from(VALUES[2], "base64url"));
    const vaultKey = new Uint8Array(Buffer.from(VALUES[3], "base64url"));
    const runtime = SqliteRuntimeController.open({
      openedAt: new Date(Date.now() - 1_000).toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    const stopped = runtime.getSnapshot();
    runtime.transition({
      expectedMode: stopped.mode,
      expectedRevision: stopped.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const operationsStore = new SqliteOperationsStore({
      path: operationsPath,
      stateKey: operationsKey,
    });
    const captureRegistry = SqliteCaptureRegistry.open({
      expectedProfile: "canary",
      path: captureRegistryPath,
      registryKey: captureRegistryKey,
    });
    const eventStore = new SqliteEventStore(eventStorePath);
    const vault = await SnapshotVault.open({
      directory: vaultPath,
      maxCaptureBytes: 1_048_576,
      wrappingKey: vaultKey,
    });
    const controller = new XReadCanaryController({
      bearerToken: TEST_TOKEN,
      captureRegistry,
      eventStore,
      operationsStore,
      runtime,
      vault,
    });
    const network = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            data: [{ id: "1900000000000000001", text: "RECOVERY RAW POST TEXT" }],
            meta: {
              newest_id: "1900000000000000001",
              oldest_id: "1900000000000000001",
              result_count: 1,
            },
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
    );
    vi.stubGlobal("fetch", network);
    const closeFault = vi.spyOn(operationsStore, "closeAttempt").mockImplementation(() => {
      throw new Error("simulated process crash before closure");
    });
    const revision = runtime.getSnapshot().revision;
    const canaryRequestId = randomUUID();

    await expect(
      controller.execute({
        schemaVersion: 1,
        planId: X_READ_CANARY_PLAN_ID,
        expectedRuntimeRevision: revision,
        requestId: canaryRequestId,
        typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
    ).rejects.toBeInstanceOf(AggregateError);
    expect(network).toHaveBeenCalledOnce();

    const resultEvent = eventStore.list({ type: "x.read-canary.result.v1" })[0]!;
    const result = resultEvent.payload as unknown as Pick<
      XReadCanaryReceiptV1,
      | "acquiredAt"
      | "attemptId"
      | "byteLength"
      | "capture"
      | "completedAt"
      | "failureCode"
      | "hasNextPage"
      | "outcome"
      | "postCount"
      | "rateLimit"
      | "requestFingerprint"
      | "requestId"
      | "runtime"
    >;
    const restoredReceipt: XReadCanaryReceiptV1 = {
      schemaVersion: 1,
      receiptId: `x-read-canary:${result.requestId}`,
      planId: X_READ_CANARY_PLAN_ID,
      providerId: X_READ_CANARY_PROVIDER_ID,
      requestId: result.requestId,
      attemptId: result.attemptId,
      requestFingerprint: result.requestFingerprint,
      outcome: result.outcome,
      failureCode: result.failureCode,
      acquiredAt: result.acquiredAt,
      completedAt: result.completedAt,
      postCount: result.postCount,
      byteLength: result.byteLength,
      hasNextPage: result.hasNextPage,
      rateLimit: result.rateLimit,
      maximumRequests: 1,
      maximumResults: 10,
      maximumChargeUsdMicros: "50000",
      actualChargeUsdMicros: null,
      runtime: result.runtime,
      capture: result.capture,
    };
    eventStore.append({
      aggregateId: "read-canary:x",
      idempotencyKey: `x-read-canary-receipt-v1:${result.requestId}`,
      occurredAt: result.completedAt,
      payload: restoredReceipt,
      type: "x.read-canary.receipt.v1",
    });
    expect(readXReadCanaryProjection(eventStore, "unknown").status).toBe("completed");
    expect(captureRegistry.listCommittedCaptures()).toHaveLength(1);

    closeFault.mockRestore();
    controller.close();
    runtime.close();
    operationsStore.close();
    captureRegistry.close();
    eventStore.close();
    await vault.close();

    network.mockClear();
    const missingMarkerRequests: OneShotClaimCommandRequest[] = [];
    const missingMarkerCredentials: CredentialCommandRequest[] = [];
    await expect(
      startXCanaryOperatorForTesting({
        claimHost: claimHost(missingMarkerRequests, 44),
        credentialHost: credentialHost(missingMarkerCredentials),
        databasePath: runtimePath,
        port: 0,
        researchDatabasePath: researchPath,
      }),
    ).rejects.toThrow("completed X canary requires its permanent one-shot marker");
    expect(missingMarkerRequests).toHaveLength(1);
    expect(missingMarkerRequests[0]!.args[0]).toBe("find-generic-password");
    expect(missingMarkerRequests[0]!.args).not.toContain("-w");
    expect(
      missingMarkerCredentials.filter(
        (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
      ),
    ).toEqual([]);
    expect(network).not.toHaveBeenCalled();

    const credentialRequests: CredentialCommandRequest[] = [];
    const claimRequests: OneShotClaimCommandRequest[] = [];
    operator = await startXCanaryOperatorForTesting({
      claimHost: claimHost(claimRequests, 0, 0),
      credentialHost: credentialHost(credentialRequests),
      databasePath: runtimePath,
      port: 0,
      researchDatabasePath: researchPath,
    });
    expect(network).not.toHaveBeenCalled();
    expect(claimRequests).toHaveLength(1);
    expect(claimRequests[0]!.args[0]).toBe("find-generic-password");
    expect(claimRequests[0]!.args).not.toContain("-w");
    expect(
      credentialRequests
        .filter((request) => request.args.at(-1) === "-w")
        .map((request) => request.args[4]),
    ).toEqual(SERVICES.slice(1));

    const reconciledRegistry = SqliteCaptureRegistry.open({
      expectedProfile: "canary",
      path: captureRegistryPath,
      registryKey: new Uint8Array(Buffer.from(VALUES[2], "base64url")),
    });
    expect(reconciledRegistry.listCommittedCaptures()).toEqual([]);
    reconciledRegistry.close();

    const reconciledOperations = new SqliteOperationsStore({
      path: operationsPath,
      stateKey: new Uint8Array(Buffer.from(VALUES[1], "base64url")),
    });
    expect(reconciledOperations.readNetworkAttemptBinding(result.attemptId)).toMatchObject({
      state: "closed",
      outcome: "succeeded",
    });
    reconciledOperations.close();

    vi.unstubAllGlobals();
    const response = await fetch(`${operator.origin}/api/read-canary`);
    const projection = await response.json();
    const secondResponse = await fetch(`${operator.origin}/api/read-canary`);
    expect(secondResponse.status).toBe(200);
    const existingReceiptResponse = await fetch(`${operator.origin}/api/read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: X_READ_CANARY_PLAN_ID,
        expectedRuntimeRevision: operator.runtime.getSnapshot().revision,
        requestId: canaryRequestId,
        typedPlanIdAcknowledgement: X_READ_CANARY_PLAN_ID,
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
      headers: controlHeaders(operator.origin),
      method: "POST",
    });

    expect(response.status).toBe(200);
    expect(existingReceiptResponse.status).toBe(409);
    expect(projection).toMatchObject({
      readCanary: {
        lastReceipt: { outcome: "accepted", postCount: 1 },
        status: "completed",
      },
    });
    expect(network).not.toHaveBeenCalled();
    expect(claimRequests).toHaveLength(1);
    expect(JSON.stringify(projection)).not.toContain("RECOVERY RAW POST TEXT");
    expect(
      credentialRequests
        .filter((request) => request.args.at(-1) === "-w")
        .map((request) => request.args[4]),
    ).toEqual(SERVICES.slice(1));
  });
});
