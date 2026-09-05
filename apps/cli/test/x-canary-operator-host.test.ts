import { randomUUID } from "node:crypto";
import { chmod, mkdtemp, readdir, rm, stat } from "node:fs/promises";
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

import { startXCanaryOperatorForTesting } from "../src/x-canary-operator-host.testing.js";
import * as productionHost from "../src/x-canary-operator-host.js";
import type { RunningXCanaryOperator } from "../src/x-canary-operator-host.js";

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
let operator: RunningXCanaryOperator | undefined;

afterEach(async () => {
  vi.unstubAllGlobals();
  await operator?.close().catch(() => undefined);
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
  exitCode: number | null = 0,
): DarwinOneShotClaimHost {
  return createDarwinOneShotClaimHostForTesting("x", {
    executor: vi.fn(async (request) => {
      requests?.push(request);
      return {
        exitCode,
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
    ).rejects.toThrow("Stage 1 data directories must be owner-only (mode 0700)");
    expect(requests).toEqual([]);
    expect(await readdir(directory)).toEqual([]);
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
      expect(claimRequests).toHaveLength(1);
      expect(
        credentialRequests.filter(
          (request) => request.args[4] === SERVICES[0] && request.args.at(-1) === "-w",
        ),
      ).toEqual([]);
      expect(network).not.toHaveBeenCalled();
    },
  );

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
      claimHost: claimHost(claimRequests),
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
    expect(existingReceiptResponse.status).toBe(200);
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
