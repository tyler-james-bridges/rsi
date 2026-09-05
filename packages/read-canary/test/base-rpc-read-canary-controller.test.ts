import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { BASE_RPC_ANCHOR_BODY } from "@rsi/base-rpc-collector";
import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import { SqliteOperationsStore } from "@rsi/operations";
import { SqliteRuntimeController, type RuntimeMode } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { SnapshotVault, isCaptureId, type CaptureId } from "@rsi/vault";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BaseRpcReadCanaryConflictError,
  BaseRpcReadCanaryController,
  getBaseRpcReadCanaryPlan,
  type BaseRpcReadCanaryRunCommand,
} from "../src/base-rpc.js";
import { recoverBaseRpcReadCanary } from "../src/base-rpc-recovery.js";

const API_KEY = "offline-alchemy-key-never-persist-0123456789";
const BLOCK_HASH = `0x${"11".repeat(32)}`;
const PARENT_HASH = `0x${"22".repeat(32)}`;
const BLOCK_NUMBER_HEX = "0x1234abcd";

interface Fixture {
  captureRegistry: SqliteCaptureRegistry;
  readonly controller: BaseRpcReadCanaryController;
  readonly directory: string;
  eventStore: SqliteEventStore;
  operationsStore: SqliteOperationsStore;
  runtime: SqliteRuntimeController;
  vault: SnapshotVault;
  readonly keys: Readonly<{
    captureRegistry: Uint8Array;
    operations: Uint8Array;
    vault: Uint8Array;
  }>;
  readonly paths: Readonly<{
    captureRegistry: string;
    eventStore: string;
    operations: string;
    runtime: string;
    vault: string;
  }>;
}

const fixtures: Fixture[] = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  for (const fixture of fixtures.splice(0)) {
    fixture.controller.close();
    fixture.runtime.close();
    fixture.operationsStore.close();
    fixture.captureRegistry.close();
    fixture.eventStore.close();
    await fixture.vault.close();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

function hexTimestamp(timestamp: string): string {
  return `0x${Math.floor(Date.parse(timestamp) / 1_000).toString(16)}`;
}

function validResponseObject(): unknown[] {
  const root = `0x${"33".repeat(32)}`;
  const finalizedAt = new Date(Date.now() - 30 * 60 * 1_000).toISOString();
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
        hash: BLOCK_HASH,
        logsBloom: `0x${"00".repeat(256)}`,
        miner: `0x${"44".repeat(20)}`,
        mixHash: root,
        nonce: "0x0000000000000000",
        number: BLOCK_NUMBER_HEX,
        parentBeaconBlockRoot: root,
        parentHash: PARENT_HASH,
        receiptsRoot: root,
        requestsHash: root,
        sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        size: "0x200",
        stateRoot: root,
        timestamp: hexTimestamp(finalizedAt),
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

function jsonResponse(
  body: ConstructorParameters<typeof Response>[0] = JSON.stringify(validResponseObject()),
): Response {
  return new Response(body, {
    headers: { "content-type": "application/json; charset=utf-8" },
    status: 200,
  });
}

async function createFixture(mode: RuntimeMode = "RESEARCH"): Promise<Fixture> {
  const directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-read-canary-"));
  const paths = Object.freeze({
    captureRegistry: join(directory, "capture-registry", "captures.sqlite"),
    eventStore: join(directory, "events.sqlite"),
    operations: join(directory, "operations.sqlite"),
    runtime: join(directory, "runtime.sqlite"),
    vault: join(directory, "vault"),
  });
  const keys = Object.freeze({
    captureRegistry: new Uint8Array(randomBytes(32)),
    operations: new Uint8Array(randomBytes(32)),
    vault: new Uint8Array(randomBytes(32)),
  });
  const runtime = SqliteRuntimeController.open({
    openedAt: new Date(Date.now() - 1_000).toISOString(),
    path: paths.runtime,
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
  if (mode === "PROPOSE_ONLY") {
    const research = runtime.getSnapshot();
    runtime.transition({
      expectedMode: research.mode,
      expectedRevision: research.revision,
      occurredAt: new Date().toISOString(),
      requestId: randomUUID(),
      targetMode: "PROPOSE_ONLY",
    });
  }
  if (mode === "STOPPED") {
    runtime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
  }
  const operationsStore = new SqliteOperationsStore({
    path: paths.operations,
    stateKey: keys.operations,
  });
  const captureRegistry = SqliteCaptureRegistry.open({
    expectedProfile: "canary",
    path: paths.captureRegistry,
    registryKey: keys.captureRegistry,
  });
  const eventStore = new SqliteEventStore(paths.eventStore);
  const vault = await SnapshotVault.open({
    directory: paths.vault,
    maxCaptureBytes: 2 * 1_024 * 1_024,
    wrappingKey: keys.vault,
  });
  const controller = new BaseRpcReadCanaryController({
    apiKey: API_KEY,
    captureRegistry,
    eventStore,
    operationsStore,
    runtime,
    vault,
  });
  const fixture: Fixture = {
    captureRegistry,
    controller,
    directory,
    eventStore,
    keys,
    operationsStore,
    paths,
    runtime,
    vault,
  };
  fixtures.push(fixture);
  return fixture;
}

async function reopenForRecovery(fixture: Fixture): Promise<void> {
  fixture.controller.close();
  fixture.runtime.close();
  fixture.operationsStore.close();
  fixture.captureRegistry.close();
  fixture.eventStore.close();
  await fixture.vault.close();
  fixture.runtime = SqliteRuntimeController.open({
    openedAt: new Date().toISOString(),
    path: fixture.paths.runtime,
    processInstanceId: randomUUID(),
  });
  fixture.operationsStore = new SqliteOperationsStore({
    path: fixture.paths.operations,
    stateKey: fixture.keys.operations,
  });
  fixture.captureRegistry = SqliteCaptureRegistry.open({
    expectedProfile: "canary",
    path: fixture.paths.captureRegistry,
    registryKey: fixture.keys.captureRegistry,
  });
  fixture.eventStore = new SqliteEventStore(fixture.paths.eventStore);
  fixture.vault = await SnapshotVault.open({
    directory: fixture.paths.vault,
    maxCaptureBytes: 2 * 1_024 * 1_024,
    wrappingKey: fixture.keys.vault,
  });
}

function command(fixture: Fixture, requestId = randomUUID()): BaseRpcReadCanaryRunCommand {
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    expectedRuntimeRevision: fixture.runtime.getSnapshot().revision,
    requestId,
    typedPlanIdAcknowledgement: BASE_RPC_READ_CANARY_PLAN_ID,
    oneRequestAcknowledgement: true,
    nonPaymentReadAcknowledgement: true,
    noTransactionAuthorityAcknowledgement: true,
    finalizedAnchorAcknowledgement: true,
    methodSetAcknowledgement: BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
    ledgerReserveUsdMicrosAcknowledgement: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  };
}

function preparedAttemptId(fixture: Fixture): string {
  const event = fixture.eventStore.list({ type: "base-rpc.read-canary.prepared.v1" })[0];
  if (event === undefined) throw new Error("prepared event is unavailable");
  return (event.payload as { attemptId: string }).attemptId;
}

function recoveryOptions(fixture: Fixture) {
  return {
    captureRegistry: fixture.captureRegistry,
    eventStore: fixture.eventStore,
    operationsStore: fixture.operationsStore,
    runtime: fixture.runtime,
    vault: fixture.vault,
  };
}

describe("BaseRpcReadCanaryController", () => {
  it("publishes the exact fixed, non-payment and transactionless plan", () => {
    expect(getBaseRpcReadCanaryPlan()).toEqual({
      actualChargeUsdMicros: null,
      automaticFallback: false,
      automaticRetries: 0,
      blockTag: "finalized",
      chain: "base-mainnet",
      ledgerReserveUsdMicros: "1",
      maximumAnchors: 1,
      maximumRequests: 1,
      method: "POST",
      paymentAuthority: "none",
      planId: BASE_RPC_READ_CANARY_PLAN_ID,
      profile: "canary",
      rawContentDisposition: "encrypted_ephemeral",
      requestFingerprint: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
      schemaVersion: 1,
      transactionAuthority: "none",
    });
  });

  it("dispatches exactly once, deletes before receipt, and returns only sanitized facts", async () => {
    const fixture = await createFixture();
    const network = vi.fn(async (request: Request) => {
      expect(request.url).toBe("https://base-mainnet.g.alchemy.com/v2");
      expect(request.method).toBe("POST");
      expect(request.credentials).toBe("omit");
      expect(request.redirect).toBe("error");
      expect(request.headers.get("authorization")).toBe(`Bearer ${API_KEY}`);
      expect(request.headers.get("accept-encoding")).toBe("identity");
      expect(request.headers.get("content-type")).toBe("application/json");
      expect(await request.text()).toBe(BASE_RPC_ANCHOR_BODY);
      return jsonResponse();
    });
    vi.stubGlobal("fetch", network);
    const append = fixture.eventStore.append.bind(fixture.eventStore);
    let captureId: CaptureId | undefined;
    let attemptId: string | undefined;
    vi.spyOn(fixture.eventStore, "append").mockImplementation((input) => {
      if (input.type === "source.capture.recorded.v2") {
        const reference = fixture.captureRegistry.listCommittedCaptures()[0];
        const attempt =
          reference === undefined
            ? undefined
            : fixture.captureRegistry.getAttempt(reference.attemptId);
        if (attempt?.state !== "committed" || !isCaptureId(attempt.captureId)) {
          throw new Error("capture is not committed");
        }
        captureId = attempt.captureId;
        attemptId = attempt.attemptId;
      }
      if (input.type === "base-rpc.read-canary.receipt.v1") {
        expect(attemptId).toBeDefined();
        expect(fixture.captureRegistry.getAttempt(attemptId!)).toMatchObject({
          keyDestroyed: true,
          removalReason: "capture_deleted_explicit",
          state: "removed",
        });
      }
      return append(input);
    });
    const run = command(fixture);

    const receipt = await fixture.controller.execute(run);

    expect(network).toHaveBeenCalledOnce();
    expect(receipt).toMatchObject({
      actualChargeUsdMicros: null,
      failureCode: null,
      freshnessVerdict: "fresh",
      ledgerReserveUsdMicros: "1",
      maximumRequests: 1,
      outcome: "accepted",
      providerReportedFinalized: true,
      rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
    });
    for (const forbiddenProperty of [
      "providerId",
      "requestId",
      "receiptId",
      "attemptId",
      "capture",
      "runtime",
      "anchorCount",
      "byteLength",
      "acquiredAt",
    ]) {
      expect(receipt).not.toHaveProperty(forbiddenProperty);
    }
    const exactCaptureId = captureId;
    if (exactCaptureId === undefined) throw new Error("capture ID was not observed");
    await expect(fixture.vault.get(exactCaptureId)).rejects.toThrow();
    const publicJson = JSON.stringify(receipt);
    const projectionJson = JSON.stringify(fixture.controller.getProjection());
    for (const secret of [
      API_KEY,
      BLOCK_HASH,
      PARENT_HASH,
      BLOCK_NUMBER_HEX,
      String(BigInt(BLOCK_NUMBER_HEX)),
      exactCaptureId,
      attemptId!,
      "rsi-base-chain-id-v1",
      "rsi-base-finalized-block-v1",
    ]) {
      expect(publicJson).not.toContain(secret);
      expect(projectionJson).not.toContain(secret);
    }
    await expect(fixture.controller.execute(run)).resolves.toEqual(receipt);
    expect(network).toHaveBeenCalledOnce();
  });

  it("rejects request customization and acknowledgement drift before claim or egress", async () => {
    const fixture = await createFixture();
    const network = vi.fn();
    vi.stubGlobal("fetch", network);
    const run = command(fixture);
    await expect(fixture.controller.execute({ ...run, blockTag: "latest" })).rejects.toThrow(
      TypeError,
    );
    await expect(
      fixture.controller.execute({ ...run, noTransactionAuthorityAcknowledgement: false }),
    ).rejects.toThrow(TypeError);
    await expect(
      fixture.controller.execute({
        ...run,
        methodSetAcknowledgement: "eth_sendRawTransaction",
      }),
    ).rejects.toThrow(TypeError);
    expect(network).not.toHaveBeenCalled();
    expect(fixture.eventStore.list()).toHaveLength(0);
  });

  it("requires RESEARCH mode and fails closed under STOP before preparation", async () => {
    for (const mode of ["PROPOSE_ONLY", "STOPPED"] as const) {
      const fixture = await createFixture(mode);
      const network = vi.fn();
      vi.stubGlobal("fetch", network);
      await expect(fixture.controller.execute(command(fixture))).rejects.toBeInstanceOf(
        BaseRpcReadCanaryConflictError,
      );
      expect(network).not.toHaveBeenCalled();
      expect(fixture.eventStore.list()).toHaveLength(0);
    }
  });

  it("lets STOP reject completion after dispatch without replay", async () => {
    const fixture = await createFixture();
    let release: ((response: Response) => void) | undefined;
    const network = vi.fn(
      async () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    vi.stubGlobal("fetch", network);
    const execution = fixture.controller.execute(command(fixture));
    await vi.waitFor(() => expect(network).toHaveBeenCalledOnce());
    fixture.runtime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
    release!(jsonResponse());

    await expect(execution).resolves.toMatchObject({
      failureCode: "RUNTIME_DENIED",
      freshnessVerdict: null,
      outcome: "rejected",
      providerReportedFinalized: null,
    });
    expect(fixture.captureRegistry.getAttempt(preparedAttemptId(fixture))).toMatchObject({
      keyDestroyed: true,
      state: "removed",
    });
    expect(network).toHaveBeenCalledOnce();
  });

  it("treats 402 as terminal with no payment or retry path", async () => {
    const fixture = await createFixture();
    const network = vi.fn(async () => new Response("payment marker", { status: 402 }));
    vi.stubGlobal("fetch", network);

    await expect(fixture.controller.execute(command(fixture))).resolves.toMatchObject({
      actualChargeUsdMicros: null,
      failureCode: "PAYMENT_REQUIRED",
      outcome: "failed",
    });
    expect(network).toHaveBeenCalledOnce();
    expect(JSON.stringify(fixture.eventStore.list())).not.toContain("payment marker");
  });

  it("encrypts malformed provider bytes before content-free rejection and deletion", async () => {
    const fixture = await createFixture();
    const marker = "UNTRUSTED_RAW_BASE_RPC_MARKER";
    const network = vi.fn(async () => jsonResponse(`{\"${marker}\":`));
    vi.stubGlobal("fetch", network);

    await expect(fixture.controller.execute(command(fixture))).resolves.toMatchObject({
      failureCode: "INVALID_RESPONSE_SCHEMA",
      freshnessVerdict: null,
      outcome: "rejected",
      providerReportedFinalized: null,
    });
    expect(fixture.captureRegistry.getAttempt(preparedAttemptId(fixture))).toMatchObject({
      keyDestroyed: true,
      state: "removed",
    });
    expect(JSON.stringify(fixture.eventStore.list())).not.toContain(marker);
  });

  it("refuses credential and collector capabilities at the recovery boundary", async () => {
    const fixture = await createFixture();
    const network = vi.fn();
    vi.stubGlobal("fetch", network);
    await expect(
      recoverBaseRpcReadCanary({ ...recoveryOptions(fixture), apiKey: API_KEY } as never),
    ).rejects.toThrow(TypeError);
    await expect(
      recoverBaseRpcReadCanary({ ...recoveryOptions(fixture), collector: {} } as never),
    ).rejects.toThrow(TypeError);
    expect(network).not.toHaveBeenCalled();
  });

  it("recovers a committed capture storage-only after a result-checkpoint crash", async () => {
    const fixture = await createFixture();
    const network = vi.fn(async () => jsonResponse());
    vi.stubGlobal("fetch", network);
    const append = fixture.eventStore.append.bind(fixture.eventStore);
    const fault = vi.spyOn(fixture.eventStore, "append").mockImplementation((input) => {
      if (input.type === "base-rpc.read-canary.result.v1") {
        throw new Error("simulated result checkpoint crash");
      }
      return append(input);
    });
    await expect(fixture.controller.execute(command(fixture))).rejects.toBeInstanceOf(
      AggregateError,
    );
    expect(network).toHaveBeenCalledOnce();
    expect(fixture.captureRegistry.listCommittedCaptures()).toHaveLength(1);

    fault.mockRestore();
    await reopenForRecovery(fixture);
    const recoveryNetwork = vi.fn(() => {
      throw new Error("recovery attempted egress");
    });
    vi.stubGlobal("fetch", recoveryNetwork);
    await expect(recoverBaseRpcReadCanary(recoveryOptions(fixture))).resolves.toMatchObject({
      failureCode: "RUNTIME_DENIED",
      outcome: "rejected",
    });
    expect(recoveryNetwork).not.toHaveBeenCalled();
    expect(fixture.captureRegistry.listCommittedCaptures()).toEqual([]);
  });

  it("recovers an authenticated accepted result after a closure crash without egress", async () => {
    const fixture = await createFixture();
    const network = vi.fn(async () => jsonResponse());
    vi.stubGlobal("fetch", network);
    const closeFault = vi.spyOn(fixture.operationsStore, "closeAttempt").mockImplementation(() => {
      throw new Error("simulated closure crash");
    });
    await expect(fixture.controller.execute(command(fixture))).rejects.toBeInstanceOf(
      AggregateError,
    );
    expect(fixture.eventStore.list({ type: "base-rpc.read-canary.result.v1" })).toHaveLength(1);
    expect(fixture.captureRegistry.listCommittedCaptures()).toHaveLength(1);

    closeFault.mockRestore();
    await reopenForRecovery(fixture);
    const recoveryNetwork = vi.fn();
    vi.stubGlobal("fetch", recoveryNetwork);
    await expect(recoverBaseRpcReadCanary(recoveryOptions(fixture))).resolves.toMatchObject({
      failureCode: null,
      freshnessVerdict: "fresh",
      outcome: "accepted",
      providerReportedFinalized: true,
    });
    expect(recoveryNetwork).not.toHaveBeenCalled();
    expect(fixture.captureRegistry.getAttempt(preparedAttemptId(fixture))).toMatchObject({
      keyDestroyed: true,
      state: "removed",
    });
  });

  it("terminalizes an ambiguous dispatched attempt after restart without retry", async () => {
    const fixture = await createFixture();
    const network = vi.fn(async () => {
      throw new Error("ambiguous transport loss");
    });
    vi.stubGlobal("fetch", network);
    const append = fixture.eventStore.append.bind(fixture.eventStore);
    const fault = vi.spyOn(fixture.eventStore, "append").mockImplementation((input) => {
      if (input.type === "base-rpc.read-canary.failure.v1") {
        throw new Error("simulated failure-checkpoint crash");
      }
      return append(input);
    });
    await expect(fixture.controller.execute(command(fixture))).rejects.toThrow(
      "simulated failure-checkpoint crash",
    );
    const attemptId = preparedAttemptId(fixture);
    expect(fixture.operationsStore.readNetworkAttemptBinding(attemptId)).toMatchObject({
      state: "dispatched",
    });
    expect(network).toHaveBeenCalledOnce();

    fault.mockRestore();
    await reopenForRecovery(fixture);
    const recoveryNetwork = vi.fn();
    vi.stubGlobal("fetch", recoveryNetwork);
    await expect(recoverBaseRpcReadCanary(recoveryOptions(fixture))).resolves.toMatchObject({
      failureCode: "INTERRUPTED",
      outcome: "failed",
    });
    expect(recoveryNetwork).not.toHaveBeenCalled();
    expect(fixture.operationsStore.readNetworkAttemptBinding(attemptId)).toMatchObject({
      outcome: "failed",
      state: "closed",
    });
  });

  it("enforces one durable singleton claim across controller instances", async () => {
    const fixture = await createFixture();
    let release: ((response: Response) => void) | undefined;
    const network = vi.fn(
      async () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    vi.stubGlobal("fetch", network);
    const second = new BaseRpcReadCanaryController({
      apiKey: API_KEY,
      captureRegistry: fixture.captureRegistry,
      eventStore: fixture.eventStore,
      operationsStore: fixture.operationsStore,
      runtime: fixture.runtime,
      vault: fixture.vault,
    });
    const firstRun = fixture.controller.execute(command(fixture));
    await vi.waitFor(() => expect(network).toHaveBeenCalledOnce());
    await expect(second.execute(command(fixture))).rejects.toBeInstanceOf(
      BaseRpcReadCanaryConflictError,
    );
    release!(jsonResponse());
    await expect(firstRun).resolves.toMatchObject({ outcome: "accepted" });
    expect(network).toHaveBeenCalledOnce();
    second.close();
  });
});
