import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Worker } from "node:worker_threads";

import { SqliteEventStore } from "@rsi/store";
import { afterEach, describe, expect, it } from "vitest";

import {
  PERMANENTLY_DENIED_RUNTIME_BOUNDARIES,
  RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS,
  RUNTIME_AGGREGATE_ID,
  RUNTIME_BOUNDARY_EVENT_TYPE,
  RUNTIME_STOP_EVENT_TYPE,
  RUNTIME_TRANSITION_EVENT_TYPE,
  RuntimeBoundaryDeniedError,
  RuntimeBoundaryReceiptSchema,
  RuntimeConflictError,
  RuntimeIntegrityError,
  RuntimeValidationError,
  SqliteRuntimeController,
  isRuntimeBoundaryAuthorization,
  isSqliteRuntimeController,
  type RuntimeBoundary,
} from "../src/index.js";

const PROCESS_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PROCESS_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PROCESS_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const timestamps = Array.from(
  { length: 30 },
  (_, index) => `2026-08-23T12:${String(index).padStart(2, "0")}:00.000Z`,
);

const uuids = Array.from(
  { length: 30 },
  (_, index) => `${String(index + 1).padStart(8, "0")}-0000-4000-8000-000000000000`,
);

const temporaryDirectories: string[] = [];
let trustedClockAt = timestamps[0]!;
let trustedMonotonicAt = 0;

const HELD_WRITE_LOCK_WORKER = String.raw`
  const { parentPort, workerData } = require("node:worker_threads");
  const { DatabaseSync } = require("node:sqlite");

  const coordination = new Int32Array(workerData.coordination);
  const database = new DatabaseSync(workerData.path);
  database.exec("PRAGMA busy_timeout = 5000");
  database.exec("BEGIN IMMEDIATE");
  Atomics.store(coordination, 0, 1);
  Atomics.notify(coordination, 0);
  parentPort.postMessage("locked");

  // A vulnerable pre-lock monotonic sample wakes us immediately. The fixed
  // implementation remains blocked on BEGIN IMMEDIATE, so time advances at
  // the bounded fallback before the lock is released.
  Atomics.wait(coordination, 2, 0, 750);
  Atomics.store(coordination, 1, workerData.releaseClock);
  Atomics.store(coordination, 0, 0);
  database.exec("COMMIT");
  database.close();
`;

const COMPETING_STOP_WORKER = String.raw`
  import { parentPort, workerData } from "node:worker_threads";

  const coordination = new Int32Array(workerData.coordination);
  void import(workerData.runtimeModuleUrl)
    .then(({ SqliteRuntimeController }) => {
      const runtime = SqliteRuntimeController.open(
        {
          path: workerData.path,
          openedAt: workerData.openedAt,
          processInstanceId: workerData.processInstanceId,
        },
        {
          clock: () => workerData.stoppedAt,
          monotonicClock: () => 1_000,
        },
      );
      parentPort.postMessage({ type: "ready" });
      Atomics.wait(coordination, 0, 0);
      Atomics.store(coordination, 1, 1);
      Atomics.notify(coordination, 1);
      const snapshot = runtime.stop({
        occurredAt: workerData.stoppedAt,
        requestId: workerData.requestId,
      });
      const dispatchWasInvoked = Atomics.load(coordination, 2) === 1;
      runtime.close();
      parentPort.postMessage({ dispatchWasInvoked, snapshot, type: "stopped" });
    })
    .catch((error) => {
      parentPort.postMessage({
        message: error instanceof Error ? error.message : String(error),
        type: "error",
      });
    });
`;

function holdRuntimeWriteLock(
  path: string,
  coordination: Int32Array,
  releaseClock: number,
): Readonly<{ locked: Promise<void>; finished: Promise<void> }> {
  const worker = new Worker(HELD_WRITE_LOCK_WORKER, {
    eval: true,
    workerData: { coordination: coordination.buffer, path, releaseClock },
  });
  const locked = new Promise<void>((resolve, reject) => {
    worker.once("message", (message: unknown) => {
      if (message === "locked") resolve();
      else reject(new Error("Lock worker returned an unexpected message"));
    });
    worker.once("error", reject);
  });
  const finished = new Promise<void>((resolve, reject) => {
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Lock worker exited with code ${code}`));
    });
  });
  // Keep an error observed even if acquiring the lock itself fails first.
  void finished.catch(() => undefined);
  return Object.freeze({ locked, finished });
}

function databasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "rsi-runtime-"));
  temporaryDirectories.push(directory);
  return join(directory, "runtime.sqlite");
}

function open(path = databasePath(), openedAt = timestamps[0]!, processInstanceId = PROCESS_A) {
  trustedClockAt = openedAt;
  trustedMonotonicAt = 0;
  return SqliteRuntimeController.open(
    { path, openedAt, processInstanceId },
    {
      clock: () => trustedClockAt,
      monotonicClock: () => trustedMonotonicAt,
    },
  );
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("SqliteRuntimeController", () => {
  it("starts in a content-free STOPPED state with every authority disabled", () => {
    const runtime = open();

    expect(isSqliteRuntimeController(runtime)).toBe(true);
    expect(Object.isFrozen(runtime)).toBe(true);
    expect(Object.isFrozen(SqliteRuntimeController)).toBe(true);
    expect(Object.isFrozen(SqliteRuntimeController.prototype)).toBe(true);
    let prototypeTrapWasInvoked = false;
    const proxiedRuntime = new Proxy(runtime, {
      getPrototypeOf: () => {
        prototypeTrapWasInvoked = true;
        throw new Error("prototype trap must not run");
      },
    });
    expect(isSqliteRuntimeController(proxiedRuntime)).toBe(false);
    expect(prototypeTrapWasInvoked).toBe(false);
    expect(() => Object.assign(runtime, { processInstanceId: PROCESS_B })).toThrow(TypeError);
    expect(isSqliteRuntimeController(Object.create(SqliteRuntimeController.prototype))).toBe(false);
    expect(runtime.getSnapshot()).toEqual({
      schemaVersion: 1,
      auditHead: { hash: expect.stringMatching(/^[0-9a-f]{64}$/), sequence: 1 },
      capabilities: {
        executionAdapter: false,
        externalPublish: false,
        paidRead: false,
        policyApproval: false,
        proposalPersistence: false,
        researchCollection: false,
        transactionBroadcast: false,
        walletSign: false,
      },
      mode: "STOPPED",
      modeChangedAt: timestamps[0],
      processInstanceId: PROCESS_A,
      revision: 1,
    });
    expect(runtime.listAudit()).toHaveLength(1);
    expect(runtime.listAudit()[0]).toMatchObject({
      aggregateId: RUNTIME_AGGREGATE_ID,
      type: RUNTIME_STOP_EVENT_TYPE,
    });
    expect(JSON.stringify(runtime.listAudit())).not.toMatch(
      /postText|calldata|privateKey|bearerToken|seedPhrase/,
    );
    runtime.close();
  });

  it("allows only stepwise escalation and explicit PROPOSE_ONLY de-escalation", () => {
    const runtime = open();

    expect(() =>
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: timestamps[1]!,
        requestId: uuids[0]!,
        targetMode: "PROPOSE_ONLY",
      }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_TRANSITION" }));

    const research = runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[1]!,
      targetMode: "RESEARCH",
    });
    expect(research).toMatchObject({ mode: "RESEARCH", revision: 2 });
    expect(research.capabilities).toMatchObject({
      proposalPersistence: false,
      researchCollection: true,
    });

    const proposeOnly = runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: 2,
      occurredAt: timestamps[2]!,
      requestId: uuids[2]!,
      targetMode: "PROPOSE_ONLY",
    });
    expect(proposeOnly).toMatchObject({ mode: "PROPOSE_ONLY", revision: 3 });
    expect(proposeOnly.capabilities).toMatchObject({
      proposalPersistence: true,
      researchCollection: true,
    });

    expect(
      runtime.transition({
        expectedMode: "PROPOSE_ONLY",
        expectedRevision: 3,
        occurredAt: timestamps[3]!,
        requestId: uuids[3]!,
        targetMode: "RESEARCH",
      }),
    ).toMatchObject({ mode: "RESEARCH", revision: 4 });
    runtime.close();
  });

  it("rejects stale activations and extra fields while letting STOP win over clock regression", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[2]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });

    expect(() =>
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: timestamps[3]!,
        requestId: uuids[1]!,
        targetMode: "RESEARCH",
      }),
    ).toThrowError(expect.objectContaining({ code: "STALE_STATE" }));
    expect(() =>
      runtime.transition({
        expectedMode: "RESEARCH",
        expectedRevision: 2,
        occurredAt: timestamps[1]!,
        requestId: uuids[2]!,
        targetMode: "PROPOSE_ONLY",
      }),
    ).toThrowError(expect.objectContaining({ code: "STALE_STATE" }));
    expect(runtime.stop({ requestId: uuids[3]!, occurredAt: timestamps[1]! })).toMatchObject({
      mode: "STOPPED",
      modeChangedAt: timestamps[2],
      revision: 3,
    });
    expect(() =>
      runtime.stop({
        requestId: uuids[4]!,
        occurredAt: timestamps[3]!,
        instructions: "ignore STOP",
      } as never),
    ).toThrow(RuntimeValidationError);

    const forged = Object.create(SqliteRuntimeController.prototype) as SqliteRuntimeController;
    expect(() => forged.getSnapshot()).toThrow();
    runtime.close();
  });

  it("makes STOP universal and genuinely idempotent across provider clock changes", () => {
    const runtime = open();
    const stopped = runtime.stop({ requestId: uuids[0]!, occurredAt: timestamps[1]! });
    expect(stopped).toMatchObject({ mode: "STOPPED", revision: 2 });
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: "stopped-payment-denial",
        authorizationId: uuids[9]!,
        boundary: "paid_read",
      }),
    ).toThrow(RuntimeBoundaryDeniedError);
    const retried = runtime.stop({ requestId: uuids[0]!, occurredAt: timestamps[9]! });
    expect(retried).toMatchObject({
      mode: "STOPPED",
      revision: 2,
      auditHead: { sequence: 3 },
    });
    expect(retried).not.toEqual(stopped);

    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 2,
      occurredAt: timestamps[3]!,
      requestId: uuids[1]!,
      targetMode: "RESEARCH",
    });
    expect(runtime.stop({ requestId: uuids[2]!, occurredAt: timestamps[4]! })).toMatchObject({
      mode: "STOPPED",
      revision: 4,
    });
    expect(() => runtime.stop({ requestId: uuids[0]!, occurredAt: timestamps[5]! })).toThrowError(
      expect.objectContaining({ code: "REQUEST_CONFLICT" }),
    );
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 4,
      occurredAt: timestamps[5]!,
      requestId: uuids[3]!,
      targetMode: "RESEARCH",
    });
    runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: 5,
      occurredAt: timestamps[6]!,
      requestId: uuids[4]!,
      targetMode: "PROPOSE_ONLY",
    });
    expect(runtime.stop({ requestId: uuids[5]!, occurredAt: timestamps[7]! })).toMatchObject({
      mode: "STOPPED",
      revision: 7,
    });
    runtime.close();
  });

  it("returns current state for a current transition retry and conflicts after state advances", () => {
    const runtime = open();
    const input = {
      expectedMode: "STOPPED" as const,
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH" as const,
    };
    const first = runtime.transition(input);
    expect(runtime.transition({ ...input, occurredAt: timestamps[2]! })).toEqual(first);
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: "research-signing-denial",
        authorizationId: uuids[9]!,
        boundary: "wallet_sign",
      }),
    ).toThrow(RuntimeBoundaryDeniedError);
    const currentRetry = runtime.transition({ ...input, occurredAt: timestamps[3]! });
    expect(currentRetry).toMatchObject({
      mode: "RESEARCH",
      revision: 2,
      auditHead: { sequence: 3 },
    });
    expect(currentRetry).not.toEqual(first);
    expect(() => runtime.transition({ ...input, targetMode: "PROPOSE_ONLY" })).toThrowError(
      expect.objectContaining({ code: "REQUEST_CONFLICT" }),
    );

    runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: 2,
      occurredAt: timestamps[4]!,
      requestId: uuids[1]!,
      targetMode: "PROPOSE_ONLY",
    });
    expect(() => runtime.transition({ ...input, occurredAt: timestamps[5]! })).toThrowError(
      expect.objectContaining({ code: "REQUEST_CONFLICT" }),
    );
    runtime.close();
  });

  it("rejects request ID reuse across startup, transition, and STOP without poisoning the store", () => {
    const runtime = open();
    expect(() =>
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: timestamps[1]!,
        requestId: PROCESS_A,
        targetMode: "RESEARCH",
      }),
    ).toThrowError(expect.objectContaining({ code: "REQUEST_CONFLICT" }));
    expect(runtime.listAudit()).toHaveLength(1);

    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[2]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    expect(() => runtime.stop({ requestId: uuids[0]!, occurredAt: timestamps[3]! })).toThrowError(
      expect.objectContaining({ code: "REQUEST_CONFLICT" }),
    );
    expect(runtime.listAudit()).toHaveLength(2);

    runtime.stop({ requestId: uuids[1]!, occurredAt: timestamps[4]! });
    expect(() =>
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 3,
        occurredAt: timestamps[5]!,
        requestId: uuids[1]!,
        targetMode: "RESEARCH",
      }),
    ).toThrowError(expect.objectContaining({ code: "REQUEST_CONFLICT" }));
    expect(runtime.listAudit()).toHaveLength(3);
    runtime.close();
  });

  it("never resumes an active mode after another process opens", () => {
    const path = databasePath();
    const first = open(path);
    first.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });

    const restarted = open(path, timestamps[2]!, PROCESS_B);
    expect(restarted.getSnapshot()).toMatchObject({
      mode: "STOPPED",
      processInstanceId: PROCESS_B,
      revision: 3,
    });
    expect(() =>
      first.transition({
        expectedMode: "RESEARCH",
        expectedRevision: 2,
        occurredAt: timestamps[3]!,
        requestId: uuids[1]!,
        targetMode: "PROPOSE_ONLY",
      }),
    ).toThrowError(expect.objectContaining({ code: "PROCESS_SUPERSEDED" }));

    first.close();
    restarted.close();
  });

  it("enforces startup STOP even when the provider clock moved backward", () => {
    const path = databasePath();
    const first = open(path);
    first.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[3]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });

    const restarted = open(path, timestamps[1]!, PROCESS_B);
    expect(restarted.getSnapshot()).toMatchObject({
      mode: "STOPPED",
      modeChangedAt: timestamps[3],
      processInstanceId: PROCESS_B,
      revision: 3,
    });
    first.close();
    restarted.close();
  });

  it("issues authentic one-shot collection and proposal authorizations only in allowed modes", () => {
    const runtime = open();
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: "collection-before-research",
        authorizationId: uuids[0]!,
        boundary: "research_collection",
      }),
    ).toThrowError(
      expect.objectContaining({ receipt: expect.objectContaining({ reason: "MODE_NOT_ALLOWED" }) }),
    );

    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[2]!,
      requestId: uuids[1]!,
      targetMode: "RESEARCH",
    });
    const collection = runtime.requestBoundaryAuthorization({
      actionId: "x-attempt-1",
      authorizationId: uuids[2]!,
      boundary: "research_collection",
    });
    expect(isRuntimeBoundaryAuthorization(collection)).toBe(true);
    expect(isRuntimeBoundaryAuthorization({ ...collection })).toBe(false);
    let authorizationPrototypeTrapWasInvoked = false;
    const proxiedAuthorization = new Proxy(collection, {
      getPrototypeOf: () => {
        authorizationPrototypeTrapWasInvoked = true;
        throw new Error("prototype trap must not run");
      },
    });
    expect(isRuntimeBoundaryAuthorization(proxiedAuthorization)).toBe(false);
    expect(authorizationPrototypeTrapWasInvoked).toBe(false);
    expect(Object.getPrototypeOf(collection)).toBeNull();
    expect(Object.hasOwn(collection, "consume")).toBe(false);
    expect(Object.hasOwn(collection, "consumeAndDispatch")).toBe(true);
    expect(Object.hasOwn(collection, "guardCompletion")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(collection, "consumeAndDispatch")).toMatchObject({
      configurable: false,
      writable: false,
    });
    expect(Object.getOwnPropertyDescriptor(collection, "guardCompletion")).toMatchObject({
      configurable: false,
      writable: false,
    });

    let constructorMint: unknown;
    const reachableConstructor = Reflect.get(collection, "constructor") as unknown;
    expect(reachableConstructor).toBeUndefined();
    if (typeof reachableConstructor === "function") {
      try {
        constructorMint = Reflect.construct(reachableConstructor, [
          {
            actionId: "forged-action",
            authorizationId: uuids[29]!,
            boundary: "proposal_persist",
            processInstanceId: PROCESS_A,
            requestedAt: timestamps[3]!,
            requestedMode: "PROPOSE_ONLY",
            requestedRevision: 999,
            consume: () => ({ decision: "allowed" }),
          },
        ]);
      } catch {
        constructorMint = undefined;
      }
    }
    expect(isRuntimeBoundaryAuthorization(constructorMint)).toBe(false);
    expect(
      RuntimeBoundaryReceiptSchema.safeParse({
        actionId: "x-attempt-1",
        boundary: "research_collection",
        decision: "allowed",
        mode: "RESEARCH",
        reason: "ALLOWED",
      }).success,
    ).toBe(false);
    const invalidArgumentsAuthorization = runtime.requestBoundaryAuthorization({
      actionId: "x-attempt-invalid-arguments",
      authorizationId: uuids[10]!,
      boundary: "research_collection",
    });
    expect(() =>
      (invalidArgumentsAuthorization.consumeAndDispatch as (...arguments_: unknown[]) => unknown)({
        consumedAt: "2099-01-01T00:00:00.000Z",
      }),
    ).toThrow(RuntimeValidationError);
    expect(() => invalidArgumentsAuthorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );
    expect(
      runtime
        .listAudit()
        .some(({ payload }) =>
          JSON.stringify(payload).includes(invalidArgumentsAuthorization.authorizationId),
        ),
    ).toBe(false);

    const asyncDispatchAuthorization = runtime.requestBoundaryAuthorization({
      actionId: "x-attempt-async-dispatch",
      authorizationId: uuids[11]!,
      boundary: "research_collection",
    });
    expect(() => asyncDispatchAuthorization.consumeAndDispatch(async () => undefined)).toThrow(
      RuntimeValidationError,
    );
    expect(() => asyncDispatchAuthorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );

    const boundAsyncDispatchAuthorization = runtime.requestBoundaryAuthorization({
      actionId: "x-attempt-bound-async-dispatch",
      authorizationId: uuids[14]!,
      boundary: "research_collection",
    });
    const boundAsyncDispatch = (async () => undefined).bind(null);
    expect(() => boundAsyncDispatchAuthorization.consumeAndDispatch(boundAsyncDispatch)).toThrow(
      RuntimeValidationError,
    );
    expect(() => boundAsyncDispatchAuthorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );

    const proxiedDispatchAuthorization = runtime.requestBoundaryAuthorization({
      actionId: "x-attempt-proxied-dispatch",
      authorizationId: uuids[12]!,
      boundary: "research_collection",
    });
    const proxiedDispatch = new Proxy(() => undefined, {});
    expect(() => proxiedDispatchAuthorization.consumeAndDispatch(proxiedDispatch)).toThrow(
      RuntimeValidationError,
    );
    expect(() => proxiedDispatchAuthorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );

    const throwingDispatchAuthorization = runtime.requestBoundaryAuthorization({
      actionId: "x-attempt-throwing-dispatch",
      authorizationId: uuids[13]!,
      boundary: "research_collection",
    });
    const auditBeforeThrowingDispatch = runtime.listAudit();
    expect(() =>
      throwingDispatchAuthorization.consumeAndDispatch(() => {
        throw new Error("synthetic dispatch refusal");
      }),
    ).toThrowError("synthetic dispatch refusal");
    expect(runtime.listAudit()).toEqual(auditBeforeThrowingDispatch);
    expect(() => throwingDispatchAuthorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );

    let dispatchedReceipt: unknown;
    expect(
      collection.consumeAndDispatch((receipt) => {
        dispatchedReceipt = receipt;
      }),
    ).toMatchObject({
      boundary: "research_collection",
      decision: "allowed",
      reason: "ALLOWED",
    });
    expect(dispatchedReceipt).toMatchObject({
      boundary: "research_collection",
      decision: "allowed",
    });
    expect(() => collection.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );
    let guardedFacts: unknown;
    expect(
      collection.guardCompletion((facts) => {
        guardedFacts = facts;
      }),
    ).toMatchObject({
      actionId: collection.actionId,
      authorizationId: collection.authorizationId,
      boundary: "research_collection",
      decision: "allowed",
      mode: "RESEARCH",
      modeRevision: 2,
      processInstanceId: PROCESS_A,
      reason: "ALLOWED",
      schemaVersion: 1,
    });
    expect(guardedFacts).toMatchObject({ decision: "allowed", reason: "ALLOWED" });
    expect(Object.isFrozen(guardedFacts)).toBe(true);
    expect(() => collection.guardCompletion(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );

    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: "proposal-too-early",
        authorizationId: uuids[3]!,
        boundary: "proposal_persist",
      }),
    ).toThrow(RuntimeBoundaryDeniedError);
    runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: 2,
      occurredAt: timestamps[6]!,
      requestId: uuids[4]!,
      targetMode: "PROPOSE_ONLY",
    });
    const proposalAuthorization = runtime.requestBoundaryAuthorization({
      actionId: "rsi-proposal:fixture-001",
      authorizationId: uuids[5]!,
      boundary: "proposal_persist",
    });
    expect(Object.hasOwn(proposalAuthorization, "consume")).toBe(true);
    expect(Object.hasOwn(proposalAuthorization, "consumeAndDispatch")).toBe(false);
    expect(Object.hasOwn(proposalAuthorization, "guardCompletion")).toBe(false);
    expect(proposalAuthorization.consume()).toMatchObject({
      decision: "allowed",
      boundary: "proposal_persist",
    });
    runtime.close();
  });

  it("makes completion guarding terminal, synchronous, and unavailable before dispatch", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });

    const premature = runtime.requestBoundaryAuthorization({
      actionId: "x-completion-before-dispatch",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    expect(() => premature.guardCompletion(() => undefined)).toThrowError(
      expect.objectContaining({ code: "STALE_STATE" }),
    );
    premature.consumeAndDispatch(() => undefined);
    expect(() => premature.guardCompletion(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );

    const invalid = [
      async () => undefined,
      (async () => undefined).bind(null),
      function* completionGenerator() {
        yield undefined;
      },
      new Proxy(() => undefined, {}),
    ];
    invalid.forEach((completion, index) => {
      const authorization = runtime.requestBoundaryAuthorization({
        actionId: `x-invalid-completion-${index}`,
        authorizationId: uuids[index + 2]!,
        boundary: "research_collection",
      });
      authorization.consumeAndDispatch(() => undefined);
      expect(() => authorization.guardCompletion(completion)).toThrow(RuntimeValidationError);
      expect(() => authorization.guardCompletion(() => undefined)).toThrowError(
        expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
      );
    });

    const throwing = runtime.requestBoundaryAuthorization({
      actionId: "x-throwing-completion",
      authorizationId: uuids[7]!,
      boundary: "research_collection",
    });
    throwing.consumeAndDispatch(() => undefined);
    expect(() =>
      throwing.guardCompletion(() => {
        throw new Error("synthetic result checkpoint failure");
      }),
    ).toThrowError("synthetic result checkpoint failure");
    expect(() => throwing.guardCompletion(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );
    runtime.close();
  });

  it("does not invoke completion after STOP has already won", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    const authorization = runtime.requestBoundaryAuthorization({
      actionId: "x-stop-before-completion",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    authorization.consumeAndDispatch(() => undefined);
    runtime.stop({ occurredAt: timestamps[3]!, requestId: uuids[2]! });

    let completionWasInvoked = false;
    expect(
      authorization.guardCompletion(() => {
        completionWasInvoked = true;
      }),
    ).toMatchObject({
      decision: "denied",
      mode: "STOPPED",
      modeRevision: 3,
      reason: "STALE_REVISION",
    });
    expect(completionWasInvoked).toBe(false);
    runtime.close();
  });

  it("refuses completion when dispatch ran but its allowed event did not commit", () => {
    const path = databasePath();
    const runtime = open(path);
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    const database = new DatabaseSync(path);
    database.exec(`
      PRAGMA foreign_keys = ON;
      CREATE TABLE completion_commit_parent (id INTEGER PRIMARY KEY);
      CREATE TABLE completion_commit_child (
        id INTEGER PRIMARY KEY,
        parent_id INTEGER NOT NULL REFERENCES completion_commit_parent(id)
          DEFERRABLE INITIALLY DEFERRED
      );
      CREATE TRIGGER fail_runtime_boundary_commit
      AFTER INSERT ON rsi_events
      WHEN NEW.event_type = 'runtime.boundary.checked.v1'
      BEGIN
        INSERT INTO completion_commit_child (id, parent_id) VALUES (NEW.sequence, 999);
      END;
    `);
    database.close();

    const authorization = runtime.requestBoundaryAuthorization({
      actionId: "x-dispatched-uncommitted",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    let dispatchWasInvoked = false;
    expect(() =>
      authorization.consumeAndDispatch(() => {
        dispatchWasInvoked = true;
      }),
    ).toThrow();
    expect(dispatchWasInvoked).toBe(true);
    expect(runtime.listAudit()).toHaveLength(2);

    const cleanup = new DatabaseSync(path);
    cleanup.exec(`
      DROP TRIGGER fail_runtime_boundary_commit;
      DROP TABLE completion_commit_child;
      DROP TABLE completion_commit_parent;
    `);
    cleanup.close();
    let completionWasInvoked = false;
    expect(() =>
      authorization.guardCompletion(() => {
        completionWasInvoked = true;
      }),
    ).toThrow(RuntimeIntegrityError);
    expect(completionWasInvoked).toBe(false);
    runtime.close();
  });

  it("holds the cross-process write lock from revalidation through synchronous dispatch", async () => {
    const path = databasePath();
    const coordination = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 3));
    const worker = new Worker(
      new URL(`data:text/javascript,${encodeURIComponent(COMPETING_STOP_WORKER)}`),
      {
        execArgv: ["--import", "tsx"],
        workerData: {
          coordination: coordination.buffer,
          openedAt: timestamps[0]!,
          path,
          processInstanceId: PROCESS_B,
          requestId: uuids[4]!,
          runtimeModuleUrl: new URL("../src/index.ts", import.meta.url).href,
          stoppedAt: timestamps[4]!,
        },
      },
    );
    let resolveReady!: () => void;
    let rejectReady!: (error: Error) => void;
    const ready = new Promise<void>((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    let resolveStopped!: (value: {
      dispatchWasInvoked: boolean;
      snapshot: { mode: string; revision: number };
    }) => void;
    let rejectStopped!: (error: Error) => void;
    const stopped = new Promise<{
      dispatchWasInvoked: boolean;
      snapshot: { mode: string; revision: number };
    }>((resolve, reject) => {
      resolveStopped = resolve;
      rejectStopped = reject;
    });
    void stopped.catch(() => undefined);
    worker.on("message", (message: unknown) => {
      if (typeof message !== "object" || message === null || !("type" in message)) return;
      if (message.type === "ready") resolveReady();
      else if (
        message.type === "stopped" &&
        "dispatchWasInvoked" in message &&
        "snapshot" in message
      ) {
        resolveStopped(
          message as {
            dispatchWasInvoked: boolean;
            snapshot: { mode: string; revision: number };
          },
        );
      } else if (message.type === "error" && "message" in message) {
        const error = new Error(String(message.message));
        rejectReady(error);
        rejectStopped(error);
      }
    });
    worker.on("error", (error) => {
      rejectReady(error);
      rejectStopped(error);
    });

    let runtime: SqliteRuntimeController | undefined;
    try {
      await ready;
      runtime = open(path, timestamps[1]!, PROCESS_C);
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 2,
        occurredAt: timestamps[2]!,
        requestId: uuids[0]!,
        targetMode: "RESEARCH",
      });
      const authorization = runtime.requestBoundaryAuthorization({
        actionId: "x-dispatch-stop-race",
        authorizationId: uuids[1]!,
        boundary: "research_collection",
      });

      const receipt = authorization.consumeAndDispatch((checked) => {
        Atomics.store(coordination, 0, 1);
        Atomics.notify(coordination, 0);
        expect(Atomics.wait(coordination, 1, 0, 2_000)).toBe("ok");
        expect(Atomics.load(coordination, 1)).toBe(1);
        expect(checked).toMatchObject({ decision: "allowed", mode: "RESEARCH" });
        // The competing controller announced its STOP attempt before this
        // dispatch marker. It cannot persist until this callback returns and
        // the runtime transaction releases its write lock.
        Atomics.store(coordination, 2, 1);
        Atomics.notify(coordination, 2);
      });
      expect(receipt).toMatchObject({ decision: "allowed", mode: "RESEARCH" });

      const stopResult = await stopped;
      expect(stopResult.dispatchWasInvoked).toBe(true);
      expect(stopResult.snapshot).toMatchObject({ mode: "STOPPED", revision: 4 });
      const relevantEvents = runtime
        .listAudit()
        .filter(
          (event) =>
            event.type === RUNTIME_BOUNDARY_EVENT_TYPE ||
            (event.type === RUNTIME_STOP_EVENT_TYPE && event.payload.cause === "operator"),
        );
      expect(relevantEvents.map((event) => event.type)).toEqual([
        RUNTIME_BOUNDARY_EVENT_TYPE,
        RUNTIME_STOP_EVENT_TYPE,
      ]);
      expect(runtime.getSnapshot()).toMatchObject({ mode: "STOPPED", revision: 4 });
    } finally {
      runtime?.close();
      await worker.terminate();
    }
  });

  it("holds the cross-process write lock through the completion checkpoint", async () => {
    const path = databasePath();
    const resultStore = new SqliteEventStore(join(dirname(path), "result.sqlite"));
    const coordination = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 3));
    const worker = new Worker(
      new URL(`data:text/javascript,${encodeURIComponent(COMPETING_STOP_WORKER)}`),
      {
        execArgv: ["--import", "tsx"],
        workerData: {
          coordination: coordination.buffer,
          openedAt: timestamps[0]!,
          path,
          processInstanceId: PROCESS_B,
          requestId: uuids[4]!,
          runtimeModuleUrl: new URL("../src/index.ts", import.meta.url).href,
          stoppedAt: timestamps[4]!,
        },
      },
    );
    let resolveReady!: () => void;
    let rejectReady!: (error: Error) => void;
    const ready = new Promise<void>((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    let resolveStopped!: (value: {
      dispatchWasInvoked: boolean;
      snapshot: { mode: string; revision: number };
    }) => void;
    let rejectStopped!: (error: Error) => void;
    const stopped = new Promise<{
      dispatchWasInvoked: boolean;
      snapshot: { mode: string; revision: number };
    }>((resolve, reject) => {
      resolveStopped = resolve;
      rejectStopped = reject;
    });
    void stopped.catch(() => undefined);
    worker.on("message", (message: unknown) => {
      if (typeof message !== "object" || message === null || !("type" in message)) return;
      if (message.type === "ready") resolveReady();
      else if (
        message.type === "stopped" &&
        "dispatchWasInvoked" in message &&
        "snapshot" in message
      ) {
        resolveStopped(
          message as {
            dispatchWasInvoked: boolean;
            snapshot: { mode: string; revision: number };
          },
        );
      } else if (message.type === "error" && "message" in message) {
        const error = new Error(String(message.message));
        rejectReady(error);
        rejectStopped(error);
      }
    });
    worker.on("error", (error) => {
      rejectReady(error);
      rejectStopped(error);
    });

    let runtime: SqliteRuntimeController | undefined;
    try {
      await ready;
      runtime = open(path, timestamps[1]!, PROCESS_C);
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 2,
        occurredAt: timestamps[2]!,
        requestId: uuids[0]!,
        targetMode: "RESEARCH",
      });
      const authorization = runtime.requestBoundaryAuthorization({
        actionId: "x-completion-stop-race",
        authorizationId: uuids[1]!,
        boundary: "research_collection",
      });
      authorization.consumeAndDispatch(() => undefined);

      const completion = authorization.guardCompletion((facts) => {
        Atomics.store(coordination, 0, 1);
        Atomics.notify(coordination, 0);
        expect(Atomics.wait(coordination, 1, 0, 2_000)).toBe("ok");
        expect(Atomics.load(coordination, 1)).toBe(1);
        resultStore.append({
          aggregateId: `canary:${authorization.actionId}`,
          idempotencyKey: `canary-result-v1:${authorization.authorizationId}`,
          occurredAt: facts.checkedAt,
          payload: {
            schemaVersion: 1,
            authorizationId: facts.authorizationId,
            outcome: "captured",
          },
          type: "canary.result.recorded.v1",
        });
        // The competing process has announced STOP, but cannot commit it
        // before this content-free result checkpoint completes.
        Atomics.store(coordination, 2, 1);
        Atomics.notify(coordination, 2);
      });
      expect(completion).toMatchObject({
        decision: "allowed",
        mode: "RESEARCH",
        reason: "ALLOWED",
      });
      expect(resultStore.list({ order: "asc" })).toHaveLength(1);

      const stopResult = await stopped;
      expect(stopResult.dispatchWasInvoked).toBe(true);
      expect(stopResult.snapshot).toMatchObject({ mode: "STOPPED", revision: 4 });
      expect(
        runtime
          .listAudit()
          .filter(
            (event) =>
              event.type === RUNTIME_BOUNDARY_EVENT_TYPE ||
              (event.type === RUNTIME_STOP_EVENT_TYPE && event.payload.cause === "operator"),
          )
          .map((event) => event.type),
      ).toEqual([RUNTIME_BOUNDARY_EVENT_TYPE, RUNTIME_STOP_EVENT_TYPE]);
    } finally {
      runtime?.close();
      resultStore.close();
      await worker.terminate();
    }
  });

  it("rejects caller-supplied boundary timestamps without changing the audit", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    const auditBefore = runtime.listAudit();

    for (const requestedAt of [timestamps[0]!, timestamps[29]!]) {
      expect(() =>
        runtime.requestBoundaryAuthorization({
          actionId: `caller-time-${requestedAt}`,
          authorizationId: requestedAt === timestamps[0] ? uuids[1]! : uuids[2]!,
          boundary: "research_collection",
          requestedAt,
        } as never),
      ).toThrow(RuntimeValidationError);
    }
    expect(runtime.listAudit()).toEqual(auditBefore);
    runtime.close();
  });

  it("permanently denies payment, signing, execution, broadcast, approval, and publication", () => {
    const runtime = open();
    const permanentlyDenied = [
      "policy_approval",
      "paid_read",
      "wallet_sign",
      "execution_adapter",
      "transaction_broadcast",
      "external_publish",
    ] as const satisfies readonly RuntimeBoundary[];
    expect(PERMANENTLY_DENIED_RUNTIME_BOUNDARIES).toEqual(permanentlyDenied);

    permanentlyDenied.forEach((boundary, index) => {
      expect(() =>
        runtime.requestBoundaryAuthorization({
          actionId: `forbidden-${index}`,
          authorizationId: uuids[index]!,
          boundary,
        }),
      ).toThrowError(
        expect.objectContaining({
          receipt: expect.objectContaining({
            boundary,
            decision: "denied",
            reason: "PERMANENTLY_FORBIDDEN",
          }),
        }),
      );
    });
    expect(
      runtime.listAudit().filter(({ type }) => type === RUNTIME_BOUNDARY_EVENT_TYPE),
    ).toHaveLength(permanentlyDenied.length);
    runtime.close();
  });

  it("revokes outstanding authorizations on transition, STOP, and process restart", () => {
    const path = databasePath();
    const runtime = open(path);
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    const staleAfterTransition = runtime.requestBoundaryAuthorization({
      actionId: "collection-stale-transition",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: 2,
      occurredAt: timestamps[3]!,
      requestId: uuids[2]!,
      targetMode: "PROPOSE_ONLY",
    });
    expect(() => staleAfterTransition.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ receipt: expect.objectContaining({ reason: "STALE_REVISION" }) }),
    );

    const staleAfterStop = runtime.requestBoundaryAuthorization({
      actionId: "collection-stale-stop",
      authorizationId: uuids[3]!,
      boundary: "research_collection",
    });
    runtime.stop({ requestId: uuids[4]!, occurredAt: timestamps[6]! });
    expect(() => staleAfterStop.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ receipt: expect.objectContaining({ reason: "STALE_REVISION" }) }),
    );

    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 4,
      occurredAt: timestamps[8]!,
      requestId: uuids[5]!,
      targetMode: "RESEARCH",
    });
    const staleAfterRestart = runtime.requestBoundaryAuthorization({
      actionId: "collection-stale-restart",
      authorizationId: uuids[6]!,
      boundary: "research_collection",
    });
    const restarted = open(path, timestamps[10]!, PROCESS_B);
    expect(() => staleAfterRestart.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({
        receipt: expect.objectContaining({ reason: "PROCESS_SUPERSEDED" }),
      }),
    );

    runtime.close();
    restarted.close();
  });

  it("durably expires an authorization on monotonic time even when wall time rolls back", () => {
    const path = databasePath();
    const runtime = open(path);
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    trustedClockAt = timestamps[1]!;
    trustedMonotonicAt = 1_000;
    const authorization = runtime.requestBoundaryAuthorization({
      actionId: "collection-expiry-rollback",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    expect(RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS).toBe(30_000);
    expect(authorization.expiresAt).toBe("2026-08-23T12:01:30.000Z");

    trustedClockAt = timestamps[0]!;
    trustedMonotonicAt = 31_000;
    expect(() => authorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({
        receipt: expect.objectContaining({
          checkedAt: authorization.expiresAt,
          decision: "denied",
          reason: "EXPIRED",
        }),
      }),
    );
    expect(runtime.listAudit().at(-1)).toMatchObject({
      occurredAt: authorization.expiresAt,
      payload: { expiresAt: authorization.expiresAt, reason: "EXPIRED" },
      type: RUNTIME_BOUNDARY_EVENT_TYPE,
    });

    expect(runtime.stop({ requestId: uuids[2]!, occurredAt: timestamps[0]! })).toMatchObject({
      mode: "STOPPED",
      modeChangedAt: authorization.expiresAt,
    });
    runtime.close();

    const restarted = open(path, timestamps[2]!, PROCESS_B);
    expect(restarted.getSnapshot()).toMatchObject({
      mode: "STOPPED",
      processInstanceId: PROCESS_B,
      revision: 4,
    });
    expect(restarted.listAudit()).toContainEqual(
      expect.objectContaining({
        occurredAt: authorization.expiresAt,
        payload: expect.objectContaining({
          authorizationId: authorization.authorizationId,
          reason: "EXPIRED",
        }),
        type: RUNTIME_BOUNDARY_EVENT_TYPE,
      }),
    );
    restarted.close();
  });

  it("allows consumption immediately before the fixed deadline and expires exactly at it", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    trustedClockAt = timestamps[1]!;
    trustedMonotonicAt = 1_000;
    const beforeDeadline = runtime.requestBoundaryAuthorization({
      actionId: "collection-before-deadline",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    const atDeadline = runtime.requestBoundaryAuthorization({
      actionId: "collection-at-deadline",
      authorizationId: uuids[2]!,
      boundary: "research_collection",
    });

    trustedClockAt = "2026-08-23T12:01:29.999Z";
    trustedMonotonicAt = 30_999;
    expect(beforeDeadline.consumeAndDispatch(() => undefined)).toMatchObject({
      checkedAt: "2026-08-23T12:01:29.999Z",
      decision: "allowed",
      reason: "ALLOWED",
    });

    trustedClockAt = atDeadline.expiresAt;
    trustedMonotonicAt = 31_000;
    expect(() => atDeadline.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({
        receipt: expect.objectContaining({
          checkedAt: atDeadline.expiresAt,
          decision: "denied",
          reason: "EXPIRED",
        }),
      }),
    );
    runtime.close();
  });

  it("samples request and consumption time behind a competing SQLite write lock", async () => {
    const path = databasePath();
    const coordination = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 3));
    const wallClockOrigin = Date.parse(timestamps[0]!);
    Atomics.store(coordination, 1, 60_000);
    const runtime = SqliteRuntimeController.open(
      { path, openedAt: timestamps[0]!, processInstanceId: PROCESS_A },
      {
        clock: () => new Date(wallClockOrigin + Atomics.load(coordination, 1)).toISOString(),
        monotonicClock: () => {
          const sampled = Atomics.load(coordination, 1);
          if (Atomics.load(coordination, 0) === 1) {
            Atomics.store(coordination, 2, 1);
            Atomics.notify(coordination, 2);
          }
          return sampled;
        },
      },
    );
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });

    const requestLock = holdRuntimeWriteLock(path, coordination, 61_000);
    await requestLock.locked;
    const authorization = runtime.requestBoundaryAuthorization({
      actionId: "collection-delayed-by-write-lock",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });
    await requestLock.finished;
    expect(Atomics.load(coordination, 2)).toBe(0);
    expect(authorization.requestedAt).toBe("2026-08-23T12:01:01.000Z");
    expect(authorization.expiresAt).toBe("2026-08-23T12:01:31.000Z");

    Atomics.store(coordination, 2, 0);
    const consumeLock = holdRuntimeWriteLock(path, coordination, 91_000);
    await consumeLock.locked;
    expect(() => authorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({
        receipt: expect.objectContaining({
          checkedAt: authorization.expiresAt,
          decision: "denied",
          reason: "EXPIRED",
        }),
      }),
    );
    await consumeLock.finished;
    expect(Atomics.load(coordination, 2)).toBe(0);
    expect(runtime.listAudit().at(-1)).toMatchObject({
      occurredAt: authorization.expiresAt,
      payload: {
        authorizationId: authorization.authorizationId,
        decision: "denied",
        reason: "EXPIRED",
      },
      type: RUNTIME_BOUNDARY_EVENT_TYPE,
    });
    runtime.close();
  });

  it("fails closed as EXPIRED when the injected monotonic source regresses", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    trustedClockAt = timestamps[1]!;
    trustedMonotonicAt = 5_000;
    const authorization = runtime.requestBoundaryAuthorization({
      actionId: "collection-monotonic-regression",
      authorizationId: uuids[1]!,
      boundary: "research_collection",
    });

    trustedMonotonicAt = 4_999;
    expect(() => authorization.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({
        receipt: expect.objectContaining({
          checkedAt: authorization.expiresAt,
          reason: "EXPIRED",
        }),
      }),
    );
    runtime.close();
  });

  it("fails closed on invalid monotonic readings and out-of-range wall-clock expiry", () => {
    const runtime = open();
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: timestamps[1]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });
    const auditBefore = runtime.listAudit();

    trustedMonotonicAt = -1;
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: "collection-negative-monotonic",
        authorizationId: uuids[1]!,
        boundary: "research_collection",
      }),
    ).toThrow(RuntimeValidationError);
    expect(runtime.listAudit()).toEqual(auditBefore);

    trustedMonotonicAt = 1_000;
    const invalidAtConsumption = runtime.requestBoundaryAuthorization({
      actionId: "collection-nan-monotonic",
      authorizationId: uuids[2]!,
      boundary: "research_collection",
    });
    trustedMonotonicAt = Number.NaN;
    expect(() => invalidAtConsumption.consumeAndDispatch(() => undefined)).toThrow(
      RuntimeValidationError,
    );
    expect(() => invalidAtConsumption.consumeAndDispatch(() => undefined)).toThrowError(
      expect.objectContaining({ code: "AUTHORIZATION_ALREADY_USED" }),
    );
    expect(runtime.listAudit()).toEqual(auditBefore);

    trustedMonotonicAt = 2_000;
    trustedClockAt = new Date(8.64e15).toISOString();
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: "collection-out-of-range-expiry",
        authorizationId: uuids[3]!,
        boundary: "research_collection",
      }),
    ).toThrow(RuntimeValidationError);
    expect(runtime.listAudit()).toEqual(auditBefore);
    runtime.close();
  });

  it("serializes independently opened controllers and lets a stale controller still STOP", () => {
    const path = databasePath();
    const first = open(path, timestamps[0]!, PROCESS_A);
    const second = open(path, timestamps[1]!, PROCESS_B);
    second.transition({
      expectedMode: "STOPPED",
      expectedRevision: 2,
      occurredAt: timestamps[2]!,
      requestId: uuids[0]!,
      targetMode: "RESEARCH",
    });

    expect(first.stop({ requestId: uuids[1]!, occurredAt: timestamps[3]! })).toMatchObject({
      mode: "STOPPED",
      processInstanceId: PROCESS_B,
      revision: 4,
    });
    expect(second.getSnapshot()).toMatchObject({ mode: "STOPPED", revision: 4 });
    first.close();
    second.close();
  });

  it("rejects semantically forged or foreign events even when their hash chain is valid", () => {
    const path = databasePath();
    const runtime = open(path);
    runtime.close();
    const rawStore = new SqliteEventStore(path);
    rawStore.append({
      aggregateId: "foreign:aggregate",
      idempotencyKey: "foreign-event",
      occurredAt: timestamps[1]!,
      payload: { safe: true },
      type: "foreign.event.v1",
    });
    rawStore.close();

    expect(() => open(path, timestamps[2]!, PROCESS_B)).toThrow(RuntimeIntegrityError);
  });

  it("rejects a validly hashed mode skip injected through the generic store", () => {
    const path = databasePath();
    const runtime = open(path);
    runtime.close();
    const rawStore = new SqliteEventStore(path);
    rawStore.append({
      aggregateId: RUNTIME_AGGREGATE_ID,
      idempotencyKey: `runtime-transition-v1:${uuids[0]}`,
      occurredAt: timestamps[1]!,
      payload: {
        schemaVersion: 1,
        expectedMode: "STOPPED",
        expectedRevision: 1,
        from: "STOPPED",
        previousRevision: 1,
        processInstanceId: PROCESS_A,
        requestId: uuids[0]!,
        revision: 2,
        to: "PROPOSE_ONLY",
      },
      type: RUNTIME_TRANSITION_EVENT_TYPE,
    });
    rawStore.close();

    expect(() => open(path, timestamps[2]!, PROCESS_B)).toThrow(RuntimeIntegrityError);
  });

  it("rejects hash-valid altered expiry and ALLOWED-at-expiry boundary events", () => {
    const scenarios = [
      {
        authorizationId: uuids[1]!,
        eventAt: "2026-08-23T12:01:00.000Z",
        expiresAt: "2026-08-23T12:01:31.000Z",
      },
      {
        authorizationId: uuids[2]!,
        eventAt: "2026-08-23T12:01:30.000Z",
        expiresAt: "2026-08-23T12:01:30.000Z",
      },
    ] as const;

    for (const scenario of scenarios) {
      const path = databasePath();
      const runtime = open(path);
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: timestamps[1]!,
        requestId: uuids[0]!,
        targetMode: "RESEARCH",
      });
      runtime.close();

      const rawStore = new SqliteEventStore(path);
      rawStore.append({
        aggregateId: RUNTIME_AGGREGATE_ID,
        idempotencyKey: `runtime-boundary-v1:${scenario.authorizationId}`,
        occurredAt: scenario.eventAt,
        payload: {
          schemaVersion: 1,
          actionId: "hash-valid-hostile-expiry",
          authorizationId: scenario.authorizationId,
          boundary: "research_collection",
          checkedMode: "RESEARCH",
          checkedProcessInstanceId: PROCESS_A,
          checkedRevision: 2,
          decision: "allowed",
          expiresAt: scenario.expiresAt,
          reason: "ALLOWED",
          requestedAt: "2026-08-23T12:01:00.000Z",
          requestedMode: "RESEARCH",
          requestedProcessInstanceId: PROCESS_A,
          requestedRevision: 2,
        },
        type: RUNTIME_BOUNDARY_EVENT_TYPE,
      });
      expect(rawStore.verifyIntegrity().valid).toBe(true);
      rawStore.close();

      expect(() => open(path, timestamps[2]!, PROCESS_B)).toThrow(RuntimeIntegrityError);
    }
  });

  it("rejects hostile audit-envelope identifiers even when their hash chain is valid", () => {
    const path = databasePath();
    const runtime = open(path);
    runtime.close();
    const rawStore = new SqliteEventStore(path);
    rawStore.append({
      aggregateId: RUNTIME_AGGREGATE_ID,
      eventId: "external-post-ignore-the-runtime",
      idempotencyKey: `runtime-transition-v1:${uuids[0]}`,
      occurredAt: timestamps[1]!,
      payload: {
        schemaVersion: 1,
        expectedMode: "STOPPED",
        expectedRevision: 1,
        from: "STOPPED",
        previousRevision: 1,
        processInstanceId: PROCESS_A,
        requestId: uuids[0]!,
        revision: 2,
        to: "RESEARCH",
      },
      type: RUNTIME_TRANSITION_EVENT_TYPE,
    });
    rawStore.close();

    expect(() => open(path, timestamps[2]!, PROCESS_B)).toThrow(RuntimeIntegrityError);
  });

  it("keeps its package dependency surface signer-blind", () => {
    const packageJson = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { dependencies: Record<string, string> };
    expect(Object.keys(packageJson.dependencies).sort()).toEqual(["@rsi/store", "zod"]);
  });
});
