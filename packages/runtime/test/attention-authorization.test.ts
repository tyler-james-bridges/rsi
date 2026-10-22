import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteEventStore } from "@rsi/store";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MAX_PERSISTED_ATTENTION_REFRESH_RECEIPTS,
  RuntimeBoundaryDeniedError,
  RuntimeIntegrityError,
  RuntimeValidationError,
  SqliteRuntimeController,
  type RuntimeBoundaryReceipt,
} from "../src/index.js";

const NOW = "2026-10-21T00:00:00.000Z";
const LATER = "2026-10-21T00:01:00.000Z";
const RESEARCH_AFTER_RESTART = "2026-10-21T00:02:00.000Z";
const PROPOSE_AFTER_RESTART = "2026-10-21T00:03:00.000Z";
const temporaryDirectories: string[] = [];

function databasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "rsi-attention-runtime-"));
  temporaryDirectories.push(directory);
  return join(directory, "runtime.sqlite");
}

function deniedReceipt(operation: () => unknown): Readonly<RuntimeBoundaryReceipt> {
  try {
    operation();
  } catch (error) {
    if (error instanceof RuntimeBoundaryDeniedError) return error.receipt;
    throw error;
  }
  throw new Error("Expected a denied runtime boundary receipt");
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("attention refresh authorization", () => {
  it("binds authority ownership to the exact issuing controller instance", () => {
    const firstPath = databasePath();
    const secondPath = databasePath();
    const processInstanceId = randomUUID();
    let clockReads = 0;
    const clock = () => {
      clockReads += 1;
      return NOW;
    };
    const first = SqliteRuntimeController.open(
      { path: firstPath, openedAt: NOW, processInstanceId },
      { clock, monotonicClock: () => 0 },
    );
    const second = SqliteRuntimeController.open(
      { path: secondPath, openedAt: NOW, processInstanceId },
      { clock, monotonicClock: () => 0 },
    );
    for (const runtime of [first, second]) {
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: NOW,
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });
    }
    const sharedAuthorizationId = randomUUID();
    const firstAuthorization = first.requestBoundaryAuthorization({
      actionId: "shared-attention-batch",
      authorizationId: sharedAuthorizationId,
      boundary: "attention_refresh",
    });
    const staleAuthorization = first.requestBoundaryAuthorization({
      actionId: "stale-attention-batch",
      authorizationId: randomUUID(),
      boundary: "attention_refresh",
    });
    const secondAuthorization = second.requestBoundaryAuthorization({
      actionId: "shared-attention-batch",
      authorizationId: sharedAuthorizationId,
      boundary: "attention_refresh",
    });
    const wrongBoundary = first.requestBoundaryAuthorization({
      actionId: "shared-attention-batch",
      authorizationId: randomUUID(),
      boundary: "watchlist_import",
    });
    const firstAudit = first.listAudit();
    const secondAudit = second.listAudit();
    const readsBeforeOwnershipChecks = clockReads;
    let proxyTrapWasInvoked = false;
    const proxy = new Proxy(firstAuthorization, {
      get: () => {
        proxyTrapWasInvoked = true;
        throw new Error("authorization proxy trap must not run");
      },
    });

    expect(first.ownsAttentionRefreshAuthorization(firstAuthorization)).toBe(true);
    expect(first.ownsAttentionRefreshAuthorization(secondAuthorization)).toBe(false);
    expect(second.ownsAttentionRefreshAuthorization(firstAuthorization)).toBe(false);
    expect(second.ownsAttentionRefreshAuthorization(secondAuthorization)).toBe(true);
    expect(first.ownsAttentionRefreshAuthorization({ ...firstAuthorization })).toBe(false);
    expect(
      first.ownsAttentionRefreshAuthorization(JSON.parse(JSON.stringify(firstAuthorization))),
    ).toBe(false);
    expect(first.ownsAttentionRefreshAuthorization(Object.create(firstAuthorization))).toBe(false);
    expect(first.ownsAttentionRefreshAuthorization(proxy)).toBe(false);
    expect(first.ownsAttentionRefreshAuthorization(wrongBoundary)).toBe(false);
    expect(proxyTrapWasInvoked).toBe(false);
    expect(clockReads).toBe(readsBeforeOwnershipChecks);
    expect(first.listAudit()).toEqual(firstAudit);
    expect(second.listAudit()).toEqual(secondAudit);

    firstAuthorization.consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
    });
    secondAuthorization.consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
    });
    first.close();

    let restartedClockWasRead = false;
    const restarted = SqliteRuntimeController.open(
      { path: firstPath, openedAt: LATER, processInstanceId: randomUUID() },
      {
        clock: () => {
          restartedClockWasRead = true;
          throw new Error("ownership checks must not read the wall clock");
        },
        monotonicClock: () => {
          restartedClockWasRead = true;
          throw new Error("ownership checks must not read the monotonic clock");
        },
      },
    );

    try {
      const restartedAudit = restarted.listAudit();
      expect(restarted.ownsAttentionRefreshAuthorization(staleAuthorization)).toBe(false);
      expect(first.ownsAttentionRefreshAuthorization(staleAuthorization)).toBe(true);
      expect(restartedClockWasRead).toBe(false);
      expect(restarted.listAudit()).toEqual(restartedAudit);
    } finally {
      restarted.close();
      second.close();
    }
  });

  it("allows only RESEARCH and exposes only the local commit method", () => {
    const runtime = SqliteRuntimeController.open(
      { path: ":memory:", openedAt: NOW, processInstanceId: randomUUID() },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    const request = () =>
      runtime.requestBoundaryAuthorization({
        actionId: "attention-batch",
        authorizationId: randomUUID(),
        boundary: "attention_refresh",
      });

    try {
      expect(deniedReceipt(request)).toMatchObject({
        boundary: "attention_refresh",
        decision: "denied",
        mode: "STOPPED",
        reason: "MODE_NOT_ALLOWED",
      });
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: NOW,
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });

      const authorization = request();
      expect(Object.keys(authorization).sort()).toEqual(
        [
          "actionId",
          "authorizationId",
          "boundary",
          "consumeAndCommit",
          "expiresAt",
          "kind",
          "processInstanceId",
          "requestedAt",
          "requestedMode",
          "requestedRevision",
        ].sort(),
      );
      expect("consume" in authorization).toBe(false);
      expect("consumeAndDispatch" in authorization).toBe(false);
      expect("guardCompletion" in authorization).toBe(false);
      expect(
        authorization.consumeAndCommit((receipt, checkpoint) => {
          expect(checkpoint()).toEqual({ schemaVersion: 1, checkedAt: NOW });
          expect(receipt).toMatchObject({
            boundary: "attention_refresh",
            decision: "allowed",
            mode: "RESEARCH",
            reason: "ALLOWED",
          });
        }),
      ).toMatchObject({ boundary: "attention_refresh", decision: "allowed" });

      runtime.transition({
        expectedMode: "RESEARCH",
        expectedRevision: 2,
        occurredAt: NOW,
        requestId: randomUUID(),
        targetMode: "PROPOSE_ONLY",
      });
      expect(deniedReceipt(request)).toMatchObject({
        boundary: "attention_refresh",
        decision: "denied",
        mode: "PROPOSE_ONLY",
        reason: "MODE_NOT_ALLOWED",
      });
    } finally {
      runtime.close();
    }
  });

  it("requires one synchronous checkpoint and consumes every attempted authorization", () => {
    const runtime = SqliteRuntimeController.open(
      { path: ":memory:", openedAt: NOW, processInstanceId: randomUUID() },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: NOW,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const request = () =>
      runtime.requestBoundaryAuthorization({
        actionId: "attention-batch",
        authorizationId: randomUUID(),
        boundary: "attention_refresh",
      });

    try {
      const omitted = request();
      expect(() => omitted.consumeAndCommit(() => undefined)).toThrow("checkpoint exactly once");
      expect(() => omitted.consumeAndCommit(() => undefined)).toThrow("already consumed");

      const reused = request();
      expect(() =>
        reused.consumeAndCommit((_receipt, checkpoint) => {
          checkpoint();
          expect(() => checkpoint()).toThrow("exactly once");
        }),
      ).toThrow("checkpoint exactly once");
      expect(() => reused.consumeAndCommit(() => undefined)).toThrow("already consumed");

      const asynchronous = request();
      expect(() =>
        asynchronous.consumeAndCommit(async (_receipt, checkpoint) => {
          checkpoint();
        }),
      ).toThrow("synchronous");
      expect(() => asynchronous.consumeAndCommit(() => undefined)).toThrow("already consumed");

      const proxied = request();
      const callback = new Proxy(() => undefined, {});
      expect(() => proxied.consumeAndCommit(callback)).toThrow(RuntimeValidationError);
      expect(() => proxied.consumeAndCommit(() => undefined)).toThrow("already consumed");
    } finally {
      runtime.close();
    }
  });

  it("denies a refresh when STOP commits after issuance", () => {
    const runtime = SqliteRuntimeController.open(
      { path: ":memory:", openedAt: NOW, processInstanceId: randomUUID() },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: NOW,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const authorization = runtime.requestBoundaryAuthorization({
      actionId: "attention-stop-after-issuance",
      authorizationId: randomUUID(),
      boundary: "attention_refresh",
    });
    runtime.stop({ occurredAt: NOW, requestId: randomUUID() });

    try {
      let commitWasInvoked = false;
      expect(() =>
        authorization.consumeAndCommit(() => {
          commitWasInvoked = true;
        }),
      ).toThrowError(
        expect.objectContaining({
          receipt: expect.objectContaining({ decision: "denied", reason: "STALE_REVISION" }),
        }),
      );
      expect(commitWasInvoked).toBe(false);
    } finally {
      runtime.close();
    }
  });

  it("verifies an exact persisted allowed receipt after restart without clock access or writes", () => {
    const path = databasePath();
    const first = SqliteRuntimeController.open(
      { path, openedAt: NOW, processInstanceId: randomUUID() },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    first.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: NOW,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const attentionAuthorization = first.requestBoundaryAuthorization({
      actionId: "attention-persisted-batch",
      authorizationId: randomUUID(),
      boundary: "attention_refresh",
    });
    const allowedReceipt = attentionAuthorization.consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
    });
    const watchlistAuthorization = first.requestBoundaryAuthorization({
      actionId: "watchlist-persisted-batch",
      authorizationId: randomUUID(),
      boundary: "watchlist_import",
    });
    const wrongBoundaryReceipt = watchlistAuthorization.consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
    });
    first.stop({ occurredAt: NOW, requestId: randomUUID() });
    const denied = deniedReceipt(() =>
      first.requestBoundaryAuthorization({
        actionId: "attention-denied-batch",
        authorizationId: randomUUID(),
        boundary: "attention_refresh",
      }),
    );
    first.close();

    let clockWasRead = false;
    const restarted = SqliteRuntimeController.open(
      { path, openedAt: LATER, processInstanceId: randomUUID() },
      {
        clock: () => {
          clockWasRead = true;
          throw new Error("receipt verification must not read the wall clock");
        },
        monotonicClock: () => {
          clockWasRead = true;
          throw new Error("receipt verification must not read the monotonic clock");
        },
      },
    );

    try {
      const persisted: unknown = JSON.parse(JSON.stringify(allowedReceipt));
      const verifyWithoutAuthority = (mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED") => {
        const before = restarted.listAudit();
        const verified = restarted.verifyPersistedAttentionRefreshReceipt(persisted);
        expect(restarted.getSnapshot().mode).toBe(mode);
        expect(verified).toEqual(allowedReceipt);
        expect(Object.isFrozen(verified)).toBe(true);
        expect(Object.values(verified).some((value) => typeof value === "function")).toBe(false);
        expect("consume" in verified).toBe(false);
        expect("consumeAndCommit" in verified).toBe(false);
        expect("consumeAndDispatch" in verified).toBe(false);
        expect("guardCompletion" in verified).toBe(false);
        expect("capabilities" in verified).toBe(false);
        expect(restarted.listAudit()).toEqual(before);
        expect(clockWasRead).toBe(false);
      };

      verifyWithoutAuthority("STOPPED");
      restarted.transition({
        expectedMode: "STOPPED",
        expectedRevision: 4,
        occurredAt: RESEARCH_AFTER_RESTART,
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });
      verifyWithoutAuthority("RESEARCH");
      restarted.transition({
        expectedMode: "RESEARCH",
        expectedRevision: 5,
        occurredAt: PROPOSE_AFTER_RESTART,
        requestId: randomUUID(),
        targetMode: "PROPOSE_ONLY",
      });
      verifyWithoutAuthority("PROPOSE_ONLY");

      const changedEventHash = `${allowedReceipt.eventHash.startsWith("0") ? "1" : "0"}${allowedReceipt.eventHash.slice(1)}`;
      const mutatedReceipts = [
        ["schemaVersion", { ...allowedReceipt, schemaVersion: 2 }, RuntimeValidationError],
        [
          "actionId",
          { ...allowedReceipt, actionId: "different-attention-batch" },
          RuntimeIntegrityError,
        ],
        [
          "authorizationId",
          { ...allowedReceipt, authorizationId: randomUUID() },
          RuntimeIntegrityError,
        ],
        ["boundary", { ...allowedReceipt, boundary: "watchlist_import" }, RuntimeValidationError],
        ["checkedAt", { ...allowedReceipt, checkedAt: LATER }, RuntimeIntegrityError],
        ["decision", { ...allowedReceipt, decision: "denied" }, RuntimeValidationError],
        ["eventHash", { ...allowedReceipt, eventHash: changedEventHash }, RuntimeIntegrityError],
        [
          "eventSequence",
          { ...allowedReceipt, eventSequence: allowedReceipt.eventSequence + 1 },
          RuntimeIntegrityError,
        ],
        ["mode", { ...allowedReceipt, mode: "PROPOSE_ONLY" }, RuntimeValidationError],
        [
          "modeRevision",
          { ...allowedReceipt, modeRevision: allowedReceipt.modeRevision + 1 },
          RuntimeIntegrityError,
        ],
        [
          "processInstanceId",
          { ...allowedReceipt, processInstanceId: randomUUID() },
          RuntimeIntegrityError,
        ],
        ["reason", { ...allowedReceipt, reason: "MODE_NOT_ALLOWED" }, RuntimeValidationError],
        ["extra key", { ...allowedReceipt, extra: true }, RuntimeValidationError],
      ] as const;
      const beforeRejections = restarted.listAudit();
      for (const [field, mutated, ErrorType] of mutatedReceipts) {
        expect(
          () => restarted.verifyPersistedAttentionRefreshReceipt(mutated),
          `mutated ${field} must fail closed`,
        ).toThrow(ErrorType);
      }
      expect(() => restarted.verifyPersistedAttentionRefreshReceipt(denied)).toThrow(
        RuntimeValidationError,
      );
      expect(() => restarted.verifyPersistedAttentionRefreshReceipt(wrongBoundaryReceipt)).toThrow(
        RuntimeValidationError,
      );

      let proxyTrapWasInvoked = false;
      const proxy = new Proxy(
        { ...allowedReceipt },
        {
          ownKeys: () => {
            proxyTrapWasInvoked = true;
            throw new Error("receipt proxy trap must not run");
          },
        },
      );
      expect(() => restarted.verifyPersistedAttentionRefreshReceipt(proxy)).toThrow(
        RuntimeValidationError,
      );
      expect(proxyTrapWasInvoked).toBe(false);
      expect(restarted.listAudit()).toEqual(beforeRejections);
      expect(clockWasRead).toBe(false);
    } finally {
      restarted.close();
    }
  });

  it("verifies a bounded receipt batch with one runtime replay and indexed exact lookups", () => {
    const runtime = SqliteRuntimeController.open(
      { path: databasePath(), openedAt: NOW, processInstanceId: randomUUID() },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: NOW,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const issue = (actionId: string) =>
      runtime
        .requestBoundaryAuthorization({
          actionId,
          authorizationId: randomUUID(),
          boundary: "attention_refresh",
        })
        .consumeAndCommit((_receipt, checkpoint) => {
          checkpoint();
        });
    const first = issue("attention-batch-first");
    const second = issue("attention-batch-second");
    const transaction = vi.spyOn(SqliteEventStore.prototype, "withExclusiveTransaction");
    const list = vi.spyOn(SqliteEventStore.prototype, "list");
    const lookup = vi.spyOn(SqliteEventStore.prototype, "getByIdempotencyKey");

    try {
      const verified = runtime.verifyPersistedAttentionRefreshReceipts(
        JSON.parse(JSON.stringify([first, second])),
      );
      expect(verified).toEqual([first, second]);
      expect(Object.isFrozen(verified)).toBe(true);
      expect(verified.every(Object.isFrozen)).toBe(true);
      expect(transaction).toHaveBeenCalledTimes(1);
      expect(list).toHaveBeenCalledTimes(1);
      expect(lookup).toHaveBeenCalledTimes(2);

      expect(
        runtime.verifyPersistedAttentionRefreshReceipts(
          Array(MAX_PERSISTED_ATTENTION_REFRESH_RECEIPTS).fill(first),
        ),
      ).toHaveLength(MAX_PERSISTED_ATTENTION_REFRESH_RECEIPTS);

      expect(() =>
        runtime.verifyPersistedAttentionRefreshReceipts([
          first,
          { ...second, authorizationId: randomUUID() },
        ]),
      ).toThrow(RuntimeIntegrityError);
      expect(() =>
        runtime.verifyPersistedAttentionRefreshReceipts(
          Array(MAX_PERSISTED_ATTENTION_REFRESH_RECEIPTS + 1).fill(first),
        ),
      ).toThrow(RuntimeValidationError);
      expect(() => runtime.verifyPersistedAttentionRefreshReceipts(new Proxy([first], {}))).toThrow(
        RuntimeValidationError,
      );
      const accessorBatch: unknown[] = [];
      Object.defineProperty(accessorBatch, "0", {
        enumerable: true,
        get: () => {
          throw new Error("batch accessor must not run");
        },
      });
      expect(() => runtime.verifyPersistedAttentionRefreshReceipts(accessorBatch)).toThrow(
        RuntimeValidationError,
      );

      let unrelatedGetterWasRead = false;
      const noisyBatch = [first];
      for (let index = 0; index < 10_000; index += 1) {
        Object.defineProperty(noisyBatch, `unrelated-${index}`, {
          enumerable: true,
          get: () => {
            unrelatedGetterWasRead = true;
            throw new Error("unrelated receipt-batch property must not be read");
          },
        });
      }
      expect(runtime.verifyPersistedAttentionRefreshReceipts(noisyBatch)).toEqual([first]);
      expect(unrelatedGetterWasRead).toBe(false);

      const revocable = Proxy.revocable([first], {});
      revocable.revoke();
      expect(() => runtime.verifyPersistedAttentionRefreshReceipts(revocable.proxy)).toThrow(
        RuntimeValidationError,
      );
    } finally {
      runtime.close();
    }
  });
});
