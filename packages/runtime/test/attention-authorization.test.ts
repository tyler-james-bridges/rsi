import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  RuntimeBoundaryDeniedError,
  RuntimeIntegrityError,
  RuntimeValidationError,
  SqliteRuntimeController,
  type RuntimeBoundaryReceipt,
} from "../src/index.js";

const NOW = "2026-10-21T00:00:00.000Z";
const LATER = "2026-10-21T00:01:00.000Z";
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
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("attention refresh authorization", () => {
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
      const before = restarted.listAudit();
      const verified = restarted.verifyPersistedAttentionRefreshReceipt(persisted);
      expect(verified).toEqual(allowedReceipt);
      expect(Object.isFrozen(verified)).toBe(true);
      expect(restarted.listAudit()).toEqual(before);
      expect(clockWasRead).toBe(false);

      expect(() =>
        restarted.verifyPersistedAttentionRefreshReceipt({
          ...allowedReceipt,
          eventHash: "0".repeat(64),
        }),
      ).toThrow(RuntimeIntegrityError);
      expect(() => restarted.verifyPersistedAttentionRefreshReceipt(denied)).toThrow(
        RuntimeValidationError,
      );
      expect(() => restarted.verifyPersistedAttentionRefreshReceipt(wrongBoundaryReceipt)).toThrow(
        RuntimeValidationError,
      );
      expect(() =>
        restarted.verifyPersistedAttentionRefreshReceipt({ ...allowedReceipt, extra: true }),
      ).toThrow(RuntimeValidationError);

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
      expect(restarted.listAudit()).toEqual(before);
      expect(clockWasRead).toBe(false);
    } finally {
      restarted.close();
    }
  });
});
