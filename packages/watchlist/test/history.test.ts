import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Worker } from "node:worker_threads";

import { RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS, SqliteRuntimeController } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { afterEach, describe, expect, it } from "vitest";
import {
  OfflineBaseWatchlist,
  parseOfflineBaseWatchlistSnapshot,
  snapshotId,
  type SnapshotId,
} from "../src/index.js";
import { fixture } from "./fixtures.js";

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const close of cleanups.splice(0).reverse()) close();
});
function setup() {
  const dir = mkdtempSync(join(tmpdir(), "rsi-watchlist-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  let now = "2026-10-20T00:00:30.000Z";
  let scheduledClockAdvance: { readsBeforeAdvance: number; value: string } | undefined;
  const monotonic = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  const runtimePath = join(dir, "runtime.sqlite");
  const path = join(dir, "watchlist.sqlite");
  const runtime = SqliteRuntimeController.open(
    { path: runtimePath, openedAt: now, processInstanceId: randomUUID() },
    {
      clock: () => {
        if (scheduledClockAdvance?.readsBeforeAdvance === 0) {
          now = scheduledClockAdvance.value;
          scheduledClockAdvance = undefined;
        }
        const value = now;
        if (scheduledClockAdvance !== undefined) scheduledClockAdvance.readsBeforeAdvance -= 1;
        return value;
      },
      monotonicClock: () => Atomics.load(monotonic, 0),
    },
  );
  cleanups.push(() => runtime.close());
  runtime.transition({
    expectedMode: "STOPPED",
    expectedRevision: 1,
    occurredAt: now,
    requestId: randomUUID(),
    targetMode: "RESEARCH",
  });
  const history = OfflineBaseWatchlist.open(path);
  cleanups.push(() => history.close());
  const preview = (input: unknown) =>
    history.preview(input, {
      evaluatedAt: now,
      processInstanceId: runtime.processInstanceId,
      modeRevision: runtime.getSnapshot().revision,
    });
  const permit = (id: string) =>
    runtime.requestBoundaryAuthorization({
      boundary: "watchlist_import",
      actionId: id,
      authorizationId: randomUUID(),
    });
  return {
    runtime,
    history,
    path,
    runtimePath,
    monotonic,
    preview,
    permit,
    advanceRuntimeClockAfter: (readsBeforeAdvance: number, value: string) => {
      scheduledClockAdvance = { readsBeforeAdvance, value };
    },
    setTime: (at: string) => {
      now = at;
      scheduledClockAdvance = undefined;
    },
  };
}

describe("watchlist event history", () => {
  it("bounds history at 1000 while accepting an exact old retry and returning 20 headers", () => {
    const s = setup();
    const first = fixture();
    const expected = s.preview(first).binding;
    s.history.importSnapshot({
      input: first,
      expected,
      authorization: s.permit(expected.snapshotId),
    });
    const store = new SqliteEventStore(s.path);
    let predecessor: SnapshotId = expected.snapshotId;
    store.withExclusiveTransaction(() => {
      for (let index = 1; index < 1000; index += 1) {
        const raw = fixture();
        raw.acquiredAt = new Date(Date.parse(first.acquiredAt) + index * 1000).toISOString();
        raw.validUntil = new Date(Date.parse(raw.acquiredAt) + 120000).toISOString();
        const normalized = parseOfflineBaseWatchlistSnapshot(raw);
        const id = snapshotId(normalized);
        const importedAt = new Date(
          Date.parse(first.acquiredAt) + 30_000 + index * 1000,
        ).toISOString();
        store.append({
          aggregateId: "watchlist:base",
          type: "watchlist.snapshot.recorded.v1",
          idempotencyKey: `watchlist-snapshot-v1:${id}`,
          occurredAt: importedAt,
          payload: {
            snapshotId: id,
            predecessorId: predecessor,
            snapshot: raw,
            importedAt,
            authorization: {
              schemaVersion: 1,
              actionId: id,
              boundary: "watchlist_import",
              authorizationId: randomUUID(),
              checkedAt: importedAt,
              decision: "allowed",
              eventHash: index.toString(16).padStart(64, "0"),
              eventSequence: index + 3,
              mode: "RESEARCH",
              modeRevision: 2,
              processInstanceId: s.runtime.processInstanceId,
              reason: "ALLOWED",
            },
          },
        });
        predecessor = id;
      }
    });
    store.close();
    expect(s.history.read(first.acquiredAt).history).toHaveLength(20);
    expect(
      s.history.importSnapshot({
        input: first,
        expected,
        authorization: s.permit(expected.snapshotId),
      }).duplicate,
    ).toBe(true);
    const next = fixture();
    next.acquiredAt = "2026-10-20T01:00:00.000Z";
    next.validUntil = "2026-10-20T01:02:00.000Z";
    s.setTime(next.acquiredAt);
    const preview = s.preview(next).binding;
    expect(() =>
      s.history.importSnapshot({
        input: next,
        expected: preview,
        authorization: s.permit(preview.snapshotId),
      }),
    ).toThrow("full");
  });
  it("previews without writes, imports once, retries after lost response, and reopens", () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    expect(s.history.read(input.acquiredAt).head).toBeNull();
    const first = s.history.importSnapshot({
      input,
      expected,
      authorization: s.permit(expected.snapshotId),
    });
    expect(first.duplicate).toBe(false);
    const retry = s.history.importSnapshot({
      input,
      expected,
      authorization: s.permit(expected.snapshotId),
    });
    expect(retry).toEqual({ ...first, duplicate: true });
    expect(s.history.read(input.validUntil).stale).toBe(true);
    expect(s.history.read(input.acquiredAt).stale).toBe(false);
    s.history.close();
    const reopened = OfflineBaseWatchlist.open(s.path);
    cleanups.push(() => reopened.close());
    expect(reopened.read(input.validUntil).history).toHaveLength(1);
    expect(reopened.read(input.validUntil).rows[0]?.change).toBe("new");
    const receipt = s.runtime
      .listAudit()
      .find((event) => event.type === "runtime.boundary.checked.v1");
    expect(receipt?.payload).toMatchObject({ boundary: "watchlist_import", decision: "allowed" });
  });
  it("accepts a coherent exact retry without a server-issued preview", () => {
    const s = setup();
    const input = fixture();
    const firstBinding = s.preview(input).binding;
    const first = s.history.importSnapshot({
      input,
      expected: firstBinding,
      authorization: s.permit(firstBinding.snapshotId),
    });
    s.runtime.close();

    const restarted = SqliteRuntimeController.open({
      path: s.runtimePath,
      openedAt: "2026-10-20T00:00:30.000Z",
      processInstanceId: randomUUID(),
    });
    cleanups.push(() => restarted.close());
    const stopped = restarted.getSnapshot();
    restarted.transition({
      expectedMode: "STOPPED",
      expectedRevision: stopped.revision,
      occurredAt: "2026-10-20T00:00:30.000Z",
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const current = restarted.getSnapshot();
    const expected = {
      snapshotId: firstBinding.snapshotId,
      predecessorId: null,
      processInstanceId: current.processInstanceId,
      modeRevision: current.revision,
      previewedAt: "2026-10-20T00:00:30.000Z",
    };
    const retry = s.history.importSnapshot({
      input,
      expected,
      authorization: restarted.requestBoundaryAuthorization({
        boundary: "watchlist_import",
        actionId: expected.snapshotId,
        authorizationId: randomUUID(),
      }),
    });
    expect(retry).toEqual({ ...first, duplicate: true });
  });
  it("rejects future acquisition times without poisoning the head", () => {
    const s = setup();
    const future = fixture();
    future.acquiredAt = "9999-01-01T00:00:00.000Z";
    future.validUntil = "9999-01-01T00:02:00.000Z";
    expect(() => s.preview(future)).toThrow("future");

    const normalized = parseOfflineBaseWatchlistSnapshot(future);
    const id = snapshotId(normalized);
    expect(() =>
      s.history.importSnapshot({
        input: future,
        expected: {
          snapshotId: id,
          predecessorId: null,
          processInstanceId: s.runtime.processInstanceId,
          modeRevision: s.runtime.getSnapshot().revision,
          previewedAt: "2026-10-20T00:00:30.000Z",
        },
        authorization: s.permit(id),
      }),
    ).toThrow("future");
    expect(s.history.read("2026-10-20T00:00:30.000Z").head).toBeNull();

    const current = fixture();
    const expected = s.preview(current).binding;
    expect(
      s.history.importSnapshot({
        input: current,
        expected,
        authorization: s.permit(expected.snapshotId),
      }).duplicate,
    ).toBe(false);
  });
  it("requires a new preview when freshness changes but permits an exact retry", () => {
    const s = setup();
    const input = fixture();
    const fresh = s.preview(input).binding;
    s.setTime(input.validUntil);
    expect(() =>
      s.history.importSnapshot({
        input,
        expected: fresh,
        authorization: s.permit(fresh.snapshotId),
      }),
    ).toThrow("freshness changed");
    expect(s.history.read(input.validUntil).head).toBeNull();

    const stale = s.preview(input).binding;
    const imported = s.history.importSnapshot({
      input,
      expected: stale,
      authorization: s.permit(stale.snapshotId),
    });
    expect(imported.duplicate).toBe(false);
    expect(
      s.history.importSnapshot({
        input,
        expected: fresh,
        authorization: s.permit(fresh.snapshotId),
      }).duplicate,
    ).toBe(true);
  });
  it("rechecks freshness at the final commit checkpoint", () => {
    const s = setup();
    const input = fixture();
    s.setTime("2026-10-20T00:01:59.900Z");
    const expected = s.preview(input).binding;
    const authorization = s.permit(expected.snapshotId);
    s.advanceRuntimeClockAfter(2, input.validUntil);
    expect(() => s.history.importSnapshot({ input, expected, authorization })).toThrow(
      "freshness changed",
    );
    expect(s.history.read(input.validUntil).head).toBeNull();
  });
  it("rechecks authority after waiting for the watchlist write lock", async () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    const authorization = s.permit(expected.snapshotId);
    const worker = new Worker(
      `
        const { parentPort, workerData } = require("node:worker_threads");
        const { DatabaseSync } = require("node:sqlite");
        const monotonic = new Int32Array(workerData.monotonic);
        const database = new DatabaseSync(workerData.path);
        database.exec("PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE");
        parentPort.postMessage("locked");
        Atomics.wait(monotonic, 0, 0, 100);
        Atomics.store(monotonic, 0, workerData.expiresAt);
        database.exec("COMMIT");
        database.close();
      `,
      {
        eval: true,
        workerData: {
          expiresAt: RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS,
          monotonic: s.monotonic.buffer,
          path: s.path,
        },
      },
    );
    cleanups.push(() => {
      void worker.terminate();
    });
    const exited = once(worker, "exit");
    await once(worker, "message");
    expect(() => s.history.importSnapshot({ input, expected, authorization })).toThrow(
      "authority changed before commit",
    );
    await exited;
    expect(s.history.read(input.acquiredAt).head).toBeNull();
    expect(s.runtime.listAudit().at(-1)?.payload).toMatchObject({
      authorizationId: authorization.authorizationId,
      decision: "allowed",
    });
  });
  it("binds predecessor, increasing acquisition time and snapshot content", () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    s.history.importSnapshot({ input, expected, authorization: s.permit(expected.snapshotId) });
    const wrongRetry = s.preview(input).binding;
    expect(() =>
      s.history.importSnapshot({
        input,
        expected: wrongRetry,
        authorization: s.permit(expected.snapshotId),
      }),
    ).toThrow("reused");
    const changed = fixture();
    changed.hasNextPage = true;
    const changedPreview = s.preview(changed).binding;
    expect(() =>
      s.history.importSnapshot({
        input: changed,
        expected: changedPreview,
        authorization: s.permit(changedPreview.snapshotId),
      }),
    ).toThrow("increase");
    expect(() =>
      s.history.importSnapshot({
        input: changed,
        expected,
        authorization: s.permit(expected.snapshotId),
      }),
    ).toThrow("preview authority");
    changed.acquiredAt = "2026-10-20T00:01:00.000Z";
    changed.validUntil = "2026-10-20T00:03:00.000Z";
    s.setTime(changed.acquiredAt);
    const next = s.preview(changed).binding;
    expect(() =>
      s.history.importSnapshot({
        input: changed,
        expected: { ...next, predecessorId: null },
        authorization: s.permit(next.snapshotId),
      }),
    ).toThrow("head is stale");
    s.history.importSnapshot({
      input: changed,
      expected: next,
      authorization: s.permit(next.snapshotId),
    });
    expect(s.history.read(changed.acquiredAt)).toMatchObject({
      partial: true,
      rows: [{ change: "unchanged" }],
    });
  });
  it.each(["stop", "revision", "expiry", "process"])(
    "rejects %s between permit and commit",
    (kind) => {
      const s = setup();
      const input = fixture();
      const expected = s.preview(input).binding;
      const authorization = s.permit(expected.snapshotId);
      if (kind === "stop")
        s.runtime.stop({ occurredAt: "2026-10-20T00:00:30.000Z", requestId: randomUUID() });
      if (kind === "revision")
        s.runtime.transition({
          expectedMode: "RESEARCH",
          expectedRevision: 2,
          occurredAt: "2026-10-20T00:00:30.000Z",
          requestId: randomUUID(),
          targetMode: "PROPOSE_ONLY",
        });
      if (kind === "expiry") s.setTime("2026-10-20T01:00:00.000Z");
      if (kind === "process") {
        const other = SqliteRuntimeController.open({
          path: s.runtimePath,
          openedAt: "2026-10-20T00:00:30.000Z",
          processInstanceId: randomUUID(),
        });
        other.close();
      }
      expect(() => s.history.importSnapshot({ input, expected, authorization })).toThrow();
      expect(s.history.read(input.acquiredAt).head).toBeNull();
      expect(() => s.history.importSnapshot({ input, expected, authorization })).toThrow();
    },
  );
  it("retains a committed authorization when a protected callback crashes", () => {
    const s = setup();
    const authorization = s.permit("test-crash");
    expect(() =>
      authorization.consumeAndCommit(() => {
        throw new Error("crash-before-append");
      }),
    ).toThrow("crash-before-append");
    expect(s.runtime.listAudit().at(-1)?.payload).toMatchObject({
      authorizationId: authorization.authorizationId,
      decision: "allowed",
    });
    expect(() => authorization.consumeAndCommit(() => undefined)).toThrow();
    expect(s.history.read("2026-10-20T00:00:30.000Z").head).toBeNull();
  });
  it("rejects forged authority and asynchronous callbacks", () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    const authorization = s.permit(expected.snapshotId);
    expect(() =>
      s.history.importSnapshot({ input, expected, authorization: { ...authorization } }),
    ).toThrow();
    expect(() => authorization.consumeAndCommit(async () => undefined)).toThrow("synchronous");
  });
  it("detects raw tampering and semantically invalid hash-valid history", () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    s.history.importSnapshot({ input, expected, authorization: s.permit(expected.snapshotId) });
    s.history.close();
    const raw = new DatabaseSync(s.path);
    raw.exec("UPDATE rsi_events SET occurred_at = '2026-10-21T00:00:00.000Z'");
    raw.close();
    expect(() => OfflineBaseWatchlist.open(s.path)).toThrow();
    const wrongPath = s.path + ".wrong";
    const store = new SqliteEventStore(wrongPath);
    store.append({
      aggregateId: "watchlist:base",
      type: "unexpected",
      payload: {},
      occurredAt: input.acquiredAt,
    });
    store.close();
    expect(() => OfflineBaseWatchlist.open(wrongPath)).toThrow();
  });
  it("rejects instances constructed outside the trusted factory", () => {
    const s = setup();
    const store = new SqliteEventStore(s.path + ".forged");
    cleanups.push(() => store.close());
    const forged = Reflect.construct(OfflineBaseWatchlist as unknown as Function, [
      store,
    ]) as OfflineBaseWatchlist;
    expect(() => forged.read("2026-10-20T00:00:30.000Z")).toThrow("unavailable");
  });
});
