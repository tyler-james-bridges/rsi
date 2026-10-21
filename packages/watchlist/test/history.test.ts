import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { SqliteRuntimeController } from "@rsi/runtime";
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
  const runtimePath = join(dir, "runtime.sqlite");
  const path = join(dir, "watchlist.sqlite");
  const runtime = SqliteRuntimeController.open(
    { path: runtimePath, openedAt: now, processInstanceId: randomUUID() },
    { clock: () => now },
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
    preview,
    permit,
    setTime: (at: string) => {
      now = at;
    },
  };
}

describe("watchlist event history", () => {
  it("bounds history at 1000 while accepting an exact old retry and returning 20 headers", () => {
    const s = setup();
    const first = fixture();
    const expected = s.preview(first).binding;
    s.history.import({ input: first, expected, authorization: s.permit(expected.snapshotId) });
    const store = new SqliteEventStore(s.path);
    let predecessor: SnapshotId = expected.snapshotId;
    store.withExclusiveTransaction(() => {
      for (let index = 1; index < 1000; index += 1) {
        const raw = fixture();
        raw.acquiredAt = new Date(Date.parse(first.acquiredAt) + index * 1000).toISOString();
        raw.validUntil = new Date(Date.parse(raw.acquiredAt) + 120000).toISOString();
        const normalized = parseOfflineBaseWatchlistSnapshot(raw);
        const id = snapshotId(normalized);
        store.append({
          aggregateId: "watchlist:base",
          type: "watchlist.snapshot.recorded.v1",
          idempotencyKey: `watchlist-snapshot-v1:${id}`,
          occurredAt: raw.acquiredAt,
          payload: {
            snapshotId: id,
            predecessorId: predecessor,
            snapshot: raw,
            importedAt: raw.acquiredAt,
            authorization: {
              boundary: "watchlist_import",
              authorizationId: randomUUID(),
              processInstanceId: s.runtime.processInstanceId,
              mode: "RESEARCH",
              modeRevision: 2,
              checkedAt: raw.acquiredAt,
              eventHash: "a".repeat(64),
            },
          },
        });
        predecessor = id;
      }
    });
    store.close();
    expect(s.history.read(first.acquiredAt).history).toHaveLength(20);
    expect(
      s.history.import({ input: first, expected, authorization: s.permit(expected.snapshotId) })
        .duplicate,
    ).toBe(true);
    const next = fixture();
    next.acquiredAt = "2026-10-20T01:00:00.000Z";
    next.validUntil = "2026-10-20T01:02:00.000Z";
    const preview = s.preview(next).binding;
    expect(() =>
      s.history.import({
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
    const first = s.history.import({
      input,
      expected,
      authorization: s.permit(expected.snapshotId),
    });
    expect(first.duplicate).toBe(false);
    const retry = s.history.import({
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
  it("binds predecessor, increasing acquisition time and snapshot content", () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    s.history.import({ input, expected, authorization: s.permit(expected.snapshotId) });
    const wrongRetry = s.preview(input).binding;
    expect(() =>
      s.history.import({
        input,
        expected: wrongRetry,
        authorization: s.permit(expected.snapshotId),
      }),
    ).toThrow("reused");
    const changed = fixture();
    changed.hasNextPage = true;
    const changedPreview = s.preview(changed).binding;
    expect(() =>
      s.history.import({
        input: changed,
        expected: changedPreview,
        authorization: s.permit(changedPreview.snapshotId),
      }),
    ).toThrow("increase");
    expect(() =>
      s.history.import({ input: changed, expected, authorization: s.permit(expected.snapshotId) }),
    ).toThrow("preview authority");
    changed.acquiredAt = "2026-10-20T00:01:00.000Z";
    changed.validUntil = "2026-10-20T00:03:00.000Z";
    const next = s.preview(changed).binding;
    expect(() =>
      s.history.import({
        input: changed,
        expected: { ...next, predecessorId: null },
        authorization: s.permit(next.snapshotId),
      }),
    ).toThrow("head is stale");
    s.history.import({ input: changed, expected: next, authorization: s.permit(next.snapshotId) });
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
      expect(() => s.history.import({ input, expected, authorization })).toThrow();
      expect(s.history.read(input.acquiredAt).head).toBeNull();
      expect(() => s.history.import({ input, expected, authorization })).toThrow();
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
      s.history.import({ input, expected, authorization: { ...authorization } }),
    ).toThrow();
    expect(() => authorization.consumeAndCommit(async () => undefined)).toThrow("synchronous");
  });
  it("detects raw tampering and semantically invalid hash-valid history", () => {
    const s = setup();
    const input = fixture();
    const expected = s.preview(input).binding;
    s.history.import({ input, expected, authorization: s.permit(expected.snapshotId) });
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
});
