import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { SqliteRuntimeController, type RuntimeBoundaryAuthorization } from "@rsi/runtime";
import { SqliteEventStore, type AppendEventInput, type StoredEvent } from "@rsi/store";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MAX_ATTENTION_EVENT_BYTES,
  MAX_ATTENTION_HISTORY,
  RecordedAttentionHistory,
  createRuntimeAttentionReceiptVerifier,
  type AttentionPreviewBinding,
  type AttentionRecordCommand,
  type RecordedAttentionBundleV1,
} from "../src/index.js";
import { AttentionRecordedEventSchema } from "../src/history-schemas.js";
import { sanitizeRecordedAttentionBundle } from "../src/sanitize.js";
import { ADDRESS_A, ADDRESS_B, candidate, mixedFixture, recordedBundle } from "./fixtures.js";

const NOW = "2026-10-21T12:00:30.000Z";
const directories: string[] = [];
const closeables: { close(): void }[] = [];

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), "rsi-attention-history-"));
  directories.push(path);
  return path;
}

function fixture() {
  const root = directory();
  const path = join(root, "attention.sqlite");
  const runtimePath = join(root, "runtime.sqlite");
  const clock = { now: NOW, reads: 0, samples: [] as string[], fail: false };
  const runtime = SqliteRuntimeController.open(
    { path: runtimePath, openedAt: NOW, processInstanceId: randomUUID() },
    {
      clock: () => {
        clock.reads += 1;
        if (clock.fail) throw new Error("read must not consult the clock");
        return clock.samples.shift() ?? clock.now;
      },
      monotonicClock: () => 0,
    },
  );
  closeables.push(runtime);
  runtime.transition({
    expectedMode: "STOPPED",
    expectedRevision: 1,
    occurredAt: NOW,
    requestId: randomUUID(),
    targetMode: "RESEARCH",
  });
  const receiptVerifier = createRuntimeAttentionReceiptVerifier(runtime);
  const history = RecordedAttentionHistory.open({ path, receiptVerifier });
  closeables.push(history);
  const context = () => ({
    processInstanceId: runtime.getSnapshot().processInstanceId,
    modeRevision: runtime.getSnapshot().revision,
    evaluatedAt: clock.now,
  });
  const preview = (input: unknown) => {
    const value = history.preview(input, context());
    if (value.kind !== "preview") throw new Error("expected a new preview");
    return value;
  };
  const authorize = (expected: AttentionPreviewBinding) =>
    runtime.requestBoundaryAuthorization({
      boundary: "attention_refresh",
      actionId: expected.refreshId,
      authorizationId: randomUUID(),
    });
  const record = (input: RecordedAttentionBundleV1) => {
    const expected = preview(input).binding;
    return history.record({ input, expected, authorization: authorize(expected) });
  };
  return {
    root,
    path,
    runtimePath,
    clock,
    runtime,
    receiptVerifier,
    history,
    context,
    preview,
    authorize,
    record,
  };
}

function events(path: string): readonly StoredEvent[] {
  using store = new SqliteEventStore(path);
  return store.list();
}

function eventInput(event: StoredEvent): AppendEventInput {
  return {
    type: event.type,
    aggregateId: event.aggregateId,
    eventId: event.eventId,
    ...(event.idempotencyKey === null ? {} : { idempotencyKey: event.idempotencyKey }),
    occurredAt: event.occurredAt,
    payload: event.payload,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const closeable of closeables.splice(0).reverse()) closeable.close();
  for (const path of directories.splice(0)) rmSync(path, { force: true, recursive: true });
});

describe("recorded attention history", () => {
  it("previews without writes, commits one complete event, and reads the saved golden assessment", () => {
    const f = fixture();
    const input = mixedFixture();
    const beforeAudit = f.runtime.listAudit();
    const preview = f.preview(input);
    expect(events(f.path)).toEqual([]);
    expect(f.runtime.listAudit()).toEqual(beforeAudit);
    expect(preview.binding).toMatchObject({
      policyVersion: "attention-v1",
      auditHead: null,
      evaluatedAt: NOW,
      deadline: "2026-10-21T12:01:00.000Z",
    });
    expect(f.preview(input)).toEqual(preview);
    const result = f.history.record({
      input,
      expected: preview.binding,
      authorization: f.authorize(preview.binding),
    });
    expect(result.assessment).toEqual(preview.assessment);
    expect(result.assessment.rows.map((row) => row.outcome.kind)).toEqual([
      "review",
      "watch",
      "rejected",
    ]);
    expect(Object.isFrozen(result.assessment.rows)).toBe(true);
    const saved = events(f.path);
    expect(saved).toHaveLength(1);
    const payload = AttentionRecordedEventSchema.parse(saved[0]?.payload);
    expect(payload.result).toEqual(result);
    expect(payload.nextFacts.headRefreshId).toBe(result.assessment.refreshId);
    expect(payload.sourceFacts.kind).toBe("sanitized_recorded_collection_attention");
    const view = f.history.read(NOW);
    expect(view.kind).toBe("available");
    if (view.kind !== "available") throw new Error("expected available");
    expect(view.latest).toEqual(result);
    expect(view.rows.map((row) => row.saved)).toEqual(result.assessment.rows);
    expect(view.history[0]?.head.refreshId).toBe(result.assessment.refreshId);
    expect(view.rows[0]?.saved).toMatchObject({
      provenance: { kind: "operator_supplied_unverified" },
      scorecard: { rank: 40 },
      missingChecks: expect.arrayContaining(["authenticated_provenance"]),
    });
  });

  it("applies expiry without changing saved outcomes and refuses a regressed read clock", () => {
    const f = fixture();
    const result = f.record(mixedFixture());
    const before = events(f.path);
    const view = f.history.read("2026-10-21T12:02:00.000Z");
    if (view.kind !== "available") throw new Error("expected available");
    expect(view.rows.map((row) => row.effectiveOutcome.kind)).toEqual([
      "watch",
      "watch",
      "rejected",
    ]);
    expect(view.rows[0]).toMatchObject({
      saved: { outcome: { kind: "review", priority: 45 } },
      expired: true,
      effectiveOutcome: { kind: "watch", reasons: ["ASSESSMENT_EXPIRED"], priority: 0 },
      effectiveNextAction: "supply_new_recorded_rank_window",
    });
    expect(view.latest).toEqual(result);
    expect(f.history.read("2026-10-21T12:00:29.999Z")).toEqual({
      schemaVersion: 1,
      kind: "unavailable",
      reason: "clock_regressed",
      evaluatedAt: "2026-10-21T12:00:29.999Z",
      latestCheckpointAt: NOW,
    });
    expect(events(f.path)).toEqual(before);
  });

  it("denies new records after STOP, including authority issued before STOP", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const authorization = f.authorize(expected);
    f.runtime.stop({ occurredAt: NOW, requestId: randomUUID() });
    expect(() => f.history.record({ input, expected, authorization })).toThrow();
    expect(() => f.authorize(expected)).toThrow();
    expect(events(f.path)).toEqual([]);
  });

  it("rejects forged, serialized, proxied, wrong-boundary, and wrong-action authority", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const genuine = f.authorize(expected);
    let invoked = false;
    const forged = {
      ...genuine,
      consumeAndCommit: () => {
        invoked = true;
      },
    };
    const serialized: unknown = JSON.parse(JSON.stringify(genuine));
    const wrongBoundary = f.runtime.requestBoundaryAuthorization({
      boundary: "watchlist_import",
      actionId: expected.refreshId,
      authorizationId: randomUUID(),
    });
    const wrongAction = f.runtime.requestBoundaryAuthorization({
      boundary: "attention_refresh",
      actionId: "different",
      authorizationId: randomUUID(),
    });
    const runtimeAudit = f.runtime.listAudit();
    for (const authority of [
      forged,
      serialized,
      new Proxy(genuine, {}),
      wrongBoundary,
      wrongAction,
    ]) {
      expect(() =>
        f.history.record({
          input,
          expected,
          authorization: authority as RuntimeBoundaryAuthorization<"attention_refresh">,
        }),
      ).toThrow("attention_authority_mismatch");
    }
    expect(invoked).toBe(false);
    expect(f.runtime.listAudit()).toEqual(runtimeAudit);
    expect(events(f.path)).toEqual([]);
    expect(f.history.record({ input, expected, authorization: genuine })).toMatchObject({
      binding: expected,
    });
    expect(events(f.path)).toHaveLength(1);
    expect(() => createRuntimeAttentionReceiptVerifier({} as SqliteRuntimeController)).toThrow(
      "runtime_verifier_invalid",
    );
    expect(() =>
      RecordedAttentionHistory.open({
        path: f.path,
        receiptVerifier: {
          ownsAttentionRefreshAuthorization: (
            input: unknown,
          ): input is RuntimeBoundaryAuthorization<"attention_refresh"> => input !== null,
          verifyPersistedAttentionRefreshReceipt: () => {
            throw new Error("forged");
          },
        },
      }),
    ).toThrow("runtime_verifier_invalid");
  });

  it("checks command descriptors before invoking accessors", () => {
    const f = fixture();
    let read = false;
    const command = { input: recordedBundle(), expected: f.preview(recordedBundle()).binding };
    Object.defineProperty(command, "authorization", {
      enumerable: true,
      get: () => {
        read = true;
        return null;
      },
    });
    expect(() => f.history.record(command as AttentionRecordCommand)).toThrow(
      "attention_command_invalid",
    );
    expect(read).toBe(false);
    expect(() => f.history.record(new Proxy(command, {}) as AttentionRecordCommand)).toThrow(
      "attention_command_invalid",
    );
  });

  it("rejects a genuine authority and preview context from a different runtime owner", () => {
    const f = fixture();
    const other = fixture();
    const input = recordedBundle();
    const expected = other.preview(input).binding;
    expect(() => f.history.preview(input, other.context())).toThrow("attention_authority_mismatch");
    const authorization = other.authorize(expected);
    const before = other.runtime.listAudit();
    expect(() => f.history.record({ input, expected, authorization })).toThrow(
      "attention_authority_mismatch",
    );
    expect(other.runtime.listAudit()).toEqual(before);
    expect(events(f.path)).toEqual([]);
  });

  it("rejects a live foreign authority with the same public runtime identity", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const foreignRuntime = SqliteRuntimeController.open(
      {
        path: join(f.root, "foreign-runtime.sqlite"),
        openedAt: NOW,
        processInstanceId: f.runtime.processInstanceId,
      },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    closeables.push(foreignRuntime);
    foreignRuntime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: NOW,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const foreignAuthorization = foreignRuntime.requestBoundaryAuthorization({
      boundary: "attention_refresh",
      actionId: expected.refreshId,
      authorizationId: randomUUID(),
    });
    const foreignAudit = foreignRuntime.listAudit();

    expect(() =>
      f.history.record({ input, expected, authorization: foreignAuthorization }),
    ).toThrow("attention_authority_mismatch");
    expect(foreignRuntime.listAudit()).toEqual(foreignAudit);
    expect(events(f.path)).toEqual([]);

    let foreignAuthorizationWasStillUsable = false;
    foreignAuthorization.consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
      foreignAuthorizationWasStillUsable = true;
    });
    expect(foreignAuthorizationWasStillUsable).toBe(true);
    expect(events(f.path)).toEqual([]);

    expect(
      f.history.record({ input, expected, authorization: f.authorize(expected) }),
    ).toMatchObject({ binding: expected });
    expect(events(f.path)).toHaveLength(1);
  });

  it("rejects authority issued by a stale controller instance before touching attention", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const staleRuntimePath = join(f.root, "stale-runtime.sqlite");
    const staleRuntime = SqliteRuntimeController.open(
      {
        path: staleRuntimePath,
        openedAt: NOW,
        processInstanceId: f.runtime.processInstanceId,
      },
      { clock: () => NOW, monotonicClock: () => 0 },
    );
    staleRuntime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: NOW,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const staleAuthorization = staleRuntime.requestBoundaryAuthorization({
      boundary: "attention_refresh",
      actionId: expected.refreshId,
      authorizationId: randomUUID(),
    });
    staleRuntime.close();

    const replacementRuntime = SqliteRuntimeController.open(
      {
        path: staleRuntimePath,
        openedAt: "2026-10-21T12:00:31.000Z",
        processInstanceId: randomUUID(),
      },
      {
        clock: () => {
          throw new Error("ownership rejection must not read the replacement clock");
        },
        monotonicClock: () => {
          throw new Error("ownership rejection must not read the replacement clock");
        },
      },
    );
    closeables.push(replacementRuntime);
    const replacementAudit = replacementRuntime.listAudit();

    expect(replacementRuntime.ownsAttentionRefreshAuthorization(staleAuthorization)).toBe(false);
    expect(() => f.history.record({ input, expected, authorization: staleAuthorization })).toThrow(
      "attention_authority_mismatch",
    );
    expect(replacementRuntime.listAudit()).toEqual(replacementAudit);
    expect(events(f.path)).toEqual([]);
    expect(
      f.history.record({ input, expected, authorization: f.authorize(expected) }),
    ).toMatchObject({ binding: expected });
    expect(events(f.path)).toHaveLength(1);
  });

  it("rejects stale heads, changed bundles, decision hashes, process IDs, and revisions before consuming authority", () => {
    const f = fixture();
    const input = recordedBundle();
    const original = f.preview(input).binding;
    for (const expected of [
      { ...original, decisionHash: "f".repeat(64) },
      { ...original, processInstanceId: randomUUID() },
      { ...original, modeRevision: original.modeRevision + 1 },
      {
        ...original,
        auditHead: { refreshId: original.refreshId, eventHash: "f".repeat(64), sequence: 1 },
      },
    ]) {
      const before = f.runtime.listAudit();
      expect(() =>
        f.history.record({ input, expected, authorization: f.authorize(original) }),
      ).toThrow();
      expect(f.runtime.listAudit()).toEqual(before);
    }
    const changed = recordedBundle({ posts: [{ id: "2", text: `Different ${ADDRESS_A}` }] });
    expect(() =>
      f.history.record({
        input: changed,
        expected: original,
        authorization: f.authorize(original),
      }),
    ).toThrow("attention_authority_mismatch");
    f.record(changed);
    expect(() =>
      f.history.record({ input, expected: original, authorization: f.authorize(original) }),
    ).toThrow("attention_preview_mismatch");
    expect(events(f.path)).toHaveLength(1);
  });

  it("checks the 30-second preview deadline independently of newer runtime authority", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    f.clock.now = "2026-10-21T12:00:50.000Z";
    const authorization = f.authorize(expected);
    f.clock.samples = [f.clock.now, f.clock.now, "2026-10-21T12:01:00.000Z"];
    expect(() => f.history.record({ input, expected, authorization })).toThrow(
      "attention_preview_expired",
    );
    expect(events(f.path)).toEqual([]);
  });

  it.each([
    ["mandatory expiry", recordedBundle(), "2026-10-21T12:01:59.000Z", "2026-10-21T12:02:00.000Z"],
    [
      "marketplace future",
      recordedBundle({ acquiredAt: "2026-10-21T12:00:31.000Z", x: { kind: "absent" } }),
      NOW,
      "2026-10-21T12:00:31.000Z",
    ],
    [
      "social future",
      recordedBundle({
        x: {
          kind: "recorded_posts",
          acquiredAt: "2026-10-21T12:00:31.000Z",
          hasNextPage: false,
          posts: [{ id: "1", text: `Research ${ADDRESS_A}` }],
        },
      }),
      NOW,
      "2026-10-21T12:00:31.000Z",
    ],
    [
      "social expiry",
      recordedBundle({
        x: {
          kind: "recorded_posts",
          acquiredAt: "2026-10-21T10:00:31.000Z",
          hasNextPage: false,
          posts: [{ id: "1", text: `Research ${ADDRESS_A}` }],
        },
      }),
      NOW,
      "2026-10-21T12:00:31.000Z",
    ],
    [
      "base expiry",
      recordedBundle({
        base: {
          kind: "reported_finalized_head",
          chainId: "8453",
          acquiredAt: "2026-10-21T11:58:31.000Z",
          blockTimestamp: "2026-10-21T11:58:00.000Z",
        },
      }),
      NOW,
      "2026-10-21T12:00:31.000Z",
    ],
  ])(
    "requires a new preview when %s crosses at the final checkpoint",
    (_label, input, previewAt, checkpointAt) => {
      const f = fixture();
      f.clock.now = previewAt;
      const expected = f.preview(input).binding;
      const authorization = f.authorize(expected);
      f.clock.samples = [previewAt, previewAt, checkpointAt];
      expect(() => f.history.record({ input, expected, authorization })).toThrow(
        "attention_classification_changed",
      );
      expect(events(f.path)).toEqual([]);
      expect(() => f.history.record({ input, expected, authorization })).toThrow(
        "already consumed",
      );
      f.clock.now = checkpointAt;
      expect(f.record(input).checkpointAt).toBe(checkpointAt);
    },
  );

  it("persists the final checkpoint, not the earlier allowed receipt time", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const authorization = f.authorize(expected);
    const checkpointAt = "2026-10-21T12:00:31.000Z";
    f.clock.samples = [NOW, NOW, checkpointAt];
    const result = f.history.record({ input, expected, authorization });
    expect(result.authorization.checkedAt).toBe(NOW);
    expect(result.checkpointAt).toBe(checkpointAt);
    expect(events(f.path)[0]?.occurredAt).toBe(checkpointAt);
    expect(f.history.read(NOW)).toMatchObject({ kind: "unavailable", reason: "clock_regressed" });
  });

  it("returns exact canonical duplicates after restart and STOP without writes, clock reads, or renewed evidence", () => {
    const f = fixture();
    const input = recordedBundle({ candidates: [candidate(1, "alpha", [ADDRESS_B, ADDRESS_A])] });
    const result = f.record(input);
    f.history.close();
    f.runtime.close();
    const runtime = SqliteRuntimeController.open(
      {
        path: f.runtimePath,
        openedAt: "2026-10-21T13:00:00.000Z",
        processInstanceId: randomUUID(),
      },
      {
        clock: () => {
          throw new Error("no wall clock reads");
        },
        monotonicClock: () => {
          throw new Error("no monotonic clock reads");
        },
      },
    );
    closeables.push(runtime);
    const before = runtime.listAudit();
    const append = vi.spyOn(SqliteEventStore.prototype, "append");
    const history = RecordedAttentionHistory.open({
      path: f.path,
      receiptVerifier: createRuntimeAttentionReceiptVerifier(runtime),
    });
    closeables.push(history);
    const equivalent = structuredClone(input);
    equivalent.marketplace.candidates[0]?.contracts.reverse();
    expect(runtime.getSnapshot().mode).toBe("STOPPED");
    expect(history.findRecorded(equivalent)).toEqual(result);
    const preview = history.preview(equivalent, {
      processInstanceId: runtime.getSnapshot().processInstanceId,
      modeRevision: runtime.getSnapshot().revision,
      evaluatedAt: "2026-10-21T13:00:00.000Z",
    });
    expect(preview).toEqual({ kind: "already_recorded", result });
    expect(history.read("2026-10-21T13:00:00.000Z")).toMatchObject({
      kind: "available",
      latest: result,
    });
    expect(append).not.toHaveBeenCalled();
    expect(runtime.listAudit()).toEqual(before);
    expect(events(f.path)).toHaveLength(1);
  });

  it("replays a changed post cluster without renewing it under a later post ID", () => {
    const f = fixture();
    const first = f.record(
      recordedBundle({ posts: [{ id: "1", text: `Original research ${ADDRESS_A}` }] }),
    );
    expect(first.assessment.rows[0]?.outcome.kind).toBe("review");

    f.clock.now = "2026-10-21T12:01:30.000Z";
    const conflict = f.record(
      recordedBundle({
        acquiredAt: "2026-10-21T12:01:00.000Z",
        posts: [{ id: "1", text: `Replacement research ${ADDRESS_A}` }],
      }),
    );
    expect(conflict.assessment.rows[0]?.outcome).toMatchObject({
      kind: "rejected",
      reasons: ["POST_CONTENT_CONFLICT"],
    });
    const conflictPayload = AttentionRecordedEventSchema.parse(events(f.path)[1]?.payload);
    expect(conflictPayload.nextFacts.conflictingClusterFirstSeen).toMatchObject([
      { firstSeenAt: "2026-10-21T12:01:10.000Z" },
    ]);

    f.clock.now = "2026-10-21T14:01:30.000Z";
    const copied = f.record(
      recordedBundle({
        acquiredAt: "2026-10-21T14:01:00.000Z",
        posts: [{ id: "2", text: `Replacement research ${ADDRESS_A}` }],
      }),
    );
    expect(copied.assessment.rows[0]).toMatchObject({
      scorecard: { socialPresence: 0 },
      outcome: { kind: "watch", reasons: ["STALE_X"] },
    });

    f.history.close();
    const reopened = RecordedAttentionHistory.open({
      path: f.path,
      receiptVerifier: f.receiptVerifier,
    });
    closeables.push(reopened);
    const view = reopened.read(f.clock.now);
    expect(view).toMatchObject({
      kind: "available",
      latest: { assessment: copied.assessment },
    });
  });

  it("requires exact stored binding for a record retry and does not consume valid retry authority", () => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const consumedAuthorization = f.authorize(expected);
    const result = f.history.record({ input, expected, authorization: consumedAuthorization });
    const beforeConsumedRetry = f.runtime.listAudit();
    expect(f.history.record({ input, expected, authorization: consumedAuthorization })).toEqual(
      result,
    );
    expect(f.runtime.listAudit()).toEqual(beforeConsumedRetry);
    expect(events(f.path)).toHaveLength(1);
    const authorization = f.authorize(result.binding);
    const before = f.runtime.listAudit();
    expect(() =>
      f.history.record({
        input,
        expected: { ...result.binding, decisionHash: "f".repeat(64) },
        authorization,
      }),
    ).toThrow("attention_preview_mismatch");
    expect(f.history.record({ input, expected: result.binding, authorization })).toEqual(result);
    expect(f.runtime.listAudit()).toEqual(before);
  });

  it("allows orphan runtime receipts without importing them or doing startup work", () => {
    const f = fixture();
    const expected = f.preview(recordedBundle()).binding;
    f.authorize(expected).consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
    });
    const before = f.runtime.listAudit();
    f.clock.fail = true;
    const append = vi.spyOn(SqliteEventStore.prototype, "append");
    using reopened = RecordedAttentionHistory.open({
      path: f.path,
      receiptVerifier: f.receiptVerifier,
    });
    expect(reopened.read(NOW)).toMatchObject({
      kind: "available",
      latest: null,
      rows: [],
      history: [],
    });
    expect(append).not.toHaveBeenCalled();
    expect(f.runtime.listAudit()).toEqual(before);
  });

  it("keeps incident audit chronology separate from the latest usable rank window", () => {
    const f = fixture();
    const first = f.record(recordedBundle({ candidates: [candidate(2, "alpha", [ADDRESS_A])] }));
    f.clock.now = "2026-10-21T12:00:40.000Z";
    const future = f.record(
      recordedBundle({ acquiredAt: "2026-10-21T14:00:00.000Z", x: { kind: "absent" } }),
    );
    expect(future.assessment.sourceSummary.marketplace.usable).toBe(false);
    f.clock.now = "2026-10-21T12:01:30.000Z";
    const latest = f.record(recordedBundle({ acquiredAt: "2026-10-21T12:01:00.000Z" }));
    expect(latest.assessment.predecessorId).toBe(future.assessment.refreshId);
    expect(latest.assessment.sourceSummary.marketplace.priorUsableWindowId).toBe(
      first.assessment.rows[0]?.evidenceIds[0],
    );
    expect(latest.assessment.rows[0]?.comparison).toEqual({
      kind: "comparable",
      previousRank: 2,
      delta: 1,
    });
  });

  it("preserves first-seen social expiry across close and reopen", () => {
    const f = fixture();
    f.record(recordedBundle());
    f.history.close();
    using reopened = RecordedAttentionHistory.open({
      path: f.path,
      receiptVerifier: f.receiptVerifier,
    });
    f.clock.now = "2026-10-21T14:00:30.000Z";
    const input = recordedBundle({
      acquiredAt: "2026-10-21T14:00:00.000Z",
      posts: [{ id: "2", text: `Research ${ADDRESS_A}` }],
    });
    const preview = reopened.preview(input, f.context());
    if (preview.kind !== "preview") throw new Error("expected preview");
    const result = reopened.record({
      input,
      expected: preview.binding,
      authorization: f.authorize(preview.binding),
    });
    expect(result.assessment.rows[0]?.outcome).toMatchObject({
      kind: "watch",
      reasons: ["STALE_X"],
    });
    expect(result.assessment.sourceSummary.x).toMatchObject({
      validUntil: "2026-10-21T14:00:10.000Z",
    });
  });

  it("returns only the last twenty headers without dropping durable history", () => {
    const f = fixture();
    for (let index = 0; index < 22; index += 1) {
      f.clock.now = new Date(Date.parse(NOW) + index * 1_000).toISOString();
      f.record(
        recordedBundle({
          acquiredAt: new Date(
            Date.parse("2026-10-21T12:00:00.000Z") + index * 1_000,
          ).toISOString(),
          candidates: [],
          x: { kind: "absent" },
        }),
      );
    }
    const view = f.history.read(f.clock.now);
    if (view.kind !== "available") throw new Error("expected available");
    expect(view.history).toHaveLength(20);
    expect(view.history[0]?.head.sequence).toBe(22);
    expect(view.history.at(-1)?.head.sequence).toBe(3);
    expect(events(f.path)).toHaveLength(22);
  });

  it("rejects new retained facts at capacity before requesting or consuming authority", () => {
    const f = fixture();
    for (let batch = 0; batch < 50; batch += 1) {
      const acquiredAt = new Date(
        Date.parse("2026-10-21T12:00:00.000Z") + batch * 1_000,
      ).toISOString();
      f.clock.now = new Date(Date.parse(acquiredAt) + 30_000).toISOString();
      f.record(
        recordedBundle({
          acquiredAt,
          candidates: [],
          posts: Array.from({ length: 10 }, (_, index) => ({
            id: String(batch * 10 + index),
            text: `Unbound observation ${batch * 10 + index}`,
          })),
        }),
      );
    }
    const before = f.runtime.listAudit();
    const input = recordedBundle({
      acquiredAt: "2026-10-21T12:00:50.000Z",
      candidates: [],
      posts: [{ id: "500", text: "One excess observation" }],
    });
    f.clock.now = "2026-10-21T12:01:20.000Z";
    expect(() => f.preview(input)).toThrow("attention_input_invalid");
    expect(f.runtime.listAudit()).toEqual(before);
    expect(events(f.path)).toHaveLength(50);
    expect(f.history.read(f.clock.now).kind).toBe("available");
  }, 30_000);

  it("verifies receipts with no attention lock held and acquires runtime before the commit lock", () => {
    const f = fixture();
    f.record(recordedBundle());
    const original = SqliteEventStore.prototype.withExclusiveTransaction;
    const locks: string[] = [];
    const seen: string[][] = [];
    vi.spyOn(SqliteEventStore.prototype, "withExclusiveTransaction").mockImplementation(function <
      T,
    >(this: SqliteEventStore, operation: () => T): T {
      if (this.path === f.runtimePath) expect(locks).not.toContain(f.path);
      locks.push(this.path);
      seen.push([...locks]);
      try {
        return original.call(this, operation) as T;
      } finally {
        locks.pop();
      }
    });
    f.clock.now = "2026-10-21T12:01:30.000Z";
    f.record(recordedBundle({ acquiredAt: "2026-10-21T12:01:00.000Z" }));
    f.history.read(f.clock.now);
    expect(seen).toContainEqual([f.runtimePath, f.path]);
    expect(seen).toContainEqual([f.runtimePath]);
    expect(locks).toEqual([]);
  });

  it.each(["authorizationId", "eventHash", "eventSequence"] as const)(
    "rejects reused or reversed authorization %s during full replay",
    (field) => {
      const f = fixture();
      f.record(recordedBundle());
      f.clock.now = "2026-10-21T12:01:30.000Z";
      f.record(recordedBundle({ acquiredAt: "2026-10-21T12:01:00.000Z" }));
      const [first, second] = events(f.path);
      if (first === undefined || second === undefined) throw new Error("missing events");
      const firstPayload = AttentionRecordedEventSchema.parse(first.payload);
      const secondPayload = AttentionRecordedEventSchema.parse(second.payload);
      Object.assign(secondPayload.result.authorization, {
        [field]: firstPayload.result.authorization[field],
      });
      const path = join(f.root, `reused-${field}.sqlite`);
      using store = new SqliteEventStore(path);
      store.append(eventInput(first));
      store.append({ ...eventInput(second), payload: secondPayload });
      expect(() =>
        RecordedAttentionHistory.open({ path, receiptVerifier: f.receiptVerifier }),
      ).toThrow("attention_history_inconsistent");
    },
  );

  it("never saves or returns raw text, post IDs, URLs, or internal source facts", () => {
    const f = fixture();
    const text = `Private observation ${ADDRESS_A} https://untrusted.example/private-path`;
    const input = recordedBundle({ posts: [{ id: "987654321987654321", text }] });
    const preview = f.preview(input);
    const result = f.history.record({
      input,
      expected: preview.binding,
      authorization: f.authorize(preview.binding),
    });
    const view = f.history.read(NOW);
    for (const output of [preview, result, view]) {
      expect(JSON.stringify(output)).not.toContain("sourceFacts");
      expect(JSON.stringify(output)).not.toContain("nextFacts");
    }
    f.history.close();
    const stored = JSON.stringify(events(f.path)) + readFileSync(f.path).toString("utf8");
    const publicOutput = JSON.stringify([preview, result, view]);
    for (const secret of [
      "Private observation",
      "987654321987654321",
      "untrusted.example",
      "private-path",
      '"text":',
    ]) {
      expect(stored).not.toContain(secret);
      expect(publicOutput).not.toContain(secret);
    }
  });

  it("rejects sanitized input at every public ingestion boundary", () => {
    const f = fixture();
    const input = recordedBundle();
    const sanitized = sanitizeRecordedAttentionBundle(input);
    const expected = f.preview(input).binding;
    expect(() => f.history.preview(sanitized, f.context())).toThrow("attention_input_invalid");
    expect(() => f.history.findRecorded(sanitized)).toThrow("attention_input_invalid");
    expect(() =>
      f.history.record({ input: sanitized, expected, authorization: f.authorize(expected) }),
    ).toThrow("attention_input_invalid");
  });

  it.each(["type", "aggregateId", "eventId", "idempotencyKey", "occurredAt"] as const)(
    "rejects a hash-consistent wrong event envelope %s",
    (field) => {
      const f = fixture();
      f.record(recordedBundle());
      const event = events(f.path)[0];
      if (event === undefined) throw new Error("missing event");
      const path = join(f.root, `bad-${field}.sqlite`);
      using store = new SqliteEventStore(path);
      store.append({
        ...eventInput(event),
        [field]: field === "occurredAt" ? "2026-10-21T12:00:31.000Z" : "wrong",
      });
      expect(() =>
        RecordedAttentionHistory.open({ path, receiptVerifier: f.receiptVerifier }),
      ).toThrow();
    },
  );

  it.each([
    "assessment",
    "facts",
    "decision",
    "predecessor",
    "receipt",
    "policy",
    "checkpoint",
    "source",
  ] as const)("rejects hash-consistent %s corruption", (mutation) => {
    const f = fixture();
    f.record(recordedBundle());
    const event = events(f.path)[0];
    if (event === undefined) throw new Error("missing event");
    const payload = AttentionRecordedEventSchema.parse(event.payload);
    switch (mutation) {
      case "assessment":
        payload.result.assessment.rows[0]!.nextAction = "continue_recorded_observation";
        break;
      case "facts":
        payload.nextFacts.latestUsableRankWindow = null;
        break;
      case "decision":
        payload.result.binding.decisionHash = "f".repeat(64);
        break;
      case "predecessor":
        payload.result.assessment.predecessorId = payload.result.assessment.refreshId;
        break;
      case "receipt":
        payload.result.authorization.eventHash = "f".repeat(64);
        break;
      case "policy":
        Object.assign(payload.result.binding, { policyVersion: "unknown-policy" });
        break;
      case "checkpoint":
        payload.result.checkpointAt = "2026-10-21T12:02:00.000Z";
        break;
      case "source":
        payload.sourceFacts.marketplace.hasNextPage = true;
        break;
    }
    const path = join(f.root, `bad-${mutation}.sqlite`);
    using store = new SqliteEventStore(path);
    store.append({ ...eventInput(event), payload });
    expect(() =>
      RecordedAttentionHistory.open({ path, receiptVerifier: f.receiptVerifier }),
    ).toThrow();
  });

  it("fails closed on live database tampering and inconsistent runtime restore", () => {
    const f = fixture();
    f.record(recordedBundle());
    const otherRuntime = SqliteRuntimeController.open(
      {
        path: join(f.root, "restored-runtime.sqlite"),
        openedAt: NOW,
        processInstanceId: randomUUID(),
      },
      { clock: () => NOW },
    );
    closeables.push(otherRuntime);
    expect(() =>
      RecordedAttentionHistory.open({
        path: f.path,
        receiptVerifier: createRuntimeAttentionReceiptVerifier(otherRuntime),
      }),
    ).toThrow("no exact durable event");
    using runtimeDb = new DatabaseSync(f.runtimePath);
    runtimeDb.exec("UPDATE rsi_events SET event_type = 'corrupt' WHERE sequence = 3");
    expect(() => f.history.read(NOW)).toThrow();
  });

  it("fails closed on attention hash corruption and unknown appended events", () => {
    const f = fixture();
    f.record(recordedBundle());
    using db = new DatabaseSync(f.path);
    db.exec(
      "UPDATE rsi_events SET event_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE sequence = 1",
    );
    expect(() => f.history.read(NOW)).toThrow();
    const g = fixture();
    using store = new SqliteEventStore(g.path);
    store.append({
      type: "unknown",
      aggregateId: "attention:recorded-base",
      occurredAt: NOW,
      payload: {},
    });
    expect(() => g.history.read(NOW)).toThrow();
  });

  it("rejects oversized history and payload before replaying unprocessable state", () => {
    const f = fixture();
    const path = join(f.root, "overflow.sqlite");
    using store = new SqliteEventStore(path);
    store.withExclusiveTransaction(() => {
      for (let index = 0; index <= MAX_ATTENTION_HISTORY; index += 1)
        store.append({
          type: "unknown",
          aggregateId: "attention:recorded-base",
          occurredAt: NOW,
          payload: {},
        });
    });
    expect(() =>
      RecordedAttentionHistory.open({ path, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_full");
    const largePath = join(f.root, "large.sqlite");
    using largeStore = new SqliteEventStore(largePath);
    largeStore.append({
      type: "unknown",
      aggregateId: "attention:recorded-base",
      occurredAt: NOW,
      payload: { padding: "x".repeat(MAX_ATTENTION_EVENT_BYTES) },
    });
    expect(() =>
      RecordedAttentionHistory.open({ path: largePath, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_event_too_large");
  });
});
