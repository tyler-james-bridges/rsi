import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

import {
  SqliteRuntimeController,
  type RuntimeAllowedAttentionRefreshReceipt,
  type RuntimeBoundaryAuthorization,
} from "@rsi/runtime";
import { SqliteEventStore, type AppendEventInput, type StoredEvent } from "@rsi/store";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ATTENTION_PREVIEW_TTL_MS,
  MAX_ATTENTION_EVENT_BYTES,
  MAX_ATTENTION_HISTORY,
  MAX_LIVE_ATTENTION_PREVIEWS,
  RecordedAttentionHistory,
  AttentionPreviewBindingSchema,
  attentionPreviewActionId,
  createRuntimeAttentionReceiptVerifier,
  emptyRecordedAttentionFacts,
  type AttentionPreviewBinding,
  type AttentionRecordCommand,
  type RecordedAttentionBundleV1,
  type RecordedAttentionFactsV1,
} from "../src/index.js";
import { assessStoredRecordedAttention } from "../src/assess.js";
import {
  AttentionHistoryInitializedEventSchema,
  AttentionReceiptSchema,
  AttentionRecordedEventSchema,
  buildAttentionRecordedEvent,
  buildLargestValidAttentionRecordedEvent,
  decisionHash,
  serialize,
} from "../src/history-schemas.js";
import { sanitizeRecordedAttentionBundle } from "../src/sanitize.js";
import { ADDRESS_A, ADDRESS_B, candidate, mixedFixture, recordedBundle } from "./fixtures.js";

const NOW = "2026-10-21T12:00:30.000Z";
const directories: string[] = [];
const closeables: { close(): void }[] = [];

function differentHash(value: string): string {
  return `${value.startsWith("f") ? "e" : "f"}${value.slice(1)}`;
}

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
  const leaseClock = { now: 0, reads: 0, samples: [] as number[], fail: false };
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
  const history = RecordedAttentionHistory.open({
    path,
    receiptVerifier,
    monotonicClock: () => {
      leaseClock.reads += 1;
      if (leaseClock.fail) throw new Error("read must not consult the lease clock");
      return leaseClock.samples.shift() ?? leaseClock.now;
    },
  });
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
      actionId: attentionPreviewActionId(expected),
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
    leaseClock,
    runtime,
    receiptVerifier,
    history,
    context,
    preview,
    authorize,
    record,
  };
}

function rawEvents(path: string): readonly StoredEvent[] {
  using store = new SqliteEventStore(path);
  return store.list();
}

function events(path: string): readonly StoredEvent[] {
  return rawEvents(path).filter((event) => event.type === "attention.batch.recorded.v2");
}

function recordedEventDraft(evaluatedAt: string) {
  const acquiredAt = new Date(Date.parse(evaluatedAt) - 30_000).toISOString();
  const sourceFacts = sanitizeRecordedAttentionBundle(
    recordedBundle({ acquiredAt, x: { kind: "absent" } }),
  );
  const assessed = assessStoredRecordedAttention({ sourceFacts, evaluatedAt });
  const binding = AttentionPreviewBindingSchema.parse({
    schemaVersion: 2,
    kind: "attention_preview_binding",
    policyVersion: "attention-v2",
    historyId: "00000000-0000-4000-8000-000000000001",
    previewId: "00000000-0000-4000-8000-000000000002",
    bundleId: assessed.assessment.bundleId,
    refreshId: assessed.assessment.refreshId,
    auditHead: null,
    processInstanceId: "00000000-0000-4000-8000-000000000003",
    modeRevision: Number.MAX_SAFE_INTEGER,
    evaluatedAt,
    deadline: new Date(Date.parse(evaluatedAt) + ATTENTION_PREVIEW_TTL_MS).toISOString(),
    decisionHash: decisionHash(assessed),
  });
  return { sourceFacts, binding, assessed };
}

function recordedEventReceipt(
  draft: ReturnType<typeof recordedEventDraft>,
  checkedAt: string,
  eventSequence: number,
): RuntimeAllowedAttentionRefreshReceipt {
  return {
    schemaVersion: 1,
    actionId: attentionPreviewActionId(draft.binding),
    authorizationId: "00000000-0000-4000-8000-000000000004",
    boundary: "attention_refresh",
    checkedAt,
    decision: "allowed",
    eventHash: "0".repeat(64),
    eventSequence,
    mode: "RESEARCH",
    modeRevision: draft.binding.modeRevision,
    processInstanceId: draft.binding.processInstanceId,
    reason: "ALLOWED",
  };
}

function maximumWidthCandidates(
  batch: number,
): RecordedAttentionBundleV1["marketplace"]["candidates"] {
  return Array.from({ length: 10 }, (_, rankIndex) => {
    const collectionIndex = batch * 10 + rankIndex;
    const slugPrefix = `c${collectionIndex.toString().padStart(6, "0")}-`;
    return candidate(
      rankIndex + 1,
      `${slugPrefix}${"z".repeat(128 - slugPrefix.length)}`,
      Array.from({ length: 16 }, (_unused, contractIndex) => {
        const addressIndex = collectionIndex * 16 + contractIndex + 1;
        return `0x${addressIndex.toString(16).padStart(40, "0")}`;
      }),
    );
  });
}

type RecordedHistorySeedResult =
  | Readonly<{ kind: "complete"; appended: number }>
  | Readonly<{ kind: "oversized"; appended: number; input: RecordedAttentionBundleV1 }>;

function seedRecordedHistory(
  f: ReturnType<typeof fixture>,
  batchCount: number,
  buildBatch: (
    batch: number,
  ) => Readonly<{ evaluatedAt: string; input: RecordedAttentionBundleV1 }>,
): RecordedHistorySeedResult {
  const genesis = rawEvents(f.path)[0];
  const initialized = AttentionHistoryInitializedEventSchema.parse(genesis?.payload);
  const runtimeSnapshot = f.runtime.getSnapshot();
  let auditHead: AttentionPreviewBinding["auditHead"] = null;
  let priorFacts: RecordedAttentionFactsV1 = emptyRecordedAttentionFacts();
  using store = new SqliteEventStore(f.path);

  for (let batch = 0; batch < batchCount; batch += 1) {
    const { evaluatedAt, input } = buildBatch(batch);
    const sourceFacts = sanitizeRecordedAttentionBundle(input);
    const assessed = assessStoredRecordedAttention({ sourceFacts, evaluatedAt, priorFacts });
    const binding = AttentionPreviewBindingSchema.parse({
      schemaVersion: 2,
      kind: "attention_preview_binding",
      policyVersion: "attention-v2",
      historyId: initialized.historyId,
      previewId: randomUUID(),
      bundleId: assessed.assessment.bundleId,
      refreshId: assessed.assessment.refreshId,
      auditHead,
      processInstanceId: runtimeSnapshot.processInstanceId,
      modeRevision: runtimeSnapshot.revision,
      evaluatedAt,
      deadline: new Date(Date.parse(evaluatedAt) + ATTENTION_PREVIEW_TTL_MS).toISOString(),
      decisionHash: decisionHash(assessed),
    });
    const largest = buildLargestValidAttentionRecordedEvent({
      sourceFacts,
      binding,
      assessed,
    });
    if (Buffer.byteLength(serialize(largest), "utf8") > MAX_ATTENTION_EVENT_BYTES) {
      f.clock.now = evaluatedAt;
      return { kind: "oversized", appended: batch, input };
    }

    f.clock.now = evaluatedAt;
    f.runtime
      .requestBoundaryAuthorization({
        boundary: "attention_refresh",
        actionId: attentionPreviewActionId(binding),
        authorizationId: randomUUID(),
      })
      .consumeAndCommit((receipt, checkpoint) => {
        const checkpointAt = checkpoint().checkedAt;
        const payload = buildAttentionRecordedEvent({
          sourceFacts,
          binding,
          assessed,
          authorization: AttentionReceiptSchema.parse(receipt),
          checkpointAt,
        });
        expect(Buffer.byteLength(serialize(payload), "utf8")).toBeLessThanOrEqual(
          MAX_ATTENTION_EVENT_BYTES,
        );
        const event = store.append({
          type: "attention.batch.recorded.v2",
          aggregateId: "attention:recorded-base",
          eventId: `attention-batch-v2:${binding.refreshId}`,
          idempotencyKey: `attention-batch-v2:${binding.refreshId}`,
          occurredAt: checkpointAt,
          payload,
        });
        auditHead = {
          refreshId: binding.refreshId,
          eventHash: event.eventHash,
          sequence: event.sequence,
        };
      });
    priorFacts = assessed.nextFacts;
  }

  return { kind: "complete", appended: batchCount };
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

function appendGenesis(store: SqliteEventStore, sourcePath: string): void {
  const genesis = rawEvents(sourcePath)[0];
  if (genesis === undefined || genesis.type !== "attention.history.initialized.v1") {
    throw new Error("missing attention genesis");
  }
  store.append(eventInput(genesis));
}

function runOpenProcess(attentionPath: string, runtimePath: string): Promise<void> {
  const script = fileURLToPath(new URL("./open-history-child.ts", import.meta.url));
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", script, attentionPath, runtimePath], {
      cwd: join(import.meta.dirname, "../../.."),
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`open child failed (${String(code ?? signal)}): ${stderr}`));
    });
  });
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
      policyVersion: "attention-v2",
      auditHead: null,
      evaluatedAt: NOW,
      deadline: "2026-10-21T12:01:00.000Z",
    });
    const secondPreview = f.preview(input);
    expect(secondPreview).toMatchObject({ assessment: preview.assessment });
    if (secondPreview.kind !== "preview") throw new Error("expected a new preview");
    expect(secondPreview.binding.previewId).not.toBe(preview.binding.previewId);
    expect(attentionPreviewActionId(secondPreview.binding)).not.toBe(
      attentionPreviewActionId(preview.binding),
    );
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
    const sourceFacts = sanitizeRecordedAttentionBundle(input);
    expect(payload).toEqual(
      buildAttentionRecordedEvent({
        sourceFacts,
        binding: result.binding,
        assessed: assessStoredRecordedAttention({
          sourceFacts,
          evaluatedAt: result.binding.evaluatedAt,
        }),
        authorization: result.authorization,
        checkpointAt: result.checkpointAt,
      }),
    );
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

    const stored = rawEvents(f.path);
    expect(stored).toHaveLength(2);
    expect(stored[0]).toMatchObject({
      sequence: 1,
      type: "attention.history.initialized.v1",
      payload: {
        schemaVersion: 1,
        kind: "attention_history_initialized",
        historyId: preview.binding.historyId,
      },
    });
    expect(stored[1]).toMatchObject({
      sequence: 2,
      type: "attention.batch.recorded.v2",
      payload: { schemaVersion: 2, kind: "attention_batch_recorded" },
    });
    expect(result).toMatchObject({ schemaVersion: 2, binding: { schemaVersion: 2 } });
    expect(result.authorization.actionId).toBe(attentionPreviewActionId(result.binding));
    expect(view.kind === "available" ? view.auditHead?.sequence : null).toBe(2);
  });

  it.each([
    ["ordinary year", "2026-10-21T12:00:30.000Z"],
    ["extended year", "+010000-01-01T00:00:00.000Z"],
    ["year-width crossing", "9999-12-31T23:59:45.000Z"],
  ] as const)("builds a schema-valid maximum event that dominates valid %s receipts", (_, at) => {
    const draft = recordedEventDraft(at);
    const largest = buildLargestValidAttentionRecordedEvent(draft);
    expect(AttentionRecordedEventSchema.parse(largest)).toEqual(largest);
    expect(largest.result.authorization).toMatchObject({
      actionId: attentionPreviewActionId(draft.binding),
      eventSequence: Number.MAX_SAFE_INTEGER,
      modeRevision: draft.binding.modeRevision,
      processInstanceId: draft.binding.processInstanceId,
    });

    const lastValidTime = new Date(Date.parse(draft.binding.deadline) - 1).toISOString();
    const widestTime =
      Buffer.byteLength(draft.binding.evaluatedAt, "utf8") >=
      Buffer.byteLength(lastValidTime, "utf8")
        ? draft.binding.evaluatedAt
        : lastValidTime;
    expect(largest.result.authorization.checkedAt).toBe(widestTime);
    expect(largest.result.checkpointAt).toBe(widestTime);

    for (const checkedAt of [draft.binding.evaluatedAt, lastValidTime]) {
      for (const eventSequence of [1, Number.MAX_SAFE_INTEGER]) {
        const actual = buildAttentionRecordedEvent({
          ...draft,
          authorization: recordedEventReceipt(draft, checkedAt, eventSequence),
          checkpointAt: checkedAt,
        });
        expect(Buffer.byteLength(serialize(actual), "utf8")).toBeLessThanOrEqual(
          Buffer.byteLength(serialize(largest), "utf8"),
        );
      }
    }
  });

  it("rejects a valid oversized event during preview without consuming runtime authority", () => {
    const f = fixture();
    const seeded = seedRecordedHistory(f, 50, (batch) => {
      const acquiredAt = new Date(Date.parse(NOW) + batch * 180_000).toISOString();
      return {
        evaluatedAt: new Date(Date.parse(acquiredAt) + 30_000).toISOString(),
        input: recordedBundle({
          acquiredAt,
          candidates: maximumWidthCandidates(batch),
          x: { kind: "absent" },
        }),
      };
    });
    if (seeded.kind !== "oversized") {
      throw new Error("maximum valid attention history did not reach the event limit");
    }
    const before = f.runtime.listAudit();
    expect(() => f.preview(seeded.input)).toThrowError(
      expect.objectContaining({ code: "attention_event_too_large" }),
    );
    expect(f.runtime.listAudit()).toEqual(before);
  }, 30_000);

  it("initializes one durable lineage and appends nothing on an empty reopen", () => {
    const f = fixture();
    const [genesis] = rawEvents(f.path);
    if (genesis === undefined) throw new Error("missing genesis");
    f.history.close();
    const append = vi.spyOn(SqliteEventStore.prototype, "append");
    using reopened = RecordedAttentionHistory.open({
      path: f.path,
      receiptVerifier: f.receiptVerifier,
      monotonicClock: () => 0,
    });
    expect(reopened.read(NOW)).toMatchObject({ kind: "available", latest: null });
    expect(rawEvents(f.path)).toEqual([genesis]);
    expect(append).not.toHaveBeenCalled();
  });

  it("retains lineage when a closed database is copied", () => {
    const f = fixture();
    const saved = f.record(recordedBundle());
    f.history.close();
    const copiedPath = join(f.root, "copied-attention.sqlite");
    copyFileSync(f.path, copiedPath);
    using original = RecordedAttentionHistory.open({
      path: f.path,
      receiptVerifier: f.receiptVerifier,
      monotonicClock: () => 0,
    });
    using copied = RecordedAttentionHistory.open({
      path: copiedPath,
      receiptVerifier: f.receiptVerifier,
      monotonicClock: () => 0,
    });
    expect(copied.findRecorded(recordedBundle())).toEqual(saved);
    const nextInput = recordedBundle({ candidates: [], x: { kind: "absent" } });
    const originalPreview = original.preview(nextInput, f.context());
    const copiedPreview = copied.preview(nextInput, f.context());
    if (originalPreview.kind !== "preview" || copiedPreview.kind !== "preview") {
      throw new Error("expected new previews");
    }
    expect(copiedPreview.binding.historyId).toBe(originalPreview.binding.historyId);
    expect(copiedPreview.binding.auditHead).toEqual(originalPreview.binding.auditHead);
    expect(copiedPreview.binding.previewId).not.toBe(originalPreview.binding.previewId);
  });

  it("serializes concurrent first opens into one genesis event", async () => {
    const root = directory();
    const attentionPath = join(root, "shared-attention.sqlite");
    await Promise.all([
      runOpenProcess(attentionPath, join(root, "runtime-a.sqlite")),
      runOpenProcess(attentionPath, join(root, "runtime-b.sqlite")),
    ]);
    expect(rawEvents(attentionPath)).toMatchObject([
      { sequence: 1, type: "attention.history.initialized.v1" },
    ]);
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
      actionId: attentionPreviewActionId(expected),
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
          verifyPersistedAttentionRefreshReceipts: () => {
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
      "attention_history_mismatch",
    );
    expect(other.runtime.listAudit()).toEqual(before);
    expect(events(f.path)).toEqual([]);
    expect(other.history.record({ input, expected, authorization })).toMatchObject({
      binding: expected,
    });
    expect(events(other.path)).toHaveLength(1);
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
      actionId: attentionPreviewActionId(expected),
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
      actionId: attentionPreviewActionId(expected),
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
    ).toThrow("attention_preview_mismatch");
    f.record(changed);
    expect(() =>
      f.history.record({ input, expected: original, authorization: f.authorize(original) }),
    ).toThrow("attention_preview_stale");
    expect(events(f.path)).toHaveLength(1);
  });

  it("commits every mutable V2 binding field into the preview action", () => {
    const fixedBinding = AttentionPreviewBindingSchema.parse({
      schemaVersion: 2,
      kind: "attention_preview_binding",
      policyVersion: "attention-v2",
      historyId: "00000000-0000-4000-8000-000000000001",
      previewId: "00000000-0000-4000-8000-000000000002",
      bundleId: "1".repeat(64),
      refreshId: "2".repeat(64),
      auditHead: { refreshId: "3".repeat(64), eventHash: "4".repeat(64), sequence: 6 },
      processInstanceId: "00000000-0000-4000-8000-000000000003",
      modeRevision: 7,
      evaluatedAt: "2026-10-21T12:00:00.000Z",
      deadline: "2026-10-21T12:00:30.000Z",
      decisionHash: "5".repeat(64),
    });
    expect(attentionPreviewActionId(fixedBinding)).toBe(
      "attention-preview-v2:d025e5c0f6cd90308349220ed504bec1cd9e1d7345da9170da5d763149778720",
    );

    const f = fixture();
    const input = recordedBundle();
    const original = f.preview(input).binding;
    const shiftedEvaluatedAt = new Date(Date.parse(original.evaluatedAt) + 1).toISOString();
    const shiftedDeadline = new Date(Date.parse(original.deadline) + 1).toISOString();
    const mutations: ReadonlyArray<readonly [string, unknown]> = [
      ["historyId", { ...original, historyId: randomUUID() }],
      ["previewId", { ...original, previewId: randomUUID() }],
      ["bundleId", { ...original, bundleId: differentHash(original.bundleId) }],
      ["refreshId", { ...original, refreshId: differentHash(original.refreshId) }],
      [
        "auditHead",
        {
          ...original,
          auditHead: {
            refreshId: original.refreshId,
            eventHash: "f".repeat(64),
            sequence: 1,
          },
        },
      ],
      ["processInstanceId", { ...original, processInstanceId: randomUUID() }],
      ["modeRevision", { ...original, modeRevision: original.modeRevision + 1 }],
      [
        "evaluatedAt/deadline",
        { ...original, evaluatedAt: shiftedEvaluatedAt, deadline: shiftedDeadline },
      ],
      ["decisionHash", { ...original, decisionHash: differentHash(original.decisionHash) }],
    ];
    const originalAction = attentionPreviewActionId(original);
    for (const [field, value] of mutations) {
      const mutated = AttentionPreviewBindingSchema.parse(value);
      expect(attentionPreviewActionId(mutated), field).not.toBe(originalAction);
      const authorization = f.authorize(original);
      const before = f.runtime.listAudit();
      expect(() => f.history.record({ input, expected: mutated, authorization }), field).toThrow();
      expect(f.runtime.listAudit(), field).toEqual(before);
    }
    for (const invalid of [
      { ...original, schemaVersion: 1 },
      { ...original, kind: "other" },
      { ...original, policyVersion: "attention-v1" },
      {
        ...original,
        deadline: new Date(Date.parse(original.deadline) + 1).toISOString(),
      },
    ]) {
      expect(() => AttentionPreviewBindingSchema.parse(invalid)).toThrow();
    }
    expect(
      f.history.record({ input, expected: original, authorization: f.authorize(original) }),
    ).toMatchObject({ binding: original });

    f.clock.now = "2026-10-21T12:01:30.000Z";
    const next = f.preview(
      recordedBundle({
        acquiredAt: "2026-10-21T12:01:00.000Z",
        candidates: [],
        x: { kind: "absent" },
      }),
    ).binding;
    if (next.auditHead === null) throw new Error("expected a committed audit head");
    const actionWithHead = attentionPreviewActionId(next);
    for (const [field, auditHead] of [
      [
        "auditHead.refreshId",
        { ...next.auditHead, refreshId: differentHash(next.auditHead.refreshId) },
      ],
      [
        "auditHead.eventHash",
        { ...next.auditHead, eventHash: differentHash(next.auditHead.eventHash) },
      ],
      ["auditHead.sequence", { ...next.auditHead, sequence: next.auditHead.sequence + 1 }],
    ] as const) {
      const mutated = AttentionPreviewBindingSchema.parse({ ...next, auditHead });
      expect(attentionPreviewActionId(mutated), field).not.toBe(actionWithHead);
    }
  });

  it("rejects old permits and old heads after an intervening commit without extra writes", () => {
    const f = fixture();
    const delayedInput = recordedBundle({
      candidates: [],
      x: { kind: "absent" },
    });
    const oldBinding = f.preview(delayedInput).binding;
    const oldAuthorization = f.authorize(oldBinding);
    f.record(recordedBundle());
    f.clock.now = "2026-10-21T12:01:30.000Z";
    const newInput = recordedBundle({
      acquiredAt: "2026-10-21T12:01:00.000Z",
      candidates: [],
      x: { kind: "absent" },
    });
    const newBinding = f.preview(newInput).binding;
    const before = f.runtime.listAudit();
    expect(() =>
      f.history.record({
        input: newInput,
        expected: newBinding,
        authorization: oldAuthorization,
      }),
    ).toThrow("attention_authority_mismatch");
    expect(f.runtime.listAudit()).toEqual(before);
    expect(events(f.path)).toHaveLength(1);
    expect(() =>
      f.history.record({
        input: delayedInput,
        expected: oldBinding,
        authorization: oldAuthorization,
      }),
    ).toThrow("attention_preview_stale");
    expect(f.runtime.listAudit()).toEqual(before);
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

  it("accepts a frozen-wall preview at 29,999ms and rejects it at 30,000ms", () => {
    const beforeDeadline = fixture();
    const firstInput = recordedBundle();
    const firstBinding = beforeDeadline.preview(firstInput).binding;
    beforeDeadline.leaseClock.now = 29_999;
    expect(
      beforeDeadline.history.record({
        input: firstInput,
        expected: firstBinding,
        authorization: beforeDeadline.authorize(firstBinding),
      }),
    ).toMatchObject({ binding: firstBinding });

    const atDeadline = fixture();
    const secondInput = recordedBundle();
    const secondBinding = atDeadline.preview(secondInput).binding;
    const authorization = atDeadline.authorize(secondBinding);
    const before = atDeadline.runtime.listAudit();
    atDeadline.leaseClock.now = 30_000;
    expect(() =>
      atDeadline.history.record({
        input: secondInput,
        expected: secondBinding,
        authorization,
      }),
    ).toThrow("attention_preview_expired");
    expect(atDeadline.runtime.listAudit()).toEqual(before);
    expect(events(atDeadline.path)).toEqual([]);
  });

  it.each([
    ["after the attention lock", [29_999, 30_000]],
    ["immediately before append", [29_999, 29_999, 30_000]],
  ] as const)("rechecks a lease %s", (_label, samples) => {
    const f = fixture();
    const input = recordedBundle();
    const expected = f.preview(input).binding;
    const authorization = f.authorize(expected);
    f.leaseClock.samples = [...samples];
    expect(() => f.history.record({ input, expected, authorization })).toThrow(
      "attention_preview_expired",
    );
    expect(events(f.path)).toEqual([]);
    expect(
      f.runtime
        .listAudit()
        .filter(
          (event) =>
            event.type === "runtime.boundary.checked.v1" &&
            event.payload.authorizationId === authorization.authorizationId,
        ),
    ).toHaveLength(1);
  });

  it.each([
    [
      "throwing",
      (): never => {
        throw new Error("clock failed");
      },
      "attention_monotonic_clock_failed",
    ],
    ["negative", (): number => -1, "attention_monotonic_clock_invalid"],
    ["non-finite", (): number => Number.NaN, "attention_monotonic_clock_invalid"],
    [
      "unsafe expiry",
      (): number => Number.MAX_SAFE_INTEGER - ATTENTION_PREVIEW_TTL_MS + 1,
      "attention_monotonic_clock_invalid",
    ],
  ] as const)("rejects a %s monotonic clock", (_label, monotonicClock, code) => {
    const f = fixture();
    using history = RecordedAttentionHistory.open({
      path: join(f.root, `${_label}.sqlite`),
      receiptVerifier: f.receiptVerifier,
      monotonicClock,
    });
    expect(() => history.preview(recordedBundle(), f.context())).toThrow(code);
  });

  it("rejects a regressed monotonic sample", () => {
    const f = fixture();
    f.leaseClock.now = 10;
    f.preview(recordedBundle());
    f.leaseClock.now = 9;
    expect(() => f.preview(recordedBundle({ candidates: [], x: { kind: "absent" } }))).toThrow(
      "attention_monotonic_clock_regressed",
    );
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
      monotonicClock: () => {
        throw new Error("duplicate lookup must not read the lease clock");
      },
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
    expect(preview).toEqual({ schemaVersion: 2, kind: "already_recorded", result });
    expect(history.read("2026-10-21T13:00:00.000Z")).toMatchObject({
      kind: "available",
      latest: result,
    });
    expect(append).not.toHaveBeenCalled();
    expect(runtime.listAudit()).toEqual(before);
    expect(events(f.path)).toHaveLength(1);
  });

  it("invalidates uncommitted previews on restart and close without consuming their permits", () => {
    const restarted = fixture();
    const input = recordedBundle();
    const binding = restarted.preview(input).binding;
    const authorization = restarted.authorize(binding);
    restarted.history.close();
    const auditBeforeRestart = restarted.runtime.listAudit();
    using reopened = RecordedAttentionHistory.open({
      path: restarted.path,
      receiptVerifier: restarted.receiptVerifier,
      monotonicClock: () => 0,
    });
    expect(() => reopened.record({ input, expected: binding, authorization })).toThrow(
      "attention_preview_lease_missing",
    );
    expect(restarted.runtime.listAudit()).toEqual(auditBeforeRestart);
    let restartedPermitUsable = false;
    authorization.consumeAndCommit((_receipt, checkpoint) => {
      checkpoint();
      restartedPermitUsable = true;
    });
    expect(restartedPermitUsable).toBe(true);

    const closed = fixture();
    const closedInput = recordedBundle();
    const closedBinding = closed.preview(closedInput).binding;
    const closedAuthorization = closed.authorize(closedBinding);
    closed.history.close();
    const auditBeforeCloseRetry = closed.runtime.listAudit();
    expect(() =>
      closed.history.record({
        input: closedInput,
        expected: closedBinding,
        authorization: closedAuthorization,
      }),
    ).toThrow("attention_history_unavailable");
    expect(closed.runtime.listAudit()).toEqual(auditBeforeCloseRetry);
  });

  it("fails closed at live-preview capacity without evicting an existing lease", () => {
    const f = fixture();
    const input = recordedBundle();
    const first = f.preview(input).binding;
    for (let index = 1; index < MAX_LIVE_ATTENTION_PREVIEWS; index += 1) f.preview(input);
    expect(() => f.preview(input)).toThrow("attention_preview_capacity_reached");
    expect(
      f.history.record({ input, expected: first, authorization: f.authorize(first) }),
    ).toMatchObject({ binding: first });
  });

  it("prunes expired preview leases before admitting a new one", () => {
    const f = fixture();
    const input = recordedBundle();
    for (let index = 0; index < MAX_LIVE_ATTENTION_PREVIEWS; index += 1) f.preview(input);
    f.leaseClock.now = ATTENTION_PREVIEW_TTL_MS;
    expect(f.preview(input)).toMatchObject({ schemaVersion: 2, kind: "preview" });
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
    const leaseReads = f.leaseClock.reads;
    f.leaseClock.fail = true;
    const append = vi.spyOn(SqliteEventStore.prototype, "append");
    expect(f.history.record({ input, expected, authorization: consumedAuthorization })).toEqual(
      result,
    );
    expect(f.runtime.listAudit()).toEqual(beforeConsumedRetry);
    expect(f.leaseClock.reads).toBe(leaseReads);
    expect(append).not.toHaveBeenCalled();
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
    expect(view.history[0]?.head.sequence).toBe(23);
    expect(view.history.at(-1)?.head.sequence).toBe(4);
    expect(events(f.path)).toHaveLength(22);
  });

  it("rejects new retained facts at capacity before requesting or consuming authority", () => {
    const f = fixture();
    const seeded = seedRecordedHistory(f, 50, (batch) => {
      const acquiredAt = new Date(
        Date.parse("2026-10-21T12:00:00.000Z") + batch * 1_000,
      ).toISOString();
      return {
        evaluatedAt: new Date(Date.parse(acquiredAt) + 30_000).toISOString(),
        input: recordedBundle({
          acquiredAt,
          candidates: [],
          posts: Array.from({ length: 10 }, (_, index) => ({
            id: String(batch * 10 + index),
            text: `Unbound observation ${batch * 10 + index}`,
          })),
        }),
      };
    });
    expect(seeded).toEqual({ kind: "complete", appended: 50 });
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
      appendGenesis(store, f.path);
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

  it("rejects missing, replaced, duplicated, misordered, and legacy genesis histories", () => {
    const f = fixture();
    f.record(recordedBundle());
    const [genesis, batch] = rawEvents(f.path);
    if (genesis === undefined || batch === undefined) throw new Error("missing history events");

    const missingPath = join(f.root, "missing-genesis.sqlite");
    using missing = new SqliteEventStore(missingPath);
    missing.append(eventInput(batch));
    expect(() =>
      RecordedAttentionHistory.open({ path: missingPath, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_inconsistent");

    const replacedPath = join(f.root, "replaced-genesis.sqlite");
    using replaced = new SqliteEventStore(replacedPath);
    replaced.append({ ...eventInput(genesis), type: "unknown" });
    expect(() =>
      RecordedAttentionHistory.open({ path: replacedPath, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_inconsistent");

    const duplicatePath = join(f.root, "duplicate-genesis.sqlite");
    using duplicate = new SqliteEventStore(duplicatePath);
    duplicate.append(eventInput(genesis));
    const duplicateId = randomUUID();
    duplicate.append({
      type: "attention.history.initialized.v1",
      aggregateId: "attention:recorded-base",
      eventId: `attention-history-v1:${duplicateId}`,
      idempotencyKey: `attention-history-v1:${duplicateId}`,
      occurredAt: NOW,
      payload: {
        schemaVersion: 1,
        kind: "attention_history_initialized",
        historyId: duplicateId,
        initializedAt: NOW,
      },
    });
    expect(() =>
      RecordedAttentionHistory.open({ path: duplicatePath, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_inconsistent");

    const misorderedPath = join(f.root, "misordered-genesis.sqlite");
    using misordered = new SqliteEventStore(misorderedPath);
    misordered.append({
      type: "unknown",
      aggregateId: "attention:recorded-base",
      occurredAt: NOW,
      payload: {},
    });
    misordered.append(eventInput(genesis));
    expect(() =>
      RecordedAttentionHistory.open({ path: misorderedPath, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_inconsistent");

    const legacyPath = join(f.root, "legacy.sqlite");
    using legacy = new SqliteEventStore(legacyPath);
    legacy.append({
      type: "attention.batch.recorded.v1",
      aggregateId: "attention:recorded-base",
      occurredAt: NOW,
      payload: {},
    });
    expect(() =>
      RecordedAttentionHistory.open({ path: legacyPath, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_unsupported");
  });

  it.each(["different history ID", "same history ID with a different genesis"] as const)(
    "pins its exact initialized lineage across a self-consistent empty-store replacement: %s",
    (replacementKind) => {
      const f = fixture();
      const originalGenesis = rawEvents(f.path)[0];
      if (originalGenesis === undefined) throw new Error("missing genesis");
      const originalHistoryId = (originalGenesis.payload as { historyId: string }).historyId;
      using database = new DatabaseSync(f.path);
      database.exec(`
      BEGIN IMMEDIATE;
      DELETE FROM rsi_events;
      UPDATE rsi_event_store_metadata
         SET head_sequence = 0,
             head_hash = '${"0".repeat(64)}'
       WHERE singleton = 1;
      COMMIT;
    `);
      const replacementId =
        replacementKind === "different history ID" ? randomUUID() : originalHistoryId;
      const replacementAt = originalGenesis.occurredAt === NOW ? "2026-10-21T12:00:31.000Z" : NOW;
      using replacement = new SqliteEventStore(f.path);
      replacement.append({
        type: "attention.history.initialized.v1",
        aggregateId: "attention:recorded-base",
        eventId: `attention-history-v1:${replacementId}`,
        idempotencyKey: `attention-history-v1:${replacementId}`,
        occurredAt: replacementAt,
        payload: {
          schemaVersion: 1,
          kind: "attention_history_initialized",
          historyId: replacementId,
          initializedAt: replacementAt,
        },
      });
      expect(() => f.history.read(NOW)).toThrow("attention_history_changed");
    },
  );

  it("requires a V2 batch receipt action to match the complete stored binding", () => {
    const f = fixture();
    f.record(recordedBundle());
    const batch = events(f.path)[0];
    if (batch === undefined) throw new Error("missing batch");
    const payload = AttentionRecordedEventSchema.parse(batch.payload);
    Object.assign(payload.result.authorization, {
      actionId: `attention-preview-v2:${"f".repeat(64)}`,
    });
    const path = join(f.root, "wrong-preview-action.sqlite");
    using store = new SqliteEventStore(path);
    appendGenesis(store, f.path);
    store.append({ ...eventInput(batch), payload });
    expect(() =>
      RecordedAttentionHistory.open({ path, receiptVerifier: f.receiptVerifier }),
    ).toThrow("attention_history_inconsistent");
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
      appendGenesis(store, f.path);
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
    appendGenesis(store, f.path);
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

  it("detects corruption before the latest persisted runtime receipt", () => {
    const f = fixture();
    f.record(recordedBundle());
    f.clock.now = "2026-10-21T12:01:30.000Z";
    f.record(recordedBundle({ acquiredAt: "2026-10-21T12:01:00.000Z" }));
    const first = AttentionRecordedEventSchema.parse(events(f.path)[0]?.payload);
    using runtimeDb = new DatabaseSync(f.runtimePath);
    runtimeDb
      .prepare("UPDATE rsi_events SET event_type = 'corrupt' WHERE event_hash = ?")
      .run(first.result.authorization.eventHash);
    expect(() => f.history.read(f.clock.now)).toThrow();
  });

  it("rejects a forged earlier receipt when the latest receipt is genuine", () => {
    const f = fixture();
    f.record(recordedBundle());
    f.clock.now = "2026-10-21T12:01:30.000Z";
    f.record(recordedBundle({ acquiredAt: "2026-10-21T12:01:00.000Z" }));
    const [firstEvent, secondEvent] = events(f.path);
    if (firstEvent === undefined || secondEvent === undefined) {
      throw new Error("missing attention batches");
    }
    const firstPayload = AttentionRecordedEventSchema.parse(firstEvent.payload);
    const secondPayload = AttentionRecordedEventSchema.parse(secondEvent.payload);
    Object.assign(firstPayload.result.authorization, {
      authorizationId: randomUUID(),
      eventHash: differentHash(firstPayload.result.authorization.eventHash),
    });

    const path = join(f.root, "forged-earlier-receipt.sqlite");
    using store = new SqliteEventStore(path);
    appendGenesis(store, f.path);
    const forgedFirst = store.append({ ...eventInput(firstEvent), payload: firstPayload });
    if (secondPayload.result.binding.auditHead === null) {
      throw new Error("missing predecessor head");
    }
    secondPayload.result.binding.auditHead.eventHash = forgedFirst.eventHash;
    const genuineLatest = f
      .authorize(secondPayload.result.binding)
      .consumeAndCommit((_receipt, checkpoint) => {
        checkpoint();
      });
    Object.assign(secondPayload.result, { authorization: genuineLatest });
    store.append({ ...eventInput(secondEvent), payload: secondPayload });
    expect(f.runtime.verifyPersistedAttentionRefreshReceipt(genuineLatest)).toEqual(genuineLatest);
    expect(() =>
      RecordedAttentionHistory.open({ path, receiptVerifier: f.receiptVerifier }),
    ).toThrow("no exact durable event");
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
      appendGenesis(store, f.path);
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
    appendGenesis(largeStore, f.path);
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
