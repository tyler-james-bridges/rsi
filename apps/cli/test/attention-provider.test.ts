import { randomUUID } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AttentionHistoryError,
  AttentionOperatorPreviewSchema,
  AttentionOperatorResultSchema,
  AttentionOperatorViewSchema,
  createRuntimeAttentionReceiptVerifier,
  RecordedAttentionHistory,
  type RecordedAttentionBundleV1,
} from "@rsi/attention";
import { RuntimeConflictError, SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it } from "vitest";

import { createAttentionProvider, type AttentionHistoryPort } from "../src/attention-provider.js";

const FIXTURE_URL = new URL(
  "../../../packages/attention/fixtures/recorded-mixed.json",
  import.meta.url,
);

function currentMixedFixture(evaluatedAt: string): RecordedAttentionBundleV1 {
  const original = JSON.parse(readFileSync(FIXTURE_URL, "utf8")) as RecordedAttentionBundleV1;
  const acquiredAt = new Date(Date.parse(evaluatedAt) - 30_000).toISOString();
  const validUntil = new Date(Date.parse(acquiredAt) + 120_000).toISOString();
  return {
    ...original,
    marketplace: { ...original.marketplace, acquiredAt, validUntil },
    x:
      original.x.kind === "recorded_posts"
        ? {
            ...original.x,
            acquiredAt: new Date(Date.parse(acquiredAt) + 10_000).toISOString(),
          }
        : original.x,
    base:
      original.base.kind === "reported_finalized_head"
        ? {
            ...original.base,
            acquiredAt: new Date(Date.parse(acquiredAt) + 20_000).toISOString(),
            blockTimestamp: new Date(Date.parse(acquiredAt) + 15_000).toISOString(),
          }
        : original.base,
  };
}

describe("recorded attention operator provider", () => {
  let directory: string | undefined;

  afterEach(() => {
    if (directory !== undefined) rmSync(directory, { force: true, recursive: true });
    directory = undefined;
  });

  it("reads empty state while stopped and returns exact duplicates without new authority", () => {
    directory = mkdtempSync(join(tmpdir(), "rsi-attention-provider-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const attentionPath = join(directory, "attention.sqlite");
    let currentAt = new Date().toISOString();
    const input = currentMixedFixture(currentAt);
    let runtime = SqliteRuntimeController.open(
      { path: runtimePath, openedAt: currentAt, processInstanceId: randomUUID() },
      { clock: () => currentAt, monotonicClock: () => 0 },
    );
    let history = RecordedAttentionHistory.open({
      path: attentionPath,
      receiptVerifier: createRuntimeAttentionReceiptVerifier(runtime),
    });
    let closing = false;
    let provider = createAttentionProvider({
      runtime,
      history,
      isClosing: () => closing,
      now: () => currentAt,
    });

    const empty = AttentionOperatorViewSchema.parse(provider.readAttention());
    expect(empty).toMatchObject({ kind: "available", latest: null, rows: [], history: [] });
    expect(() => provider.previewAttention(input)).toThrow(RuntimeConflictError);

    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: runtime.getSnapshot().revision,
      occurredAt: currentAt,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const preview = AttentionOperatorPreviewSchema.parse(provider.previewAttention(input));
    if (preview.kind !== "preview") throw new Error("expected a new attention preview");
    const result = AttentionOperatorResultSchema.parse(
      provider.recordAttention(input, preview.binding),
    );
    expect(result.assessment.rows.map((row) => row.outcome.kind).sort()).toEqual([
      "rejected",
      "review",
      "watch",
    ]);
    expect(JSON.stringify(result)).not.toContain('"authorization"');
    const boundaryCount = () =>
      runtime.listAudit().filter((event) => event.type === "runtime.boundary.checked.v1").length;
    expect(boundaryCount()).toBe(1);

    currentAt = new Date(Date.parse(currentAt) + 1_000).toISOString();
    runtime.stop({ occurredAt: currentAt, requestId: randomUUID() });
    const stoppedPreview = AttentionOperatorPreviewSchema.parse(provider.previewAttention(input));
    expect(stoppedPreview).toEqual({ schemaVersion: 2, kind: "already_recorded", result });
    expect(provider.recordAttention(input, result.binding)).toEqual(result);
    expect(boundaryCount()).toBe(1);

    history.close();
    runtime.close();
    currentAt = new Date(Date.parse(currentAt) + 1_000).toISOString();
    runtime = SqliteRuntimeController.open(
      { path: runtimePath, openedAt: currentAt, processInstanceId: randomUUID() },
      { clock: () => currentAt, monotonicClock: () => 0 },
    );
    history = RecordedAttentionHistory.open({
      path: attentionPath,
      receiptVerifier: createRuntimeAttentionReceiptVerifier(runtime),
    });
    provider = createAttentionProvider({
      runtime,
      history,
      isClosing: () => closing,
      now: () => currentAt,
    });
    const restartedAuditLength = runtime.listAudit().length;
    expect(provider.recordAttention(input, result.binding)).toEqual(result);
    expect(runtime.listAudit()).toHaveLength(restartedAuditLength);

    closing = true;
    expect(() => provider.readAttention()).toThrow(RuntimeConflictError);
    expect(() => provider.previewAttention(input)).toThrow(RuntimeConflictError);
    expect(() => provider.recordAttention(input, result.binding)).toThrow(RuntimeConflictError);
    history.close();
    runtime.close();
  });

  it("rejects a preview from an earlier runtime revision before requesting authority", () => {
    directory = mkdtempSync(join(tmpdir(), "rsi-attention-provider-stale-"));
    const evaluatedAt = new Date().toISOString();
    const input = currentMixedFixture(evaluatedAt);
    using runtime = SqliteRuntimeController.open(
      {
        path: join(directory, "runtime.sqlite"),
        openedAt: evaluatedAt,
        processInstanceId: randomUUID(),
      },
      { clock: () => evaluatedAt, monotonicClock: () => 0 },
    );
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 1,
      occurredAt: evaluatedAt,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    using history = RecordedAttentionHistory.open({
      path: join(directory, "attention.sqlite"),
      receiptVerifier: createRuntimeAttentionReceiptVerifier(runtime),
    });
    const provider = createAttentionProvider({
      runtime,
      history,
      isClosing: () => false,
      now: () => evaluatedAt,
    });
    const preview = AttentionOperatorPreviewSchema.parse(provider.previewAttention(input));
    if (preview.kind !== "preview") throw new Error("expected a new attention preview");
    runtime.stop({ occurredAt: evaluatedAt, requestId: randomUUID() });
    runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: 3,
      occurredAt: evaluatedAt,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    const before = runtime.listAudit();

    expect(() => provider.recordAttention(input, preview.binding)).toThrow(RuntimeConflictError);
    expect(runtime.listAudit()).toEqual(before);
    expect(() => provider.previewAttention({ invalid: true })).toThrow("attention_input_invalid");
  });

  it("translates only recoverable history conflicts", () => {
    directory = mkdtempSync(join(tmpdir(), "rsi-attention-provider-conflict-"));
    const evaluatedAt = new Date().toISOString();
    const input = currentMixedFixture(evaluatedAt);
    using runtime = SqliteRuntimeController.open(
      {
        path: join(directory, "runtime.sqlite"),
        openedAt: evaluatedAt,
        processInstanceId: randomUUID(),
      },
      { clock: () => evaluatedAt, monotonicClock: () => 0 },
    );
    let conflict = "attention_history_full";
    const history: AttentionHistoryPort = {
      findRecorded: () => {
        throw new AttentionHistoryError(conflict);
      },
      preview: () => {
        throw new Error("preview must not run");
      },
      record: () => {
        throw new Error("record must not run");
      },
      read: () => {
        throw new Error("read must not run");
      },
    };
    const provider = createAttentionProvider({
      runtime,
      history,
      isClosing: () => false,
      now: () => evaluatedAt,
    });
    for (conflict of [
      "attention_history_changed",
      "attention_history_full",
      "attention_identity_reused",
    ]) {
      expect(() => provider.previewAttention(input)).toThrow(RuntimeConflictError);
    }
    conflict = "attention_history_inconsistent";
    expect(() => provider.previewAttention(input)).toThrow(AttentionHistoryError);
  });
});
