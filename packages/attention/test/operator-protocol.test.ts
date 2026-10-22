import { randomUUID } from "node:crypto";

import { SqliteRuntimeController } from "@rsi/runtime";
import { describe, expect, it } from "vitest";

import {
  RecordedAttentionHistory,
  attentionPreviewActionId,
  createRuntimeAttentionReceiptVerifier,
  parseAttentionPreviewCommand,
  parseAttentionRecordCommand,
  parseAttentionPreview,
  parseAttentionResult,
  parseAttentionView,
} from "../src/index.js";
import { recordedBundle } from "./fixtures.js";

const NOW = "2026-10-21T12:00:30.000Z";

describe("attention operator protocol", () => {
  it("round trips strict commands, previews, immutable results, and views without wire authority", () => {
    using runtime = SqliteRuntimeController.open(
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
    using history = RecordedAttentionHistory.open({
      path: ":memory:",
      receiptVerifier: createRuntimeAttentionReceiptVerifier(runtime),
    });
    const input = recordedBundle();
    expect(parseAttentionPreviewCommand({ input })).toEqual({ input });
    const preview = history.preview(input, {
      processInstanceId: runtime.getSnapshot().processInstanceId,
      modeRevision: 2,
      evaluatedAt: NOW,
    });
    if (preview.kind !== "preview") throw new Error("expected preview");
    expect(parseAttentionPreview(JSON.parse(JSON.stringify(preview)))).toEqual(preview);
    const command = { input, expected: preview.binding };
    expect(parseAttentionRecordCommand(command)).toEqual(command);
    const authorization = runtime.requestBoundaryAuthorization({
      boundary: "attention_refresh",
      actionId: attentionPreviewActionId(preview.binding),
      authorizationId: randomUUID(),
    });
    expect(() => parseAttentionRecordCommand({ ...command, authorization })).toThrow();
    expect(() =>
      parseAttentionRecordCommand({
        ...command,
        authorization: JSON.parse(JSON.stringify(authorization)),
      }),
    ).toThrow();
    const result = history.record({ ...command, authorization });
    expect(parseAttentionResult(JSON.parse(JSON.stringify(result)))).toEqual(result);
    expect(
      parseAttentionPreview(
        history.preview(input, {
          processInstanceId: runtime.getSnapshot().processInstanceId,
          modeRevision: 2,
          evaluatedAt: NOW,
        }),
      ),
    ).toEqual({ schemaVersion: 2, kind: "already_recorded", result });
    for (const at of [NOW, "2026-10-21T12:02:00.000Z", "2026-10-21T12:00:00.000Z"]) {
      const view = history.read(at);
      expect(parseAttentionView(JSON.parse(JSON.stringify(view)))).toEqual(view);
      expect(() => parseAttentionView({ ...view, extra: true })).toThrow();
    }
    expect(() => parseAttentionPreview({ ...preview, sourceFacts: {} })).toThrow();
    expect(() => parseAttentionResult({ ...result, rawText: "untrusted" })).toThrow();
    expect(() =>
      parseAttentionResult({ ...result, checkpointAt: "2026-10-21T12:00:00.000Z" }),
    ).toThrow();
    const view = history.read("2026-10-21T12:02:00.000Z");
    if (view.kind !== "available") throw new Error("expected available");
    const changed = structuredClone(view);
    changed.rows[0]!.effectiveOutcome = { kind: "review", priority: 45 };
    expect(() => parseAttentionView(changed)).toThrow();
  });

  it("rejects proxies, accessors, unknown keys, and provenance claims before traversal", () => {
    let read = false;
    const accessor = {};
    Object.defineProperty(accessor, "input", {
      enumerable: true,
      get: () => {
        read = true;
        return recordedBundle();
      },
    });
    for (const parse of [
      parseAttentionPreviewCommand,
      parseAttentionRecordCommand,
      parseAttentionPreview,
      parseAttentionResult,
      parseAttentionView,
    ]) {
      expect(() => parse(accessor)).toThrow();
      expect(() => parse(new Proxy({}, {}))).toThrow();
    }
    expect(read).toBe(false);
    expect(() =>
      parseAttentionPreviewCommand({ input: recordedBundle(), authenticated: true }),
    ).toThrow();
    expect(() =>
      parseAttentionPreviewCommand({ input: { ...recordedBundle(), provenance: "authenticated" } }),
    ).toThrow();
  });
});
