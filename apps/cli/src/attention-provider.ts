import { randomUUID } from "node:crypto";

import type { OperatorAttentionProvider } from "@rsi/operator";
import { RuntimeConflictError, type SqliteRuntimeController } from "@rsi/runtime";
import {
  AttentionHistoryError,
  attentionPreviewActionId,
  parseAttentionPreviewBinding,
  parseAttentionPreviewCommand,
  parseAttentionRecordCommand,
  projectAttentionOperatorPreview,
  projectAttentionOperatorResult,
  projectAttentionOperatorView,
  type AttentionPreview,
  type AttentionPreviewContext,
  type AttentionRecordCommand,
  type AttentionRecordResult,
  type AttentionView,
} from "@rsi/attention";

const RECOVERABLE_ATTENTION_CONFLICTS = new Set([
  "attention_authority_mismatch",
  "attention_authorization_reused",
  "attention_classification_changed",
  "attention_history_changed",
  "attention_history_full",
  "attention_history_mismatch",
  "attention_identity_reused",
  "attention_preview_capacity_reached",
  "attention_preview_expired",
  "attention_preview_lease_mismatch",
  "attention_preview_lease_missing",
  "attention_preview_mismatch",
  "attention_preview_stale",
  "clock_regressed",
]);

function translateAttentionConflict<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof AttentionHistoryError && RECOVERABLE_ATTENTION_CONFLICTS.has(error.code)) {
      throw new RuntimeConflictError("STALE_STATE", "Recorded attention state changed");
    }
    throw error;
  }
}

export interface AttentionHistoryPort {
  findRecorded(input: unknown): AttentionRecordResult | null;
  preview(input: unknown, context: AttentionPreviewContext): AttentionPreview;
  record(command: AttentionRecordCommand): AttentionRecordResult;
  read(evaluatedAt: string): AttentionView;
}

export function createAttentionProvider(
  options: Readonly<{
    runtime: SqliteRuntimeController;
    history: AttentionHistoryPort;
    isClosing: () => boolean;
    now?: () => string;
  }>,
): OperatorAttentionProvider {
  const now = options.now ?? (() => new Date().toISOString());
  const assertHostOpen = (): void => {
    if (options.isClosing()) {
      throw new RuntimeConflictError(
        "STALE_STATE",
        "Recorded attention is unavailable while the Stage 0 host is closing",
      );
    }
  };
  const activeRuntime = () => {
    const snapshot = options.runtime.getSnapshot();
    if (
      snapshot.mode !== "RESEARCH" ||
      snapshot.processInstanceId !== options.runtime.processInstanceId
    ) {
      throw new RuntimeConflictError(
        "STALE_STATE",
        "Recorded attention changes require this process in RESEARCH",
      );
    }
    return snapshot;
  };

  return Object.freeze({
    parsePreviewCommand: parseAttentionPreviewCommand,
    parseRecordCommand: parseAttentionRecordCommand,
    projectPreview: projectAttentionOperatorPreview,
    projectResult: projectAttentionOperatorResult,
    projectView: projectAttentionOperatorView,
    previewAttention(input: unknown): unknown {
      assertHostOpen();
      return translateAttentionConflict(() => {
        const existing = options.history.findRecorded(input);
        if (existing !== null) {
          return projectAttentionOperatorPreview({
            schemaVersion: 2,
            kind: "already_recorded",
            result: existing,
          });
        }
        const runtime = activeRuntime();
        return projectAttentionOperatorPreview(
          options.history.preview(input, {
            processInstanceId: runtime.processInstanceId,
            modeRevision: runtime.revision,
            evaluatedAt: now(),
          }),
        );
      });
    },
    recordAttention(input: unknown, expectedValue: unknown): unknown {
      assertHostOpen();
      return translateAttentionConflict(() => {
        const expected = parseAttentionPreviewBinding(expectedValue);
        const existing = options.history.findRecorded(input);
        if (existing !== null) {
          if (attentionPreviewActionId(existing.binding) !== attentionPreviewActionId(expected)) {
            throw new AttentionHistoryError("attention_preview_mismatch");
          }
          return projectAttentionOperatorResult(existing);
        }
        const runtime = activeRuntime();
        if (
          runtime.processInstanceId !== expected.processInstanceId ||
          runtime.revision !== expected.modeRevision
        ) {
          throw new RuntimeConflictError("STALE_STATE", "Recorded attention preview is stale");
        }
        const authorization = options.runtime.requestBoundaryAuthorization({
          boundary: "attention_refresh",
          actionId: attentionPreviewActionId(expected),
          authorizationId: randomUUID(),
        });
        return projectAttentionOperatorResult(
          options.history.record({ input, expected, authorization }),
        );
      });
    },
    readAttention(): unknown {
      assertHostOpen();
      return translateAttentionConflict(() =>
        projectAttentionOperatorView(options.history.read(now())),
      );
    },
  });
}
