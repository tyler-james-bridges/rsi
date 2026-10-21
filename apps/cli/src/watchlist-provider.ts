import { randomUUID } from "node:crypto";

import type { OperatorWatchlistProvider } from "@rsi/operator";
import { RuntimeConflictError, type SqliteRuntimeController } from "@rsi/runtime";
import {
  parseOfflineBaseWatchlistSnapshot,
  parseWatchlistConfirmCommand,
  parseWatchlistPreview,
  parseWatchlistPreviewBinding,
  parseWatchlistPreviewCommand,
  parseWatchlistResult,
  parseWatchlistView,
  snapshotId,
  WatchlistConflictError,
  type OfflineBaseWatchlist,
} from "@rsi/watchlist";

function translateWatchlistConflict<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof WatchlistConflictError) {
      throw new RuntimeConflictError("STALE_STATE", "Watchlist state changed; preview again");
    }
    throw error;
  }
}

export function createWatchlistProvider(
  options: Readonly<{
    runtime: SqliteRuntimeController;
    watchlist: OfflineBaseWatchlist;
    isClosing: () => boolean;
    now?: () => string;
  }>,
): OperatorWatchlistProvider {
  const now = options.now ?? (() => new Date().toISOString());
  const activeRuntime = () => {
    if (options.isClosing())
      throw new RuntimeConflictError("STALE_STATE", "Watchlist host is closing");
    const runtime = options.runtime.getSnapshot();
    if (
      runtime.mode !== "RESEARCH" ||
      runtime.processInstanceId !== options.runtime.processInstanceId
    )
      throw new RuntimeConflictError(
        "STALE_STATE",
        "Watchlist imports require this process in RESEARCH",
      );
    return runtime;
  };
  return Object.freeze({
    parsePreviewCommand: parseWatchlistPreviewCommand,
    parseConfirmCommand: parseWatchlistConfirmCommand,
    parsePreview: parseWatchlistPreview,
    parseResult: parseWatchlistResult,
    parseView: parseWatchlistView,
    previewWatchlist(input: unknown) {
      return translateWatchlistConflict(() => {
        const runtime = activeRuntime();
        return options.watchlist.preview(input, {
          evaluatedAt: now(),
          processInstanceId: runtime.processInstanceId,
          modeRevision: runtime.revision,
        });
      });
    },
    confirmWatchlist(input: unknown, expectedValue: unknown) {
      return translateWatchlistConflict(() => {
        const snapshot = parseOfflineBaseWatchlistSnapshot(input);
        const expected = parseWatchlistPreviewBinding(expectedValue);
        const runtime = activeRuntime();
        if (
          snapshotId(snapshot) !== expected.snapshotId ||
          runtime.processInstanceId !== expected.processInstanceId ||
          runtime.revision !== expected.modeRevision
        )
          throw new RuntimeConflictError("STALE_STATE", "Watchlist preview is stale");
        const authorization = options.runtime.requestBoundaryAuthorization({
          actionId: expected.snapshotId,
          authorizationId: randomUUID(),
          boundary: "watchlist_import",
        });
        return options.watchlist.importSnapshot({ input: snapshot, expected, authorization });
      });
    },
    readWatchlist() {
      return translateWatchlistConflict(() => options.watchlist.read(now()));
    },
  });
}
