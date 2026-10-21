import { randomUUID } from "node:crypto";

import type { OperatorWatchlistProvider } from "@rsi/operator";
import { RuntimeConflictError, type SqliteRuntimeController } from "@rsi/runtime";
import {
  parseOfflineBaseWatchlistSnapshot,
  parseWatchlistPreviewBinding,
  snapshotId,
  type OfflineBaseWatchlist,
} from "@rsi/watchlist";

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
    previewWatchlist(input: unknown) {
      const runtime = activeRuntime();
      return options.watchlist.preview(input, {
        evaluatedAt: now(),
        processInstanceId: runtime.processInstanceId,
        modeRevision: runtime.revision,
      });
    },
    confirmWatchlist(input: unknown, expectedValue: unknown) {
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
      return options.watchlist.import({ input: snapshot, expected, authorization });
    },
    readWatchlist() {
      return options.watchlist.read(now());
    },
  });
}
