import { describe, expect, it } from "vitest";

import {
  parseWatchlistPreviewCommand,
  parseWatchlistResult,
  parseWatchlistView,
} from "../src/operator-protocol.js";

describe("watchlist HTTP protocol", () => {
  const view = {
    schemaVersion: 1,
    provenance: "operator_supplied_unverified",
    evaluatedAt: "2026-10-20T00:00:00.000Z",
    head: null,
    stale: false,
    partial: false,
    rows: [],
    history: [],
  };

  it("rejects unknown output and command fields", () => {
    expect(parseWatchlistView(view)).toEqual(view);
    expect(() => parseWatchlistView({ ...view, secret: "not-permitted" })).toThrow();
    expect(() => parseWatchlistPreviewCommand({ path: "local.json" })).toThrow();
    expect(() =>
      parseWatchlistResult({
        snapshotId: "a".repeat(64),
        predecessorId: null,
        importedAt: view.evaluatedAt,
        duplicate: false,
        extra: true,
      }),
    ).toThrow();
  });

  it("rejects accessor and proxy responses without invoking them", () => {
    let invoked = false;
    const accessor = { ...view };
    Object.defineProperty(accessor, "rows", {
      enumerable: true,
      get: () => {
        invoked = true;
        return [];
      },
    });
    expect(() => parseWatchlistView(accessor)).toThrow();
    expect(() =>
      parseWatchlistView(
        new Proxy(view, {
          get() {
            invoked = true;
            return undefined;
          },
        }),
      ),
    ).toThrow();
    expect(invoked).toBe(false);
  });

  it("rejects shared response objects before schema traversal", () => {
    const shared: unknown[] = [];
    expect(() => parseWatchlistView({ ...view, rows: [shared, shared] })).toThrow(
      "shared references",
    );
  });
});
