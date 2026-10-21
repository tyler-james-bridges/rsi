import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SqliteRuntimeController } from "../src/index.js";

describe("watchlist import mode table", () => {
  it("rechecks expiry after the authorization receipt commits", () => {
    const now = "2026-10-20T00:00:00.000Z";
    let clockReads = 0;
    const runtime = SqliteRuntimeController.open(
      { path: ":memory:", openedAt: now, processInstanceId: randomUUID() },
      { clock: () => (++clockReads >= 3 ? "2026-10-20T01:00:00.000Z" : now) },
    );
    try {
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: now,
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });
      const permit = runtime.requestBoundaryAuthorization({
        boundary: "watchlist_import",
        actionId: "snapshot",
        authorizationId: randomUUID(),
      });
      let committed = false;
      expect(() =>
        permit.consumeAndCommit(() => {
          committed = true;
        }),
      ).toThrow("changed before commit");
      expect(committed).toBe(false);
      expect(runtime.listAudit().at(-1)?.payload).toMatchObject({
        decision: "allowed",
        authorizationId: permit.authorizationId,
      });
    } finally {
      runtime.close();
    }
  });
  it("permits only RESEARCH and exposes only protected commit", () => {
    const now = "2026-10-20T00:00:00.000Z";
    const runtime = SqliteRuntimeController.open(
      { path: ":memory:", openedAt: now, processInstanceId: randomUUID() },
      { clock: () => now },
    );
    const request = () =>
      runtime.requestBoundaryAuthorization({
        boundary: "watchlist_import",
        actionId: "snapshot",
        authorizationId: randomUUID(),
      });
    try {
      expect(request).toThrow();
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: now,
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });
      const permit = request();
      expect("consume" in permit).toBe(false);
      expect("consumeAndDispatch" in permit).toBe(false);
      let called = false;
      permit.consumeAndCommit((receipt) => {
        called = true;
        expect(receipt.boundary).toBe("watchlist_import");
      });
      expect(called).toBe(true);
      runtime.transition({
        expectedMode: "RESEARCH",
        expectedRevision: 2,
        occurredAt: now,
        requestId: randomUUID(),
        targetMode: "PROPOSE_ONLY",
      });
      expect(request).toThrow();
    } finally {
      runtime.close();
    }
  });
});
