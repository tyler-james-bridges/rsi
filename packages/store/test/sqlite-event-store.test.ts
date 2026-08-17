import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  canonicalJson,
  EventConflictError,
  EventStoreIntegrityError,
  InvalidEventError,
  SqliteEventStore,
  isSqliteEventStore,
} from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

function makeDatabasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "rsi-event-store-"));
  temporaryDirectories.push(directory);
  return join(directory, "events.sqlite");
}

describe("canonicalJson", () => {
  it("sorts keys recursively while preserving array order", () => {
    expect(canonicalJson({ z: 1, a: { y: true, b: [3, { d: null, c: "value" }] } })).toBe(
      '{"a":{"b":[3,{"c":"value","d":null}],"y":true},"z":1}',
    );
  });

  it("rejects values that JSON would silently coerce", () => {
    expect(() => canonicalJson({ value: Number.NaN })).toThrow();
    expect(() => canonicalJson({ value: undefined } as never)).toThrow();
  });
});

describe("SqliteEventStore", () => {
  it("appends a monotonic, hash-linked event chain", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    expect(isSqliteEventStore(store)).toBe(true);
    expect(isSqliteEventStore(Object.create(SqliteEventStore.prototype))).toBe(false);
    expect(isSqliteEventStore({ append: () => undefined })).toBe(false);
    const first = store.append({
      aggregateId: "research:base",
      eventId: "event-1",
      occurredAt: "2026-08-11T01:02:03Z",
      payload: { source: "x", score: 0.8 },
      type: "claim.observed",
    });
    const second = store.append({
      aggregateId: "research:base",
      eventId: "event-2",
      occurredAt: "2026-08-11T01:03:03.000Z",
      payload: { score: 0.9, source: "onchain" },
      type: "claim.corroborated",
    });

    expect(first.sequence).toBe(1);
    expect(first.previousHash).toBe("0".repeat(64));
    expect(first.occurredAt).toBe("2026-08-11T01:02:03.000Z");
    expect(first.eventHash).toMatch(/^[0-9a-f]{64}$/);
    expect(second.sequence).toBe(2);
    expect(second.previousHash).toBe(first.eventHash);
    expect(store.verifyIntegrity()).toMatchObject({
      errors: [],
      eventCount: 2,
      headHash: second.eventHash,
      headSequence: 2,
      valid: true,
    });
    expect(() => {
      (first.payload as { source: string }).source = "tampered";
    }).toThrow();
    store.close();
  });

  it("persists events and verifies the chain when reopened", () => {
    const path = makeDatabasePath();
    const firstStore = new SqliteEventStore(path);
    const appended = firstStore.append({
      aggregateId: "strategy:rsi-v1",
      idempotencyKey: "strategy-rsi-v1-proposed",
      occurredAt: "2026-08-11T02:00:00.000Z",
      payload: { version: 1 },
      type: "strategy.proposed",
    });
    firstStore.close();

    const reopened = new SqliteEventStore(path);
    expect(reopened.getByEventId(appended.eventId)).toEqual(appended);
    expect(reopened.getByIdempotencyKey("strategy-rsi-v1-proposed")).toEqual(appended);
    expect(reopened.getByIdempotencyKey("missing-key")).toBeUndefined();
    expect(reopened.verifyIntegrity().valid).toBe(true);
    reopened.close();
  });

  it("filters by type, aggregate and exclusive sequence boundaries", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    store.append({
      aggregateId: "agent:a",
      eventId: "event-1",
      payload: { n: 1 },
      type: "run.started",
    });
    store.append({
      aggregateId: "agent:b",
      eventId: "event-2",
      payload: { n: 2 },
      type: "run.started",
    });
    store.append({
      aggregateId: "agent:a",
      eventId: "event-3",
      payload: { n: 3 },
      type: "run.completed",
    });

    expect(store.list({ type: "run.started" }).map((event) => event.eventId)).toEqual([
      "event-1",
      "event-2",
    ]);
    expect(store.list({ aggregateId: "agent:a" }).map((event) => event.eventId)).toEqual([
      "event-1",
      "event-3",
    ]);
    expect(
      store
        .list({ afterSequence: 1, beforeSequence: 4, limit: 1, order: "desc" })
        .map((event) => event.eventId),
    ).toEqual(["event-3"]);
    store.close();
  });

  it("returns the original event for an exact eventId retry", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    const input = {
      aggregateId: "agent:rsi",
      eventId: "stable-event-id",
      payload: { state: "quarantined" },
      type: "claim.ingested",
    } as const;

    const first = store.append(input);
    const retried = store.append(input);

    expect(retried).toEqual(first);
    expect(store.list()).toHaveLength(1);
    store.close();
  });

  it("deduplicates retries by idempotency key and rejects changed content", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    const input = {
      aggregateId: "agent:rsi",
      idempotencyKey: "x-post-1234",
      payload: { postId: "1234" },
      type: "claim.ingested",
    } as const;

    const first = store.append(input);
    expect(store.append(input)).toEqual(first);
    expect(() => store.append({ ...input, payload: { postId: "changed" } })).toThrow(
      EventConflictError,
    );
    expect(store.list()).toHaveLength(1);
    store.close();
  });

  it("serializes a synchronous read/decide/append block across store instances", () => {
    const path = makeDatabasePath();
    const first = new SqliteEventStore(path);
    const second = new SqliteEventStore(path);

    first.withExclusiveTransaction(() => {
      expect(first.list()).toHaveLength(0);
      first.append({
        aggregateId: "policy:fixture",
        payload: { spend: "10000000" },
        type: "policy.decided",
      });
    });
    second.withExclusiveTransaction(() => {
      expect(second.list({ type: "policy.decided" })).toHaveLength(1);
      second.append({
        aggregateId: "policy:fixture",
        payload: { spend: "5000000" },
        type: "policy.decided",
      });
    });

    expect(first.verifyIntegrity()).toMatchObject({ valid: true, eventCount: 2 });
    first.close();
    second.close();
  });

  it("rolls back a failed exclusive transaction and rejects async callbacks before invocation", () => {
    const store = new SqliteEventStore(makeDatabasePath());

    expect(() =>
      store.withExclusiveTransaction(() => {
        store.append({ aggregateId: "run:failed", payload: {}, type: "run.started" });
        throw new Error("abort");
      }),
    ).toThrow("abort");
    expect(store.list()).toEqual([]);

    let invoked = false;
    expect(() =>
      store.withExclusiveTransaction(async () => {
        invoked = true;
      }),
    ).toThrow("must be synchronous");
    expect(invoked).toBe(false);
    expect(store.verifyIntegrity()).toMatchObject({ valid: true, eventCount: 0 });
    store.close();
  });

  it("invalidates promise continuations created inside an exclusive transaction", async () => {
    const store = new SqliteEventStore(makeDatabasePath());
    let continuationWasBlocked = false;

    expect(() =>
      store.withExclusiveTransaction(() =>
        Promise.resolve().then(() => {
          try {
            store.append({
              aggregateId: "run:escaped",
              payload: {},
              type: "policy.decided",
            });
          } catch (error) {
            continuationWasBlocked =
              error instanceof Error && error.message.includes("escaped its synchronous scope");
          }
        }),
      ),
    ).toThrow("must be synchronous");

    await Promise.resolve();
    expect(continuationWasBlocked).toBe(true);
    expect(store.verifyIntegrity()).toMatchObject({ valid: true, eventCount: 0 });
    store.close();
  });

  it("cannot commit around a caught append conflict inside an exclusive transaction", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    store.append({
      aggregateId: "run:one",
      idempotencyKey: "fixed-key",
      payload: { value: 1 },
      type: "run.started",
    });

    expect(() =>
      store.withExclusiveTransaction(() => {
        try {
          store.append({
            aggregateId: "run:one",
            idempotencyKey: "fixed-key",
            payload: { value: 2 },
            type: "run.started",
          });
        } catch {
          // A caller cannot swallow a failed write and commit later events.
        }
        store.append({ aggregateId: "run:two", payload: {}, type: "run.started" });
      }),
    ).toThrow("failed append");
    expect(store.list()).toHaveLength(1);
    store.close();
  });

  it("rejects a reused eventId with changed content without a partial append", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    store.append({
      aggregateId: "agent:rsi",
      eventId: "event-1",
      payload: { decision: "abstain" },
      type: "decision.recorded",
    });

    expect(() =>
      store.append({
        aggregateId: "agent:rsi",
        eventId: "event-1",
        payload: { decision: "execute" },
        type: "decision.recorded",
      }),
    ).toThrow(EventConflictError);
    expect(store.list()).toHaveLength(1);
    expect(store.verifyIntegrity().valid).toBe(true);
    store.close();
  });

  it("detects direct payload tampering before reopening", () => {
    const path = makeDatabasePath();
    const store = new SqliteEventStore(path);
    store.append({
      aggregateId: "agent:rsi",
      eventId: "event-1",
      payload: { verdict: "blocked" },
      type: "policy.decided",
    });
    store.close();

    const attacker = new DatabaseSync(path);
    attacker
      .prepare("UPDATE rsi_events SET payload_json = ? WHERE sequence = 1")
      .run('{"verdict":"approved"}');
    attacker.close();

    expect(() => new SqliteEventStore(path)).toThrow(EventStoreIntegrityError);
  });

  it("detects deletion of the chain tail through the persisted head anchor", () => {
    const path = makeDatabasePath();
    const store = new SqliteEventStore(path);
    for (const eventId of ["event-1", "event-2"]) {
      store.append({
        aggregateId: "agent:rsi",
        eventId,
        payload: { eventId },
        type: "run.recorded",
      });
    }
    store.close();

    const attacker = new DatabaseSync(path);
    attacker.prepare("DELETE FROM rsi_events WHERE sequence = 2").run();
    attacker.close();

    expect(() => new SqliteEventStore(path)).toThrowError(
      expect.objectContaining({
        report: expect.objectContaining({
          valid: false,
          errors: expect.arrayContaining([
            expect.objectContaining({ code: "HEAD_SEQUENCE_MISMATCH" }),
          ]),
        }),
      }),
    );
  });

  it("validates identifiers, filters and payloads", () => {
    const store = new SqliteEventStore(makeDatabasePath());
    expect(() => store.append({ aggregateId: " ", payload: {}, type: "event.invalid" })).toThrow(
      InvalidEventError,
    );
    expect(() =>
      store.append({
        aggregateId: "agent:rsi",
        payload: { amount: Number.POSITIVE_INFINITY },
        type: "event.invalid",
      }),
    ).toThrow(InvalidEventError);
    expect(() => store.list({ limit: 0 })).toThrow(InvalidEventError);
    expect(store.list()).toEqual([]);
    store.close();
  });
});
