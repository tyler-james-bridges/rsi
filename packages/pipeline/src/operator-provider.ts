import type {
  OperatorEventPage,
  OperatorEventQuery,
  OperatorSnapshotProvider,
} from "@rsi/operator";
import {
  EventStoreIntegrityError,
  type JsonValue,
  type SqliteEventStore,
  type StoredEvent,
} from "@rsi/store";

function assertIntegrity(store: SqliteEventStore): void {
  const report = store.verifyIntegrity();
  if (!report.valid) throw new EventStoreIntegrityError(report);
}

function objectPayload(event: StoredEvent): Record<string, JsonValue> | undefined {
  return event.payload !== null &&
    !Array.isArray(event.payload) &&
    typeof event.payload === "object"
    ? (event.payload as Record<string, JsonValue>)
    : undefined;
}

function eventDecisionId(event: StoredEvent): string | undefined {
  const payload = objectPayload(event);
  if (payload === undefined) return undefined;
  if (typeof payload.decisionId === "string") return payload.decisionId;
  const decision = payload.decision;
  if (decision !== null && !Array.isArray(decision) && typeof decision === "object") {
    const candidate = decision as Record<string, JsonValue>;
    return typeof candidate.decisionId === "string" ? candidate.decisionId : undefined;
  }
  return undefined;
}

function cursorSequence(cursor: string | undefined): number | undefined {
  if (cursor === undefined) return undefined;
  const match = /^seq:(\d+)$/.exec(cursor);
  const value = match?.[1] === undefined ? Number.NaN : Number(match[1]);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("invalid event cursor");
  return value;
}

export class SqliteOperatorSnapshotProvider implements OperatorSnapshotProvider {
  constructor(readonly store: SqliteEventStore) {}

  getSummary(): unknown {
    const integrity = this.store.verifyIntegrity();
    if (!integrity.valid) {
      return {
        status: "integrity-failure",
        integrity,
        runs: null,
        decisions: null,
      };
    }
    const decisions = this.store.list({ type: "policy.decided" });
    const completedRuns = this.store.list({ type: "run.completed" });
    let approved = 0;
    let rejected = 0;
    for (const event of decisions) {
      const decision = objectPayload(event)?.decision;
      if (decision !== null && !Array.isArray(decision) && typeof decision === "object") {
        const flag = (decision as Record<string, JsonValue>).approved;
        if (flag === true) approved += 1;
        if (flag === false) rejected += 1;
      }
    }
    return {
      status: integrity.valid ? "ok" : "integrity-failure",
      integrity,
      runs: completedRuns.length,
      decisions: { approved, rejected, total: decisions.length },
    };
  }

  listEvents(query: Readonly<OperatorEventQuery>): OperatorEventPage {
    assertIntegrity(this.store);
    const beforeSequence = cursorSequence(query.cursor);
    let events = [
      ...this.store.list({
        ...(beforeSequence === undefined ? {} : { beforeSequence }),
        ...(query.type === undefined ? {} : { type: query.type }),
        order: "desc",
      }),
    ];
    if (query.decisionId !== undefined) {
      events = events.filter((event) => eventDecisionId(event) === query.decisionId);
    }
    if (query.since !== undefined) {
      events = events.filter((event) => event.occurredAt >= query.since!);
    }
    if (query.until !== undefined) {
      events = events.filter((event) => event.occurredAt <= query.until!);
    }

    const items = events.slice(0, query.limit);
    const hasMore = events.length > query.limit;
    return {
      items,
      nextCursor: hasMore && items.length > 0 ? `seq:${items[items.length - 1]!.sequence}` : null,
    };
  }

  getDecision(id: string): unknown | null {
    assertIntegrity(this.store);
    const event = this.store
      .list({ type: "policy.decided", order: "desc" })
      .find((candidate) => eventDecisionId(candidate) === id);
    return event === undefined ? null : (objectPayload(event)?.decision ?? null);
  }
}
