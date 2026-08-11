import type { IntegrityReport } from "./types.js";

export type EventConflictCode =
  "EVENT_ID_CONFLICT" | "EVENT_ID_IDEMPOTENCY_MISMATCH" | "IDEMPOTENCY_KEY_CONFLICT";

export class EventConflictError extends Error {
  readonly code: EventConflictCode;

  constructor(code: EventConflictCode, message: string) {
    super(message);
    this.name = "EventConflictError";
    this.code = code;
  }
}

export class EventStoreClosedError extends Error {
  constructor() {
    super("The event store is closed");
    this.name = "EventStoreClosedError";
  }
}

export class EventStoreIntegrityError extends Error {
  readonly report: IntegrityReport;

  constructor(report: IntegrityReport) {
    const summary = report.errors
      .slice(0, 3)
      .map((issue) => issue.code)
      .join(", ");
    super(`Event-store integrity verification failed${summary === "" ? "" : `: ${summary}`}`);
    this.name = "EventStoreIntegrityError";
    this.report = report;
  }
}

export class InvalidEventError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidEventError";
  }
}
