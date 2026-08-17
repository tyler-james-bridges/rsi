import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, deepFreezeJson, InvalidJsonValueError } from "./canonical-json.js";
import {
  EventConflictError,
  EventStoreClosedError,
  EventStoreIntegrityError,
  InvalidEventError,
} from "./errors.js";
import type {
  AppendEventInput,
  EventListFilters,
  IntegrityIssue,
  IntegrityReport,
  JsonValue,
  StoredEvent,
} from "./types.js";

const SCHEMA_VERSION = 1;
const GENESIS_HASH = "0".repeat(64);
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const MAX_IDENTIFIER_BYTES = 512;
const MAX_PAYLOAD_BYTES = 1_048_576;
const authenticSqliteEventStores = new WeakSet<object>();

interface EventRow {
  aggregate_id: string;
  event_hash: string;
  event_id: string;
  event_type: string;
  idempotency_key: string | null;
  occurred_at: string;
  payload_json: string;
  previous_hash: string;
  sequence: number;
}

interface MetadataRow {
  head_hash: string;
  head_sequence: number;
  schema_version: number;
}

interface PreparedEvent {
  aggregateId: string;
  eventId: string | undefined;
  idempotencyKey: string | undefined;
  occurredAt: string;
  occurredAtWasSupplied: boolean;
  payloadJson: string;
  type: string;
}

interface HashFields {
  aggregateId: string;
  eventId: string;
  idempotencyKey: string | null;
  occurredAt: string;
  payloadJson: string;
  previousHash: string;
  sequence: number;
  type: string;
}

interface TransactionScope {
  active: boolean;
}

export class SqliteEventStore {
  readonly path: string;

  private closed = false;
  private exclusiveTransactionActive = false;
  private exclusiveTransactionFailed = false;
  private readonly database: DatabaseSync;
  private readonly transactionScope = new AsyncLocalStorage<TransactionScope>();

  constructor(path: string) {
    if (typeof path !== "string" || path.trim() === "") {
      throw new InvalidEventError("SQLite path must be a non-empty string");
    }

    this.path = path;
    this.database = new DatabaseSync(path);

    try {
      this.configureDatabase();
      this.initializeSchema();
      const report = this.verifyIntegrityInternal();
      if (!report.valid) throw new EventStoreIntegrityError(report);
    } catch (error) {
      this.closed = true;
      this.database.close();
      throw error;
    }
    authenticSqliteEventStores.add(this);
  }

  append(input: AppendEventInput): StoredEvent {
    this.assertOpen();
    const prepared = prepareEvent(input);
    const ownsTransaction = !this.exclusiveTransactionActive;

    if (ownsTransaction) this.database.exec("BEGIN IMMEDIATE");
    try {
      if (ownsTransaction) {
        const report = this.verifyIntegrityInternal();
        if (!report.valid) throw new EventStoreIntegrityError(report);
      }

      const duplicate = this.resolveDuplicate(prepared);
      if (duplicate !== undefined) {
        if (ownsTransaction) this.database.exec("COMMIT");
        return rowToEvent(duplicate);
      }

      const metadata = this.getMetadata();
      if (metadata === undefined) {
        throw new EventStoreIntegrityError(this.verifyIntegrityInternal());
      }

      const sequence = metadata.head_sequence + 1;
      const eventId = prepared.eventId ?? randomUUID();
      const idempotencyKey = prepared.idempotencyKey ?? null;
      const eventHash = computeEventHash({
        aggregateId: prepared.aggregateId,
        eventId,
        idempotencyKey,
        occurredAt: prepared.occurredAt,
        payloadJson: prepared.payloadJson,
        previousHash: metadata.head_hash,
        sequence,
        type: prepared.type,
      });

      this.database
        .prepare(
          `INSERT INTO rsi_events (
             sequence, event_id, idempotency_key, event_type, aggregate_id,
             payload_json, occurred_at, previous_hash, event_hash
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          sequence,
          eventId,
          idempotencyKey,
          prepared.type,
          prepared.aggregateId,
          prepared.payloadJson,
          prepared.occurredAt,
          metadata.head_hash,
          eventHash,
        );

      const metadataUpdate = this.database
        .prepare(
          `UPDATE rsi_event_store_metadata
             SET head_sequence = ?, head_hash = ?
           WHERE singleton = 1 AND head_sequence = ? AND head_hash = ?`,
        )
        .run(sequence, eventHash, metadata.head_sequence, metadata.head_hash);

      if (metadataUpdate.changes !== 1) {
        throw new Error("Event-store head changed during append");
      }

      if (ownsTransaction) this.database.exec("COMMIT");
      return rowToEvent({
        aggregate_id: prepared.aggregateId,
        event_hash: eventHash,
        event_id: eventId,
        event_type: prepared.type,
        idempotency_key: idempotencyKey,
        occurred_at: prepared.occurredAt,
        payload_json: prepared.payloadJson,
        previous_hash: metadata.head_hash,
        sequence,
      });
    } catch (error) {
      if (!ownsTransaction) this.exclusiveTransactionFailed = true;
      if (ownsTransaction && this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  /**
   * Serializes a synchronous read/decide/append block with every other writer
   * to this SQLite database. Calls to append() inside the callback participate
   * in the same transaction. Async callbacks are rejected so the lock cannot
   * be committed while work is still pending.
   */
  withExclusiveTransaction<T>(operation: () => T): T {
    this.assertOpen();
    if (this.exclusiveTransactionActive || this.database.isTransaction) {
      throw new Error("Nested event-store transactions are not supported");
    }
    if (Object.prototype.toString.call(operation) === "[object AsyncFunction]") {
      throw new TypeError("Event-store transactions must be synchronous");
    }

    this.database.exec("BEGIN IMMEDIATE");
    this.exclusiveTransactionActive = true;
    this.exclusiveTransactionFailed = false;
    const scope: TransactionScope = { active: true };
    try {
      const report = this.verifyIntegrityInternal();
      if (!report.valid) throw new EventStoreIntegrityError(report);

      const result = this.transactionScope.run(scope, operation);
      if (
        result !== null &&
        (typeof result === "object" || typeof result === "function") &&
        typeof (result as { then?: unknown }).then === "function"
      ) {
        void Promise.resolve(result).catch(() => undefined);
        throw new TypeError("Event-store transactions must be synchronous");
      }
      if (this.exclusiveTransactionFailed) {
        throw new Error("Event-store transaction contains a failed append");
      }

      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    } finally {
      scope.active = false;
      this.exclusiveTransactionActive = false;
      this.exclusiveTransactionFailed = false;
    }
  }

  list(filters: EventListFilters = {}): readonly StoredEvent[] {
    this.assertOpen();
    validateFilters(filters);

    const predicates: string[] = [];
    const parameters: Array<number | string> = [];

    if (filters.type !== undefined) {
      predicates.push("event_type = ?");
      parameters.push(filters.type);
    }
    if (filters.aggregateId !== undefined) {
      predicates.push("aggregate_id = ?");
      parameters.push(filters.aggregateId);
    }
    if (filters.afterSequence !== undefined) {
      predicates.push("sequence > ?");
      parameters.push(filters.afterSequence);
    }
    if (filters.beforeSequence !== undefined) {
      predicates.push("sequence < ?");
      parameters.push(filters.beforeSequence);
    }

    const where = predicates.length === 0 ? "" : ` WHERE ${predicates.join(" AND ")}`;
    const order = filters.order === "desc" ? "DESC" : "ASC";
    const limit = filters.limit === undefined ? "" : " LIMIT ?";
    if (filters.limit !== undefined) parameters.push(filters.limit);

    const rows = this.database
      .prepare(`${EVENT_COLUMNS}${where} ORDER BY sequence ${order}${limit}`)
      .all(...parameters) as unknown as EventRow[];

    return Object.freeze(rows.map(rowToEvent));
  }

  getByEventId(eventId: string): StoredEvent | undefined {
    this.assertOpen();
    validateIdentifier(eventId, "eventId");
    const row = this.database.prepare(`${EVENT_COLUMNS} WHERE event_id = ?`).get(eventId) as
      EventRow | undefined;
    return row === undefined ? undefined : rowToEvent(row);
  }

  getByIdempotencyKey(idempotencyKey: string): StoredEvent | undefined {
    this.assertOpen();
    validateIdentifier(idempotencyKey, "idempotencyKey");
    const row = this.database
      .prepare(`${EVENT_COLUMNS} WHERE idempotency_key = ?`)
      .get(idempotencyKey) as EventRow | undefined;
    return row === undefined ? undefined : rowToEvent(row);
  }

  verifyIntegrity(): IntegrityReport {
    this.assertOpen();
    return this.verifyIntegrityInternal();
  }

  close(): void {
    if (this.closed) return;
    this.database.close();
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.close();
  }

  private assertOpen(): void {
    if (this.transactionScope.getStore()?.active === false) {
      throw new Error("Event-store transaction work escaped its synchronous scope");
    }
    if (this.closed) throw new EventStoreClosedError();
  }

  private configureDatabase(): void {
    this.database.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA trusted_schema = OFF;
    `);
  }

  private initializeSchema(): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.exec(`
        CREATE TABLE IF NOT EXISTS rsi_events (
          sequence INTEGER PRIMARY KEY,
          event_id TEXT NOT NULL UNIQUE CHECK(length(event_id) > 0),
          idempotency_key TEXT UNIQUE,
          event_type TEXT NOT NULL CHECK(length(event_type) > 0),
          aggregate_id TEXT NOT NULL CHECK(length(aggregate_id) > 0),
          payload_json TEXT NOT NULL,
          occurred_at TEXT NOT NULL,
          previous_hash TEXT NOT NULL CHECK(length(previous_hash) = 64),
          event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_event_store_metadata (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          schema_version INTEGER NOT NULL,
          head_sequence INTEGER NOT NULL CHECK(head_sequence >= 0),
          head_hash TEXT NOT NULL CHECK(length(head_hash) = 64)
        ) STRICT;
      `);

      this.database
        .prepare(
          `INSERT INTO rsi_event_store_metadata (
             singleton, schema_version, head_sequence, head_hash
           )
           SELECT 1, ?, 0, ?
           WHERE NOT EXISTS (SELECT 1 FROM rsi_event_store_metadata)
             AND NOT EXISTS (SELECT 1 FROM rsi_events)`,
        )
        .run(SCHEMA_VERSION, GENESIS_HASH);
      this.database.exec("COMMIT");
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private getMetadata(): MetadataRow | undefined {
    return this.database
      .prepare(
        `SELECT schema_version, head_sequence, head_hash
           FROM rsi_event_store_metadata
          WHERE singleton = 1`,
      )
      .get() as MetadataRow | undefined;
  }

  private resolveDuplicate(prepared: PreparedEvent): EventRow | undefined {
    const byEventId =
      prepared.eventId === undefined
        ? undefined
        : (this.database.prepare(`${EVENT_COLUMNS} WHERE event_id = ?`).get(prepared.eventId) as
            EventRow | undefined);
    const byIdempotencyKey =
      prepared.idempotencyKey === undefined
        ? undefined
        : (this.database
            .prepare(`${EVENT_COLUMNS} WHERE idempotency_key = ?`)
            .get(prepared.idempotencyKey) as EventRow | undefined);

    if (
      byEventId !== undefined &&
      byIdempotencyKey !== undefined &&
      byEventId.sequence !== byIdempotencyKey.sequence
    ) {
      throw new EventConflictError(
        "EVENT_ID_IDEMPOTENCY_MISMATCH",
        "eventId and idempotencyKey identify different stored events",
      );
    }

    const existing = byEventId ?? byIdempotencyKey;
    if (existing === undefined) return undefined;

    if (prepared.eventId !== undefined && prepared.eventId !== existing.event_id) {
      throw new EventConflictError(
        "IDEMPOTENCY_KEY_CONFLICT",
        "The idempotency key is already associated with another eventId",
      );
    }
    if (
      prepared.idempotencyKey !== undefined &&
      prepared.idempotencyKey !== existing.idempotency_key
    ) {
      throw new EventConflictError(
        "EVENT_ID_CONFLICT",
        "The eventId is already associated with another idempotency key",
      );
    }

    const sameContent =
      prepared.type === existing.event_type &&
      prepared.aggregateId === existing.aggregate_id &&
      prepared.payloadJson === existing.payload_json &&
      (!prepared.occurredAtWasSupplied || prepared.occurredAt === existing.occurred_at);
    if (!sameContent) {
      throw new EventConflictError(
        byEventId === undefined ? "IDEMPOTENCY_KEY_CONFLICT" : "EVENT_ID_CONFLICT",
        "A duplicate event identity was used with different event content",
      );
    }

    return existing;
  }

  private verifyIntegrityInternal(): IntegrityReport {
    const errors: IntegrityIssue[] = [];
    let metadata: MetadataRow | undefined;
    let rows: EventRow[];

    try {
      metadata = this.getMetadata();
      rows = this.database
        .prepare(`${EVENT_COLUMNS} ORDER BY sequence ASC`)
        .all() as unknown as EventRow[];
    } catch (error) {
      return freezeReport({
        errors: [
          {
            code: "DATABASE_ERROR",
            message: error instanceof Error ? error.message : "Unable to read event-store tables",
            sequence: null,
          },
        ],
        eventCount: 0,
        headHash: GENESIS_HASH,
        headSequence: 0,
        valid: false,
      });
    }

    if (metadata === undefined) {
      errors.push({
        code: "INVALID_METADATA",
        message: "Event-store metadata row is missing",
        sequence: null,
      });
    } else if (metadata.schema_version !== SCHEMA_VERSION) {
      errors.push({
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message: `Expected schema version ${SCHEMA_VERSION}, received ${String(metadata.schema_version)}`,
        sequence: null,
      });
    }

    let expectedPreviousHash = GENESIS_HASH;
    let expectedSequence = 1;

    for (const row of rows) {
      const sequence = Number.isSafeInteger(row.sequence) ? row.sequence : null;
      if (sequence === null) {
        errors.push({
          code: "INVALID_ROW",
          message: "Event sequence is not a safe integer",
          sequence: null,
        });
      } else if (sequence !== expectedSequence) {
        errors.push({
          code: "SEQUENCE_GAP",
          message: `Expected sequence ${expectedSequence}, received ${sequence}`,
          sequence,
        });
      }

      if (!HASH_PATTERN.test(row.previous_hash)) {
        errors.push({
          code: "INVALID_PREVIOUS_HASH",
          message: "previousHash is not a lowercase SHA-256 digest",
          sequence,
        });
      }
      if (row.previous_hash !== expectedPreviousHash) {
        errors.push({
          code: "PREVIOUS_HASH_MISMATCH",
          message: "previousHash does not match the preceding eventHash",
          sequence,
        });
      }

      if (!HASH_PATTERN.test(row.event_hash)) {
        errors.push({
          code: "INVALID_EVENT_HASH",
          message: "eventHash is not a lowercase SHA-256 digest",
          sequence,
        });
      }

      try {
        const parsed = JSON.parse(row.payload_json) as JsonValue;
        if (canonicalJson(parsed) !== row.payload_json) {
          errors.push({
            code: "NON_CANONICAL_PAYLOAD",
            message: "Stored payload JSON is not canonical",
            sequence,
          });
        }
      } catch (error) {
        errors.push({
          code:
            error instanceof InvalidJsonValueError
              ? "NON_CANONICAL_PAYLOAD"
              : "INVALID_PAYLOAD_JSON",
          message: "Stored payload is not valid canonical JSON",
          sequence,
        });
      }

      try {
        if (normalizeOccurredAt(row.occurred_at) !== row.occurred_at) {
          errors.push({
            code: "NON_CANONICAL_TIMESTAMP",
            message: "occurredAt is not a canonical UTC ISO timestamp",
            sequence,
          });
        }
      } catch {
        errors.push({
          code: "NON_CANONICAL_TIMESTAMP",
          message: "occurredAt is not a valid timestamp",
          sequence,
        });
      }

      if (sequence !== null) {
        const computedHash = computeEventHash({
          aggregateId: row.aggregate_id,
          eventId: row.event_id,
          idempotencyKey: row.idempotency_key,
          occurredAt: row.occurred_at,
          payloadJson: row.payload_json,
          previousHash: row.previous_hash,
          sequence,
          type: row.event_type,
        });
        if (computedHash !== row.event_hash) {
          errors.push({
            code: "INVALID_EVENT_HASH",
            message: "eventHash does not match the stored event fields",
            sequence,
          });
        }
      }

      expectedPreviousHash = row.event_hash;
      expectedSequence += 1;
    }

    const observedHeadSequence = rows.at(-1)?.sequence ?? 0;
    const observedHeadHash = rows.at(-1)?.event_hash ?? GENESIS_HASH;
    if (metadata !== undefined) {
      if (metadata.head_sequence !== observedHeadSequence) {
        errors.push({
          code: "HEAD_SEQUENCE_MISMATCH",
          message: "Metadata head sequence does not match the final stored event",
          sequence: null,
        });
      }
      if (metadata.head_hash !== observedHeadHash) {
        errors.push({
          code: "HEAD_HASH_MISMATCH",
          message: "Metadata head hash does not match the final stored event",
          sequence: null,
        });
      }
    }

    return freezeReport({
      errors,
      eventCount: rows.length,
      headHash: observedHeadHash,
      headSequence: observedHeadSequence,
      valid: errors.length === 0,
    });
  }
}

/** Returns true only for an event store whose constructor completed successfully. */
export function isSqliteEventStore(value: unknown): value is SqliteEventStore {
  return (
    typeof value === "object" &&
    value !== null &&
    authenticSqliteEventStores.has(value) &&
    Object.getPrototypeOf(value) === SqliteEventStore.prototype
  );
}

const EVENT_COLUMNS = `SELECT sequence, event_id, idempotency_key, event_type,
  aggregate_id, payload_json, occurred_at, previous_hash, event_hash
  FROM rsi_events`;

function prepareEvent(input: AppendEventInput): PreparedEvent {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new InvalidEventError("Event input must be an object");
  }

  validateIdentifier(input.type, "type");
  validateIdentifier(input.aggregateId, "aggregateId");
  if (input.eventId !== undefined) validateIdentifier(input.eventId, "eventId");
  if (input.idempotencyKey !== undefined) {
    validateIdentifier(input.idempotencyKey, "idempotencyKey");
  }

  let payloadJson: string;
  try {
    payloadJson = canonicalJson(input.payload);
  } catch (error) {
    if (error instanceof InvalidJsonValueError) {
      throw new InvalidEventError(`Invalid event payload: ${error.message}`);
    }
    throw error;
  }
  if (Buffer.byteLength(payloadJson, "utf8") > MAX_PAYLOAD_BYTES) {
    throw new InvalidEventError(`Event payload exceeds ${MAX_PAYLOAD_BYTES} bytes`);
  }

  return {
    aggregateId: input.aggregateId,
    eventId: input.eventId,
    idempotencyKey: input.idempotencyKey,
    occurredAt: normalizeOccurredAt(input.occurredAt ?? new Date().toISOString()),
    occurredAtWasSupplied: input.occurredAt !== undefined,
    payloadJson,
    type: input.type,
  };
}

function validateIdentifier(value: string, field: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new InvalidEventError(`${field} must be a non-empty string`);
  }
  if (value.includes("\0")) {
    throw new InvalidEventError(`${field} may not contain NUL characters`);
  }
  if (Buffer.byteLength(value, "utf8") > MAX_IDENTIFIER_BYTES) {
    throw new InvalidEventError(`${field} exceeds ${MAX_IDENTIFIER_BYTES} bytes`);
  }
}

function validateFilters(filters: EventListFilters): void {
  if (filters.type !== undefined) validateIdentifier(filters.type, "type");
  if (filters.aggregateId !== undefined) {
    validateIdentifier(filters.aggregateId, "aggregateId");
  }
  for (const [field, value] of [
    ["afterSequence", filters.afterSequence],
    ["beforeSequence", filters.beforeSequence],
  ] as const) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) {
      throw new InvalidEventError(`${field} must be a non-negative safe integer`);
    }
  }
  if (
    filters.limit !== undefined &&
    (!Number.isSafeInteger(filters.limit) || filters.limit < 1 || filters.limit > 10_000)
  ) {
    throw new InvalidEventError("limit must be a safe integer from 1 through 10000");
  }
  if (filters.order !== undefined && filters.order !== "asc" && filters.order !== "desc") {
    throw new InvalidEventError('order must be either "asc" or "desc"');
  }
}

function normalizeOccurredAt(value: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new InvalidEventError("occurredAt must be a valid date-time string");
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new InvalidEventError("occurredAt must be a valid date-time string");
  }
  return new Date(timestamp).toISOString();
}

function computeEventHash(fields: HashFields): string {
  const hashInput: JsonValue = {
    aggregateId: fields.aggregateId,
    eventId: fields.eventId,
    idempotencyKey: fields.idempotencyKey,
    occurredAt: fields.occurredAt,
    payloadJson: fields.payloadJson,
    previousHash: fields.previousHash,
    schemaVersion: SCHEMA_VERSION,
    sequence: fields.sequence,
    type: fields.type,
  };
  return createHash("sha256")
    .update("rsi-event-v1\0", "utf8")
    .update(canonicalJson(hashInput), "utf8")
    .digest("hex");
}

function rowToEvent(row: EventRow): StoredEvent {
  const payload = deepFreezeJson(JSON.parse(row.payload_json) as JsonValue);
  return Object.freeze({
    aggregateId: row.aggregate_id,
    eventHash: row.event_hash,
    eventId: row.event_id,
    idempotencyKey: row.idempotency_key,
    occurredAt: row.occurred_at,
    payload,
    previousHash: row.previous_hash,
    sequence: row.sequence,
    type: row.event_type,
  });
}

function freezeReport(report: IntegrityReport): IntegrityReport {
  for (const error of report.errors) Object.freeze(error);
  Object.freeze(report.errors);
  return Object.freeze(report);
}
