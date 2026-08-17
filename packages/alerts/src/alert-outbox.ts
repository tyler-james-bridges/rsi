import { DatabaseSync } from "node:sqlite";
import { existsSync } from "node:fs";

import { canonicalJson, type JsonValue } from "@rsi/store";
import { z } from "zod";

import {
  decryptValue,
  deriveAlertKeys,
  encryptValue,
  keyedHex,
  macJson,
  secureEqualHex,
  type EncryptedValue,
} from "./crypto.js";
import {
  AlertConflictError,
  AlertIntegrityError,
  AlertOutboxClosedError,
  AlertValidationError,
} from "./errors.js";
import {
  AlertPlaneSchema,
  AlertProfileSchema,
  AlertTrustedHeadV1Schema,
  CanonicalTimestampSchema,
  ClaimDeliveryInputSchema,
  CompleteDeliveryInputSchema,
  EnqueueAlertInputSchema,
  FailDeliveryInputSchema,
  IncidentAlertV1Schema,
  RecoverDeliveriesInputSchema,
  parseWithSchema,
} from "./schemas.js";
import type {
  AlertDeliveryClaim,
  AlertDeliveryReceipt,
  AlertIntegrityReport,
  AlertPlane,
  AlertProfile,
  AlertRecoveryReceipt,
  AlertSessionSummaryV1,
  AlertTrustedHeadV1,
  ClaimDeliveryInput,
  CompleteDeliveryInput,
  DeliveryState,
  EnqueueAlertInput,
  FailDeliveryInput,
  IncidentAlertV1,
  OpenAlertOutboxOptions,
  RecoverDeliveriesInput,
} from "./types.js";

const SCHEMA_VERSION = 2;
const GENESIS_MAC = "0".repeat(64);
const MAX_ATTEMPTS = 2;
const ALERT_OUTBOX_CONSTRUCTION_TOKEN = Object.freeze({});
const AUTHENTIC_ALERT_OUTBOXES = new WeakSet<object>();
const MAX_ALERT_BYTES = 8 * 1_024;

const METADATA_TABLE_SQL = `CREATE TABLE rsi_alert_metadata (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  schema_version INTEGER NOT NULL,
  profile TEXT NOT NULL,
  audit_head_sequence INTEGER NOT NULL CHECK(audit_head_sequence >= 0),
  audit_head_mac TEXT NOT NULL CHECK(length(audit_head_mac) = 64),
  key_check_mac TEXT NOT NULL CHECK(length(key_check_mac) = 64),
  schema_mac TEXT NOT NULL CHECK(length(schema_mac) = 64),
  state_mac TEXT NOT NULL CHECK(length(state_mac) = 64),
  metadata_mac TEXT NOT NULL CHECK(length(metadata_mac) = 64)
) STRICT`;

const DELIVERIES_TABLE_SQL = `CREATE TABLE rsi_alert_deliveries (
  delivery_id TEXT PRIMARY KEY CHECK(length(delivery_id) = 64),
  profile TEXT NOT NULL CHECK(profile IN ('dev', 'canary', 'production-observer')),
  plane TEXT NOT NULL CHECK(plane IN ('healthchecks', 'resend')),
  payload_binding TEXT NOT NULL CHECK(length(payload_binding) = 64),
  payload_ciphertext BLOB NOT NULL,
  payload_nonce BLOB NOT NULL CHECK(length(payload_nonce) = 12),
  payload_tag BLOB NOT NULL CHECK(length(payload_tag) = 16),
  state TEXT NOT NULL CHECK(state IN ('pending', 'in_flight', 'delivered', 'exhausted')),
  attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 2),
  active_attempt INTEGER CHECK(active_attempt IS NULL OR active_attempt IN (1, 2)),
  queued_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
) STRICT`;

const ATTEMPTS_TABLE_SQL = `CREATE TABLE rsi_alert_attempts (
  delivery_id TEXT NOT NULL REFERENCES rsi_alert_deliveries(delivery_id),
  attempt INTEGER NOT NULL CHECK(attempt IN (1, 2)),
  state TEXT NOT NULL CHECK(state IN ('in_flight', 'delivered', 'failed', 'crashed')),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  retryable INTEGER CHECK(retryable IS NULL OR retryable IN (0, 1)),
  result_state TEXT CHECK(result_state IS NULL OR result_state IN ('pending', 'delivered', 'exhausted')),
  provider_binding TEXT CHECK(provider_binding IS NULL OR length(provider_binding) = 64),
  provider_ciphertext BLOB,
  provider_nonce BLOB CHECK(provider_nonce IS NULL OR length(provider_nonce) = 12),
  provider_tag BLOB CHECK(provider_tag IS NULL OR length(provider_tag) = 16),
  row_mac TEXT NOT NULL CHECK(length(row_mac) = 64),
  PRIMARY KEY(delivery_id, attempt)
) STRICT`;

const AUDIT_TABLE_SQL = `CREATE TABLE rsi_alert_audit (
  sequence INTEGER PRIMARY KEY,
  event_type TEXT NOT NULL CHECK(event_type IN (
    'alert.queued.v1', 'delivery.claimed.v1', 'delivery.completed.v1',
    'delivery.failed.v1', 'delivery.recovered.v1'
  )),
  delivery_id TEXT NOT NULL CHECK(length(delivery_id) = 64),
  plane TEXT NOT NULL CHECK(plane IN ('healthchecks', 'resend')),
  attempt INTEGER CHECK(attempt IS NULL OR attempt IN (1, 2)),
  delivery_state TEXT NOT NULL CHECK(delivery_state IN ('pending', 'in_flight', 'delivered', 'exhausted')),
  retryable INTEGER CHECK(retryable IS NULL OR retryable IN (0, 1)),
  occurred_at TEXT NOT NULL,
  previous_mac TEXT NOT NULL CHECK(length(previous_mac) = 64),
  event_mac TEXT NOT NULL UNIQUE CHECK(length(event_mac) = 64)
) STRICT`;

const CANONICAL_SCHEMA_SQL = [
  METADATA_TABLE_SQL,
  DELIVERIES_TABLE_SQL,
  ATTEMPTS_TABLE_SQL,
  AUDIT_TABLE_SQL,
].join(";\n");

const OpenAlertOutboxOptionsSchema = z.strictObject({
  databasePath: z
    .string()
    .min(1)
    .max(4_096)
    .refine((value) => !value.includes("\0")),
  profile: AlertProfileSchema,
  stateKey: z.custom<Uint8Array>(
    (value) =>
      value instanceof Uint8Array &&
      Object.getPrototypeOf(value) === Uint8Array.prototype &&
      value.buffer instanceof ArrayBuffer &&
      Object.getPrototypeOf(value.buffer) === ArrayBuffer.prototype,
  ),
  trustedHead: AlertTrustedHeadV1Schema.optional(),
});

type AttemptState = "crashed" | "delivered" | "failed" | "in_flight";
type AuditEventType =
  | "alert.queued.v1"
  | "delivery.claimed.v1"
  | "delivery.completed.v1"
  | "delivery.failed.v1"
  | "delivery.recovered.v1";

interface MetadataRow {
  audit_head_mac: string;
  audit_head_sequence: number;
  key_check_mac: string;
  metadata_mac: string;
  profile: string;
  schema_mac: string;
  schema_version: number;
  state_mac: string;
}

interface SqliteSchemaRow {
  name: string;
  sql: string | null;
  tbl_name: string;
  type: string;
}

const CANONICAL_SCHEMA_OBJECTS: readonly SqliteSchemaRow[] = Object.freeze([
  Object.freeze({
    name: "sqlite_autoindex_rsi_alert_attempts_1",
    sql: null,
    tbl_name: "rsi_alert_attempts",
    type: "index",
  }),
  Object.freeze({
    name: "sqlite_autoindex_rsi_alert_audit_1",
    sql: null,
    tbl_name: "rsi_alert_audit",
    type: "index",
  }),
  Object.freeze({
    name: "sqlite_autoindex_rsi_alert_deliveries_1",
    sql: null,
    tbl_name: "rsi_alert_deliveries",
    type: "index",
  }),
  Object.freeze({
    name: "rsi_alert_attempts",
    sql: ATTEMPTS_TABLE_SQL,
    tbl_name: "rsi_alert_attempts",
    type: "table",
  }),
  Object.freeze({
    name: "rsi_alert_audit",
    sql: AUDIT_TABLE_SQL,
    tbl_name: "rsi_alert_audit",
    type: "table",
  }),
  Object.freeze({
    name: "rsi_alert_deliveries",
    sql: DELIVERIES_TABLE_SQL,
    tbl_name: "rsi_alert_deliveries",
    type: "table",
  }),
  Object.freeze({
    name: "rsi_alert_metadata",
    sql: METADATA_TABLE_SQL,
    tbl_name: "rsi_alert_metadata",
    type: "table",
  }),
]);

interface DeliveryRow {
  active_attempt: number | null;
  attempt_count: number;
  delivery_id: string;
  payload_binding: string;
  payload_ciphertext: Uint8Array;
  payload_nonce: Uint8Array;
  payload_tag: Uint8Array;
  plane: string;
  profile: string;
  queued_at: string;
  row_mac: string;
  state: string;
  updated_at: string;
}

interface AttemptRow {
  attempt: number;
  delivery_id: string;
  finished_at: string | null;
  provider_binding: string | null;
  provider_ciphertext: Uint8Array | null;
  provider_nonce: Uint8Array | null;
  provider_tag: Uint8Array | null;
  result_state: string | null;
  retryable: number | null;
  row_mac: string;
  started_at: string;
  state: string;
}

interface AuditRow {
  attempt: number | null;
  delivery_id: string;
  delivery_state: string;
  event_mac: string;
  event_type: string;
  occurred_at: string;
  plane: string;
  previous_mac: string;
  retryable: number | null;
  sequence: number;
}

interface AppendAuditInput {
  readonly attempt: 1 | 2 | null;
  readonly deliveryId: string;
  readonly deliveryState: DeliveryState;
  readonly eventType: AuditEventType;
  readonly occurredAt: string;
  readonly plane: AlertPlane;
  readonly retryable: boolean | null;
}

/**
 * Durable offline alert queue. This class performs no network or credential work;
 * a later, separately qualified adapter can consume its bounded claims.
 */
export class AlertOutbox {
  readonly profile: AlertProfile;

  private readonly database: DatabaseSync;
  private readonly encryptionKey: Buffer;
  private readonly identityKey: Buffer;
  private readonly macKey: Buffer;
  private closed = false;

  static open(options: OpenAlertOutboxOptions): AlertOutbox {
    const parsed = parseWithSchema(OpenAlertOutboxOptionsSchema, options, "alert outbox options");
    if (parsed.stateKey.byteLength !== 32) {
      throw new AlertValidationError("stateKey must contain exactly 32 bytes");
    }
    const databaseExisted = parsed.databasePath !== ":memory:" && existsSync(parsed.databasePath);
    const outbox = new AlertOutbox(parsed, databaseExisted, ALERT_OUTBOX_CONSTRUCTION_TOKEN);
    AUTHENTIC_ALERT_OUTBOXES.add(outbox);
    return outbox;
  }

  private constructor(
    options: OpenAlertOutboxOptions,
    databaseExisted: boolean,
    constructionToken: unknown,
  ) {
    if (constructionToken !== ALERT_OUTBOX_CONSTRUCTION_TOKEN) {
      throw new AlertIntegrityError("Alert outbox construction was not authenticated");
    }
    this.profile = options.profile;
    const keys = deriveAlertKeys(options.stateKey, options.profile);
    this.encryptionKey = keys.encryptionKey;
    this.identityKey = keys.identityKey;
    this.macKey = keys.macKey;
    try {
      this.database = new DatabaseSync(options.databasePath);
    } catch (error) {
      this.clearKeys();
      throw error;
    }

    try {
      this.configureDatabase();
      this.initializeOrVerify(databaseExisted, options.trustedHead);
    } catch (error) {
      this.database.close();
      this.clearKeys();
      throw error;
    }
  }

  enqueue(input: EnqueueAlertInput): AlertDeliveryReceipt {
    const parsed = parseWithSchema(EnqueueAlertInputSchema, input, "alert enqueue");
    if (parsed.alert.profile !== this.profile) {
      throw new AlertValidationError("alert profile does not match this outbox boundary");
    }
    if (compareTimes(parsed.queuedAt, parsed.alert.occurredAt) < 0) {
      throw new AlertValidationError("queuedAt must not be before alert occurredAt");
    }

    return this.transaction(() => {
      const deliveryId = this.deliveryId(
        parsed.plane,
        parsed.alert.incidentId,
        parsed.alert.sessionId,
      );
      const existing = this.getDeliveryRow(deliveryId);
      if (existing !== undefined) {
        const existingAlert = this.decryptAlert(existing);
        if (
          existing.plane !== parsed.plane ||
          existing.profile !== parsed.alert.profile ||
          existing.queued_at !== parsed.queuedAt ||
          canonicalAlert(existingAlert) !== canonicalAlert(parsed.alert)
        ) {
          throw new AlertConflictError(
            "ALERT_CONFLICT",
            "The incident delivery identity was reused with conflicting alert content",
          );
        }
        return this.toReceipt(existing);
      }

      const payloadJson = canonicalAlert(parsed.alert);
      if (Buffer.byteLength(payloadJson, "utf8") > MAX_ALERT_BYTES) {
        throw new AlertValidationError("alert payload exceeds the 8 KiB contract");
      }
      const encrypted = encryptValue(
        this.encryptionKey,
        this.alertAad(deliveryId, parsed.plane, this.profile),
        payloadJson,
      );
      const unsigned: Omit<DeliveryRow, "row_mac"> = {
        active_attempt: null,
        attempt_count: 0,
        delivery_id: deliveryId,
        payload_binding: keyedHex(this.identityKey, "alert-payload", {
          alert: parsed.alert as unknown as JsonValue,
          deliveryId,
        }),
        payload_ciphertext: encrypted.ciphertext,
        payload_nonce: encrypted.nonce,
        payload_tag: encrypted.tag,
        plane: parsed.plane,
        profile: this.profile,
        queued_at: parsed.queuedAt,
        state: "pending",
        updated_at: parsed.queuedAt,
      };
      const row: DeliveryRow = { ...unsigned, row_mac: this.deliveryRowMac(unsigned) };
      const inserted = this.database
        .prepare(
          `INSERT INTO rsi_alert_deliveries (
             delivery_id, profile, plane, payload_binding,
             payload_ciphertext, payload_nonce, payload_tag,
             state, attempt_count, active_attempt, queued_at, updated_at, row_mac
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          row.delivery_id,
          row.profile,
          row.plane,
          row.payload_binding,
          row.payload_ciphertext,
          row.payload_nonce,
          row.payload_tag,
          row.state,
          row.attempt_count,
          row.active_attempt,
          row.queued_at,
          row.updated_at,
          row.row_mac,
        );
      if (inserted.changes !== 1) {
        throw new AlertIntegrityError("Alert delivery insertion did not write one row");
      }
      this.appendAudit({
        attempt: null,
        deliveryId,
        deliveryState: "pending",
        eventType: "alert.queued.v1",
        occurredAt: parsed.queuedAt,
        plane: parsed.plane,
        retryable: null,
      });
      return this.toReceipt(row);
    });
  }

  claim(input: ClaimDeliveryInput): AlertDeliveryClaim | undefined {
    const parsed = parseWithSchema(ClaimDeliveryInputSchema, input, "alert claim");

    return this.transaction(() => {
      const row = this.database
        .prepare(
          `SELECT * FROM rsi_alert_deliveries
            WHERE profile = ? AND plane = ? AND state = 'pending'
            ORDER BY queued_at, delivery_id
            LIMIT 1`,
        )
        .get(this.profile, parsed.plane) as DeliveryRow | undefined;
      if (row === undefined) return undefined;
      this.assertDeliveryRow(row);
      if (compareTimes(parsed.claimedAt, row.updated_at) < 0) {
        throw new AlertValidationError("claimedAt must not be before delivery state time");
      }

      const attempt = row.attempt_count + 1;
      if (attempt !== 1 && attempt !== 2) {
        throw new AlertIntegrityError("Pending alert has no bounded delivery attempt available");
      }
      const attemptUnsigned: Omit<AttemptRow, "row_mac"> = {
        attempt,
        delivery_id: row.delivery_id,
        finished_at: null,
        provider_binding: null,
        provider_ciphertext: null,
        provider_nonce: null,
        provider_tag: null,
        result_state: null,
        retryable: null,
        started_at: parsed.claimedAt,
        state: "in_flight",
      };
      const attemptRow: AttemptRow = {
        ...attemptUnsigned,
        row_mac: this.attemptRowMac(attemptUnsigned),
      };
      const inserted = this.database
        .prepare(
          `INSERT INTO rsi_alert_attempts (
             delivery_id, attempt, state, started_at, finished_at, retryable,
             result_state, provider_binding, provider_ciphertext, provider_nonce,
             provider_tag, row_mac
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          attemptRow.delivery_id,
          attemptRow.attempt,
          attemptRow.state,
          attemptRow.started_at,
          attemptRow.finished_at,
          attemptRow.retryable,
          attemptRow.result_state,
          attemptRow.provider_binding,
          attemptRow.provider_ciphertext,
          attemptRow.provider_nonce,
          attemptRow.provider_tag,
          attemptRow.row_mac,
        );
      if (inserted.changes !== 1) {
        throw new AlertIntegrityError("Alert attempt insertion did not write one row");
      }

      const updated = this.updateDelivery(row, {
        active_attempt: attempt,
        attempt_count: attempt,
        state: "in_flight",
        updated_at: parsed.claimedAt,
      });
      this.appendAudit({
        attempt,
        deliveryId: row.delivery_id,
        deliveryState: "in_flight",
        eventType: "delivery.claimed.v1",
        occurredAt: parsed.claimedAt,
        plane: parsed.plane,
        retryable: null,
      });

      const alert = this.decryptAlert(updated);
      return Object.freeze({
        alert,
        attempt,
        claimedAt: parsed.claimedAt,
        deliveryId: row.delivery_id,
        idempotencyKey: row.delivery_id,
        plane: parsed.plane,
      });
    });
  }

  complete(input: CompleteDeliveryInput): AlertDeliveryReceipt {
    const parsed = parseWithSchema(CompleteDeliveryInputSchema, input, "delivery completion");

    return this.transaction(() => {
      const delivery = this.requireDeliveryRow(parsed.deliveryId);
      const attempt = this.requireAttemptRow(parsed.deliveryId, parsed.attempt);
      if (attempt.state === "delivered") {
        if (
          attempt.finished_at !== parsed.completedAt ||
          this.decryptProviderMessageId(attempt) !== parsed.providerMessageId
        ) {
          throw new AlertConflictError(
            "DELIVERY_CONFLICT",
            "The delivery attempt was completed with conflicting content",
          );
        }
        return this.receiptAtAttemptResult(delivery, attempt);
      }
      this.assertActiveAttempt(delivery, attempt, parsed.attempt);
      if (compareTimes(parsed.completedAt, attempt.started_at) < 0) {
        throw new AlertValidationError("completedAt must not be before the attempt start");
      }

      const provider = this.encryptProviderMessageId(
        parsed.deliveryId,
        parsed.attempt,
        parsed.providerMessageId,
      );
      const completedAttempt = this.updateAttempt(attempt, {
        finished_at: parsed.completedAt,
        provider_binding: provider.binding,
        provider_ciphertext: provider.encrypted?.ciphertext ?? null,
        provider_nonce: provider.encrypted?.nonce ?? null,
        provider_tag: provider.encrypted?.tag ?? null,
        result_state: "delivered",
        retryable: null,
        state: "delivered",
      });
      this.updateDelivery(delivery, {
        active_attempt: null,
        state: "delivered",
        updated_at: parsed.completedAt,
      });
      this.appendAudit({
        attempt: parsed.attempt,
        deliveryId: parsed.deliveryId,
        deliveryState: "delivered",
        eventType: "delivery.completed.v1",
        occurredAt: parsed.completedAt,
        plane: parseWithSchema(AlertPlaneSchema, delivery.plane, "delivery plane"),
        retryable: null,
      });
      return this.receiptAtAttemptResult(delivery, completedAttempt);
    });
  }

  fail(input: FailDeliveryInput): AlertDeliveryReceipt {
    const parsed = parseWithSchema(FailDeliveryInputSchema, input, "delivery failure");

    return this.transaction(() => {
      const delivery = this.requireDeliveryRow(parsed.deliveryId);
      const attempt = this.requireAttemptRow(parsed.deliveryId, parsed.attempt);
      if (attempt.state === "failed") {
        if (
          attempt.finished_at !== parsed.failedAt ||
          attempt.retryable !== booleanToInteger(parsed.retryable)
        ) {
          throw new AlertConflictError(
            "DELIVERY_CONFLICT",
            "The delivery attempt was failed with conflicting content",
          );
        }
        return this.receiptAtAttemptResult(delivery, attempt);
      }
      this.assertActiveAttempt(delivery, attempt, parsed.attempt);
      if (compareTimes(parsed.failedAt, attempt.started_at) < 0) {
        throw new AlertValidationError("failedAt must not be before the attempt start");
      }

      const resultState: DeliveryState =
        parsed.retryable && parsed.attempt < MAX_ATTEMPTS ? "pending" : "exhausted";
      const failedAttempt = this.updateAttempt(attempt, {
        finished_at: parsed.failedAt,
        provider_binding: null,
        provider_ciphertext: null,
        provider_nonce: null,
        provider_tag: null,
        result_state: resultState,
        retryable: booleanToInteger(parsed.retryable),
        state: "failed",
      });
      this.updateDelivery(delivery, {
        active_attempt: null,
        state: resultState,
        updated_at: parsed.failedAt,
      });
      this.appendAudit({
        attempt: parsed.attempt,
        deliveryId: parsed.deliveryId,
        deliveryState: resultState,
        eventType: "delivery.failed.v1",
        occurredAt: parsed.failedAt,
        plane: parseWithSchema(AlertPlaneSchema, delivery.plane, "delivery plane"),
        retryable: parsed.retryable,
      });
      return this.receiptAtAttemptResult(delivery, failedAttempt);
    });
  }

  recover(input: RecoverDeliveriesInput): AlertRecoveryReceipt {
    const parsed = parseWithSchema(RecoverDeliveriesInputSchema, input, "delivery recovery");

    return this.transaction(() => {
      const rows = this.database
        .prepare(
          `SELECT * FROM rsi_alert_deliveries
            WHERE profile = ? AND state = 'in_flight'
            ORDER BY updated_at, delivery_id`,
        )
        .all(this.profile) as unknown as DeliveryRow[];
      for (const row of rows) {
        this.assertDeliveryRow(row);
        if (compareTimes(parsed.recoveredAt, row.updated_at) < 0) {
          throw new AlertValidationError("recoveredAt must not be before in-flight state time");
        }
      }

      let exhausted = 0;
      let retryReady = 0;
      for (const delivery of rows) {
        if (delivery.active_attempt !== 1 && delivery.active_attempt !== 2) {
          throw new AlertIntegrityError("In-flight alert has no active attempt");
        }
        const attempt = this.requireAttemptRow(delivery.delivery_id, delivery.active_attempt);
        const resultState: DeliveryState =
          delivery.active_attempt < MAX_ATTEMPTS ? "pending" : "exhausted";
        this.updateAttempt(attempt, {
          finished_at: parsed.recoveredAt,
          provider_binding: null,
          provider_ciphertext: null,
          provider_nonce: null,
          provider_tag: null,
          result_state: resultState,
          retryable: delivery.active_attempt < MAX_ATTEMPTS ? 1 : 0,
          state: "crashed",
        });
        this.updateDelivery(delivery, {
          active_attempt: null,
          state: resultState,
          updated_at: parsed.recoveredAt,
        });
        this.appendAudit({
          attempt: delivery.active_attempt,
          deliveryId: delivery.delivery_id,
          deliveryState: resultState,
          eventType: "delivery.recovered.v1",
          occurredAt: parsed.recoveredAt,
          plane: parseWithSchema(AlertPlaneSchema, delivery.plane, "delivery plane"),
          retryable: delivery.active_attempt < MAX_ATTEMPTS,
        });
        if (resultState === "pending") retryReady += 1;
        else exhausted += 1;
      }
      return Object.freeze({ exhausted, recoveredAt: parsed.recoveredAt, retryReady });
    });
  }

  list(): readonly AlertDeliveryReceipt[] {
    return this.verifiedRead(() => {
      const rows = this.database
        .prepare(
          `SELECT * FROM rsi_alert_deliveries
            WHERE profile = ? ORDER BY queued_at, delivery_id`,
        )
        .all(this.profile) as unknown as DeliveryRow[];
      return Object.freeze(rows.map((row) => this.toReceipt(row)));
    });
  }

  getSessionSummary(sessionIdInput: unknown): Readonly<AlertSessionSummaryV1> {
    const sessionId = parseWithSchema(
      IncidentAlertV1Schema.shape.sessionId,
      sessionIdInput,
      "sessionId",
    );
    return this.verifiedRead(() => {
      const rows = this.database
        .prepare(
          `SELECT * FROM rsi_alert_deliveries
            WHERE profile = ? ORDER BY queued_at, delivery_id`,
        )
        .all(this.profile) as unknown as DeliveryRow[];
      const states: Record<DeliveryState, number> = {
        delivered: 0,
        exhausted: 0,
        in_flight: 0,
        pending: 0,
      };
      const incidents = new Set<string>();
      let deliveryCount = 0;
      for (const row of rows) {
        const alert = this.decryptAlert(row);
        if (alert.sessionId !== sessionId) continue;
        incidents.add(alert.incidentId);
        states[assertDeliveryState(row.state)] += 1;
        deliveryCount += 1;
      }
      return Object.freeze({
        deliveryCount,
        incidentCount: incidents.size,
        profile: this.profile,
        schemaVersion: 1 as const,
        sessionId,
        states: Object.freeze(states),
      });
    });
  }

  getTrustedHead(): AlertTrustedHeadV1 {
    return this.verifiedRead(() => this.currentTrustedHead());
  }

  verifyIntegrity(): AlertIntegrityReport {
    this.assertOpen();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const report = this.verifyIntegrityInternal();
      this.database.exec("COMMIT");
      return report;
    } catch {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      return Object.freeze({
        auditEvents: 0,
        attempts: 0,
        deliveries: 0,
        errors: Object.freeze(["Integrity verification could not complete"]),
        valid: false,
      });
    }
  }

  close(): void {
    this.assertAuthentic();
    if (this.closed) return;
    this.closed = true;
    this.database.close();
    this.clearKeys();
  }

  [Symbol.dispose](): void {
    this.close();
  }

  private clearKeys(): void {
    this.encryptionKey.fill(0);
    this.identityKey.fill(0);
    this.macKey.fill(0);
  }

  private assertOpen(): void {
    this.assertAuthentic();
    if (this.closed) throw new AlertOutboxClosedError();
  }

  private assertAuthentic(): void {
    if (
      Object.getPrototypeOf(this) !== AlertOutbox.prototype ||
      !AUTHENTIC_ALERT_OUTBOXES.has(this)
    ) {
      throw new AlertIntegrityError("Alert outbox was not opened through AlertOutbox.open");
    }
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

  private initializeOrVerify(
    databaseExisted: boolean,
    trustedHead: AlertTrustedHeadV1 | undefined,
  ): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      if (!databaseExisted) this.initializeNewDatabase();
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) {
        throw new AlertIntegrityError("Alert outbox integrity verification failed");
      }
      if (databaseExisted && trustedHead === undefined) {
        throw new AlertValidationError(
          "trustedHead is required when reopening an existing alert database",
        );
      }
      if (trustedHead !== undefined) this.assertTrustedHeadPrefix(trustedHead);
      this.database.exec("COMMIT");
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private initializeNewDatabase(): void {
    if (this.readSchemaRows().length !== 0) {
      throw new AlertIntegrityError("A new alert database contained unexpected schema objects");
    }
    this.database.exec(CANONICAL_SCHEMA_SQL);
    const schema = this.requireCanonicalSchema();
    const inserted = this.database
      .prepare(
        `INSERT INTO rsi_alert_metadata (
             singleton, schema_version, profile, audit_head_sequence, audit_head_mac,
             key_check_mac, schema_mac, state_mac, metadata_mac
           ) VALUES (1, ?, ?, 0, ?, ?, ?, ?, ?)`,
      )
      .run(
        SCHEMA_VERSION,
        this.profile,
        GENESIS_MAC,
        macJson(this.macKey, "key-check", {
          profile: this.profile,
          schemaVersion: SCHEMA_VERSION,
        }),
        this.schemaProjectionMac(schema),
        GENESIS_MAC,
        GENESIS_MAC,
      );
    if (inserted.changes !== 1) {
      throw new AlertIntegrityError("Alert metadata initialization did not insert one row");
    }
    this.sealState();
  }

  private transaction<T>(operation: () => T): T {
    this.assertOpen();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) {
        throw new AlertIntegrityError("Alert outbox integrity verification failed");
      }
      const result = operation();
      this.sealState();
      const sealedIntegrity = this.verifyIntegrityInternal();
      if (!sealedIntegrity.valid) {
        throw new AlertIntegrityError("Alert outbox post-mutation integrity verification failed");
      }
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private verifiedRead<T>(operation: () => T): T {
    this.assertOpen();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) {
        throw new AlertIntegrityError("Alert outbox integrity verification failed");
      }
      const result = operation();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private metadata(): MetadataRow {
    const metadata = this.database
      .prepare(`SELECT * FROM rsi_alert_metadata WHERE singleton = 1`)
      .get() as MetadataRow | undefined;
    if (metadata === undefined) throw new AlertIntegrityError("Alert metadata is missing");
    return metadata;
  }

  private readSchemaRows(): SqliteSchemaRow[] {
    return this.database
      .prepare(
        `SELECT type, name, tbl_name, sql
           FROM sqlite_schema
          ORDER BY type, name`,
      )
      .all() as unknown as SqliteSchemaRow[];
  }

  private requireCanonicalSchema(): SqliteSchemaRow[] {
    const schema = this.readSchemaRows();
    if (
      canonicalJson(schema as unknown as JsonValue) !==
      canonicalJson(CANONICAL_SCHEMA_OBJECTS as unknown as JsonValue)
    ) {
      throw new AlertIntegrityError("Alert SQLite schema is not canonical");
    }
    return schema;
  }

  private schemaProjectionMac(schema: readonly SqliteSchemaRow[]): string {
    return macJson(this.macKey, "sqlite-schema", {
      objects: schema as unknown as JsonValue,
      schemaVersion: SCHEMA_VERSION,
    });
  }

  private fullStateMac(
    metadata: MetadataRow,
    schema: readonly SqliteSchemaRow[],
    deliveries: readonly DeliveryRow[],
    attempts: readonly AttemptRow[],
    audit: readonly AuditRow[],
  ): string {
    return macJson(this.macKey, "full-state", {
      attempts: attempts.map((row) => attemptStateProjection(row)),
      audit: audit.map((row) => auditStateProjection(row)),
      deliveries: deliveries.map((row) => deliveryStateProjection(row)),
      metadata: metadataStateProjection(metadata),
      schema: schema as unknown as JsonValue,
    });
  }

  private metadataRowMac(row: Omit<MetadataRow, "metadata_mac">): string {
    return macJson(this.macKey, "metadata-row", {
      auditHeadMac: row.audit_head_mac,
      auditHeadSequence: row.audit_head_sequence,
      keyCheckMac: row.key_check_mac,
      profile: row.profile,
      schemaMac: row.schema_mac,
      schemaVersion: row.schema_version,
      stateMac: row.state_mac,
    });
  }

  private sealState(): void {
    const schema = this.requireCanonicalSchema();
    const metadata = this.metadata();
    const deliveries = this.readDeliveryRows();
    const attempts = this.readAttemptRows();
    const audit = this.readAuditRows();
    const schemaMac = this.schemaProjectionMac(schema);
    const stateMac = this.fullStateMac(
      { ...metadata, schema_mac: schemaMac },
      schema,
      deliveries,
      attempts,
      audit,
    );
    const metadataMac = this.metadataRowMac({
      ...metadata,
      schema_mac: schemaMac,
      state_mac: stateMac,
    });
    const updated = this.database
      .prepare(
        `UPDATE rsi_alert_metadata
            SET schema_mac = ?, state_mac = ?, metadata_mac = ?
          WHERE singleton = 1
            AND schema_version = ?
            AND profile = ?
            AND audit_head_sequence = ?
            AND audit_head_mac = ?
            AND key_check_mac = ?
            AND metadata_mac = ?`,
      )
      .run(
        schemaMac,
        stateMac,
        metadataMac,
        metadata.schema_version,
        metadata.profile,
        metadata.audit_head_sequence,
        metadata.audit_head_mac,
        metadata.key_check_mac,
        metadata.metadata_mac,
      );
    if (updated.changes !== 1) {
      throw new AlertIntegrityError("Alert metadata sealing did not update one row");
    }
  }

  private currentTrustedHead(): AlertTrustedHeadV1 {
    const metadata = this.metadata();
    const unsigned = {
      schemaVersion: "alert-trusted-head.v1",
      profile: parseWithSchema(AlertProfileSchema, metadata.profile, "alert head profile"),
      auditSequence: metadata.audit_head_sequence,
      auditMac: metadata.audit_head_mac,
      schemaMac: metadata.schema_mac,
    } as const;
    return Object.freeze({
      ...unsigned,
      headMac: macJson(this.macKey, "trusted-head", unsigned),
    });
  }

  private assertTrustedHeadPrefix(trustedHead: AlertTrustedHeadV1): void {
    const metadata = this.metadata();
    const expectedHeadMac = macJson(this.macKey, "trusted-head", {
      schemaVersion: trustedHead.schemaVersion,
      profile: trustedHead.profile,
      auditSequence: trustedHead.auditSequence,
      auditMac: trustedHead.auditMac,
      schemaMac: trustedHead.schemaMac,
    });
    if (
      trustedHead.profile !== this.profile ||
      !secureEqualHex(trustedHead.schemaMac, metadata.schema_mac) ||
      !secureEqualHex(trustedHead.headMac, expectedHeadMac) ||
      trustedHead.auditSequence > metadata.audit_head_sequence
    ) {
      throw new AlertIntegrityError("Alert outbox trusted head is not an authenticated prefix");
    }

    if (trustedHead.auditSequence === 0) {
      if (!secureEqualHex(trustedHead.auditMac, GENESIS_MAC)) {
        throw new AlertIntegrityError("Alert outbox trusted genesis head is invalid");
      }
      return;
    }

    const pinned = this.database
      .prepare(`SELECT event_mac FROM rsi_alert_audit WHERE sequence = ?`)
      .get(trustedHead.auditSequence) as { event_mac: string } | undefined;
    if (pinned === undefined || !secureEqualHex(trustedHead.auditMac, pinned.event_mac)) {
      throw new AlertIntegrityError("Alert outbox trusted audit prefix is absent");
    }
  }

  private readDeliveryRows(): DeliveryRow[] {
    return this.database
      .prepare(`SELECT * FROM rsi_alert_deliveries ORDER BY delivery_id`)
      .all() as unknown as DeliveryRow[];
  }

  private readAttemptRows(): AttemptRow[] {
    return this.database
      .prepare(`SELECT * FROM rsi_alert_attempts ORDER BY delivery_id, attempt`)
      .all() as unknown as AttemptRow[];
  }

  private readAuditRows(): AuditRow[] {
    return this.database
      .prepare(`SELECT * FROM rsi_alert_audit ORDER BY sequence`)
      .all() as unknown as AuditRow[];
  }

  private appendAudit(input: AppendAuditInput): void {
    const metadata = this.metadata();
    const previous = this.database
      .prepare(`SELECT occurred_at FROM rsi_alert_audit ORDER BY sequence DESC LIMIT 1`)
      .get() as { occurred_at: string } | undefined;
    if (previous !== undefined && compareTimes(input.occurredAt, previous.occurred_at) < 0) {
      throw new AlertValidationError("alert state time must not move backward");
    }
    const sequence = metadata.audit_head_sequence + 1;
    const retryable = input.retryable === null ? null : booleanToInteger(input.retryable);
    const eventMac = macJson(this.macKey, "audit-event", {
      attempt: input.attempt,
      deliveryId: input.deliveryId,
      deliveryState: input.deliveryState,
      eventType: input.eventType,
      occurredAt: input.occurredAt,
      plane: input.plane,
      previousMac: metadata.audit_head_mac,
      retryable,
      sequence,
    });
    const inserted = this.database
      .prepare(
        `INSERT INTO rsi_alert_audit (
           sequence, event_type, delivery_id, plane, attempt, delivery_state,
           retryable, occurred_at, previous_mac, event_mac
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        sequence,
        input.eventType,
        input.deliveryId,
        input.plane,
        input.attempt,
        input.deliveryState,
        retryable,
        input.occurredAt,
        metadata.audit_head_mac,
        eventMac,
      );
    if (inserted.changes !== 1) {
      throw new AlertIntegrityError("Alert audit insertion did not write one row");
    }
    const updated = this.database
      .prepare(
        `UPDATE rsi_alert_metadata
            SET audit_head_sequence = ?, audit_head_mac = ?
          WHERE singleton = 1 AND audit_head_sequence = ? AND audit_head_mac = ?`,
      )
      .run(sequence, eventMac, metadata.audit_head_sequence, metadata.audit_head_mac);
    if (updated.changes !== 1) {
      throw new AlertIntegrityError("Alert audit head changed during append");
    }
  }

  private getDeliveryRow(deliveryId: string): DeliveryRow | undefined {
    return this.database
      .prepare(`SELECT * FROM rsi_alert_deliveries WHERE delivery_id = ?`)
      .get(deliveryId) as DeliveryRow | undefined;
  }

  private requireDeliveryRow(deliveryId: string): DeliveryRow {
    const row = this.getDeliveryRow(deliveryId);
    if (row === undefined) {
      throw new AlertConflictError("DELIVERY_CONFLICT", "The alert delivery does not exist");
    }
    this.assertDeliveryRow(row);
    return row;
  }

  private requireAttemptRow(deliveryId: string, attempt: number): AttemptRow {
    const row = this.database
      .prepare(`SELECT * FROM rsi_alert_attempts WHERE delivery_id = ? AND attempt = ?`)
      .get(deliveryId, attempt) as AttemptRow | undefined;
    if (row === undefined) {
      throw new AlertConflictError(
        "DELIVERY_CONFLICT",
        "The alert delivery attempt does not exist",
      );
    }
    this.assertAttemptRow(row);
    return row;
  }

  private assertActiveAttempt(
    delivery: DeliveryRow,
    attempt: AttemptRow,
    expectedAttempt: number,
  ): void {
    if (
      delivery.state !== "in_flight" ||
      delivery.active_attempt !== expectedAttempt ||
      delivery.attempt_count !== expectedAttempt ||
      attempt.state !== "in_flight"
    ) {
      throw new AlertConflictError(
        "INVALID_TRANSITION",
        "The alert delivery attempt is not active",
      );
    }
  }

  private updateDelivery(
    row: DeliveryRow,
    changes: Partial<
      Pick<DeliveryRow, "active_attempt" | "attempt_count" | "state" | "updated_at">
    >,
  ): DeliveryRow {
    const unsigned: Omit<DeliveryRow, "row_mac"> = {
      active_attempt: changes.active_attempt ?? row.active_attempt,
      attempt_count: changes.attempt_count ?? row.attempt_count,
      delivery_id: row.delivery_id,
      payload_binding: row.payload_binding,
      payload_ciphertext: row.payload_ciphertext,
      payload_nonce: row.payload_nonce,
      payload_tag: row.payload_tag,
      plane: row.plane,
      profile: row.profile,
      queued_at: row.queued_at,
      state: changes.state ?? row.state,
      updated_at: changes.updated_at ?? row.updated_at,
    };
    // `null` is an intentional active-attempt update and cannot use nullish coalescing.
    if (Object.hasOwn(changes, "active_attempt")) {
      unsigned.active_attempt = changes.active_attempt ?? null;
    }
    const updated: DeliveryRow = { ...unsigned, row_mac: this.deliveryRowMac(unsigned) };
    const result = this.database
      .prepare(
        `UPDATE rsi_alert_deliveries
            SET state = ?, attempt_count = ?, active_attempt = ?, updated_at = ?, row_mac = ?
          WHERE delivery_id = ? AND row_mac = ?`,
      )
      .run(
        updated.state,
        updated.attempt_count,
        updated.active_attempt,
        updated.updated_at,
        updated.row_mac,
        row.delivery_id,
        row.row_mac,
      );
    if (result.changes !== 1) {
      throw new AlertIntegrityError("Alert delivery changed during update");
    }
    return updated;
  }

  private updateAttempt(
    row: AttemptRow,
    changes: Pick<
      AttemptRow,
      | "finished_at"
      | "provider_binding"
      | "provider_ciphertext"
      | "provider_nonce"
      | "provider_tag"
      | "result_state"
      | "retryable"
      | "state"
    >,
  ): AttemptRow {
    const unsigned: Omit<AttemptRow, "row_mac"> = {
      attempt: row.attempt,
      delivery_id: row.delivery_id,
      finished_at: changes.finished_at,
      provider_binding: changes.provider_binding,
      provider_ciphertext: changes.provider_ciphertext,
      provider_nonce: changes.provider_nonce,
      provider_tag: changes.provider_tag,
      result_state: changes.result_state,
      retryable: changes.retryable,
      started_at: row.started_at,
      state: changes.state,
    };
    const updated: AttemptRow = { ...unsigned, row_mac: this.attemptRowMac(unsigned) };
    const result = this.database
      .prepare(
        `UPDATE rsi_alert_attempts
            SET state = ?, finished_at = ?, retryable = ?, result_state = ?,
                provider_binding = ?, provider_ciphertext = ?, provider_nonce = ?,
                provider_tag = ?, row_mac = ?
          WHERE delivery_id = ? AND attempt = ? AND row_mac = ?`,
      )
      .run(
        updated.state,
        updated.finished_at,
        updated.retryable,
        updated.result_state,
        updated.provider_binding,
        updated.provider_ciphertext,
        updated.provider_nonce,
        updated.provider_tag,
        updated.row_mac,
        row.delivery_id,
        row.attempt,
        row.row_mac,
      );
    if (result.changes !== 1) {
      throw new AlertIntegrityError("Alert attempt changed during update");
    }
    return updated;
  }

  private deliveryId(plane: AlertPlane, incidentId: string, sessionId: string): string {
    return keyedHex(this.identityKey, "delivery-id", {
      incidentId,
      plane,
      profile: this.profile,
      sessionId,
    });
  }

  private alertAad(deliveryId: string, plane: string, profile: string): string {
    return `rsi.alerts.payload.v1:${profile}:${plane}:${deliveryId}`;
  }

  private providerAad(deliveryId: string, attempt: number): string {
    return `rsi.alerts.provider-id.v1:${this.profile}:${deliveryId}:${attempt}`;
  }

  private decryptAlert(row: DeliveryRow): IncidentAlertV1 {
    const plaintext = decryptValue(
      this.encryptionKey,
      this.alertAad(row.delivery_id, row.plane, row.profile),
      {
        ciphertext: row.payload_ciphertext,
        nonce: row.payload_nonce,
        tag: row.payload_tag,
      },
    );
    let value: unknown;
    try {
      value = JSON.parse(plaintext);
    } catch {
      throw new AlertIntegrityError("Encrypted alert payload is not valid JSON");
    }
    const parsed = IncidentAlertV1Schema.safeParse(value);
    if (!parsed.success || canonicalAlert(parsed.data) !== plaintext) {
      throw new AlertIntegrityError("Encrypted alert payload violates its closed schema");
    }
    return Object.freeze(parsed.data);
  }

  private encryptProviderMessageId(
    deliveryId: string,
    attempt: number,
    providerMessageId: string | undefined,
  ): { readonly binding: string | null; readonly encrypted?: EncryptedValue } {
    if (providerMessageId === undefined) return Object.freeze({ binding: null });
    return Object.freeze({
      binding: keyedHex(this.identityKey, "provider-message-id", {
        attempt,
        deliveryId,
        providerMessageId,
      }),
      encrypted: encryptValue(
        this.encryptionKey,
        this.providerAad(deliveryId, attempt),
        providerMessageId,
      ),
    });
  }

  private decryptProviderMessageId(row: AttemptRow): string | undefined {
    const values = [
      row.provider_binding,
      row.provider_ciphertext,
      row.provider_nonce,
      row.provider_tag,
    ];
    if (values.every((value) => value === null)) return undefined;
    if (values.some((value) => value === null)) {
      throw new AlertIntegrityError("Provider message ID encryption fields are incomplete");
    }
    const providerMessageId = decryptValue(
      this.encryptionKey,
      this.providerAad(row.delivery_id, row.attempt),
      {
        ciphertext: row.provider_ciphertext as Uint8Array,
        nonce: row.provider_nonce as Uint8Array,
        tag: row.provider_tag as Uint8Array,
      },
    );
    const expected = keyedHex(this.identityKey, "provider-message-id", {
      attempt: row.attempt,
      deliveryId: row.delivery_id,
      providerMessageId,
    });
    if (!secureEqualHex(row.provider_binding as string, expected)) {
      throw new AlertIntegrityError("Provider message ID binding is invalid");
    }
    return providerMessageId;
  }

  private deliveryRowMac(row: Omit<DeliveryRow, "row_mac">): string {
    return macJson(this.macKey, "delivery-row", {
      activeAttempt: row.active_attempt,
      attemptCount: row.attempt_count,
      deliveryId: row.delivery_id,
      payloadBinding: row.payload_binding,
      payloadCiphertext: blobBase64(row.payload_ciphertext),
      payloadNonce: blobBase64(row.payload_nonce),
      payloadTag: blobBase64(row.payload_tag),
      plane: row.plane,
      profile: row.profile,
      queuedAt: row.queued_at,
      state: row.state,
      updatedAt: row.updated_at,
    });
  }

  private attemptRowMac(row: Omit<AttemptRow, "row_mac">): string {
    return macJson(this.macKey, "attempt-row", {
      attempt: row.attempt,
      deliveryId: row.delivery_id,
      finishedAt: row.finished_at,
      providerBinding: row.provider_binding,
      providerCiphertext: nullableBlobBase64(row.provider_ciphertext),
      providerNonce: nullableBlobBase64(row.provider_nonce),
      providerTag: nullableBlobBase64(row.provider_tag),
      resultState: row.result_state,
      retryable: row.retryable,
      startedAt: row.started_at,
      state: row.state,
    });
  }

  private assertDeliveryRow(row: DeliveryRow): void {
    const { row_mac: rowMac, ...unsigned } = row;
    if (!secureEqualHex(rowMac, this.deliveryRowMac(unsigned))) {
      throw new AlertIntegrityError("Alert delivery row authentication failed");
    }
    const profile = parseWithSchema(AlertProfileSchema, row.profile, "stored alert profile");
    const plane = parseWithSchema(AlertPlaneSchema, row.plane, "stored alert plane");
    if (profile !== this.profile) {
      throw new AlertIntegrityError("Alert delivery crossed its profile boundary");
    }
    parseWithSchema(CanonicalTimestampSchema, row.queued_at, "stored queuedAt");
    parseWithSchema(CanonicalTimestampSchema, row.updated_at, "stored updatedAt");
    if (compareTimes(row.updated_at, row.queued_at) < 0) {
      throw new AlertIntegrityError("Alert delivery time moved backward");
    }
    const alert = this.decryptAlert(row);
    if (alert.profile !== profile) {
      throw new AlertIntegrityError("Encrypted alert profile does not match its boundary");
    }
    if (compareTimes(row.queued_at, alert.occurredAt) < 0) {
      throw new AlertIntegrityError("Alert queue time predates its incident");
    }
    if (this.deliveryId(plane, alert.incidentId, alert.sessionId) !== row.delivery_id) {
      throw new AlertIntegrityError("Alert delivery identity is invalid");
    }
    const expectedBinding = keyedHex(this.identityKey, "alert-payload", {
      alert: alert as unknown as JsonValue,
      deliveryId: row.delivery_id,
    });
    if (!secureEqualHex(row.payload_binding, expectedBinding)) {
      throw new AlertIntegrityError("Alert payload binding is invalid");
    }
    assertDeliveryState(row.state);
    if (!Number.isInteger(row.attempt_count) || row.attempt_count < 0 || row.attempt_count > 2) {
      throw new AlertIntegrityError("Alert attempt count is invalid");
    }
    if (
      (row.state === "in_flight" && row.active_attempt !== row.attempt_count) ||
      (row.state !== "in_flight" && row.active_attempt !== null) ||
      (row.state === "in_flight" && row.attempt_count === 0) ||
      ((row.state === "delivered" || row.state === "exhausted") && row.attempt_count === 0)
    ) {
      throw new AlertIntegrityError("Alert delivery state invariants are invalid");
    }
  }

  private assertAttemptRow(row: AttemptRow): void {
    const { row_mac: rowMac, ...unsigned } = row;
    if (!secureEqualHex(rowMac, this.attemptRowMac(unsigned))) {
      throw new AlertIntegrityError("Alert attempt row authentication failed");
    }
    if (row.attempt !== 1 && row.attempt !== 2) {
      throw new AlertIntegrityError("Alert attempt number is invalid");
    }
    parseWithSchema(CanonicalTimestampSchema, row.started_at, "stored attempt start");
    assertAttemptState(row.state);
    if (row.state === "in_flight") {
      if (
        row.finished_at !== null ||
        row.retryable !== null ||
        row.result_state !== null ||
        this.providerFieldsPresent(row)
      ) {
        throw new AlertIntegrityError("In-flight alert attempt contains terminal state");
      }
      return;
    }
    if (row.finished_at === null) {
      throw new AlertIntegrityError("Terminal alert attempt has no finish time");
    }
    parseWithSchema(CanonicalTimestampSchema, row.finished_at, "stored attempt finish");
    if (compareTimes(row.finished_at, row.started_at) < 0) {
      throw new AlertIntegrityError("Alert attempt time moved backward");
    }
    if (row.state === "delivered") {
      if (row.retryable !== null || row.result_state !== "delivered") {
        throw new AlertIntegrityError("Delivered alert attempt has invalid result state");
      }
      this.decryptProviderMessageId(row);
      return;
    }
    if (
      (row.retryable !== 0 && row.retryable !== 1) ||
      (row.result_state !== "pending" && row.result_state !== "exhausted") ||
      this.providerFieldsPresent(row)
    ) {
      throw new AlertIntegrityError("Failed alert attempt has invalid bounded state");
    }
    if (
      (row.result_state === "pending" && (row.attempt !== 1 || row.retryable !== 1)) ||
      (row.attempt === 2 && row.result_state !== "exhausted")
    ) {
      throw new AlertIntegrityError("Alert retry bound is invalid");
    }
  }

  private providerFieldsPresent(row: AttemptRow): boolean {
    return [
      row.provider_binding,
      row.provider_ciphertext,
      row.provider_nonce,
      row.provider_tag,
    ].some((value) => value !== null);
  }

  private toReceipt(row: DeliveryRow): AlertDeliveryReceipt {
    this.assertDeliveryRow(row);
    const attempts = row.attempt_count;
    if (attempts !== 0 && attempts !== 1 && attempts !== 2) {
      throw new AlertIntegrityError("Alert attempt count cannot be projected");
    }
    return Object.freeze({
      attempts,
      deliveryId: row.delivery_id,
      plane: parseWithSchema(AlertPlaneSchema, row.plane, "delivery plane"),
      profile: parseWithSchema(AlertProfileSchema, row.profile, "delivery profile"),
      queuedAt: row.queued_at,
      state: assertDeliveryState(row.state),
      updatedAt: row.updated_at,
    });
  }

  private receiptAtAttemptResult(delivery: DeliveryRow, attempt: AttemptRow): AlertDeliveryReceipt {
    if (
      attempt.finished_at === null ||
      (attempt.result_state !== "pending" &&
        attempt.result_state !== "delivered" &&
        attempt.result_state !== "exhausted") ||
      (attempt.attempt !== 1 && attempt.attempt !== 2)
    ) {
      throw new AlertIntegrityError("Alert attempt has no projectable result");
    }
    return Object.freeze({
      attempts: attempt.attempt,
      deliveryId: delivery.delivery_id,
      plane: parseWithSchema(AlertPlaneSchema, delivery.plane, "delivery plane"),
      profile: parseWithSchema(AlertProfileSchema, delivery.profile, "delivery profile"),
      queuedAt: delivery.queued_at,
      state: attempt.result_state,
      updatedAt: attempt.finished_at,
    });
  }

  private verifyIntegrityInternal(): AlertIntegrityReport {
    const errors: string[] = [];
    let schema: SqliteSchemaRow[];
    try {
      schema = this.requireCanonicalSchema();
    } catch {
      return Object.freeze({
        auditEvents: 0,
        attempts: 0,
        deliveries: 0,
        errors: Object.freeze(["Alert SQLite schema is not canonical"]),
        valid: false,
      });
    }
    const metadataRows = this.database
      .prepare(`SELECT * FROM rsi_alert_metadata ORDER BY singleton`)
      .all() as unknown as MetadataRow[];
    const deliveries = this.readDeliveryRows();
    const attempts = this.readAttemptRows();
    const audit = this.readAuditRows();

    const metadata = metadataRows[0];
    if (metadataRows.length !== 1 || metadata === undefined) {
      errors.push("Alert metadata cardinality is invalid");
    } else {
      if (metadata.schema_version !== SCHEMA_VERSION) {
        errors.push("Alert schema version is invalid");
      }
      if (metadata.profile !== this.profile) {
        errors.push("Alert database profile boundary does not match");
      }
      if (!Number.isInteger(metadata.audit_head_sequence) || metadata.audit_head_sequence < 0) {
        errors.push("Alert audit head sequence is invalid");
      }
      const expectedKeyCheck = macJson(this.macKey, "key-check", {
        profile: this.profile,
        schemaVersion: SCHEMA_VERSION,
      });
      if (!secureEqualHex(metadata.key_check_mac, expectedKeyCheck)) {
        errors.push("Alert database key check failed");
      }
      const expectedSchemaMac = this.schemaProjectionMac(schema);
      if (!secureEqualHex(metadata.schema_mac, expectedSchemaMac)) {
        errors.push("Alert schema authentication failed");
      }
      const expectedStateMac = this.fullStateMac(
        { ...metadata, schema_mac: expectedSchemaMac },
        schema,
        deliveries,
        attempts,
        audit,
      );
      if (!secureEqualHex(metadata.state_mac, expectedStateMac)) {
        errors.push("Alert full-state authentication failed");
      }
      const { metadata_mac: _metadataMac, ...unsignedMetadata } = metadata;
      if (!secureEqualHex(metadata.metadata_mac, this.metadataRowMac(unsignedMetadata))) {
        errors.push("Alert metadata authentication failed");
      }
    }

    const validDeliveries = new Map<string, DeliveryRow>();
    for (const row of deliveries) {
      try {
        this.assertDeliveryRow(row);
        validDeliveries.set(row.delivery_id, row);
      } catch {
        errors.push(`Alert delivery integrity failed at row ${validDeliveries.size + 1}`);
      }
    }
    const attemptsByDelivery = new Map<string, AttemptRow[]>();
    for (const row of attempts) {
      try {
        this.assertAttemptRow(row);
      } catch {
        errors.push(`Alert attempt integrity failed at row ${attemptsByDelivery.size + 1}`);
      }
      const current = attemptsByDelivery.get(row.delivery_id) ?? [];
      current.push(row);
      attemptsByDelivery.set(row.delivery_id, current);
    }

    for (const delivery of deliveries) {
      const related = attemptsByDelivery.get(delivery.delivery_id) ?? [];
      if (related.length !== delivery.attempt_count) {
        errors.push("Alert delivery attempt cardinality is invalid");
        continue;
      }
      for (let index = 0; index < related.length; index += 1) {
        if (related[index]?.attempt !== index + 1) {
          errors.push("Alert delivery attempts are not contiguous");
        }
      }
      let priorTransitionAt = delivery.queued_at;
      for (const attempt of related) {
        if (compareTimes(attempt.started_at, priorTransitionAt) < 0) {
          errors.push("Alert attempt predates its prior transition");
        }
        priorTransitionAt = attempt.finished_at ?? attempt.started_at;
      }
      const latest = related.at(-1);
      if (delivery.state === "pending") {
        if (
          (latest !== undefined && latest.result_state !== "pending") ||
          related.some((row) => row.state === "in_flight")
        ) {
          errors.push("Pending alert does not match its attempt history");
        }
      } else if (delivery.state === "in_flight") {
        if (latest?.state !== "in_flight" || latest.attempt !== delivery.active_attempt) {
          errors.push("In-flight alert does not match its active attempt");
        }
      } else if (delivery.state === "delivered") {
        if (latest?.state !== "delivered" || latest.result_state !== "delivered") {
          errors.push("Delivered alert does not match its attempt history");
        }
      } else if (
        latest === undefined ||
        (latest.state !== "failed" && latest.state !== "crashed") ||
        latest.result_state !== "exhausted"
      ) {
        errors.push("Exhausted alert does not match its attempt history");
      }
      if (
        latest !== undefined &&
        delivery.updated_at !== (latest.finished_at ?? latest.started_at)
      ) {
        errors.push("Alert delivery update time does not match its attempt history");
      }
    }
    for (const deliveryId of attemptsByDelivery.keys()) {
      if (!validDeliveries.has(deliveryId)) {
        errors.push("Alert attempt references an invalid delivery");
      }
    }

    let previousMac = GENESIS_MAC;
    let previousTime: string | undefined;
    for (let index = 0; index < audit.length; index += 1) {
      const row = audit[index];
      if (row === undefined) continue;
      try {
        if (row.sequence !== index + 1 || row.previous_mac !== previousMac) {
          throw new AlertIntegrityError("Alert audit continuity failed");
        }
        parseAuditRow(row);
        if (previousTime !== undefined && compareTimes(row.occurred_at, previousTime) < 0) {
          throw new AlertIntegrityError("Alert audit time moved backward");
        }
        const delivery = validDeliveries.get(row.delivery_id);
        if (delivery === undefined || delivery.plane !== row.plane) {
          throw new AlertIntegrityError("Alert audit references an invalid delivery boundary");
        }
        if (
          compareTimes(row.occurred_at, delivery.queued_at) < 0 ||
          (row.event_type === "alert.queued.v1" && row.occurred_at !== delivery.queued_at)
        ) {
          throw new AlertIntegrityError("Alert audit predates its delivery boundary");
        }
        const expected = macJson(this.macKey, "audit-event", {
          attempt: row.attempt,
          deliveryId: row.delivery_id,
          deliveryState: row.delivery_state,
          eventType: row.event_type,
          occurredAt: row.occurred_at,
          plane: row.plane,
          previousMac: row.previous_mac,
          retryable: row.retryable,
          sequence: row.sequence,
        });
        if (!secureEqualHex(row.event_mac, expected)) {
          throw new AlertIntegrityError("Alert audit event authentication failed");
        }
        previousMac = row.event_mac;
        previousTime = row.occurred_at;
      } catch {
        errors.push(`Alert audit integrity failed at sequence ${index + 1}`);
      }
    }
    if (metadata !== undefined) {
      if (
        metadata.audit_head_sequence !== audit.length ||
        metadata.audit_head_mac !== previousMac
      ) {
        errors.push("Alert audit head is invalid");
      }
    }

    const auditByDelivery = new Map<string, AuditRow[]>();
    for (const row of audit) {
      const current = auditByDelivery.get(row.delivery_id) ?? [];
      current.push(row);
      auditByDelivery.set(row.delivery_id, current);
    }
    for (const delivery of validDeliveries.values()) {
      const relatedAttempts = attemptsByDelivery.get(delivery.delivery_id) ?? [];
      const events = auditByDelivery.get(delivery.delivery_id) ?? [];
      const queuedEvents = events.filter((row) => row.event_type === "alert.queued.v1");
      if (
        queuedEvents.length !== 1 ||
        queuedEvents[0]?.occurred_at !== delivery.queued_at ||
        queuedEvents[0]?.plane !== delivery.plane
      ) {
        errors.push("Alert delivery does not have one exact queue audit event");
      }
      let expectedEventCount = 1;
      for (const attempt of relatedAttempts) {
        const claimed = events.filter(
          (row) => row.event_type === "delivery.claimed.v1" && row.attempt === attempt.attempt,
        );
        if (
          claimed.length !== 1 ||
          claimed[0]?.occurred_at !== attempt.started_at ||
          claimed[0]?.delivery_state !== "in_flight"
        ) {
          errors.push("Alert attempt does not have one exact claim audit event");
        }
        expectedEventCount += 1;
        if (attempt.finished_at === null) continue;

        expectedEventCount += 1;
        const terminalEventType: AuditEventType =
          attempt.state === "delivered"
            ? "delivery.completed.v1"
            : attempt.state === "crashed"
              ? "delivery.recovered.v1"
              : "delivery.failed.v1";
        const terminal = events.filter(
          (row) => row.event_type === terminalEventType && row.attempt === attempt.attempt,
        );
        if (
          terminal.length !== 1 ||
          terminal[0]?.occurred_at !== attempt.finished_at ||
          terminal[0]?.delivery_state !== attempt.result_state ||
          terminal[0]?.retryable !== attempt.retryable
        ) {
          errors.push("Alert attempt does not have one exact terminal audit event");
        }
      }
      if (events.length !== expectedEventCount) {
        errors.push("Alert delivery audit event cardinality is invalid");
      }
    }

    return Object.freeze({
      auditEvents: audit.length,
      attempts: attempts.length,
      deliveries: deliveries.length,
      errors: Object.freeze(errors),
      valid: errors.length === 0,
    });
  }
}

/** Returns true only after the outbox completes its authenticated open path. */
export function isAlertOutbox(value: unknown): value is AlertOutbox {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === AlertOutbox.prototype &&
    AUTHENTIC_ALERT_OUTBOXES.has(value)
  );
}

function metadataStateProjection(row: MetadataRow): JsonValue {
  return {
    auditHeadMac: row.audit_head_mac,
    auditHeadSequence: row.audit_head_sequence,
    keyCheckMac: row.key_check_mac,
    profile: row.profile,
    schemaMac: row.schema_mac,
    schemaVersion: row.schema_version,
  };
}

function deliveryStateProjection(row: DeliveryRow): JsonValue {
  return {
    activeAttempt: row.active_attempt,
    attemptCount: row.attempt_count,
    deliveryId: row.delivery_id,
    payloadBinding: row.payload_binding,
    payloadCiphertext: blobBase64(row.payload_ciphertext),
    payloadNonce: blobBase64(row.payload_nonce),
    payloadTag: blobBase64(row.payload_tag),
    plane: row.plane,
    profile: row.profile,
    queuedAt: row.queued_at,
    rowMac: row.row_mac,
    state: row.state,
    updatedAt: row.updated_at,
  };
}

function attemptStateProjection(row: AttemptRow): JsonValue {
  return {
    attempt: row.attempt,
    deliveryId: row.delivery_id,
    finishedAt: row.finished_at,
    providerBinding: row.provider_binding,
    providerCiphertext: nullableBlobBase64(row.provider_ciphertext),
    providerNonce: nullableBlobBase64(row.provider_nonce),
    providerTag: nullableBlobBase64(row.provider_tag),
    resultState: row.result_state,
    retryable: row.retryable,
    rowMac: row.row_mac,
    startedAt: row.started_at,
    state: row.state,
  };
}

function auditStateProjection(row: AuditRow): JsonValue {
  return {
    attempt: row.attempt,
    deliveryId: row.delivery_id,
    deliveryState: row.delivery_state,
    eventMac: row.event_mac,
    eventType: row.event_type,
    occurredAt: row.occurred_at,
    plane: row.plane,
    previousMac: row.previous_mac,
    retryable: row.retryable,
    sequence: row.sequence,
  };
}

function canonicalAlert(alert: IncidentAlertV1): string {
  return canonicalJson(alert as unknown as JsonValue);
}

function compareTimes(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function booleanToInteger(value: boolean): 0 | 1 {
  return value ? 1 : 0;
}

function blobBase64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64");
}

function nullableBlobBase64(value: Uint8Array | null): string | null {
  return value === null ? null : blobBase64(value);
}

function assertDeliveryState(value: string): DeliveryState {
  if (
    value !== "pending" &&
    value !== "in_flight" &&
    value !== "delivered" &&
    value !== "exhausted"
  ) {
    throw new AlertIntegrityError("Stored alert delivery state is invalid");
  }
  return value;
}

function assertAttemptState(value: string): AttemptState {
  if (value !== "in_flight" && value !== "delivered" && value !== "failed" && value !== "crashed") {
    throw new AlertIntegrityError("Stored alert attempt state is invalid");
  }
  return value;
}

function parseAuditRow(row: AuditRow): void {
  const eventTypes: readonly AuditEventType[] = [
    "alert.queued.v1",
    "delivery.claimed.v1",
    "delivery.completed.v1",
    "delivery.failed.v1",
    "delivery.recovered.v1",
  ];
  if (!eventTypes.includes(row.event_type as AuditEventType)) {
    throw new AlertIntegrityError("Stored alert audit event type is invalid");
  }
  parseWithSchema(AlertPlaneSchema, row.plane, "stored alert audit plane");
  parseWithSchema(CanonicalTimestampSchema, row.occurred_at, "stored alert audit time");
  assertDeliveryState(row.delivery_state);
  if (!/^[0-9a-f]{64}$/.test(row.delivery_id)) {
    throw new AlertIntegrityError("Stored alert audit delivery ID is invalid");
  }
  if (row.attempt !== null && row.attempt !== 1 && row.attempt !== 2) {
    throw new AlertIntegrityError("Stored alert audit attempt is invalid");
  }
  if (row.retryable !== null && row.retryable !== 0 && row.retryable !== 1) {
    throw new AlertIntegrityError("Stored alert audit retry state is invalid");
  }
  if (
    (row.event_type === "alert.queued.v1" &&
      (row.attempt !== null || row.delivery_state !== "pending" || row.retryable !== null)) ||
    (row.event_type === "delivery.claimed.v1" &&
      (row.attempt === null || row.delivery_state !== "in_flight" || row.retryable !== null)) ||
    (row.event_type === "delivery.completed.v1" &&
      (row.attempt === null || row.delivery_state !== "delivered" || row.retryable !== null)) ||
    ((row.event_type === "delivery.failed.v1" || row.event_type === "delivery.recovered.v1") &&
      (row.attempt === null ||
        (row.delivery_state !== "pending" && row.delivery_state !== "exhausted") ||
        row.retryable === null))
  ) {
    throw new AlertIntegrityError("Stored alert audit shape is invalid");
  }
}
