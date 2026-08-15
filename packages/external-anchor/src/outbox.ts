import { DatabaseSync } from "node:sqlite";
import { existsSync, statSync } from "node:fs";

import {
  canonicalJson,
  assertNotProxy,
  strictRecord,
  validateHash,
  validateSafeInteger,
  validateString,
  validateTimestamp,
} from "./canonical.js";
import { deriveExternalAnchorStateKeys, macJson, secureMacEqual } from "./crypto.js";
import {
  ExternalAnchorConflictError,
  ExternalAnchorIntegrityError,
  ExternalAnchorOutboxClosedError,
  ExternalAnchorValidationError,
} from "./errors.js";
import { ExternalAnchorProtocol, parseObjectKey, retentionPolicy, sha256 } from "./protocol.js";
import { assertRetentionResult, createObjectRequest, parseCreateResult } from "./transports.js";
import {
  EXTERNAL_ANCHOR_MAX_ATTEMPTS,
  EXTERNAL_ANCHOR_MAX_BYTES,
  type AnchorOutboxState,
  type ClaimExternalAnchorInput,
  type CompleteExternalAnchorInput,
  type CreateAnchorObjectResult,
  type EnqueueExternalAnchorInput,
  type ExternalAnchorOutboxIntegrityReport,
  type ExternalAnchorPublicationReceipt,
  type ExternalAnchorPublishClaim,
  type ExternalAnchorQueueReceipt,
  type ExternalAnchorRecoveryReceipt,
  type FailExternalAnchorInput,
  type OpenExternalAnchorOutboxOptions,
  type PreparedExternalAnchorObject,
  type RecoverExternalAnchorsInput,
} from "./types.js";

const SCHEMA_VERSION = 1;
const EMPTY_ROWS_MAC = "0".repeat(64);
const MAX_OUTBOX_ROWS = 10_000;
const EXTERNAL_ANCHOR_OUTBOX_CONSTRUCTION_TOKEN = Object.freeze({});
const AUTHENTIC_EXTERNAL_ANCHOR_OUTBOXES = new WeakSet<object>();

interface MetadataRow {
  identity_binding: string;
  key_check_mac: string;
  metadata_mac: string;
  profile: string;
  row_count: number;
  rows_mac: string;
  schema_mac: string;
  schema_version: number;
}

interface AnchorRow {
  active_attempt: number | null;
  attempt_count: number;
  body: string;
  checkpoint_hash: string;
  content_sha256: string;
  disposition: string | null;
  journal_sequence: number;
  object_key: string;
  profile: string;
  queued_at: string;
  retained_until: string | null;
  retention_days: number;
  retention_mode: string;
  row_mac: string;
  state: string;
  stored_at: string | null;
  store_head_sequence: number;
  updated_at: string;
}

export class SqliteExternalAnchorOutbox {
  readonly profile: "canary" | "production-observer";

  readonly #database: DatabaseSync;
  readonly #identityBinding: string;
  readonly #macKey: Buffer;
  readonly #protocol: ExternalAnchorProtocol;
  #closed = false;

  static open(options: OpenExternalAnchorOutboxOptions): SqliteExternalAnchorOutbox {
    const record = strictRecord(
      options,
      [
        "databasePath",
        "expectedKeyId",
        "expectedPublicKey",
        "expectedStoreId",
        "profile",
        "stateKey",
      ],
      "external anchor outbox options",
    );
    const databasePath = validateString(record.databasePath, "databasePath", 4_096);
    if (databasePath.includes("\0")) {
      throw new ExternalAnchorValidationError("databasePath may not contain NUL");
    }
    if (!(record.stateKey instanceof Uint8Array)) {
      throw new ExternalAnchorValidationError("stateKey must be a Uint8Array");
    }
    assertNotProxy(record.stateKey, "stateKey");
    if (record.profile !== "canary" && record.profile !== "production-observer") {
      throw new ExternalAnchorValidationError("profile is invalid");
    }
    const outbox = new SqliteExternalAnchorOutbox(
      {
        databasePath,
        expectedKeyId: record.expectedKeyId as string,
        expectedPublicKey:
          record.expectedPublicKey as OpenExternalAnchorOutboxOptions["expectedPublicKey"],
        expectedStoreId: record.expectedStoreId as string,
        profile: record.profile,
        stateKey: record.stateKey,
      },
      EXTERNAL_ANCHOR_OUTBOX_CONSTRUCTION_TOKEN,
    );
    AUTHENTIC_EXTERNAL_ANCHOR_OUTBOXES.add(outbox);
    return outbox;
  }

  private constructor(options: OpenExternalAnchorOutboxOptions, constructionToken: unknown) {
    if (constructionToken !== EXTERNAL_ANCHOR_OUTBOX_CONSTRUCTION_TOKEN) {
      throw new ExternalAnchorIntegrityError(
        "external anchor outbox construction was not authenticated",
      );
    }
    this.profile = options.profile;
    this.#protocol = new ExternalAnchorProtocol({
      expectedKeyId: options.expectedKeyId,
      expectedPublicKey: options.expectedPublicKey,
      expectedStoreId: options.expectedStoreId,
    });
    const keys = deriveExternalAnchorStateKeys(options.stateKey);
    this.#macKey = keys.macKey;
    this.#identityBinding = macJson(this.#macKey, "identity-binding", {
      expectedKeyId: this.#protocol.expectedKeyId,
      expectedStoreId: this.#protocol.expectedStoreId,
      profile: this.profile,
      publicKeyFingerprint: this.#protocol.publicKeyFingerprint,
    });
    let databaseHadContent = false;
    try {
      databaseHadContent =
        existsSync(options.databasePath) && statSync(options.databasePath).size > 0;
    } catch {
      this.#macKey.fill(0);
      throw new ExternalAnchorValidationError("external anchor database path is not readable");
    }
    try {
      this.#database = new DatabaseSync(options.databasePath);
    } catch (error) {
      this.#macKey.fill(0);
      throw error;
    }
    try {
      this.configure();
      this.initialize(databaseHadContent);
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) {
        throw new ExternalAnchorIntegrityError(integrity.errors.join("; "));
      }
    } catch (error) {
      this.#macKey.fill(0);
      this.#database.close();
      throw error;
    }
  }

  enqueue(input: EnqueueExternalAnchorInput): ExternalAnchorQueueReceipt {
    const record = strictRecord(
      input,
      ["authorization", "checkpoint", "queuedAt"],
      "external anchor enqueue",
    );
    const queuedAt = validateTimestamp(record.queuedAt, "queuedAt");
    const prepared = this.#protocol.prepare({
      authorization: record.authorization as EnqueueExternalAnchorInput["authorization"],
      checkpoint: record.checkpoint as EnqueueExternalAnchorInput["checkpoint"],
    });
    if (prepared.profile !== this.profile) {
      throw new ExternalAnchorValidationError("anchor authorization crosses the outbox profile");
    }
    const envelope = this.#protocol.parseAndVerifyBody(prepared.body);
    if (queuedAt < envelope.checkpoint.payload.createdAt) {
      throw new ExternalAnchorValidationError("queuedAt predates the signed checkpoint");
    }

    return this.transaction(() => {
      const byKey = this.getRow(prepared.objectKey);
      const bySequence = this.#database
        .prepare(`SELECT * FROM rsi_external_anchor_outbox WHERE journal_sequence = ?`)
        .get(prepared.journalSequence) as AnchorRow | undefined;
      if (byKey !== undefined || bySequence !== undefined) {
        if (
          byKey === undefined ||
          bySequence === undefined ||
          byKey.object_key !== bySequence.object_key
        ) {
          throw new ExternalAnchorConflictError(
            "JOURNAL_FORK",
            "journal sequence is already bound to a different external anchor",
          );
        }
        this.assertRow(byKey);
        if (!this.rowMatchesPrepared(byKey, prepared, queuedAt)) {
          throw new ExternalAnchorConflictError(
            "ANCHOR_CONFLICT",
            "external anchor identity was reused with conflicting content",
          );
        }
        return this.queueReceipt(byKey);
      }
      const count = (
        this.#database
          .prepare(`SELECT count(*) AS count FROM rsi_external_anchor_outbox`)
          .get() as {
          count: number;
        }
      ).count;
      if (count >= MAX_OUTBOX_ROWS) {
        throw new ExternalAnchorValidationError(
          `external anchor outbox reached its ${MAX_OUTBOX_ROWS}-row rotation bound`,
        );
      }
      const unsigned: Omit<AnchorRow, "row_mac"> = {
        active_attempt: null,
        attempt_count: 0,
        body: prepared.body,
        checkpoint_hash: prepared.checkpointHash,
        content_sha256: prepared.contentSha256,
        disposition: null,
        journal_sequence: prepared.journalSequence,
        object_key: prepared.objectKey,
        profile: prepared.profile,
        queued_at: queuedAt,
        retained_until: null,
        retention_days: prepared.retention.days,
        retention_mode: prepared.retention.mode,
        state: "pending",
        stored_at: null,
        store_head_sequence: prepared.storeHeadSequence,
        updated_at: queuedAt,
      };
      const row = { ...unsigned, row_mac: this.rowMac(unsigned) };
      this.#database
        .prepare(
          `INSERT INTO rsi_external_anchor_outbox (
             object_key, profile, body, content_sha256, checkpoint_hash,
             journal_sequence, store_head_sequence, retention_mode, retention_days,
             state, attempt_count, active_attempt, queued_at, updated_at,
             stored_at, retained_until, disposition, row_mac
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          row.object_key,
          row.profile,
          row.body,
          row.content_sha256,
          row.checkpoint_hash,
          row.journal_sequence,
          row.store_head_sequence,
          row.retention_mode,
          row.retention_days,
          row.state,
          row.attempt_count,
          row.active_attempt,
          row.queued_at,
          row.updated_at,
          row.stored_at,
          row.retained_until,
          row.disposition,
          row.row_mac,
        );
      this.refreshMetadataProjection();
      return this.queueReceipt(row);
    });
  }

  claim(input: ClaimExternalAnchorInput): ExternalAnchorPublishClaim | undefined {
    const record = strictRecord(input, ["claimedAt"], "external anchor claim");
    const claimedAt = validateTimestamp(record.claimedAt, "claimedAt");
    return this.transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT * FROM rsi_external_anchor_outbox
            WHERE state = 'pending'
            ORDER BY journal_sequence
            LIMIT 1`,
        )
        .get() as AnchorRow | undefined;
      if (row === undefined) return undefined;
      this.assertRow(row);
      if (claimedAt < row.updated_at) {
        throw new ExternalAnchorValidationError("claimedAt regresses anchor state time");
      }
      const attempt = row.attempt_count + 1;
      if (attempt !== 1 && attempt !== 2) {
        throw new ExternalAnchorIntegrityError("pending anchor has no bounded attempt available");
      }
      const unsigned: Omit<AnchorRow, "row_mac"> = {
        ...this.withoutRowMac(row),
        active_attempt: attempt,
        attempt_count: attempt,
        state: "in_flight",
        updated_at: claimedAt,
      };
      const updated = this.writeRow(unsigned);
      this.refreshMetadataProjection();
      return Object.freeze({
        ...this.queueReceipt(updated),
        attempt,
        request: createObjectRequest(this.preparedFromRow(updated)),
      });
    });
  }

  complete(input: CompleteExternalAnchorInput): ExternalAnchorPublicationReceipt {
    const record = strictRecord(
      input,
      ["attempt", "completedAt", "objectKey", "result"],
      "external anchor completion",
    );
    const attempt = parseAttempt(record.attempt);
    const completedAt = validateTimestamp(record.completedAt, "completedAt");
    parseObjectKey(record.objectKey);
    const result = parseCreateResult(record.result);
    return this.transaction(() => {
      const row = this.getRow(record.objectKey as string);
      if (row === undefined) throw new ExternalAnchorValidationError("anchor object is unknown");
      this.assertRow(row);
      if (row.state === "published") {
        if (!this.completionMatches(row, attempt, completedAt, result)) {
          throw new ExternalAnchorConflictError(
            "ANCHOR_CONFLICT",
            "published anchor completion was retried with different content",
          );
        }
        return this.publicationReceipt(row);
      }
      if (row.state !== "in_flight" || row.active_attempt !== attempt) {
        throw new ExternalAnchorConflictError(
          "ANCHOR_CONFLICT",
          "anchor completion does not match the active attempt",
        );
      }
      if (
        completedAt < row.updated_at ||
        completedAt < result.storedAt ||
        result.storedAt < row.queued_at ||
        (result.disposition === "created" && result.storedAt < row.updated_at)
      ) {
        throw new ExternalAnchorValidationError("anchor completion timestamps are inconsistent");
      }
      this.assertResultMatchesRow(row, result);
      const unsigned: Omit<AnchorRow, "row_mac"> = {
        ...this.withoutRowMac(row),
        active_attempt: null,
        disposition: result.disposition,
        retained_until: result.retainedUntil,
        state: "published",
        stored_at: result.storedAt,
        updated_at: completedAt,
      };
      const updated = this.writeRow(unsigned);
      this.refreshMetadataProjection();
      return this.publicationReceipt(updated);
    });
  }

  fail(input: FailExternalAnchorInput): ExternalAnchorQueueReceipt {
    const record = strictRecord(
      input,
      ["attempt", "failedAt", "objectKey", "retryable"],
      "external anchor failure",
    );
    const attempt = parseAttempt(record.attempt);
    const failedAt = validateTimestamp(record.failedAt, "failedAt");
    parseObjectKey(record.objectKey);
    if (typeof record.retryable !== "boolean") {
      throw new ExternalAnchorValidationError("retryable must be boolean");
    }
    return this.transaction(() => {
      const row = this.getRow(record.objectKey as string);
      if (row === undefined) throw new ExternalAnchorValidationError("anchor object is unknown");
      this.assertRow(row);
      const expectedState =
        record.retryable && attempt < EXTERNAL_ANCHOR_MAX_ATTEMPTS ? "pending" : "failed";
      if (row.state !== "in_flight") {
        if (
          row.active_attempt === null &&
          row.attempt_count === attempt &&
          row.state === expectedState &&
          row.updated_at === failedAt
        ) {
          return this.queueReceipt(row);
        }
        throw new ExternalAnchorConflictError(
          "ANCHOR_CONFLICT",
          "anchor failure does not match the active attempt",
        );
      }
      if (row.active_attempt !== attempt || failedAt < row.updated_at) {
        throw new ExternalAnchorConflictError(
          "ANCHOR_CONFLICT",
          "anchor failure does not match the active attempt",
        );
      }
      const unsigned: Omit<AnchorRow, "row_mac"> = {
        ...this.withoutRowMac(row),
        active_attempt: null,
        state: expectedState,
        updated_at: failedAt,
      };
      const updated = this.writeRow(unsigned);
      this.refreshMetadataProjection();
      return this.queueReceipt(updated);
    });
  }

  recover(input: RecoverExternalAnchorsInput): ExternalAnchorRecoveryReceipt {
    const record = strictRecord(input, ["recoveredAt"], "external anchor recovery");
    const recoveredAt = validateTimestamp(record.recoveredAt, "recoveredAt");
    return this.transaction(() => {
      const rows = this.#database
        .prepare(
          `SELECT * FROM rsi_external_anchor_outbox
            WHERE state = 'in_flight'
            ORDER BY journal_sequence`,
        )
        .all() as unknown as AnchorRow[];
      let failed = 0;
      let requeued = 0;
      for (const row of rows) {
        this.assertRow(row);
        if (recoveredAt < row.updated_at) {
          throw new ExternalAnchorValidationError("recoveredAt regresses anchor state time");
        }
        const state = row.attempt_count < EXTERNAL_ANCHOR_MAX_ATTEMPTS ? "pending" : "failed";
        if (state === "pending") requeued += 1;
        else failed += 1;
        this.writeRow({
          ...this.withoutRowMac(row),
          active_attempt: null,
          state,
          updated_at: recoveredAt,
        });
      }
      if (rows.length > 0) this.refreshMetadataProjection();
      return Object.freeze({ failed, recoveredAt, requeued });
    });
  }

  get(objectKeyInput: string): ExternalAnchorQueueReceipt | undefined {
    this.assertOpen();
    parseObjectKey(objectKeyInput);
    const row = this.getRow(objectKeyInput);
    if (row === undefined) return undefined;
    this.assertRow(row);
    return this.queueReceipt(row);
  }

  verifyIntegrity(): ExternalAnchorOutboxIntegrityReport {
    this.assertOpen();
    return this.verifyIntegrityInternal();
  }

  close(): void {
    this.assertAuthentic();
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
    this.#macKey.fill(0);
  }

  [Symbol.dispose](): void {
    this.close();
  }

  private configure(): void {
    this.#database.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA trusted_schema = OFF;
    `);
  }

  private initialize(databaseHadContent: boolean): void {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const existingTables = this.#database
        .prepare(
          `SELECT name FROM sqlite_schema
            WHERE type = 'table'
              AND name IN ('rsi_external_anchor_metadata', 'rsi_external_anchor_outbox')
            ORDER BY name`,
        )
        .all() as unknown as ReadonlyArray<Readonly<{ name: string }>>;
      if (existingTables.length === 1 || (existingTables.length === 0 && databaseHadContent)) {
        throw new ExternalAnchorIntegrityError(
          "external anchor database initialization state is inconsistent",
        );
      }
      const initializeMetadata = existingTables.length === 0;
      this.#database.exec(`
        CREATE TABLE IF NOT EXISTS rsi_external_anchor_metadata (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          schema_version INTEGER NOT NULL,
          profile TEXT NOT NULL,
          identity_binding TEXT NOT NULL CHECK(length(identity_binding) = 64),
          row_count INTEGER NOT NULL CHECK(row_count >= 0),
          rows_mac TEXT NOT NULL CHECK(length(rows_mac) = 64),
          schema_mac TEXT NOT NULL CHECK(length(schema_mac) = 64),
          key_check_mac TEXT NOT NULL CHECK(length(key_check_mac) = 64),
          metadata_mac TEXT NOT NULL CHECK(length(metadata_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_external_anchor_outbox (
          object_key TEXT PRIMARY KEY,
          profile TEXT NOT NULL,
          body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 4096),
          content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
          checkpoint_hash TEXT NOT NULL CHECK(length(checkpoint_hash) = 64),
          journal_sequence INTEGER NOT NULL UNIQUE CHECK(journal_sequence >= 1),
          store_head_sequence INTEGER NOT NULL CHECK(store_head_sequence >= 1),
          retention_mode TEXT NOT NULL CHECK(retention_mode IN ('governance', 'compliance')),
          retention_days INTEGER NOT NULL CHECK(retention_days IN (30, 365)),
          state TEXT NOT NULL CHECK(state IN ('pending', 'in_flight', 'published', 'failed')),
          attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 2),
          active_attempt INTEGER CHECK(active_attempt IS NULL OR active_attempt IN (1, 2)),
          queued_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          stored_at TEXT,
          retained_until TEXT,
          disposition TEXT CHECK(disposition IS NULL OR disposition IN ('created', 'already_exists')),
          row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
        ) STRICT;
      `);
      const initial: Omit<MetadataRow, "metadata_mac"> = {
        identity_binding: this.#identityBinding,
        key_check_mac: this.keyCheckMac(),
        profile: this.profile,
        row_count: 0,
        rows_mac: EMPTY_ROWS_MAC,
        schema_mac: this.schemaMac(),
        schema_version: SCHEMA_VERSION,
      };
      if (initializeMetadata) {
        this.#database
          .prepare(
            `INSERT INTO rsi_external_anchor_metadata (
               singleton, schema_version, profile, identity_binding,
               row_count, rows_mac, schema_mac, key_check_mac, metadata_mac
             ) VALUES (1, ?, ?, ?, 0, ?, ?, ?, ?)`,
          )
          .run(
            SCHEMA_VERSION,
            this.profile,
            this.#identityBinding,
            EMPTY_ROWS_MAC,
            initial.schema_mac,
            initial.key_check_mac,
            this.metadataMac(initial),
          );
      }
      this.#database.exec("COMMIT");
    } catch (error) {
      if (this.#database.isTransaction) this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  private transaction<T>(operation: () => T): T {
    this.assertOpen();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) throw new ExternalAnchorIntegrityError(integrity.errors.join("; "));
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.#database.isTransaction) this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  private verifyIntegrityInternal(): ExternalAnchorOutboxIntegrityReport {
    const errors: string[] = [];
    let metadata: MetadataRow | undefined;
    try {
      metadata = this.metadata();
      this.assertMetadata(metadata);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "metadata is invalid");
    }
    let rows: AnchorRow[] = [];
    try {
      rows = this.#database
        .prepare(`SELECT * FROM rsi_external_anchor_outbox ORDER BY object_key`)
        .all() as unknown as AnchorRow[];
      for (const row of rows) this.assertRow(row);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "outbox rows are invalid");
    }
    if (metadata !== undefined) {
      const rowsMac = this.rowsMac(rows);
      if (metadata.row_count !== rows.length || !secureMacEqual(metadata.rows_mac, rowsMac)) {
        errors.push("outbox row-set projection failed authentication");
      }
    }
    return Object.freeze({
      errors: Object.freeze(errors),
      failedCount: rows.filter((row) => row.state === "failed").length,
      inFlightCount: rows.filter((row) => row.state === "in_flight").length,
      pendingCount: rows.filter((row) => row.state === "pending").length,
      profile: this.profile,
      publishedCount: rows.filter((row) => row.state === "published").length,
      rowCount: rows.length,
      valid: errors.length === 0,
    });
  }

  private assertMetadata(row: MetadataRow): void {
    if (
      row.schema_version !== SCHEMA_VERSION ||
      row.profile !== this.profile ||
      row.identity_binding !== this.#identityBinding ||
      !Number.isSafeInteger(row.row_count) ||
      row.row_count < 0 ||
      !secureMacEqual(row.key_check_mac, this.keyCheckMac()) ||
      !secureMacEqual(row.schema_mac, this.schemaMac())
    ) {
      throw new ExternalAnchorIntegrityError("external anchor metadata identity is invalid");
    }
    const expected = this.metadataMac({
      identity_binding: row.identity_binding,
      key_check_mac: row.key_check_mac,
      profile: row.profile,
      row_count: row.row_count,
      rows_mac: row.rows_mac,
      schema_mac: row.schema_mac,
      schema_version: row.schema_version,
    });
    if (!secureMacEqual(row.metadata_mac, expected)) {
      throw new ExternalAnchorIntegrityError("external anchor metadata failed authentication");
    }
  }

  private assertRow(row: AnchorRow): void {
    const key = parseObjectKey(row.object_key);
    if (
      key.profile !== this.profile ||
      row.profile !== this.profile ||
      key.journalSequence !== row.journal_sequence ||
      key.checkpointHash !== row.checkpoint_hash
    ) {
      throw new ExternalAnchorIntegrityError("external anchor row identity is inconsistent");
    }
    validateHash(row.content_sha256, "stored content hash");
    if (
      sha256(row.body) !== row.content_sha256 ||
      Buffer.byteLength(row.body, "utf8") > EXTERNAL_ANCHOR_MAX_BYTES
    ) {
      throw new ExternalAnchorIntegrityError("external anchor row body is invalid");
    }
    const envelope = this.#protocol.parseAndVerifyBody(row.body);
    if (
      envelope.authorization.payload.profile !== this.profile ||
      envelope.authorization.payload.retention.days !== row.retention_days ||
      envelope.authorization.payload.retention.mode !== row.retention_mode ||
      envelope.checkpoint.checkpointHash !== row.checkpoint_hash ||
      envelope.checkpoint.payload.journalSequence !== row.journal_sequence ||
      envelope.checkpoint.payload.storeHeadSequence !== row.store_head_sequence
    ) {
      throw new ExternalAnchorIntegrityError("external anchor row does not match its body");
    }
    const retention = retentionPolicy(row.retention_mode);
    if (retention.days !== row.retention_days) {
      throw new ExternalAnchorIntegrityError("external anchor row retention is inconsistent");
    }
    validateTimestamp(row.queued_at, "stored queuedAt");
    validateTimestamp(row.updated_at, "stored updatedAt");
    if (row.updated_at < row.queued_at) {
      throw new ExternalAnchorIntegrityError("external anchor row time regressed");
    }
    validateSafeInteger(row.attempt_count, "stored attempt count", 0);
    if (row.attempt_count > EXTERNAL_ANCHOR_MAX_ATTEMPTS) {
      throw new ExternalAnchorIntegrityError("external anchor attempt bound is invalid");
    }
    const activeValid =
      (row.state === "pending" && row.active_attempt === null && row.attempt_count < 2) ||
      (row.state === "in_flight" &&
        row.active_attempt === row.attempt_count &&
        row.attempt_count >= 1) ||
      (row.state === "failed" && row.active_attempt === null && row.attempt_count >= 1) ||
      (row.state === "published" && row.active_attempt === null && row.attempt_count >= 1);
    if (!activeValid)
      throw new ExternalAnchorIntegrityError("external anchor row state is invalid");
    const hasPublication =
      row.stored_at !== null && row.retained_until !== null && row.disposition !== null;
    if ((row.state === "published") !== hasPublication) {
      throw new ExternalAnchorIntegrityError("external anchor publication fields are inconsistent");
    }
    if (row.state === "published") {
      validateTimestamp(row.stored_at, "stored provider time");
      validateTimestamp(row.retained_until, "stored retention time");
      if (row.updated_at < row.stored_at!) {
        throw new ExternalAnchorIntegrityError(
          "external anchor completion predates provider storage",
        );
      }
      assertRetentionResult(retention, {
        contentSha256: row.content_sha256,
        objectKey: row.object_key,
        retainedUntil: row.retained_until!,
        retentionMode: retention.mode,
        sizeBytes: Buffer.byteLength(row.body, "utf8"),
        storedAt: row.stored_at!,
      });
    }
    const expectedMac = this.rowMac(this.withoutRowMac(row));
    if (!secureMacEqual(row.row_mac, expectedMac)) {
      throw new ExternalAnchorIntegrityError("external anchor row failed authentication");
    }
  }

  private metadata(): MetadataRow {
    const row = this.#database
      .prepare(`SELECT * FROM rsi_external_anchor_metadata WHERE singleton = 1`)
      .get() as MetadataRow | undefined;
    if (row === undefined) throw new ExternalAnchorIntegrityError("metadata is missing");
    return row;
  }

  private refreshMetadataProjection(): void {
    const metadata = this.metadata();
    const rows = this.#database
      .prepare(`SELECT * FROM rsi_external_anchor_outbox ORDER BY object_key`)
      .all() as unknown as AnchorRow[];
    const next: Omit<MetadataRow, "metadata_mac"> = {
      identity_binding: metadata.identity_binding,
      key_check_mac: metadata.key_check_mac,
      profile: metadata.profile,
      row_count: rows.length,
      rows_mac: this.rowsMac(rows),
      schema_mac: metadata.schema_mac,
      schema_version: metadata.schema_version,
    };
    const updated = this.#database
      .prepare(
        `UPDATE rsi_external_anchor_metadata
            SET row_count = ?, rows_mac = ?, metadata_mac = ?
          WHERE singleton = 1 AND metadata_mac = ?`,
      )
      .run(next.row_count, next.rows_mac, this.metadataMac(next), metadata.metadata_mac);
    if (updated.changes !== 1) {
      throw new ExternalAnchorIntegrityError("metadata projection update failed");
    }
  }

  private rowsMac(rows: readonly AnchorRow[]): string {
    return rows.length === 0
      ? EMPTY_ROWS_MAC
      : macJson(
          this.#macKey,
          "row-set",
          rows.map((row) => ({ objectKey: row.object_key, rowMac: row.row_mac })),
        );
  }

  private keyCheckMac(): string {
    return macJson(this.#macKey, "key-check", {
      identityBinding: this.#identityBinding,
      schemaVersion: SCHEMA_VERSION,
    });
  }

  private metadataMac(row: Omit<MetadataRow, "metadata_mac">): string {
    return macJson(this.#macKey, "metadata-row", {
      identityBinding: row.identity_binding,
      keyCheckMac: row.key_check_mac,
      profile: row.profile,
      rowCount: row.row_count,
      rowsMac: row.rows_mac,
      schemaMac: row.schema_mac,
      schemaVersion: row.schema_version,
    });
  }

  private schemaMac(): string {
    const rows = this.#database
      .prepare(
        `SELECT type, name, tbl_name, sql
           FROM sqlite_schema
          WHERE name NOT LIKE 'sqlite_%'
          ORDER BY type, name, tbl_name`,
      )
      .all() as unknown as ReadonlyArray<
      Readonly<{ name: string; sql: string | null; tbl_name: string; type: string }>
    >;
    return macJson(
      this.#macKey,
      "sqlite-schema",
      rows.map((row) => ({
        name: row.name,
        sql: row.sql,
        tableName: row.tbl_name,
        type: row.type,
      })),
    );
  }

  private rowMac(row: Omit<AnchorRow, "row_mac">): string {
    return macJson(this.#macKey, "outbox-row", {
      activeAttempt: row.active_attempt,
      attemptCount: row.attempt_count,
      body: row.body,
      checkpointHash: row.checkpoint_hash,
      contentSha256: row.content_sha256,
      disposition: row.disposition,
      journalSequence: row.journal_sequence,
      objectKey: row.object_key,
      profile: row.profile,
      queuedAt: row.queued_at,
      retainedUntil: row.retained_until,
      retentionDays: row.retention_days,
      retentionMode: row.retention_mode,
      state: row.state,
      storedAt: row.stored_at,
      storeHeadSequence: row.store_head_sequence,
      updatedAt: row.updated_at,
    });
  }

  private getRow(objectKey: string): AnchorRow | undefined {
    return this.#database
      .prepare(`SELECT * FROM rsi_external_anchor_outbox WHERE object_key = ?`)
      .get(objectKey) as AnchorRow | undefined;
  }

  private writeRow(row: Omit<AnchorRow, "row_mac">): AnchorRow {
    const rowMac = this.rowMac(row);
    const updated = this.#database
      .prepare(
        `UPDATE rsi_external_anchor_outbox SET
           profile = ?, body = ?, content_sha256 = ?, checkpoint_hash = ?,
           journal_sequence = ?, store_head_sequence = ?, retention_mode = ?,
           retention_days = ?, state = ?, attempt_count = ?, active_attempt = ?,
           queued_at = ?, updated_at = ?, stored_at = ?, retained_until = ?,
           disposition = ?, row_mac = ?
         WHERE object_key = ?`,
      )
      .run(
        row.profile,
        row.body,
        row.content_sha256,
        row.checkpoint_hash,
        row.journal_sequence,
        row.store_head_sequence,
        row.retention_mode,
        row.retention_days,
        row.state,
        row.attempt_count,
        row.active_attempt,
        row.queued_at,
        row.updated_at,
        row.stored_at,
        row.retained_until,
        row.disposition,
        rowMac,
        row.object_key,
      );
    if (updated.changes !== 1) throw new ExternalAnchorIntegrityError("outbox row update failed");
    return { ...row, row_mac: rowMac };
  }

  private withoutRowMac(row: AnchorRow): Omit<AnchorRow, "row_mac"> {
    const { row_mac: _rowMac, ...unsigned } = row;
    return unsigned;
  }

  private preparedFromRow(row: AnchorRow): PreparedExternalAnchorObject {
    return Object.freeze({
      body: row.body,
      checkpointHash: row.checkpoint_hash,
      contentSha256: row.content_sha256,
      journalSequence: row.journal_sequence,
      objectKey: row.object_key,
      profile: this.profile,
      retention: retentionPolicy(row.retention_mode),
      sizeBytes: Buffer.byteLength(row.body, "utf8"),
      storeHeadSequence: row.store_head_sequence,
    });
  }

  private rowMatchesPrepared(
    row: AnchorRow,
    prepared: PreparedExternalAnchorObject,
    queuedAt: string,
  ): boolean {
    return (
      row.body === prepared.body &&
      row.content_sha256 === prepared.contentSha256 &&
      row.checkpoint_hash === prepared.checkpointHash &&
      row.journal_sequence === prepared.journalSequence &&
      row.profile === prepared.profile &&
      row.queued_at === queuedAt &&
      row.retention_days === prepared.retention.days &&
      row.retention_mode === prepared.retention.mode &&
      row.store_head_sequence === prepared.storeHeadSequence
    );
  }

  private completionMatches(
    row: AnchorRow,
    attempt: 1 | 2,
    completedAt: string,
    result: CreateAnchorObjectResult,
  ): boolean {
    return (
      row.attempt_count === attempt &&
      row.updated_at === completedAt &&
      row.disposition === result.disposition &&
      row.stored_at === result.storedAt &&
      row.retained_until === result.retainedUntil &&
      result.objectKey === row.object_key &&
      result.contentSha256 === row.content_sha256 &&
      result.sizeBytes === Buffer.byteLength(row.body, "utf8") &&
      result.retentionMode === row.retention_mode
    );
  }

  private assertResultMatchesRow(row: AnchorRow, result: CreateAnchorObjectResult): void {
    if (
      result.objectKey !== row.object_key ||
      result.contentSha256 !== row.content_sha256 ||
      result.sizeBytes !== Buffer.byteLength(row.body, "utf8") ||
      result.retentionMode !== row.retention_mode
    ) {
      throw new ExternalAnchorConflictError(
        "ANCHOR_CONFLICT",
        "provider creation result does not match the claimed object",
      );
    }
    assertRetentionResult(retentionPolicy(row.retention_mode), result);
  }

  private queueReceipt(row: AnchorRow): ExternalAnchorQueueReceipt {
    return Object.freeze({
      attemptCount: row.attempt_count,
      checkpointHash: row.checkpoint_hash,
      journalSequence: row.journal_sequence,
      objectKey: row.object_key,
      profile: this.profile,
      queuedAt: row.queued_at,
      retentionMode: retentionPolicy(row.retention_mode).mode,
      state: row.state as AnchorOutboxState,
      storeHeadSequence: row.store_head_sequence,
      updatedAt: row.updated_at,
    });
  }

  private publicationReceipt(row: AnchorRow): ExternalAnchorPublicationReceipt {
    if (
      row.state !== "published" ||
      (row.disposition !== "created" && row.disposition !== "already_exists") ||
      row.retained_until === null ||
      row.stored_at === null
    ) {
      throw new ExternalAnchorIntegrityError("row does not contain a publication receipt");
    }
    return Object.freeze({
      ...this.queueReceipt(row),
      disposition: row.disposition,
      retainedUntil: row.retained_until,
      storedAt: row.stored_at,
    });
  }

  private assertOpen(): void {
    this.assertAuthentic();
    if (this.#closed) throw new ExternalAnchorOutboxClosedError();
  }

  private assertAuthentic(): void {
    if (
      Object.getPrototypeOf(this) !== SqliteExternalAnchorOutbox.prototype ||
      !AUTHENTIC_EXTERNAL_ANCHOR_OUTBOXES.has(this)
    ) {
      throw new ExternalAnchorIntegrityError(
        "external anchor outbox was not opened through its authenticated factory",
      );
    }
  }
}

/** Returns true only after the outbox completes its authenticated open path. */
export function isSqliteExternalAnchorOutbox(value: unknown): value is SqliteExternalAnchorOutbox {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === SqliteExternalAnchorOutbox.prototype &&
    AUTHENTIC_EXTERNAL_ANCHOR_OUTBOXES.has(value)
  );
}

function parseAttempt(value: unknown): 1 | 2 {
  if (value !== 1 && value !== 2) {
    throw new ExternalAnchorValidationError("attempt must be 1 or 2");
  }
  return value;
}
