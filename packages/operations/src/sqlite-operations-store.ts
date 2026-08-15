import { randomBytes, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, type JsonValue } from "@rsi/store";
import { z } from "zod";

import {
  decryptCursor,
  deriveOperationsKeys,
  encryptCursor,
  macJson,
  secureEqualHex,
  sha256,
} from "./crypto.js";
import {
  BudgetExceededError,
  InvalidAttemptPermitError,
  OperationsClosedError,
  OperationsConflictError,
  OperationsIntegrityError,
  OperationsValidationError,
} from "./errors.js";
import {
  createNetworkAttemptAuthorization,
  type NetworkAttemptAuthorization,
} from "./network-authorization.js";
import {
  AttemptPermitTokenSchema,
  CanonicalTimestampSchema,
  HashSchema,
  IdentifierSchema,
  OpaqueCursorSchema,
  OperationsProfileSchema,
  PositiveAtomicAmountSchema,
  ResearchLaneSchema,
  ResearchOperationSchema,
  SourcePlaneSchema,
  UuidSchema,
  parseWithSchema,
} from "./schemas.js";
import type {
  AttemptPermit,
  AttemptPermitToken,
  AttemptRecord,
  AttemptState,
  AtomicAmount,
  BudgetRecord,
  BudgetSummary,
  CreateBudgetInput,
  CursorAdvanceRecord,
  CursorAdvanceState,
  CursorCommitReceipt,
  CursorIdentity,
  CursorState,
  DurableNetworkAttemptBinding,
  ExternalAnchorReceipt,
  ExternalVerificationReceipt,
  InitializeCursorLineageInput,
  LocalCheckpointReceipt,
  OperationsIntegrityReport,
  ReserveAttemptInput,
  SafeEventReceipt,
  SessionAttemptSummaryV1,
  SourceAttemptGroupSummaryV1,
  StageCursorAdvanceInput,
} from "./types.js";

const SCHEMA_VERSION = 2;
const GENESIS_MAC = "0".repeat(64);
const MAX_AUTHORIZATION_WINDOW_MS = 2 * 60 * 60 * 1_000;
const authenticSqliteOperationsStores = new WeakSet<object>();
const CURSOR_ADVANCE_ORDER: readonly CursorAdvanceState[] = [
  "staged",
  "validated",
  "event_persisted",
  "checkpointed",
  "anchor_published",
  "externally_verified",
  "committed",
];

const CreateBudgetInputSchema = z.strictObject({
  budgetId: UuidSchema,
  createdAt: CanonicalTimestampSchema,
  currency: z.literal("USD_MICRO"),
  endsAt: CanonicalTimestampSchema,
  maxAtomic: PositiveAtomicAmountSchema,
  maxAttempts: z.number().int().min(1).max(10_000),
  profile: OperationsProfileSchema,
  startsAt: CanonicalTimestampSchema,
});

const ReserveAttemptInputSchema = z.strictObject({
  attemptId: UuidSchema,
  authorizationExpiresAt: CanonicalTimestampSchema,
  budgetId: UuidSchema,
  createdAt: CanonicalTimestampSchema,
  idempotencyKey: IdentifierSchema,
  lane: ResearchLaneSchema,
  operation: ResearchOperationSchema,
  permitToken: AttemptPermitTokenSchema,
  reservedAtomic: PositiveAtomicAmountSchema,
  sessionId: UuidSchema,
  sourcePlane: SourcePlaneSchema,
});

const AttemptPermitSchema = z.strictObject({
  attemptId: UuidSchema,
  token: AttemptPermitTokenSchema,
});

const CursorIdentitySchema = z.strictObject({
  lane: ResearchLaneSchema,
  profile: OperationsProfileSchema,
  sourcePlane: SourcePlaneSchema,
});

const InitializeCursorLineageInputSchema = CursorIdentitySchema.extend({
  initializedAt: CanonicalTimestampSchema,
  lineageId: UuidSchema,
}).strict();

const StageCursorAdvanceInputSchema = CursorIdentitySchema.extend({
  advanceId: UuidSchema,
  attemptId: UuidSchema,
  candidateCursor: OpaqueCursorSchema,
  expectedRevision: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  lineageId: UuidSchema,
  stagedAt: CanonicalTimestampSchema,
}).strict();

const SafeEventReceiptSchema = z.strictObject({
  eventHash: HashSchema,
  eventId: UuidSchema,
  eventSequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  persistedAt: CanonicalTimestampSchema,
});

const LocalCheckpointReceiptSchema = z.strictObject({
  anchoredThroughSequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  checkpointHead: HashSchema,
  checkpointedAt: CanonicalTimestampSchema,
});

const ExternalAnchorReceiptSchema = z.strictObject({
  anchorHead: HashSchema,
  anchorId: UuidSchema,
  publishedAt: CanonicalTimestampSchema,
});

const ExternalVerificationReceiptSchema = z.strictObject({
  anchorHead: HashSchema,
  anchorId: UuidSchema,
  verifiedAt: CanonicalTimestampSchema,
});

interface MetadataRow {
  audit_head_mac: string;
  audit_head_sequence: number;
  cursor_erasure_pending: number;
  key_check_mac: string;
  metadata_mac: string;
  schema_version: number;
}

interface AuditRow {
  aggregate_id: string;
  event_mac: string;
  event_type: string;
  occurred_at: string;
  payload_json: string;
  previous_mac: string;
  sequence: number;
}

interface BudgetRow {
  budget_id: string;
  created_at: string;
  currency: "USD_MICRO";
  ends_at: string;
  max_atomic: string;
  max_attempts: number;
  profile: string;
  row_mac: string;
  starts_at: string;
}

interface AttemptRow {
  attempt_id: string;
  authorization_expires_at: string;
  budget_id: string;
  closed_at: string | null;
  created_at: string;
  dispatched_at: string | null;
  idempotency_key: string;
  lane: string;
  operation: string;
  outcome: string | null;
  permit_hash: string;
  reserved_atomic: string;
  row_mac: string;
  session_id: string;
  source_plane: string;
  state: string;
}

interface CursorHeadRow {
  ciphertext: Uint8Array | null;
  cursor_key: string;
  lane: string;
  lineage_id: string;
  nonce: Uint8Array | null;
  profile: string;
  revision: number;
  row_mac: string;
  source_plane: string;
  tag: Uint8Array | null;
  updated_at: string;
  wrapped_dek_ciphertext: Uint8Array | null;
  wrapped_dek_nonce: Uint8Array | null;
  wrapped_dek_tag: Uint8Array | null;
}

interface CursorAdvanceRow {
  advance_id: string;
  anchor_head: string | null;
  anchor_id: string | null;
  attempt_id: string;
  base_revision: number;
  candidate_binding: string;
  candidate_ciphertext: Uint8Array | null;
  candidate_nonce: Uint8Array | null;
  candidate_tag: Uint8Array | null;
  candidate_wrapped_dek_ciphertext: Uint8Array | null;
  candidate_wrapped_dek_nonce: Uint8Array | null;
  candidate_wrapped_dek_tag: Uint8Array | null;
  checkpoint_head: string | null;
  checkpoint_sequence: number | null;
  cursor_key: string;
  event_hash: string | null;
  event_id: string | null;
  event_sequence: number | null;
  lane: string;
  lineage_id: string;
  profile: string;
  row_mac: string;
  source_plane: string;
  staged_at: string;
  state: string;
}

function jsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function bufferBase64(value: Uint8Array | null): string | null {
  return value === null ? null : Buffer.from(value).toString("base64");
}

function cursorStorageKey(identity: CursorIdentity): string {
  return `${identity.profile}:${identity.sourcePlane}:${identity.lane}`;
}

function cursorAad(
  role: "candidate" | "head",
  cursorKey: string,
  lineageId: string,
  revision: number,
  entityId: string,
): string {
  return [
    "rsi.operations.cursor-value.aad.v2",
    role,
    cursorKey,
    lineageId,
    String(revision),
    entityId,
  ].join("\n");
}

function compareCanonicalTimes(left: string, right: string): number {
  return Date.parse(left) - Date.parse(right);
}

interface MutableAttemptGroup {
  abortedCount: number;
  attemptCount: number;
  closedCount: number;
  emptyCount: number;
  failedCount: number;
  reservedAtomic: bigint;
  succeededCount: number;
}

interface SessionAttemptGroups {
  canonicalChain: MutableAttemptGroup;
  openSeaRest: MutableAttemptGroup;
  openSeaStream: MutableAttemptGroup;
  xContract: MutableAttemptGroup;
  xDiscovery: MutableAttemptGroup;
  xMarketplace: MutableAttemptGroup;
  xOfficial: MutableAttemptGroup;
  xSecurity: MutableAttemptGroup;
}

function emptyAttemptGroup(): MutableAttemptGroup {
  return {
    abortedCount: 0,
    attemptCount: 0,
    closedCount: 0,
    emptyCount: 0,
    failedCount: 0,
    reservedAtomic: 0n,
    succeededCount: 0,
  };
}

function groupForAttempt(groups: SessionAttemptGroups, row: AttemptRow): MutableAttemptGroup {
  switch (row.operation) {
    case "alchemy.json-rpc.v1":
      return groups.canonicalChain;
    case "opensea.rest.v1":
      return groups.openSeaRest;
    case "opensea.stream.v1":
      return groups.openSeaStream;
    case "x.recent-search.v1":
      switch (row.lane) {
        case "contract":
          return groups.xContract;
        case "discovery":
          return groups.xDiscovery;
        case "marketplace":
          return groups.xMarketplace;
        case "official":
          return groups.xOfficial;
        case "security":
          return groups.xSecurity;
        default:
          throw new OperationsIntegrityError("Attempt lane is invalid");
      }
    default:
      throw new OperationsIntegrityError("Attempt operation is invalid");
  }
}

function updateAttemptGroup(group: MutableAttemptGroup, row: AttemptRow): void {
  group.attemptCount += 1;
  group.reservedAtomic += BigInt(row.reserved_atomic);
  if (row.state !== "closed") return;
  group.closedCount += 1;
  switch (row.outcome) {
    case "aborted":
      group.abortedCount += 1;
      return;
    case "empty":
      group.emptyCount += 1;
      return;
    case "failed":
      group.failedCount += 1;
      return;
    case "succeeded":
      group.succeededCount += 1;
      return;
    default:
      throw new OperationsIntegrityError("Closed attempt outcome is invalid");
  }
}

function freezeAttemptGroup(group: MutableAttemptGroup): Readonly<SourceAttemptGroupSummaryV1> {
  return Object.freeze({
    abortedCount: group.abortedCount,
    attemptCount: group.attemptCount,
    closedCount: group.closedCount,
    emptyCount: group.emptyCount,
    failedCount: group.failedCount,
    reservedAtomic: String(group.reservedAtomic) as AtomicAmount,
    succeededCount: group.succeededCount,
  });
}

function parsePayloadJson(value: string): JsonValue {
  try {
    return JSON.parse(value) as JsonValue;
  } catch {
    throw new OperationsIntegrityError("Operations audit contains invalid JSON");
  }
}

export interface SqliteOperationsStoreOptions {
  readonly path: string;
  readonly stateKey: Uint8Array;
}

export class SqliteOperationsStore {
  readonly path: string;

  private closed = false;
  private readonly cursorWrappingKey: Buffer;
  private readonly database: DatabaseSync;
  private readonly macKey: Buffer;

  constructor(options: SqliteOperationsStoreOptions) {
    if (
      typeof options !== "object" ||
      options === null ||
      typeof options.path !== "string" ||
      options.path.trim() === ""
    ) {
      throw new OperationsValidationError("path must be a non-empty string");
    }
    this.path = options.path;
    const keys = deriveOperationsKeys(options.stateKey);
    this.cursorWrappingKey = keys.cursorWrappingKey;
    this.macKey = keys.macKey;
    this.database = new DatabaseSync(options.path);
    try {
      this.configureDatabase();
      this.initializeSchema();
      let report = this.verifyIntegrityInternal();
      if (!report.valid) throw new OperationsIntegrityError(report.errors.join("; "));
      this.completePendingCursorErasure();
      report = this.verifyIntegrityInternal();
      if (!report.valid) throw new OperationsIntegrityError(report.errors.join("; "));
    } catch (error) {
      this.closed = true;
      this.database.close();
      this.cursorWrappingKey.fill(0);
      this.macKey.fill(0);
      throw error;
    }
    authenticSqliteOperationsStores.add(this);
  }

  static createAttemptPermit(): AttemptPermit {
    return Object.freeze({
      attemptId: randomUUID(),
      token: randomBytes(32).toString("base64url") as AttemptPermitToken,
    });
  }

  createNetworkAttemptAuthorization(permit: AttemptPermit): NetworkAttemptAuthorization {
    const parsed = parseWithSchema(AttemptPermitSchema, permit, "attempt permit");
    return this.transaction(() => {
      const attempt = this.getAttemptRow(parsed.attemptId);
      if (attempt === undefined) throw new InvalidAttemptPermitError("Attempt permit is unknown");
      this.assertAttemptRow(attempt);
      if (
        attempt.state !== "reserved" ||
        !secureEqualHex(attempt.permit_hash, sha256(parsed.token))
      ) {
        throw new InvalidAttemptPermitError("Attempt permit is unavailable or invalid");
      }
      const budget = this.getBudgetRow(attempt.budget_id);
      if (budget === undefined) throw new OperationsIntegrityError("Attempt budget is missing");
      this.assertBudgetRow(budget);
      return createNetworkAttemptAuthorization(
        {
          attemptId: attempt.attempt_id,
          authorizationExpiresAt: attempt.authorization_expires_at,
          lane: parseWithSchema(ResearchLaneSchema, attempt.lane, "attempt lane"),
          operation: parseWithSchema(
            ResearchOperationSchema,
            attempt.operation,
            "attempt operation",
          ),
          profile: parseWithSchema(OperationsProfileSchema, budget.profile, "attempt profile"),
          reservedAtomic: attempt.reserved_atomic as AtomicAmount,
          sessionId: attempt.session_id,
          sourcePlane: parseWithSchema(
            SourcePlaneSchema,
            attempt.source_plane,
            "attempt source plane",
          ),
        },
        (dispatchedAt) => {
          this.authorizeAttempt(
            {
              attemptId: parsed.attemptId,
              token: parsed.token as AttemptPermitToken,
            },
            dispatchedAt,
          );
        },
      );
    });
  }

  /**
   * Reads the authenticated binding needed to verify ingestion after the
   * one-shot permit has been consumed. Permit material is never returned.
   */
  readNetworkAttemptBinding(attemptIdInput: unknown): Readonly<DurableNetworkAttemptBinding> {
    const attemptId = parseWithSchema(UuidSchema, attemptIdInput, "attemptId");
    return this.transaction(() => {
      const attempt = this.getAttemptRow(attemptId);
      if (attempt === undefined) {
        throw new OperationsConflictError("ATTEMPT_CONFLICT", "Network attempt is unavailable");
      }
      this.assertAttemptRow(attempt);
      const budget = this.getBudgetRow(attempt.budget_id);
      if (budget === undefined) throw new OperationsIntegrityError("Attempt budget is missing");
      this.assertBudgetRow(budget);
      return Object.freeze({
        attemptId: attempt.attempt_id,
        authorizationExpiresAt: attempt.authorization_expires_at,
        dispatchedAt: attempt.dispatched_at,
        lane: parseWithSchema(ResearchLaneSchema, attempt.lane, "attempt lane"),
        operation: parseWithSchema(ResearchOperationSchema, attempt.operation, "attempt operation"),
        profile: parseWithSchema(OperationsProfileSchema, budget.profile, "attempt profile"),
        reservedAtomic: attempt.reserved_atomic as AtomicAmount,
        sessionId: attempt.session_id,
        sourcePlane: parseWithSchema(
          SourcePlaneSchema,
          attempt.source_plane,
          "attempt source plane",
        ),
        state: attempt.state as AttemptState,
      });
    });
  }

  /**
   * Returns aggregate-only authenticated attempt closure facts for one supervised session.
   * It deliberately excludes attempt identifiers, idempotency keys, and permit material.
   */
  getSessionAttemptSummary(
    sessionIdInput: unknown,
    profileInput: unknown,
  ): Readonly<SessionAttemptSummaryV1> {
    const sessionId = parseWithSchema(UuidSchema, sessionIdInput, "sessionId");
    const profile = parseWithSchema(OperationsProfileSchema, profileInput, "profile");
    if (profile === "dev") {
      throw new OperationsValidationError("session closure is unavailable for the dev profile");
    }
    return this.transaction(() => {
      const rows = this.database
        .prepare(`SELECT * FROM rsi_attempts WHERE session_id = ? ORDER BY created_at, attempt_id`)
        .all(sessionId) as unknown as AttemptRow[];
      const groups = {
        canonicalChain: emptyAttemptGroup(),
        openSeaRest: emptyAttemptGroup(),
        openSeaStream: emptyAttemptGroup(),
        xContract: emptyAttemptGroup(),
        xDiscovery: emptyAttemptGroup(),
        xMarketplace: emptyAttemptGroup(),
        xOfficial: emptyAttemptGroup(),
        xSecurity: emptyAttemptGroup(),
      };
      let crossProfileAttemptCount = 0;
      let reservedAtomic = 0n;
      let profileAttemptCount = 0;
      let allAttemptsClosed = true;
      for (const row of rows) {
        this.assertAttemptRow(row);
        const budget = this.getBudgetRow(row.budget_id);
        if (budget === undefined) throw new OperationsIntegrityError("Attempt budget is missing");
        this.assertBudgetRow(budget);
        if (budget.profile !== profile) {
          crossProfileAttemptCount += 1;
          continue;
        }
        profileAttemptCount += 1;
        reservedAtomic += BigInt(row.reserved_atomic);
        if (row.state !== "closed") allAttemptsClosed = false;
        updateAttemptGroup(groupForAttempt(groups, row), row);
      }
      return Object.freeze({
        allAttemptsClosed,
        attemptCount: profileAttemptCount,
        canonicalChain: freezeAttemptGroup(groups.canonicalChain),
        crossProfileAttemptCount,
        openSea: Object.freeze({
          rest: freezeAttemptGroup(groups.openSeaRest),
          stream: freezeAttemptGroup(groups.openSeaStream),
        }),
        profile,
        reservedAtomic: String(reservedAtomic) as AtomicAmount,
        schemaVersion: 1 as const,
        sessionId,
        xLanes: Object.freeze({
          contract: freezeAttemptGroup(groups.xContract),
          discovery: freezeAttemptGroup(groups.xDiscovery),
          marketplace: freezeAttemptGroup(groups.xMarketplace),
          official: freezeAttemptGroup(groups.xOfficial),
          security: freezeAttemptGroup(groups.xSecurity),
        }),
      });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.database.close();
    this.cursorWrappingKey.fill(0);
    this.macKey.fill(0);
  }

  [Symbol.dispose](): void {
    this.close();
  }

  verifyIntegrity(): OperationsIntegrityReport {
    this.assertOpen();
    this.completePendingCursorErasure();
    return this.verifyIntegrityInternal();
  }

  private assertOpen(): void {
    if (this.closed) throw new OperationsClosedError();
  }

  private configureDatabase(): void {
    this.database.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA secure_delete = ON;
      PRAGMA trusted_schema = OFF;
    `);
    const secureDelete = this.database.prepare("PRAGMA secure_delete").get() as
      { secure_delete: number } | undefined;
    if (secureDelete?.secure_delete !== 1) {
      throw new OperationsIntegrityError("SQLite secure_delete could not be enabled");
    }
  }

  private initializeSchema(): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.exec(`
        CREATE TABLE IF NOT EXISTS rsi_operations_metadata (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          schema_version INTEGER NOT NULL,
          audit_head_sequence INTEGER NOT NULL CHECK(audit_head_sequence >= 0),
          audit_head_mac TEXT NOT NULL CHECK(length(audit_head_mac) = 64),
          key_check_mac TEXT NOT NULL CHECK(length(key_check_mac) = 64),
          cursor_erasure_pending INTEGER NOT NULL CHECK(cursor_erasure_pending IN (0, 1)),
          metadata_mac TEXT NOT NULL CHECK(length(metadata_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_operation_audit (
          sequence INTEGER PRIMARY KEY,
          event_type TEXT NOT NULL,
          aggregate_id TEXT NOT NULL,
          occurred_at TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          previous_mac TEXT NOT NULL CHECK(length(previous_mac) = 64),
          event_mac TEXT NOT NULL UNIQUE CHECK(length(event_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_budgets (
          budget_id TEXT PRIMARY KEY,
          profile TEXT NOT NULL,
          currency TEXT NOT NULL,
          max_atomic TEXT NOT NULL,
          max_attempts INTEGER NOT NULL,
          starts_at TEXT NOT NULL,
          ends_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_attempts (
          attempt_id TEXT PRIMARY KEY,
          budget_id TEXT NOT NULL REFERENCES rsi_budgets(budget_id),
          idempotency_key TEXT NOT NULL UNIQUE,
          session_id TEXT NOT NULL,
          source_plane TEXT NOT NULL,
          lane TEXT NOT NULL,
          operation TEXT NOT NULL,
          reserved_atomic TEXT NOT NULL,
          permit_hash TEXT NOT NULL CHECK(length(permit_hash) = 64),
          authorization_expires_at TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('reserved', 'dispatched', 'closed')),
          outcome TEXT CHECK(outcome IS NULL OR outcome IN ('succeeded', 'failed', 'empty', 'aborted')),
          created_at TEXT NOT NULL,
          dispatched_at TEXT,
          closed_at TEXT,
          row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_cursor_heads (
          cursor_key TEXT PRIMARY KEY,
          profile TEXT NOT NULL,
          source_plane TEXT NOT NULL,
          lane TEXT NOT NULL,
          lineage_id TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 0),
          ciphertext BLOB CHECK(ciphertext IS NULL OR length(ciphertext) BETWEEN 1 AND 2048),
          nonce BLOB CHECK(nonce IS NULL OR length(nonce) = 12),
          tag BLOB CHECK(tag IS NULL OR length(tag) = 16),
          wrapped_dek_ciphertext BLOB
            CHECK(wrapped_dek_ciphertext IS NULL OR length(wrapped_dek_ciphertext) = 32),
          wrapped_dek_nonce BLOB CHECK(wrapped_dek_nonce IS NULL OR length(wrapped_dek_nonce) = 12),
          wrapped_dek_tag BLOB CHECK(wrapped_dek_tag IS NULL OR length(wrapped_dek_tag) = 16),
          updated_at TEXT NOT NULL,
          row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_cursor_advances (
          advance_id TEXT PRIMARY KEY,
          cursor_key TEXT NOT NULL REFERENCES rsi_cursor_heads(cursor_key),
          profile TEXT NOT NULL,
          source_plane TEXT NOT NULL,
          lane TEXT NOT NULL,
          lineage_id TEXT NOT NULL,
          base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
          attempt_id TEXT NOT NULL UNIQUE REFERENCES rsi_attempts(attempt_id),
          state TEXT NOT NULL CHECK(state IN (
            'staged', 'validated', 'event_persisted', 'checkpointed',
            'anchor_published', 'externally_verified', 'committed', 'aborted'
          )),
          candidate_binding TEXT NOT NULL CHECK(length(candidate_binding) = 64),
          candidate_ciphertext BLOB
            CHECK(candidate_ciphertext IS NULL OR length(candidate_ciphertext) BETWEEN 1 AND 2048),
          candidate_nonce BLOB CHECK(candidate_nonce IS NULL OR length(candidate_nonce) = 12),
          candidate_tag BLOB CHECK(candidate_tag IS NULL OR length(candidate_tag) = 16),
          candidate_wrapped_dek_ciphertext BLOB
            CHECK(candidate_wrapped_dek_ciphertext IS NULL OR length(candidate_wrapped_dek_ciphertext) = 32),
          candidate_wrapped_dek_nonce BLOB
            CHECK(candidate_wrapped_dek_nonce IS NULL OR length(candidate_wrapped_dek_nonce) = 12),
          candidate_wrapped_dek_tag BLOB
            CHECK(candidate_wrapped_dek_tag IS NULL OR length(candidate_wrapped_dek_tag) = 16),
          event_id TEXT,
          event_sequence INTEGER,
          event_hash TEXT,
          checkpoint_sequence INTEGER,
          checkpoint_head TEXT,
          anchor_id TEXT,
          anchor_head TEXT,
          staged_at TEXT NOT NULL,
          row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
        ) STRICT;
      `);
      const keyCheckMac = macJson(this.macKey, "key-check", {
        schemaVersion: SCHEMA_VERSION,
      });
      const initialMetadata: Omit<MetadataRow, "metadata_mac"> = {
        audit_head_mac: GENESIS_MAC,
        audit_head_sequence: 0,
        cursor_erasure_pending: 0,
        key_check_mac: keyCheckMac,
        schema_version: SCHEMA_VERSION,
      };
      this.database
        .prepare(
          `INSERT INTO rsi_operations_metadata (
             singleton, schema_version, audit_head_sequence, audit_head_mac, key_check_mac,
             cursor_erasure_pending, metadata_mac
           ) SELECT 1, ?, 0, ?, ?, 0, ?
             WHERE NOT EXISTS (SELECT 1 FROM rsi_operations_metadata)
               AND NOT EXISTS (SELECT 1 FROM rsi_operation_audit)`,
        )
        .run(SCHEMA_VERSION, GENESIS_MAC, keyCheckMac, this.metadataMac(initialMetadata));
      this.database.exec("COMMIT");
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private transaction<T>(operation: () => T): T {
    this.assertOpen();
    this.completePendingCursorErasure();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) throw new OperationsIntegrityError(integrity.errors.join("; "));
      const result = operation();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private metadata(): MetadataRow {
    const row = this.database
      .prepare(
        `SELECT schema_version, audit_head_sequence, audit_head_mac, key_check_mac,
                cursor_erasure_pending, metadata_mac
           FROM rsi_operations_metadata WHERE singleton = 1`,
      )
      .get() as MetadataRow | undefined;
    if (row === undefined) throw new OperationsIntegrityError("Operations metadata is missing");
    return row;
  }

  private metadataMac(row: Omit<MetadataRow, "metadata_mac">): string {
    return macJson(this.macKey, "metadata-row", {
      auditHeadMac: row.audit_head_mac,
      auditHeadSequence: row.audit_head_sequence,
      cursorErasurePending: row.cursor_erasure_pending,
      keyCheckMac: row.key_check_mac,
      schemaVersion: row.schema_version,
    });
  }

  private writeCursorErasurePending(pending: boolean): void {
    const metadata = this.metadata();
    const next: Omit<MetadataRow, "metadata_mac"> = {
      audit_head_mac: metadata.audit_head_mac,
      audit_head_sequence: metadata.audit_head_sequence,
      cursor_erasure_pending: pending ? 1 : 0,
      key_check_mac: metadata.key_check_mac,
      schema_version: metadata.schema_version,
    };
    const updated = this.database
      .prepare(
        `UPDATE rsi_operations_metadata
            SET cursor_erasure_pending = ?, metadata_mac = ?
          WHERE singleton = 1 AND cursor_erasure_pending = ? AND metadata_mac = ?`,
      )
      .run(
        next.cursor_erasure_pending,
        this.metadataMac(next),
        metadata.cursor_erasure_pending,
        metadata.metadata_mac,
      );
    if (updated.changes !== 1) {
      throw new OperationsIntegrityError("Operations erasure state changed unexpectedly");
    }
  }

  /**
   * Finish a logically committed cursor-key erasure. SQLite secure_delete removes
   * freed cell payloads, VACUUM rebuilds the main database, and the two truncate
   * checkpoints eliminate stale pre/post-VACUUM WAL frames from the live file
   * namespace. The authenticated pending bit makes a crash between logical
   * deletion and physical hardening self-healing on reopen.
   */
  private completePendingCursorErasure(): void {
    this.assertOpen();
    let metadata: MetadataRow;
    try {
      metadata = this.metadata();
    } catch {
      return;
    }
    if (metadata.cursor_erasure_pending !== 1) return;

    this.assertMetadataRow(metadata);
    const beforeHardening = this.verifyIntegrityInternal();
    if (!beforeHardening.valid) {
      throw new OperationsIntegrityError(beforeHardening.errors.join("; "));
    }
    this.assertCheckpointTruncated("before cursor erasure VACUUM");
    this.database.exec("VACUUM");
    this.assertCheckpointTruncated("after cursor erasure VACUUM");

    this.database.exec("BEGIN IMMEDIATE");
    try {
      const integrity = this.verifyIntegrityInternal();
      if (!integrity.valid) throw new OperationsIntegrityError(integrity.errors.join("; "));
      this.writeCursorErasurePending(false);
      this.database.exec("COMMIT");
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
    this.assertCheckpointTruncated("after cursor erasure completion");
  }

  private assertCheckpointTruncated(context: string): void {
    const result = this.database.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get() as
      { busy: number; checkpointed: number; log: number } | undefined;
    if (
      result === undefined ||
      result.busy !== 0 ||
      result.log !== 0 ||
      result.checkpointed !== 0
    ) {
      throw new OperationsIntegrityError(`SQLite WAL hardening failed ${context}`);
    }
  }

  private assertMetadataRow(metadata: MetadataRow): void {
    if (metadata.schema_version !== SCHEMA_VERSION) {
      throw new OperationsIntegrityError("Unsupported operations schema version");
    }
    if (
      !Number.isSafeInteger(metadata.audit_head_sequence) ||
      metadata.audit_head_sequence < 0 ||
      !/^[0-9a-f]{64}$/.test(metadata.audit_head_mac) ||
      !/^[0-9a-f]{64}$/.test(metadata.key_check_mac) ||
      !/^[0-9a-f]{64}$/.test(metadata.metadata_mac)
    ) {
      throw new OperationsIntegrityError("Operations metadata shape is invalid");
    }
    if (metadata.cursor_erasure_pending !== 0 && metadata.cursor_erasure_pending !== 1) {
      throw new OperationsIntegrityError("Operations cursor erasure state is invalid");
    }
    const expectedKeyCheck = macJson(this.macKey, "key-check", {
      schemaVersion: SCHEMA_VERSION,
    });
    if (!secureEqualHex(metadata.key_check_mac, expectedKeyCheck)) {
      throw new OperationsIntegrityError("Operations state key check failed");
    }
    const expectedMetadataMac = this.metadataMac({
      audit_head_mac: metadata.audit_head_mac,
      audit_head_sequence: metadata.audit_head_sequence,
      cursor_erasure_pending: metadata.cursor_erasure_pending,
      key_check_mac: metadata.key_check_mac,
      schema_version: metadata.schema_version,
    });
    if (!secureEqualHex(metadata.metadata_mac, expectedMetadataMac)) {
      throw new OperationsIntegrityError("Operations metadata failed authentication");
    }
  }

  private appendAudit(
    eventType: string,
    aggregateId: string,
    occurredAt: string,
    payload: JsonValue,
  ): void {
    const metadata = this.metadata();
    const sequence = metadata.audit_head_sequence + 1;
    const payloadJson = canonicalJson(payload);
    const eventMac = macJson(this.macKey, "audit-event", {
      aggregateId,
      eventType,
      occurredAt,
      payloadJson,
      previousMac: metadata.audit_head_mac,
      sequence,
    });
    this.database
      .prepare(
        `INSERT INTO rsi_operation_audit (
           sequence, event_type, aggregate_id, occurred_at, payload_json, previous_mac, event_mac
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        sequence,
        eventType,
        aggregateId,
        occurredAt,
        payloadJson,
        metadata.audit_head_mac,
        eventMac,
      );
    const nextMetadata: Omit<MetadataRow, "metadata_mac"> = {
      audit_head_mac: eventMac,
      audit_head_sequence: sequence,
      cursor_erasure_pending: metadata.cursor_erasure_pending,
      key_check_mac: metadata.key_check_mac,
      schema_version: metadata.schema_version,
    };
    const updated = this.database
      .prepare(
        `UPDATE rsi_operations_metadata
            SET audit_head_sequence = ?, audit_head_mac = ?, metadata_mac = ?
          WHERE singleton = 1 AND audit_head_sequence = ? AND audit_head_mac = ?
            AND metadata_mac = ?`,
      )
      .run(
        sequence,
        eventMac,
        this.metadataMac(nextMetadata),
        metadata.audit_head_sequence,
        metadata.audit_head_mac,
        metadata.metadata_mac,
      );
    if (updated.changes !== 1) {
      throw new OperationsIntegrityError("Operations audit head changed during append");
    }
  }

  createBudget(input: CreateBudgetInput): BudgetRecord {
    const budget = parseWithSchema(CreateBudgetInputSchema, input, "budget");
    if (compareCanonicalTimes(budget.startsAt, budget.endsAt) >= 0) {
      throw new OperationsValidationError("budget startsAt must be before endsAt");
    }
    if (compareCanonicalTimes(budget.createdAt, budget.endsAt) > 0) {
      throw new OperationsValidationError("budget createdAt must not be after endsAt");
    }

    return this.transaction(() => {
      const existing = this.getBudgetRow(budget.budgetId);
      if (existing !== undefined) {
        this.assertBudgetRow(existing);
        const record = this.budgetFromRow(existing);
        if (canonicalJson(jsonValue(record)) !== canonicalJson(jsonValue(budget))) {
          throw new OperationsConflictError(
            "BUDGET_CONFLICT",
            "The budget ID is already bound to different content",
          );
        }
        return record;
      }

      const unsigned: Omit<BudgetRow, "row_mac"> = {
        budget_id: budget.budgetId,
        created_at: budget.createdAt,
        currency: budget.currency,
        ends_at: budget.endsAt,
        max_atomic: budget.maxAtomic,
        max_attempts: budget.maxAttempts,
        profile: budget.profile,
        starts_at: budget.startsAt,
      };
      const rowMac = this.budgetMac(unsigned);
      this.database
        .prepare(
          `INSERT INTO rsi_budgets (
             budget_id, profile, currency, max_atomic, max_attempts,
             starts_at, ends_at, created_at, row_mac
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          unsigned.budget_id,
          unsigned.profile,
          unsigned.currency,
          unsigned.max_atomic,
          unsigned.max_attempts,
          unsigned.starts_at,
          unsigned.ends_at,
          unsigned.created_at,
          rowMac,
        );
      this.appendAudit("budget.created.v1", budget.budgetId, budget.createdAt, {
        budgetId: budget.budgetId,
        currency: budget.currency,
        endsAt: budget.endsAt,
        maxAtomic: budget.maxAtomic,
        maxAttempts: budget.maxAttempts,
        profile: budget.profile,
        startsAt: budget.startsAt,
      });
      return Object.freeze({ ...budget, maxAtomic: budget.maxAtomic as AtomicAmount });
    });
  }

  getBudgetSummary(budgetId: string): BudgetSummary {
    const parsedBudgetId = parseWithSchema(UuidSchema, budgetId, "budgetId");
    this.assertOpen();
    const row = this.getBudgetRow(parsedBudgetId);
    if (row === undefined) throw new OperationsValidationError("budget does not exist");
    this.assertBudgetRow(row);
    const budget = this.budgetFromRow(row);
    const attempts = this.database
      .prepare(`SELECT * FROM rsi_attempts WHERE budget_id = ? ORDER BY created_at, attempt_id`)
      .all(parsedBudgetId) as unknown as AttemptRow[];
    let reserved = 0n;
    for (const attempt of attempts) {
      this.assertAttemptRow(attempt);
      reserved += BigInt(attempt.reserved_atomic);
    }
    const maximum = BigInt(budget.maxAtomic);
    if (reserved > maximum) {
      throw new OperationsIntegrityError("Budget reservations exceed the configured maximum");
    }
    return Object.freeze({
      ...budget,
      attemptedCount: attempts.length,
      remainingAtomic: String(maximum - reserved) as AtomicAmount,
      reservedAtomic: String(reserved) as AtomicAmount,
    });
  }

  reserveAttempt(input: ReserveAttemptInput): AttemptRecord {
    const attempt = parseWithSchema(ReserveAttemptInputSchema, input, "attempt reservation");
    const created = Date.parse(attempt.createdAt);
    const expires = Date.parse(attempt.authorizationExpiresAt);
    if (expires < created || expires - created > MAX_AUTHORIZATION_WINDOW_MS) {
      throw new OperationsValidationError(
        "authorizationExpiresAt must be between createdAt and two hours after createdAt",
      );
    }
    const expectedSourcePlane =
      attempt.operation === "x.recent-search.v1"
        ? "social"
        : attempt.operation === "alchemy.json-rpc.v1"
          ? "canonical_chain"
          : "marketplace";
    if (attempt.sourcePlane !== expectedSourcePlane) {
      throw new OperationsValidationError("attempt operation does not match its source plane");
    }

    return this.transaction(() => {
      const budgetRow = this.getBudgetRow(attempt.budgetId);
      if (budgetRow === undefined) throw new OperationsValidationError("budget does not exist");
      this.assertBudgetRow(budgetRow);
      const budget = this.budgetFromRow(budgetRow);
      if (
        compareCanonicalTimes(attempt.createdAt, budget.startsAt) < 0 ||
        compareCanonicalTimes(attempt.createdAt, budget.createdAt) < 0 ||
        compareCanonicalTimes(attempt.createdAt, budget.endsAt) > 0 ||
        compareCanonicalTimes(attempt.authorizationExpiresAt, budget.endsAt) > 0
      ) {
        throw new BudgetExceededError(
          "WINDOW_CLOSED",
          "The attempt falls outside the budget window",
        );
      }

      const byId = this.getAttemptRow(attempt.attemptId);
      const byKey = this.database
        .prepare(`SELECT * FROM rsi_attempts WHERE idempotency_key = ?`)
        .get(attempt.idempotencyKey) as AttemptRow | undefined;
      if (byId !== undefined || byKey !== undefined) {
        if (byId === undefined || byKey === undefined || byId.attempt_id !== byKey.attempt_id) {
          throw new OperationsConflictError(
            "ATTEMPT_CONFLICT",
            "Attempt ID and idempotency key do not identify the same reservation",
          );
        }
        this.assertAttemptRow(byId);
        const expectedPermitHash = sha256(attempt.permitToken);
        const same =
          byId.budget_id === attempt.budgetId &&
          byId.session_id === attempt.sessionId &&
          byId.source_plane === attempt.sourcePlane &&
          byId.lane === attempt.lane &&
          byId.operation === attempt.operation &&
          byId.reserved_atomic === attempt.reservedAtomic &&
          byId.authorization_expires_at === attempt.authorizationExpiresAt &&
          byId.created_at === attempt.createdAt &&
          secureEqualHex(byId.permit_hash, expectedPermitHash);
        if (!same) {
          throw new OperationsConflictError(
            "ATTEMPT_CONFLICT",
            "The attempt identity is already bound to different content",
          );
        }
        return this.attemptFromRow(byId);
      }

      const rows = this.database
        .prepare(`SELECT * FROM rsi_attempts WHERE budget_id = ?`)
        .all(attempt.budgetId) as unknown as AttemptRow[];
      let reserved = 0n;
      for (const row of rows) {
        this.assertAttemptRow(row);
        reserved += BigInt(row.reserved_atomic);
      }
      if (rows.length >= budget.maxAttempts) {
        throw new BudgetExceededError(
          "ATTEMPT_LIMIT_EXCEEDED",
          "The budget attempt limit is exhausted",
        );
      }
      const proposed = reserved + BigInt(attempt.reservedAtomic);
      if (proposed > BigInt(budget.maxAtomic)) {
        throw new BudgetExceededError(
          "SPEND_LIMIT_EXCEEDED",
          "The reservation would exceed the budget",
        );
      }

      const unsigned: Omit<AttemptRow, "row_mac"> = {
        attempt_id: attempt.attemptId,
        authorization_expires_at: attempt.authorizationExpiresAt,
        budget_id: attempt.budgetId,
        closed_at: null,
        created_at: attempt.createdAt,
        dispatched_at: null,
        idempotency_key: attempt.idempotencyKey,
        lane: attempt.lane,
        operation: attempt.operation,
        outcome: null,
        permit_hash: sha256(attempt.permitToken),
        reserved_atomic: attempt.reservedAtomic,
        session_id: attempt.sessionId,
        source_plane: attempt.sourcePlane,
        state: "reserved",
      };
      const rowMac = this.attemptMac(unsigned);
      this.database
        .prepare(
          `INSERT INTO rsi_attempts (
             attempt_id, budget_id, idempotency_key, session_id, source_plane, lane, operation,
             reserved_atomic, permit_hash, authorization_expires_at, state, outcome,
             created_at, dispatched_at, closed_at, row_mac
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          unsigned.attempt_id,
          unsigned.budget_id,
          unsigned.idempotency_key,
          unsigned.session_id,
          unsigned.source_plane,
          unsigned.lane,
          unsigned.operation,
          unsigned.reserved_atomic,
          unsigned.permit_hash,
          unsigned.authorization_expires_at,
          unsigned.state,
          unsigned.outcome,
          unsigned.created_at,
          unsigned.dispatched_at,
          unsigned.closed_at,
          rowMac,
        );
      this.appendAudit("budget.attempt.reserved.v1", attempt.budgetId, attempt.createdAt, {
        attemptId: attempt.attemptId,
        authorizationExpiresAt: attempt.authorizationExpiresAt,
        budgetId: attempt.budgetId,
        lane: attempt.lane,
        operation: attempt.operation,
        reservedAtomic: attempt.reservedAtomic,
        sessionId: attempt.sessionId,
        sourcePlane: attempt.sourcePlane,
      });
      return this.attemptFromRow({ ...unsigned, row_mac: rowMac });
    });
  }

  authorizeAttempt(permitInput: AttemptPermit, dispatchedAtInput: string): AttemptRecord {
    const permit = parseWithSchema(AttemptPermitSchema, permitInput, "attempt permit");
    const dispatchedAt = parseWithSchema(
      CanonicalTimestampSchema,
      dispatchedAtInput,
      "dispatchedAt",
    );
    return this.transaction(() => {
      const row = this.getAttemptRow(permit.attemptId);
      if (row === undefined) throw new InvalidAttemptPermitError("Attempt permit is unknown");
      this.assertAttemptRow(row);
      if (row.state !== "reserved") {
        throw new InvalidAttemptPermitError("Attempt permit was already consumed");
      }
      if (!secureEqualHex(row.permit_hash, sha256(permit.token))) {
        throw new InvalidAttemptPermitError("Attempt permit is invalid");
      }
      if (
        compareCanonicalTimes(dispatchedAt, row.created_at) < 0 ||
        compareCanonicalTimes(dispatchedAt, row.authorization_expires_at) > 0
      ) {
        throw new InvalidAttemptPermitError("Attempt permit is outside its authorization window");
      }
      const budgetRow = this.getBudgetRow(row.budget_id);
      if (budgetRow === undefined) throw new OperationsIntegrityError("Attempt budget is missing");
      this.assertBudgetRow(budgetRow);
      if (compareCanonicalTimes(dispatchedAt, budgetRow.ends_at) > 0) {
        throw new BudgetExceededError("WINDOW_CLOSED", "Budget window closed before dispatch");
      }

      const updated: Omit<AttemptRow, "row_mac"> = {
        ...this.withoutAttemptMac(row),
        dispatched_at: dispatchedAt,
        state: "dispatched",
      };
      const rowMac = this.attemptMac(updated);
      this.writeAttempt(updated, rowMac);
      this.appendAudit("budget.attempt.dispatched.v1", row.budget_id, dispatchedAt, {
        attemptId: row.attempt_id,
        budgetId: row.budget_id,
        lane: row.lane,
        operation: row.operation,
        reservedAtomic: row.reserved_atomic,
        sessionId: row.session_id,
        sourcePlane: row.source_plane,
      });
      return this.attemptFromRow({ ...updated, row_mac: rowMac });
    });
  }

  closeAttempt(
    attemptIdInput: string,
    input: Readonly<{ closedAt: string; outcome: "aborted" | "empty" | "failed" | "succeeded" }>,
  ): AttemptRecord {
    const attemptId = parseWithSchema(UuidSchema, attemptIdInput, "attemptId");
    const close = parseWithSchema(
      z.strictObject({
        closedAt: CanonicalTimestampSchema,
        outcome: z.enum(["succeeded", "failed", "empty", "aborted"]),
      }),
      input,
      "attempt close",
    );
    return this.transaction(() => {
      const row = this.getAttemptRow(attemptId);
      if (row === undefined) throw new OperationsValidationError("attempt does not exist");
      this.assertAttemptRow(row);
      if (row.state === "closed") {
        if (row.closed_at !== close.closedAt || row.outcome !== close.outcome) {
          throw new OperationsConflictError(
            "ATTEMPT_CONFLICT",
            "Attempt was already closed with a different outcome",
          );
        }
        return this.attemptFromRow(row);
      }
      if (row.state === "reserved" && close.outcome !== "aborted") {
        throw new OperationsConflictError(
          "INVALID_TRANSITION",
          "An undispatched reservation can only close as aborted",
        );
      }
      const lowerBound = row.dispatched_at ?? row.created_at;
      if (compareCanonicalTimes(close.closedAt, lowerBound) < 0) {
        throw new OperationsValidationError("closedAt predates the attempt state");
      }
      const updated: Omit<AttemptRow, "row_mac"> = {
        ...this.withoutAttemptMac(row),
        closed_at: close.closedAt,
        outcome: close.outcome,
        state: "closed",
      };
      const rowMac = this.attemptMac(updated);
      this.writeAttempt(updated, rowMac);
      this.appendAudit("budget.attempt.closed.v1", row.budget_id, close.closedAt, {
        attemptId: row.attempt_id,
        budgetId: row.budget_id,
        outcome: close.outcome,
        reservedAtomic: row.reserved_atomic,
        sessionId: row.session_id,
      });
      return this.attemptFromRow({ ...updated, row_mac: rowMac });
    });
  }

  recoverExpiredAttempts(recoveredAtInput: string): number {
    const recoveredAt = parseWithSchema(CanonicalTimestampSchema, recoveredAtInput, "recoveredAt");
    return this.transaction(() => {
      const rows = this.database
        .prepare(
          `SELECT * FROM rsi_attempts
            WHERE state != 'closed' AND authorization_expires_at < ?
            ORDER BY created_at, attempt_id`,
        )
        .all(recoveredAt) as unknown as AttemptRow[];
      for (const row of rows) {
        this.assertAttemptRow(row);
        const updated: Omit<AttemptRow, "row_mac"> = {
          ...this.withoutAttemptMac(row),
          closed_at: recoveredAt,
          outcome: "aborted",
          state: "closed",
        };
        const rowMac = this.attemptMac(updated);
        this.writeAttempt(updated, rowMac);
        this.appendAudit("budget.attempt.recovered.v1", row.budget_id, recoveredAt, {
          attemptId: row.attempt_id,
          budgetId: row.budget_id,
          outcome: "aborted",
          reservedAtomic: row.reserved_atomic,
          sessionId: row.session_id,
        });
      }
      return rows.length;
    });
  }

  initializeCursorLineage(input: InitializeCursorLineageInput): CursorState {
    const lineage = parseWithSchema(InitializeCursorLineageInputSchema, input, "cursor lineage");
    return this.transaction(() => {
      const key = cursorStorageKey(lineage);
      const existing = this.getCursorHeadRow(key);
      if (existing !== undefined) {
        this.assertCursorHeadRow(existing);
        if (
          existing.profile !== lineage.profile ||
          existing.source_plane !== lineage.sourcePlane ||
          existing.lane !== lineage.lane ||
          existing.lineage_id !== lineage.lineageId
        ) {
          throw new OperationsConflictError(
            "CURSOR_CONFLICT",
            "Cursor identity is already bound to a different lineage",
          );
        }
        this.assertAuditReplay(key, "cursor.lineage.initialized.v1", lineage.initializedAt, {
          lane: lineage.lane,
          lineageId: lineage.lineageId,
          profile: lineage.profile,
          revision: 0,
          sourcePlane: lineage.sourcePlane,
        });
        return this.cursorStateFromRow(existing);
      }
      const unsigned: Omit<CursorHeadRow, "row_mac"> = {
        ciphertext: null,
        cursor_key: key,
        lane: lineage.lane,
        lineage_id: lineage.lineageId,
        nonce: null,
        profile: lineage.profile,
        revision: 0,
        source_plane: lineage.sourcePlane,
        tag: null,
        updated_at: lineage.initializedAt,
        wrapped_dek_ciphertext: null,
        wrapped_dek_nonce: null,
        wrapped_dek_tag: null,
      };
      const rowMac = this.cursorHeadMac(unsigned);
      this.database
        .prepare(
          `INSERT INTO rsi_cursor_heads (
             cursor_key, profile, source_plane, lane, lineage_id, revision,
             ciphertext, nonce, tag, wrapped_dek_ciphertext, wrapped_dek_nonce,
             wrapped_dek_tag, updated_at, row_mac
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          unsigned.cursor_key,
          unsigned.profile,
          unsigned.source_plane,
          unsigned.lane,
          unsigned.lineage_id,
          unsigned.revision,
          unsigned.ciphertext,
          unsigned.nonce,
          unsigned.tag,
          unsigned.wrapped_dek_ciphertext,
          unsigned.wrapped_dek_nonce,
          unsigned.wrapped_dek_tag,
          unsigned.updated_at,
          rowMac,
        );
      this.appendAudit("cursor.lineage.initialized.v1", key, lineage.initializedAt, {
        lane: lineage.lane,
        lineageId: lineage.lineageId,
        profile: lineage.profile,
        revision: 0,
        sourcePlane: lineage.sourcePlane,
      });
      return this.cursorStateFromRow({ ...unsigned, row_mac: rowMac });
    });
  }

  readCursor(identityInput: CursorIdentity): CursorState {
    const identity = parseWithSchema(CursorIdentitySchema, identityInput, "cursor identity");
    this.assertOpen();
    const key = cursorStorageKey(identity);
    const row = this.getCursorHeadRow(key);
    if (row === undefined) throw new OperationsValidationError("cursor lineage does not exist");
    this.assertCursorHeadRow(row);
    return this.cursorStateFromRow(row);
  }

  stageCursorAdvance(input: StageCursorAdvanceInput): CursorAdvanceRecord {
    const stage = parseWithSchema(StageCursorAdvanceInputSchema, input, "cursor advance");
    return this.transaction(() => {
      const key = cursorStorageKey(stage);
      const head = this.getCursorHeadRow(key);
      if (head === undefined) throw new OperationsValidationError("cursor lineage does not exist");
      this.assertCursorHeadRow(head);
      const existing = this.getCursorAdvanceRow(stage.advanceId);
      if (existing !== undefined) {
        this.assertCursorAdvanceRow(existing);
        const requestedBinding = this.cursorCandidateBinding(
          key,
          stage.lineageId,
          stage.expectedRevision + 1,
          stage.candidateCursor,
        );
        if (
          existing.cursor_key !== key ||
          existing.lineage_id !== stage.lineageId ||
          existing.base_revision !== stage.expectedRevision ||
          existing.attempt_id !== stage.attemptId ||
          existing.staged_at !== stage.stagedAt ||
          !secureEqualHex(existing.candidate_binding, requestedBinding)
        ) {
          throw new OperationsConflictError(
            "CURSOR_CONFLICT",
            "Cursor advance ID is already bound to different content",
          );
        }
        return this.cursorAdvanceFromRow(existing);
      }
      const existingForAttempt = this.database
        .prepare(`SELECT advance_id FROM rsi_cursor_advances WHERE attempt_id = ?`)
        .get(stage.attemptId) as { advance_id: string } | undefined;
      if (existingForAttempt !== undefined) {
        throw new OperationsConflictError(
          "CURSOR_CONFLICT",
          "A network attempt may advance a cursor only once",
        );
      }
      if (head.lineage_id !== stage.lineageId || head.revision !== stage.expectedRevision) {
        throw new OperationsConflictError(
          "CURSOR_CONFLICT",
          "Cursor lineage or revision does not match the expected head",
        );
      }
      if (compareCanonicalTimes(stage.stagedAt, head.updated_at) < 0) {
        throw new OperationsValidationError("stagedAt predates the current cursor head");
      }
      const attempt = this.getAttemptRow(stage.attemptId);
      if (attempt === undefined) throw new OperationsValidationError("attempt does not exist");
      this.assertAttemptRow(attempt);
      if (attempt.state !== "closed" || attempt.outcome !== "succeeded") {
        throw new OperationsConflictError(
          "INVALID_TRANSITION",
          "Only a successfully closed attempt may stage a cursor",
        );
      }
      const attemptBudget = this.getBudgetRow(attempt.budget_id);
      if (attemptBudget === undefined) {
        throw new OperationsIntegrityError("Cursor attempt budget is missing");
      }
      this.assertBudgetRow(attemptBudget);
      if (
        attemptBudget.profile !== stage.profile ||
        attempt.source_plane !== stage.sourcePlane ||
        attempt.lane !== stage.lane ||
        attempt.closed_at === null ||
        compareCanonicalTimes(stage.stagedAt, attempt.closed_at) < 0
      ) {
        throw new OperationsConflictError(
          "CURSOR_CONFLICT",
          "Cursor advance does not match its authorized attempt",
        );
      }

      const revision = stage.expectedRevision + 1;
      const encrypted = encryptCursor(
        this.cursorWrappingKey,
        cursorAad("candidate", key, stage.lineageId, revision, stage.advanceId),
        stage.candidateCursor,
      );
      const unsigned: Omit<CursorAdvanceRow, "row_mac"> = {
        advance_id: stage.advanceId,
        anchor_head: null,
        anchor_id: null,
        attempt_id: stage.attemptId,
        base_revision: stage.expectedRevision,
        candidate_binding: this.cursorCandidateBinding(
          key,
          stage.lineageId,
          revision,
          stage.candidateCursor,
        ),
        candidate_ciphertext: encrypted.encrypted.ciphertext,
        candidate_nonce: encrypted.encrypted.nonce,
        candidate_tag: encrypted.encrypted.tag,
        candidate_wrapped_dek_ciphertext: encrypted.wrappedDek.ciphertext,
        candidate_wrapped_dek_nonce: encrypted.wrappedDek.nonce,
        candidate_wrapped_dek_tag: encrypted.wrappedDek.tag,
        checkpoint_head: null,
        checkpoint_sequence: null,
        cursor_key: key,
        event_hash: null,
        event_id: null,
        event_sequence: null,
        lane: stage.lane,
        lineage_id: stage.lineageId,
        profile: stage.profile,
        source_plane: stage.sourcePlane,
        staged_at: stage.stagedAt,
        state: "staged",
      };
      const rowMac = this.cursorAdvanceMac(unsigned);
      this.insertCursorAdvance(unsigned, rowMac);
      this.appendAudit("cursor.advance.staged.v1", stage.advanceId, stage.stagedAt, {
        advanceId: stage.advanceId,
        attemptId: stage.attemptId,
        baseRevision: stage.expectedRevision,
        lane: stage.lane,
        lineageId: stage.lineageId,
        profile: stage.profile,
        sourcePlane: stage.sourcePlane,
      });
      return this.cursorAdvanceFromRow({ ...unsigned, row_mac: rowMac });
    });
  }

  readCursorAdvance(advanceIdInput: string): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    this.assertOpen();
    const row = this.getCursorAdvanceRow(advanceId);
    if (row === undefined) throw new OperationsValidationError("cursor advance does not exist");
    this.assertCursorAdvanceRow(row);
    return this.cursorAdvanceFromRow(row);
  }

  markCursorValidated(advanceIdInput: string, validatedAtInput: string): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const validatedAt = parseWithSchema(CanonicalTimestampSchema, validatedAtInput, "validatedAt");
    return this.transitionAdvance(
      advanceId,
      "staged",
      "validated",
      validatedAt,
      "cursor.advance.validated.v1",
      (row) => row,
      {},
    );
  }

  markCursorEventPersisted(
    advanceIdInput: string,
    receiptInput: SafeEventReceipt,
  ): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const receipt = parseWithSchema(SafeEventReceiptSchema, receiptInput, "safe event receipt");
    return this.transitionAdvance(
      advanceId,
      "validated",
      "event_persisted",
      receipt.persistedAt,
      "cursor.advance.event-persisted.v1",
      (row) => ({
        ...row,
        event_hash: receipt.eventHash,
        event_id: receipt.eventId,
        event_sequence: receipt.eventSequence,
      }),
      {
        eventHash: receipt.eventHash,
        eventId: receipt.eventId,
        eventSequence: receipt.eventSequence,
      },
    );
  }

  markCursorCheckpointed(
    advanceIdInput: string,
    receiptInput: LocalCheckpointReceipt,
  ): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const receipt = parseWithSchema(
      LocalCheckpointReceiptSchema,
      receiptInput,
      "checkpoint receipt",
    );
    return this.transitionAdvance(
      advanceId,
      "event_persisted",
      "checkpointed",
      receipt.checkpointedAt,
      "cursor.advance.checkpointed.v1",
      (row) => {
        if (row.event_sequence === null || receipt.anchoredThroughSequence < row.event_sequence) {
          throw new OperationsConflictError(
            "CURSOR_CONFLICT",
            "Checkpoint does not anchor the persisted safe event",
          );
        }
        return {
          ...row,
          checkpoint_head: receipt.checkpointHead,
          checkpoint_sequence: receipt.anchoredThroughSequence,
        };
      },
      {
        anchoredThroughSequence: receipt.anchoredThroughSequence,
        checkpointHead: receipt.checkpointHead,
      },
    );
  }

  markCursorAnchorPublished(
    advanceIdInput: string,
    receiptInput: ExternalAnchorReceipt,
  ): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const receipt = parseWithSchema(
      ExternalAnchorReceiptSchema,
      receiptInput,
      "external anchor receipt",
    );
    return this.transitionAdvance(
      advanceId,
      "checkpointed",
      "anchor_published",
      receipt.publishedAt,
      "cursor.advance.anchor-published.v1",
      (row) => {
        if (row.checkpoint_head !== receipt.anchorHead) {
          throw new OperationsConflictError(
            "CURSOR_CONFLICT",
            "External anchor does not match the local checkpoint head",
          );
        }
        return { ...row, anchor_head: receipt.anchorHead, anchor_id: receipt.anchorId };
      },
      { anchorHead: receipt.anchorHead, anchorId: receipt.anchorId },
    );
  }

  markCursorExternallyVerified(
    advanceIdInput: string,
    receiptInput: ExternalVerificationReceipt,
  ): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const receipt = parseWithSchema(
      ExternalVerificationReceiptSchema,
      receiptInput,
      "external verification receipt",
    );
    return this.transitionAdvance(
      advanceId,
      "anchor_published",
      "externally_verified",
      receipt.verifiedAt,
      "cursor.advance.externally-verified.v1",
      (row) => {
        if (row.anchor_id !== receipt.anchorId || row.anchor_head !== receipt.anchorHead) {
          throw new OperationsConflictError(
            "CURSOR_CONFLICT",
            "External verification does not match the published anchor",
          );
        }
        return row;
      },
      { anchorHead: receipt.anchorHead, anchorId: receipt.anchorId },
    );
  }

  commitCursor(advanceIdInput: string, committedAtInput: string): CursorCommitReceipt {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const committedAt = parseWithSchema(CanonicalTimestampSchema, committedAtInput, "committedAt");
    const receipt = this.transaction(() => {
      const advance = this.getCursorAdvanceRow(advanceId);
      if (advance === undefined)
        throw new OperationsValidationError("cursor advance does not exist");
      this.assertCursorAdvanceRow(advance);
      if (advance.state === "committed") {
        this.assertAuditReplay(advance.advance_id, "cursor.advance.committed.v1", committedAt, {
          advanceId: advance.advance_id,
          baseRevision: advance.base_revision,
          lane: advance.lane,
          lineageId: advance.lineage_id,
          profile: advance.profile,
          revision: advance.base_revision + 1,
          sourcePlane: advance.source_plane,
        });
        return this.cursorCommitReceiptFromAdvance(advance, committedAt);
      }
      if (advance.state !== "externally_verified") {
        throw new OperationsConflictError(
          "INVALID_TRANSITION",
          "Cursor cannot commit before independent external verification",
        );
      }
      const attempt = this.getAttemptRow(advance.attempt_id);
      if (attempt === undefined) throw new OperationsIntegrityError("Cursor attempt is missing");
      this.assertAttemptRow(attempt);
      if (attempt.state !== "closed" || attempt.outcome !== "succeeded") {
        throw new OperationsConflictError(
          "INVALID_TRANSITION",
          "Cursor cannot commit without a successfully closed attempt",
        );
      }
      if (
        advance.candidate_ciphertext === null ||
        advance.candidate_nonce === null ||
        advance.candidate_tag === null ||
        advance.candidate_wrapped_dek_ciphertext === null ||
        advance.candidate_wrapped_dek_nonce === null ||
        advance.candidate_wrapped_dek_tag === null
      ) {
        throw new OperationsIntegrityError("Cursor advance candidate is missing");
      }
      if (compareCanonicalTimes(committedAt, advance.staged_at) < 0) {
        throw new OperationsValidationError("committedAt predates the cursor advance");
      }
      this.assertAuditTimeNotRegressed(advance.advance_id, committedAt);
      const head = this.getCursorHeadRow(advance.cursor_key);
      if (head === undefined) throw new OperationsIntegrityError("Cursor head is missing");
      this.assertCursorHeadRow(head);
      if (head.lineage_id !== advance.lineage_id || head.revision !== advance.base_revision) {
        throw new OperationsConflictError("CURSOR_CONFLICT", "Cursor head changed before commit");
      }
      if (compareCanonicalTimes(committedAt, head.updated_at) < 0) {
        throw new OperationsValidationError("committedAt predates the current cursor head");
      }
      const candidate = this.decryptAdvanceCandidate(advance);
      const encryptedHead = encryptCursor(
        this.cursorWrappingKey,
        cursorAad(
          "head",
          advance.cursor_key,
          advance.lineage_id,
          advance.base_revision + 1,
          advance.cursor_key,
        ),
        candidate,
      );
      const headUnsigned: Omit<CursorHeadRow, "row_mac"> = {
        ...this.withoutCursorHeadMac(head),
        ciphertext: encryptedHead.encrypted.ciphertext,
        nonce: encryptedHead.encrypted.nonce,
        revision: advance.base_revision + 1,
        tag: encryptedHead.encrypted.tag,
        updated_at: committedAt,
        wrapped_dek_ciphertext: encryptedHead.wrappedDek.ciphertext,
        wrapped_dek_nonce: encryptedHead.wrappedDek.nonce,
        wrapped_dek_tag: encryptedHead.wrappedDek.tag,
      };
      const headMac = this.cursorHeadMac(headUnsigned);
      this.writeCursorHead(headUnsigned, headMac);

      const advanceUnsigned: Omit<CursorAdvanceRow, "row_mac"> = {
        ...this.withoutCursorAdvanceMac(advance),
        candidate_ciphertext: null,
        candidate_nonce: null,
        candidate_tag: null,
        candidate_wrapped_dek_ciphertext: null,
        candidate_wrapped_dek_nonce: null,
        candidate_wrapped_dek_tag: null,
        state: "committed",
      };
      const advanceMac = this.cursorAdvanceMac(advanceUnsigned);
      this.writeCursorAdvance(advanceUnsigned, advanceMac);
      this.writeCursorErasurePending(true);
      this.appendAudit("cursor.advance.committed.v1", advance.advance_id, committedAt, {
        advanceId: advance.advance_id,
        baseRevision: advance.base_revision,
        lane: advance.lane,
        lineageId: advance.lineage_id,
        profile: advance.profile,
        revision: advance.base_revision + 1,
        sourcePlane: advance.source_plane,
      });
      return this.cursorCommitReceiptFromAdvance(
        { ...advanceUnsigned, row_mac: advanceMac },
        committedAt,
      );
    });
    this.completePendingCursorErasure();
    return receipt;
  }

  abortCursorAdvance(advanceIdInput: string, abortedAtInput: string): CursorAdvanceRecord {
    const advanceId = parseWithSchema(UuidSchema, advanceIdInput, "advanceId");
    const abortedAt = parseWithSchema(CanonicalTimestampSchema, abortedAtInput, "abortedAt");
    const record = this.transaction(() => {
      const row = this.getCursorAdvanceRow(advanceId);
      if (row === undefined) throw new OperationsValidationError("cursor advance does not exist");
      this.assertCursorAdvanceRow(row);
      if (row.state === "committed") {
        throw new OperationsConflictError(
          "INVALID_TRANSITION",
          "A committed cursor advance cannot be aborted",
        );
      }
      if (row.state === "aborted") {
        this.assertAuditReplay(row.advance_id, "cursor.advance.aborted.v1", abortedAt, {
          advanceId: row.advance_id,
          baseRevision: row.base_revision,
          lane: row.lane,
          lineageId: row.lineage_id,
          profile: row.profile,
          sourcePlane: row.source_plane,
        });
        return this.cursorAdvanceFromRow(row);
      }
      if (compareCanonicalTimes(abortedAt, row.staged_at) < 0) {
        throw new OperationsValidationError("abortedAt predates the cursor advance");
      }
      this.assertAuditTimeNotRegressed(row.advance_id, abortedAt);
      const updated: Omit<CursorAdvanceRow, "row_mac"> = {
        ...this.withoutCursorAdvanceMac(row),
        candidate_ciphertext: null,
        candidate_nonce: null,
        candidate_tag: null,
        candidate_wrapped_dek_ciphertext: null,
        candidate_wrapped_dek_nonce: null,
        candidate_wrapped_dek_tag: null,
        state: "aborted",
      };
      const rowMac = this.cursorAdvanceMac(updated);
      this.writeCursorAdvance(updated, rowMac);
      this.writeCursorErasurePending(true);
      this.appendAudit("cursor.advance.aborted.v1", row.advance_id, abortedAt, {
        advanceId: row.advance_id,
        baseRevision: row.base_revision,
        lane: row.lane,
        lineageId: row.lineage_id,
        profile: row.profile,
        sourcePlane: row.source_plane,
      });
      return this.cursorAdvanceFromRow({ ...updated, row_mac: rowMac });
    });
    this.completePendingCursorErasure();
    return record;
  }

  private transitionAdvance(
    advanceId: string,
    expected: CursorAdvanceState,
    next: CursorAdvanceState,
    occurredAt: string,
    eventType: string,
    update: (row: Omit<CursorAdvanceRow, "row_mac">) => Omit<CursorAdvanceRow, "row_mac">,
    payload: Readonly<Record<string, JsonValue>>,
  ): CursorAdvanceRecord {
    return this.transaction(() => {
      const row = this.getCursorAdvanceRow(advanceId);
      if (row === undefined) throw new OperationsValidationError("cursor advance does not exist");
      this.assertCursorAdvanceRow(row);
      const currentIndex = CURSOR_ADVANCE_ORDER.indexOf(row.state as CursorAdvanceState);
      const nextIndex = CURSOR_ADVANCE_ORDER.indexOf(next);
      if (row.state !== "aborted" && currentIndex >= nextIndex) {
        const replayed = { ...update(this.withoutCursorAdvanceMac(row)), state: row.state };
        if (!secureEqualHex(this.cursorAdvanceMac(replayed), row.row_mac)) {
          throw new OperationsConflictError(
            "CURSOR_CONFLICT",
            "Cursor transition was retried with different receipt content",
          );
        }
        this.assertAuditReplay(advanceId, eventType, occurredAt, {
          advanceId: row.advance_id,
          ...payload,
        });
        return this.cursorAdvanceFromRow(row);
      }
      if (row.state !== expected) {
        throw new OperationsConflictError(
          "INVALID_TRANSITION",
          `Cursor advance must be ${expected} before moving to ${next}`,
        );
      }
      if (compareCanonicalTimes(occurredAt, row.staged_at) < 0) {
        throw new OperationsValidationError("transition timestamp predates the cursor advance");
      }
      this.assertAuditTimeNotRegressed(row.advance_id, occurredAt);
      const updated = { ...update(this.withoutCursorAdvanceMac(row)), state: next };
      const rowMac = this.cursorAdvanceMac(updated);
      this.writeCursorAdvance(updated, rowMac);
      this.appendAudit(eventType, row.advance_id, occurredAt, {
        advanceId: row.advance_id,
        ...payload,
      });
      return this.cursorAdvanceFromRow({ ...updated, row_mac: rowMac });
    });
  }

  private assertAuditReplay(
    aggregateId: string,
    eventType: string,
    occurredAt: string,
    payload: Readonly<Record<string, JsonValue>>,
  ): void {
    const row = this.database
      .prepare(
        `SELECT * FROM rsi_operation_audit
          WHERE aggregate_id = ? AND event_type = ?
          ORDER BY sequence DESC
          LIMIT 1`,
      )
      .get(aggregateId, eventType) as AuditRow | undefined;
    if (
      row === undefined ||
      row.event_type !== eventType ||
      row.occurred_at !== occurredAt ||
      row.payload_json !== canonicalJson(jsonValue(payload))
    ) {
      throw new OperationsConflictError(
        "CURSOR_CONFLICT",
        "Cursor transition was retried with different audit content",
      );
    }
  }

  private assertAuditTimeNotRegressed(aggregateId: string, occurredAt: string): void {
    const row = this.latestAuditRow(aggregateId);
    if (row === undefined || compareCanonicalTimes(occurredAt, row.occurred_at) < 0) {
      throw new OperationsValidationError("transition timestamp regresses its audit history");
    }
  }

  private latestAuditRow(aggregateId: string): AuditRow | undefined {
    return this.database
      .prepare(
        `SELECT * FROM rsi_operation_audit
          WHERE aggregate_id = ?
          ORDER BY sequence DESC
          LIMIT 1`,
      )
      .get(aggregateId) as AuditRow | undefined;
  }

  private getBudgetRow(budgetId: string): BudgetRow | undefined {
    return this.database.prepare(`SELECT * FROM rsi_budgets WHERE budget_id = ?`).get(budgetId) as
      BudgetRow | undefined;
  }

  private budgetMac(row: Omit<BudgetRow, "row_mac">): string {
    return macJson(this.macKey, "budget-row", {
      budgetId: row.budget_id,
      createdAt: row.created_at,
      currency: row.currency,
      endsAt: row.ends_at,
      maxAtomic: row.max_atomic,
      maxAttempts: row.max_attempts,
      profile: row.profile,
      startsAt: row.starts_at,
    });
  }

  private assertBudgetRow(row: BudgetRow): void {
    parseWithSchema(
      CreateBudgetInputSchema,
      {
        budgetId: row.budget_id,
        createdAt: row.created_at,
        currency: row.currency,
        endsAt: row.ends_at,
        maxAtomic: row.max_atomic,
        maxAttempts: row.max_attempts,
        profile: row.profile,
        startsAt: row.starts_at,
      },
      "stored budget",
    );
    if (compareCanonicalTimes(row.starts_at, row.ends_at) >= 0) {
      throw new OperationsIntegrityError("Stored budget window is invalid");
    }
    const actual = this.budgetMac({
      budget_id: row.budget_id,
      created_at: row.created_at,
      currency: row.currency,
      ends_at: row.ends_at,
      max_atomic: row.max_atomic,
      max_attempts: row.max_attempts,
      profile: row.profile,
      starts_at: row.starts_at,
    });
    if (!secureEqualHex(actual, row.row_mac)) {
      throw new OperationsIntegrityError("Stored budget row failed authentication");
    }
  }

  private budgetFromRow(row: BudgetRow): BudgetRecord {
    return Object.freeze({
      budgetId: row.budget_id,
      createdAt: row.created_at,
      currency: row.currency,
      endsAt: row.ends_at,
      maxAtomic: row.max_atomic as AtomicAmount,
      maxAttempts: row.max_attempts,
      profile: parseWithSchema(OperationsProfileSchema, row.profile, "stored budget profile"),
      startsAt: row.starts_at,
    });
  }

  private getAttemptRow(attemptId: string): AttemptRow | undefined {
    return this.database
      .prepare(`SELECT * FROM rsi_attempts WHERE attempt_id = ?`)
      .get(attemptId) as AttemptRow | undefined;
  }

  private withoutAttemptMac(row: AttemptRow): Omit<AttemptRow, "row_mac"> {
    const { row_mac: _rowMac, ...unsigned } = row;
    return unsigned;
  }

  private attemptMac(row: Omit<AttemptRow, "row_mac">): string {
    return macJson(this.macKey, "attempt-row", {
      attemptId: row.attempt_id,
      authorizationExpiresAt: row.authorization_expires_at,
      budgetId: row.budget_id,
      closedAt: row.closed_at,
      createdAt: row.created_at,
      dispatchedAt: row.dispatched_at,
      idempotencyKey: row.idempotency_key,
      lane: row.lane,
      operation: row.operation,
      outcome: row.outcome,
      permitHash: row.permit_hash,
      reservedAtomic: row.reserved_atomic,
      sessionId: row.session_id,
      sourcePlane: row.source_plane,
      state: row.state,
    });
  }

  private assertAttemptRow(row: AttemptRow): void {
    parseWithSchema(UuidSchema, row.attempt_id, "stored attempt ID");
    parseWithSchema(UuidSchema, row.budget_id, "stored budget ID");
    parseWithSchema(IdentifierSchema, row.idempotency_key, "stored idempotency key");
    parseWithSchema(UuidSchema, row.session_id, "stored session ID");
    parseWithSchema(SourcePlaneSchema, row.source_plane, "stored source plane");
    parseWithSchema(ResearchLaneSchema, row.lane, "stored research lane");
    parseWithSchema(ResearchOperationSchema, row.operation, "stored research operation");
    parseWithSchema(PositiveAtomicAmountSchema, row.reserved_atomic, "stored reservation");
    parseWithSchema(HashSchema, row.permit_hash, "stored permit hash");
    parseWithSchema(CanonicalTimestampSchema, row.authorization_expires_at, "stored expiry");
    parseWithSchema(CanonicalTimestampSchema, row.created_at, "stored createdAt");
    parseWithSchema(z.enum(["reserved", "dispatched", "closed"]), row.state, "stored state");
    if (row.dispatched_at !== null) {
      parseWithSchema(CanonicalTimestampSchema, row.dispatched_at, "stored dispatchedAt");
    }
    if (row.closed_at !== null) {
      parseWithSchema(CanonicalTimestampSchema, row.closed_at, "stored closedAt");
    }
    if (row.outcome !== null) {
      parseWithSchema(
        z.enum(["succeeded", "failed", "empty", "aborted"]),
        row.outcome,
        "stored outcome",
      );
    }
    const stateValid =
      (row.state === "reserved" &&
        row.dispatched_at === null &&
        row.closed_at === null &&
        row.outcome === null) ||
      (row.state === "dispatched" &&
        row.dispatched_at !== null &&
        row.closed_at === null &&
        row.outcome === null) ||
      (row.state === "closed" && row.closed_at !== null && row.outcome !== null);
    if (!stateValid) throw new OperationsIntegrityError("Stored attempt state is inconsistent");
    const actual = this.attemptMac(this.withoutAttemptMac(row));
    if (!secureEqualHex(actual, row.row_mac)) {
      throw new OperationsIntegrityError("Stored attempt row failed authentication");
    }
  }

  private attemptFromRow(row: AttemptRow): AttemptRecord {
    return Object.freeze({
      attemptId: row.attempt_id,
      authorizationExpiresAt: row.authorization_expires_at,
      budgetId: row.budget_id,
      closedAt: row.closed_at,
      createdAt: row.created_at,
      dispatchedAt: row.dispatched_at,
      idempotencyKey: row.idempotency_key,
      lane: parseWithSchema(ResearchLaneSchema, row.lane, "stored lane"),
      operation: parseWithSchema(ResearchOperationSchema, row.operation, "stored operation"),
      outcome:
        row.outcome === null
          ? null
          : parseWithSchema(
              z.enum(["succeeded", "failed", "empty", "aborted"]),
              row.outcome,
              "stored outcome",
            ),
      reservedAtomic: row.reserved_atomic as AtomicAmount,
      sessionId: row.session_id,
      sourcePlane: parseWithSchema(SourcePlaneSchema, row.source_plane, "stored source plane"),
      state: row.state as AttemptState,
    });
  }

  private writeAttempt(row: Omit<AttemptRow, "row_mac">, rowMac: string): void {
    const updated = this.database
      .prepare(
        `UPDATE rsi_attempts SET
           budget_id = ?, idempotency_key = ?, session_id = ?, source_plane = ?, lane = ?,
           operation = ?, reserved_atomic = ?, permit_hash = ?, authorization_expires_at = ?, state = ?,
           outcome = ?, created_at = ?, dispatched_at = ?, closed_at = ?, row_mac = ?
         WHERE attempt_id = ?`,
      )
      .run(
        row.budget_id,
        row.idempotency_key,
        row.session_id,
        row.source_plane,
        row.lane,
        row.operation,
        row.reserved_atomic,
        row.permit_hash,
        row.authorization_expires_at,
        row.state,
        row.outcome,
        row.created_at,
        row.dispatched_at,
        row.closed_at,
        rowMac,
        row.attempt_id,
      );
    if (updated.changes !== 1) throw new OperationsIntegrityError("Attempt update failed");
  }

  private getCursorHeadRow(key: string): CursorHeadRow | undefined {
    return this.database.prepare(`SELECT * FROM rsi_cursor_heads WHERE cursor_key = ?`).get(key) as
      CursorHeadRow | undefined;
  }

  private withoutCursorHeadMac(row: CursorHeadRow): Omit<CursorHeadRow, "row_mac"> {
    const { row_mac: _rowMac, ...unsigned } = row;
    return unsigned;
  }

  private cursorHeadMac(row: Omit<CursorHeadRow, "row_mac">): string {
    return macJson(this.macKey, "cursor-head-row", {
      ciphertext: bufferBase64(row.ciphertext),
      cursorKey: row.cursor_key,
      lane: row.lane,
      lineageId: row.lineage_id,
      nonce: bufferBase64(row.nonce),
      profile: row.profile,
      revision: row.revision,
      sourcePlane: row.source_plane,
      tag: bufferBase64(row.tag),
      updatedAt: row.updated_at,
      wrappedDekCiphertext: bufferBase64(row.wrapped_dek_ciphertext),
      wrappedDekNonce: bufferBase64(row.wrapped_dek_nonce),
      wrappedDekTag: bufferBase64(row.wrapped_dek_tag),
    });
  }

  private assertCursorHeadRow(row: CursorHeadRow): void {
    parseWithSchema(
      CursorIdentitySchema,
      { lane: row.lane, profile: row.profile, sourcePlane: row.source_plane },
      "stored cursor identity",
    );
    if (
      row.cursor_key !==
      cursorStorageKey({
        lane: row.lane as CursorIdentity["lane"],
        profile: row.profile as CursorIdentity["profile"],
        sourcePlane: row.source_plane as CursorIdentity["sourcePlane"],
      })
    ) {
      throw new OperationsIntegrityError("Stored cursor key is inconsistent");
    }
    parseWithSchema(UuidSchema, row.lineage_id, "stored cursor lineage");
    parseWithSchema(CanonicalTimestampSchema, row.updated_at, "stored cursor updatedAt");
    if (!Number.isSafeInteger(row.revision) || row.revision < 0) {
      throw new OperationsIntegrityError("Stored cursor revision is invalid");
    }
    const allNull =
      row.ciphertext === null &&
      row.nonce === null &&
      row.tag === null &&
      row.wrapped_dek_ciphertext === null &&
      row.wrapped_dek_nonce === null &&
      row.wrapped_dek_tag === null;
    const allPresent =
      row.ciphertext !== null &&
      row.nonce !== null &&
      row.tag !== null &&
      row.wrapped_dek_ciphertext !== null &&
      row.wrapped_dek_nonce !== null &&
      row.wrapped_dek_tag !== null;
    if (!allNull && !allPresent) {
      throw new OperationsIntegrityError("Stored cursor encryption fields are incomplete");
    }
    if ((row.revision === 0) !== allNull) {
      throw new OperationsIntegrityError("Stored cursor revision and value disagree");
    }
    const actual = this.cursorHeadMac(this.withoutCursorHeadMac(row));
    if (!secureEqualHex(actual, row.row_mac)) {
      throw new OperationsIntegrityError("Stored cursor head failed authentication");
    }
    if (allPresent) {
      const value = decryptCursor(
        this.cursorWrappingKey,
        cursorAad("head", row.cursor_key, row.lineage_id, row.revision, row.cursor_key),
        { ciphertext: row.ciphertext!, nonce: row.nonce!, tag: row.tag! },
        {
          ciphertext: row.wrapped_dek_ciphertext!,
          nonce: row.wrapped_dek_nonce!,
          tag: row.wrapped_dek_tag!,
        },
      );
      parseWithSchema(OpaqueCursorSchema, value, "stored cursor value");
    }
  }

  private cursorStateFromRow(row: CursorHeadRow): CursorState {
    let value: string | null = null;
    if (
      row.ciphertext !== null &&
      row.nonce !== null &&
      row.tag !== null &&
      row.wrapped_dek_ciphertext !== null &&
      row.wrapped_dek_nonce !== null &&
      row.wrapped_dek_tag !== null
    ) {
      value = decryptCursor(
        this.cursorWrappingKey,
        cursorAad("head", row.cursor_key, row.lineage_id, row.revision, row.cursor_key),
        { ciphertext: row.ciphertext, nonce: row.nonce, tag: row.tag },
        {
          ciphertext: row.wrapped_dek_ciphertext,
          nonce: row.wrapped_dek_nonce,
          tag: row.wrapped_dek_tag,
        },
      );
    }
    return Object.freeze({
      lane: parseWithSchema(ResearchLaneSchema, row.lane, "stored cursor lane"),
      lineageId: row.lineage_id,
      profile: parseWithSchema(OperationsProfileSchema, row.profile, "stored cursor profile"),
      revision: row.revision,
      sourcePlane: parseWithSchema(
        SourcePlaneSchema,
        row.source_plane,
        "stored cursor source plane",
      ),
      updatedAt: row.updated_at,
      value,
    });
  }

  private writeCursorHead(row: Omit<CursorHeadRow, "row_mac">, rowMac: string): void {
    const updated = this.database
      .prepare(
        `UPDATE rsi_cursor_heads SET
           profile = ?, source_plane = ?, lane = ?, lineage_id = ?, revision = ?,
           ciphertext = ?, nonce = ?, tag = ?, wrapped_dek_ciphertext = ?,
           wrapped_dek_nonce = ?, wrapped_dek_tag = ?, updated_at = ?, row_mac = ?
         WHERE cursor_key = ?`,
      )
      .run(
        row.profile,
        row.source_plane,
        row.lane,
        row.lineage_id,
        row.revision,
        row.ciphertext,
        row.nonce,
        row.tag,
        row.wrapped_dek_ciphertext,
        row.wrapped_dek_nonce,
        row.wrapped_dek_tag,
        row.updated_at,
        rowMac,
        row.cursor_key,
      );
    if (updated.changes !== 1) throw new OperationsIntegrityError("Cursor head update failed");
  }

  private getCursorAdvanceRow(advanceId: string): CursorAdvanceRow | undefined {
    return this.database
      .prepare(`SELECT * FROM rsi_cursor_advances WHERE advance_id = ?`)
      .get(advanceId) as CursorAdvanceRow | undefined;
  }

  private withoutCursorAdvanceMac(row: CursorAdvanceRow): Omit<CursorAdvanceRow, "row_mac"> {
    const { row_mac: _rowMac, ...unsigned } = row;
    return unsigned;
  }

  private cursorAdvanceMac(row: Omit<CursorAdvanceRow, "row_mac">): string {
    return macJson(this.macKey, "cursor-advance-row", {
      advanceId: row.advance_id,
      anchorHead: row.anchor_head,
      anchorId: row.anchor_id,
      attemptId: row.attempt_id,
      baseRevision: row.base_revision,
      candidateBinding: row.candidate_binding,
      candidateCiphertext: bufferBase64(row.candidate_ciphertext),
      candidateNonce: bufferBase64(row.candidate_nonce),
      candidateTag: bufferBase64(row.candidate_tag),
      candidateWrappedDekCiphertext: bufferBase64(row.candidate_wrapped_dek_ciphertext),
      candidateWrappedDekNonce: bufferBase64(row.candidate_wrapped_dek_nonce),
      candidateWrappedDekTag: bufferBase64(row.candidate_wrapped_dek_tag),
      checkpointHead: row.checkpoint_head,
      checkpointSequence: row.checkpoint_sequence,
      cursorKey: row.cursor_key,
      eventHash: row.event_hash,
      eventId: row.event_id,
      eventSequence: row.event_sequence,
      lane: row.lane,
      lineageId: row.lineage_id,
      profile: row.profile,
      sourcePlane: row.source_plane,
      stagedAt: row.staged_at,
      state: row.state,
    });
  }

  private assertCursorAdvanceRow(row: CursorAdvanceRow): void {
    parseWithSchema(UuidSchema, row.advance_id, "stored advance ID");
    parseWithSchema(UuidSchema, row.attempt_id, "stored advance attempt ID");
    parseWithSchema(UuidSchema, row.lineage_id, "stored advance lineage ID");
    parseWithSchema(CanonicalTimestampSchema, row.staged_at, "stored advance timestamp");
    parseWithSchema(
      CursorIdentitySchema,
      { lane: row.lane, profile: row.profile, sourcePlane: row.source_plane },
      "stored advance identity",
    );
    parseWithSchema(
      z.enum([
        "staged",
        "validated",
        "event_persisted",
        "checkpointed",
        "anchor_published",
        "externally_verified",
        "committed",
        "aborted",
      ]),
      row.state,
      "stored advance state",
    );
    if (!Number.isSafeInteger(row.base_revision) || row.base_revision < 0) {
      throw new OperationsIntegrityError("Stored advance revision is invalid");
    }
    parseWithSchema(HashSchema, row.candidate_binding, "stored candidate binding");
    const candidateAllNull =
      row.candidate_ciphertext === null &&
      row.candidate_nonce === null &&
      row.candidate_tag === null &&
      row.candidate_wrapped_dek_ciphertext === null &&
      row.candidate_wrapped_dek_nonce === null &&
      row.candidate_wrapped_dek_tag === null;
    const candidateAllPresent =
      row.candidate_ciphertext !== null &&
      row.candidate_nonce !== null &&
      row.candidate_tag !== null &&
      row.candidate_wrapped_dek_ciphertext !== null &&
      row.candidate_wrapped_dek_nonce !== null &&
      row.candidate_wrapped_dek_tag !== null;
    if (!candidateAllNull && !candidateAllPresent) {
      throw new OperationsIntegrityError("Stored advance candidate fields are incomplete");
    }
    if (["committed", "aborted"].includes(row.state) !== candidateAllNull) {
      throw new OperationsIntegrityError("Stored advance state and candidate disagree");
    }
    const stateOrder: readonly string[] = [
      "staged",
      "validated",
      "event_persisted",
      "checkpointed",
      "anchor_published",
      "externally_verified",
      "committed",
    ];
    const stateIndex = stateOrder.indexOf(row.state);
    const expectsEvent = stateIndex >= stateOrder.indexOf("event_persisted");
    const expectsCheckpoint = stateIndex >= stateOrder.indexOf("checkpointed");
    const expectsAnchor = stateIndex >= stateOrder.indexOf("anchor_published");
    const hasEvent =
      row.event_id !== null && row.event_sequence !== null && row.event_hash !== null;
    const hasCheckpoint = row.checkpoint_sequence !== null && row.checkpoint_head !== null;
    const hasAnchor = row.anchor_id !== null && row.anchor_head !== null;
    if (row.state !== "aborted") {
      if (
        expectsEvent !== hasEvent ||
        expectsCheckpoint !== hasCheckpoint ||
        expectsAnchor !== hasAnchor
      ) {
        throw new OperationsIntegrityError("Stored advance receipts do not match its state");
      }
    }
    if (row.event_id !== null) parseWithSchema(UuidSchema, row.event_id, "stored event ID");
    if (row.event_hash !== null) parseWithSchema(HashSchema, row.event_hash, "stored event hash");
    if (
      row.event_sequence !== null &&
      (!Number.isSafeInteger(row.event_sequence) || row.event_sequence < 1)
    ) {
      throw new OperationsIntegrityError("Stored event sequence is invalid");
    }
    if (row.checkpoint_head !== null) {
      parseWithSchema(HashSchema, row.checkpoint_head, "stored checkpoint head");
    }
    if (
      row.checkpoint_sequence !== null &&
      (!Number.isSafeInteger(row.checkpoint_sequence) || row.checkpoint_sequence < 1)
    ) {
      throw new OperationsIntegrityError("Stored checkpoint sequence is invalid");
    }
    if (row.anchor_id !== null) parseWithSchema(UuidSchema, row.anchor_id, "stored anchor ID");
    if (row.anchor_head !== null)
      parseWithSchema(HashSchema, row.anchor_head, "stored anchor head");
    if (
      row.checkpoint_sequence !== null &&
      row.event_sequence !== null &&
      row.checkpoint_sequence < row.event_sequence
    ) {
      throw new OperationsIntegrityError("Stored checkpoint does not cover the event");
    }
    if (
      row.anchor_head !== null &&
      row.checkpoint_head !== null &&
      row.anchor_head !== row.checkpoint_head
    ) {
      throw new OperationsIntegrityError("Stored external anchor does not match the checkpoint");
    }
    const actual = this.cursorAdvanceMac(this.withoutCursorAdvanceMac(row));
    if (!secureEqualHex(actual, row.row_mac)) {
      throw new OperationsIntegrityError("Stored cursor advance failed authentication");
    }
    if (candidateAllPresent) {
      const candidate = this.decryptAdvanceCandidate(row);
      const expectedBinding = this.cursorCandidateBinding(
        row.cursor_key,
        row.lineage_id,
        row.base_revision + 1,
        candidate,
      );
      if (!secureEqualHex(row.candidate_binding, expectedBinding)) {
        throw new OperationsIntegrityError("Stored cursor candidate binding is invalid");
      }
    }
  }

  private cursorCandidateBinding(
    cursorKey: string,
    lineageId: string,
    revision: number,
    value: string,
  ): string {
    return macJson(this.macKey, "cursor-candidate-binding", {
      cursorKey,
      lineageId,
      revision,
      value,
    });
  }

  private decryptAdvanceCandidate(row: CursorAdvanceRow): string {
    if (
      row.candidate_ciphertext === null ||
      row.candidate_nonce === null ||
      row.candidate_tag === null ||
      row.candidate_wrapped_dek_ciphertext === null ||
      row.candidate_wrapped_dek_nonce === null ||
      row.candidate_wrapped_dek_tag === null
    ) {
      throw new OperationsIntegrityError("Cursor advance candidate has been destroyed");
    }
    const value = decryptCursor(
      this.cursorWrappingKey,
      cursorAad("candidate", row.cursor_key, row.lineage_id, row.base_revision + 1, row.advance_id),
      {
        ciphertext: row.candidate_ciphertext,
        nonce: row.candidate_nonce,
        tag: row.candidate_tag,
      },
      {
        ciphertext: row.candidate_wrapped_dek_ciphertext,
        nonce: row.candidate_wrapped_dek_nonce,
        tag: row.candidate_wrapped_dek_tag,
      },
    );
    return parseWithSchema(OpaqueCursorSchema, value, "stored cursor candidate");
  }

  private cursorCommitReceiptFromAdvance(
    row: CursorAdvanceRow,
    committedAt: string,
  ): CursorCommitReceipt {
    if (row.state !== "committed") {
      throw new OperationsIntegrityError("Cursor advance is not committed");
    }
    return Object.freeze({
      advanceId: row.advance_id,
      committedAt,
      lane: parseWithSchema(ResearchLaneSchema, row.lane, "stored cursor lane"),
      lineageId: row.lineage_id,
      profile: parseWithSchema(OperationsProfileSchema, row.profile, "stored cursor profile"),
      revision: row.base_revision + 1,
      sourcePlane: parseWithSchema(
        SourcePlaneSchema,
        row.source_plane,
        "stored cursor source plane",
      ),
      state: "committed" as const,
    });
  }

  private cursorAdvanceFromRow(row: CursorAdvanceRow): CursorAdvanceRecord {
    return Object.freeze({
      advanceId: row.advance_id,
      attemptId: row.attempt_id,
      baseRevision: row.base_revision,
      lane: parseWithSchema(ResearchLaneSchema, row.lane, "stored advance lane"),
      lineageId: row.lineage_id,
      profile: parseWithSchema(OperationsProfileSchema, row.profile, "stored advance profile"),
      sourcePlane: parseWithSchema(
        SourcePlaneSchema,
        row.source_plane,
        "stored advance source plane",
      ),
      stagedAt: row.staged_at,
      state: row.state as CursorAdvanceState,
    });
  }

  private insertCursorAdvance(row: Omit<CursorAdvanceRow, "row_mac">, rowMac: string): void {
    this.database
      .prepare(
        `INSERT INTO rsi_cursor_advances (
           advance_id, cursor_key, profile, source_plane, lane, lineage_id, base_revision,
           attempt_id, state, candidate_binding, candidate_ciphertext, candidate_nonce, candidate_tag,
           candidate_wrapped_dek_ciphertext, candidate_wrapped_dek_nonce, candidate_wrapped_dek_tag,
           event_id, event_sequence, event_hash, checkpoint_sequence, checkpoint_head,
           anchor_id, anchor_head, staged_at, row_mac
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.advance_id,
        row.cursor_key,
        row.profile,
        row.source_plane,
        row.lane,
        row.lineage_id,
        row.base_revision,
        row.attempt_id,
        row.state,
        row.candidate_binding,
        row.candidate_ciphertext,
        row.candidate_nonce,
        row.candidate_tag,
        row.candidate_wrapped_dek_ciphertext,
        row.candidate_wrapped_dek_nonce,
        row.candidate_wrapped_dek_tag,
        row.event_id,
        row.event_sequence,
        row.event_hash,
        row.checkpoint_sequence,
        row.checkpoint_head,
        row.anchor_id,
        row.anchor_head,
        row.staged_at,
        rowMac,
      );
  }

  private writeCursorAdvance(row: Omit<CursorAdvanceRow, "row_mac">, rowMac: string): void {
    const updated = this.database
      .prepare(
        `UPDATE rsi_cursor_advances SET
           cursor_key = ?, profile = ?, source_plane = ?, lane = ?, lineage_id = ?,
           base_revision = ?, attempt_id = ?, state = ?, candidate_ciphertext = ?,
           candidate_binding = ?, candidate_nonce = ?, candidate_tag = ?,
           candidate_wrapped_dek_ciphertext = ?, candidate_wrapped_dek_nonce = ?,
           candidate_wrapped_dek_tag = ?, event_id = ?, event_sequence = ?,
           event_hash = ?, checkpoint_sequence = ?, checkpoint_head = ?, anchor_id = ?,
           anchor_head = ?, staged_at = ?, row_mac = ?
         WHERE advance_id = ?`,
      )
      .run(
        row.cursor_key,
        row.profile,
        row.source_plane,
        row.lane,
        row.lineage_id,
        row.base_revision,
        row.attempt_id,
        row.state,
        row.candidate_ciphertext,
        row.candidate_binding,
        row.candidate_nonce,
        row.candidate_tag,
        row.candidate_wrapped_dek_ciphertext,
        row.candidate_wrapped_dek_nonce,
        row.candidate_wrapped_dek_tag,
        row.event_id,
        row.event_sequence,
        row.event_hash,
        row.checkpoint_sequence,
        row.checkpoint_head,
        row.anchor_id,
        row.anchor_head,
        row.staged_at,
        rowMac,
        row.advance_id,
      );
    if (updated.changes !== 1) throw new OperationsIntegrityError("Cursor advance update failed");
  }

  private verifyIntegrityInternal(): OperationsIntegrityReport {
    const errors: string[] = [];
    let metadata: MetadataRow | undefined;
    try {
      metadata = this.database
        .prepare(
          `SELECT schema_version, audit_head_sequence, audit_head_mac, key_check_mac,
                  cursor_erasure_pending, metadata_mac
             FROM rsi_operations_metadata WHERE singleton = 1`,
        )
        .get() as MetadataRow | undefined;
      if (metadata === undefined) errors.push("Operations metadata is missing");
      else {
        try {
          this.assertMetadataRow(metadata);
        } catch (error) {
          errors.push(error instanceof Error ? error.message : "Operations metadata is invalid");
        }
      }
    } catch {
      errors.push("Operations metadata cannot be read");
    }

    let auditRows: AuditRow[] = [];
    try {
      auditRows = this.database
        .prepare(`SELECT * FROM rsi_operation_audit ORDER BY sequence`)
        .all() as unknown as AuditRow[];
      let previous = GENESIS_MAC;
      for (let index = 0; index < auditRows.length; index += 1) {
        const row = auditRows[index]!;
        const expectedSequence = index + 1;
        if (row.sequence !== expectedSequence)
          errors.push(`Audit sequence gap at ${expectedSequence}`);
        if (row.previous_mac !== previous)
          errors.push(`Audit predecessor mismatch at ${row.sequence}`);
        try {
          parseWithSchema(CanonicalTimestampSchema, row.occurred_at, "audit timestamp");
          const payload = parsePayloadJson(row.payload_json);
          if (canonicalJson(payload) !== row.payload_json) {
            errors.push(`Non-canonical audit payload at ${row.sequence}`);
          }
          const expected = macJson(this.macKey, "audit-event", {
            aggregateId: row.aggregate_id,
            eventType: row.event_type,
            occurredAt: row.occurred_at,
            payloadJson: row.payload_json,
            previousMac: row.previous_mac,
            sequence: row.sequence,
          });
          if (!secureEqualHex(expected, row.event_mac)) {
            errors.push(`Audit authentication failed at ${row.sequence}`);
          }
        } catch (error) {
          errors.push(
            `Invalid audit row ${row.sequence}: ${error instanceof Error ? error.message : "unknown"}`,
          );
        }
        previous = row.event_mac;
      }
      if (
        metadata !== undefined &&
        (metadata.audit_head_sequence !== auditRows.length ||
          metadata.audit_head_mac !== (auditRows.at(-1)?.event_mac ?? GENESIS_MAC))
      ) {
        errors.push("Operations audit head does not match the audit tail");
      }
    } catch {
      errors.push("Operations audit cannot be read");
    }

    const budgetRows = this.readAndVerifyRows<BudgetRow>(
      "rsi_budgets",
      (row) => this.assertBudgetRow(row),
      errors,
    );
    const attemptRows = this.readAndVerifyRows<AttemptRow>(
      "rsi_attempts",
      (row) => this.assertAttemptRow(row),
      errors,
    );
    const cursorRows = this.readAndVerifyRows<CursorHeadRow>(
      "rsi_cursor_heads",
      (row) => this.assertCursorHeadRow(row),
      errors,
    );
    const advanceRows = this.readAndVerifyRows<CursorAdvanceRow>(
      "rsi_cursor_advances",
      (row) => this.assertCursorAdvanceRow(row),
      errors,
    );
    this.verifyRelationalIntegrity(
      budgetRows,
      attemptRows,
      cursorRows,
      advanceRows,
      auditRows,
      errors,
    );

    return Object.freeze({
      attemptCount: attemptRows.length,
      budgetCount: budgetRows.length,
      cursorAdvanceCount: advanceRows.length,
      cursorCount: cursorRows.length,
      errors: Object.freeze(errors),
      eventCount: auditRows.length,
      headMac: metadata?.audit_head_mac ?? GENESIS_MAC,
      headSequence: metadata?.audit_head_sequence ?? 0,
      valid: errors.length === 0,
    });
  }

  private verifyRelationalIntegrity(
    budgets: readonly BudgetRow[],
    attempts: readonly AttemptRow[],
    cursors: readonly CursorHeadRow[],
    advances: readonly CursorAdvanceRow[],
    auditRows: readonly AuditRow[],
    errors: string[],
  ): void {
    const budgetsById = new Map(budgets.map((row) => [row.budget_id, row]));
    const attemptsById = new Map(attempts.map((row) => [row.attempt_id, row]));
    const cursorsByKey = new Map(cursors.map((row) => [row.cursor_key, row]));

    for (const budget of budgets) {
      try {
        const reservations = attempts.filter((row) => row.budget_id === budget.budget_id);
        const reserved = reservations.reduce(
          (total, row) => total + BigInt(row.reserved_atomic),
          0n,
        );
        if (reservations.length > budget.max_attempts) {
          errors.push(`Budget ${budget.budget_id} exceeds its attempt limit`);
        }
        if (reserved > BigInt(budget.max_atomic)) {
          errors.push(`Budget ${budget.budget_id} exceeds its spend limit`);
        }
      } catch {
        errors.push(`Budget ${budget.budget_id} relationships cannot be verified`);
      }
    }

    for (const attempt of attempts) {
      const budget = budgetsById.get(attempt.budget_id);
      if (budget === undefined) {
        errors.push(`Attempt ${attempt.attempt_id} has no budget`);
        continue;
      }
      const created = Date.parse(attempt.created_at);
      const expires = Date.parse(attempt.authorization_expires_at);
      if (
        created < Date.parse(budget.starts_at) ||
        created < Date.parse(budget.created_at) ||
        created > Date.parse(budget.ends_at) ||
        expires < created ||
        expires - created > MAX_AUTHORIZATION_WINDOW_MS ||
        expires > Date.parse(budget.ends_at)
      ) {
        errors.push(`Attempt ${attempt.attempt_id} has an invalid authorization window`);
      }
      const expectedSourcePlane =
        attempt.operation === "x.recent-search.v1"
          ? "social"
          : attempt.operation === "alchemy.json-rpc.v1"
            ? "canonical_chain"
            : "marketplace";
      if (attempt.source_plane !== expectedSourcePlane) {
        errors.push(`Attempt ${attempt.attempt_id} has an invalid operation source plane`);
      }
      if (
        attempt.dispatched_at !== null &&
        (Date.parse(attempt.dispatched_at) < created ||
          Date.parse(attempt.dispatched_at) > expires ||
          Date.parse(attempt.dispatched_at) > Date.parse(budget.ends_at))
      ) {
        errors.push(`Attempt ${attempt.attempt_id} has an invalid dispatch time`);
      }
      const lowerBound = attempt.dispatched_at ?? attempt.created_at;
      if (attempt.closed_at !== null && compareCanonicalTimes(attempt.closed_at, lowerBound) < 0) {
        errors.push(`Attempt ${attempt.attempt_id} has an invalid close time`);
      }
    }

    const committedBases = new Map<string, number[]>();
    const committedTimes = new Map<string, Map<number, string>>();
    for (const advance of advances) {
      const cursor = cursorsByKey.get(advance.cursor_key);
      const attempt = attemptsById.get(advance.attempt_id);
      const budget = attempt === undefined ? undefined : budgetsById.get(attempt.budget_id);
      if (cursor === undefined) {
        errors.push(`Cursor advance ${advance.advance_id} has no cursor head`);
        continue;
      }
      if (attempt === undefined || budget === undefined) {
        errors.push(`Cursor advance ${advance.advance_id} has no authorized attempt`);
        continue;
      }
      if (
        cursor.profile !== advance.profile ||
        cursor.source_plane !== advance.source_plane ||
        cursor.lane !== advance.lane ||
        cursor.lineage_id !== advance.lineage_id ||
        budget.profile !== advance.profile ||
        attempt.source_plane !== advance.source_plane ||
        attempt.lane !== advance.lane
      ) {
        errors.push(`Cursor advance ${advance.advance_id} crosses an identity boundary`);
      }
      if (
        attempt.state !== "closed" ||
        attempt.outcome !== "succeeded" ||
        attempt.closed_at === null ||
        compareCanonicalTimes(advance.staged_at, attempt.closed_at) < 0
      ) {
        errors.push(`Cursor advance ${advance.advance_id} lacks a successful attempt`);
      }
      if (advance.base_revision > cursor.revision) {
        errors.push(`Cursor advance ${advance.advance_id} is ahead of its cursor head`);
      }
      if (advance.state === "committed") {
        const bases = committedBases.get(advance.cursor_key) ?? [];
        bases.push(advance.base_revision);
        committedBases.set(advance.cursor_key, bases);
        const matchingAudits = auditRows.filter(
          (audit) =>
            audit.aggregate_id === advance.advance_id &&
            audit.event_type === "cursor.advance.committed.v1",
        );
        if (matchingAudits.length !== 1) {
          errors.push(`Cursor advance ${advance.advance_id} has invalid commit audit evidence`);
        } else {
          const times = committedTimes.get(advance.cursor_key) ?? new Map<number, string>();
          times.set(advance.base_revision, matchingAudits[0]!.occurred_at);
          committedTimes.set(advance.cursor_key, times);
        }
      }
    }

    for (const cursor of cursors) {
      const bases = (committedBases.get(cursor.cursor_key) ?? []).sort(
        (left, right) => left - right,
      );
      if (
        bases.length !== cursor.revision ||
        bases.some((baseRevision, index) => baseRevision !== index)
      ) {
        errors.push(`Cursor ${cursor.cursor_key} committed history is incomplete or conflicting`);
      }
      const times = committedTimes.get(cursor.cursor_key) ?? new Map<number, string>();
      let previousTime: string | undefined;
      for (let baseRevision = 0; baseRevision < cursor.revision; baseRevision += 1) {
        const committedAt = times.get(baseRevision);
        if (
          committedAt === undefined ||
          (previousTime !== undefined && compareCanonicalTimes(committedAt, previousTime) < 0)
        ) {
          errors.push(`Cursor ${cursor.cursor_key} commit timestamps are incomplete or regressed`);
          break;
        }
        previousTime = committedAt;
      }
      if (previousTime !== undefined && previousTime !== cursor.updated_at) {
        errors.push(`Cursor ${cursor.cursor_key} head timestamp does not match its last commit`);
      }
      if (cursor.revision > 0) {
        const latestAdvance = advances.find(
          (advance) =>
            advance.cursor_key === cursor.cursor_key &&
            advance.state === "committed" &&
            advance.base_revision === cursor.revision - 1,
        );
        try {
          const value = this.cursorStateFromRow(cursor).value;
          if (
            latestAdvance === undefined ||
            value === null ||
            !secureEqualHex(
              latestAdvance.candidate_binding,
              this.cursorCandidateBinding(
                cursor.cursor_key,
                cursor.lineage_id,
                cursor.revision,
                value,
              ),
            )
          ) {
            errors.push(`Cursor ${cursor.cursor_key} head does not match its latest commit`);
          }
        } catch {
          errors.push(`Cursor ${cursor.cursor_key} head cannot be linked to its latest commit`);
        }
      }
    }
  }

  private readAndVerifyRows<T>(table: string, verify: (row: T) => void, errors: string[]): T[] {
    try {
      const rows = this.database.prepare(`SELECT * FROM ${table}`).all() as unknown as T[];
      for (const row of rows) {
        try {
          verify(row);
        } catch (error) {
          errors.push(
            `${table} integrity failure: ${error instanceof Error ? error.message : "unknown"}`,
          );
        }
      }
      return rows;
    } catch {
      errors.push(`${table} cannot be read`);
      return [];
    }
  }
}

/** Returns true only for a store whose constructor completed successfully. */
export function isSqliteOperationsStore(value: unknown): value is SqliteOperationsStore {
  return (
    typeof value === "object" &&
    value !== null &&
    authenticSqliteOperationsStores.has(value) &&
    Object.getPrototypeOf(value) === SqliteOperationsStore.prototype
  );
}
