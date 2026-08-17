import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  type Stats,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  decryptRegistryValue,
  deriveCaptureRegistryKeys,
  encryptRegistryValue,
  keyedLookupToken,
  mac,
  secureMacEqual,
  type CaptureRegistryKeys,
} from "./crypto.js";
import {
  CaptureRegistryClosedError,
  CaptureRegistryConflictError,
  CaptureRegistryError,
  CaptureRegistryIntegrityError,
  CaptureRegistrySecurityError,
  CaptureRegistryValidationError,
} from "./errors.js";
import {
  BeginCaptureAttemptInputSchema,
  CaptureRegistryAttemptSchema,
  CommitCaptureInputSchema,
  DEFAULT_REGISTRY_OPERATION_LIMIT,
  MAX_CAPTURE_REGISTRY_RECORDS,
  OpenCaptureRegistryOptionsSchema,
  PurgeRemovedCaptureAttemptsInputSchema,
  RecoverPendingCaptureAttemptsInputSchema,
  RecordVerifiedCaptureDeletionInputSchema,
  RemovePendingCaptureAttemptInputSchema,
  StoredCaptureTombstoneSchema,
  UuidSchema,
  parseRegistryInput,
  validateAttemptWindow,
} from "./schemas.js";
import type {
  BeginCaptureAttemptInput,
  CaptureRegistryAttempt,
  CaptureRegistryIntegrityReportV1,
  CaptureRegistryProfile,
  CommitCaptureInput,
  CommittedCaptureReference,
  CommittedCaptureAttempt,
  OpenCaptureRegistryOptions,
  PendingCaptureAttempt,
  PendingCaptureRecoveryResultV1,
  PurgeRemovedCaptureAttemptsInput,
  RecordVerifiedCaptureDeletionInput,
  RecoverPendingCaptureAttemptsInput,
  RemovePendingCaptureAttemptInput,
  RemovedCaptureAttempt,
  RemovedCapturePurgeResultV1,
  SessionRemovalSummaryV1,
  SessionCaptureStateSummaryV1,
} from "./types.js";

const SCHEMA_VERSION = 1;
const DATABASE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const DIRECTORY = constants.O_DIRECTORY ?? 0;
const OPEN_PATHS = new Set<string>();
const authenticSqliteCaptureRegistries = new WeakSet<object>();
const CAPTURE_REGISTRY_CONSTRUCTION_TOKEN = Object.freeze({});
const EFFECTIVE_USER_ID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : null;

interface MetadataRow {
  key_check_mac: string;
  metadata_mac: string;
  next_sequence: number;
  profile: CaptureRegistryProfile;
  record_count: number;
  rows_mac: string;
  schema_version: number;
}

interface RegistryRow {
  attempt_token: string;
  begin_binding: string | null;
  capture_token: string | null;
  ciphertext: Uint8Array;
  commit_binding: string | null;
  deletion_binding: string | null;
  nonce: Uint8Array;
  row_mac: string;
  sequence: number;
  session_token: string;
  state: "committed" | "pending" | "removed";
  tag: Uint8Array;
  wrapped_dek_ciphertext: Uint8Array | null;
  wrapped_dek_nonce: Uint8Array | null;
  wrapped_dek_tag: Uint8Array | null;
}

interface StoredCaptureTombstone {
  readonly keyDestroyed: true;
  readonly removalReason: RemovedCaptureAttempt["removalReason"];
  readonly removedAt: string;
  readonly schemaVersion: 1;
  readonly state: "removed";
}

interface FileIdentity {
  readonly device: bigint;
  readonly inode: bigint;
  readonly owner: bigint;
}

interface OpenedRegistryPath {
  readonly databaseDescriptor: number;
  readonly databaseIdentity: FileIdentity;
  readonly parentDescriptor: number;
  readonly parentIdentity: FileIdentity;
  readonly path: string;
  readonly parentPath: string;
}

function registryAad(
  row: Pick<
    RegistryRow,
    | "attempt_token"
    | "begin_binding"
    | "capture_token"
    | "commit_binding"
    | "deletion_binding"
    | "sequence"
    | "session_token"
    | "state"
  >,
): string {
  return [
    "rsi.capture-registry.record.aad.v1",
    String(row.sequence),
    row.attempt_token,
    row.session_token,
    row.capture_token ?? "-",
    row.state,
    row.begin_binding ?? "-",
    row.commit_binding ?? "-",
    row.deletion_binding ?? "-",
  ].join("\n");
}

function wrappedDekAad(row: Pick<RegistryRow, "attempt_token" | "sequence">): string {
  return ["rsi.capture-registry.wrapped-dek.aad.v1", String(row.sequence), row.attempt_token].join(
    "\n",
  );
}

function rowAuthenticationParts(
  row: Omit<RegistryRow, "row_mac">,
): readonly (number | string | Uint8Array | null)[] {
  return [
    row.sequence,
    row.attempt_token,
    row.session_token,
    row.capture_token,
    row.state,
    row.begin_binding,
    row.commit_binding,
    row.deletion_binding,
    row.nonce,
    row.ciphertext,
    row.tag,
    row.wrapped_dek_nonce,
    row.wrapped_dek_ciphertext,
    row.wrapped_dek_tag,
  ];
}

function exactJson(value: unknown): string {
  return JSON.stringify(value);
}

function assertRecordSemantics(record: CaptureRegistryAttempt): void {
  if (record.state === "removed") return;
  validateAttemptWindow(record.acquiredAt, record.expiresAt);
  if (record.state === "pending") return;
  const committed = Date.parse(record.committedAt);
  if (committed < Date.parse(record.acquiredAt) || committed > Date.parse(record.expiresAt)) {
    throw new CaptureRegistryValidationError(
      "committedAt must be between acquiredAt and expiresAt",
    );
  }
  if (record.sourceIdentifiers.source !== record.source) {
    throw new CaptureRegistryValidationError("source identifiers must match the attempt source");
  }
}

function deepFreezeAttempt<T extends CaptureRegistryAttempt>(record: T): Readonly<T> {
  if (record.state === "committed") {
    if (record.sourceIdentifiers.source === "x") {
      Object.freeze(record.sourceIdentifiers.editIds);
      Object.freeze(record.sourceIdentifiers.postIds);
      Object.freeze(record.sourceIdentifiers.userIds);
    } else {
      for (const identifier of record.sourceIdentifiers.identifiers) Object.freeze(identifier);
      Object.freeze(record.sourceIdentifiers.identifiers);
    }
    Object.freeze(record.sourceIdentifiers);
  }
  return Object.freeze(record);
}

function validateDirectoryStats(stats: Stats): void {
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o777) !== DIRECTORY_MODE ||
    (EFFECTIVE_USER_ID !== null && BigInt(stats.uid) !== EFFECTIVE_USER_ID)
  ) {
    throw new CaptureRegistrySecurityError();
  }
}

function validateFileStats(stats: Stats): void {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (stats.mode & 0o777) !== DATABASE_MODE ||
    (EFFECTIVE_USER_ID !== null && BigInt(stats.uid) !== EFFECTIVE_USER_ID)
  ) {
    throw new CaptureRegistrySecurityError();
  }
}

function identity(stats: Stats): FileIdentity {
  return {
    device: BigInt(stats.dev),
    inode: BigInt(stats.ino),
    owner: BigInt(stats.uid),
  };
}

function sameIdentity(stats: Stats, expected: FileIdentity): boolean {
  return (
    BigInt(stats.dev) === expected.device &&
    BigInt(stats.ino) === expected.inode &&
    BigInt(stats.uid) === expected.owner
  );
}

function openRegistryPath(requestedPath: string): OpenedRegistryPath {
  if (requestedPath.includes("\0")) throw new CaptureRegistryValidationError("path is invalid");
  const requestedAbsolute = resolve(requestedPath);
  const filename = basename(requestedAbsolute);
  if (filename === "." || filename === ".." || filename === "") {
    throw new CaptureRegistryValidationError("path must name a SQLite file");
  }
  const requestedParent = dirname(requestedAbsolute);
  mkdirSync(requestedParent, { mode: DIRECTORY_MODE, recursive: true });
  const parentPath = realpathSync(requestedParent);
  const path = join(parentPath, filename);
  if (OPEN_PATHS.has(path)) throw new CaptureRegistrySecurityError("Capture registry is open");

  let parentDescriptor: number | undefined;
  let databaseDescriptor: number | undefined;
  try {
    const parentStats = lstatSync(parentPath);
    validateDirectoryStats(parentStats);
    parentDescriptor = openSync(parentPath, constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    const openedParent = fstatSync(parentDescriptor);
    validateDirectoryStats(openedParent);
    if (!sameIdentity(parentStats, identity(openedParent)))
      throw new CaptureRegistrySecurityError();

    let fileExists = true;
    try {
      validateFileStats(lstatSync(path));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      fileExists = false;
    }
    if (!fileExists) {
      const created = openSync(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | NOFOLLOW,
        DATABASE_MODE,
      );
      try {
        fchmodSync(created, DATABASE_MODE);
      } finally {
        closeSync(created);
      }
    }
    const beforeOpen = lstatSync(path);
    validateFileStats(beforeOpen);
    databaseDescriptor = openSync(path, constants.O_RDONLY | NOFOLLOW);
    const openedDatabase = fstatSync(databaseDescriptor);
    validateFileStats(openedDatabase);
    const databaseIdentity = identity(openedDatabase);
    if (!sameIdentity(beforeOpen, databaseIdentity)) throw new CaptureRegistrySecurityError();

    OPEN_PATHS.add(path);
    return {
      databaseDescriptor,
      databaseIdentity,
      parentDescriptor,
      parentIdentity: identity(openedParent),
      parentPath,
      path,
    };
  } catch (error) {
    if (databaseDescriptor !== undefined) closeSync(databaseDescriptor);
    if (parentDescriptor !== undefined) closeSync(parentDescriptor);
    if (error instanceof CaptureRegistryError) throw error;
    throw new CaptureRegistrySecurityError();
  }
}

export class SqliteCaptureRegistry {
  readonly path: string;

  private closed = false;
  private readonly database: DatabaseSync;
  private readonly databaseDescriptor: number;
  private readonly databaseIdentity: FileIdentity;
  private readonly encryptionKey: Buffer;
  private readonly expectedProfile: CaptureRegistryProfile;
  private readonly lookupKey: Buffer;
  private readonly macKey: Buffer;
  private readonly parentDescriptor: number;
  private readonly parentIdentity: FileIdentity;
  private readonly parentPath: string;

  private constructor(
    opened: OpenedRegistryPath,
    keys: CaptureRegistryKeys,
    expectedProfile: CaptureRegistryProfile,
    constructionToken: unknown,
  ) {
    if (constructionToken !== CAPTURE_REGISTRY_CONSTRUCTION_TOKEN) {
      throw new CaptureRegistryIntegrityError(
        "Capture registry construction was not authenticated",
      );
    }
    this.path = opened.path;
    this.parentPath = opened.parentPath;
    this.parentDescriptor = opened.parentDescriptor;
    this.parentIdentity = opened.parentIdentity;
    this.databaseDescriptor = opened.databaseDescriptor;
    this.databaseIdentity = opened.databaseIdentity;
    this.encryptionKey = keys.encryptionKey;
    this.expectedProfile = expectedProfile;
    this.lookupKey = keys.lookupKey;
    this.macKey = keys.macKey;
    this.database = new DatabaseSync(opened.path);
  }

  static open(options: OpenCaptureRegistryOptions): SqliteCaptureRegistry {
    const parsed = parseRegistryInput(
      OpenCaptureRegistryOptionsSchema,
      options,
      "capture registry options",
    );
    const keys = deriveCaptureRegistryKeys(parsed.registryKey, parsed.expectedProfile);
    let opened: OpenedRegistryPath | undefined;
    let registry: SqliteCaptureRegistry | undefined;
    try {
      opened = openRegistryPath(parsed.path);
      registry = new SqliteCaptureRegistry(
        opened,
        keys,
        parsed.expectedProfile,
        CAPTURE_REGISTRY_CONSTRUCTION_TOKEN,
      );
      authenticSqliteCaptureRegistries.add(registry);
      registry.configureDatabase();
      registry.initializeSchema();
      registry.assertFilesystemSafe();
      registry.verifyIntegrityInternal();
      // A crash after a tombstone commit but before its VACUUM is healed before
      // the registry is returned to callers. Repeating VACUUM is safe.
      if (registry.tombstoneCount() > 0) registry.hardenErasure();
      authenticSqliteCaptureRegistries.add(registry);
      return registry;
    } catch (error) {
      if (registry !== undefined) {
        registry.closeAfterFailedOpen();
      } else {
        keys.encryptionKey.fill(0);
        keys.lookupKey.fill(0);
        keys.macKey.fill(0);
        if (opened !== undefined) {
          closeSync(opened.databaseDescriptor);
          closeSync(opened.parentDescriptor);
          OPEN_PATHS.delete(opened.path);
        }
      }
      if (error instanceof CaptureRegistryError) throw error;
      throw new CaptureRegistryIntegrityError();
    }
  }

  beginAttempt(input: BeginCaptureAttemptInput): Readonly<CaptureRegistryAttempt> {
    const parsed = parseRegistryInput(BeginCaptureAttemptInputSchema, input, "capture attempt");
    if (parsed.profile !== this.expectedProfile) {
      throw new CaptureRegistryConflictError(
        "ATTEMPT_CONFLICT",
        "The capture attempt profile does not match the registry profile",
      );
    }
    validateAttemptWindow(parsed.acquiredAt, parsed.expiresAt);
    const pending = this.prepareAttempt({
      ...parsed,
      requestFingerprint: parsed.requestFingerprint as `sha256:${string}`,
      schemaVersion: 1,
      state: "pending",
    });

    return this.writeTransaction(() => {
      const attemptToken = this.attemptToken(parsed.attemptId);
      const existingRow = this.getRow(attemptToken);
      if (existingRow !== undefined) {
        if (existingRow.state === "removed") {
          return this.decodeTombstone(existingRow, parsed.attemptId);
        }
        if (
          existingRow.begin_binding === null ||
          !secureMacEqual(existingRow.begin_binding, this.beginBinding(parsed))
        ) {
          throw new CaptureRegistryConflictError(
            "ATTEMPT_CONFLICT",
            "The attempt identity is already bound to different context",
          );
        }
        return this.decodeSensitiveRow(existingRow);
      }
      const metadata = this.metadata();
      if (metadata.record_count >= MAX_CAPTURE_REGISTRY_RECORDS) {
        throw new CaptureRegistryConflictError(
          "REGISTRY_FULL",
          "The capture registry record limit is exhausted",
        );
      }
      this.insertRecord(pending, metadata.next_sequence);
      this.refreshMetadata(metadata.next_sequence + 1);
      return pending;
    });
  }

  commitCapture(input: CommitCaptureInput): Readonly<CaptureRegistryAttempt> {
    const parsed = parseRegistryInput(CommitCaptureInputSchema, input, "capture commit");
    return this.writeTransaction(() => {
      const attemptToken = this.attemptToken(parsed.attemptId);
      const row = this.getRow(attemptToken);
      if (row === undefined) {
        throw new CaptureRegistryConflictError(
          "ATTEMPT_NOT_PENDING",
          "The capture attempt is not pending",
        );
      }
      if (row.state === "removed") {
        throw new CaptureRegistryConflictError(
          "ATTEMPT_NOT_PENDING",
          "The capture attempt has already been removed",
        );
      }
      const existing = this.decodeSensitiveRow(row);
      const committed = this.prepareAttempt({
        acquiredAt: existing.acquiredAt,
        attemptId: existing.attemptId,
        captureId: parsed.captureId,
        committedAt: parsed.committedAt,
        expiresAt: existing.expiresAt,
        lane: existing.lane,
        profile: existing.profile,
        requestFingerprint: existing.requestFingerprint,
        schemaVersion: 1,
        sessionId: existing.sessionId,
        source: existing.source,
        sourceIdentifiers: parsed.sourceIdentifiers,
        state: "committed",
      });
      assertRecordSemantics(committed);

      if (existing.state === "committed") {
        const sameCommit =
          existing.captureId === committed.captureId &&
          existing.committedAt === committed.committedAt &&
          exactJson(existing.sourceIdentifiers) === exactJson(committed.sourceIdentifiers);
        if (!sameCommit) {
          throw new CaptureRegistryConflictError(
            "CAPTURE_CONFLICT",
            "The attempt is already bound to a different capture",
          );
        }
        return existing;
      }

      const captureToken = this.captureToken(parsed.captureId);
      const captureOwner = this.database
        .prepare("SELECT attempt_token FROM rsi_capture_registry_records WHERE capture_token = ?")
        .get(captureToken) as { attempt_token: string } | undefined;
      if (captureOwner !== undefined && captureOwner.attempt_token !== attemptToken) {
        throw new CaptureRegistryConflictError(
          "CAPTURE_CONFLICT",
          "The capture is already bound to another attempt",
        );
      }
      const dek = this.unwrapDek(row);
      try {
        this.updateSensitiveRecord(row, committed, dek);
      } finally {
        dek.fill(0);
      }
      this.refreshMetadata();
      return committed;
    });
  }

  getAttempt(attemptId: string): Readonly<CaptureRegistryAttempt> | undefined {
    const parsed = parseRegistryInput(UuidSchema, attemptId, "attemptId");
    return this.readTransaction(() => {
      const row = this.getRow(this.attemptToken(parsed));
      if (row === undefined) return undefined;
      return row.state === "removed"
        ? this.decodeTombstone(row, parsed)
        : this.decodeSensitiveRow(row);
    });
  }

  listCommittedCaptureIds(): readonly string[] {
    return this.readTransaction(() => this.listCaptureIds());
  }

  /** Private lifecycle integration only; results are never safe for logs or projections. */
  listCommittedCaptures(): readonly Readonly<CommittedCaptureReference>[] {
    return this.readTransaction(() => this.listCaptureReferences());
  }

  listSessionCaptureIds(sessionId: string): readonly string[] {
    const parsed = parseRegistryInput(UuidSchema, sessionId, "sessionId");
    return this.readTransaction(() => this.listCaptureIds(this.sessionToken(parsed)));
  }

  /** Private lifecycle integration only; results are never safe for logs or projections. */
  listSessionCommittedCaptures(sessionId: string): readonly Readonly<CommittedCaptureReference>[] {
    const parsed = parseRegistryInput(UuidSchema, sessionId, "sessionId");
    return this.readTransaction(() => this.listCaptureReferences(this.sessionToken(parsed)));
  }

  /** Aggregate-only restart receipt: never includes an attempt, capture, or source identifier. */
  getSessionRemovalSummary(sessionId: string): Readonly<SessionRemovalSummaryV1> {
    const parsed = parseRegistryInput(UuidSchema, sessionId, "sessionId");
    return this.readTransaction(() => {
      const rows = this.database
        .prepare(
          `SELECT * FROM rsi_capture_registry_records
            WHERE state = 'removed' AND session_token = ?
            ORDER BY sequence`,
        )
        .all(this.sessionToken(parsed)) as unknown as RegistryRow[];
      const counts = {
        captureDeletedExpired: 0,
        captureDeletedExplicit: 0,
        pendingExplicit: 0,
        pendingRecovery: 0,
      };
      for (const row of rows) {
        const tombstone = this.decodeStoredTombstone(row);
        switch (tombstone.removalReason) {
          case "capture_deleted_expired":
            counts.captureDeletedExpired += 1;
            break;
          case "capture_deleted_explicit":
            counts.captureDeletedExplicit += 1;
            break;
          case "pending_explicit":
            counts.pendingExplicit += 1;
            break;
          case "pending_recovery":
            counts.pendingRecovery += 1;
            break;
        }
      }
      return Object.freeze({
        counts: Object.freeze(counts),
        schemaVersion: 1 as const,
        total: rows.length,
      });
    });
  }

  /** Aggregate-only state used to prove that no active capture remains for a session. */
  getSessionStateSummary(sessionId: string): Readonly<SessionCaptureStateSummaryV1> {
    const parsed = parseRegistryInput(UuidSchema, sessionId, "sessionId");
    return this.readTransaction(() => {
      const rows = this.database
        .prepare(
          `SELECT state, COUNT(*) AS count FROM rsi_capture_registry_records
            WHERE session_token = ? GROUP BY state ORDER BY state`,
        )
        .all(this.sessionToken(parsed)) as unknown as Array<{
        readonly count: number;
        readonly state: "committed" | "pending" | "removed";
      }>;
      const counts = { committed: 0, pending: 0, removed: 0 };
      for (const row of rows) counts[row.state] = row.count;
      return Object.freeze({
        committed: counts.committed,
        pending: counts.pending,
        profile: this.expectedProfile,
        removed: counts.removed,
        schemaVersion: 1 as const,
        sessionId: parsed,
        total: counts.committed + counts.pending + counts.removed,
      });
    });
  }

  recordVerifiedDeletion(
    input: RecordVerifiedCaptureDeletionInput,
  ): Readonly<RemovedCaptureAttempt> {
    const parsed = parseRegistryInput(
      RecordVerifiedCaptureDeletionInputSchema,
      input,
      "verified capture deletion",
    );
    const removed = this.writeTransaction(() => {
      const row = this.getRow(this.attemptToken(parsed.attemptId));
      if (row === undefined) {
        throw new CaptureRegistryConflictError(
          "ATTEMPT_NOT_COMMITTED",
          "The capture attempt is not committed",
        );
      }
      if (row.state === "removed") {
        if (
          row.deletion_binding === null ||
          !secureMacEqual(row.deletion_binding, this.deletionBinding(parsed.deletionReceipt))
        ) {
          throw new CaptureRegistryConflictError(
            "DELETION_CONFLICT",
            "The capture already has a different deletion receipt",
          );
        }
        return this.decodeTombstone(row, parsed.attemptId);
      }
      const existing = this.decodeSensitiveRow(row);
      if (existing.state !== "committed") {
        throw new CaptureRegistryConflictError(
          "ATTEMPT_NOT_COMMITTED",
          "The capture attempt is not committed",
        );
      }
      if (existing.captureId !== parsed.deletionReceipt.captureId) {
        throw new CaptureRegistryConflictError(
          "DELETION_CONFLICT",
          "The deletion receipt does not match the committed capture",
        );
      }
      if (Date.parse(parsed.deletionReceipt.deletedAt) < Date.parse(existing.committedAt)) {
        throw new CaptureRegistryValidationError("deletedAt must not precede committedAt");
      }
      const tombstone = this.prepareTombstone({
        keyDestroyed: true,
        removalReason: `capture_deleted_${parsed.deletionReceipt.reason}`,
        removedAt: parsed.deletionReceipt.deletedAt,
        schemaVersion: 1,
        state: "removed",
      });
      this.updateTombstone(row, tombstone, this.deletionBinding(parsed.deletionReceipt));
      this.refreshMetadata();
      return this.publicTombstone(tombstone, parsed.attemptId);
    });
    this.hardenErasure();
    return removed;
  }

  removePendingAttempt(input: RemovePendingCaptureAttemptInput): boolean {
    const parsed = parseRegistryInput(
      RemovePendingCaptureAttemptInputSchema,
      input,
      "pending capture removal",
    );
    const result = this.writeTransaction(() => {
      const row = this.getRow(this.attemptToken(parsed.attemptId));
      if (row === undefined) return false;
      if (row.state === "removed") {
        const tombstone = this.decodeStoredTombstone(row);
        if (
          tombstone.removalReason === "pending_explicit" &&
          tombstone.removedAt === parsed.removedAt
        ) {
          return true;
        }
        throw new CaptureRegistryConflictError(
          "ATTEMPT_NOT_PENDING",
          "The attempt already has a different terminal state",
        );
      }
      const record = this.decodeSensitiveRow(row);
      if (record.state !== "pending") {
        throw new CaptureRegistryConflictError(
          "ATTEMPT_NOT_PENDING",
          "Only pending attempts can be removed without a Vault deletion receipt",
        );
      }
      if (Date.parse(parsed.removedAt) < Date.parse(record.acquiredAt)) {
        throw new CaptureRegistryValidationError("removedAt must not precede acquiredAt");
      }
      this.updateTombstone(
        row,
        this.prepareTombstone({
          keyDestroyed: true,
          removalReason: "pending_explicit",
          removedAt: parsed.removedAt,
          schemaVersion: 1,
          state: "removed",
        }),
        null,
      );
      this.refreshMetadata();
      return true;
    });
    if (result) this.hardenErasure();
    return result;
  }

  recoverPendingAttempts(
    input: RecoverPendingCaptureAttemptsInput,
  ): Readonly<PendingCaptureRecoveryResultV1> {
    const parsed = parseRegistryInput(
      RecoverPendingCaptureAttemptsInputSchema,
      input,
      "pending capture recovery",
    );
    const limit = parsed.limit ?? DEFAULT_REGISTRY_OPERATION_LIMIT;
    const result = this.writeTransaction(() => {
      const rows = this.database
        .prepare(
          "SELECT * FROM rsi_capture_registry_records WHERE state = 'pending' ORDER BY sequence",
        )
        .all() as unknown as RegistryRow[];
      // Authenticate, decrypt, and time-check the complete pending set before
      // mutating a bounded prefix. Otherwise a backward recoveredAt could
      // tombstone an early batch and only fail on a later, newer attempt.
      const attempts = rows.map((row) => this.decodeSensitiveRow(row));
      if (
        attempts.some((attempt) => Date.parse(parsed.recoveredAt) < Date.parse(attempt.acquiredAt))
      ) {
        throw new CaptureRegistryValidationError(
          "recoveredAt must not precede a pending attempt's acquiredAt",
        );
      }
      const selected = rows.slice(0, limit);
      for (const [index, row] of selected.entries()) {
        const attempt = attempts[index]!;
        this.updateTombstone(
          row,
          this.prepareTombstone({
            keyDestroyed: true,
            removalReason: "pending_recovery",
            removedAt: parsed.recoveredAt,
            schemaVersion: 1,
            state: "removed",
          }),
          null,
        );
        if (attempt.state !== "pending") throw new CaptureRegistryIntegrityError();
      }
      if (selected.length > 0) this.refreshMetadata();
      const result: PendingCaptureRecoveryResultV1 = {
        recoveredAt: parsed.recoveredAt,
        removed: selected.length,
        schemaVersion: 1,
        truncated: rows.length > limit,
      };
      return Object.freeze(result);
    });
    if (result.removed > 0) this.hardenErasure();
    return result;
  }

  purgeRemoved(input: PurgeRemovedCaptureAttemptsInput): Readonly<RemovedCapturePurgeResultV1> {
    const parsed = parseRegistryInput(
      PurgeRemovedCaptureAttemptsInputSchema,
      input,
      "removed capture purge",
    );
    const limit = parsed.limit ?? DEFAULT_REGISTRY_OPERATION_LIMIT;
    const result = this.writeTransaction(() => {
      const rows = this.database
        .prepare(
          "SELECT * FROM rsi_capture_registry_records WHERE state = 'removed' ORDER BY sequence",
        )
        .all() as unknown as RegistryRow[];
      const eligible = rows.filter((row) => {
        const record = this.decodeStoredTombstone(row);
        return Date.parse(record.removedAt) <= Date.parse(parsed.before);
      });
      const selected = eligible.slice(0, limit);
      this.deleteSequences(selected.map((row) => row.sequence));
      if (selected.length > 0) this.refreshMetadata();
      return Object.freeze({
        before: parsed.before,
        purged: selected.length,
        schemaVersion: 1 as const,
        truncated: eligible.length > limit,
      });
    });
    if (result.purged > 0) this.hardenErasure();
    return result;
  }

  verifyIntegrity(): Readonly<CaptureRegistryIntegrityReportV1> {
    return this.readTransaction(() => {
      const metadata = this.metadata();
      const tombstones = this.database
        .prepare(
          "SELECT COUNT(*) AS count FROM rsi_capture_registry_records WHERE state = 'removed'",
        )
        .get() as { count: number };
      return Object.freeze({
        keyDestroyedTombstones: tombstones.count,
        nextSequence: metadata.next_sequence,
        recordCount: metadata.record_count,
        schemaVersion: 1 as const,
        valid: true as const,
      });
    });
  }

  close(): void {
    this.assertAuthentic();
    if (this.closed) return;
    this.closed = true;
    try {
      this.database.close();
    } finally {
      closeSync(this.databaseDescriptor);
      closeSync(this.parentDescriptor);
      this.encryptionKey.fill(0);
      this.lookupKey.fill(0);
      this.macKey.fill(0);
      OPEN_PATHS.delete(this.path);
    }
  }

  [Symbol.dispose](): void {
    this.close();
  }

  private closeAfterFailedOpen(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.database.close();
    } catch {
      // The caller receives only the initialization failure.
    }
    closeSync(this.databaseDescriptor);
    closeSync(this.parentDescriptor);
    this.encryptionKey.fill(0);
    this.lookupKey.fill(0);
    this.macKey.fill(0);
    authenticSqliteCaptureRegistries.delete(this);
    OPEN_PATHS.delete(this.path);
  }

  private configureDatabase(): void {
    this.database.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = DELETE;
      PRAGMA secure_delete = ON;
      PRAGMA synchronous = FULL;
      PRAGMA temp_store = MEMORY;
      PRAGMA trusted_schema = OFF;
    `);
  }

  private initializeSchema(): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.exec(`
        CREATE TABLE IF NOT EXISTS rsi_capture_registry_metadata (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          schema_version INTEGER NOT NULL,
          profile TEXT NOT NULL CHECK(profile IN ('dev', 'canary', 'production-observer')),
          record_count INTEGER NOT NULL CHECK(record_count >= 0 AND record_count <= 1000),
          next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1),
          rows_mac TEXT NOT NULL CHECK(length(rows_mac) = 64),
          key_check_mac TEXT NOT NULL CHECK(length(key_check_mac) = 64),
          metadata_mac TEXT NOT NULL CHECK(length(metadata_mac) = 64)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS rsi_capture_registry_records (
          sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
          attempt_token TEXT NOT NULL UNIQUE CHECK(length(attempt_token) = 64),
          session_token TEXT NOT NULL CHECK(length(session_token) = 64),
          capture_token TEXT UNIQUE CHECK(capture_token IS NULL OR length(capture_token) = 64),
          begin_binding TEXT CHECK(begin_binding IS NULL OR length(begin_binding) = 64),
          commit_binding TEXT CHECK(commit_binding IS NULL OR length(commit_binding) = 64),
          deletion_binding TEXT CHECK(deletion_binding IS NULL OR length(deletion_binding) = 64),
          state TEXT NOT NULL CHECK(state IN ('pending', 'committed', 'removed')),
          nonce BLOB NOT NULL CHECK(length(nonce) = 12),
          ciphertext BLOB NOT NULL,
          tag BLOB NOT NULL CHECK(length(tag) = 16),
          wrapped_dek_nonce BLOB CHECK(wrapped_dek_nonce IS NULL OR length(wrapped_dek_nonce) = 12),
          wrapped_dek_ciphertext BLOB CHECK(wrapped_dek_ciphertext IS NULL OR length(wrapped_dek_ciphertext) = 32),
          wrapped_dek_tag BLOB CHECK(wrapped_dek_tag IS NULL OR length(wrapped_dek_tag) = 16),
          row_mac TEXT NOT NULL CHECK(length(row_mac) = 64)
        ) STRICT;

        CREATE INDEX IF NOT EXISTS rsi_capture_registry_by_session
          ON rsi_capture_registry_records(session_token, state, sequence);
      `);
      const keyCheck = this.keyCheckMac();
      const rowsMac = this.rowsMac([]);
      const metadataMac = this.metadataMac({
        key_check_mac: keyCheck,
        next_sequence: 1,
        profile: this.expectedProfile,
        record_count: 0,
        rows_mac: rowsMac,
        schema_version: SCHEMA_VERSION,
      });
      this.database
        .prepare(
          `INSERT INTO rsi_capture_registry_metadata (
             singleton, schema_version, profile, record_count, next_sequence,
             rows_mac, key_check_mac, metadata_mac
           ) SELECT 1, ?, ?, 0, 1, ?, ?, ?
             WHERE NOT EXISTS (SELECT 1 FROM rsi_capture_registry_metadata)
               AND NOT EXISTS (SELECT 1 FROM rsi_capture_registry_records)`,
        )
        .run(SCHEMA_VERSION, this.expectedProfile, rowsMac, keyCheck, metadataMac);
      this.database.exec("COMMIT");
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      if (error instanceof CaptureRegistryError) throw error;
      throw new CaptureRegistryIntegrityError();
    }
  }

  private assertOpen(): void {
    this.assertAuthentic();
    if (this.closed) throw new CaptureRegistryClosedError();
  }

  private assertAuthentic(): void {
    if (
      Object.getPrototypeOf(this) !== SqliteCaptureRegistry.prototype ||
      !authenticSqliteCaptureRegistries.has(this)
    ) {
      throw new CaptureRegistryIntegrityError(
        "Capture registry was not opened through its authenticated factory",
      );
    }
  }

  private assertFilesystemSafe(): void {
    this.assertOpen();
    try {
      const parentPathStats = lstatSync(this.parentPath);
      const parentDescriptorStats = fstatSync(this.parentDescriptor);
      validateDirectoryStats(parentPathStats);
      validateDirectoryStats(parentDescriptorStats);
      if (
        !sameIdentity(parentPathStats, this.parentIdentity) ||
        !sameIdentity(parentDescriptorStats, this.parentIdentity)
      ) {
        throw new CaptureRegistrySecurityError();
      }

      const pathStats = lstatSync(this.path);
      const descriptorStats = fstatSync(this.databaseDescriptor);
      validateFileStats(pathStats);
      validateFileStats(descriptorStats);
      if (
        !sameIdentity(pathStats, this.databaseIdentity) ||
        !sameIdentity(descriptorStats, this.databaseIdentity)
      ) {
        throw new CaptureRegistrySecurityError();
      }
    } catch (error) {
      if (error instanceof CaptureRegistrySecurityError) throw error;
      throw new CaptureRegistrySecurityError();
    }
  }

  private readTransaction<T>(operation: () => T): T {
    this.assertFilesystemSafe();
    this.database.exec("BEGIN");
    try {
      this.verifyIntegrityInternal();
      const result = operation();
      this.database.exec("COMMIT");
      this.assertFilesystemSafe();
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private writeTransaction<T>(operation: () => T): T {
    this.assertFilesystemSafe();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.verifyIntegrityInternal();
      const result = operation();
      this.verifyIntegrityInternal();
      this.database.exec("COMMIT");
      this.assertFilesystemSafe();
      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private verifyIntegrityInternal(): void {
    try {
      this.verifySchema();
      const metadata = this.metadata();
      if (
        metadata.schema_version !== SCHEMA_VERSION ||
        metadata.profile !== this.expectedProfile ||
        metadata.record_count < 0 ||
        metadata.record_count > MAX_CAPTURE_REGISTRY_RECORDS ||
        metadata.next_sequence < 1 ||
        !secureMacEqual(metadata.key_check_mac, this.keyCheckMac())
      ) {
        throw new CaptureRegistryIntegrityError();
      }
      const expectedMetadataMac = this.metadataMac(metadata);
      if (!secureMacEqual(metadata.metadata_mac, expectedMetadataMac)) {
        throw new CaptureRegistryIntegrityError();
      }
      const rows = this.allRows();
      if (rows.length !== metadata.record_count) throw new CaptureRegistryIntegrityError();
      let maximumSequence = 0;
      const rowMacs: string[] = [];
      for (const row of rows) {
        this.assertRow(row);
        maximumSequence = Math.max(maximumSequence, row.sequence);
        rowMacs.push(row.row_mac);
        if (row.state === "removed") this.decodeStoredTombstone(row);
        else this.decodeSensitiveRow(row);
      }
      if (metadata.next_sequence <= maximumSequence) throw new CaptureRegistryIntegrityError();
      if (!secureMacEqual(metadata.rows_mac, this.rowsMac(rowMacs))) {
        throw new CaptureRegistryIntegrityError();
      }
    } catch (error) {
      if (error instanceof CaptureRegistryIntegrityError) throw error;
      throw new CaptureRegistryIntegrityError();
    }
  }

  private verifySchema(): void {
    const objects = this.database
      .prepare(
        `SELECT type, name FROM sqlite_schema
          WHERE name NOT LIKE 'sqlite_%'
          ORDER BY type, name`,
      )
      .all() as unknown as Array<{ name: string; type: string }>;
    const actual = objects.map((object) => `${object.type}:${object.name}`);
    const expected = [
      "index:rsi_capture_registry_by_session",
      "table:rsi_capture_registry_metadata",
      "table:rsi_capture_registry_records",
    ];
    if (exactJson(actual) !== exactJson(expected)) throw new CaptureRegistryIntegrityError();
    this.assertTableColumns("rsi_capture_registry_metadata", [
      "singleton:INTEGER:0:1",
      "schema_version:INTEGER:1:0",
      "profile:TEXT:1:0",
      "record_count:INTEGER:1:0",
      "next_sequence:INTEGER:1:0",
      "rows_mac:TEXT:1:0",
      "key_check_mac:TEXT:1:0",
      "metadata_mac:TEXT:1:0",
    ]);
    this.assertTableColumns("rsi_capture_registry_records", [
      "sequence:INTEGER:0:1",
      "attempt_token:TEXT:1:0",
      "session_token:TEXT:1:0",
      "capture_token:TEXT:0:0",
      "begin_binding:TEXT:0:0",
      "commit_binding:TEXT:0:0",
      "deletion_binding:TEXT:0:0",
      "state:TEXT:1:0",
      "nonce:BLOB:1:0",
      "ciphertext:BLOB:1:0",
      "tag:BLOB:1:0",
      "wrapped_dek_nonce:BLOB:0:0",
      "wrapped_dek_ciphertext:BLOB:0:0",
      "wrapped_dek_tag:BLOB:0:0",
      "row_mac:TEXT:1:0",
    ]);
  }

  private assertTableColumns(table: string, expected: readonly string[]): void {
    const columns = this.database
      .prepare(`PRAGMA table_xinfo(${table})`)
      .all() as unknown as Array<{
      hidden: number;
      name: string;
      notnull: number;
      pk: number;
      type: string;
    }>;
    const actual = columns.map(
      (column) =>
        `${column.name}:${column.type}:${column.notnull}:${column.pk}${column.hidden === 0 ? "" : `:${column.hidden}`}`,
    );
    if (exactJson(actual) !== exactJson(expected)) throw new CaptureRegistryIntegrityError();
  }

  private metadata(): MetadataRow {
    const rows = this.database
      .prepare(
        `SELECT schema_version, profile, record_count, next_sequence,
                rows_mac, key_check_mac, metadata_mac
           FROM rsi_capture_registry_metadata WHERE singleton = 1`,
      )
      .all() as unknown as MetadataRow[];
    if (rows.length !== 1) throw new CaptureRegistryIntegrityError();
    return rows[0]!;
  }

  private allRows(): RegistryRow[] {
    return this.database
      .prepare("SELECT * FROM rsi_capture_registry_records ORDER BY sequence")
      .all() as unknown as RegistryRow[];
  }

  private getRow(attemptToken: string): RegistryRow | undefined {
    return this.database
      .prepare("SELECT * FROM rsi_capture_registry_records WHERE attempt_token = ?")
      .get(attemptToken) as RegistryRow | undefined;
  }

  private prepareAttempt<T extends CaptureRegistryAttempt>(value: T): Readonly<T> {
    const parsed = parseRegistryInput(
      CaptureRegistryAttemptSchema,
      value,
      "capture registry record",
    );
    const typed = parsed as CaptureRegistryAttempt;
    assertRecordSemantics(typed);
    return deepFreezeAttempt(typed as T);
  }

  private prepareTombstone(value: unknown): Readonly<StoredCaptureTombstone> {
    return Object.freeze(
      parseRegistryInput(StoredCaptureTombstoneSchema, value, "capture registry tombstone"),
    );
  }

  private publicTombstone(
    tombstone: StoredCaptureTombstone,
    attemptId: string,
  ): Readonly<RemovedCaptureAttempt> {
    const parsed = parseRegistryInput(
      CaptureRegistryAttemptSchema,
      { attemptId, ...tombstone },
      "capture registry tombstone",
    ) as CaptureRegistryAttempt;
    return deepFreezeAttempt(parsed) as Readonly<RemovedCaptureAttempt>;
  }

  private encodeAttempt(record: Exclude<CaptureRegistryAttempt, RemovedCaptureAttempt>): Buffer {
    return Buffer.from(exactJson(this.prepareAttempt(record)), "utf8");
  }

  private decodeSensitiveRow(
    row: RegistryRow,
  ): Readonly<PendingCaptureAttempt | CommittedCaptureAttempt> {
    this.assertRow(row);
    if (row.state === "removed") throw new CaptureRegistryIntegrityError();
    const dek = this.unwrapDek(row);
    let plaintext: Buffer | undefined;
    try {
      plaintext = decryptRegistryValue(dek, registryAad(row), {
        ciphertext: row.ciphertext,
        nonce: row.nonce,
        tag: row.tag,
      });
      const decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plaintext);
      const parsed = this.prepareAttempt(JSON.parse(decoded) as CaptureRegistryAttempt);
      if (parsed.state === "removed") throw new CaptureRegistryIntegrityError();
      if (exactJson(parsed) !== decoded) throw new CaptureRegistryIntegrityError();
      if (
        this.attemptToken(parsed.attemptId) !== row.attempt_token ||
        this.sessionToken(parsed.sessionId) !== row.session_token ||
        parsed.state !== row.state ||
        row.begin_binding === null ||
        !secureMacEqual(row.begin_binding, this.beginBinding(parsed))
      ) {
        throw new CaptureRegistryIntegrityError();
      }
      const expectedCaptureToken =
        parsed.state === "pending" ? null : this.captureToken(parsed.captureId);
      if (expectedCaptureToken !== row.capture_token) throw new CaptureRegistryIntegrityError();
      const expectedCommitBinding =
        parsed.state === "pending"
          ? null
          : this.commitBinding({
              attemptId: parsed.attemptId,
              captureId: parsed.captureId,
              committedAt: parsed.committedAt,
              sourceIdentifiers: parsed.sourceIdentifiers,
            });
      if (expectedCommitBinding !== row.commit_binding || row.deletion_binding !== null) {
        throw new CaptureRegistryIntegrityError();
      }
      return parsed;
    } catch (error) {
      if (error instanceof CaptureRegistryIntegrityError) throw error;
      throw new CaptureRegistryIntegrityError();
    } finally {
      plaintext?.fill(0);
      dek.fill(0);
    }
  }

  private decodeStoredTombstone(row: RegistryRow): Readonly<StoredCaptureTombstone> {
    this.assertRow(row);
    if (row.state !== "removed") throw new CaptureRegistryIntegrityError();
    const plaintext = decryptRegistryValue(this.encryptionKey, registryAad(row), {
      ciphertext: row.ciphertext,
      nonce: row.nonce,
      tag: row.tag,
    });
    try {
      const decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plaintext);
      const tombstone = this.prepareTombstone(JSON.parse(decoded) as unknown);
      if (exactJson(tombstone) !== decoded) throw new CaptureRegistryIntegrityError();
      if (
        row.begin_binding !== null ||
        row.commit_binding !== null ||
        tombstone.removalReason.startsWith("capture_deleted_") !==
          (row.deletion_binding !== null) ||
        (tombstone.removalReason.startsWith("pending_") && row.deletion_binding !== null)
      ) {
        throw new CaptureRegistryIntegrityError();
      }
      return tombstone;
    } catch (error) {
      if (error instanceof CaptureRegistryIntegrityError) throw error;
      throw new CaptureRegistryIntegrityError();
    } finally {
      plaintext.fill(0);
    }
  }

  private decodeTombstone(row: RegistryRow, attemptId: string): Readonly<RemovedCaptureAttempt> {
    return this.publicTombstone(this.decodeStoredTombstone(row), attemptId);
  }

  private unwrapDek(row: RegistryRow): Buffer {
    if (
      row.state === "removed" ||
      row.wrapped_dek_nonce === null ||
      row.wrapped_dek_ciphertext === null ||
      row.wrapped_dek_tag === null
    ) {
      throw new CaptureRegistryIntegrityError();
    }
    const dek = decryptRegistryValue(this.encryptionKey, wrappedDekAad(row), {
      ciphertext: row.wrapped_dek_ciphertext,
      nonce: row.wrapped_dek_nonce,
      tag: row.wrapped_dek_tag,
    });
    if (dek.byteLength !== 32) {
      dek.fill(0);
      throw new CaptureRegistryIntegrityError();
    }
    return dek;
  }

  private assertRow(row: RegistryRow): void {
    if (
      !Number.isSafeInteger(row.sequence) ||
      row.sequence < 1 ||
      !/^[0-9a-f]{64}$/.test(row.attempt_token) ||
      !/^[0-9a-f]{64}$/.test(row.session_token) ||
      (row.capture_token !== null && !/^[0-9a-f]{64}$/.test(row.capture_token)) ||
      (row.begin_binding !== null && !/^[0-9a-f]{64}$/.test(row.begin_binding)) ||
      (row.commit_binding !== null && !/^[0-9a-f]{64}$/.test(row.commit_binding)) ||
      (row.deletion_binding !== null && !/^[0-9a-f]{64}$/.test(row.deletion_binding)) ||
      !["committed", "pending", "removed"].includes(row.state) ||
      !(row.nonce instanceof Uint8Array) ||
      row.nonce.byteLength !== 12 ||
      !(row.ciphertext instanceof Uint8Array) ||
      !(row.tag instanceof Uint8Array) ||
      row.tag.byteLength !== 16 ||
      (row.state === "removed"
        ? row.capture_token !== null ||
          row.wrapped_dek_nonce !== null ||
          row.wrapped_dek_ciphertext !== null ||
          row.wrapped_dek_tag !== null
        : !(row.wrapped_dek_nonce instanceof Uint8Array) ||
          row.wrapped_dek_nonce.byteLength !== 12 ||
          !(row.wrapped_dek_ciphertext instanceof Uint8Array) ||
          row.wrapped_dek_ciphertext.byteLength !== 32 ||
          !(row.wrapped_dek_tag instanceof Uint8Array) ||
          row.wrapped_dek_tag.byteLength !== 16)
    ) {
      throw new CaptureRegistryIntegrityError();
    }
    const expected = mac(this.macKey, "row", rowAuthenticationParts(row));
    if (!secureMacEqual(row.row_mac, expected)) throw new CaptureRegistryIntegrityError();
  }

  private insertRecord(record: CaptureRegistryAttempt, sequence: number): void {
    if (record.state === "removed") throw new CaptureRegistryIntegrityError();
    const dek = randomBytes(32);
    let row: RegistryRow;
    try {
      row = this.encryptSensitiveRecord(record, sequence, dek);
    } finally {
      dek.fill(0);
    }
    this.database
      .prepare(
        `INSERT INTO rsi_capture_registry_records (
           sequence, attempt_token, session_token, capture_token,
           begin_binding, commit_binding, deletion_binding, state,
           nonce, ciphertext, tag,
           wrapped_dek_nonce, wrapped_dek_ciphertext, wrapped_dek_tag, row_mac
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.sequence,
        row.attempt_token,
        row.session_token,
        row.capture_token,
        row.begin_binding,
        row.commit_binding,
        row.deletion_binding,
        row.state,
        row.nonce,
        row.ciphertext,
        row.tag,
        row.wrapped_dek_nonce,
        row.wrapped_dek_ciphertext,
        row.wrapped_dek_tag,
        row.row_mac,
      );
  }

  private updateSensitiveRecord(
    previous: RegistryRow,
    record: PendingCaptureAttempt | CommittedCaptureAttempt,
    dek: Buffer,
  ): void {
    const row = this.encryptSensitiveRecord(record, previous.sequence, dek);
    this.replaceRow(row);
  }

  private updateTombstone(
    previous: RegistryRow,
    tombstone: StoredCaptureTombstone,
    deletionBinding: string | null,
  ): void {
    const structural: Omit<RegistryRow, "ciphertext" | "nonce" | "row_mac" | "tag"> = {
      attempt_token: previous.attempt_token,
      begin_binding: null,
      capture_token: null,
      commit_binding: null,
      deletion_binding: deletionBinding,
      sequence: previous.sequence,
      session_token: previous.session_token,
      state: "removed",
      wrapped_dek_ciphertext: null,
      wrapped_dek_nonce: null,
      wrapped_dek_tag: null,
    };
    const plaintext = Buffer.from(exactJson(this.prepareTombstone(tombstone)), "utf8");
    try {
      const encrypted = encryptRegistryValue(
        this.encryptionKey,
        registryAad(structural),
        plaintext,
      );
      const unsigned: Omit<RegistryRow, "row_mac"> = {
        ...structural,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        tag: encrypted.tag,
      };
      this.replaceRow({
        ...unsigned,
        row_mac: mac(this.macKey, "row", rowAuthenticationParts(unsigned)),
      });
    } finally {
      plaintext.fill(0);
    }
  }

  private replaceRow(row: RegistryRow): void {
    const result = this.database
      .prepare(
        `UPDATE rsi_capture_registry_records
            SET attempt_token = ?, session_token = ?, capture_token = ?,
                begin_binding = ?, commit_binding = ?, deletion_binding = ?, state = ?,
                nonce = ?, ciphertext = ?, tag = ?,
                wrapped_dek_nonce = ?, wrapped_dek_ciphertext = ?, wrapped_dek_tag = ?,
                row_mac = ?
          WHERE sequence = ?`,
      )
      .run(
        row.attempt_token,
        row.session_token,
        row.capture_token,
        row.begin_binding,
        row.commit_binding,
        row.deletion_binding,
        row.state,
        row.nonce,
        row.ciphertext,
        row.tag,
        row.wrapped_dek_nonce,
        row.wrapped_dek_ciphertext,
        row.wrapped_dek_tag,
        row.row_mac,
        row.sequence,
      );
    if (result.changes !== 1) throw new CaptureRegistryIntegrityError();
  }

  private encryptSensitiveRecord(
    record: PendingCaptureAttempt | CommittedCaptureAttempt,
    sequence: number,
    dek: Buffer,
  ): RegistryRow {
    const plaintext = this.encodeAttempt(record);
    const attemptToken = this.attemptToken(record.attemptId);
    const wrappedDek = encryptRegistryValue(
      this.encryptionKey,
      wrappedDekAad({ attempt_token: attemptToken, sequence }),
      dek,
    );
    const structural: Omit<RegistryRow, "ciphertext" | "nonce" | "row_mac" | "tag"> = {
      attempt_token: this.attemptToken(record.attemptId),
      begin_binding: this.beginBinding(record),
      capture_token: record.state === "pending" ? null : this.captureToken(record.captureId),
      commit_binding:
        record.state === "pending"
          ? null
          : this.commitBinding({
              attemptId: record.attemptId,
              captureId: record.captureId,
              committedAt: record.committedAt,
              sourceIdentifiers: record.sourceIdentifiers,
            }),
      deletion_binding: null,
      sequence,
      session_token: this.sessionToken(record.sessionId),
      state: record.state,
      wrapped_dek_ciphertext: wrappedDek.ciphertext,
      wrapped_dek_nonce: wrappedDek.nonce,
      wrapped_dek_tag: wrappedDek.tag,
    };
    try {
      const encrypted = encryptRegistryValue(dek, registryAad(structural), plaintext);
      const unsigned: Omit<RegistryRow, "row_mac"> = {
        ...structural,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        tag: encrypted.tag,
      };
      return {
        ...unsigned,
        row_mac: mac(this.macKey, "row", rowAuthenticationParts(unsigned)),
      };
    } finally {
      plaintext.fill(0);
    }
  }

  private deleteSequences(sequences: readonly number[]): void {
    const statement = this.database.prepare(
      "DELETE FROM rsi_capture_registry_records WHERE sequence = ?",
    );
    for (const sequence of sequences) {
      const result = statement.run(sequence);
      if (result.changes !== 1) throw new CaptureRegistryIntegrityError();
    }
  }

  private listCaptureIds(sessionToken?: string): readonly string[] {
    return Object.freeze(
      this.listCaptureReferences(sessionToken).map((reference) => reference.captureId),
    );
  }

  private listCaptureReferences(
    sessionToken?: string,
  ): readonly Readonly<CommittedCaptureReference>[] {
    const rows = (sessionToken === undefined
      ? this.database
          .prepare(
            "SELECT * FROM rsi_capture_registry_records WHERE state = 'committed' ORDER BY sequence",
          )
          .all()
      : this.database
          .prepare(
            "SELECT * FROM rsi_capture_registry_records WHERE state = 'committed' AND session_token = ? ORDER BY sequence",
          )
          .all(sessionToken)) as unknown as RegistryRow[];
    return Object.freeze(
      rows.map((row) => {
        const record = this.decodeSensitiveRow(row);
        if (record.state !== "committed") throw new CaptureRegistryIntegrityError();
        return Object.freeze({
          attemptId: record.attemptId,
          captureId: record.captureId,
        });
      }),
    );
  }

  private refreshMetadata(nextSequence?: number): void {
    const previous = this.metadata();
    const rows = this.allRows();
    const recordCount = rows.length;
    const next = nextSequence ?? previous.next_sequence;
    const rowsMac = this.rowsMac(rows.map((row) => row.row_mac));
    const unsigned = {
      key_check_mac: previous.key_check_mac,
      next_sequence: next,
      profile: previous.profile,
      record_count: recordCount,
      rows_mac: rowsMac,
      schema_version: SCHEMA_VERSION,
    };
    const metadataMac = this.metadataMac(unsigned);
    const result = this.database
      .prepare(
        `UPDATE rsi_capture_registry_metadata
            SET schema_version = ?, profile = ?, record_count = ?, next_sequence = ?,
                rows_mac = ?, key_check_mac = ?, metadata_mac = ?
          WHERE singleton = 1`,
      )
      .run(
        SCHEMA_VERSION,
        previous.profile,
        recordCount,
        next,
        rowsMac,
        previous.key_check_mac,
        metadataMac,
      );
    if (result.changes !== 1) throw new CaptureRegistryIntegrityError();
  }

  private keyCheckMac(): string {
    return mac(this.macKey, "key-check", [SCHEMA_VERSION, this.expectedProfile]);
  }

  private tombstoneCount(): number {
    const row = this.database
      .prepare("SELECT COUNT(*) AS count FROM rsi_capture_registry_records WHERE state = 'removed'")
      .get() as { count: number };
    if (!Number.isSafeInteger(row.count) || row.count < 0) {
      throw new CaptureRegistryIntegrityError();
    }
    return row.count;
  }

  private rowsMac(rowMacs: readonly string[]): string {
    return mac(this.macKey, "rows", [rowMacs.length, ...rowMacs]);
  }

  private metadataMac(metadata: Omit<MetadataRow, "metadata_mac">): string {
    return mac(this.macKey, "metadata", [
      metadata.schema_version,
      metadata.profile,
      metadata.record_count,
      metadata.next_sequence,
      metadata.rows_mac,
      metadata.key_check_mac,
    ]);
  }

  private attemptToken(attemptId: string): string {
    return keyedLookupToken(this.lookupKey, "attempt", attemptId);
  }

  private sessionToken(sessionId: string): string {
    return keyedLookupToken(this.lookupKey, "session", sessionId);
  }

  private captureToken(captureId: string): string {
    return keyedLookupToken(this.lookupKey, "capture", captureId);
  }

  private beginBinding(input: {
    readonly acquiredAt: string;
    readonly attemptId: string;
    readonly expiresAt: string;
    readonly lane: string;
    readonly profile: string;
    readonly requestFingerprint: string;
    readonly sessionId: string;
    readonly source: string;
  }): string {
    return mac(this.macKey, "begin-binding", [
      input.acquiredAt,
      input.attemptId,
      input.expiresAt,
      input.lane,
      input.profile,
      input.requestFingerprint,
      input.sessionId,
      input.source,
    ]);
  }

  private commitBinding(input: CommitCaptureInput): string {
    return mac(this.macKey, "commit-binding", [
      input.attemptId,
      input.captureId,
      input.committedAt,
      exactJson(input.sourceIdentifiers),
    ]);
  }

  private deletionBinding(receipt: RecordVerifiedCaptureDeletionInput["deletionReceipt"]): string {
    return mac(this.macKey, "deletion-binding", [
      receipt.schemaVersion,
      receipt.captureId,
      receipt.deletedAt,
      receipt.keyDestroyed ? 1 : 0,
      receipt.reason,
      receipt.state,
    ]);
  }

  /** Completes local crypto-erasure before a destructive lifecycle method returns. */
  private hardenErasure(): void {
    this.assertFilesystemSafe();
    try {
      this.database.exec("VACUUM");
      this.assertFilesystemSafe();
      this.database.exec("BEGIN");
      try {
        this.verifyIntegrityInternal();
        this.database.exec("COMMIT");
      } catch (error) {
        if (this.database.isTransaction) this.database.exec("ROLLBACK");
        throw error;
      }
    } catch (error) {
      if (error instanceof CaptureRegistryError) throw error;
      throw new CaptureRegistryIntegrityError("Capture registry erasure compaction failed");
    }
  }
}

/** Returns true only for a registry whose authenticated open completed successfully. */
export function isSqliteCaptureRegistry(value: unknown): value is SqliteCaptureRegistry {
  return (
    typeof value === "object" &&
    value !== null &&
    authenticSqliteCaptureRegistries.has(value) &&
    Object.getPrototypeOf(value) === SqliteCaptureRegistry.prototype
  );
}
