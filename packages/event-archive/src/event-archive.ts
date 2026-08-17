import { types as utilTypes } from "node:util";

import { SqliteEventStore, isSqliteEventStore } from "@rsi/store";

import {
  encodeSignedEventArchive,
  normalizeSigner,
  verifyEventArchiveBytes,
  type VerifiedEventArchive,
} from "./archive.js";
import {
  canonicalJson,
  exactArray,
  exactObject,
  validateHash,
  validateSafeInteger,
} from "./canonical.js";
import { EventArchiveError, fail } from "./errors.js";
import { publishArchiveCreateOnly, readArchiveFile, restoreVerifiedArchive } from "./filesystem.js";
import { EVENT_STORE_GENESIS_HASH, parseSanitizedEvent, sanitizeSnapshot } from "./schema.js";
import type {
  CreateSanitizedEventArchiveOptions,
  EventArchiveImportIntegrityReportLike,
  EventArchiveImportTarget,
  ImportSanitizedEventArchiveOptions,
  JsonValue,
  RestoreSanitizedEventArchiveOptions,
  SanitizedEventArchiveImportReportV1,
  SanitizedEventArchiveReceiptV1,
  SanitizedEventArchiveRestoreReportV1,
  SanitizedEventArchiveVerificationReportV1,
  SanitizedStoredEventV1,
  VerifySanitizedEventArchiveOptions,
} from "./types.js";

/**
 * Creates the complete typed event-history companion for one independently
 * retained `@rsi/backup` state-evidence component. No generic bytes or paths
 * other than the create-only destination are accepted as archive content.
 */
export async function createSanitizedEventArchive(
  optionsValue: CreateSanitizedEventArchiveOptions,
): Promise<SanitizedEventArchiveReceiptV1> {
  const options = exactObject(
    optionsValue,
    ["createdAt", "destinationPath", "signer", "snapshot"],
    "Create-event-archive options",
  );
  if (typeof options.destinationPath !== "string") {
    fail("INPUT_INVALID", "Event-archive destination must be a path string");
  }
  const data = sanitizeSnapshot(options.snapshot);
  const signer = normalizeSigner(options.signer);
  const encoded = await encodeSignedEventArchive(data, options.createdAt, signer);
  const trust = Object.freeze({
    receipt: encoded.receipt,
    releasePublicKeySpkiDer: Uint8Array.from(signer.publicKeySpkiDer),
    stateEvidence: data.stateEvidence,
  });
  verifyEventArchiveBytes(encoded.bytes, trust);
  await publishArchiveCreateOnly(options.destinationPath, encoded.bytes);
  const persisted = await readArchiveFile(options.destinationPath);
  verifyEventArchiveBytes(persisted, trust);
  return encoded.receipt;
}

/** Verifies the exact archive pinned by both independently retained receipts. */
export async function verifySanitizedEventArchive(
  optionsValue: VerifySanitizedEventArchiveOptions,
): Promise<SanitizedEventArchiveVerificationReportV1> {
  const options = exactObject(
    optionsValue,
    ["archivePath", "trust"],
    "Verify-event-archive options",
  );
  return (await verifyFromPath(options.archivePath, options.trust)).report;
}

/**
 * Buffers and verifies the complete signed archive before creating anything.
 * The destination must not exist; restoration never merges or overwrites.
 */
export async function restoreSanitizedEventArchive(
  optionsValue: RestoreSanitizedEventArchiveOptions,
): Promise<SanitizedEventArchiveRestoreReportV1> {
  const options = exactObject(
    optionsValue,
    ["archivePath", "destinationDirectory", "trust"],
    "Restore-event-archive options",
  );
  const verified = await verifyFromPath(options.archivePath, options.trust);
  await restoreVerifiedArchive(options.destinationDirectory, verified);
  return Object.freeze({ ...verified.report, restoredFileCount: 2 as const });
}

/**
 * Verifies before touching the target, then reconstructs an exact event store
 * in one caller-provided synchronous exclusive transaction. The target must be
 * genesis-empty; an existing record is never merged, retried, or overwritten.
 */
export async function importSanitizedEventArchiveToEmptyStore(
  optionsValue: ImportSanitizedEventArchiveOptions,
): Promise<SanitizedEventArchiveImportReportV1> {
  const options = exactObject(
    optionsValue,
    ["archivePath", "target", "trust"],
    "Import-event-archive options",
  );
  const verified = await verifyFromPath(options.archivePath, options.trust);
  const target = normalizeImportTarget(options.target);
  let invocationCount = 0;
  const completed = Symbol("event-archive-import-complete");
  let result: unknown;
  try {
    result = target.withExclusiveTransaction(() => {
      invocationCount += 1;
      if (invocationCount !== 1)
        fail("IMPORT_TARGET_INVALID", "Import transaction was invoked more than once");
      assertEmptyTarget(target);
      for (const expected of verified.events) {
        const appended = parseSanitizedEvent(
          target.append({
            aggregateId: expected.aggregateId,
            eventId: expected.eventId,
            idempotencyKey: expected.idempotencyKey,
            occurredAt: expected.occurredAt,
            payload: expected.payload as unknown as JsonValue,
            type: expected.type,
          }),
        );
        if (
          canonicalJson(appended as unknown as JsonValue) !==
          canonicalJson(expected as unknown as JsonValue)
        ) {
          fail("INTEGRITY_MISMATCH", "Imported event does not match its archived record");
        }
      }
      assertFinalTarget(target, verified);
      return completed;
    });
  } catch (error) {
    if (error instanceof EventArchiveError) throw error;
    fail("IMPORT_TARGET_INVALID", "Event-store import failed");
  }
  if (isThenable(result) || result !== completed || invocationCount !== 1) {
    fail(
      "IMPORT_TARGET_INVALID",
      "Import transaction did not complete synchronously and exactly once",
    );
  }
  return Object.freeze({
    ...verified.report,
    importedEventCount: verified.events.length,
    status: "imported-and-verified" as const,
  });
}

async function verifyFromPath(path: unknown, trust: unknown): Promise<VerifiedEventArchive> {
  const bytes = await readArchiveFile(path);
  return verifyEventArchiveBytes(bytes, trust);
}

interface NormalizedImportTarget {
  readonly append: EventArchiveImportTarget["append"];
  readonly list: EventArchiveImportTarget["list"];
  readonly verifyIntegrity: EventArchiveImportTarget["verifyIntegrity"];
  readonly withExclusiveTransaction: EventArchiveImportTarget["withExclusiveTransaction"];
}

function normalizeImportTarget(value: unknown): NormalizedImportTarget {
  if (!isSqliteEventStore(value)) {
    fail("IMPORT_TARGET_INVALID", "Import target must be an authentic SQLite event store");
  }
  return Object.freeze({
    append: SqliteEventStore.prototype.append.bind(value),
    list: SqliteEventStore.prototype.list.bind(value),
    verifyIntegrity: SqliteEventStore.prototype.verifyIntegrity.bind(value),
    withExclusiveTransaction: SqliteEventStore.prototype.withExclusiveTransaction.bind(value),
  });
}

function assertEmptyTarget(target: NormalizedImportTarget): void {
  const report = parseTargetIntegrity(target.verifyIntegrity());
  if (
    !report.valid ||
    report.errors.length !== 0 ||
    report.eventCount !== 0 ||
    report.headSequence !== 0 ||
    report.headHash !== EVENT_STORE_GENESIS_HASH
  ) {
    fail("DESTINATION_EXISTS", "Import target is not a verified empty event store");
  }
  const listed = exactArray(target.list({ limit: 1, order: "asc" }), "Import-target event list");
  if (listed.length !== 0) fail("DESTINATION_EXISTS", "Import target already contains events");
}

function assertFinalTarget(target: NormalizedImportTarget, verified: VerifiedEventArchive): void {
  const report = parseTargetIntegrity(target.verifyIntegrity());
  if (
    !report.valid ||
    report.errors.length !== 0 ||
    report.eventCount !== verified.events.length ||
    report.headSequence !== verified.report.headSequence ||
    report.headHash !== verified.report.headHash
  ) {
    fail("INTEGRITY_MISMATCH", "Reconstructed event store does not match the archive head");
  }
}

function parseTargetIntegrity(value: unknown): EventArchiveImportIntegrityReportLike {
  const record = exactObject(
    value,
    ["errors", "eventCount", "headHash", "headSequence", "valid"],
    "Import-target integrity report",
  );
  const errors = exactArray(record.errors, "Import-target integrity issues");
  if (typeof record.valid !== "boolean") {
    fail("IMPORT_TARGET_INVALID", "Import-target integrity status is invalid");
  }
  return Object.freeze({
    errors,
    eventCount: validateSafeInteger(record.eventCount, "Import-target event count", 0),
    headHash: validateHash(record.headHash, "Import-target head hash"),
    headSequence: validateSafeInteger(record.headSequence, "Import-target head sequence", 0),
    valid: record.valid,
  });
}

function isThenable(value: unknown): boolean {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return false;
  if (utilTypes.isProxy(value)) return true;
  const descriptor = Object.getOwnPropertyDescriptor(value, "then");
  return descriptor !== undefined;
}
