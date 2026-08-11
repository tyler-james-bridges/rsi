import { validateHash, validateSafeInteger } from "./canonical.js";
import { InvalidCheckpointError } from "./errors.js";
import {
  CHECKPOINT_JOURNAL_GENESIS_HASH,
  type CheckpointPayload,
  type CheckpointStore,
  type StoreIntegrityReportLike,
} from "./types.js";

export function validateStoreReport(report: StoreIntegrityReportLike): StoreIntegrityReportLike {
  if (report === null || typeof report !== "object") {
    throw new InvalidCheckpointError("Event store returned an invalid integrity report");
  }
  if (typeof report.valid !== "boolean" || !Array.isArray(report.errors)) {
    throw new InvalidCheckpointError("Event store returned an invalid integrity report");
  }
  validateSafeInteger(report.eventCount, "store report eventCount", 0);
  validateSafeInteger(report.headSequence, "store report headSequence", 0);
  validateHash(report.headHash, "store report headHash");
  if (report.eventCount !== report.headSequence) {
    throw new InvalidCheckpointError(
      "Event-store eventCount must equal its contiguous headSequence",
    );
  }
  if (report.headSequence === 0 && report.headHash !== CHECKPOINT_JOURNAL_GENESIS_HASH) {
    throw new InvalidCheckpointError("Empty event store has an invalid genesis head hash");
  }
  return report;
}

export function eventHashAt(store: CheckpointStore, sequence: number): string | undefined {
  if (sequence === 0) return CHECKPOINT_JOURNAL_GENESIS_HASH;
  const rows = store.list({ afterSequence: sequence - 1, limit: 1, order: "asc" });
  const row = rows[0];
  if (row === undefined || row.sequence !== sequence) return undefined;
  validateHash(row.eventHash, `eventHash at sequence ${sequence}`);
  return row.eventHash;
}

export function storeContainsAnchor(store: CheckpointStore, payload: CheckpointPayload): boolean {
  if (payload.storeHeadSequence === 0) return false;
  return eventHashAt(store, payload.storeHeadSequence) === payload.storeHeadHash;
}
