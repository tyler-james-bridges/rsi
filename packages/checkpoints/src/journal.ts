import { TextDecoder } from "node:util";
import type { KeyObject } from "node:crypto";

import { canonicalJson, parseSignedCheckpoint, validateJournalHead } from "./canonical.js";
import { computeCheckpointHash, verifyCheckpointSignature } from "./crypto.js";
import { JournalFileError, readJournalFile, type JournalPathGuard } from "./safe-path.js";
import {
  CHECKPOINT_JOURNAL_GENESIS_HASH,
  type CheckpointJournalHead,
  type CheckpointJournalIssue,
  type CheckpointJournalIssueCode,
  type CheckpointJournalVerificationReport,
  type SignedCheckpoint,
} from "./types.js";

const MAX_ENTRY_BYTES = 8 * 1024;
export const MAX_JOURNAL_ENTRIES = 100_000;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export interface JournalVerificationContext {
  readonly expectedKeyId: string;
  readonly expectedPublicKey: KeyObject;
  readonly expectedStoreId: string;
  readonly trustedJournalHead?: CheckpointJournalHead;
}

export function journalHasEntryCapacity(entryCount: number): boolean {
  return Number.isSafeInteger(entryCount) && entryCount >= 0 && entryCount < MAX_JOURNAL_ENTRIES;
}

export function verifyJournalFile(
  guard: JournalPathGuard,
  context: JournalVerificationContext,
): CheckpointJournalVerificationReport {
  let file: ReturnType<typeof readJournalFile>;
  try {
    file = readJournalFile(guard);
  } catch (error) {
    const issueCode: CheckpointJournalIssueCode =
      error instanceof JournalFileError
        ? error.kind === "TOO_LARGE"
          ? "JOURNAL_TOO_LARGE"
          : error.kind === "UNSAFE"
            ? "UNSAFE_JOURNAL_PATH"
            : "JOURNAL_READ_ERROR"
        : "JOURNAL_READ_ERROR";
    return freezeJournalReport({
      entries: [],
      issues: [issue(issueCode, error instanceof Error ? error.message : "Journal read failed")],
      journalExists: true,
      journalHead: null,
      truncationProtectedThrough: null,
      valid: false,
    });
  }
  return verifyJournalBytes(file.bytes, file.exists, context);
}

export function verifyJournalBytes(
  bytes: Uint8Array,
  journalExists: boolean,
  context: JournalVerificationContext,
): CheckpointJournalVerificationReport {
  const issues: CheckpointJournalIssue[] = [];
  const entries: SignedCheckpoint[] = [];
  let text: string;

  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    return freezeJournalReport({
      entries,
      issues: [issue("INVALID_JOURNAL_ENCODING", "Journal is not valid UTF-8")],
      journalExists,
      journalHead: null,
      truncationProtectedThrough: null,
      valid: false,
    });
  }

  if (text.length !== 0 && !text.endsWith("\n")) {
    issues.push(issue("INVALID_JOURNAL_ENCODING", "Non-empty journal must end with a newline"));
  }
  const body = text.endsWith("\n") ? text.slice(0, -1) : text;
  const lines = text.length === 0 ? [] : body.split("\n");
  if (lines.length > MAX_JOURNAL_ENTRIES) {
    return freezeJournalReport({
      entries,
      issues: [
        issue("JOURNAL_TOO_LARGE", `Journal exceeds ${MAX_JOURNAL_ENTRIES} checkpoint entries`),
      ],
      journalExists,
      journalHead: null,
      truncationProtectedThrough: null,
      valid: false,
    });
  }
  let previousHash = CHECKPOINT_JOURNAL_GENESIS_HASH;
  let previousStoreSequence = -1;
  let previousTimestamp: string | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] as string;
    const lineNumber = index + 1;
    if (Buffer.byteLength(line, "utf8") > MAX_ENTRY_BYTES) {
      issues.push(
        issue("INVALID_ENTRY", `Journal entry exceeds ${MAX_ENTRY_BYTES} bytes`, lineNumber),
      );
      continue;
    }
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(line) as unknown;
    } catch {
      issues.push(issue("INVALID_ENTRY", "Journal entry is not valid JSON", lineNumber));
      continue;
    }
    try {
      if (canonicalJson(parsedJson) !== line) {
        issues.push(
          issue("NON_CANONICAL_ENTRY", "Journal entry is not canonically encoded", lineNumber),
        );
      }
    } catch (error) {
      issues.push(
        issue(
          "INVALID_ENTRY",
          error instanceof Error ? error.message : "Journal entry cannot be encoded canonically",
          lineNumber,
        ),
      );
      continue;
    }

    let entry: SignedCheckpoint;
    try {
      entry = parseSignedCheckpoint(parsedJson);
    } catch (error) {
      issues.push(
        issue(
          "INVALID_ENTRY",
          error instanceof Error ? error.message : "Journal entry has an invalid shape",
          lineNumber,
        ),
      );
      continue;
    }
    entries.push(entry);
    const sequence = entry.payload.journalSequence;

    if (sequence !== lineNumber) {
      issues.push(
        issue(
          "JOURNAL_SEQUENCE_GAP",
          `Expected journalSequence ${lineNumber}, received ${sequence}`,
          lineNumber,
          sequence,
        ),
      );
    }
    if (entry.payload.previousCheckpointHash !== previousHash) {
      issues.push(
        issue(
          "PREVIOUS_CHECKPOINT_HASH_MISMATCH",
          "previousCheckpointHash does not match the preceding checkpoint",
          lineNumber,
          sequence,
        ),
      );
    }
    if (entry.payload.storeHeadSequence <= previousStoreSequence) {
      issues.push(
        issue(
          "STORE_SEQUENCE_NOT_INCREASING",
          "Checkpoint store sequences must strictly increase",
          lineNumber,
          sequence,
        ),
      );
    }
    if (entry.payload.storeHeadSequence === 0) {
      issues.push(
        issue(
          "EMPTY_STORE_ANCHOR",
          "Checkpoints may not anchor an empty event store",
          lineNumber,
          sequence,
        ),
      );
    }
    if (previousTimestamp !== undefined && entry.payload.createdAt < previousTimestamp) {
      issues.push(
        issue(
          "TIMESTAMP_REGRESSION",
          "Checkpoint timestamps may not move backwards",
          lineNumber,
          sequence,
        ),
      );
    }
    if (entry.payload.keyId !== context.expectedKeyId) {
      issues.push(
        issue(
          "WRONG_KEY_ID",
          `Expected keyId ${context.expectedKeyId}, received ${entry.payload.keyId}`,
          lineNumber,
          sequence,
        ),
      );
    }
    if (entry.payload.storeId !== context.expectedStoreId) {
      issues.push(
        issue(
          "WRONG_STORE_ID",
          `Expected storeId ${context.expectedStoreId}, received ${entry.payload.storeId}`,
          lineNumber,
          sequence,
        ),
      );
    }

    let calculatedHash: string | undefined;
    try {
      calculatedHash = computeCheckpointHash(entry.payload, entry.signature);
      if (calculatedHash !== entry.checkpointHash) {
        issues.push(
          issue(
            "CHECKPOINT_HASH_MISMATCH",
            "checkpointHash does not match the signed checkpoint fields",
            lineNumber,
            sequence,
          ),
        );
      }
      if (!verifyCheckpointSignature(entry.payload, entry.signature, context.expectedPublicKey)) {
        issues.push(
          issue(
            "INVALID_SIGNATURE",
            "Ed25519 signature is not valid for the expected public key",
            lineNumber,
            sequence,
          ),
        );
      }
    } catch (error) {
      issues.push(
        issue(
          "INVALID_SIGNATURE",
          error instanceof Error ? error.message : "Unable to verify checkpoint signature",
          lineNumber,
          sequence,
        ),
      );
    }

    previousHash = entry.checkpointHash;
    previousStoreSequence = entry.payload.storeHeadSequence;
    previousTimestamp = entry.payload.createdAt;
  }

  let trusted: CheckpointJournalHead | null = null;
  if (context.trustedJournalHead !== undefined) {
    let expected: CheckpointJournalHead;
    try {
      expected = validateJournalHead(context.trustedJournalHead, "trustedJournalHead");
    } catch (error) {
      issues.push(
        issue(
          "TRUSTED_CHECKPOINT_MISMATCH",
          error instanceof Error ? error.message : "trustedJournalHead is invalid",
        ),
      );
      expected = context.trustedJournalHead;
    }
    const atPosition = entries.find(
      (entry) => entry.payload.journalSequence === expected.journalSequence,
    );
    if (atPosition === undefined) {
      issues.push(
        issue(
          "TRUSTED_CHECKPOINT_MISSING",
          `Trusted journal checkpoint ${expected.journalSequence} is missing; the journal may be truncated`,
          null,
          expected.journalSequence,
        ),
      );
    } else if (atPosition.checkpointHash !== expected.checkpointHash) {
      issues.push(
        issue(
          "TRUSTED_CHECKPOINT_MISMATCH",
          "Trusted checkpoint hash does not match the journal",
          expected.journalSequence,
          expected.journalSequence,
        ),
      );
    } else {
      trusted = expected;
    }
  }

  const last = entries.at(-1);
  return freezeJournalReport({
    entries,
    issues,
    journalExists,
    journalHead:
      last === undefined
        ? null
        : {
            checkpointHash: last.checkpointHash,
            journalSequence: last.payload.journalSequence,
          },
    truncationProtectedThrough: trusted,
    valid: issues.length === 0,
  });
}

export function withAdditionalJournalIssue(
  report: CheckpointJournalVerificationReport,
  added: CheckpointJournalIssue,
): CheckpointJournalVerificationReport {
  return freezeJournalReport({
    entries: [...report.entries],
    issues: [...report.issues, added],
    journalExists: report.journalExists,
    journalHead: report.journalHead,
    truncationProtectedThrough: report.truncationProtectedThrough,
    valid: false,
  });
}

export function journalIssue(
  code: CheckpointJournalIssueCode,
  message: string,
  journalSequence: number | null = null,
): CheckpointJournalIssue {
  return issue(code, message, null, journalSequence);
}

function issue(
  code: CheckpointJournalIssueCode,
  message: string,
  line: number | null = null,
  journalSequence: number | null = null,
): CheckpointJournalIssue {
  return { code, journalSequence, line, message };
}

function freezeJournalReport(
  report: CheckpointJournalVerificationReport,
): CheckpointJournalVerificationReport {
  for (const entry of report.entries) {
    Object.freeze(entry.payload);
    Object.freeze(entry);
  }
  for (const item of report.issues) Object.freeze(item);
  Object.freeze(report.entries);
  Object.freeze(report.issues);
  if (report.journalHead !== null) Object.freeze(report.journalHead);
  if (report.truncationProtectedThrough !== null) Object.freeze(report.truncationProtectedThrough);
  return Object.freeze(report);
}
