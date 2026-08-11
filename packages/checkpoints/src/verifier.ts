import type { KeyObject } from "node:crypto";

import { validateExactObjectKeys, validateIdentifier, validateJournalHead } from "./canonical.js";
import { importEd25519PublicKey } from "./crypto.js";
import { InvalidCheckpointError } from "./errors.js";
import { journalIssue, verifyJournalFile, withAdditionalJournalIssue } from "./journal.js";
import {
  assertJournalSeparateFromStore,
  createJournalPathGuard,
  type JournalPathGuard,
} from "./safe-path.js";
import { eventHashAt, validateStoreReport } from "./store-snapshot.js";
import type {
  CheckpointJournalHead,
  CheckpointJournalVerificationReport,
  CheckpointStore,
  CheckpointStoreIssue,
  CheckpointVerificationReport,
  CheckpointVerifierOptions,
  SignedCheckpoint,
} from "./types.js";

export class CheckpointVerifier {
  readonly expectedKeyId: string;
  readonly expectedStoreId: string;
  readonly journalPath: string;

  readonly #expectedPublicKey: KeyObject;
  readonly #pathGuard: JournalPathGuard;
  readonly #trustedJournalHead: CheckpointJournalHead | undefined;

  constructor(options: CheckpointVerifierOptions) {
    if (options === null || typeof options !== "object") {
      throw new InvalidCheckpointError("Checkpoint verifier options must be an object");
    }
    validateExactObjectKeys(
      options,
      [
        "expectedKeyId",
        "expectedPublicKey",
        "expectedStoreId",
        "journalPath",
        "trustedJournalHead",
      ].filter((key) => key !== "trustedJournalHead" || Object.hasOwn(options, key)),
      "Checkpoint verifier options",
    );
    validateIdentifier(options.expectedKeyId, "expectedKeyId");
    validateIdentifier(options.expectedStoreId, "expectedStoreId");
    this.#pathGuard = createJournalPathGuard(options.journalPath);
    this.journalPath = this.#pathGuard.path;
    this.expectedKeyId = options.expectedKeyId;
    this.expectedStoreId = options.expectedStoreId;
    this.#expectedPublicKey = importEd25519PublicKey(options.expectedPublicKey);
    this.#trustedJournalHead =
      options.trustedJournalHead === undefined
        ? undefined
        : validateJournalHead(options.trustedJournalHead, "trustedJournalHead");
  }

  verifyJournal(): CheckpointJournalVerificationReport {
    return verifyJournalFile(this.#pathGuard, this.journalContext());
  }

  verify(store: CheckpointStore): CheckpointVerificationReport {
    let journal = this.verifyJournal();
    try {
      assertJournalSeparateFromStore(this.#pathGuard, store.path);
    } catch (error) {
      if (!journal.issues.some((item) => item.code === "UNSAFE_JOURNAL_PATH")) {
        journal = withAdditionalJournalIssue(
          journal,
          journalIssue(
            "UNSAFE_JOURNAL_PATH",
            error instanceof Error ? error.message : "Checkpoint journal path is unsafe",
          ),
        );
      }
    }
    const latest = journal.entries.at(-1) ?? null;

    return store.withExclusiveTransaction(() => {
      const storeIssues: CheckpointStoreIssue[] = [];
      let storeHeadSequence = 0;
      let storeHeadHash = "0".repeat(64);
      let storeValid = false;
      try {
        const integrity = validateStoreReport(store.verifyIntegrity());
        storeHeadSequence = integrity.headSequence;
        storeHeadHash = integrity.headHash;
        storeValid = integrity.valid;
        if (!integrity.valid) {
          storeIssues.push(
            storeIssue(
              "STORE_INTEGRITY_INVALID",
              `Event-store integrity failed: ${integrity.errors.map((item) => item.code).join(", ")}`,
            ),
          );
        }
      } catch (error) {
        storeIssues.push(
          storeIssue(
            "INVALID_STORE_REPORT",
            error instanceof Error ? error.message : "Event store returned an invalid report",
          ),
        );
      }

      if (journal.valid && latest === null) {
        storeIssues.push(storeIssue("NO_CHECKPOINT", "Journal contains no signed checkpoint"));
      }
      if (journal.valid && latest !== null && storeValid) {
        for (const entry of journal.entries) {
          checkStoreAnchor(store, entry, storeHeadSequence, storeIssues);
        }
      }

      const valid = journal.valid && storeValid && latest !== null && storeIssues.length === 0;
      const anchoredThroughSequence = valid ? latest.payload.storeHeadSequence : null;
      return freezeVerificationReport({
        anchoredThroughSequence,
        journal,
        latestCheckpoint: latest,
        recordedAnchorSequence: latest?.payload.storeHeadSequence ?? null,
        status: valid
          ? "ANCHORED"
          : latest === null && journal.valid && storeValid
            ? "UNANCHORED"
            : "INVALID",
        storeHeadHash,
        storeHeadSequence,
        storeIssues,
        unanchoredEventCount:
          anchoredThroughSequence !== null
            ? storeHeadSequence - anchoredThroughSequence
            : journal.valid && latest === null && storeValid
              ? storeHeadSequence
              : null,
        valid,
      });
    });
  }

  private journalContext() {
    return {
      expectedKeyId: this.expectedKeyId,
      expectedPublicKey: this.#expectedPublicKey,
      expectedStoreId: this.expectedStoreId,
      ...(this.#trustedJournalHead === undefined
        ? {}
        : { trustedJournalHead: this.#trustedJournalHead }),
    };
  }
}

function checkStoreAnchor(
  store: CheckpointStore,
  entry: SignedCheckpoint,
  storeHeadSequence: number,
  issues: CheckpointStoreIssue[],
): void {
  const sequence = entry.payload.storeHeadSequence;
  if (sequence === 0) {
    issues.push(
      storeIssue(
        "EMPTY_STORE_ANCHOR",
        "A sequence-zero checkpoint cannot establish event-store lineage",
        0,
        entry.payload.journalSequence,
      ),
    );
    return;
  }
  if (sequence > storeHeadSequence) {
    issues.push(
      storeIssue(
        "ANCHORED_EVENT_MISSING",
        `Store ends at sequence ${storeHeadSequence}, before anchored sequence ${sequence}`,
        sequence,
        entry.payload.journalSequence,
      ),
    );
    return;
  }
  const actualHash = eventHashAt(store, sequence);
  if (actualHash === undefined) {
    issues.push(
      storeIssue(
        "ANCHORED_EVENT_MISSING",
        `Store has no event at anchored sequence ${sequence}`,
        sequence,
        entry.payload.journalSequence,
      ),
    );
  } else if (actualHash !== entry.payload.storeHeadHash) {
    issues.push(
      storeIssue(
        "ANCHORED_HASH_MISMATCH",
        `Store hash at sequence ${sequence} does not match the signed anchor`,
        sequence,
        entry.payload.journalSequence,
      ),
    );
  }
}

function storeIssue(
  code: CheckpointStoreIssue["code"],
  message: string,
  storeSequence: number | null = null,
  journalSequence: number | null = null,
): CheckpointStoreIssue {
  return { code, journalSequence, message, storeSequence };
}

function freezeVerificationReport(
  report: CheckpointVerificationReport,
): CheckpointVerificationReport {
  for (const issue of report.storeIssues) Object.freeze(issue);
  Object.freeze(report.storeIssues);
  return Object.freeze(report);
}
