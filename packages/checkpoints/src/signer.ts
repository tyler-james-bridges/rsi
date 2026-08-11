import type { KeyObject } from "node:crypto";

import {
  canonicalJson,
  validateCanonicalTimestamp,
  validateExactObjectKeys,
  validateIdentifier,
  validateJournalHead,
} from "./canonical.js";
import {
  computeCheckpointHash,
  importEd25519PrivateKey,
  publicKeyForPrivateKey,
  signCheckpointPayload,
} from "./crypto.js";
import {
  CheckpointJournalIntegrityError,
  CheckpointStoreIntegrityError,
  InvalidCheckpointError,
} from "./errors.js";
import {
  MAX_JOURNAL_ENTRIES,
  journalHasEntryCapacity,
  journalIssue,
  verifyJournalFile,
  withAdditionalJournalIssue,
} from "./journal.js";
import {
  appendJournalBytes,
  assertJournalSeparateFromStore,
  createJournalPathGuard,
  type JournalPathGuard,
  withJournalLock,
} from "./safe-path.js";
import { storeContainsAnchor, validateStoreReport } from "./store-snapshot.js";
import {
  CHECKPOINT_JOURNAL_GENESIS_HASH,
  CHECKPOINT_PAYLOAD_VERSION,
  CHECKPOINT_TYPE,
  type AppendCheckpointOptions,
  type CheckpointJournalHead,
  type CheckpointPayload,
  type CheckpointSignerOptions,
  type CheckpointStore,
  type SignedCheckpoint,
} from "./types.js";

export class CheckpointSigner {
  readonly journalPath: string;
  readonly keyId: string;
  readonly storeId: string;

  #expectedHead: CheckpointJournalHead | null;
  readonly #privateKey: KeyObject;
  readonly #publicKey: KeyObject;
  readonly #pathGuard: JournalPathGuard;

  constructor(options: CheckpointSignerOptions) {
    if (options === null || typeof options !== "object") {
      throw new InvalidCheckpointError("Checkpoint signer options must be an object");
    }
    if (!Object.hasOwn(options, "expectedJournalHead")) {
      throw new InvalidCheckpointError(
        "expectedJournalHead is required (use null for a new journal)",
      );
    }
    validateExactObjectKeys(
      options,
      ["expectedJournalHead", "journalPath", "keyId", "privateKey", "storeId"],
      "Checkpoint signer options",
    );
    validateIdentifier(options.keyId, "keyId");
    validateIdentifier(options.storeId, "storeId");
    this.#pathGuard = createJournalPathGuard(options.journalPath);
    this.journalPath = this.#pathGuard.path;
    this.keyId = options.keyId;
    this.storeId = options.storeId;
    this.#privateKey = importEd25519PrivateKey(options.privateKey);
    this.#publicKey = publicKeyForPrivateKey(this.#privateKey);
    this.#expectedHead =
      options.expectedJournalHead === null
        ? null
        : validateJournalHead(options.expectedJournalHead, "expectedJournalHead");
  }

  /** The head this signer will require on its next append. Retain it outside SQLite across restarts. */
  get journalHead(): CheckpointJournalHead | null {
    return this.#expectedHead;
  }

  append(store: CheckpointStore, options: AppendCheckpointOptions = {}): SignedCheckpoint {
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw new InvalidCheckpointError("Append checkpoint options must be an object");
    }
    validateExactObjectKeys(
      options,
      Object.hasOwn(options, "createdAt") ? ["createdAt"] : [],
      "Append checkpoint options",
    );
    const createdAt = options.createdAt ?? new Date().toISOString();
    validateCanonicalTimestamp(createdAt);
    assertJournalSeparateFromStore(this.#pathGuard, store.path);

    return withJournalLock(this.#pathGuard, () => {
      const journal = verifyJournalFile(this.#pathGuard, {
        expectedKeyId: this.keyId,
        expectedPublicKey: this.#publicKey,
        expectedStoreId: this.storeId,
      });
      if (!journal.valid) throw new CheckpointJournalIntegrityError(journal);
      if (!journalHasEntryCapacity(journal.entries.length)) {
        throw new CheckpointJournalIntegrityError(
          withAdditionalJournalIssue(
            journal,
            journalIssue(
              "JOURNAL_TOO_LARGE",
              `Checkpoint journal has reached its ${MAX_JOURNAL_ENTRIES}-entry limit; rotate it before appending`,
            ),
          ),
        );
      }
      if (!headsEqual(journal.journalHead, this.#expectedHead)) {
        throw new CheckpointJournalIntegrityError(
          withAdditionalJournalIssue(
            journal,
            journalIssue(
              "TRUSTED_CHECKPOINT_MISMATCH",
              "Journal head differs from the signer's expected prior head; append refused",
              journal.journalHead?.journalSequence ?? null,
            ),
          ),
        );
      }

      const previous = journal.entries.at(-1);
      const entry = store.withExclusiveTransaction(() => {
        let storeReport;
        try {
          storeReport = validateStoreReport(store.verifyIntegrity());
        } catch (error) {
          throw new CheckpointStoreIntegrityError(
            error instanceof Error ? error.message : "Event-store report is invalid",
          );
        }
        if (!storeReport.valid) {
          throw new CheckpointStoreIntegrityError("Cannot checkpoint an invalid event store");
        }
        if (storeReport.headSequence === 0) {
          throw new CheckpointStoreIntegrityError(
            "Cannot checkpoint an empty event store; an anchor requires at least one event",
          );
        }
        if (previous !== undefined && !storeContainsAnchor(store, previous.payload)) {
          throw new CheckpointStoreIntegrityError(
            "Current event store does not contain the journal's previous anchored head",
          );
        }
        if (
          previous !== undefined &&
          storeReport.headSequence <= previous.payload.storeHeadSequence
        ) {
          throw new CheckpointStoreIntegrityError(
            "Checkpoint append requires at least one new event after the previous anchor",
          );
        }
        if (previous !== undefined && createdAt < previous.payload.createdAt) {
          throw new InvalidCheckpointError("createdAt may not precede the previous checkpoint");
        }

        const payload: CheckpointPayload = Object.freeze({
          checkpointType: CHECKPOINT_TYPE,
          createdAt,
          journalSequence: (previous?.payload.journalSequence ?? 0) + 1,
          keyId: this.keyId,
          previousCheckpointHash: previous?.checkpointHash ?? CHECKPOINT_JOURNAL_GENESIS_HASH,
          storeHeadHash: storeReport.headHash,
          storeHeadSequence: storeReport.headSequence,
          storeId: this.storeId,
          version: CHECKPOINT_PAYLOAD_VERSION,
        });
        const signature = signCheckpointPayload(payload, this.#privateKey);
        const checkpointHash = computeCheckpointHash(payload, signature);
        const signed = Object.freeze({ checkpointHash, payload, signature });
        appendJournalBytes(this.#pathGuard, Buffer.from(`${canonicalJson(signed)}\n`, "utf8"));
        return signed;
      });

      const persisted = verifyJournalFile(this.#pathGuard, {
        expectedKeyId: this.keyId,
        expectedPublicKey: this.#publicKey,
        expectedStoreId: this.storeId,
      });
      if (!persisted.valid || persisted.journalHead?.checkpointHash !== entry.checkpointHash) {
        throw new CheckpointJournalIntegrityError(persisted);
      }
      this.#expectedHead = Object.freeze({
        checkpointHash: entry.checkpointHash,
        journalSequence: entry.payload.journalSequence,
      });
      return entry;
    });
  }
}

function headsEqual(
  left: CheckpointJournalHead | null,
  right: CheckpointJournalHead | null,
): boolean {
  return (
    (left === null && right === null) ||
    (left !== null &&
      right !== null &&
      left.checkpointHash === right.checkpointHash &&
      left.journalSequence === right.journalSequence)
  );
}
