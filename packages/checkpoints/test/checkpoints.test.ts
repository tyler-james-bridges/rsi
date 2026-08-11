import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { SqliteEventStore } from "@rsi/store";
import { canonicalJson } from "../src/canonical.js";
import { signCheckpointPayload } from "../src/crypto.js";
import { MAX_JOURNAL_ENTRIES, journalHasEntryCapacity } from "../src/journal.js";
import {
  JournalFileError,
  MAX_JOURNAL_BYTES,
  appendJournalBytes,
  createJournalPathGuard,
} from "../src/safe-path.js";
import {
  CheckpointConcurrencyError,
  CheckpointJournalIntegrityError,
  CheckpointSigner,
  CheckpointStoreIntegrityError,
  CheckpointVerifier,
  computeCheckpointHash,
  type Ed25519PrivateKeyMaterial,
  encodeCheckpointPayload,
  InvalidCheckpointError,
  type CheckpointJournalHead,
  type CheckpointPayload,
} from "../src/index.js";

const primaryKeys = generateKeyPairSync("ed25519");
const otherKeys = generateKeyPairSync("ed25519");
const rsaKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const directories: string[] = [];
const stores: SqliteEventStore[] = [];

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const directory of directories.splice(0))
    rmSync(directory, { force: true, recursive: true });
});

interface Fixture {
  directory: string;
  journalPath: string;
  store: SqliteEventStore;
  storePath: string;
}

function fixture(name = "main"): Fixture {
  const directory = mkdtempSync(join(tmpdir(), "rsi-checkpoints-"));
  directories.push(directory);
  const storePath = join(directory, `${name}.sqlite`);
  const store = new SqliteEventStore(storePath);
  stores.push(store);
  return { directory, journalPath: join(directory, `${name}.checkpoints.jsonl`), store, storePath };
}

function appendEvent(store: SqliteEventStore, index: number): void {
  store.append({
    aggregateId: "agent:rsi",
    eventId: `event-${index}`,
    occurredAt: `2026-08-11T00:00:${String(index).padStart(2, "0")}.000Z`,
    payload: { index },
    type: "run.recorded",
  });
}

function signer(
  target: Fixture,
  expectedJournalHead: CheckpointJournalHead | null = null,
  privateKey: Ed25519PrivateKeyMaterial = primaryKeys.privateKey,
): CheckpointSigner {
  return new CheckpointSigner({
    expectedJournalHead,
    journalPath: target.journalPath,
    keyId: "operator-key-v1",
    privateKey,
    storeId: "rsi-production-events",
  });
}

function verifier(
  target: Fixture,
  overrides: Partial<ConstructorParameters<typeof CheckpointVerifier>[0]> = {},
): CheckpointVerifier {
  return new CheckpointVerifier({
    expectedKeyId: "operator-key-v1",
    expectedPublicKey: primaryKeys.publicKey,
    expectedStoreId: "rsi-production-events",
    journalPath: target.journalPath,
    ...overrides,
  });
}

function journalLines(path: string): string[] {
  return readFileSync(path, "utf8").trimEnd().split("\n");
}

function writeEntries(path: string, entries: unknown[]): void {
  writeFileSync(path, `${entries.map((entry) => canonicalJson(entry)).join("\n")}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

describe("CheckpointSigner and CheckpointVerifier", () => {
  it("signs a canonical, versioned store-head payload and verifies the exact anchor", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const checkpoint = signer(target).append(target.store, {
      createdAt: "2026-08-11T01:00:00.000Z",
    });

    expect(checkpoint.payload).toEqual({
      checkpointType: "rsi.store.head",
      createdAt: "2026-08-11T01:00:00.000Z",
      journalSequence: 1,
      keyId: "operator-key-v1",
      previousCheckpointHash: "0".repeat(64),
      storeHeadHash: target.store.verifyIntegrity().headHash,
      storeHeadSequence: 1,
      storeId: "rsi-production-events",
      version: 1,
    });
    expect(checkpoint.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(checkpoint.checkpointHash).toMatch(/^[0-9a-f]{64}$/);
    const line = readFileSync(target.journalPath, "utf8");
    expect(line).toBe(`${canonicalJson(checkpoint)}\n`);

    expect(verifier(target).verify(target.store)).toMatchObject({
      anchoredThroughSequence: 1,
      recordedAnchorSequence: 1,
      status: "ANCHORED",
      unanchoredEventCount: 0,
      valid: true,
    });
  });

  it("reports an unanchored event tail separately from the signed prefix", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    appendEvent(target.store, 2);

    expect(verifier(target).verify(target.store)).toMatchObject({
      anchoredThroughSequence: 1,
      recordedAnchorSequence: 1,
      status: "ANCHORED",
      storeHeadSequence: 2,
      unanchoredEventCount: 1,
      valid: true,
    });
  });

  it("appends a strictly advancing, hash-linked checkpoint chain", () => {
    const target = fixture();
    const checkpointSigner = signer(target);
    appendEvent(target.store, 1);
    const first = checkpointSigner.append(target.store, {
      createdAt: "2026-08-11T01:00:00.000Z",
    });
    appendEvent(target.store, 2);
    const second = checkpointSigner.append(target.store, {
      createdAt: "2026-08-11T01:01:00.000Z",
    });

    expect(second.payload.journalSequence).toBe(2);
    expect(second.payload.previousCheckpointHash).toBe(first.checkpointHash);
    expect(checkpointSigner.journalHead).toEqual({
      checkpointHash: second.checkpointHash,
      journalSequence: 2,
    });
    expect(verifier(target).verifyJournal()).toMatchObject({ valid: true, issues: [] });
  });

  it("accepts caller-injected PEM private material without exposing a key-generation API", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const privatePem = primaryKeys.privateKey.export({ format: "pem", type: "pkcs8" });
    const checkpointSigner = signer(target, null, privatePem);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });

    expect(verifier(target).verify(target.store).valid).toBe(true);
  });

  it("uses deterministic, domain-separated canonical signing bytes", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const checkpoint = signer(target).append(target.store, {
      createdAt: "2026-08-11T01:00:00.000Z",
    });
    const encoded = encodeCheckpointPayload(checkpoint.payload);

    expect(encoded.toString("utf8")).toBe(
      `rsi-store-checkpoint-signature-v1\0${canonicalJson(checkpoint.payload)}`,
    );
    expect(computeCheckpointHash(checkpoint.payload, checkpoint.signature)).toBe(
      checkpoint.checkpointHash,
    );
  });

  it("does not treat an empty or missing journal as an anchored store", () => {
    const target = fixture();
    appendEvent(target.store, 1);

    expect(verifier(target).verify(target.store)).toMatchObject({
      anchoredThroughSequence: null,
      recordedAnchorSequence: null,
      status: "UNANCHORED",
      unanchoredEventCount: 1,
      valid: false,
      storeIssues: [expect.objectContaining({ code: "NO_CHECKPOINT" })],
    });
  });

  it("refuses to sign an empty event store", () => {
    const target = fixture();

    expect(() =>
      signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" }),
    ).toThrow(CheckpointStoreIntegrityError);
    expect(existsSync(target.journalPath)).toBe(false);
  });

  it("rejects replay and continuation of a legacy signed empty-store anchor", () => {
    const target = fixture("legacy-anchor");
    const payload: CheckpointPayload = {
      checkpointType: "rsi.store.head",
      createdAt: "2026-08-11T01:00:00.000Z",
      journalSequence: 1,
      keyId: "operator-key-v1",
      previousCheckpointHash: "0".repeat(64),
      storeHeadHash: "0".repeat(64),
      storeHeadSequence: 0,
      storeId: "rsi-production-events",
      version: 1,
    };
    const signature = signCheckpointPayload(payload, primaryKeys.privateKey);
    const checkpointHash = computeCheckpointHash(payload, signature);
    writeEntries(target.journalPath, [{ checkpointHash, payload, signature }]);

    const replacement = new SqliteEventStore(join(target.directory, "different.sqlite"));
    stores.push(replacement);
    expect(verifier(target).verify(replacement)).toMatchObject({
      anchoredThroughSequence: null,
      recordedAnchorSequence: 0,
      status: "INVALID",
      valid: false,
      journal: {
        issues: expect.arrayContaining([expect.objectContaining({ code: "EMPTY_STORE_ANCHOR" })]),
        valid: false,
      },
    });

    appendEvent(replacement, 1);
    expect(verifier(target).verify(replacement)).toMatchObject({
      anchoredThroughSequence: null,
      status: "INVALID",
      valid: false,
      journal: {
        issues: expect.arrayContaining([expect.objectContaining({ code: "EMPTY_STORE_ANCHOR" })]),
      },
    });
    expect(() =>
      signer(target, { checkpointHash, journalSequence: 1 }).append(replacement, {
        createdAt: "2026-08-11T01:01:00.000Z",
      }),
    ).toThrow(CheckpointJournalIntegrityError);
    expect(journalLines(target.journalPath)).toHaveLength(1);
  });
});

describe("journal adversarial verification", () => {
  it("rejects a forged signature even when the attacker recomputes the entry hash", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const entry = JSON.parse(journalLines(target.journalPath)[0] as string) as {
      checkpointHash: string;
      payload: Parameters<typeof computeCheckpointHash>[0];
      signature: string;
    };
    entry.signature = `${entry.signature[0] === "A" ? "B" : "A"}${entry.signature.slice(1)}`;
    entry.checkpointHash = computeCheckpointHash(entry.payload, entry.signature);
    writeEntries(target.journalPath, [entry]);

    expect(verifier(target).verifyJournal()).toMatchObject({
      valid: false,
      issues: expect.arrayContaining([expect.objectContaining({ code: "INVALID_SIGNATURE" })]),
    });
  });

  it("rejects an expected key that differs from the signing key", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });

    expect(
      verifier(target, { expectedPublicKey: otherKeys.publicKey }).verifyJournal(),
    ).toMatchObject({
      valid: false,
      issues: expect.arrayContaining([expect.objectContaining({ code: "INVALID_SIGNATURE" })]),
    });
  });

  it("pins both the expected key ID and store ID", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });

    expect(verifier(target, { expectedKeyId: "other-key" }).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "WRONG_KEY_ID" })]),
    );
    expect(verifier(target, { expectedStoreId: "other-store" }).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "WRONG_STORE_ID" })]),
    );
  });

  it("rejects signed-payload modification", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const entry = JSON.parse(journalLines(target.journalPath)[0] as string) as {
      checkpointHash: string;
      payload: Parameters<typeof computeCheckpointHash>[0];
      signature: string;
    };
    entry.payload = { ...entry.payload, storeHeadHash: "f".repeat(64) };
    entry.checkpointHash = computeCheckpointHash(entry.payload, entry.signature);
    writeEntries(target.journalPath, [entry]);

    expect(verifier(target).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "INVALID_SIGNATURE" })]),
    );
  });

  it("rejects reordered entries and broken predecessor links", () => {
    const target = fixture();
    const checkpointSigner = signer(target);
    appendEvent(target.store, 1);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    appendEvent(target.store, 2);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:01:00.000Z" });
    const entries = journalLines(target.journalPath).map((line) => JSON.parse(line) as unknown);
    writeEntries(target.journalPath, [entries[1], entries[0]]);

    expect(verifier(target).verifyJournal()).toMatchObject({
      valid: false,
      issues: expect.arrayContaining([
        expect.objectContaining({ code: "JOURNAL_SEQUENCE_GAP" }),
        expect.objectContaining({ code: "PREVIOUS_CHECKPOINT_HASH_MISMATCH" }),
      ]),
    });
  });

  it("rejects deletion from the middle of the journal", () => {
    const target = fixture();
    const checkpointSigner = signer(target);
    for (let index = 1; index <= 3; index += 1) {
      appendEvent(target.store, index);
      checkpointSigner.append(target.store, {
        createdAt: `2026-08-11T01:0${index}:00.000Z`,
      });
    }
    const entries = journalLines(target.journalPath).map((line) => JSON.parse(line) as unknown);
    writeEntries(target.journalPath, [entries[0], entries[2]]);

    expect(verifier(target).verifyJournal()).toMatchObject({
      valid: false,
      issues: expect.arrayContaining([
        expect.objectContaining({ code: "JOURNAL_SEQUENCE_GAP" }),
        expect.objectContaining({ code: "PREVIOUS_CHECKPOINT_HASH_MISMATCH" }),
      ]),
    });
  });

  it("rejects a duplicated journal entry as a sequence and predecessor fork", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const entry = JSON.parse(journalLines(target.journalPath)[0] as string) as unknown;
    writeEntries(target.journalPath, [entry, entry]);

    expect(verifier(target).verifyJournal()).toMatchObject({
      valid: false,
      issues: expect.arrayContaining([
        expect.objectContaining({ code: "JOURNAL_SEQUENCE_GAP" }),
        expect.objectContaining({ code: "PREVIOUS_CHECKPOINT_HASH_MISMATCH" }),
        expect.objectContaining({ code: "STORE_SEQUENCE_NOT_INCREASING" }),
      ]),
    });
  });

  it("detects valid suffix truncation using an externally retained journal head", () => {
    const target = fixture();
    const checkpointSigner = signer(target);
    appendEvent(target.store, 1);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    appendEvent(target.store, 2);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:01:00.000Z" });
    const trustedJournalHead = checkpointSigner.journalHead as CheckpointJournalHead;
    const lines = journalLines(target.journalPath);
    writeFileSync(target.journalPath, `${lines[0]}\n`, "utf8");

    expect(verifier(target, { trustedJournalHead }).verifyJournal()).toMatchObject({
      valid: false,
      truncationProtectedThrough: null,
      issues: expect.arrayContaining([
        expect.objectContaining({ code: "TRUSTED_CHECKPOINT_MISSING" }),
      ]),
    });
  });

  it("reports the externally retained checkpoint through which truncation was checked", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const checkpointSigner = signer(target);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const trustedJournalHead = checkpointSigner.journalHead as CheckpointJournalHead;

    expect(verifier(target, { trustedJournalHead }).verifyJournal()).toMatchObject({
      truncationProtectedThrough: trustedJournalHead,
      valid: true,
    });
  });

  it("rejects partial final appends, noncanonical JSON, invalid timestamps, and unknown fields", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const canonicalLine = journalLines(target.journalPath)[0] as string;
    writeFileSync(target.journalPath, canonicalLine, "utf8");
    expect(verifier(target).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "INVALID_JOURNAL_ENCODING" })]),
    );

    const entry = JSON.parse(canonicalLine) as Record<string, unknown>;
    writeFileSync(target.journalPath, `${canonicalLine} \n`, "utf8");
    expect(verifier(target).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "NON_CANONICAL_ENTRY" })]),
    );

    const invalidTimestamp = structuredClone(entry) as {
      payload: Record<string, unknown>;
    } & Record<string, unknown>;
    invalidTimestamp.payload.createdAt = "2026-08-11T01:00:00Z";
    writeEntries(target.journalPath, [invalidTimestamp]);
    expect(verifier(target).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "INVALID_ENTRY" })]),
    );

    writeEntries(target.journalPath, [{ ...entry, unexpected: true }]);
    expect(verifier(target).verifyJournal().issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "INVALID_ENTRY" })]),
    );
  });
});

describe("store rollback and replacement protection", () => {
  it("rejects a valid replacement store whose anchored-sequence hash differs", () => {
    const target = fixture("original");
    appendEvent(target.store, 1);
    signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const replacementPath = join(target.directory, "replacement.sqlite");
    const replacement = new SqliteEventStore(replacementPath);
    stores.push(replacement);
    replacement.append({
      aggregateId: "agent:attacker",
      eventId: "replacement-event",
      occurredAt: "2026-08-11T00:00:01.000Z",
      payload: { replaced: true },
      type: "run.recorded",
    });

    expect(verifier(target).verify(replacement)).toMatchObject({
      anchoredThroughSequence: null,
      recordedAnchorSequence: 1,
      status: "INVALID",
      valid: false,
      storeIssues: expect.arrayContaining([
        expect.objectContaining({ code: "ANCHORED_HASH_MISMATCH" }),
      ]),
    });
  });

  it("rejects a valid rolled-back store shorter than the signed anchor", () => {
    const target = fixture("original");
    const checkpointSigner = signer(target);
    appendEvent(target.store, 1);
    appendEvent(target.store, 2);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const rollback = new SqliteEventStore(join(target.directory, "rollback.sqlite"));
    stores.push(rollback);
    appendEvent(rollback, 1);

    expect(verifier(target).verify(rollback).storeIssues).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "ANCHORED_EVENT_MISSING" })]),
    );
  });

  it("will not extend a journal from a store that lacks the prior signed anchor", () => {
    const target = fixture("original");
    appendEvent(target.store, 1);
    const originalSigner = signer(target);
    originalSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const replacement = new SqliteEventStore(join(target.directory, "replacement.sqlite"));
    stores.push(replacement);
    replacement.append({
      aggregateId: "agent:attacker",
      eventId: "replacement-1",
      occurredAt: "2026-08-11T00:00:01.000Z",
      payload: {},
      type: "run.recorded",
    });
    replacement.append({
      aggregateId: "agent:attacker",
      eventId: "replacement-2",
      occurredAt: "2026-08-11T00:00:02.000Z",
      payload: {},
      type: "run.recorded",
    });
    const restartedSigner = signer(target, originalSigner.journalHead);

    expect(() =>
      restartedSigner.append(replacement, { createdAt: "2026-08-11T01:01:00.000Z" }),
    ).toThrow(CheckpointStoreIntegrityError);
    expect(journalLines(target.journalPath)).toHaveLength(1);
  });
});

describe("append safety and input validation", () => {
  it("refuses byte and entry capacity overflow before changing the journal", () => {
    const target = fixture();
    writeFileSync(target.journalPath, "x", { mode: 0o600 });
    truncateSync(target.journalPath, MAX_JOURNAL_BYTES - 1);
    const guard = createJournalPathGuard(target.journalPath);

    expect(() => appendJournalBytes(guard, Buffer.from("ab"))).toThrow(JournalFileError);
    expect(statSync(target.journalPath).size).toBe(MAX_JOURNAL_BYTES - 1);
    expect(journalHasEntryCapacity(MAX_JOURNAL_ENTRIES - 1)).toBe(true);
    expect(journalHasEntryCapacity(MAX_JOURNAL_ENTRIES)).toBe(false);
  });

  it("rejects duplicate checkpointing without a new store event", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const checkpointSigner = signer(target);
    checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });

    expect(() =>
      checkpointSigner.append(target.store, { createdAt: "2026-08-11T01:01:00.000Z" }),
    ).toThrow(CheckpointStoreIntegrityError);
    expect(journalLines(target.journalPath)).toHaveLength(1);
  });

  it("rejects a stale or forked expected journal head", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const firstWriter = signer(target);
    const staleWriter = signer(target);
    firstWriter.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" });
    appendEvent(target.store, 2);

    expect(() =>
      staleWriter.append(target.store, { createdAt: "2026-08-11T01:01:00.000Z" }),
    ).toThrow(CheckpointJournalIntegrityError);
    expect(journalLines(target.journalPath)).toHaveLength(1);
  });

  it("refuses to append through an existing lock", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    writeFileSync(`${target.journalPath}.lock`, "another-writer\n", { mode: 0o600 });

    expect(() =>
      signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" }),
    ).toThrow(CheckpointConcurrencyError);
  });

  it("pins the journal parent and never writes through a later directory symlink", () => {
    const directory = mkdtempSync(join(tmpdir(), "rsi-checkpoint-parent-"));
    directories.push(directory);
    const journalParent = join(directory, "anchors");
    const movedParent = join(directory, "anchors-original");
    const replacementTarget = join(directory, "attacker-target");
    mkdirSync(journalParent, { mode: 0o700 });
    mkdirSync(replacementTarget, { mode: 0o700 });
    const storePath = join(directory, "events.sqlite");
    const store = new SqliteEventStore(storePath);
    stores.push(store);
    appendEvent(store, 1);
    const target: Fixture = {
      directory,
      journalPath: join(journalParent, "events.checkpoints.jsonl"),
      store,
      storePath,
    };
    const checkpointSigner = signer(target);

    renameSync(journalParent, movedParent);
    symlinkSync(replacementTarget, journalParent, "dir");

    expect(() => checkpointSigner.append(store, { createdAt: "2026-08-11T01:00:00.000Z" })).toThrow(
      /parent was removed, replaced, or redirected/,
    );
    expect(existsSync(join(replacementTarget, "events.checkpoints.jsonl"))).toBe(false);
    expect(existsSync(join(replacementTarget, "events.checkpoints.jsonl.lock"))).toBe(false);
  });

  it("reports an unsafe path when a verifier's pinned parent is replaced", () => {
    const directory = mkdtempSync(join(tmpdir(), "rsi-checkpoint-parent-"));
    directories.push(directory);
    const journalParent = join(directory, "anchors");
    const movedParent = join(directory, "anchors-original");
    const replacementTarget = join(directory, "attacker-target");
    mkdirSync(journalParent, { mode: 0o700 });
    mkdirSync(replacementTarget, { mode: 0o700 });
    const storePath = join(directory, "events.sqlite");
    const store = new SqliteEventStore(storePath);
    stores.push(store);
    appendEvent(store, 1);
    const target: Fixture = {
      directory,
      journalPath: join(journalParent, "events.checkpoints.jsonl"),
      store,
      storePath,
    };
    signer(target).append(store, { createdAt: "2026-08-11T01:00:00.000Z" });
    const checkpointVerifier = verifier(target);

    renameSync(journalParent, movedParent);
    symlinkSync(replacementTarget, journalParent, "dir");

    expect(checkpointVerifier.verify(store)).toMatchObject({
      valid: false,
      journal: {
        issues: expect.arrayContaining([expect.objectContaining({ code: "UNSAFE_JOURNAL_PATH" })]),
      },
    });
    expect(existsSync(join(replacementTarget, "events.checkpoints.jsonl"))).toBe(false);
  });

  it("rejects journal symlinks, hard links, and the SQLite path itself", () => {
    const target = fixture();
    const realJournal = join(target.directory, "real.jsonl");
    writeFileSync(realJournal, "", { mode: 0o600 });
    const symbolicJournal = join(target.directory, "symbolic.jsonl");
    symlinkSync(realJournal, symbolicJournal);
    expect(
      () =>
        new CheckpointVerifier({
          expectedKeyId: "operator-key-v1",
          expectedPublicKey: primaryKeys.publicKey,
          expectedStoreId: "rsi-production-events",
          journalPath: symbolicJournal,
        }),
    ).toThrow(InvalidCheckpointError);

    const hardJournal = join(target.directory, "hard.jsonl");
    linkSync(realJournal, hardJournal);
    expect(
      () =>
        new CheckpointVerifier({
          expectedKeyId: "operator-key-v1",
          expectedPublicKey: primaryKeys.publicKey,
          expectedStoreId: "rsi-production-events",
          journalPath: hardJournal,
        }),
    ).toThrow(InvalidCheckpointError);

    appendEvent(target.store, 1);
    const sqliteAsJournal = new CheckpointSigner({
      expectedJournalHead: null,
      journalPath: target.storePath,
      keyId: "operator-key-v1",
      privateKey: primaryKeys.privateKey,
      storeId: "rsi-production-events",
    });
    expect(() =>
      sqliteAsJournal.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" }),
    ).toThrow(InvalidCheckpointError);

    const writableParent = join(target.directory, "writable-parent");
    mkdirSync(writableParent, { mode: 0o700 });
    chmodSync(writableParent, 0o770);
    expect(
      () =>
        new CheckpointVerifier({
          expectedKeyId: "operator-key-v1",
          expectedPublicKey: primaryKeys.publicKey,
          expectedStoreId: "rsi-production-events",
          journalPath: join(writableParent, "journal.jsonl"),
        }),
    ).toThrow(InvalidCheckpointError);
  });

  it("strictly validates identifiers, timestamps, key algorithms, and expected heads", () => {
    const target = fixture();
    expect(
      () =>
        new CheckpointSigner({
          expectedJournalHead: null,
          journalPath: target.journalPath,
          keyId: "bad key id",
          privateKey: primaryKeys.privateKey,
          storeId: "rsi-production-events",
        }),
    ).toThrow(InvalidCheckpointError);
    expect(
      () =>
        new CheckpointSigner({
          expectedJournalHead: null,
          journalPath: target.journalPath,
          keyId: "operator-key-v1",
          privateKey: rsaKeys.privateKey,
          storeId: "rsi-production-events",
        }),
    ).toThrow(InvalidCheckpointError);
    expect(
      () =>
        new CheckpointVerifier({
          expectedKeyId: "operator-key-v1",
          expectedPublicKey: rsaKeys.publicKey,
          expectedStoreId: "rsi-production-events",
          journalPath: target.journalPath,
        }),
    ).toThrow(InvalidCheckpointError);
    expect(
      () =>
        new CheckpointSigner({
          expectedJournalHead: { checkpointHash: "A".repeat(64), journalSequence: 1 },
          journalPath: target.journalPath,
          keyId: "operator-key-v1",
          privateKey: primaryKeys.privateKey,
          storeId: "rsi-production-events",
        }),
    ).toThrow(InvalidCheckpointError);

    appendEvent(target.store, 1);
    expect(() =>
      signer(target).append(target.store, { createdAt: "2026-08-11T01:00:00Z" }),
    ).toThrow(InvalidCheckpointError);
  });

  it("rejects timestamp regression and a changed signing key on journal continuation", () => {
    const target = fixture();
    appendEvent(target.store, 1);
    const firstSigner = signer(target);
    firstSigner.append(target.store, { createdAt: "2026-08-11T02:00:00.000Z" });
    appendEvent(target.store, 2);
    expect(() =>
      firstSigner.append(target.store, { createdAt: "2026-08-11T01:00:00.000Z" }),
    ).toThrow(InvalidCheckpointError);

    expect(() =>
      signer(target, firstSigner.journalHead, otherKeys.privateKey).append(target.store, {
        createdAt: "2026-08-11T03:00:00.000Z",
      }),
    ).toThrow(CheckpointJournalIntegrityError);
    expect(journalLines(target.journalPath)).toHaveLength(1);
  });
});
