import { Buffer } from "node:buffer";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import { createSanitizedStateEvidence } from "../../backup/src/index.js";
import {
  makeFixture as makeBackupFixture,
  unpackArchive as unpackBackupArchive,
} from "../../backup/test/fixtures.js";
import { SqliteEventStore } from "../../store/src/index.js";
import {
  EventArchiveError,
  createSanitizedEventArchive,
  importSanitizedEventArchiveToEmptyStore,
  restoreSanitizedEventArchive,
  verifySanitizedEventArchive,
  type EventArchiveImportTarget,
} from "../src/index.js";
import { canonicalJson, sha256 } from "../src/canonical.js";
import {
  MAX_EVENT_LINE_BYTES,
  MAX_EVENT_RECORDS,
  parseEventJournal,
  parseStateEvidenceManifestEnvelope,
} from "../src/schema.js";
import type { JsonValue, SanitizedEventArchiveReceiptV1 } from "../src/types.js";
import {
  PRIOR_SESSION_ID,
  clone,
  digest,
  makeFixture,
  refreshStateEvidenceProof,
  repackArchive,
  trustFor,
  unrelatedUuid,
  unpackArchive,
} from "./fixtures.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    chmodSync(directory, 0o700);
    rmSync(directory, { force: true, recursive: true });
  }
});

function makeDirectory(): string {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "rsi-event-archive-")));
  temporaryDirectories.push(directory);
  return directory;
}

function archivePath(directory: string, name = "events.rsievents"): string {
  return join(directory, name);
}

function writePrivate(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function trustWithBytes(
  fixture: ReturnType<typeof makeFixture>,
  receipt: SanitizedEventArchiveReceiptV1,
): ReturnType<typeof trustFor> {
  return trustFor(fixture, receipt);
}

describe("sanitized event archive", () => {
  it("accepts the exact signed manifest envelope emitted by @rsi/backup", async () => {
    const directory = makeDirectory();
    const fixture = makeBackupFixture();
    const path = archivePath(directory, "state-evidence.rsibackup");
    const receipt = await createSanitizedStateEvidence({
      destinationPath: path,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const raw = unpackBackupArchive(readFileSync(path));
    const parsed = parseStateEvidenceManifestEnvelope({
      manifest: raw.manifest,
      signature: raw.signature,
    });

    expect(sha256(canonicalJson(parsed.manifest as unknown as JsonValue))).toBe(
      receipt.manifestSha256,
    );
    expect(parsed.manifest).toMatchObject({
      backupId: receipt.backupId,
      profile: receipt.profile,
      session: { id: receipt.sessionId },
      signer: { publicKeyFingerprintSha256: receipt.signerFingerprintSha256 },
    });
  });

  it("creates, verifies, restores, and transactionally reimports every exact event", async () => {
    const directory = makeDirectory();
    const path = archivePath(directory);
    const fixture = makeFixture();
    const receipt = await createSanitizedEventArchive({
      createdAt: "2026-08-14T12:21:00.000Z",
      destinationPath: path,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const trust = trustFor(fixture, receipt);

    expect(receipt).toMatchObject({
      componentRole: "sanitized-event-archive",
      eventCount: 4,
      profile: "production-observer",
      sessionId: fixture.snapshot.sessionId,
      stateEvidenceBackupId: fixture.stateEvidence.receipt.backupId,
      storeId: "observer-store-v1",
    });
    await expect(verifySanitizedEventArchive({ archivePath: path, trust })).resolves.toMatchObject({
      eventCount: 4,
      status: "verified-restorable-event-archive",
      headHash: fixture.snapshot.stateEvidence.eventState.headHash,
    });

    const restored = join(directory, "restored");
    await expect(
      restoreSanitizedEventArchive({
        archivePath: path,
        destinationDirectory: restored,
        trust,
      }),
    ).resolves.toMatchObject({ restoredFileCount: 2 });
    expect(
      readFileSync(join(restored, "sanitized-events.v1.jsonl"), "utf8").trim().split("\n"),
    ).toHaveLength(4);
    expect(
      JSON.parse(readFileSync(join(restored, "event-archive-manifest.v1.json"), "utf8")),
    ).toMatchObject({ manifest: { componentRole: "sanitized-event-archive" } });

    const restoredStore = new SqliteEventStore(join(directory, "restored.sqlite"));
    await expect(
      importSanitizedEventArchiveToEmptyStore({ archivePath: path, target: restoredStore, trust }),
    ).resolves.toMatchObject({ importedEventCount: 4, status: "imported-and-verified" });
    expect(restoredStore.verifyIntegrity()).toMatchObject({
      eventCount: 4,
      headHash: receipt.headHash,
      headSequence: 4,
      valid: true,
    });
    expect(restoredStore.list()).toEqual(fixture.snapshot.events);

    await expect(
      importSanitizedEventArchiveToEmptyStore({ archivePath: path, target: restoredStore, trust }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });
    expect(restoredStore.verifyIntegrity().eventCount).toBe(4);
    await expect(
      restoreSanitizedEventArchive({
        archivePath: path,
        destinationDirectory: restored,
        trust,
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });
    restoredStore.close();
  });

  it("rejects unknown content, unknown event types, chain gaps, and mismatched bindings", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const base = clone(fixture.snapshot) as any;

    base.events[0].payload.capture.rawProviderText = "forbidden";
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "raw"),
        signer: fixture.signer,
        snapshot: base,
      }),
    ).rejects.toBeInstanceOf(EventArchiveError);

    const unknown = clone(fixture.snapshot) as any;
    unknown.events[0].type = "run.completed";
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "unknown"),
        signer: fixture.signer,
        snapshot: unknown,
      }),
    ).rejects.toBeInstanceOf(EventArchiveError);

    const gap = clone(fixture.snapshot) as any;
    gap.events[1].sequence = 9;
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "gap"),
        signer: fixture.signer,
        snapshot: gap,
      }),
    ).rejects.toMatchObject({ code: "INTEGRITY_MISMATCH" });

    const profile = clone(fixture.snapshot) as any;
    profile.events[2].payload.capture.profile = "canary";
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "profile"),
        signer: fixture.signer,
        snapshot: profile,
      }),
    ).rejects.toMatchObject({ code: "INTEGRITY_MISMATCH" });

    const tail = clone(fixture.snapshot) as any;
    tail.events = tail.events.slice(0, 2);
    tail.stateEvidence.eventState.eventCount = 2;
    tail.stateEvidence.eventState.headSequence = 2;
    tail.stateEvidence.eventState.headHash = tail.events[1].eventHash;
    tail.stateEvidence.manifestEnvelope.manifest.eventStateEvidence.eventCount = 2;
    tail.stateEvidence.manifestEnvelope.manifest.eventStateEvidence.headSequence = 2;
    tail.stateEvidence.manifestEnvelope.manifest.eventStateEvidence.headHash =
      tail.events[1].eventHash;
    tail.stateEvidence.manifestEnvelope.manifest.checkpoint.storeHeadSequence = 2;
    tail.stateEvidence.manifestEnvelope.manifest.checkpoint.storeHeadHash =
      tail.events[1].eventHash;
    refreshStateEvidenceProof(fixture, tail.stateEvidence);
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "tail"),
        signer: fixture.signer,
        snapshot: tail,
      }),
    ).rejects.toMatchObject({ code: "INTEGRITY_MISMATCH" });

    const genericBytes = { ...clone(fixture.snapshot), databaseBytes: [1, 2, 3] } as any;
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "bytes"),
        signer: fixture.signer,
        snapshot: genericBytes,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("rejects accessors, proxies, Buffer/SAB keys, sparse arrays, and oversized collections", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const accessor = clone(fixture.snapshot) as any;
    Object.defineProperty(accessor.events[0], "eventId", {
      enumerable: true,
      get: () => "40000000-0000-4000-8000-000000000001",
    });
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "accessor"),
        signer: fixture.signer,
        snapshot: accessor,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const proxied = clone(fixture.snapshot) as any;
    proxied.events[0] = new Proxy(proxied.events[0], {});
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "proxy"),
        signer: fixture.signer,
        snapshot: proxied,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "buffer"),
        signer: { ...fixture.signer, publicKeySpkiDer: Buffer.from(fixture.publicKeyDer) },
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    if (typeof SharedArrayBuffer !== "undefined") {
      const shared = new Uint8Array(new SharedArrayBuffer(fixture.publicKeyDer.length));
      shared.set(fixture.publicKeyDer);
      await expect(
        createSanitizedEventArchive({
          createdAt: "2026-08-14T12:21:00.000Z",
          destinationPath: archivePath(directory, "shared"),
          signer: { ...fixture.signer, publicKeySpkiDer: shared },
          snapshot: fixture.snapshot,
        }),
      ).rejects.toMatchObject({ code: "INPUT_INVALID" });

      Object.defineProperty(shared, "buffer", {
        value: new ArrayBuffer(fixture.publicKeyDer.length),
      });
      await expect(
        createSanitizedEventArchive({
          createdAt: "2026-08-14T12:21:00.000Z",
          destinationPath: archivePath(directory, "shadowed-shared"),
          signer: { ...fixture.signer, publicKeySpkiDer: shared },
          snapshot: fixture.snapshot,
        }),
      ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    }

    let byteLengthAccessorCalled = false;
    const accessorBytes = Uint8Array.from(fixture.publicKeyDer);
    Object.defineProperty(accessorBytes, "byteLength", {
      get: () => {
        byteLengthAccessorCalled = true;
        return fixture.publicKeyDer.length;
      },
    });
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "byte-accessor"),
        signer: { ...fixture.signer, publicKeySpkiDer: accessorBytes },
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    expect(byteLengthAccessorCalled).toBe(false);

    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "sign-proxy"),
        signer: { ...fixture.signer, sign: new Proxy(fixture.signer.sign, {}) },
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const sparse = clone(fixture.snapshot) as any;
    delete sparse.events[1];
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "sparse"),
        signer: fixture.signer,
        snapshot: sparse,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const oversized = clone(fixture.snapshot) as any;
    oversized.events = Array.from(
      { length: MAX_EVENT_RECORDS + 1 },
      () => fixture.snapshot.events[0],
    );
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "oversized"),
        signer: fixture.signer,
        snapshot: oversized,
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_BOUNDS" });

    const unprovenSession = clone(fixture.snapshot) as any;
    unprovenSession.sessionState = "accepted";
    unprovenSession.stateEvidence.sessionState = "accepted";
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "unproven-session"),
        signer: fixture.signer,
        snapshot: unprovenSession,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const invalidProofSignature = clone(fixture.snapshot) as any;
    const proofSignature = invalidProofSignature.stateEvidence.manifestEnvelope.signature as string;
    invalidProofSignature.stateEvidence.manifestEnvelope.signature = `${proofSignature[0] === "A" ? "B" : "A"}${proofSignature.slice(1)}`;
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "invalid-proof-signature"),
        signer: fixture.signer,
        snapshot: invalidProofSignature,
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });

    expect(() =>
      parseEventJournal(
        Buffer.concat([Buffer.alloc(MAX_EVENT_LINE_BYTES, 0x61), Buffer.from("\n")]),
      ),
    ).toThrowError(expect.objectContaining({ code: "ARCHIVE_BOUNDS" }));
  });

  it("fails closed on file tamper, truncation, trailing bytes, and an invalid signature", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const originalPath = archivePath(directory);
    const receipt = await createSanitizedEventArchive({
      createdAt: "2026-08-14T12:21:00.000Z",
      destinationPath: originalPath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const original = readFileSync(originalPath);

    for (const [name, bytes] of [
      ["truncated", original.subarray(0, original.length - 1)],
      ["trailing", Buffer.concat([original, Buffer.from([0])])],
      ["tampered", Buffer.from(original)],
    ] as const) {
      const mutated = Buffer.from(bytes);
      if (name === "tampered") {
        const index = mutated.length - 2;
        mutated[index] = mutated[index]! ^ 1;
      }
      const path = archivePath(directory, name);
      writePrivate(path, mutated);
      const adjusted = Object.freeze({
        ...receipt,
        archiveSha256: sha256(mutated),
        archiveSizeBytes: mutated.length,
      });
      await expect(
        verifySanitizedEventArchive({
          archivePath: path,
          trust: trustWithBytes(fixture, adjusted),
        }),
      ).rejects.toBeInstanceOf(EventArchiveError);
    }

    const raw = unpackArchive(original);
    (raw.manifest as any).createdAt = "2026-08-14T12:22:00.000Z";
    const unsigned = repackArchive(raw, fixture.privateKey, receipt, false);
    const unsignedPath = archivePath(directory, "unsigned");
    writePrivate(unsignedPath, unsigned.bytes);
    await expect(
      verifySanitizedEventArchive({
        archivePath: unsignedPath,
        trust: trustFor(fixture, unsigned.receipt),
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("rejects validly re-signed semantic attacks against schemas and companion bindings", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const originalPath = archivePath(directory);
    const receipt = await createSanitizedEventArchive({
      createdAt: "2026-08-14T12:21:00.000Z",
      destinationPath: originalPath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const original = readFileSync(originalPath);

    const scope = unpackArchive(original);
    (scope.manifest as any).recoveryCompleteness = "complete";
    const scopeAttack = repackArchive(scope, fixture.privateKey, receipt);
    const scopePath = archivePath(directory, "scope");
    writePrivate(scopePath, scopeAttack.bytes);
    await expect(
      verifySanitizedEventArchive({
        archivePath: scopePath,
        trust: trustFor(fixture, scopeAttack.receipt),
      }),
    ).rejects.toBeInstanceOf(EventArchiveError);

    const payload = unpackArchive(original);
    const lines = payload.eventBytes.toString("utf8").trim().split("\n");
    const first = JSON.parse(lines[0]!) as any;
    first.payload.capture.rawProviderText = "forbidden";
    lines[0] = canonicalJson(first as JsonValue);
    payload.eventBytes = Buffer.from(`${lines.join("\n")}\n`, "utf8");
    (payload.manifest.artifact as any).sha256 = sha256(payload.eventBytes);
    (payload.manifest.artifact as any).sizeBytes = payload.eventBytes.length;
    const payloadAttack = repackArchive(payload, fixture.privateKey, receipt);
    const payloadPath = archivePath(directory, "payload");
    writePrivate(payloadPath, payloadAttack.bytes);
    await expect(
      verifySanitizedEventArchive({
        archivePath: payloadPath,
        trust: trustFor(fixture, payloadAttack.receipt),
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const state = unpackArchive(original);
    (state.manifest.stateEvidence as any).backupId = unrelatedUuid();
    const stateAttack = repackArchive(state, fixture.privateKey, receipt);
    const statePath = archivePath(directory, "state");
    writePrivate(statePath, stateAttack.bytes);
    await expect(
      verifySanitizedEventArchive({
        archivePath: statePath,
        trust: trustFor(fixture, stateAttack.receipt),
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });

    const head = unpackArchive(original);
    (head.manifest.store as any).headHash = digest("rewritten-head");
    const headAttack = repackArchive(head, fixture.privateKey, receipt);
    const headPath = archivePath(directory, "head");
    writePrivate(headPath, headAttack.bytes);
    await expect(
      verifySanitizedEventArchive({
        archivePath: headPath,
        trust: trustFor(fixture, headAttack.receipt),
      }),
    ).rejects.toBeInstanceOf(EventArchiveError);

    const session = unpackArchive(original);
    (session.manifest.session as any).state = "accepted";
    const sessionAttack = repackArchive(session, fixture.privateKey, receipt);
    const sessionPath = archivePath(directory, "session");
    writePrivate(sessionPath, sessionAttack.bytes);
    await expect(
      verifySanitizedEventArchive({
        archivePath: sessionPath,
        trust: trustFor(fixture, sessionAttack.receipt),
      }),
    ).rejects.toBeInstanceOf(EventArchiveError);
  });

  it("detects archive rollback through the independently retained latest receipt", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const firstPath = archivePath(directory, "first");
    const secondPath = archivePath(directory, "second");
    const firstReceipt = await createSanitizedEventArchive({
      createdAt: "2026-08-14T12:21:00.000Z",
      destinationPath: firstPath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const secondReceipt = await createSanitizedEventArchive({
      createdAt: "2026-08-14T12:22:00.000Z",
      destinationPath: secondPath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    expect(firstReceipt.archiveId).not.toBe(secondReceipt.archiveId);
    await expect(
      verifySanitizedEventArchive({
        archivePath: firstPath,
        trust: trustFor(fixture, secondReceipt),
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
  });

  it("publishes create-only under concurrency and rejects links, directories, and loose modes", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const concurrentPath = archivePath(directory, "concurrent");
    const attempts = await Promise.allSettled([
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: concurrentPath,
        signer: fixture.signer,
        snapshot: fixture.snapshot,
      }),
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: concurrentPath,
        signer: fixture.signer,
        snapshot: fixture.snapshot,
      }),
    ]);
    expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((result) => result.status === "rejected")).toHaveLength(1);
    const receipt = attempts.find((result) => result.status === "fulfilled")!.value;

    const alias = archivePath(directory, "hardlink");
    linkSync(concurrentPath, alias);
    await expect(
      verifySanitizedEventArchive({
        archivePath: concurrentPath,
        trust: trustFor(fixture, receipt),
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });
    rmSync(alias);

    const symlink = archivePath(directory, "symlink");
    symlinkSync(concurrentPath, symlink);
    await expect(
      verifySanitizedEventArchive({
        archivePath: symlink,
        trust: trustFor(fixture, receipt),
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });

    chmodSync(concurrentPath, 0o644);
    await expect(
      verifySanitizedEventArchive({
        archivePath: concurrentPath,
        trust: trustFor(fixture, receipt),
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });
    chmodSync(concurrentPath, 0o600);

    const directoryPath = archivePath(directory, "directory");
    mkdirSync(directoryPath, { mode: 0o700 });
    await expect(
      verifySanitizedEventArchive({
        archivePath: directoryPath,
        trust: trustFor(fixture, receipt),
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });
  });

  it("verifies before any restore/import mutation and rolls back a failed reimport", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const path = archivePath(directory);
    const receipt = await createSanitizedEventArchive({
      createdAt: "2026-08-14T12:21:00.000Z",
      destinationPath: path,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const trust = trustFor(fixture, receipt);
    const badTrust = {
      ...trust,
      receipt: { ...receipt, headHash: digest("wrong-head") },
    };
    const destination = join(directory, "must-not-exist");
    await expect(
      restoreSanitizedEventArchive({
        archivePath: path,
        destinationDirectory: destination,
        trust: badTrust,
      }),
    ).rejects.toBeInstanceOf(EventArchiveError);
    expect(existsSync(destination)).toBe(false);

    const storePath = join(directory, "rollback.sqlite");
    const store = new SqliteEventStore(storePath);
    const fixtureConnection = new DatabaseSync(storePath);
    fixtureConnection.exec(`
      CREATE TRIGGER synthetic_second_insert_failure
      BEFORE INSERT ON rsi_events WHEN NEW.sequence = 2
      BEGIN
        SELECT RAISE(ABORT, 'synthetic import failure');
      END;
    `);
    fixtureConnection.close();
    await expect(
      importSanitizedEventArchiveToEmptyStore({
        archivePath: path,
        target: store,
        trust,
      }),
    ).rejects.toMatchObject({
      code: "IMPORT_TARGET_INVALID",
      message: "Event-store import failed",
    });
    expect(store.verifyIntegrity()).toMatchObject({ eventCount: 0, valid: true });

    const fakeTarget: EventArchiveImportTarget = {
      append: () => fixture.snapshot.events[0],
      list: () => [],
      verifyIntegrity: () => ({
        errors: [],
        eventCount: 0,
        headHash: "0".repeat(64),
        headSequence: 0,
        valid: true,
      }),
      withExclusiveTransaction: (operation) => operation(),
    };
    await expect(
      importSanitizedEventArchiveToEmptyStore({ archivePath: path, target: fakeTarget, trust }),
    ).rejects.toMatchObject({ code: "IMPORT_TARGET_INVALID" });
    store.close();
  });

  it("does not publish when signing fails or when the state-evidence receipt is out of bounds", async () => {
    const directory = makeDirectory();
    const fixture = makeFixture();
    const signerFailurePath = archivePath(directory, "signer-failure");
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: signerFailurePath,
        signer: {
          ...fixture.signer,
          sign: () => {
            throw new Error("sensitive internal signer detail");
          },
        },
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "SIGNER_FAILED", message: "Archive signer failed" });
    expect(existsSync(signerFailurePath)).toBe(false);

    const invalid = clone(fixture.snapshot) as any;
    invalid.stateEvidence.receipt.archiveSizeBytes = 6 * 1024 * 1024;
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(directory, "invalid-state-receipt"),
        signer: fixture.signer,
        snapshot: invalid,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("rejects an unsafe parent before publishing", async () => {
    const directory = makeDirectory();
    const unsafe = join(directory, "unsafe-parent");
    mkdirSync(unsafe, { mode: 0o777 });
    chmodSync(unsafe, 0o777);
    const fixture = makeFixture();
    await expect(
      createSanitizedEventArchive({
        createdAt: "2026-08-14T12:21:00.000Z",
        destinationPath: archivePath(unsafe),
        signer: fixture.signer,
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });
    chmodSync(unsafe, 0o700);
  });
});
