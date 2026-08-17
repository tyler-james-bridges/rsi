import { randomBytes, randomUUID } from "node:crypto";
import {
  chmodSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  CaptureRegistryClosedError,
  CaptureRegistryConflictError,
  CaptureRegistryIntegrityError,
  CaptureRegistrySecurityError,
  CaptureRegistryValidationError,
  MAX_CAPTURE_REGISTRY_RECORDS,
  MAX_REGISTRY_OPERATION_LIMIT,
  MAX_SOURCE_IDENTIFIERS,
  MAX_SOURCE_IDENTIFIER_BYTES,
  MAX_X_EDIT_IDS,
  MAX_X_NEXT_TOKEN_CHARACTERS,
  MAX_X_POST_IDS,
  MAX_X_USER_IDS,
  SqliteCaptureRegistry,
  isSqliteCaptureRegistry,
  type BeginCaptureAttemptInput,
  type CaptureDeletionReceiptV1,
  type CaptureSourceIdentifiers,
  type CommitCaptureInput,
} from "../src/index.js";

const ACQUIRED_AT = "2026-08-14T08:00:00.000Z";
const COMMITTED_AT = "2026-08-14T08:01:00.000Z";
const EXPIRES_AT = "2026-08-14T10:00:00.000Z";
const DELETED_AT = "2026-08-14T10:00:00.000Z";
const PROFILE = "dev" as const;
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

function makePath(prefix = "rsi-capture-registry-test-"): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return join(directory, "registry.sqlite");
}

function openTestRegistry(
  options: Readonly<{
    path: string;
    registryKey: Uint8Array;
    expectedProfile?: "canary" | "dev" | "production-observer";
  }>,
): SqliteCaptureRegistry {
  return SqliteCaptureRegistry.open({
    ...options,
    expectedProfile: options.expectedProfile ?? PROFILE,
  });
}

function beginInput(overrides: Partial<BeginCaptureAttemptInput> = {}): BeginCaptureAttemptInput {
  return {
    acquiredAt: ACQUIRED_AT,
    attemptId: randomUUID(),
    expiresAt: EXPIRES_AT,
    lane: "discovery",
    profile: PROFILE,
    requestFingerprint: `sha256:${"ab".repeat(32)}`,
    sessionId: randomUUID(),
    source: "x",
    ...overrides,
  };
}

function xIdentifiers(): Extract<CaptureSourceIdentifiers, { source: "x" }> {
  return {
    editIds: ["7000000000000000001", "7000000000000000002"],
    nextToken: "next-token_registry-private-marker_1",
    postIds: ["9000000000000000001"],
    source: "x",
    userIds: ["8000000000000000001"],
  };
}

function commitInput(
  attemptId: string,
  overrides: Partial<CommitCaptureInput> = {},
): CommitCaptureInput {
  return {
    attemptId,
    captureId: randomBytes(16).toString("hex"),
    committedAt: COMMITTED_AT,
    sourceIdentifiers: xIdentifiers(),
    ...overrides,
  };
}

function deletionReceipt(
  captureId: string,
  overrides: Partial<CaptureDeletionReceiptV1> = {},
): CaptureDeletionReceiptV1 {
  return {
    captureId,
    deletedAt: DELETED_AT,
    keyDestroyed: true,
    reason: "explicit",
    schemaVersion: 1,
    state: "deleted",
    ...overrides,
  };
}

describe("SqliteCaptureRegistry", () => {
  it("round-trips deterministic private references without plaintext identifiers on disk", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const RuntimeRegistry = SqliteCaptureRegistry as unknown as new (
      opened: object,
      keys: object,
      profile: "dev",
      constructionToken: object,
    ) => SqliteCaptureRegistry;
    expect(() => new RuntimeRegistry({}, {}, "dev", Object.freeze({}))).toThrow(
      CaptureRegistryIntegrityError,
    );
    const forged = Object.create(SqliteCaptureRegistry.prototype) as SqliteCaptureRegistry;
    expect(isSqliteCaptureRegistry(forged)).toBe(false);
    expect(() => forged.verifyIntegrity()).toThrow(CaptureRegistryIntegrityError);
    expect(() => forged.close()).toThrow(CaptureRegistryIntegrityError);

    const registry = openTestRegistry({ path, registryKey });
    expect(isSqliteCaptureRegistry(registry)).toBe(true);
    expect(isSqliteCaptureRegistry(Object.create(SqliteCaptureRegistry.prototype))).toBe(false);
    expect(isSqliteCaptureRegistry({ getAttempt: () => undefined })).toBe(false);
    const first = beginInput();
    const second = beginInput({ sessionId: first.sessionId });
    const firstCommit = commitInput(first.attemptId);
    const secondCommit = commitInput(second.attemptId);

    expect(registry.beginAttempt(first)).toMatchObject({ state: "pending", ...first });
    registry.beginAttempt(second);
    expect(registry.commitCapture(firstCommit)).toMatchObject({
      ...firstCommit,
      state: "committed",
    });
    registry.commitCapture(secondCommit);
    expect(registry.listCommittedCaptureIds()).toEqual([
      firstCommit.captureId,
      secondCommit.captureId,
    ]);
    expect(registry.listCommittedCaptures()).toEqual([
      { attemptId: first.attemptId, captureId: firstCommit.captureId },
      { attemptId: second.attemptId, captureId: secondCommit.captureId },
    ]);
    expect(registry.listSessionCommittedCaptures(first.sessionId)).toEqual(
      registry.listCommittedCaptures(),
    );
    expect(registry.getSessionStateSummary(first.sessionId)).toEqual({
      committed: 2,
      pending: 0,
      profile: "dev",
      removed: 0,
      schemaVersion: 1,
      sessionId: first.sessionId,
      total: 2,
    });
    registry.close();

    const onDisk = readFileSync(path);
    for (const secret of [
      first.attemptId,
      first.sessionId,
      first.requestFingerprint,
      firstCommit.captureId,
      "next-token_registry-private-marker_1",
      "7000000000000000001",
    ]) {
      expect(onDisk.includes(Buffer.from(secret))).toBe(false);
    }

    const reopened = openTestRegistry({ path, registryKey });
    expect(reopened.listCommittedCaptureIds()).toEqual([
      firstCommit.captureId,
      secondCommit.captureId,
    ]);
    reopened.close();
  });

  it("binds even an empty database to its dedicated key and rejects tampering or truncation", () => {
    const emptyPath = makePath();
    const emptyKey = randomBytes(32);
    openTestRegistry({ path: emptyPath, registryKey: emptyKey }).close();
    expect(() => openTestRegistry({ path: emptyPath, registryKey: randomBytes(32) })).toThrow(
      CaptureRegistryIntegrityError,
    );

    for (const attack of ["ciphertext", "tail"] as const) {
      const path = makePath();
      const registryKey = randomBytes(32);
      const registry = openTestRegistry({ path, registryKey });
      const attempt = beginInput();
      registry.beginAttempt(attempt);
      registry.commitCapture(commitInput(attempt.attemptId));
      registry.close();

      const attacker = new DatabaseSync(path);
      if (attack === "ciphertext") {
        attacker.exec(
          "UPDATE rsi_capture_registry_records SET ciphertext = zeroblob(length(ciphertext)) WHERE sequence = 1",
        );
      } else {
        attacker.exec("DELETE FROM rsi_capture_registry_records WHERE sequence = 1");
      }
      attacker.close();
      expect(() => openTestRegistry({ path, registryKey })).toThrow(CaptureRegistryIntegrityError);
    }
  });

  it("binds the database and every attempt to exactly one runtime profile", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const canary = openTestRegistry({ expectedProfile: "canary", path, registryKey });

    expect(() => canary.beginAttempt(beginInput({ profile: "production-observer" }))).toThrow(
      CaptureRegistryConflictError,
    );
    expect(canary.verifyIntegrity()).toMatchObject({ recordCount: 0, valid: true });
    canary.beginAttempt(beginInput({ profile: "canary" }));
    canary.close();

    expect(() =>
      openTestRegistry({ expectedProfile: "production-observer", path, registryKey }),
    ).toThrow(CaptureRegistryIntegrityError);
    const reopened = openTestRegistry({ expectedProfile: "canary", path, registryKey });
    expect(reopened.verifyIntegrity()).toMatchObject({ recordCount: 1, valid: true });
    reopened.close();
  });

  it("makes begin and commit retries idempotent while conflicting changes fail closed", async () => {
    const registry = openTestRegistry({
      path: makePath(),
      registryKey: randomBytes(32),
    });
    const attempt = beginInput();
    const commit = commitInput(attempt.attemptId);

    const begins = await Promise.all(
      Array.from({ length: 8 }, async () => registry.beginAttempt(attempt)),
    );
    expect(begins.every((record) => record.state === "pending")).toBe(true);
    for (const changed of [
      { ...attempt, acquiredAt: "2026-08-14T08:00:00.001Z" },
      { ...attempt, expiresAt: "2026-08-14T09:59:59.999Z" },
      { ...attempt, requestFingerprint: `sha256:${"cd".repeat(32)}` as const },
      { ...attempt, sessionId: randomUUID() },
      { ...attempt, source: "fixture" as const },
    ]) {
      expect(() => registry.beginAttempt(changed)).toThrowError(CaptureRegistryConflictError);
    }

    const commits = await Promise.all(
      Array.from({ length: 8 }, async () => registry.commitCapture(commit)),
    );
    expect(commits.every((record) => record.state === "committed")).toBe(true);
    expect(() =>
      registry.commitCapture({ ...commit, captureId: randomBytes(16).toString("hex") }),
    ).toThrowError(CaptureRegistryConflictError);
    expect(() =>
      registry.commitCapture({
        ...commit,
        sourceIdentifiers: { ...xIdentifiers(), nextToken: "changed" },
      }),
    ).toThrowError(CaptureRegistryConflictError);
    registry.close();
  });

  it("enforces one attempt per capture across sessions", () => {
    const registry = openTestRegistry({
      path: makePath(),
      registryKey: randomBytes(32),
    });
    const first = beginInput();
    const second = beginInput();
    const captureId = randomBytes(16).toString("hex");
    registry.beginAttempt(first);
    registry.beginAttempt(second);
    registry.commitCapture(commitInput(first.attemptId, { captureId }));
    expect(() => registry.commitCapture(commitInput(second.attemptId, { captureId }))).toThrow(
      CaptureRegistryConflictError,
    );
    registry.close();
  });

  it("crypto-shreds a committed record into a content-free idempotent tombstone", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const registry = openTestRegistry({ path, registryKey });
    const attempt = beginInput();
    const commit = commitInput(attempt.attemptId);
    const receipt = deletionReceipt(commit.captureId);
    registry.beginAttempt(attempt);
    registry.commitCapture(commit);

    expect(() =>
      registry.recordVerifiedDeletion({
        attemptId: attempt.attemptId,
        deletionReceipt: deletionReceipt(randomBytes(16).toString("hex")),
      }),
    ).toThrow(CaptureRegistryConflictError);
    expect(registry.listCommittedCaptureIds()).toEqual([commit.captureId]);

    const removed = registry.recordVerifiedDeletion({
      attemptId: attempt.attemptId,
      deletionReceipt: receipt,
    });
    expect(removed).toEqual({
      attemptId: attempt.attemptId,
      keyDestroyed: true,
      removalReason: "capture_deleted_explicit",
      removedAt: DELETED_AT,
      schemaVersion: 1,
      state: "removed",
    });
    expect(Object.keys(removed)).not.toEqual(
      expect.arrayContaining(["captureId", "requestFingerprint", "sourceIdentifiers"]),
    );
    expect(registry.listCommittedCaptureIds()).toEqual([]);
    expect(registry.verifyIntegrity()).toMatchObject({
      keyDestroyedTombstones: 1,
      recordCount: 1,
      valid: true,
    });
    expect(registry.beginAttempt(attempt)).toEqual(removed);
    expect(() => registry.commitCapture(commit)).toThrow(CaptureRegistryConflictError);
    expect(
      registry.recordVerifiedDeletion({ attemptId: attempt.attemptId, deletionReceipt: receipt }),
    ).toEqual(removed);
    expect(() =>
      registry.recordVerifiedDeletion({
        attemptId: attempt.attemptId,
        deletionReceipt: { ...receipt, deletedAt: "2026-08-14T10:00:00.001Z" },
      }),
    ).toThrow(CaptureRegistryConflictError);
    registry.close();

    const attacker = new DatabaseSync(path);
    const structural = attacker
      .prepare(
        `SELECT begin_binding, capture_token, commit_binding,
                wrapped_dek_nonce, wrapped_dek_ciphertext, wrapped_dek_tag, state
           FROM rsi_capture_registry_records`,
      )
      .get() as Record<string, unknown>;
    attacker.close();
    expect(structural).toEqual({
      begin_binding: null,
      capture_token: null,
      commit_binding: null,
      state: "removed",
      wrapped_dek_ciphertext: null,
      wrapped_dek_nonce: null,
      wrapped_dek_tag: null,
    });
    const onDisk = readFileSync(path);
    for (const secret of [
      attempt.requestFingerprint,
      commit.captureId,
      "next-token_registry-private-marker_1",
      "7000000000000000001",
    ]) {
      expect(onDisk.includes(Buffer.from(secret))).toBe(false);
    }

    const reopened = openTestRegistry({ path, registryKey });
    expect(reopened.getAttempt(attempt.attemptId)).toEqual(removed);
    expect(reopened.purgeRemoved({ before: DELETED_AT })).toMatchObject({
      purged: 1,
      truncated: false,
    });
    expect(reopened.getAttempt(attempt.attemptId)).toBeUndefined();
    reopened.close();
  });

  it("replays a Vault deletion receipt after a committed-registry restart boundary", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const attempt = beginInput();
    const commit = commitInput(attempt.attemptId);
    const beforeCrash = openTestRegistry({ path, registryKey });
    beforeCrash.beginAttempt(attempt);
    beforeCrash.commitCapture(commit);
    beforeCrash.close();

    // Models Vault.delete succeeding after restart; private attempt/capture pairs
    // make the exact receipt replay possible without a public projection.
    const startup = openTestRegistry({ path, registryKey });
    expect(startup.listCommittedCaptures()).toEqual([
      { attemptId: attempt.attemptId, captureId: commit.captureId },
    ]);
    const receipt = deletionReceipt(commit.captureId);
    expect(
      startup.recordVerifiedDeletion({
        attemptId: attempt.attemptId,
        deletionReceipt: receipt,
      }),
    ).toMatchObject({ keyDestroyed: true, state: "removed" });
    expect(startup.listCommittedCaptures()).toEqual([]);
    startup.close();

    const replay = openTestRegistry({ path, registryKey });
    expect(
      replay.recordVerifiedDeletion({ attemptId: attempt.attemptId, deletionReceipt: receipt }),
    ).toMatchObject({ keyDestroyed: true, state: "removed" });
    replay.close();
  });

  it("reconstructs an authenticated aggregate-only session removal summary after restart", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const sessionId = randomUUID();
    const committedAttempt = beginInput({ sessionId });
    const pendingAttempt = beginInput({ sessionId });
    const commit = commitInput(committedAttempt.attemptId);
    const registry = openTestRegistry({ path, registryKey });
    registry.beginAttempt(committedAttempt);
    registry.beginAttempt(pendingAttempt);
    registry.commitCapture(commit);
    registry.recordVerifiedDeletion({
      attemptId: committedAttempt.attemptId,
      deletionReceipt: deletionReceipt(commit.captureId, { reason: "expired" }),
    });
    registry.removePendingAttempt({
      attemptId: pendingAttempt.attemptId,
      removedAt: DELETED_AT,
    });
    registry.close();

    const restarted = openTestRegistry({ path, registryKey });
    const summary = restarted.getSessionRemovalSummary(sessionId);
    expect(summary).toEqual({
      counts: {
        captureDeletedExpired: 1,
        captureDeletedExplicit: 0,
        pendingExplicit: 1,
        pendingRecovery: 0,
      },
      schemaVersion: 1,
      total: 2,
    });
    expect(JSON.stringify(summary)).not.toContain(committedAttempt.attemptId);
    expect(JSON.stringify(summary)).not.toContain(commit.captureId);
    expect(restarted.getSessionStateSummary(sessionId)).toEqual({
      committed: 0,
      pending: 0,
      profile: "dev",
      removed: 2,
      schemaVersion: 1,
      sessionId,
      total: 2,
    });
    restarted.close();
  });

  it("recovers pending crashes into aggregate key-destroyed tombstones with bounded batches", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const first = beginInput();
    const second = beginInput();
    const original = openTestRegistry({ path, registryKey });
    original.beginAttempt(first);
    original.beginAttempt(second);
    original.close();

    const recovered = openTestRegistry({ path, registryKey });
    expect(() =>
      recovered.recoverPendingAttempts({
        recoveredAt: "2026-08-14T07:59:59.999Z",
        limit: 1,
      }),
    ).toThrow(CaptureRegistryValidationError);
    expect(recovered.getAttempt(first.attemptId)).toMatchObject({ state: "pending" });
    expect(recovered.recoverPendingAttempts({ recoveredAt: COMMITTED_AT, limit: 1 })).toEqual({
      recoveredAt: COMMITTED_AT,
      removed: 1,
      schemaVersion: 1,
      truncated: true,
    });
    expect(recovered.getAttempt(first.attemptId)).toMatchObject({
      keyDestroyed: true,
      removalReason: "pending_recovery",
      state: "removed",
    });
    expect(recovered.getAttempt(second.attemptId)).toMatchObject({ state: "pending" });
    expect(recovered.recoverPendingAttempts({ recoveredAt: COMMITTED_AT })).toMatchObject({
      removed: 1,
      truncated: false,
    });
    expect(recovered.verifyIntegrity().keyDestroyedTombstones).toBe(2);
    recovered.close();
  });

  it("validates recovery time against every pending row before mutating a bounded batch", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const registry = openTestRegistry({ path, registryKey });
    const earlier = beginInput();
    const later = beginInput({ acquiredAt: "2026-08-14T08:02:00.000Z" });
    registry.beginAttempt(earlier);
    registry.beginAttempt(later);

    expect(() => registry.recoverPendingAttempts({ recoveredAt: COMMITTED_AT, limit: 1 })).toThrow(
      CaptureRegistryValidationError,
    );
    expect(registry.getAttempt(earlier.attemptId)).toMatchObject({ state: "pending" });
    expect(registry.getAttempt(later.attemptId)).toMatchObject({ state: "pending" });
    expect(registry.verifyIntegrity()).toMatchObject({
      keyDestroyedTombstones: 0,
      recordCount: 2,
      valid: true,
    });
    registry.close();
  });

  it("conservatively heals an interrupted erasure compaction whenever a tombstone exists", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const registry = openTestRegistry({ path, registryKey });
    const attempt = beginInput();
    const commit = commitInput(attempt.attemptId);
    registry.beginAttempt(attempt);
    registry.commitCapture(commit);
    registry.recordVerifiedDeletion({
      attemptId: attempt.attemptId,
      deletionReceipt: deletionReceipt(commit.captureId),
    });
    registry.close();

    // Model pages left behind by a crash between the authenticated tombstone
    // commit and the required VACUUM. The schema is clean but freelist pages remain.
    const crashState = new DatabaseSync(path);
    crashState.exec(`
      CREATE TABLE interrupted_erasure_padding (payload BLOB) STRICT;
      INSERT INTO interrupted_erasure_padding VALUES (zeroblob(131072));
      DROP TABLE interrupted_erasure_padding;
    `);
    const before = crashState.prepare("PRAGMA freelist_count").get() as {
      freelist_count: number;
    };
    crashState.close();
    expect(before.freelist_count).toBeGreaterThan(0);

    const healed = openTestRegistry({ path, registryKey });
    expect(healed.getAttempt(attempt.attemptId)).toMatchObject({
      keyDestroyed: true,
      state: "removed",
    });
    healed.close();
    const inspected = new DatabaseSync(path);
    const after = inspected.prepare("PRAGMA freelist_count").get() as {
      freelist_count: number;
    };
    inspected.close();
    expect(after.freelist_count).toBe(0);
  });

  it("removes pending attempts only through the explicit key-destruction path", () => {
    const registry = openTestRegistry({
      path: makePath(),
      registryKey: randomBytes(32),
    });
    const attempt = beginInput();
    registry.beginAttempt(attempt);
    expect(
      registry.removePendingAttempt({ attemptId: attempt.attemptId, removedAt: COMMITTED_AT }),
    ).toBe(true);
    expect(
      registry.removePendingAttempt({ attemptId: attempt.attemptId, removedAt: COMMITTED_AT }),
    ).toBe(true);
    expect(() =>
      registry.removePendingAttempt({ attemptId: attempt.attemptId, removedAt: DELETED_AT }),
    ).toThrow(CaptureRegistryConflictError);
    expect(registry.getAttempt(attempt.attemptId)).toMatchObject({
      keyDestroyed: true,
      removalReason: "pending_explicit",
    });
    registry.close();
  });

  it("accepts every identifier in a maximum X page and rejects each boundary overflow", () => {
    expect(MAX_CAPTURE_REGISTRY_RECORDS).toBe(1_000);
    const registry = openTestRegistry({
      path: makePath(),
      registryKey: randomBytes(32),
    });
    const maximum: Extract<CaptureSourceIdentifiers, { source: "x" }> = {
      editIds: Array.from({ length: MAX_X_EDIT_IDS }, (_, index) => String(index + 1)),
      nextToken: "~".repeat(MAX_X_NEXT_TOKEN_CHARACTERS),
      postIds: Array.from({ length: MAX_X_POST_IDS }, (_, index) => String(index + 2_001)),
      source: "x",
      userIds: Array.from({ length: MAX_X_USER_IDS }, (_, index) => String(index + 3_001)),
    };
    const attempt = beginInput();
    registry.beginAttempt(attempt);
    expect(
      registry.commitCapture(commitInput(attempt.attemptId, { sourceIdentifiers: maximum })),
    ).toMatchObject({ state: "committed" });

    for (const sourceIdentifiers of [
      { ...maximum, editIds: [...maximum.editIds, "5001"] },
      { ...maximum, postIds: [...maximum.postIds, "5002"] },
      { ...maximum, userIds: [...maximum.userIds, "5003"] },
      { ...maximum, nextToken: "~".repeat(MAX_X_NEXT_TOKEN_CHARACTERS + 1) },
    ]) {
      const overflow = beginInput();
      registry.beginAttempt(overflow);
      expect(() =>
        registry.commitCapture(
          commitInput(overflow.attemptId, { sourceIdentifiers: sourceIdentifiers as never }),
        ),
      ).toThrow(CaptureRegistryValidationError);
    }

    const fixture = beginInput({ source: "fixture" });
    registry.beginAttempt(fixture);
    expect(
      registry.commitCapture(
        commitInput(fixture.attemptId, {
          sourceIdentifiers: {
            identifiers: Array.from({ length: MAX_SOURCE_IDENTIFIERS }, (_, index) => ({
              kind: "fixture_id" as const,
              value: `${index}:${"v".repeat(MAX_SOURCE_IDENTIFIER_BYTES - String(index).length - 1)}`,
            })),
            source: "fixture",
          },
        }),
      ),
    ).toMatchObject({ state: "committed" });

    const fixtureOverflow = beginInput({ source: "fixture" });
    registry.beginAttempt(fixtureOverflow);
    expect(() =>
      registry.commitCapture(
        commitInput(fixtureOverflow.attemptId, {
          sourceIdentifiers: {
            identifiers: [
              { kind: "fixture_id", value: "v".repeat(MAX_SOURCE_IDENTIFIER_BYTES + 1) },
            ],
            source: "fixture",
          },
        }),
      ),
    ).toThrow(CaptureRegistryValidationError);
    expect(() =>
      registry.recoverPendingAttempts({
        limit: MAX_REGISTRY_OPERATION_LIMIT + 1,
        recoveredAt: COMMITTED_AT,
      }),
    ).toThrow(CaptureRegistryValidationError);
    registry.close();
  });

  it("enforces exact runtime schemas, lifecycle times, path ownership, and close", () => {
    const path = makePath();
    const registryKey = randomBytes(32);
    const registry = openTestRegistry({ path, registryKey });
    const attempt = beginInput();
    expect(() => registry.beginAttempt({ ...attempt, extra: true } as never)).toThrow(
      CaptureRegistryValidationError,
    );
    const accessor = { ...attempt } as Record<string, unknown>;
    Object.defineProperty(accessor, "sessionId", {
      enumerable: true,
      get: () => attempt.sessionId,
    });
    expect(() => registry.beginAttempt(accessor as never)).toThrow(CaptureRegistryValidationError);
    const symbol = { ...attempt, [Symbol("hidden")]: true };
    expect(() => registry.beginAttempt(symbol as never)).toThrow(CaptureRegistryValidationError);
    expect(() => registry.beginAttempt({ ...attempt, expiresAt: "2026-08-14T10:00:00Z" })).toThrow(
      CaptureRegistryValidationError,
    );
    registry.close();
    expect(() => registry.getAttempt(attempt.attemptId)).toThrow(CaptureRegistryClosedError);

    chmodSync(path, 0o644);
    expect(() => openTestRegistry({ path, registryKey })).toThrow(CaptureRegistrySecurityError);
    chmodSync(path, 0o600);
    const linked = join(join(path, ".."), "linked.sqlite");
    linkSync(path, linked);
    expect(() => openTestRegistry({ path, registryKey })).toThrow(CaptureRegistrySecurityError);
  });

  it("rejects symlink opens and detects live path substitution", () => {
    const target = makePath("rsi-capture-registry-target-");
    const targetKey = randomBytes(32);
    openTestRegistry({ path: target, registryKey: targetKey }).close();
    const symlinkParent = mkdtempSync(join(tmpdir(), "rsi-capture-registry-symlink-"));
    temporaryDirectories.push(symlinkParent);
    const linkedPath = join(symlinkParent, "registry.sqlite");
    symlinkSync(target, linkedPath);
    expect(() => openTestRegistry({ path: linkedPath, registryKey: targetKey })).toThrow(
      CaptureRegistrySecurityError,
    );

    const livePath = makePath("rsi-capture-registry-live-");
    const live = openTestRegistry({ path: livePath, registryKey: randomBytes(32) });
    const moved = `${livePath}.moved`;
    renameSync(livePath, moved);
    writeFileSync(livePath, new Uint8Array(), { mode: 0o600 });
    expect(() => live.verifyIntegrity()).toThrow(CaptureRegistrySecurityError);
    live.close();
  });
});
