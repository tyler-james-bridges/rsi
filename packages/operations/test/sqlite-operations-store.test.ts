import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  BudgetExceededError,
  InvalidAttemptPermitError,
  OperationsConflictError,
  OperationsIntegrityError,
  SqliteOperationsStore,
  isSqliteOperationsStore,
} from "../src/index.js";

const T0 = "2026-08-14T12:00:00.000Z";
const T1 = "2026-08-14T12:01:00.000Z";
const T2 = "2026-08-14T12:02:00.000Z";
const T3 = "2026-08-14T12:03:00.000Z";
const T4 = "2026-08-14T12:04:00.000Z";
const T5 = "2026-08-14T12:05:00.000Z";
const T6 = "2026-08-14T12:06:00.000Z";
const T7 = "2026-08-14T12:07:00.000Z";
const T8 = "2026-08-14T12:08:00.000Z";
const T9 = "2026-08-14T12:09:00.000Z";
const T10 = "2026-08-14T12:10:00.000Z";
const T11 = "2026-08-14T12:11:00.000Z";
const T12 = "2026-08-14T12:12:00.000Z";
const T13 = "2026-08-14T12:13:00.000Z";
const END = "2026-08-14T14:00:00.000Z";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "rsi-operations-"));
  directories.push(directory);
  const path = join(directory, "operations.sqlite");
  const stateKey = randomBytes(32);
  const store = new SqliteOperationsStore({ path, stateKey });
  const budgetId = randomUUID();
  store.createBudget({
    budgetId,
    createdAt: T0,
    currency: "USD_MICRO",
    endsAt: END,
    maxAtomic: "150000",
    maxAttempts: 2,
    profile: "canary",
    startsAt: T0,
  });
  return { budgetId, directory, path, stateKey, store };
}

interface StoredCursorEnvelope {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly tag: Uint8Array;
  readonly wrapped_dek_ciphertext: Uint8Array;
  readonly wrapped_dek_nonce: Uint8Array;
  readonly wrapped_dek_tag: Uint8Array;
}

const ENVELOPE_COLUMNS = `
  ciphertext, nonce, tag,
  wrapped_dek_ciphertext, wrapped_dek_nonce, wrapped_dek_tag
`;

const CANDIDATE_ENVELOPE_COLUMNS = `
  candidate_ciphertext AS ciphertext,
  candidate_nonce AS nonce,
  candidate_tag AS tag,
  candidate_wrapped_dek_ciphertext AS wrapped_dek_ciphertext,
  candidate_wrapped_dek_nonce AS wrapped_dek_nonce,
  candidate_wrapped_dek_tag AS wrapped_dek_tag
`;

function envelopeNeedles(envelope: StoredCursorEnvelope): readonly Buffer[] {
  return [
    envelope.ciphertext,
    envelope.nonce,
    envelope.tag,
    envelope.wrapped_dek_ciphertext,
    envelope.wrapped_dek_nonce,
    envelope.wrapped_dek_tag,
  ].map((value) => Buffer.from(value));
}

async function namespaceFiles(directory: string): Promise<readonly Buffer[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries
      .filter((entry) => entry.isFile())
      .map(async (entry) => readFile(join(directory, entry.name)).catch(() => Buffer.alloc(0))),
  );
  return files;
}

async function expectNamespaceMissing(
  directory: string,
  needles: readonly Uint8Array[],
): Promise<void> {
  const files = await namespaceFiles(directory);
  for (const needle of needles) {
    const buffer = Buffer.from(needle);
    expect(
      files.some((file) => file.includes(buffer)),
      `found destroyed ${buffer.byteLength}-byte cursor envelope component in SQLite namespace`,
    ).toBe(false);
  }
}

function reserve(
  target: Awaited<ReturnType<typeof fixture>>,
  amount: string,
  permit = SqliteOperationsStore.createAttemptPermit(),
) {
  const input = {
    attemptId: permit.attemptId,
    authorizationExpiresAt: END,
    budgetId: target.budgetId,
    createdAt: T1,
    idempotencyKey: `ticket:${permit.attemptId}`,
    lane: "official" as const,
    operation: "x.recent-search.v1" as const,
    permitToken: permit.token,
    reservedAtomic: amount,
    sessionId: randomUUID(),
    sourcePlane: "social" as const,
  };
  return { input, permit, record: target.store.reserveAttempt(input) };
}

function completeCursorReceipts(
  store: SqliteOperationsStore,
  advanceId: string,
  eventSequence = 5,
) {
  const eventHash = "1".repeat(64);
  const checkpointHead = "2".repeat(64);
  const anchorId = randomUUID();
  store.markCursorValidated(advanceId, T3);
  store.markCursorEventPersisted(advanceId, {
    eventHash,
    eventId: randomUUID(),
    eventSequence,
    persistedAt: T4,
  });
  store.markCursorCheckpointed(advanceId, {
    anchoredThroughSequence: eventSequence,
    checkpointHead,
    checkpointedAt: T5,
  });
  store.markCursorAnchorPublished(advanceId, {
    anchorHead: checkpointHead,
    anchorId,
    publishedAt: T6,
  });
  store.markCursorExternallyVerified(advanceId, {
    anchorHead: checkpointHead,
    anchorId,
    verifiedAt: T7,
  });
}

describe("SqliteOperationsStore budget permits", () => {
  it("permanently reserves cost before a one-shot dispatch", async () => {
    const target = await fixture();
    const first = reserve(target, "100000");
    expect(target.store.reserveAttempt(first.input)).toEqual(first.record);

    expect(() =>
      target.store.authorizeAttempt(
        { ...first.permit, token: "A".repeat(43) as typeof first.permit.token },
        T2,
      ),
    ).toThrow(InvalidAttemptPermitError);
    expect(target.store.authorizeAttempt(first.permit, T2).state).toBe("dispatched");
    expect(() => target.store.authorizeAttempt(first.permit, T2)).toThrow("already consumed");
    target.store.closeAttempt(first.permit.attemptId, { closedAt: T3, outcome: "failed" });

    const second = reserve(target, "50000");
    target.store.closeAttempt(second.permit.attemptId, { closedAt: T2, outcome: "aborted" });
    expect(target.store.getBudgetSummary(target.budgetId)).toMatchObject({
      attemptedCount: 2,
      remainingAtomic: "0",
      reservedAtomic: "150000",
    });

    const third = SqliteOperationsStore.createAttemptPermit();
    expect(() => reserve(target, "1", third)).toThrow(BudgetExceededError);
    target.store.close();
  });

  it("reads an authenticated permit-free network binding across restart", async () => {
    const target = await fixture();
    expect(isSqliteOperationsStore(target.store)).toBe(true);
    expect(isSqliteOperationsStore(Object.create(SqliteOperationsStore.prototype))).toBe(false);
    expect(isSqliteOperationsStore({ readNetworkAttemptBinding: () => undefined })).toBe(false);
    const attempt = reserve(target, "150000");
    expect(target.store.readNetworkAttemptBinding(attempt.permit.attemptId)).toEqual({
      attemptId: attempt.permit.attemptId,
      authorizationExpiresAt: END,
      dispatchedAt: null,
      lane: "official",
      operation: "x.recent-search.v1",
      profile: "canary",
      reservedAtomic: "150000",
      sessionId: attempt.input.sessionId,
      sourcePlane: "social",
      state: "reserved",
    });
    target.store.authorizeAttempt(attempt.permit, T2);
    target.store.close();

    const reopened = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    const durable = reopened.readNetworkAttemptBinding(attempt.permit.attemptId);
    expect(durable).toMatchObject({ dispatchedAt: T2, state: "dispatched" });
    expect(JSON.stringify(durable)).not.toContain(attempt.permit.token);
    expect(() => reopened.readNetworkAttemptBinding(randomUUID())).toThrow(OperationsConflictError);
    reopened.close();
  });

  it("serializes independent writers against the same hard cap", async () => {
    const target = await fixture();
    const secondStore = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    const firstPermit = SqliteOperationsStore.createAttemptPermit();
    const secondPermit = SqliteOperationsStore.createAttemptPermit();

    reserve(target, "100000", firstPermit);
    expect(() =>
      secondStore.reserveAttempt({
        attemptId: secondPermit.attemptId,
        authorizationExpiresAt: END,
        budgetId: target.budgetId,
        createdAt: T1,
        idempotencyKey: `ticket:${secondPermit.attemptId}`,
        lane: "official",
        operation: "x.recent-search.v1",
        permitToken: secondPermit.token,
        reservedAtomic: "100000",
        sessionId: randomUUID(),
        sourcePlane: "social",
      }),
    ).toThrow("exceed the budget");
    expect(secondStore.getBudgetSummary(target.budgetId).reservedAtomic).toBe("100000");

    secondStore.close();
    target.store.close();
  });

  it("recovers expired reservations as consumed aborts", async () => {
    const target = await fixture();
    const permit = SqliteOperationsStore.createAttemptPermit();
    target.store.reserveAttempt({
      attemptId: permit.attemptId,
      authorizationExpiresAt: T2,
      budgetId: target.budgetId,
      createdAt: T1,
      idempotencyKey: `ticket:${permit.attemptId}`,
      lane: "security",
      operation: "x.recent-search.v1",
      permitToken: permit.token,
      reservedAtomic: "150000",
      sessionId: randomUUID(),
      sourcePlane: "social",
    });

    expect(target.store.recoverExpiredAttempts(T3)).toBe(1);
    expect(target.store.getBudgetSummary(target.budgetId)).toMatchObject({
      remainingAtomic: "0",
      reservedAtomic: "150000",
    });
    expect(() => target.store.authorizeAttempt(permit, T3)).toThrow("already consumed");
    target.store.close();
  });

  it("projects content-free per-session source closure aggregates", async () => {
    const target = await fixture();
    const sessionId = randomUUID();
    const budgetId = randomUUID();
    target.store.createBudget({
      budgetId,
      createdAt: T0,
      currency: "USD_MICRO",
      endsAt: END,
      maxAtomic: "800000",
      maxAttempts: 8,
      profile: "canary",
      startsAt: T0,
    });
    const specifications = [
      ["official", "x.recent-search.v1", "social", "succeeded"],
      ["contract", "x.recent-search.v1", "social", "empty"],
      ["marketplace", "x.recent-search.v1", "social", "succeeded"],
      ["security", "x.recent-search.v1", "social", "succeeded"],
      ["discovery", "x.recent-search.v1", "social", "empty"],
      ["marketplace", "opensea.rest.v1", "marketplace", "succeeded"],
      ["marketplace", "opensea.stream.v1", "marketplace", "empty"],
      ["contract", "alchemy.json-rpc.v1", "canonical_chain", "succeeded"],
    ] as const;
    for (const [lane, operation, sourcePlane, outcome] of specifications) {
      const permit = SqliteOperationsStore.createAttemptPermit();
      target.store.reserveAttempt({
        attemptId: permit.attemptId,
        authorizationExpiresAt: END,
        budgetId,
        createdAt: T1,
        idempotencyKey: `ticket:${permit.attemptId}`,
        lane,
        operation,
        permitToken: permit.token,
        reservedAtomic: "100000",
        sessionId,
        sourcePlane,
      });
      target.store.authorizeAttempt(permit, T2);
      target.store.closeAttempt(permit.attemptId, { closedAt: T3, outcome });
    }

    const summary = target.store.getSessionAttemptSummary(sessionId, "canary");
    expect(summary).toMatchObject({
      allAttemptsClosed: true,
      attemptCount: 8,
      canonicalChain: { attemptCount: 1, closedCount: 1, succeededCount: 1 },
      crossProfileAttemptCount: 0,
      openSea: {
        rest: { attemptCount: 1, succeededCount: 1 },
        stream: { attemptCount: 1, emptyCount: 1 },
      },
      profile: "canary",
      reservedAtomic: "800000",
      schemaVersion: 1,
      sessionId,
      xLanes: {
        contract: { attemptCount: 1, emptyCount: 1 },
        discovery: { attemptCount: 1, emptyCount: 1 },
        marketplace: { attemptCount: 1, succeededCount: 1 },
        official: { attemptCount: 1, succeededCount: 1 },
        security: { attemptCount: 1, succeededCount: 1 },
      },
    });
    expect(JSON.stringify(summary)).not.toContain("ticket:");
    expect(Object.isFrozen(summary)).toBe(true);
    expect(Object.isFrozen(summary.xLanes)).toBe(true);
    expect(() => target.store.getSessionAttemptSummary(sessionId, "dev")).toThrow(/dev profile/);
    target.store.close();
  });

  it("rejects retroactive and source-mismatched reservations", async () => {
    const target = await fixture();
    const retroactiveBudgetId = randomUUID();
    target.store.createBudget({
      budgetId: retroactiveBudgetId,
      createdAt: T2,
      currency: "USD_MICRO",
      endsAt: END,
      maxAtomic: "150000",
      maxAttempts: 1,
      profile: "canary",
      startsAt: T0,
    });
    const permit = SqliteOperationsStore.createAttemptPermit();
    expect(() =>
      target.store.reserveAttempt({
        attemptId: permit.attemptId,
        authorizationExpiresAt: END,
        budgetId: retroactiveBudgetId,
        createdAt: T1,
        idempotencyKey: `ticket:${permit.attemptId}`,
        lane: "official",
        operation: "x.recent-search.v1",
        permitToken: permit.token,
        reservedAtomic: "150000",
        sessionId: randomUUID(),
        sourcePlane: "social",
      }),
    ).toThrow("outside the budget window");

    const mismatched = SqliteOperationsStore.createAttemptPermit();
    expect(() =>
      target.store.reserveAttempt({
        attemptId: mismatched.attemptId,
        authorizationExpiresAt: END,
        budgetId: target.budgetId,
        createdAt: T1,
        idempotencyKey: `ticket:${mismatched.attemptId}`,
        lane: "official",
        operation: "x.recent-search.v1",
        permitToken: mismatched.token,
        reservedAtomic: "150000",
        sessionId: randomUUID(),
        sourcePlane: "canonical_chain",
      }),
    ).toThrow("does not match its source plane");
    target.store.close();
  });
});

describe("SqliteOperationsStore cursor sequencing", () => {
  it("keeps cursor ciphertext private and commits only after every receipt", async () => {
    const target = await fixture();
    const attempt = reserve(target, "100000");
    target.store.authorizeAttempt(attempt.permit, T2);
    target.store.closeAttempt(attempt.permit.attemptId, { closedAt: T2, outcome: "succeeded" });
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });
    const advanceId = randomUUID();
    const secretCursor = "1900000000000000999";
    const stageInput = {
      advanceId,
      attemptId: attempt.permit.attemptId,
      candidateCursor: secretCursor,
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    } as const;
    target.store.stageCursorAdvance(stageInput);

    expect(() => target.store.commitCursor(advanceId, T7)).toThrow("before independent");
    target.store.markCursorValidated(advanceId, T3);
    const eventId = randomUUID();
    target.store.markCursorEventPersisted(advanceId, {
      eventHash: "1".repeat(64),
      eventId,
      eventSequence: 5,
      persistedAt: T4,
    });
    expect(target.store.markCursorValidated(advanceId, T3).state).toBe("event_persisted");
    expect(() =>
      target.store.markCursorEventPersisted(advanceId, {
        eventHash: "3".repeat(64),
        eventId,
        eventSequence: 5,
        persistedAt: T4,
      }),
    ).toThrow(OperationsConflictError);
    expect(() =>
      target.store.markCursorCheckpointed(advanceId, {
        anchoredThroughSequence: 4,
        checkpointHead: "2".repeat(64),
        checkpointedAt: T5,
      }),
    ).toThrow("does not anchor");
    target.store.markCursorCheckpointed(advanceId, {
      anchoredThroughSequence: 5,
      checkpointHead: "2".repeat(64),
      checkpointedAt: T5,
    });
    expect(() =>
      target.store.markCursorAnchorPublished(advanceId, {
        anchorHead: "4".repeat(64),
        anchorId: randomUUID(),
        publishedAt: T6,
      }),
    ).toThrow("does not match");
    const anchorId = randomUUID();
    target.store.markCursorAnchorPublished(advanceId, {
      anchorHead: "2".repeat(64),
      anchorId,
      publishedAt: T6,
    });
    target.store.markCursorExternallyVerified(advanceId, {
      anchorHead: "2".repeat(64),
      anchorId,
      verifiedAt: T7,
    });
    expect(target.store.commitCursor(advanceId, T7)).toMatchObject({
      advanceId,
      committedAt: T7,
      lineageId,
      revision: 1,
      state: "committed",
    });
    expect(
      target.store.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 1, value: secretCursor });
    expect(
      target.store.initializeCursorLineage({
        initializedAt: T0,
        lane: "official",
        lineageId,
        profile: "canary",
        sourcePlane: "social",
      }),
    ).toMatchObject({ revision: 1, value: secretCursor });
    expect(target.store.stageCursorAdvance(stageInput).state).toBe("committed");
    expect(target.store.readCursorAdvance(advanceId).state).toBe("committed");
    expect(() =>
      target.store.stageCursorAdvance({
        ...stageInput,
        advanceId: randomUUID(),
        candidateCursor: "cursor-reused-attempt",
        expectedRevision: 1,
        stagedAt: T7,
      }),
    ).toThrow("only once");
    expect(() => target.store.commitCursor(advanceId, T6)).toThrow("different audit content");
    expect(target.store.verifyIntegrity().valid).toBe(true);
    target.store.close();

    const file = await readFile(target.path);
    expect(file.includes(Buffer.from(secretCursor))).toBe(false);
    expect(file.includes(Buffer.from(attempt.permit.token))).toBe(false);
    const reopened = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    expect(
      reopened.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 1, value: secretCursor });
    reopened.close();
  });

  it("destroys aborted candidates and rejects stale competing commits", async () => {
    const target = await fixture();
    const first = reserve(target, "75000");
    const second = reserve(target, "75000");
    target.store.authorizeAttempt(first.permit, T2);
    target.store.authorizeAttempt(second.permit, T2);
    target.store.closeAttempt(first.permit.attemptId, { closedAt: T2, outcome: "succeeded" });
    target.store.closeAttempt(second.permit.attemptId, { closedAt: T2, outcome: "succeeded" });
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });
    const firstAdvance = randomUUID();
    const secondAdvance = randomUUID();
    for (const [advanceId, attemptId, candidateCursor] of [
      [firstAdvance, first.permit.attemptId, "cursor-one"],
      [secondAdvance, second.permit.attemptId, "cursor-two"],
    ] as const) {
      target.store.stageCursorAdvance({
        advanceId,
        attemptId,
        candidateCursor,
        expectedRevision: 0,
        lane: "official",
        lineageId,
        profile: "canary",
        sourcePlane: "social",
        stagedAt: T2,
      });
      completeCursorReceipts(target.store, advanceId);
    }
    target.store.commitCursor(firstAdvance, T7);
    expect(() => target.store.commitCursor(secondAdvance, T7)).toThrow("head changed");
    expect(target.store.abortCursorAdvance(secondAdvance, T7).state).toBe("aborted");
    expect(
      target.store.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 1, value: "cursor-one" });
    target.store.close();

    const file = await readFile(target.path);
    expect(file.includes(Buffer.from("cursor-one"))).toBe(false);
    expect(file.includes(Buffer.from("cursor-two"))).toBe(false);
  });

  it("returns stable content-free commit receipts after later revisions", async () => {
    const target = await fixture();
    const first = reserve(target, "75000");
    const second = reserve(target, "75000");
    for (const attempt of [first, second]) {
      target.store.authorizeAttempt(attempt.permit, T2);
      target.store.closeAttempt(attempt.permit.attemptId, {
        closedAt: T2,
        outcome: "succeeded",
      });
    }
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });

    const firstAdvance = randomUUID();
    target.store.stageCursorAdvance({
      advanceId: firstAdvance,
      attemptId: first.permit.attemptId,
      candidateCursor: "cursor-one",
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    });
    completeCursorReceipts(target.store, firstAdvance);
    const firstReceipt = target.store.commitCursor(firstAdvance, T7);

    const secondAdvance = randomUUID();
    const secondStage = {
      advanceId: secondAdvance,
      attemptId: second.permit.attemptId,
      candidateCursor: "cursor-two",
      expectedRevision: 1,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T7,
    } as const;
    expect(() => target.store.stageCursorAdvance({ ...secondStage, stagedAt: T2 })).toThrow(
      "predates the current cursor head",
    );
    target.store.stageCursorAdvance(secondStage);
    target.store.markCursorValidated(secondAdvance, T8);
    const eventHash = "5".repeat(64);
    const checkpointHead = "6".repeat(64);
    const anchorId = randomUUID();
    target.store.markCursorEventPersisted(secondAdvance, {
      eventHash,
      eventId: randomUUID(),
      eventSequence: 6,
      persistedAt: T9,
    });
    target.store.markCursorCheckpointed(secondAdvance, {
      anchoredThroughSequence: 6,
      checkpointHead,
      checkpointedAt: T10,
    });
    target.store.markCursorAnchorPublished(secondAdvance, {
      anchorHead: checkpointHead,
      anchorId,
      publishedAt: T11,
    });
    target.store.markCursorExternallyVerified(secondAdvance, {
      anchorHead: checkpointHead,
      anchorId,
      verifiedAt: T12,
    });
    target.store.commitCursor(secondAdvance, T13);

    expect(target.store.commitCursor(firstAdvance, T7)).toEqual(firstReceipt);
    expect(firstReceipt).not.toHaveProperty("value");
    expect(
      target.store.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 2, value: "cursor-two" });

    const database = new DatabaseSync(target.path);
    const retainedCandidates = database
      .prepare(
        `SELECT count(*) AS count FROM rsi_cursor_advances
          WHERE state = 'committed' AND candidate_ciphertext IS NOT NULL`,
      )
      .get() as { count: number };
    database.close();
    expect(retainedCandidates.count).toBe(0);
    expect(target.store.verifyIntegrity().valid).toBe(true);
    target.store.close();
  });

  it("physically erases every aborted candidate envelope from SQLite files", async () => {
    const target = await fixture();
    const attempt = reserve(target, "150000");
    target.store.authorizeAttempt(attempt.permit, T2);
    target.store.closeAttempt(attempt.permit.attemptId, {
      closedAt: T2,
      outcome: "succeeded",
    });
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });
    const advanceId = randomUUID();
    target.store.stageCursorAdvance({
      advanceId,
      attemptId: attempt.permit.attemptId,
      candidateCursor: "abort-only-secret-cursor-1900000000000000001",
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    });

    const inspect = new DatabaseSync(target.path);
    const candidate = inspect
      .prepare(
        `SELECT ${CANDIDATE_ENVELOPE_COLUMNS}
           FROM rsi_cursor_advances WHERE advance_id = ?`,
      )
      .get(advanceId) as unknown as StoredCursorEnvelope;
    inspect.close();
    const needles = envelopeNeedles(candidate);
    expect(
      (await namespaceFiles(target.directory)).some((file) => file.includes(needles[3]!)),
    ).toBe(true);

    expect(target.store.abortCursorAdvance(advanceId, T3).state).toBe("aborted");
    await expectNamespaceMissing(target.directory, needles);

    const verify = new DatabaseSync(target.path);
    const destroyed = verify
      .prepare(
        `SELECT ${CANDIDATE_ENVELOPE_COLUMNS}
           FROM rsi_cursor_advances WHERE advance_id = ?`,
      )
      .get(advanceId) as Record<string, null>;
    const pending = verify
      .prepare(`SELECT cursor_erasure_pending AS pending FROM rsi_operations_metadata`)
      .get() as { pending: number };
    verify.close();
    expect(Object.values(destroyed).every((value) => value === null)).toBe(true);
    expect(pending.pending).toBe(0);

    target.store.close();
    const reopened = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    expect(reopened.readCursorAdvance(advanceId).state).toBe("aborted");
    reopened.close();
    await expectNamespaceMissing(target.directory, needles);
  });

  it("rekeys candidate-to-head commits and erases superseded revision envelopes", async () => {
    const target = await fixture();
    const first = reserve(target, "75000");
    const second = reserve(target, "75000");
    for (const attempt of [first, second]) {
      target.store.authorizeAttempt(attempt.permit, T2);
      target.store.closeAttempt(attempt.permit.attemptId, {
        closedAt: T2,
        outcome: "succeeded",
      });
    }
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });

    const firstAdvance = randomUUID();
    target.store.stageCursorAdvance({
      advanceId: firstAdvance,
      attemptId: first.permit.attemptId,
      candidateCursor: "revision-one-secret-cursor",
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    });
    const beforeFirstCommit = new DatabaseSync(target.path);
    const firstCandidate = beforeFirstCommit
      .prepare(
        `SELECT ${CANDIDATE_ENVELOPE_COLUMNS}
           FROM rsi_cursor_advances WHERE advance_id = ?`,
      )
      .get(firstAdvance) as unknown as StoredCursorEnvelope;
    beforeFirstCommit.close();
    completeCursorReceipts(target.store, firstAdvance);
    target.store.commitCursor(firstAdvance, T7);

    const afterFirstCommit = new DatabaseSync(target.path);
    const firstHead = afterFirstCommit
      .prepare(`SELECT ${ENVELOPE_COLUMNS} FROM rsi_cursor_heads`)
      .get() as unknown as StoredCursorEnvelope;
    afterFirstCommit.close();
    expect(Buffer.from(firstHead.ciphertext).equals(Buffer.from(firstCandidate.ciphertext))).toBe(
      false,
    );
    expect(
      Buffer.from(firstHead.wrapped_dek_ciphertext).equals(
        Buffer.from(firstCandidate.wrapped_dek_ciphertext),
      ),
    ).toBe(false);
    await expectNamespaceMissing(target.directory, envelopeNeedles(firstCandidate));

    const secondAdvance = randomUUID();
    target.store.stageCursorAdvance({
      advanceId: secondAdvance,
      attemptId: second.permit.attemptId,
      candidateCursor: "revision-two-secret-cursor",
      expectedRevision: 1,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T7,
    });
    target.store.markCursorValidated(secondAdvance, T8);
    const checkpointHead = "8".repeat(64);
    const anchorId = randomUUID();
    target.store.markCursorEventPersisted(secondAdvance, {
      eventHash: "7".repeat(64),
      eventId: randomUUID(),
      eventSequence: 6,
      persistedAt: T9,
    });
    target.store.markCursorCheckpointed(secondAdvance, {
      anchoredThroughSequence: 6,
      checkpointHead,
      checkpointedAt: T10,
    });
    target.store.markCursorAnchorPublished(secondAdvance, {
      anchorHead: checkpointHead,
      anchorId,
      publishedAt: T11,
    });
    target.store.markCursorExternallyVerified(secondAdvance, {
      anchorHead: checkpointHead,
      anchorId,
      verifiedAt: T12,
    });
    const beforeSecondCommit = new DatabaseSync(target.path);
    const secondCandidate = beforeSecondCommit
      .prepare(
        `SELECT ${CANDIDATE_ENVELOPE_COLUMNS}
           FROM rsi_cursor_advances WHERE advance_id = ?`,
      )
      .get(secondAdvance) as unknown as StoredCursorEnvelope;
    beforeSecondCommit.close();
    target.store.commitCursor(secondAdvance, T13);

    await expectNamespaceMissing(target.directory, [
      ...envelopeNeedles(firstHead),
      ...envelopeNeedles(secondCandidate),
    ]);
    expect(
      target.store.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 2, value: "revision-two-secret-cursor" });
    target.store.close();

    const reopened = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    expect(
      reopened.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 2, value: "revision-two-secret-cursor" });
    reopened.close();
    await expectNamespaceMissing(target.directory, [
      ...envelopeNeedles(firstHead),
      ...envelopeNeedles(secondCandidate),
    ]);
  });

  it("heals a crash after logical key deletion and before physical hardening", async () => {
    const target = await fixture();
    const attempt = reserve(target, "150000");
    target.store.authorizeAttempt(attempt.permit, T2);
    target.store.closeAttempt(attempt.permit.attemptId, {
      closedAt: T2,
      outcome: "succeeded",
    });
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });
    const advanceId = randomUUID();
    target.store.stageCursorAdvance({
      advanceId,
      attemptId: attempt.permit.attemptId,
      candidateCursor: "crash-recovery-secret-cursor",
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    });
    completeCursorReceipts(target.store, advanceId);
    const inspect = new DatabaseSync(target.path);
    const candidate = inspect
      .prepare(
        `SELECT ${CANDIDATE_ENVELOPE_COLUMNS}
           FROM rsi_cursor_advances WHERE advance_id = ?`,
      )
      .get(advanceId) as unknown as StoredCursorEnvelope;
    inspect.close();

    const internals = target.store as unknown as {
      completePendingCursorErasure(): void;
    };
    const complete = internals.completePendingCursorErasure.bind(target.store);
    let calls = 0;
    internals.completePendingCursorErasure = () => {
      calls += 1;
      if (calls === 1) complete();
      else throw new Error("injected crash before cursor erasure hardening");
    };
    expect(() => target.store.commitCursor(advanceId, T7)).toThrow("injected crash");

    const pendingDatabase = new DatabaseSync(target.path);
    const pending = pendingDatabase
      .prepare(`SELECT cursor_erasure_pending AS pending FROM rsi_operations_metadata`)
      .get() as { pending: number };
    pendingDatabase.close();
    expect(pending.pending).toBe(1);

    const recovered = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    expect(
      recovered.readCursor({ lane: "official", profile: "canary", sourcePlane: "social" }),
    ).toMatchObject({ revision: 1, value: "crash-recovery-secret-cursor" });
    expect(recovered.commitCursor(advanceId, T7)).toMatchObject({ state: "committed" });
    recovered.close();
    target.store.close();
    await expectNamespaceMissing(target.directory, envelopeNeedles(candidate));
  });

  it("repeats hardening when a crash leaves the authenticated pending bit after VACUUM", async () => {
    const target = await fixture();
    const attempt = reserve(target, "150000");
    target.store.authorizeAttempt(attempt.permit, T2);
    target.store.closeAttempt(attempt.permit.attemptId, {
      closedAt: T2,
      outcome: "succeeded",
    });
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });
    const advanceId = randomUUID();
    target.store.stageCursorAdvance({
      advanceId,
      attemptId: attempt.permit.attemptId,
      candidateCursor: "post-vacuum-crash-secret-cursor",
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    });
    const inspect = new DatabaseSync(target.path);
    const candidate = inspect
      .prepare(
        `SELECT ${CANDIDATE_ENVELOPE_COLUMNS}
           FROM rsi_cursor_advances WHERE advance_id = ?`,
      )
      .get(advanceId) as unknown as StoredCursorEnvelope;
    inspect.close();

    const internals = target.store as unknown as {
      writeCursorErasurePending(pending: boolean): void;
    };
    const writePending = internals.writeCursorErasurePending.bind(target.store);
    internals.writeCursorErasurePending = (pending) => {
      if (!pending) throw new Error("injected crash after cursor erasure hardening");
      writePending(pending);
    };
    expect(() => target.store.abortCursorAdvance(advanceId, T3)).toThrow("injected crash");
    await expectNamespaceMissing(target.directory, envelopeNeedles(candidate));

    const recovered = new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey });
    expect(recovered.readCursorAdvance(advanceId).state).toBe("aborted");
    expect(recovered.abortCursorAdvance(advanceId, T3).state).toBe("aborted");
    expect(recovered.verifyIntegrity().valid).toBe(true);
    recovered.close();
    target.store.close();
    await expectNamespaceMissing(target.directory, envelopeNeedles(candidate));
  });

  it("rejects cross-profile attempts, dispatched-only attempts, and timestamp-changing retries", async () => {
    const target = await fixture();
    const attempt = reserve(target, "100000");
    target.store.authorizeAttempt(attempt.permit, T2);
    const lineageId = randomUUID();
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
    });

    expect(() =>
      target.store.stageCursorAdvance({
        advanceId: randomUUID(),
        attemptId: attempt.permit.attemptId,
        candidateCursor: "cursor",
        expectedRevision: 0,
        lane: "official",
        lineageId,
        profile: "canary",
        sourcePlane: "social",
        stagedAt: T2,
      }),
    ).toThrow("successfully closed");

    target.store.closeAttempt(attempt.permit.attemptId, { closedAt: T2, outcome: "succeeded" });
    target.store.initializeCursorLineage({
      initializedAt: T0,
      lane: "official",
      lineageId,
      profile: "production-observer",
      sourcePlane: "social",
    });
    expect(() =>
      target.store.stageCursorAdvance({
        advanceId: randomUUID(),
        attemptId: attempt.permit.attemptId,
        candidateCursor: "cursor",
        expectedRevision: 0,
        lane: "official",
        lineageId,
        profile: "production-observer",
        sourcePlane: "social",
        stagedAt: T2,
      }),
    ).toThrow("authorized attempt");

    const advanceId = randomUUID();
    target.store.stageCursorAdvance({
      advanceId,
      attemptId: attempt.permit.attemptId,
      candidateCursor: "cursor",
      expectedRevision: 0,
      lane: "official",
      lineageId,
      profile: "canary",
      sourcePlane: "social",
      stagedAt: T2,
    });
    target.store.markCursorValidated(advanceId, T3);
    expect(() => target.store.markCursorValidated(advanceId, T4)).toThrow(
      "different audit content",
    );
    expect(() =>
      target.store.markCursorEventPersisted(advanceId, {
        eventHash: "1".repeat(64),
        eventId: randomUUID(),
        eventSequence: 1,
        persistedAt: T2,
      }),
    ).toThrow("regresses its audit history");

    target.store.close();
  });
});

describe("SqliteOperationsStore integrity", () => {
  it("detects projection edits and audit-tail deletion", async () => {
    const target = await fixture();
    reserve(target, "100000");
    target.store.close();

    const tamper = new DatabaseSync(target.path);
    tamper.prepare(`UPDATE rsi_attempts SET reserved_atomic = '1'`).run();
    tamper.close();
    expect(
      () => new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey }),
    ).toThrow(OperationsIntegrityError);

    const cleanDirectory = await mkdtemp(join(tmpdir(), "rsi-operations-tail-"));
    directories.push(cleanDirectory);
    const cleanPath = join(cleanDirectory, "operations.sqlite");
    const cleanKey = randomBytes(32);
    const clean = new SqliteOperationsStore({ path: cleanPath, stateKey: cleanKey });
    clean.createBudget({
      budgetId: randomUUID(),
      createdAt: T0,
      currency: "USD_MICRO",
      endsAt: END,
      maxAtomic: "1",
      maxAttempts: 1,
      profile: "canary",
      startsAt: T0,
    });
    clean.close();
    const tailTamper = new DatabaseSync(cleanPath);
    tailTamper.prepare(`DELETE FROM rsi_operation_audit WHERE sequence = 1`).run();
    tailTamper.close();
    expect(() => new SqliteOperationsStore({ path: cleanPath, stateKey: cleanKey })).toThrow(
      OperationsIntegrityError,
    );
  });

  it("rejects the wrong state key on reopen", async () => {
    const target = await fixture();
    target.store.close();
    expect(
      () => new SqliteOperationsStore({ path: target.path, stateKey: randomBytes(32) }),
    ).toThrow(OperationsIntegrityError);
  });

  it("authenticates cursor-erasure metadata independently of the key check", async () => {
    const target = await fixture();
    target.store.close();

    const tamper = new DatabaseSync(target.path);
    tamper.prepare(`UPDATE rsi_operations_metadata SET cursor_erasure_pending = 1`).run();
    tamper.close();
    expect(
      () => new SqliteOperationsStore({ path: target.path, stateKey: target.stateKey }),
    ).toThrow("metadata failed authentication");
  });

  it("binds even an empty database to its state key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rsi-operations-empty-key-"));
    directories.push(directory);
    const path = join(directory, "operations.sqlite");
    const store = new SqliteOperationsStore({ path, stateKey: randomBytes(32) });
    store.close();

    expect(() => new SqliteOperationsStore({ path, stateKey: randomBytes(32) })).toThrow(
      OperationsIntegrityError,
    );
  });
});
