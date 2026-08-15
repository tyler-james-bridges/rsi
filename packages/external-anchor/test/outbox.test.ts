import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  ExternalAnchorConflictError,
  ExternalAnchorIntegrityError,
  ExternalAnchorPublisher,
  ExternalAnchorTransportError,
  InMemoryAnchorObjectStore,
  SqliteExternalAnchorOutbox,
  isSqliteExternalAnchorOutbox,
} from "../src/index.js";
import {
  T0,
  T1,
  T2,
  T3,
  anchorAuthorization,
  checkpointChain,
  checkpointIdentity,
  signedCheckpoint,
} from "./helpers.js";

function enqueueInput(
  identity: ReturnType<typeof checkpointIdentity>,
  checkpoint: ReturnType<typeof checkpointChain>[number],
  queuedAt: string,
  retentionMode: "compliance" | "governance",
) {
  return {
    authorization: anchorAuthorization(identity, checkpoint, retentionMode),
    checkpoint,
    queuedAt,
  };
}

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "rsi-external-anchor-"));
  directories.push(directory);
  const databasePath = join(directory, "outbox.sqlite");
  const identity = checkpointIdentity();
  const stateKey = randomBytes(32);
  const options = {
    databasePath,
    expectedKeyId: identity.expectedKeyId,
    expectedPublicKey: identity.expectedPublicKey,
    expectedStoreId: identity.expectedStoreId,
    profile: "canary" as const,
    stateKey,
  };
  return {
    databasePath,
    identity,
    options,
    outbox: SqliteExternalAnchorOutbox.open(options),
    stateKey,
  };
}

describe("durable external anchor outbox", () => {
  it("requires the authenticated open path at runtime", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rsi-external-anchor-construction-"));
    directories.push(directory);
    const identity = checkpointIdentity();
    const options = {
      databasePath: join(directory, "outbox.sqlite"),
      expectedKeyId: identity.expectedKeyId,
      expectedPublicKey: identity.expectedPublicKey,
      expectedStoreId: identity.expectedStoreId,
      profile: "canary" as const,
      stateKey: randomBytes(32),
    };
    const RuntimeOutbox = SqliteExternalAnchorOutbox as unknown as new (
      openOptions: typeof options,
      constructionToken: object,
    ) => SqliteExternalAnchorOutbox;
    expect(() => new RuntimeOutbox(options, Object.freeze({}))).toThrow(
      ExternalAnchorIntegrityError,
    );

    const forged = Object.create(
      SqliteExternalAnchorOutbox.prototype,
    ) as SqliteExternalAnchorOutbox;
    expect(isSqliteExternalAnchorOutbox(forged)).toBe(false);
    expect(() => forged.verifyIntegrity()).toThrow(ExternalAnchorIntegrityError);
    expect(() => forged.close()).toThrow(ExternalAnchorIntegrityError);

    const opened = SqliteExternalAnchorOutbox.open(options);
    expect(isSqliteExternalAnchorOutbox(opened)).toBe(true);
    opened.close();
  });

  it("enqueues exactly once and rejects retention changes or journal forks", async () => {
    const target = await fixture();
    const checkpoint = checkpointChain(target.identity, 1)[0]!;
    const input = enqueueInput(target.identity, checkpoint, T0, "governance");
    const first = target.outbox.enqueue(input);
    expect(target.outbox.enqueue(input)).toEqual(first);
    expect(first).toMatchObject({
      attemptCount: 0,
      journalSequence: 1,
      retentionMode: "governance",
      state: "pending",
    });
    expect(() =>
      target.outbox.enqueue({
        ...input,
        authorization: anchorAuthorization(target.identity, checkpoint, "compliance"),
      }),
    ).toThrow(ExternalAnchorConflictError);

    const fork = signedCheckpoint(target.identity, {
      createdAt: T0,
      journalSequence: 1,
      storeHeadHash: "b".repeat(64),
      storeHeadSequence: 11,
    });
    expect(() =>
      target.outbox.enqueue(enqueueInput(target.identity, fork, T0, "governance")),
    ).toThrow("journal sequence");
    expect(target.outbox.verifyIntegrity()).toMatchObject({ pendingCount: 1, valid: true });
    target.outbox.close();
  });

  it("recovers a crash after create as an exact second-attempt already-exists completion", async () => {
    const target = await fixture();
    target.outbox.enqueue(
      enqueueInput(target.identity, checkpointChain(target.identity, 1)[0]!, T0, "governance"),
    );
    const backend = new InMemoryAnchorObjectStore({ clock: () => T1 });
    const writer = backend.publisherTransport();
    const firstClaim = target.outbox.claim({ claimedAt: T0 })!;
    const created = await writer.create(firstClaim.request);
    expect(created.disposition).toBe("created");

    target.outbox.close();
    const reopened = SqliteExternalAnchorOutbox.open(target.options);
    expect(reopened.verifyIntegrity()).toMatchObject({ inFlightCount: 1, valid: true });
    expect(reopened.recover({ recoveredAt: T2 })).toEqual({
      failed: 0,
      recoveredAt: T2,
      requeued: 1,
    });
    const secondClaim = reopened.claim({ claimedAt: T2 })!;
    expect(secondClaim.attempt).toBe(2);
    expect(secondClaim.request).toEqual(firstClaim.request);
    const existing = await writer.create(secondClaim.request);
    expect(existing.disposition).toBe("already_exists");
    const receipt = reopened.complete({
      attempt: 2,
      completedAt: T3,
      objectKey: secondClaim.objectKey,
      result: existing,
    });
    expect(receipt).toMatchObject({
      attemptCount: 2,
      disposition: "already_exists",
      state: "published",
    });
    expect(
      reopened.complete({
        attempt: 2,
        completedAt: T3,
        objectKey: secondClaim.objectKey,
        result: existing,
      }),
    ).toEqual(receipt);
    expect(reopened.verifyIntegrity()).toMatchObject({ publishedCount: 1, valid: true });
    reopened.close();
  });

  it("bounds failures to two consumed attempts and classifies retryable transport errors", async () => {
    const target = await fixture();
    target.outbox.enqueue(
      enqueueInput(target.identity, checkpointChain(target.identity, 1)[0]!, T0, "governance"),
    );
    const times = [T0, T1];
    const publisher = new ExternalAnchorPublisher({
      clock: () => times.shift()!,
      outbox: target.outbox,
      transport: Object.freeze({
        create: async () => {
          throw new ExternalAnchorTransportError("TIMEOUT");
        },
      }),
    });
    await expect(publisher.publishNext()).rejects.toBeInstanceOf(ExternalAnchorTransportError);
    expect(target.outbox.verifyIntegrity()).toMatchObject({ pendingCount: 1, valid: true });

    const second = target.outbox.claim({ claimedAt: T1 })!;
    expect(second.attempt).toBe(2);
    expect(
      target.outbox.fail({
        attempt: 2,
        failedAt: T2,
        objectKey: second.objectKey,
        retryable: true,
      }),
    ).toMatchObject({ attemptCount: 2, state: "failed" });
    expect(target.outbox.claim({ claimedAt: T3 })).toBeUndefined();
    expect(target.outbox.verifyIntegrity()).toMatchObject({ failedCount: 1, valid: true });
    target.outbox.close();
  });

  it("detects wrong keys, row edits, and authenticated row deletion", async () => {
    const wrongKeyTarget = await fixture();
    wrongKeyTarget.outbox.close();
    expect(() =>
      SqliteExternalAnchorOutbox.open({
        ...wrongKeyTarget.options,
        stateKey: randomBytes(32),
      }),
    ).toThrow(ExternalAnchorIntegrityError);

    const editTarget = await fixture();
    editTarget.outbox.enqueue(
      enqueueInput(
        editTarget.identity,
        checkpointChain(editTarget.identity, 1)[0]!,
        T0,
        "governance",
      ),
    );
    editTarget.outbox.close();
    const edit = new DatabaseSync(editTarget.databasePath);
    edit.prepare(`UPDATE rsi_external_anchor_outbox SET store_head_sequence = 999`).run();
    edit.close();
    expect(() => SqliteExternalAnchorOutbox.open(editTarget.options)).toThrow(
      ExternalAnchorIntegrityError,
    );

    const deleteTarget = await fixture();
    deleteTarget.outbox.enqueue(
      enqueueInput(
        deleteTarget.identity,
        checkpointChain(deleteTarget.identity, 1)[0]!,
        T0,
        "governance",
      ),
    );
    deleteTarget.outbox.close();
    const deletion = new DatabaseSync(deleteTarget.databasePath);
    deletion.exec(`
      DELETE FROM rsi_external_anchor_outbox;
      DELETE FROM rsi_external_anchor_metadata;
    `);
    deletion.close();
    expect(() => SqliteExternalAnchorOutbox.open(deleteTarget.options)).toThrow(
      ExternalAnchorIntegrityError,
    );

    const triggerTarget = await fixture();
    triggerTarget.outbox.enqueue(
      enqueueInput(
        triggerTarget.identity,
        checkpointChain(triggerTarget.identity, 1)[0]!,
        T0,
        "governance",
      ),
    );
    triggerTarget.outbox.close();
    const trigger = new DatabaseSync(triggerTarget.databasePath);
    trigger.exec(`
      CREATE TRIGGER delete_anchor_after_update
      AFTER UPDATE ON rsi_external_anchor_outbox
      BEGIN
        DELETE FROM rsi_external_anchor_outbox;
      END;
    `);
    trigger.close();
    expect(() => SqliteExternalAnchorOutbox.open(triggerTarget.options)).toThrow(
      ExternalAnchorIntegrityError,
    );
  });
});
