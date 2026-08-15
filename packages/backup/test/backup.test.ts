import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createSanitizedStateEvidence,
  restoreSanitizedStateEvidence,
  verifySanitizedStateEvidence,
  type StateEvidenceReceiptV1,
  type SanitizedStateEvidenceSnapshotV1,
} from "../src/index.js";
import {
  activePublicationCountForTest,
  publishArchiveCreateOnly,
  readArchiveFile,
} from "../src/filesystem.js";
import { canonicalJson, sha256 } from "../src/canonical.js";
import {
  digest,
  makeFixture,
  repackArchive,
  replaceArtifact,
  trustFor,
  unpackArchive,
  type Fixture,
} from "./fixtures.js";

const temporaryDirectories = new Set<string>();

afterEach(async () => {
  for (const directory of temporaryDirectories) {
    await rm(directory, { force: true, recursive: true });
  }
  temporaryDirectories.clear();
});

describe("sanitized state-evidence component", () => {
  it("verifies only evidence and cannot claim an acceptance-ready session is restorable", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const archivePath = join(root, "observer.rsi-backup");
    const privateDer = Buffer.from(
      fixture.releasePrivateKey.export({ format: "der", type: "pkcs8" }),
    );

    const receipt = await createSanitizedStateEvidence({
      destinationPath: archivePath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const trust = trustFor(fixture, receipt);
    const first = await verifySanitizedStateEvidence({ archivePath, trust });
    const second = await verifySanitizedStateEvidence({ archivePath, trust });

    expect(second).toEqual(first);
    expect(first).toMatchObject({
      artifactCount: 7,
      componentScope: "observer-sanitized-state-evidence",
      recoveryCompleteness: "evidence-only",
      requiredCompanionArtifacts: ["sanitized-event-archive", "signed-release-bundle"],
      status: "verified-evidence-component",
    });
    expect(first).not.toHaveProperty("path");
    expect(first).not.toHaveProperty("completeObsRec003");
    expect(first).not.toHaveProperty("restorableState");
    expect(first.status).not.toBe("accepted");
    expect(receipt).toMatchObject({
      componentScope: "observer-sanitized-state-evidence",
      recoveryCompleteness: "evidence-only",
      requiredCompanionArtifacts: ["sanitized-event-archive", "signed-release-bundle"],
    });

    const archiveBytes = await readFile(archivePath);
    expect(archiveBytes.includes(privateDer)).toBe(false);
    expect(Object.keys(fixture.signer).sort()).toEqual(["keyId", "publicKeySpkiDer", "sign"]);
    const archiveStat = await lstat(archivePath);
    expect(archiveStat.isFile()).toBe(true);
    expect(archiveStat.nlink).toBe(1);
    expect(archiveStat.mode & 0o777).toBe(0o600);

    const restorePath = join(root, "restored");
    const restored = await restoreSanitizedStateEvidence({
      archivePath,
      destinationDirectory: restorePath,
      trust,
    });
    expect(restored).toMatchObject({
      recoveryCompleteness: "evidence-only",
      restoredFileCount: 8,
      status: "verified-evidence-component",
    });
    expect((await readdir(restorePath)).sort()).toEqual(
      [
        "backup-manifest.v1.json",
        "checkpoint-head.v1.json",
        "checkpoint-journal.v1.jsonl",
        "config-schema-hashes.v1.json",
        "event-state-evidence.v1.json",
        "public-keys.v1.json",
        "recovery-evidence.v1.json",
        "release-evidence.v1.json",
      ].sort(),
    );
    expect(await readdir(restorePath)).not.toContain("sanitized-events.v1.jsonl");
    const restoredRelease = JSON.parse(
      await readFile(join(restorePath, "release-evidence.v1.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(restoredRelease).not.toHaveProperty("code");
    expect(restoredRelease).not.toHaveProperty("runbook");
  });

  it("uses random backup IDs rather than content-derived IDs", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const first = await createSanitizedStateEvidence({
      destinationPath: join(root, "first.bundle"),
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const second = await createSanitizedStateEvidence({
      destinationPath: join(root, "second.bundle"),
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    expect(first.backupId).not.toBe(second.backupId);
    expect(first.archiveSha256).not.toBe(second.archiveSha256);
  });

  it.each(["locally-verified", "acceptance-ready", "accepted"] as const)(
    "binds the closed %s session state without claiming atomic acceptance",
    async (sessionState) => {
      const root = await temporaryRoot();
      const fixture = makeFixture();
      const snapshot = cloneSnapshot(fixture.snapshot);
      snapshot.sessionState = sessionState;
      const archivePath = join(root, `${sessionState}.bundle`);
      const receipt = await createSanitizedStateEvidence({
        destinationPath: archivePath,
        signer: fixture.signer,
        snapshot,
      });
      const report = await verifySanitizedStateEvidence({
        archivePath,
        trust: trustFor(fixture, receipt),
      });
      expect(report.status).toBe("verified-evidence-component");
      expect(report.recoveryCompleteness).toBe("evidence-only");
    },
  );

  it("requires the event head, final checkpoint, and trusted head to match exactly", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const wrongEvent = cloneSnapshot(fixture.snapshot);
    wrongEvent.eventState.headHash = digest("wrong-event-head");
    await expectCreateFailure(root, fixture, wrongEvent, "INTEGRITY_MISMATCH");

    const wrongTrusted = cloneSnapshot(fixture.snapshot);
    wrongTrusted.trustedCheckpointHead.checkpointHash = digest("wrong-trusted-head");
    await expectCreateFailure(root, fixture, wrongTrusted, "INPUT_INVALID");
  });

  it("binds every closed Stage A schema and rejects duplicate or unsorted schemas", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    expect(fixture.snapshot.configSchemas.map(({ name }) => name)).toEqual([
      "alert-outbox",
      "backup-manifest",
      "capture-registry",
      "checkpoint-journal",
      "event-state",
      "external-anchor-outbox",
      "observer-config",
      "operations-state",
      "preflight-report",
      "public-projection",
      "sanitized-event-archive",
      "sanitized-state-evidence",
      "session-controller",
      "session-lifecycle",
      "source-contracts",
      "vault",
    ]);
    for (const mode of ["duplicate", "unsorted"] as const) {
      const snapshot = cloneSnapshot(fixture.snapshot);
      if (mode === "duplicate") snapshot.configSchemas[1] = { ...snapshot.configSchemas[0]! };
      else snapshot.configSchemas.reverse();
      snapshot.release.configSetSha256 = configSetHash(snapshot.configSchemas);
      await expectCreateFailure(root, fixture, snapshot, "INPUT_INVALID");
    }
  });

  it("rejects accessors, proxies, exotic records, sparse arrays, and shared byte views", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    let getterCalls = 0;
    const accessorOptions = {
      destinationPath: join(root, "accessor.bundle"),
      signer: fixture.signer,
      get snapshot() {
        getterCalls += 1;
        return fixture.snapshot;
      },
    };
    await expect(createSanitizedStateEvidence(accessorOptions)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    expect(getterCalls).toBe(0);

    const proxy = new Proxy(fixture.snapshot, {
      get() {
        throw new Error("proxy trap must not execute");
      },
    });
    await expect(
      createSanitizedStateEvidence({
        destinationPath: join(root, "proxy.bundle"),
        signer: fixture.signer,
        snapshot: proxy,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const exotic = cloneSnapshot(fixture.snapshot) as Record<string, unknown>;
    exotic.eventState = new (class EventState {})();
    await expectCreateFailure(root, fixture, exotic as never, "INPUT_INVALID");

    const sparse = cloneSnapshot(fixture.snapshot);
    delete sparse.configSchemas[2];
    await expectCreateFailure(root, fixture, sparse, "INPUT_INVALID");

    const shared = new Uint8Array(new SharedArrayBuffer(fixture.releasePublicDer.length));
    shared.set(fixture.releasePublicDer);
    await expect(
      createSanitizedStateEvidence({
        destinationPath: join(root, "shared.bundle"),
        signer: { ...fixture.signer, publicKeySpkiDer: shared },
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("rejects secret-like identifiers and unknown content fields", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const snapshot = cloneSnapshot(fixture.snapshot);
    snapshot.release.keyId = "password-token";
    snapshot.releasePublicKey.keyId = "password-token";
    await expect(
      createSanitizedStateEvidence({
        destinationPath: join(root, "secret.bundle"),
        signer: { ...fixture.signer, keyId: "password-token" },
        snapshot,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const unknown = cloneSnapshot(fixture.snapshot) as unknown as Record<string, unknown>;
    unknown.captureRegistry = { rawBody: "do-not-copy" };
    await expectCreateFailure(root, fixture, unknown as never, "INPUT_INVALID");
  });

  it("never reflects signer failures and never publishes after a failed signature", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const destinationPath = join(root, "signer-failed.bundle");
    const secretSentinel = "credential-value-must-not-escape";
    let caught: unknown;
    try {
      await createSanitizedStateEvidence({
        destinationPath,
        signer: {
          ...fixture.signer,
          sign: () => {
            throw new Error(secretSentinel);
          },
        },
        snapshot: fixture.snapshot,
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: "SIGNER_FAILED", message: "Manifest signer failed" });
    expect(String(caught)).not.toContain(secretSentinel);
    await expect(lstat(destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects validly re-signed prohibited roles, paths, collisions, and Unicode paths", async () => {
    const { root, fixture, archivePath, receipt } = await createValidArchive();
    const original = await readFile(archivePath);
    const attacks = [
      { path: ".env", role: "event-state-evidence" },
      { path: "../event-state-evidence.v1.json", role: "event-state-evidence" },
      { path: "Event-State.v1.json", role: "event-state-evidence" },
      { path: "e\u0301vent-state.v1.json", role: "event-state-evidence" },
      { path: "event-state-evidence.v1.json", role: "vault-body" },
    ];
    for (const [index, attack] of attacks.entries()) {
      const raw = unpackArchive(original);
      const descriptor = raw.manifest.artifacts[0]! as unknown as Record<string, unknown>;
      descriptor.path = attack.path;
      descriptor.role = attack.role;
      const altered = repackArchive(raw, fixture.releasePrivateKey, receipt);
      const alteredPath = join(root, `path-attack-${index}.bundle`);
      await writeSecure(alteredPath, altered.bytes);
      await expect(
        verifySanitizedStateEvidence({
          archivePath: alteredPath,
          trust: trustFor(fixture, altered.receipt),
        }),
      ).rejects.toMatchObject({ code: "ARCHIVE_FORMAT" });
    }

    const collisionRaw = unpackArchive(original);
    (collisionRaw.manifest.artifacts[1]! as unknown as Record<string, unknown>).path =
      "EVENT-STATE.V1.JSON";
    const collision = repackArchive(collisionRaw, fixture.releasePrivateKey, receipt);
    const collisionPath = join(root, "case-collision.bundle");
    await writeSecure(collisionPath, collision.bytes);
    await expect(
      verifySanitizedStateEvidence({
        archivePath: collisionPath,
        trust: trustFor(fixture, collision.receipt),
      }),
    ).rejects.toMatchObject({ code: "ARCHIVE_FORMAT" });
  });

  it("rejects validly re-signed secret-like or arbitrary bytes in public/config artifacts", async () => {
    const { root, fixture, archivePath, receipt } = await createValidArchive();
    const original = await readFile(archivePath);

    const publicRaw = unpackArchive(original);
    const publicArtifact = JSON.parse(publicRaw.artifacts[3]!.toString("utf8")) as Record<
      string,
      unknown
    >;
    publicArtifact.credential = "sk_live_forbidden";
    replaceArtifact(publicRaw, "public-keys", Buffer.from(canonicalJson(publicArtifact), "utf8"));
    const publicAttack = repackArchive(publicRaw, fixture.releasePrivateKey, receipt);
    const publicPath = join(root, "public-secret.bundle");
    await writeSecure(publicPath, publicAttack.bytes);
    await expect(
      verifySanitizedStateEvidence({
        archivePath: publicPath,
        trust: trustFor(fixture, publicAttack.receipt),
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const configRaw = unpackArchive(original);
    const configArtifact = JSON.parse(configRaw.artifacts[4]!.toString("utf8")) as Record<
      string,
      unknown
    >;
    configArtifact.environmentFile = ".env=super-secret";
    replaceArtifact(
      configRaw,
      "config-schema-hashes",
      Buffer.from(canonicalJson(configArtifact), "utf8"),
    );
    const configAttack = repackArchive(configRaw, fixture.releasePrivateKey, receipt);
    const configPath = join(root, "config-secret.bundle");
    await writeSecure(configPath, configAttack.bytes);
    await expect(
      verifySanitizedStateEvidence({
        archivePath: configPath,
        trust: trustFor(fixture, configAttack.receipt),
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("fails closed on manifest, file, signature, truncation, trailing, extra, and missing data", async () => {
    const { root, fixture, archivePath, receipt } = await createValidArchive();
    const original = await readFile(archivePath);

    const unknownRaw = unpackArchive(original);
    unknownRaw.manifest.credentials = "forbidden";
    const unknown = repackArchive(unknownRaw, fixture.releasePrivateKey, receipt);
    await expectAlteredFailure(root, fixture, unknown, "unknown", "INPUT_INVALID");

    const fileRaw = unpackArchive(original);
    fileRaw.artifacts[0]!.writeUInt8(fileRaw.artifacts[0]!.readUInt8(0) ^ 1, 0);
    const fileAttack = repackArchive(fileRaw, fixture.releasePrivateKey, receipt);
    await expectAlteredFailure(root, fixture, fileAttack, "file", "INTEGRITY_MISMATCH");

    const signatureRaw = unpackArchive(original);
    signatureRaw.signature = `${signatureRaw.signature[0] === "A" ? "B" : "A"}${signatureRaw.signature.slice(1)}`;
    const signatureAttack = repackArchive(signatureRaw, fixture.releasePrivateKey, receipt, false);
    await expectAlteredFailure(root, fixture, signatureAttack, "signature", "SIGNATURE_INVALID");

    const truncated = original.subarray(0, original.length - 1);
    await expectRawFailure(
      root,
      fixture,
      receiptForBytes(receipt, truncated),
      truncated,
      "truncated",
    );
    const trailing = Buffer.concat([original, Buffer.from([0])]);
    await expectRawFailure(root, fixture, receiptForBytes(receipt, trailing), trailing, "trailing");

    const extraRaw = unpackArchive(original);
    (extraRaw.manifest as unknown as Record<string, unknown>).artifactCount = 8;
    (extraRaw.manifest.artifacts as unknown as unknown[]).push({
      mediaType: "application/json",
      path: "extra.json",
      role: "extra",
      sha256: digest("extra"),
      sizeBytes: 1,
    });
    const extra = repackArchive(extraRaw, fixture.releasePrivateKey, receipt);
    await expectAlteredFailure(root, fixture, extra, "extra", "ARCHIVE_FORMAT");

    const missingRaw = unpackArchive(original);
    (missingRaw.manifest.artifacts as unknown as unknown[]).pop();
    (missingRaw.manifest as unknown as Record<string, unknown>).artifactCount = 6;
    missingRaw.artifacts.pop();
    const missing = repackArchive(missingRaw, fixture.releasePrivateKey, receipt);
    await expectAlteredFailure(root, fixture, missing, "missing", "ARCHIVE_FORMAT");

    const oversizedRaw = unpackArchive(original);
    (oversizedRaw.manifest.artifacts[0]! as unknown as Record<string, unknown>).sizeBytes =
      64 * 1024 + 1;
    (oversizedRaw.manifest as unknown as Record<string, unknown>).totalArtifactBytes =
      oversizedRaw.manifest.artifacts.reduce((sum, entry) => sum + entry.sizeBytes, 0);
    const oversized = repackArchive(oversizedRaw, fixture.releasePrivateKey, receipt);
    await expectAlteredFailure(root, fixture, oversized, "oversized", "ARCHIVE_BOUNDS");
  });

  it("detects rollback through the independently retained exact receipt", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const oldPath = join(root, "old.bundle");
    const newPath = join(root, "new.bundle");
    const oldReceipt = await createSanitizedStateEvidence({
      destinationPath: oldPath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    const newReceipt = await createSanitizedStateEvidence({
      destinationPath: newPath,
      signer: fixture.signer,
      snapshot: fixture.snapshot,
    });
    expect(oldReceipt.backupId).not.toBe(newReceipt.backupId);
    await expect(
      verifySanitizedStateEvidence({ archivePath: oldPath, trust: trustFor(fixture, newReceipt) }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
  });

  it("rejects any attempt to drop either recovery companion from signed claims", async () => {
    const { root, fixture, archivePath, receipt } = await createValidArchive();
    const raw = unpackArchive(await readFile(archivePath));
    (raw.manifest as unknown as Record<string, unknown>).requiredCompanionArtifacts = [
      "signed-release-bundle",
    ];
    const altered = repackArchive(raw, fixture.releasePrivateKey, receipt);
    await expectAlteredFailure(root, fixture, altered, "missing-companion", "ARCHIVE_FORMAT");

    const downgradedReceipt = {
      ...receipt,
      requiredCompanionArtifacts: ["signed-release-bundle"],
    } as never;
    await expect(
      verifySanitizedStateEvidence({
        archivePath,
        trust: trustFor(fixture, downgradedReceipt),
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
  });

  it("rejects links, special files, directories, unsafe permissions, and symlinked parents", async () => {
    const { root, fixture, archivePath, receipt } = await createValidArchive();
    const trust = trustFor(fixture, receipt);
    const symlinkPath = join(root, "archive-symlink");
    await symlink(archivePath, symlinkPath);
    await expect(
      verifySanitizedStateEvidence({ archivePath: symlinkPath, trust }),
    ).rejects.toMatchObject({
      code: "ARCHIVE_UNSAFE",
    });

    const hardlinkPath = join(root, "archive-hardlink");
    await link(archivePath, hardlinkPath);
    await expect(verifySanitizedStateEvidence({ archivePath, trust })).rejects.toMatchObject({
      code: "ARCHIVE_UNSAFE",
    });
    await rm(hardlinkPath);

    const directoryPath = join(root, "directory.bundle");
    await mkdir(directoryPath);
    await expect(
      verifySanitizedStateEvidence({ archivePath: directoryPath, trust }),
    ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });

    const socketPath = join(root, "socket.bundle");
    const server = createServer();
    await new Promise<void>((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(socketPath, resolveListen);
    });
    try {
      await expect(
        verifySanitizedStateEvidence({ archivePath: socketPath, trust }),
      ).rejects.toMatchObject({ code: "ARCHIVE_UNSAFE" });
    } finally {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }

    const realParent = join(root, "real-parent");
    const aliasParent = join(root, "alias-parent");
    await mkdir(realParent);
    await symlink(realParent, aliasParent);
    const copied = join(realParent, "copied.bundle");
    await writeSecure(copied, await readFile(archivePath));
    await expect(
      verifySanitizedStateEvidence({ archivePath: join(aliasParent, "copied.bundle"), trust }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });

    const writableParent = join(root, "world-writable-parent");
    await mkdir(writableParent);
    await chmod(writableParent, 0o777);
    const unsafeDestination = join(writableParent, "unsafe.bundle");
    await expect(
      createSanitizedStateEvidence({
        destinationPath: unsafeDestination,
        signer: fixture.signer,
        snapshot: fixture.snapshot,
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });
    await expect(lstat(unsafeDestination)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("publishes create-only under concurrency and cleans interrupted partials", async () => {
    const root = await temporaryRoot();
    const fixture = makeFixture();
    const destinationPath = join(root, "concurrent.bundle");
    const attempts = await Promise.allSettled([
      createSanitizedStateEvidence({
        destinationPath,
        signer: fixture.signer,
        snapshot: fixture.snapshot,
      }),
      createSanitizedStateEvidence({
        destinationPath,
        signer: fixture.signer,
        snapshot: fixture.snapshot,
      }),
    ]);
    expect(attempts.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    const rejected = attempts.find(({ status }) => status === "rejected");
    expect(rejected).toMatchObject({ reason: { code: "DESTINATION_EXISTS" } });

    const bytes = await readFile(destinationPath);
    const interruptedPath = join(root, "interrupted.bundle");
    await expect(
      publishArchiveCreateOnly(interruptedPath, bytes, {
        beforeLink: () => {
          throw new Error("simulated interruption");
        },
      }),
    ).rejects.toMatchObject({ code: "DESTINATION_UNSAFE" });
    await expect(lstat(interruptedPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(root)).some((name) => name.startsWith(".rsi-backup-partial-"))).toBe(
      false,
    );

    const orphan = join(root, `.rsi-backup-partial-${randomUUID()}`);
    await writeSecure(orphan, Buffer.from("crash-partial", "utf8"));
    const fulfilled = attempts.find(
      (entry): entry is PromiseFulfilledResult<StateEvidenceReceiptV1> =>
        entry.status === "fulfilled",
    )!;
    await expect(
      verifySanitizedStateEvidence({
        archivePath: destinationPath,
        trust: trustFor(fixture, fulfilled.value),
      }),
    ).resolves.toMatchObject({ status: "verified-evidence-component" });
  });

  it("boundedly waits through only its own transient nlink=2 publication window", async () => {
    const { root, archivePath } = await createValidArchive();
    const bytes = await readFile(archivePath);
    const destinationPath = join(root, "gated.bundle");
    const linked = deferred();
    const releasePublisher = deferred();
    const readerObserved = deferred();
    const publishing = publishArchiveCreateOnly(destinationPath, bytes, {
      afterLink: async () => {
        linked.resolve();
        await releasePublisher.promise;
      },
    });
    await linked.promise;
    expect(activePublicationCountForTest()).toBe(1);
    const reading = readArchiveFile(destinationPath, {
      onRecognizedTransientLink: () => readerObserved.resolve(),
    });
    await readerObserved.promise;
    releasePublisher.resolve();
    await publishing;
    await expect(reading).resolves.toEqual(bytes);
    expect(activePublicationCountForTest()).toBe(0);
    expect((await lstat(destinationPath)).nlink).toBe(1);
  });

  it("verifies before restore writes and refuses every overwrite", async () => {
    const { root, fixture, archivePath, receipt } = await createValidArchive();
    const trust = trustFor(fixture, receipt);
    const existing = join(root, "existing");
    await mkdir(existing);
    await writeFile(join(existing, "sentinel"), "keep", { mode: 0o600 });
    await expect(
      restoreSanitizedStateEvidence({ archivePath, destinationDirectory: existing, trust }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });
    expect(await readFile(join(existing, "sentinel"), "utf8")).toBe("keep");

    const tampered = Buffer.from(await readFile(archivePath));
    tampered.writeUInt8(tampered.readUInt8(tampered.length - 1) ^ 1, tampered.length - 1);
    const tamperedPath = join(root, "tampered.bundle");
    await writeSecure(tamperedPath, tampered);
    const absentDestination = join(root, "must-stay-absent");
    await expect(
      restoreSanitizedStateEvidence({
        archivePath: tamperedPath,
        destinationDirectory: absentDestination,
        trust,
      }),
    ).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
    await expect(lstat(absentDestination)).rejects.toMatchObject({ code: "ENOENT" });

    const restored = join(root, "restored-once");
    await restoreSanitizedStateEvidence({ archivePath, destinationDirectory: restored, trust });
    await expect(
      restoreSanitizedStateEvidence({ archivePath, destinationDirectory: restored, trust }),
    ).rejects.toMatchObject({ code: "DESTINATION_EXISTS" });
  });
});

async function createValidArchive(): Promise<{
  readonly archivePath: string;
  readonly fixture: Fixture;
  readonly receipt: StateEvidenceReceiptV1;
  readonly root: string;
}> {
  const root = await temporaryRoot();
  const fixture = makeFixture();
  const archivePath = join(root, "valid.bundle");
  const receipt = await createSanitizedStateEvidence({
    destinationPath: archivePath,
    signer: fixture.signer,
    snapshot: fixture.snapshot,
  });
  return { archivePath, fixture, receipt, root };
}

async function expectCreateFailure(
  root: string,
  fixture: Fixture,
  snapshot: SanitizedStateEvidenceSnapshotV1,
  code: string,
): Promise<void> {
  await expect(
    createSanitizedStateEvidence({
      destinationPath: join(root, `${randomUUID()}.bundle`),
      signer: fixture.signer,
      snapshot,
    }),
  ).rejects.toMatchObject({ code });
}

async function expectAlteredFailure(
  root: string,
  fixture: Fixture,
  altered: { readonly bytes: Buffer; readonly receipt: StateEvidenceReceiptV1 },
  name: string,
  code: string,
): Promise<void> {
  const path = join(root, `${name}.bundle`);
  await writeSecure(path, altered.bytes);
  await expect(
    verifySanitizedStateEvidence({ archivePath: path, trust: trustFor(fixture, altered.receipt) }),
  ).rejects.toMatchObject({ code });
}

async function expectRawFailure(
  root: string,
  fixture: Fixture,
  receipt: StateEvidenceReceiptV1,
  bytes: Buffer,
  name: string,
): Promise<void> {
  const path = join(root, `${name}.bundle`);
  await writeSecure(path, bytes);
  await expect(
    verifySanitizedStateEvidence({ archivePath: path, trust: trustFor(fixture, receipt) }),
  ).rejects.toBeDefined();
}

function receiptForBytes(receipt: StateEvidenceReceiptV1, bytes: Buffer): StateEvidenceReceiptV1 {
  return Object.freeze({
    ...receipt,
    archiveSha256: sha256(bytes),
    archiveSizeBytes: bytes.length,
  });
}

function configSetHash(schemas: readonly unknown[]): string {
  return sha256(
    canonicalJson({
      configSchemaHashesType: "rsi.backup.config-schema-hashes",
      schemas,
      version: 1,
    }),
  );
}

function cloneSnapshot(snapshot: SanitizedStateEvidenceSnapshotV1): WritableSnapshot {
  return JSON.parse(JSON.stringify(snapshot)) as WritableSnapshot;
}

type WritableSnapshot = {
  -readonly [
    Key in keyof SanitizedStateEvidenceSnapshotV1
  ]: SanitizedStateEvidenceSnapshotV1[Key] extends readonly (infer Entry)[]
    ? Entry[]
    : SanitizedStateEvidenceSnapshotV1[Key] extends object
      ? {
          -readonly [
            Nested in keyof SanitizedStateEvidenceSnapshotV1[Key]
          ]: SanitizedStateEvidenceSnapshotV1[Key][Nested];
        }
      : SanitizedStateEvidenceSnapshotV1[Key];
};

async function temporaryRoot(): Promise<string> {
  const created = await mkdtemp(join(tmpdir(), "rsi-backup-test-"));
  const canonical = await realpath(created);
  temporaryDirectories.add(canonical);
  return canonical;
}

async function writeSecure(path: string, bytes: Buffer): Promise<void> {
  await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
}

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolvePromise!: () => void;
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}
