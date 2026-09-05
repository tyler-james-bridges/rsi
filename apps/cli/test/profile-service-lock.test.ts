import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";
import { SnapshotVault } from "@rsi/vault";

import {
  IncompleteCanaryResourceAcquisitionError,
  IncompleteCanaryOperatorStartupCleanupError,
  acquireCanaryResource,
  rethrowCanaryStartupFailureAfterCleanup,
  rethrowCanaryStartupFailureAfterProfileLockDecision,
} from "../src/canary-operator-startup-cleanup.js";
import {
  PROFILE_SERVICE_LOCK_ERROR_MESSAGES,
  ProfileServiceLockError,
  acquireCanaryProfileLockForDatabasePathForTesting,
  acquireProfileServiceLockForTesting,
  assertCanaryProfileLockForDatabasePath,
  bindProfileServiceLock,
  type ProfileServiceLock,
} from "../src/profile-service-lock.testing.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const TSX_CLI = fileURLToPath(new URL("../../../node_modules/tsx/dist/cli.mjs", import.meta.url));
const PROCESS_FIXTURE = fileURLToPath(
  new URL("fixtures/profile-service-lock-process-fixture.ts", import.meta.url),
);
const SCOPE_ID = "stage1-canary";

let directory: string | undefined;
let child: ChildProcessWithoutNullStreams | undefined;
let lock: ProfileServiceLock | undefined;

function waitForLine(
  stream: NodeJS.ReadableStream,
  expected: string,
  timeoutMessage: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error(timeoutMessage)), 8_000);
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      output += chunk;
      if (!output.includes(expected)) return;
      clearTimeout(timeout);
      resolve(output);
    });
  });
}

function waitForExit(
  process: ChildProcessWithoutNullStreams,
): Promise<Readonly<{ code: number | null; stderr: string; stdout: string }>> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => reject(new Error("lock fixture timed out")), 8_000);
    process.stdout.setEncoding("utf8");
    process.stderr.setEncoding("utf8");
    process.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    process.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    process.once("error", reject);
    process.once("exit", (code) => {
      clearTimeout(timeout);
      resolve({ code, stderr, stdout });
    });
  });
}

function spawnFixture(command: "hold" | "once", dataDirectory: string) {
  return spawn(process.execPath, [TSX_CLI, PROCESS_FIXTURE, command, dataDirectory, SCOPE_ID], {
    cwd: ROOT,
    env: process.env,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

async function privateTemporaryDirectory(prefix: string): Promise<string> {
  const created = await mkdtemp(join(tmpdir(), prefix));
  await chmod(created, 0o700);
  return realpath(created);
}

afterEach(async () => {
  vi.restoreAllMocks();
  await lock?.release().catch(() => undefined);
  lock = undefined;
  if (child !== undefined && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await waitForExit(child).catch(() => undefined);
  }
  child = undefined;
  if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  directory = undefined;
});

describe("profile service lock", () => {
  it("creates one canonical owner-only artifact and removes it on idempotent release", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-owner-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });

    const expectedPath = join(directory, `.rsi-${SCOPE_ID}.lock`);
    const entry = await lstat(lock.artifactPath, { bigint: true });
    expect(lock.artifactPath).toBe(expectedPath);
    expect(lock.scopeId).toBe(SCOPE_ID);
    expect(entry.isFile()).toBe(true);
    expect(entry.isSymbolicLink()).toBe(false);
    expect(entry.nlink).toBe(1n);
    expect(entry.mode & 0o777n).toBe(0o600n);
    expect(entry.uid).toBe(BigInt(process.geteuid!()));
    const artifact = JSON.parse(await readFile(expectedPath, "utf8")) as Record<string, unknown>;
    expect(Object.keys(artifact).sort()).toEqual(["ownerToken", "schemaVersion", "scopeId"]);
    expect(artifact).toMatchObject({
      schemaVersion: 1,
      scopeId: SCOPE_ID,
    });
    expect(artifact.ownerToken).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );

    await Promise.all([lock.release(), lock.release()]);
    await expect(lstat(expectedPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      assertCanaryProfileLockForDatabasePath(lock, join(directory, "runtime.sqlite")),
    ).rejects.toThrow(PROFILE_SERVICE_LOCK_ERROR_MESSAGES.unsafe);
    await lock.release();
    lock = undefined;
  });

  it("atomically rejects a real child-process contender and permits acquisition after release", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-process-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });

    child = spawnFixture("once", directory);
    const refused = await waitForExit(child);
    expect(refused).toEqual({
      code: 2,
      stdout: "",
      stderr: `contended: ${PROFILE_SERVICE_LOCK_ERROR_MESSAGES.contended}\n`,
    });
    child = undefined;

    await lock.release();
    lock = undefined;
    child = spawnFixture("once", directory);
    const acquired = await waitForExit(child);
    expect(acquired).toEqual({ code: 0, stderr: "", stdout: "acquired\nreleased\n" });
    child = undefined;
  });

  it("retains the artifact when acquisition cannot synchronize its directory entry", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-create-sync-");
    const probe = await open(directory, constants.O_RDONLY);
    const fileHandlePrototype = Object.getPrototypeOf(probe) as {
      sync: FileHandle["sync"];
    };
    await probe.close();
    const originalSync = fileHandlePrototype.sync;
    let injectDirectorySyncFailure = true;
    const syncSpy = vi.spyOn(fileHandlePrototype, "sync").mockImplementation(async function (
      this: FileHandle,
    ): Promise<void> {
      if (injectDirectorySyncFailure && (await this.stat()).isDirectory()) {
        injectDirectorySyncFailure = false;
        throw new Error("injected lock directory sync failure");
      }
      await originalSync.call(this);
    });

    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "unsafe" });
    expect((await lstat(join(directory, `.rsi-${SCOPE_ID}.lock`))).isFile()).toBe(true);

    syncSpy.mockRestore();
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "contended" });
  });

  it("reports release uncertainty when the removed directory entry cannot be synchronized", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-release-sync-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
    const artifactPath = lock.artifactPath;
    const probe = await open(directory, constants.O_RDONLY);
    const fileHandlePrototype = Object.getPrototypeOf(probe) as {
      sync: FileHandle["sync"];
    };
    await probe.close();
    const originalSync = fileHandlePrototype.sync;
    let injectDirectorySyncFailure = true;
    vi.spyOn(fileHandlePrototype, "sync").mockImplementation(async function (
      this: FileHandle,
    ): Promise<void> {
      if (injectDirectorySyncFailure && (await this.stat()).isDirectory()) {
        injectDirectorySyncFailure = false;
        throw new Error("injected lock release directory sync failure");
      }
      await originalSync.call(this);
    });

    await expect(lock.release()).rejects.toMatchObject({
      code: "durability",
      message: PROFILE_SERVICE_LOCK_ERROR_MESSAGES.durability,
    });
    await expect(lstat(artifactPath)).rejects.toMatchObject({ code: "ENOENT" });
    lock = undefined;
  });

  it("releases only after full resource shutdown and shares concurrent close calls", async () => {
    const events: string[] = [];
    let finishShutdown: (() => void) | undefined;
    const shutdown = new Promise<void>((resolve) => {
      finishShutdown = resolve;
    });
    const resource = Object.freeze({
      marker: "resource",
      close: async () => {
        events.push("resource-start");
        await shutdown;
        events.push("resource-finished");
      },
    });
    const guarded = bindProfileServiceLock(resource, {
      release: async () => {
        events.push("lock-released");
      },
    });

    const first = guarded.close();
    const second = guarded.close();
    expect(first).toBe(second);
    expect(events).toEqual(["resource-start"]);
    finishShutdown!();
    await Promise.all([first, second]);
    expect(events).toEqual(["resource-start", "resource-finished", "lock-released"]);
    expect(guarded.marker).toBe("resource");
  });

  it("keeps the lock fail-closed when resource shutdown does not complete", async () => {
    const shutdownFailure = new Error("shutdown incomplete");
    const release = vi.fn(async () => undefined);
    const guarded = bindProfileServiceLock(
      Object.freeze({
        close: vi.fn(async () => {
          throw shutdownFailure;
        }),
      }),
      { release },
    );

    await expect(guarded.close()).rejects.toBe(shutdownFailure);
    expect(release).not.toHaveBeenCalled();
    await expect(guarded.close()).rejects.toBe(shutdownFailure);
    expect(release).not.toHaveBeenCalled();
  });

  it("rejects class instances and accessors without invoking resource getters", () => {
    class ClassResource {
      async close(): Promise<void> {}
    }
    expect(() =>
      bindProfileServiceLock(new ClassResource(), { release: async () => undefined }),
    ).toThrow("A plain profile-lock resource is required");

    let getterRead = false;
    const accessorResource = {};
    Object.defineProperty(accessorResource, "close", {
      enumerable: true,
      get: () => {
        getterRead = true;
        return async () => undefined;
      },
    });
    expect(() =>
      bindProfileServiceLock(accessorResource as { close(): Promise<void> }, {
        release: async () => undefined,
      }),
    ).toThrow("A plain profile-lock resource is required");
    expect(getterRead).toBe(false);
  });

  it("retains the profile lock when Vault directory synchronization fails during close", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-vault-close-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
    const vault = await SnapshotVault.open({
      directory: join(directory, "vault"),
      wrappingKey: randomBytes(32),
    });
    const probe = await open(directory, constants.O_RDONLY);
    const fileHandlePrototype = Object.getPrototypeOf(probe) as {
      sync: FileHandle["sync"];
    };
    await probe.close();
    const originalSync = fileHandlePrototype.sync;
    let injectDirectorySyncFailure = true;
    vi.spyOn(fileHandlePrototype, "sync").mockImplementation(async function (
      this: FileHandle,
    ): Promise<void> {
      if (injectDirectorySyncFailure && (await this.stat()).isDirectory()) {
        injectDirectorySyncFailure = false;
        throw new Error("injected Vault directory sync failure");
      }
      await originalSync.call(this);
    });
    const guarded = bindProfileServiceLock({ close: () => vault.close() }, lock);

    await expect(guarded.close()).rejects.toThrow("Capture vault close did not complete safely");
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "contended" });
  });

  it("retains an owned artifact when startup cleanup is incomplete", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-startup-cleanup-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
    const startupFailure = new Error("startup failed");
    const cleanupFailure = new Error("cleanup failed");
    let incomplete: unknown;

    try {
      await rethrowCanaryStartupFailureAfterCleanup(startupFailure, async () => {
        throw cleanupFailure;
      });
    } catch (error) {
      incomplete = error;
    }

    expect(incomplete).toBeInstanceOf(IncompleteCanaryOperatorStartupCleanupError);
    expect((incomplete as AggregateError).errors).toEqual([startupFailure, cleanupFailure]);
    await expect(
      rethrowCanaryStartupFailureAfterProfileLockDecision(
        incomplete,
        lock,
        "startup and release failed",
      ),
    ).rejects.toBe(incomplete);
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "contended" });

    await lock.release();
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
  });

  it("retains an owned artifact when a stateful acquisition returns no cleanup handle", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-resource-acquisition-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
    let incomplete: unknown;
    try {
      acquireCanaryResource(() => {
        throw new Error("stateful acquisition failed");
      });
    } catch (error) {
      incomplete = error;
    }

    expect(incomplete).toBeInstanceOf(IncompleteCanaryResourceAcquisitionError);
    await expect(
      rethrowCanaryStartupFailureAfterProfileLockDecision(
        incomplete,
        lock,
        "startup and release failed",
      ),
    ).rejects.toBe(incomplete);
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "contended" });
  });

  it("releases the artifact after a startup failure with proven cleanup", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-clean-startup-failure-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
    const startupFailure = new Error("startup failed after clean shutdown");

    await expect(
      rethrowCanaryStartupFailureAfterProfileLockDecision(
        startupFailure,
        lock,
        "startup and release failed",
      ),
    ).rejects.toBe(startupFailure);
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
  });

  it("does not silently reclaim a lock left by a terminated owner process", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-stale-");
    child = spawnFixture("hold", directory);
    await waitForLine(child.stdout, "acquired\n", "lock owner did not acquire");
    const exited = waitForExit(child);
    child.kill("SIGKILL");
    await exited;
    child = undefined;

    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({
      code: "contended",
      message: PROFILE_SERVICE_LOCK_ERROR_MESSAGES.contended,
    });
    expect((await lstat(join(directory, `.rsi-${SCOPE_ID}.lock`))).isFile()).toBe(true);
  });

  it("refuses symlink, non-regular, multiply-linked, and non-private existing artifacts", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-artifact-");
    const artifactPath = join(directory, `.rsi-${SCOPE_ID}.lock`);
    const targetPath = join(directory, "target");
    await writeFile(targetPath, "untrusted", { mode: 0o600 });
    await symlink(targetPath, artifactPath);
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "unsafe" });

    await rm(artifactPath);
    await rm(targetPath);
    await writeFile(artifactPath, "untrusted", { mode: 0o644 });
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "unsafe" });

    await rm(artifactPath);
    await writeFile(targetPath, "untrusted", { mode: 0o600 });
    await link(targetPath, artifactPath);
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "unsafe" });

    await rm(artifactPath);
    await chmod(directory, 0o700);
    await mkdir(artifactPath, { mode: 0o700 });
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "unsafe" });
  });

  it("uses one shared scope for distinct canary database paths before storage exists", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-database-path-");
    const dataDirectory = join(directory, "stage1");
    const runtimePath = join(dataDirectory, "rsi-runtime.sqlite");
    lock = await acquireCanaryProfileLockForDatabasePathForTesting(runtimePath);
    expect((await lstat(dataDirectory)).mode & 0o777).toBe(0o700);
    await expect(
      assertCanaryProfileLockForDatabasePath(lock, runtimePath),
    ).resolves.toBeUndefined();
    await expect(
      assertCanaryProfileLockForDatabasePath(lock, join(directory, "other", "runtime.sqlite")),
    ).rejects.toThrow(PROFILE_SERVICE_LOCK_ERROR_MESSAGES.unsafe);
    await expect(
      assertCanaryProfileLockForDatabasePath({ release: async () => undefined }, runtimePath),
    ).rejects.toThrow(PROFILE_SERVICE_LOCK_ERROR_MESSAGES.unsafe);

    await expect(
      acquireCanaryProfileLockForDatabasePathForTesting(
        join(dataDirectory, "rsi-opensea-canary-runtime.sqlite"),
      ),
    ).rejects.toMatchObject({ code: "contended" });
  });

  it("rejects unsafe parent state and a symlinked parent before creating an artifact", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-parent-");
    await chmod(directory, 0o755);
    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory: directory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({
      code: "unsafe",
      message: PROFILE_SERVICE_LOCK_ERROR_MESSAGES.unsafe,
    });

    await chmod(directory, 0o700);
    const aliasPath = `${directory}-alias`;
    await symlink(directory, aliasPath);
    try {
      await expect(
        acquireProfileServiceLockForTesting({ dataDirectory: aliasPath, scopeId: SCOPE_ID }),
      ).rejects.toMatchObject({ code: "unsafe" });
    } finally {
      await rm(aliasPath, { force: true });
    }
  });

  it("rejects a private data directory inside a non-sticky writable container", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-container-");
    const dataDirectory = join(directory, "data");
    await mkdir(dataDirectory, { mode: 0o700 });
    await chmod(directory, 0o777);

    await expect(
      acquireProfileServiceLockForTesting({ dataDirectory, scopeId: SCOPE_ID }),
    ).rejects.toMatchObject({ code: "unsafe" });
  });

  it("refuses to unlink a replacement artifact during release", async () => {
    directory = await privateTemporaryDirectory("rsi-profile-lock-replacement-");
    lock = await acquireProfileServiceLockForTesting({
      dataDirectory: directory,
      scopeId: SCOPE_ID,
    });
    const displacedPath = join(directory, "displaced-owner-lock");
    await rename(lock.artifactPath, displacedPath);
    await writeFile(lock.artifactPath, "replacement", { mode: 0o600 });

    await expect(lock.release()).rejects.toMatchObject({
      code: "ownership",
      message: PROFILE_SERVICE_LOCK_ERROR_MESSAGES.ownership,
    });
    expect(await readFile(lock.artifactPath, "utf8")).toBe("replacement");
    expect(await readFile(displacedPath, "utf8")).toContain(`"scopeId":"${SCOPE_ID}"`);
    lock = undefined;
  });

  it.each([
    { dataDirectory: "relative", scopeId: SCOPE_ID },
    { dataDirectory: "/tmp", scopeId: "../escape" },
    { dataDirectory: "/tmp", scopeId: "UPPER" },
    { dataDirectory: "/tmp", scopeId: "" },
  ])("rejects invalid lock coordinates with one sanitized error", async (options) => {
    await expect(acquireProfileServiceLockForTesting(options)).rejects.toEqual(
      new ProfileServiceLockError("unsafe"),
    );
  });
});
