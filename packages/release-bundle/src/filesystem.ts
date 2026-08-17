import { constants, type BigIntStats } from "node:fs";
import { link, lstat, mkdir, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";

import { MAX_ARCHIVE_BYTES, type VerifiedReleaseArchive } from "./archive.js";
import { canonicalJson } from "./canonical.js";
import { ReleaseBundleError, fail } from "./errors.js";

const TEMP_PREFIX = ".rsi-release-partial-";

interface PathGuard {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: number;
  readonly path: string;
  readonly uid: bigint;
}

interface FileGuard {
  readonly ctimeNanoseconds: bigint;
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: number;
  readonly modifiedNanoseconds: bigint;
  readonly path: string;
  readonly size: bigint;
  readonly uid: bigint;
}

export interface PublishHooksForTest {
  readonly afterLink?: () => Promise<void> | void;
  readonly beforeLink?: () => Promise<void> | void;
}

export async function publishBundleCreateOnly(
  destinationValue: unknown,
  bytes: Buffer,
  hooks: PublishHooksForTest = {},
): Promise<void> {
  const destinationPath = validateAbsolutePath(destinationValue, "Release destination");
  const parent = await guardExistingDirectory(dirname(destinationPath), "DESTINATION_UNSAFE");
  await assertMissing(destinationPath);
  const temporaryPath = join(parent.path, `${TEMP_PREFIX}${randomUUID()}`);
  let temporary: FileHandle | undefined;
  let temporaryCreated = false;
  let linked = false;
  try {
    temporary = await open(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    temporaryCreated = true;
    await temporary.chmod(0o600);
    const initial = await temporary.stat({ bigint: true });
    if (!initial.isFile() || initial.nlink !== 1n) {
      fail("DESTINATION_UNSAFE", "Release temporary file is unsafe");
    }
    await writeAll(temporary, bytes);
    await temporary.sync();
    const written = await temporary.stat({ bigint: true });
    if (
      !written.isFile() ||
      written.nlink !== 1n ||
      written.size !== BigInt(bytes.length) ||
      written.dev !== initial.dev ||
      written.ino !== initial.ino
    ) {
      fail("DESTINATION_UNSAFE", "Release temporary file changed during publication");
    }
    await temporary.close();
    temporary = undefined;
    await assertGuardUnchanged(parent);
    if (hooks.beforeLink !== undefined) await hooks.beforeLink();
    await assertGuardUnchanged(parent);
    const temporaryStat = await lstat(temporaryPath, { bigint: true }).catch(() => undefined);
    if (
      temporaryStat === undefined ||
      !sameIdentity(temporaryStat, written) ||
      temporaryStat.nlink !== 1n ||
      temporaryStat.size !== written.size ||
      (Number(temporaryStat.mode) & 0o777) !== 0o600
    ) {
      fail("DESTINATION_UNSAFE", "Release temporary path changed before publication");
    }
    try {
      await link(temporaryPath, destinationPath);
    } catch (error) {
      if (isErrno(error, "EEXIST"))
        fail("DESTINATION_EXISTS", "Release destination already exists");
      throw error;
    }
    linked = true;
    const linkedStat = await lstat(destinationPath, { bigint: true });
    if (!sameIdentity(linkedStat, written) || linkedStat.nlink !== 2n) {
      fail("DESTINATION_UNSAFE", "Release publication link is unsafe");
    }
    if (hooks.afterLink !== undefined) await hooks.afterLink();
    await unlink(temporaryPath);
    temporaryCreated = false;
    await assertGuardUnchanged(parent);
    const finalStat = await lstat(destinationPath, { bigint: true });
    if (
      !sameIdentity(finalStat, written) ||
      finalStat.nlink !== 1n ||
      finalStat.size !== BigInt(bytes.length) ||
      (Number(finalStat.mode) & 0o777) !== 0o600
    ) {
      fail("DESTINATION_UNSAFE", "Published release archive is unsafe");
    }
    await syncDirectory(parent.path);
  } catch (error) {
    await temporary?.close().catch(() => undefined);
    if (temporaryCreated) await unlink(temporaryPath).catch(() => undefined);
    if (error instanceof ReleaseBundleError) throw error;
    if (linked) fail("DESTINATION_UNSAFE", "Release publication did not finish cleanly");
    fail("DESTINATION_UNSAFE", "Release publication failed");
  }
}

export async function readBundleFile(pathValue: unknown): Promise<Buffer> {
  const archivePath = validateAbsolutePath(pathValue, "Release archive");
  const parent = await guardExistingDirectory(dirname(archivePath), "ARCHIVE_UNSAFE");
  let pathStat: BigIntStats;
  try {
    pathStat = await lstat(archivePath, { bigint: true });
  } catch {
    fail("ARCHIVE_UNSAFE", "Release archive cannot be safely inspected");
  }
  if (
    !pathStat.isFile() ||
    pathStat.nlink !== 1n ||
    pathStat.uid !== currentUserId(pathStat.uid) ||
    (Number(pathStat.mode) & 0o077) !== 0 ||
    pathStat.size <= 0n ||
    pathStat.size > BigInt(MAX_ARCHIVE_BYTES)
  ) {
    fail("ARCHIVE_UNSAFE", "Release archive type, links, permissions, or size are unsafe");
  }
  await assertGuardUnchanged(parent);
  let file: FileHandle;
  try {
    file = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    fail("ARCHIVE_UNSAFE", "Release archive cannot be safely opened");
  }
  try {
    const before = await file.stat({ bigint: true });
    if (!sameStableFile(pathStat, before) || before.nlink !== 1n) {
      fail("ARCHIVE_CHANGED", "Release archive changed before reading");
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) fail("ARCHIVE_CHANGED", "Release archive was truncated while reading");
      offset += bytesRead;
    }
    const after = await file.stat({ bigint: true });
    const pathAfter = await lstat(archivePath, { bigint: true });
    if (
      !sameStableFile(before, after) ||
      !sameStableFile(after, pathAfter) ||
      after.nlink !== 1n ||
      pathAfter.nlink !== 1n
    ) {
      fail("ARCHIVE_CHANGED", "Release archive changed while reading");
    }
    await assertGuardUnchanged(parent);
    return bytes;
  } finally {
    await file.close().catch(() => undefined);
  }
}

export async function restoreVerifiedReleaseArchive(
  destinationValue: unknown,
  verified: VerifiedReleaseArchive,
): Promise<number> {
  const destinationPath = validateAbsolutePath(destinationValue, "Release restore destination");
  const outerParent = await guardExistingDirectory(dirname(destinationPath), "DESTINATION_UNSAFE");
  await assertMissing(destinationPath);
  await assertGuardUnchanged(outerParent);
  try {
    await mkdir(destinationPath, { mode: 0o700, recursive: false });
  } catch (error) {
    if (isErrno(error, "EEXIST")) fail("DESTINATION_EXISTS", "Restore destination already exists");
    fail("DESTINATION_UNSAFE", "Restore destination cannot be safely created");
  }
  const root = await guardExistingDirectory(destinationPath, "DESTINATION_UNSAFE", 0o700);
  const files = new Map<string, Buffer>(verified.artifactBytes);
  const manifestPath = "release/signed-release-manifest.v1.json";
  const manifestBytes = Buffer.from(canonicalJson(verified.envelope), "utf8");
  files.set(manifestPath, manifestBytes);
  const directories = collectDirectories([...files.keys()]);
  const guards = new Map<string, PathGuard>([["", root]]);
  const restoredFiles: FileGuard[] = [];
  for (const relative of directories) {
    const parentRelative = dirname(relative) === "." ? "" : dirname(relative);
    const parent = guards.get(parentRelative);
    if (parent === undefined) fail("DESTINATION_UNSAFE", "Restore directory order is invalid");
    await assertGuardUnchanged(parent);
    const path = join(destinationPath, relative);
    try {
      await mkdir(path, { mode: 0o700, recursive: false });
    } catch {
      fail("DESTINATION_UNSAFE", "Restore directory cannot be safely created");
    }
    guards.set(relative, await guardExistingDirectory(path, "DESTINATION_UNSAFE", 0o700));
  }
  const artifactEntries = [...verified.artifactBytes].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  // The signed manifest is written last so its presence is never mistaken for
  // evidence that an interrupted restore completed.
  for (const [relative, bytes] of [...artifactEntries, [manifestPath, manifestBytes] as const]) {
    const parentRelative = dirname(relative) === "." ? "" : dirname(relative);
    const parent = guards.get(parentRelative);
    if (parent === undefined) fail("DESTINATION_UNSAFE", "Restore file parent is invalid");
    await assertGuardUnchanged(root);
    await assertGuardUnchanged(parent);
    const path = join(destinationPath, relative);
    if (!path.startsWith(`${destinationPath}${sep}`)) {
      fail("DESTINATION_UNSAFE", "Restore output escaped its destination");
    }
    let file: FileHandle;
    try {
      file = await open(
        path,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch {
      fail("DESTINATION_UNSAFE", "Restore output cannot be safely created");
    }
    try {
      await file.chmod(0o600);
      await writeAll(file, bytes);
      await file.sync();
      const stat = await file.stat({ bigint: true });
      const pathStat = await lstat(path, { bigint: true }).catch(() => undefined);
      if (
        !stat.isFile() ||
        stat.nlink !== 1n ||
        stat.uid !== currentUserId(stat.uid) ||
        stat.size !== BigInt(bytes.length) ||
        (Number(stat.mode) & 0o777) !== 0o600 ||
        pathStat === undefined ||
        !sameStableFile(stat, pathStat) ||
        pathStat.nlink !== 1n
      ) {
        fail("DESTINATION_UNSAFE", "Restored release output is unsafe");
      }
      restoredFiles.push(
        Object.freeze({
          ctimeNanoseconds: stat.ctimeNs,
          device: stat.dev,
          inode: stat.ino,
          mode: Number(stat.mode) & 0o777,
          modifiedNanoseconds: stat.mtimeNs,
          path,
          size: stat.size,
          uid: stat.uid,
        }),
      );
    } finally {
      await file.close().catch(() => undefined);
    }
  }
  for (const guard of [...guards.values()].reverse()) {
    await syncDirectory(guard.path);
    await assertGuardUnchanged(guard);
  }
  for (const guard of restoredFiles) await assertFileGuardUnchanged(guard);
  await assertGuardUnchanged(outerParent);
  return files.size;
}

function collectDirectories(paths: readonly string[]): readonly string[] {
  const directories = new Set<string>();
  for (const path of paths) {
    let current = dirname(path);
    while (current !== "." && current !== "") {
      directories.add(current);
      current = dirname(current);
    }
  }
  return [...directories].sort((left, right) => {
    const depth = left.split("/").length - right.split("/").length;
    return depth !== 0 ? depth : left < right ? -1 : left > right ? 1 : 0;
  });
}

async function writeAll(file: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await file.write(bytes, offset, bytes.length - offset, offset);
    if (bytesWritten === 0) fail("DESTINATION_UNSAFE", "Filesystem write made no progress");
    offset += bytesWritten;
  }
}

function validateAbsolutePath(value: unknown, safeName: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    value.normalize("NFC") !== value ||
    /[\u0000-\u001f\u007f]/.test(value) ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    basename(value) === "" ||
    value === "/"
  ) {
    fail("DESTINATION_UNSAFE", `${safeName} path is unsafe`);
  }
  return value;
}

async function guardExistingDirectory(
  path: string,
  errorCode: "ARCHIVE_UNSAFE" | "DESTINATION_UNSAFE",
  exactMode?: number,
): Promise<PathGuard> {
  try {
    const stat = await lstat(path, { bigint: true });
    const currentUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : stat.uid;
    if (
      !stat.isDirectory() ||
      stat.nlink < 1n ||
      stat.uid !== currentUid ||
      (Number(stat.mode) & 0o022) !== 0 ||
      (exactMode !== undefined && (Number(stat.mode) & 0o777) !== exactMode) ||
      (await realpath(path)) !== path
    ) {
      fail(errorCode, "Filesystem directory is unsafe");
    }
    return Object.freeze({
      device: stat.dev,
      inode: stat.ino,
      mode: Number(stat.mode) & 0o777,
      path,
      uid: stat.uid,
    });
  } catch (error) {
    if (error instanceof ReleaseBundleError) throw error;
    fail(errorCode, "Filesystem directory is unsafe");
  }
}

async function assertGuardUnchanged(guard: PathGuard): Promise<void> {
  const stat = await lstat(guard.path, { bigint: true }).catch(() => undefined);
  if (
    stat === undefined ||
    !stat.isDirectory() ||
    stat.dev !== guard.device ||
    stat.ino !== guard.inode ||
    stat.uid !== guard.uid ||
    (Number(stat.mode) & 0o777) !== guard.mode ||
    (await realpath(guard.path).catch(() => "")) !== guard.path
  ) {
    fail("DESTINATION_UNSAFE", "Filesystem directory changed during operation");
  }
}

async function assertFileGuardUnchanged(guard: FileGuard): Promise<void> {
  const stat = await lstat(guard.path, { bigint: true }).catch(() => undefined);
  if (
    stat === undefined ||
    !stat.isFile() ||
    stat.nlink !== 1n ||
    stat.dev !== guard.device ||
    stat.ino !== guard.inode ||
    stat.uid !== guard.uid ||
    stat.size !== guard.size ||
    stat.mtimeNs !== guard.modifiedNanoseconds ||
    stat.ctimeNs !== guard.ctimeNanoseconds ||
    (Number(stat.mode) & 0o777) !== guard.mode
  ) {
    fail("DESTINATION_UNSAFE", "Restored release output changed during operation");
  }
}

async function assertMissing(path: string): Promise<void> {
  try {
    await lstat(path, { bigint: true });
  } catch (error) {
    if (isErrno(error, "ENOENT")) return;
    fail("DESTINATION_UNSAFE", "Destination cannot be safely inspected");
  }
  fail("DESTINATION_EXISTS", "Destination already exists");
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.isFile() && right.isFile() && left.dev === right.dev && left.ino === right.ino;
}

function sameStableFile(left: BigIntStats, right: BigIntStats): boolean {
  return (
    sameIdentity(left, right) &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function syncDirectory(path: string): Promise<void> {
  let directory: FileHandle | undefined;
  try {
    directory = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    await directory.sync();
  } catch (error) {
    if (!isErrno(error, "EINVAL") && !isErrno(error, "ENOTSUP") && !isErrno(error, "EBADF")) {
      fail("DESTINATION_UNSAFE", "Directory durability sync failed");
    }
  } finally {
    await directory?.close().catch(() => undefined);
  }
}

function isErrno(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}

function currentUserId(fallback: bigint): bigint {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : fallback;
}
