import { randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { link, lstat, mkdir, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

import {
  EVENT_ARCHIVE_MAGIC,
  MAX_EVENT_ARCHIVE_BYTES,
  type VerifiedEventArchive,
} from "./archive.js";
import { canonicalJson } from "./canonical.js";
import { EventArchiveError, fail } from "./errors.js";
import type { JsonValue } from "./types.js";

const PUBLISH_WAIT_ATTEMPTS = 100;
const PUBLISH_WAIT_MILLISECONDS = 10;
const TEMP_PREFIX = ".rsi-event-archive-partial-";
const activePublications = new Map<string, ActivePublication>();

interface ActivePublication {
  readonly destinationPath: string;
  readonly device: bigint;
  readonly inode: bigint;
  readonly temporaryPath: string;
}

interface ParentGuard {
  readonly device: bigint;
  readonly inode: bigint;
  readonly path: string;
}

export interface PublishHooksForTest {
  readonly afterLink?: () => Promise<void> | void;
  readonly beforeLink?: () => Promise<void> | void;
}

export interface ReadHooksForTest {
  readonly onRecognizedTransientLink?: () => Promise<void> | void;
}

export async function publishArchiveCreateOnly(
  destinationValue: unknown,
  bytes: Buffer,
  hooks: PublishHooksForTest = {},
): Promise<void> {
  const destinationPath = validateAbsolutePath(destinationValue, "Event-archive destination");
  const parent = await guardParent(destinationPath);
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
      fail("DESTINATION_UNSAFE", "Event-archive temporary file is unsafe");
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
      fail("DESTINATION_UNSAFE", "Event-archive temporary file changed during publication");
    }
    await temporary.close();
    temporary = undefined;
    await assertParentUnchanged(parent);
    if (hooks.beforeLink !== undefined) await hooks.beforeLink();
    await assertParentUnchanged(parent);
    const temporaryPathStat = await lstat(temporaryPath, { bigint: true }).catch(() => undefined);
    if (
      temporaryPathStat === undefined ||
      !temporaryPathStat.isFile() ||
      temporaryPathStat.dev !== written.dev ||
      temporaryPathStat.ino !== written.ino ||
      temporaryPathStat.nlink !== 1n ||
      temporaryPathStat.size !== written.size ||
      (Number(temporaryPathStat.mode) & 0o777) !== 0o600
    ) {
      fail("DESTINATION_UNSAFE", "Event-archive temporary path changed before publication");
    }
    const publication: ActivePublication = Object.freeze({
      destinationPath,
      device: written.dev,
      inode: written.ino,
      temporaryPath,
    });
    activePublications.set(destinationPath, publication);
    try {
      try {
        await link(temporaryPath, destinationPath);
      } catch (error) {
        if (isErrno(error, "EEXIST")) {
          fail("DESTINATION_EXISTS", "Event-archive destination already exists");
        }
        throw error;
      }
      linked = true;
      const linkedStat = await lstat(destinationPath, { bigint: true });
      if (
        !linkedStat.isFile() ||
        linkedStat.dev !== written.dev ||
        linkedStat.ino !== written.ino ||
        linkedStat.nlink !== 2n
      ) {
        fail("DESTINATION_UNSAFE", "Event-archive publication link is unsafe");
      }
      if (hooks.afterLink !== undefined) await hooks.afterLink();
      await unlink(temporaryPath);
      temporaryCreated = false;
    } finally {
      activePublications.delete(destinationPath);
    }
    await assertParentUnchanged(parent);
    const finalStat = await lstat(destinationPath, { bigint: true });
    if (
      !finalStat.isFile() ||
      finalStat.dev !== written.dev ||
      finalStat.ino !== written.ino ||
      finalStat.nlink !== 1n ||
      finalStat.size !== BigInt(bytes.length) ||
      (Number(finalStat.mode) & 0o777) !== 0o600
    ) {
      fail("DESTINATION_UNSAFE", "Published event archive is unsafe");
    }
    await syncDirectory(parent.path);
  } catch (error) {
    if (temporary !== undefined) await temporary.close().catch(() => undefined);
    if (temporaryCreated) await unlink(temporaryPath).catch(() => undefined);
    if (error instanceof EventArchiveError) throw error;
    if (isErrno(error, "ELOOP") || isErrno(error, "ENOTDIR")) {
      fail("DESTINATION_UNSAFE", "Event-archive destination filesystem is unsafe");
    }
    if (linked) fail("DESTINATION_UNSAFE", "Event-archive publication did not finish cleanly");
    fail("DESTINATION_UNSAFE", "Event-archive publication failed");
  }
}

export async function readArchiveFile(
  pathValue: unknown,
  hooks: ReadHooksForTest = {},
): Promise<Buffer> {
  const archivePath = validateAbsolutePath(pathValue, "Event archive");
  const parent = await guardParent(archivePath);
  for (let attempt = 0; attempt <= PUBLISH_WAIT_ATTEMPTS; attempt += 1) {
    const pathStat = await lstat(archivePath, { bigint: true }).catch(() => undefined);
    if (pathStat === undefined || !pathStat.isFile()) {
      fail("ARCHIVE_UNSAFE", "Event archive is not a safely readable regular file");
    }
    if (pathStat.nlink === 2n) {
      if (!(await isActivePublicationLink(archivePath, pathStat.dev, pathStat.ino))) {
        fail("ARCHIVE_UNSAFE", "Event archive has a persistent hard link");
      }
      if (attempt === PUBLISH_WAIT_ATTEMPTS) {
        fail("PUBLISH_BUSY", "Event-archive publication did not settle within its bound");
      }
      if (hooks.onRecognizedTransientLink !== undefined) {
        await hooks.onRecognizedTransientLink();
      }
      await boundedDelay(PUBLISH_WAIT_MILLISECONDS);
      continue;
    }
    if (pathStat.nlink !== 1n || (Number(pathStat.mode) & 0o077) !== 0) {
      fail("ARCHIVE_UNSAFE", "Event archive links or permissions are unsafe");
    }
    if (
      pathStat.size <= BigInt(EVENT_ARCHIVE_MAGIC.length + 4) ||
      pathStat.size > BigInt(MAX_EVENT_ARCHIVE_BYTES)
    ) {
      fail("ARCHIVE_UNSAFE", "Event archive size is outside its bound");
    }
    await assertParentUnchanged(parent);
    let file: FileHandle;
    try {
      file = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch {
      fail("ARCHIVE_UNSAFE", "Event archive cannot be safely opened");
    }
    try {
      const before = await file.stat({ bigint: true });
      if (!sameStableFile(pathStat, before) || before.nlink !== 1n) {
        fail("ARCHIVE_CHANGED", "Event archive changed before reading");
      }
      const bytes = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < bytes.length) {
        const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
        if (bytesRead === 0) fail("ARCHIVE_CHANGED", "Event archive was truncated while reading");
        offset += bytesRead;
      }
      const after = await file.stat({ bigint: true });
      const pathAfter = await lstat(archivePath, { bigint: true }).catch(() => undefined);
      if (
        pathAfter === undefined ||
        !sameStableFile(before, after) ||
        !sameStableFile(after, pathAfter) ||
        after.nlink !== 1n ||
        pathAfter.nlink !== 1n
      ) {
        fail("ARCHIVE_CHANGED", "Event archive changed while reading");
      }
      await assertParentUnchanged(parent);
      return bytes;
    } finally {
      await file.close().catch(() => undefined);
    }
  }
  fail("PUBLISH_BUSY", "Event-archive publication did not settle within its bound");
}

export async function restoreVerifiedArchive(
  destinationValue: unknown,
  verified: VerifiedEventArchive,
): Promise<void> {
  const destinationPath = validateAbsolutePath(
    destinationValue,
    "Event-archive restore destination",
  );
  const parent = await guardParent(destinationPath);
  await assertMissing(destinationPath);
  await assertParentUnchanged(parent);
  try {
    await mkdir(destinationPath, { mode: 0o700, recursive: false });
  } catch (error) {
    if (isErrno(error, "EEXIST")) fail("DESTINATION_EXISTS", "Restore destination already exists");
    fail("DESTINATION_UNSAFE", "Restore destination cannot be created safely");
  }
  const destinationStat = await lstat(destinationPath, { bigint: true });
  if (
    !destinationStat.isDirectory() ||
    destinationStat.nlink < 1n ||
    (Number(destinationStat.mode) & 0o777) !== 0o700
  ) {
    fail("DESTINATION_UNSAFE", "Restore destination is unsafe");
  }
  const envelopeBytes = Buffer.from(
    canonicalJson(verified.envelope as unknown as JsonValue),
    "utf8",
  );
  const files: readonly (readonly [string, Buffer])[] = [
    ["event-archive-manifest.v1.json", envelopeBytes],
    ["sanitized-events.v1.jsonl", Buffer.from(verified.eventBytes)],
  ];
  for (const [name, bytes] of files) {
    await assertRestoreDirectoryIdentity(destinationPath, destinationStat.dev, destinationStat.ino);
    const filePath = join(destinationPath, name);
    let file: FileHandle;
    try {
      file = await open(
        filePath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch {
      fail("DESTINATION_UNSAFE", "Restore output cannot be created safely");
    }
    try {
      await file.chmod(0o600);
      await writeAll(file, bytes);
      await file.sync();
      const stat = await file.stat({ bigint: true });
      if (
        !stat.isFile() ||
        stat.nlink !== 1n ||
        stat.size !== BigInt(bytes.length) ||
        (Number(stat.mode) & 0o777) !== 0o600
      ) {
        fail("DESTINATION_UNSAFE", "Restored event-archive output is unsafe");
      }
    } finally {
      await file.close().catch(() => undefined);
    }
  }
  await syncDirectory(destinationPath);
  await assertRestoreDirectoryIdentity(destinationPath, destinationStat.dev, destinationStat.ino);
  await assertParentUnchanged(parent);
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

async function guardParent(targetPath: string): Promise<ParentGuard> {
  const parentPath = dirname(targetPath);
  const parentStat = await lstat(parentPath, { bigint: true }).catch(() => undefined);
  if (
    parentStat === undefined ||
    !isSafeOwnedDirectory(parentStat) ||
    (await realpath(parentPath).catch(() => "")) !== parentPath
  ) {
    fail("DESTINATION_UNSAFE", "Destination parent is unsafe");
  }
  return Object.freeze({ device: parentStat.dev, inode: parentStat.ino, path: parentPath });
}

async function assertParentUnchanged(parent: ParentGuard): Promise<void> {
  const current = await lstat(parent.path, { bigint: true }).catch(() => undefined);
  if (
    current === undefined ||
    !isSafeOwnedDirectory(current) ||
    current.dev !== parent.device ||
    current.ino !== parent.inode ||
    (await realpath(parent.path).catch(() => "")) !== parent.path
  ) {
    fail("DESTINATION_UNSAFE", "Destination parent changed during operation");
  }
}

function isSafeOwnedDirectory(stat: BigIntStats): boolean {
  const currentUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : stat.uid;
  return (
    stat.isDirectory() &&
    stat.nlink >= 1n &&
    stat.uid === currentUid &&
    (Number(stat.mode) & 0o022) === 0
  );
}

async function assertMissing(targetPath: string): Promise<void> {
  const stat = await lstat(targetPath, { bigint: true }).catch((error: unknown) => {
    if (isErrno(error, "ENOENT")) return undefined;
    fail("DESTINATION_UNSAFE", "Destination cannot be inspected safely");
  });
  if (stat !== undefined) fail("DESTINATION_EXISTS", "Destination already exists");
}

async function isActivePublicationLink(
  destinationPath: string,
  device: bigint,
  inode: bigint,
): Promise<boolean> {
  const active = activePublications.get(destinationPath);
  if (
    active === undefined ||
    active.destinationPath !== destinationPath ||
    active.device !== device ||
    active.inode !== inode
  ) {
    return false;
  }
  const temporary = await lstat(active.temporaryPath, { bigint: true }).catch(() => undefined);
  return (
    temporary !== undefined &&
    temporary.isFile() &&
    temporary.dev === device &&
    temporary.ino === inode &&
    temporary.nlink === 2n
  );
}

function sameStableFile(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.isFile() &&
    right.isFile() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function assertRestoreDirectoryIdentity(
  path: string,
  device: bigint,
  inode: bigint,
): Promise<void> {
  const stat = await lstat(path, { bigint: true }).catch(() => undefined);
  if (
    stat === undefined ||
    !stat.isDirectory() ||
    stat.dev !== device ||
    stat.ino !== inode ||
    (Number(stat.mode) & 0o777) !== 0o700 ||
    (await realpath(path).catch(() => "")) !== path
  ) {
    fail("DESTINATION_UNSAFE", "Restore destination changed during operation");
  }
}

async function writeAll(file: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await file.write(bytes, offset, bytes.length - offset, offset);
    if (bytesWritten === 0) fail("DESTINATION_UNSAFE", "Filesystem write made no progress");
    offset += bytesWritten;
  }
}

async function syncDirectory(path: string): Promise<void> {
  const directory = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

function isErrno(error: unknown, code: string): error is NodeJS.ErrnoException {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code
  );
}

function boundedDelay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
