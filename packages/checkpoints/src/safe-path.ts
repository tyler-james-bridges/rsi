import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync,
  type Stats,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

import { CheckpointConcurrencyError, InvalidCheckpointError } from "./errors.js";

export class JournalFileError extends Error {
  readonly kind: "READ" | "TOO_LARGE" | "UNSAFE";

  constructor(kind: JournalFileError["kind"], message: string) {
    super(message);
    this.name = "JournalFileError";
    this.kind = kind;
  }
}

export const MAX_JOURNAL_BYTES = 64 * 1024 * 1024;

export interface JournalPathGuard {
  readonly parentDevice: number;
  readonly parentInode: number;
  readonly parentOwner: number;
  readonly parentPath: string;
  readonly path: string;
}

/** Resolves and pins the existing parent so later operations cannot be redirected. */
export function createJournalPathGuard(input: string): JournalPathGuard {
  if (typeof input !== "string" || input.trim() === "" || input.includes("\0")) {
    throw new InvalidCheckpointError("journalPath must be a non-empty path without NUL characters");
  }
  const absolute = isAbsolute(input) ? input : resolve(input);
  const name = basename(absolute);
  if (name === "." || name === ".." || name === "") {
    throw new InvalidCheckpointError("journalPath must name a file");
  }
  let realParent: string;
  try {
    realParent = realpathSync.native(dirname(absolute));
  } catch (error) {
    throw new InvalidCheckpointError(
      `journalPath parent must be an existing directory: ${error instanceof Error ? error.message : "invalid path"}`,
    );
  }
  const parentStat = lstatSync(realParent);
  const effectiveUser = process.geteuid?.();
  if (
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    (parentStat.mode & 0o022) !== 0 ||
    (effectiveUser !== undefined && parentStat.uid !== effectiveUser)
  ) {
    throw new InvalidCheckpointError(
      "journalPath parent must be a caller-owned, non-symbolic directory that is not group/world writable",
    );
  }
  const result = join(realParent, name);
  const existing = lstatSync(result, { throwIfNoEntry: false });
  if (existing?.isSymbolicLink()) {
    throw new InvalidCheckpointError("journalPath may not be a symbolic link");
  }
  if (
    existing !== undefined &&
    (!existing.isFile() || existing.nlink !== 1 || (existing.mode & 0o022) !== 0)
  ) {
    throw new InvalidCheckpointError(
      "journalPath must be a singly linked regular file that is not group/world writable",
    );
  }
  return Object.freeze({
    parentDevice: parentStat.dev,
    parentInode: parentStat.ino,
    parentOwner: parentStat.uid,
    parentPath: realParent,
    path: result,
  });
}

export function assertPinnedJournalParent(guard: JournalPathGuard): void {
  const current = lstatSync(guard.parentPath, { throwIfNoEntry: false });
  if (
    current === undefined ||
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    current.dev !== guard.parentDevice ||
    current.ino !== guard.parentInode ||
    current.uid !== guard.parentOwner ||
    (current.mode & 0o022) !== 0
  ) {
    throw new JournalFileError(
      "UNSAFE",
      "Checkpoint journal parent was removed, replaced, or redirected",
    );
  }
}

export function assertJournalSeparateFromStore(guard: JournalPathGuard, storePath: string): void {
  assertPinnedJournalParent(guard);
  if (storePath === ":memory:" || storePath === "") return;
  let normalizedStorePath: string;
  try {
    normalizedStorePath = existsSync(storePath)
      ? realpathSync.native(storePath)
      : join(realpathSync.native(dirname(resolve(storePath))), basename(storePath));
  } catch {
    normalizedStorePath = resolve(storePath);
  }
  if (normalizedStorePath === guard.path) {
    throw new InvalidCheckpointError("Checkpoint journal must be separate from the SQLite store");
  }
  const journalStat = lstatSync(guard.path, { throwIfNoEntry: false });
  assertPinnedJournalParent(guard);
  const storeStat = lstatSync(normalizedStorePath, { throwIfNoEntry: false });
  if (
    journalStat !== undefined &&
    storeStat !== undefined &&
    journalStat.dev === storeStat.dev &&
    journalStat.ino === storeStat.ino
  ) {
    throw new InvalidCheckpointError("Checkpoint journal and SQLite store may not be hard links");
  }
}

export function readJournalFile(guard: JournalPathGuard): {
  readonly bytes: Buffer;
  readonly exists: boolean;
} {
  assertPinnedJournalParent(guard);
  const before = lstatSync(guard.path, { throwIfNoEntry: false });
  assertPinnedJournalParent(guard);
  if (before === undefined) return { bytes: Buffer.alloc(0), exists: false };
  assertSafeJournalStat(before);

  let descriptor: number | undefined;
  try {
    assertPinnedJournalParent(guard);
    descriptor = openSync(guard.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    assertPinnedJournalParent(guard);
    const opened = fstatSync(descriptor);
    assertSafeJournalStat(opened);
    if (before.dev !== opened.dev || before.ino !== opened.ino) {
      throw new JournalFileError("UNSAFE", "Checkpoint journal changed while it was opened");
    }
    if (opened.size > MAX_JOURNAL_BYTES) {
      throw new JournalFileError(
        "TOO_LARGE",
        `Checkpoint journal exceeds ${MAX_JOURNAL_BYTES} bytes`,
      );
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new JournalFileError("READ", "Unexpected end of checkpoint journal");
      offset += count;
    }
    const after = fstatSync(descriptor);
    assertPinnedJournalParent(guard);
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) {
      throw new JournalFileError("UNSAFE", "Checkpoint journal changed while it was read");
    }
    return { bytes, exists: true };
  } catch (error) {
    if (error instanceof JournalFileError) throw error;
    throw new JournalFileError(
      "READ",
      `Unable to read checkpoint journal: ${error instanceof Error ? error.message : "read failed"}`,
    );
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function appendJournalBytes(guard: JournalPathGuard, bytes: Buffer): void {
  assertPinnedJournalParent(guard);
  const existed = existsSync(guard.path);
  assertPinnedJournalParent(guard);
  let descriptor: number | undefined;
  try {
    assertPinnedJournalParent(guard);
    descriptor = openSync(
      guard.path,
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW,
      0o600,
    );
    assertPinnedJournalParent(guard);
    const opened = fstatSync(descriptor);
    assertSafeJournalStat(opened);
    if (opened.size > MAX_JOURNAL_BYTES - bytes.byteLength) {
      throw new JournalFileError(
        "TOO_LARGE",
        `Checkpoint journal append would exceed ${MAX_JOURNAL_BYTES} bytes`,
      );
    }
    let offset = 0;
    while (offset < bytes.length) {
      assertPinnedJournalParent(guard);
      const count = writeSync(descriptor, bytes, offset, bytes.length - offset);
      if (count < 1) throw new JournalFileError("READ", "Unable to append checkpoint bytes");
      offset += count;
    }
    fsyncSync(descriptor);
    assertPinnedJournalParent(guard);
  } catch (error) {
    if (error instanceof JournalFileError) throw error;
    throw new JournalFileError(
      "UNSAFE",
      `Unable to append checkpoint journal: ${error instanceof Error ? error.message : "append failed"}`,
    );
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  if (!existed) fsyncParent(guard);
}

export function withJournalLock<T>(guard: JournalPathGuard, operation: () => T): T {
  const lockPath = `${guard.path}.lock`;
  let descriptor: number | undefined;
  let opened: Stats | undefined;
  try {
    assertPinnedJournalParent(guard);
    descriptor = openSync(
      lockPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    opened = fstatSync(descriptor);
    assertSafeLockStat(opened);
    assertPinnedJournalParent(guard);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (opened !== undefined) {
      try {
        removeOwnedLock(guard, lockPath, opened);
      } catch {
        // Fail closed: never unlink through a parent whose identity is uncertain.
      }
    }
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "ELOOP") throw new CheckpointConcurrencyError();
    throw error;
  }
  try {
    assertPinnedJournalParent(guard);
    writeSync(descriptor, `${String(process.pid)}\n`, undefined, "utf8");
    fsyncSync(descriptor);
    fsyncParent(guard);
    return operation();
  } finally {
    closeSync(descriptor);
    removeOwnedLock(guard, lockPath, opened);
  }
}

function assertSafeJournalStat(stat: Stats): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0) {
    throw new JournalFileError(
      "UNSAFE",
      "Checkpoint journal must be a singly linked regular file that is not group/world writable",
    );
  }
}

function assertSafeLockStat(stat: Stats): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new JournalFileError("UNSAFE", "Checkpoint lock must be a singly linked regular file");
  }
}

function removeOwnedLock(guard: JournalPathGuard, lockPath: string, opened: Stats): void {
  assertPinnedJournalParent(guard);
  const current = lstatSync(lockPath, { throwIfNoEntry: false });
  assertPinnedJournalParent(guard);
  if (current === undefined) return;
  assertSafeLockStat(current);
  if (current.dev !== opened.dev || current.ino !== opened.ino) {
    throw new JournalFileError("UNSAFE", "Checkpoint lock was replaced while held");
  }
  unlinkSync(lockPath);
  fsyncParent(guard);
}

function fsyncParent(guard: JournalPathGuard): void {
  assertPinnedJournalParent(guard);
  const descriptor = openSync(
    guard.parentPath,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const opened = fstatSync(descriptor);
    if (
      !opened.isDirectory() ||
      opened.dev !== guard.parentDevice ||
      opened.ino !== guard.parentInode ||
      opened.uid !== guard.parentOwner ||
      (opened.mode & 0o022) !== 0
    ) {
      throw new JournalFileError("UNSAFE", "Checkpoint journal parent identity changed");
    }
    fsyncSync(descriptor);
    assertPinnedJournalParent(guard);
  } finally {
    closeSync(descriptor);
  }
}
