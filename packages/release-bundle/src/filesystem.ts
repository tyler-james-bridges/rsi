import { constants, type BigIntStats } from "node:fs";
import { link, lstat, mkdir, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";

import { MAX_ARCHIVE_BYTES, type VerifiedReleaseArchive } from "./archive.js";
import { canonicalJson, sha256 } from "./canonical.js";
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
  readonly beforeFinalCleanupSync?: () => Promise<void> | void;
}

export interface RestoreHooksForTest {
  readonly afterManifestLink?: () => Promise<void> | void;
  readonly beforeManifestLink?: () => Promise<void> | void;
  readonly beforeOuterParentSync?: () => Promise<void> | void;
}

export interface PreparedBundlePublication {
  preserve(): Promise<void>;
  publish(bytes: Buffer, hooks?: PublishHooksForTest): Promise<void>;
}

type PublicationState = "prepared" | "preserved" | "published" | "publishing";

export async function prepareBundleCreateOnly(
  destinationValue: unknown,
): Promise<PreparedBundlePublication> {
  const destinationPath = validateAbsolutePath(destinationValue, "Release destination");
  const parent = await guardExistingDirectory(dirname(destinationPath), "DESTINATION_UNSAFE");
  await assertMissing(destinationPath);
  const temporaryPath = publicationTemporaryPath(destinationPath);
  let temporary: FileHandle | undefined;
  let temporaryCreated = false;
  try {
    temporary = await open(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    temporaryCreated = true;
    await temporary.chmod(0o600);
    const initial = await temporary.stat({ bigint: true });
    if (
      !initial.isFile() ||
      initial.nlink !== 1n ||
      initial.uid !== currentUserId(initial.uid) ||
      initial.size !== 0n ||
      (Number(initial.mode) & 0o777) !== 0o600
    ) {
      fail("DESTINATION_UNSAFE", "Release reservation file is unsafe");
    }

    // The empty reservation and its directory entry must be durable before the
    // one-shot signer is ever called. It becomes the retained attempt marker if
    // signing or any later publication phase fails.
    await temporary.sync();
    await assertGuardUnchanged(parent);
    await syncGuardedDirectory(parent);
    await assertGuardUnchanged(parent);
    const reservedHandle = await temporary.stat({ bigint: true });
    const reservedPath = await lstat(temporaryPath, { bigint: true }).catch(() => undefined);
    if (
      reservedPath === undefined ||
      !sameIdentity(initial, reservedHandle) ||
      !sameIdentity(reservedHandle, reservedPath) ||
      reservedHandle.nlink !== 1n ||
      reservedPath.nlink !== 1n ||
      reservedHandle.size !== 0n ||
      reservedPath.size !== 0n ||
      reservedPath.uid !== initial.uid ||
      (Number(reservedHandle.mode) & 0o777) !== 0o600 ||
      (Number(reservedPath.mode) & 0o777) !== 0o600
    ) {
      fail("DESTINATION_UNSAFE", "Release reservation changed during preflight");
    }
    return new PreparedBundlePublicationImpl(
      parent,
      destinationPath,
      temporaryPath,
      temporary,
      initial,
    );
  } catch (error) {
    await temporary?.close().catch(() => undefined);
    if (temporaryCreated) await syncGuardedDirectoryBestEffort(parent);
    if (error instanceof ReleaseBundleError) throw error;
    if (isErrno(error, "EEXIST")) {
      fail("DESTINATION_EXISTS", "Release destination has a retained publication attempt");
    }
    fail("DESTINATION_UNSAFE", "Release destination reservation failed");
  }
}

export async function publishBundleCreateOnly(
  destinationValue: unknown,
  bytes: Buffer,
  hooks: PublishHooksForTest = {},
): Promise<void> {
  const prepared = await prepareBundleCreateOnly(destinationValue);
  await prepared.publish(bytes, hooks);
}

class PreparedBundlePublicationImpl implements PreparedBundlePublication {
  private handle: FileHandle | undefined;
  private state: PublicationState = "prepared";

  constructor(
    private readonly parent: PathGuard,
    private readonly destinationPath: string,
    private readonly temporaryPath: string,
    handle: FileHandle,
    private readonly initial: BigIntStats,
  ) {
    this.handle = handle;
  }

  async preserve(): Promise<void> {
    if (this.state === "published" || this.state === "preserved") return;
    if (this.state === "publishing") {
      fail("DESTINATION_UNSAFE", "Release publication reservation is busy");
    }
    this.state = "preserved";
    await this.handle?.close().catch(() => undefined);
    this.handle = undefined;
    await syncGuardedDirectoryBestEffort(this.parent);
  }

  async publish(bytes: Buffer, hooks: PublishHooksForTest = {}): Promise<void> {
    if (this.state !== "prepared" || this.handle === undefined) {
      fail("DESTINATION_UNSAFE", "Release publication reservation is unavailable");
    }
    this.state = "publishing";
    let linked = false;
    let written: BigIntStats | undefined;
    try {
      await assertGuardUnchanged(this.parent);
      const reservedHandle = await this.handle.stat({ bigint: true });
      const reservedPath = await lstat(this.temporaryPath, { bigint: true }).catch(() => undefined);
      if (
        reservedPath === undefined ||
        !sameIdentity(this.initial, reservedHandle) ||
        !sameIdentity(reservedHandle, reservedPath) ||
        reservedHandle.nlink !== 1n ||
        reservedPath.nlink !== 1n ||
        reservedHandle.size !== 0n ||
        reservedPath.size !== 0n ||
        reservedPath.uid !== this.initial.uid ||
        (Number(reservedHandle.mode) & 0o777) !== 0o600 ||
        (Number(reservedPath.mode) & 0o777) !== 0o600
      ) {
        fail("DESTINATION_UNSAFE", "Release reservation changed before publication");
      }
      await writeAll(this.handle, bytes);
      await this.handle.sync();
      written = await this.handle.stat({ bigint: true });
      if (
        !written.isFile() ||
        written.nlink !== 1n ||
        written.size !== BigInt(bytes.length) ||
        written.dev !== this.initial.dev ||
        written.ino !== this.initial.ino ||
        written.uid !== this.initial.uid ||
        (Number(written.mode) & 0o777) !== 0o600
      ) {
        fail("DESTINATION_UNSAFE", "Release temporary file changed during publication");
      }
      await this.handle.close();
      this.handle = undefined;
      await assertGuardUnchanged(this.parent);
      if (hooks.beforeLink !== undefined) await hooks.beforeLink();
      await assertGuardUnchanged(this.parent);
      const temporaryStat = await lstat(this.temporaryPath, { bigint: true }).catch(
        () => undefined,
      );
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
        await link(this.temporaryPath, this.destinationPath);
      } catch (error) {
        if (isErrno(error, "EEXIST")) {
          fail("DESTINATION_EXISTS", "Release destination already exists");
        }
        throw error;
      }
      linked = true;
      const linkedStat = await lstat(this.destinationPath, { bigint: true });
      if (!sameIdentity(linkedStat, written) || linkedStat.nlink !== 2n) {
        fail("DESTINATION_UNSAFE", "Release publication link is unsafe");
      }
      if (hooks.afterLink !== undefined) await hooks.afterLink();
      // Make the destination link durable while the already-synced temporary link
      // still exists. A crash before temporary cleanup therefore cannot erase the
      // only name for a completed signed archive.
      await syncGuardedDirectory(this.parent);
      await unlink(this.temporaryPath);
      await assertGuardUnchanged(this.parent);
      const finalStat = await lstat(this.destinationPath, { bigint: true });
      if (
        !sameIdentity(finalStat, written) ||
        finalStat.nlink !== 1n ||
        finalStat.size !== BigInt(bytes.length) ||
        (Number(finalStat.mode) & 0o777) !== 0o600
      ) {
        fail("DESTINATION_UNSAFE", "Published release archive is unsafe");
      }
      if (hooks.beforeFinalCleanupSync !== undefined) await hooks.beforeFinalCleanupSync();
      await syncGuardedDirectory(this.parent);
      await assertGuardUnchanged(this.parent);
      const durableFinalStat = await lstat(this.destinationPath, { bigint: true }).catch(
        () => undefined,
      );
      if (
        durableFinalStat === undefined ||
        !sameStableFile(finalStat, durableFinalStat) ||
        durableFinalStat.nlink !== 1n ||
        durableFinalStat.size !== BigInt(bytes.length) ||
        (Number(durableFinalStat.mode) & 0o777) !== 0o600
      ) {
        fail("DESTINATION_UNSAFE", "Published release archive changed during cleanup sync");
      }
      this.state = "published";
    } catch (error) {
      await this.handle?.close().catch(() => undefined);
      this.handle = undefined;
      if (linked && written !== undefined) {
        await preserveUsableLinkedDestination(
          this.parent,
          this.temporaryPath,
          this.destinationPath,
          written,
        ).catch(() => undefined);
      }
      await syncGuardedDirectoryBestEffort(this.parent);
      this.state = "preserved";
      if (error instanceof ReleaseBundleError) throw error;
      if (linked) fail("DESTINATION_UNSAFE", "Release publication did not finish cleanly");
      fail("DESTINATION_UNSAFE", "Release publication failed");
    }
  }
}

async function preserveUsableLinkedDestination(
  parent: PathGuard,
  temporaryPath: string,
  destinationPath: string,
  written: BigIntStats,
): Promise<void> {
  await assertGuardUnchanged(parent);
  const destination = await lstat(destinationPath, { bigint: true }).catch(() => undefined);
  if (
    destination === undefined ||
    !sameIdentity(destination, written) ||
    destination.size !== written.size ||
    (Number(destination.mode) & 0o777) !== 0o600
  ) {
    // The destination cannot be trusted, so retain our known temporary link.
    await syncGuardedDirectoryBestEffort(parent);
    return;
  }

  // A failed publication has not proven the destination directory entry
  // durable. Keep the already-synced temporary name even when the destination
  // link looks usable. Removing it here would create a crash window in which
  // neither name is guaranteed to survive.
  const partial = await lstat(temporaryPath, { bigint: true }).catch(() => undefined);
  if (
    partial === undefined ||
    !sameIdentity(partial, written) ||
    partial.nlink !== 2n ||
    destination.nlink !== 2n
  ) {
    return;
  }
  await syncGuardedDirectoryBestEffort(parent);
}

async function syncGuardedDirectoryBestEffort(parent: PathGuard): Promise<void> {
  try {
    await syncGuardedDirectory(parent);
  } catch {
    // Preserve the artifact and the original publication error. A sync failure
    // must never trigger cleanup of signed evidence.
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
  hooks: RestoreHooksForTest = {},
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
  try {
    await assertGuardUnchanged(outerParent);
    if (hooks.beforeOuterParentSync !== undefined) await hooks.beforeOuterParentSync();
    await syncGuardedDirectory(outerParent);
    await assertGuardUnchanged(outerParent);
    await assertGuardUnchanged(root);
  } catch (error) {
    if (error instanceof ReleaseBundleError) throw error;
    fail("DESTINATION_UNSAFE", "Restore root durability could not be proven");
  }
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
  for (const [relative, bytes] of artifactEntries) {
    restoredFiles.push(await writeRestoredFile(destinationPath, relative, bytes, root, guards));
  }

  // Every artifact file and containing directory becomes durable before the
  // signed manifest's final name can exist. The manifest then uses the same
  // synced create-only hard-link publication protocol as a release bundle.
  for (const guard of [...guards.values()].reverse()) {
    await syncGuardedDirectory(guard);
    await assertGuardUnchanged(guard);
  }
  for (const guard of restoredFiles) await assertFileGuardUnchanged(guard);

  const manifestAbsolutePath = join(destinationPath, manifestPath);
  const manifestParent = guards.get(dirname(manifestPath));
  if (manifestParent === undefined) {
    fail("DESTINATION_UNSAFE", "Restore manifest parent is invalid");
  }
  await assertGuardUnchanged(root);
  await assertGuardUnchanged(manifestParent);
  await publishBundleCreateOnly(manifestAbsolutePath, manifestBytes, {
    ...(hooks.afterManifestLink === undefined ? {} : { afterLink: hooks.afterManifestLink }),
    ...(hooks.beforeManifestLink === undefined ? {} : { beforeLink: hooks.beforeManifestLink }),
  });
  const manifestGuard = await guardRestoredFile(manifestAbsolutePath, manifestBytes.length);
  restoredFiles.push(manifestGuard);
  await assertFileGuardUnchanged(manifestGuard);
  await assertGuardUnchanged(manifestParent);
  await assertGuardUnchanged(root);
  await syncGuardedDirectory(outerParent);
  await assertGuardUnchanged(outerParent);
  for (const guard of guards.values()) await assertGuardUnchanged(guard);
  for (const guard of restoredFiles) await assertFileGuardUnchanged(guard);
  return files.size;
}

async function writeRestoredFile(
  destinationPath: string,
  relative: string,
  bytes: Buffer,
  root: PathGuard,
  guards: ReadonlyMap<string, PathGuard>,
): Promise<FileGuard> {
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
      !safeRestoredFile(stat, BigInt(bytes.length)) ||
      pathStat === undefined ||
      !sameStableFile(stat, pathStat) ||
      pathStat.nlink !== 1n
    ) {
      fail("DESTINATION_UNSAFE", "Restored release output is unsafe");
    }
    return fileGuard(path, stat);
  } finally {
    await file.close().catch(() => undefined);
  }
}

async function guardRestoredFile(path: string, expectedSize: number): Promise<FileGuard> {
  const stat = await lstat(path, { bigint: true }).catch(() => undefined);
  if (stat === undefined || !safeRestoredFile(stat, BigInt(expectedSize))) {
    fail("DESTINATION_UNSAFE", "Restored release output is unsafe");
  }
  return fileGuard(path, stat);
}

function safeRestoredFile(stat: BigIntStats, expectedSize: bigint): boolean {
  return (
    stat.isFile() &&
    stat.nlink === 1n &&
    stat.uid === currentUserId(stat.uid) &&
    stat.size === expectedSize &&
    (Number(stat.mode) & 0o777) === 0o600
  );
}

function fileGuard(path: string, stat: BigIntStats): FileGuard {
  return Object.freeze({
    ctimeNanoseconds: stat.ctimeNs,
    device: stat.dev,
    inode: stat.ino,
    mode: Number(stat.mode) & 0o777,
    modifiedNanoseconds: stat.mtimeNs,
    path,
    size: stat.size,
    uid: stat.uid,
  });
}

function publicationTemporaryPath(destinationPath: string): string {
  return join(
    dirname(destinationPath),
    `${TEMP_PREFIX}${sha256(`rsi-release-publication-v1\0${destinationPath}`).slice(0, 32)}`,
  );
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

async function syncGuardedDirectory(guard: PathGuard): Promise<void> {
  let directory: FileHandle | undefined;
  try {
    const before = await lstat(guard.path, { bigint: true });
    if (!directoryMatchesGuard(before, guard)) {
      fail("DESTINATION_UNSAFE", "Directory durability target changed before sync");
    }
    directory = await open(
      guard.path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const opened = await directory.stat({ bigint: true });
    if (!directoryMatchesGuard(opened, guard) || !sameDirectorySnapshot(before, opened)) {
      fail("DESTINATION_UNSAFE", "Directory durability target changed before sync");
    }
    await directory.sync();
    const [after, pathAfter] = await Promise.all([
      directory.stat({ bigint: true }),
      lstat(guard.path, { bigint: true }),
    ]);
    if (
      !directoryMatchesGuard(after, guard) ||
      !directoryMatchesGuard(pathAfter, guard) ||
      !sameDirectorySnapshot(opened, after) ||
      !sameDirectorySnapshot(after, pathAfter)
    ) {
      fail("DESTINATION_UNSAFE", "Directory durability target changed during sync");
    }
  } catch {
    fail("DESTINATION_UNSAFE", "Directory durability sync failed");
  } finally {
    await directory?.close().catch(() => undefined);
  }
}

function directoryMatchesGuard(stat: BigIntStats, guard: PathGuard): boolean {
  return (
    stat.isDirectory() &&
    stat.dev === guard.device &&
    stat.ino === guard.inode &&
    stat.uid === guard.uid &&
    (Number(stat.mode) & 0o777) === guard.mode
  );
}

function sameDirectorySnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.isDirectory() &&
    right.isDirectory() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === right.nlink
  );
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
