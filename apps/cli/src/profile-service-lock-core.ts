import { randomUUID, timingSafeEqual } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, mkdir, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { types as utilTypes } from "node:util";

const PRIVATE_DIRECTORY_MODE = 0o700n;
const PRIVATE_FILE_MODE = 0o600n;
const STICKY_DIRECTORY_BIT = 0o1000n;
const LOCK_SCHEMA_VERSION = 1 as const;
const MAX_SCOPE_ID_LENGTH = 64;
const SCOPE_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const SHARED_CANARY_SCOPE_ID = "stage1-canary" as const;
const AUTHENTIC_PROFILE_SERVICE_LOCKS = new WeakSet<object>();

export const PROFILE_SERVICE_LOCK_ERROR_MESSAGES = Object.freeze({
  contended:
    "RSI operator startup refused because another process holds the selected service lock.",
  durability: "RSI operator lock release could not confirm directory durability.",
  ownership: "RSI operator lock release refused because ownership could not be verified.",
  unsafe: "RSI operator startup refused because the selected service lock path is unsafe.",
} as const);

export type ProfileServiceLockErrorCode = keyof typeof PROFILE_SERVICE_LOCK_ERROR_MESSAGES;

export class ProfileServiceLockError extends Error {
  readonly code: ProfileServiceLockErrorCode;

  constructor(code: ProfileServiceLockErrorCode) {
    super(PROFILE_SERVICE_LOCK_ERROR_MESSAGES[code]);
    this.name = "ProfileServiceLockError";
    this.code = code;
  }
}

export interface AcquireProfileServiceLockOptions {
  /** Existing owner-only directory containing every mutable resource in this lock scope. */
  readonly dataDirectory: string;
  /** Stable code-owned identifier; callers sharing mutable authority must share this value. */
  readonly scopeId: string;
}

export interface ProfileServiceLock {
  /** Canonical owner-only lock artifact. Its contents must never be used as instructions. */
  readonly artifactPath: string;
  readonly scopeId: string;
  /** Idempotent for this owning handle. Refuses to remove an artifact it cannot prove it owns. */
  release(): Promise<void>;
}

export interface ProfileServiceLockBoundResource {
  close(): Promise<void>;
}

export interface CanaryProfileLockLease {
  release(): Promise<void>;
}

interface ParsedLockOptions {
  readonly dataDirectory: string;
  readonly scopeId: string;
}

interface LockIdentity {
  readonly device: bigint;
  readonly inode: bigint;
}

function errnoCode(error: unknown): string | undefined {
  if (!(error instanceof Error) || !("code" in error)) return undefined;
  const value = (error as NodeJS.ErrnoException).code;
  return typeof value === "string" ? value : undefined;
}

function unsafe(): ProfileServiceLockError {
  return new ProfileServiceLockError("unsafe");
}

function ownershipFailure(): ProfileServiceLockError {
  return new ProfileServiceLockError("ownership");
}

function durabilityFailure(): ProfileServiceLockError {
  return new ProfileServiceLockError("durability");
}

function parseOptions(value: AcquireProfileServiceLockOptions): ParsedLockOptions {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw unsafe();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw unsafe();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value).sort();
    if (keys.length !== 2 || keys[0] !== "dataDirectory" || keys[1] !== "scopeId") {
      throw unsafe();
    }
    const dataDirectory = descriptors.dataDirectory?.value;
    const scopeId = descriptors.scopeId?.value;
    if (
      typeof dataDirectory !== "string" ||
      !isAbsolute(dataDirectory) ||
      dataDirectory.includes("\0") ||
      typeof scopeId !== "string" ||
      scopeId.length > MAX_SCOPE_ID_LENGTH ||
      !SCOPE_ID_PATTERN.test(scopeId)
    ) {
      throw unsafe();
    }
    return { dataDirectory, scopeId };
  } catch (error) {
    if (error instanceof ProfileServiceLockError) throw error;
    throw unsafe();
  }
}

function effectiveUserId(): bigint {
  if (typeof process.geteuid !== "function") throw unsafe();
  const value = process.geteuid();
  if (!Number.isSafeInteger(value) || value < 0) throw unsafe();
  return BigInt(value);
}

function isPrivateDirectory(entry: BigIntStats, expectedUserId: bigint): boolean {
  return (
    entry.isDirectory() &&
    !entry.isSymbolicLink() &&
    entry.uid === expectedUserId &&
    (entry.mode & 0o777n) === PRIVATE_DIRECTORY_MODE
  );
}

function isPrivateLockFile(entry: BigIntStats, expectedUserId: bigint): boolean {
  return (
    entry.isFile() &&
    !entry.isSymbolicLink() &&
    entry.uid === expectedUserId &&
    entry.nlink === 1n &&
    (entry.mode & 0o777n) === PRIVATE_FILE_MODE
  );
}

function isSafeContainingDirectory(entry: BigIntStats, expectedUserId: bigint): boolean {
  const writableByAnotherIdentity = (entry.mode & 0o022n) !== 0n;
  const trustedOwner = entry.uid === expectedUserId || entry.uid === 0n;
  return (
    entry.isDirectory() &&
    !entry.isSymbolicLink() &&
    trustedOwner &&
    (!writableByAnotherIdentity || (entry.mode & STICKY_DIRECTORY_BIT) !== 0n)
  );
}

async function assertSafeAncestorChain(path: string, expectedUserId: bigint): Promise<void> {
  let current = resolve(path);
  for (;;) {
    const entry = await lstat(current, { bigint: true });
    if (!isSafeContainingDirectory(entry, expectedUserId)) throw unsafe();
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function canonicalPrivateDirectory(path: string, expectedUserId: bigint): Promise<string> {
  try {
    const requestedPath = resolve(path);
    const requestedEntry = await lstat(requestedPath, { bigint: true });
    if (!isPrivateDirectory(requestedEntry, expectedUserId)) throw unsafe();

    const canonicalPath = await realpath(requestedPath);
    const canonicalEntry = await lstat(canonicalPath, { bigint: true });
    if (
      !isPrivateDirectory(canonicalEntry, expectedUserId) ||
      !sameIdentity(requestedEntry, canonicalEntry)
    ) {
      throw unsafe();
    }
    await assertSafeAncestorChain(dirname(canonicalPath), expectedUserId);
    return canonicalPath;
  } catch (error) {
    if (error instanceof ProfileServiceLockError) throw error;
    throw unsafe();
  }
}

async function classifyExistingArtifact(path: string, expectedUserId: bigint): Promise<never> {
  try {
    const entry = await lstat(path, { bigint: true });
    if (!isPrivateLockFile(entry, expectedUserId)) throw unsafe();
    throw new ProfileServiceLockError("contended");
  } catch (error) {
    if (error instanceof ProfileServiceLockError) throw error;
    throw unsafe();
  }
}

async function verifiedOwnedEntry(
  path: string,
  handle: FileHandle,
  expectedUserId: bigint,
): Promise<Readonly<{ descriptor: BigIntStats; path: BigIntStats }>> {
  try {
    const [descriptorEntry, pathEntry] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (
      !isPrivateLockFile(descriptorEntry, expectedUserId) ||
      !isPrivateLockFile(pathEntry, expectedUserId) ||
      !sameIdentity(descriptorEntry, pathEntry)
    ) {
      throw ownershipFailure();
    }
    return { descriptor: descriptorEntry, path: pathEntry };
  } catch (error) {
    if (error instanceof ProfileServiceLockError) throw error;
    throw ownershipFailure();
  }
}

async function verifiedPrivateDirectoryHandle(
  path: string,
  handle: FileHandle,
  expectedUserId: bigint,
): Promise<void> {
  try {
    const [descriptorEntry, pathEntry] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (
      !isPrivateDirectory(descriptorEntry, expectedUserId) ||
      !isPrivateDirectory(pathEntry, expectedUserId) ||
      !sameIdentity(descriptorEntry, pathEntry)
    ) {
      throw unsafe();
    }
  } catch (error) {
    if (error instanceof ProfileServiceLockError) throw error;
    throw unsafe();
  }
}

async function openVerifiedPrivateDirectory(
  path: string,
  expectedUserId: bigint,
): Promise<FileHandle> {
  let handle: FileHandle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw unsafe();
  }
  try {
    await verifiedPrivateDirectoryHandle(path, handle, expectedUserId);
    return handle;
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function removePartiallyOwnedArtifact(
  path: string,
  handle: FileHandle,
  identity: LockIdentity,
  expectedUserId: bigint,
): Promise<void> {
  try {
    const entry = await lstat(path, { bigint: true });
    if (
      isPrivateLockFile(entry, expectedUserId) &&
      entry.dev === identity.device &&
      entry.ino === identity.inode
    ) {
      await unlink(path);
    }
  } catch {
    // Acquisition already failed. Leaving an uncertain artifact in place is fail-closed.
  } finally {
    await handle.close().catch(() => undefined);
  }
}

class OwnedProfileServiceLock implements ProfileServiceLock {
  readonly artifactPath: string;
  readonly scopeId: string;

  readonly #expectedArtifact: Uint8Array;
  readonly #expectedUserId: bigint;
  readonly #directoryHandle: FileHandle;
  readonly #handle: FileHandle;
  #releasePromise: Promise<void> | null = null;
  #released = false;

  constructor(options: {
    artifactPath: string;
    directoryHandle: FileHandle;
    expectedArtifact: Uint8Array;
    expectedUserId: bigint;
    handle: FileHandle;
    scopeId: string;
  }) {
    this.artifactPath = options.artifactPath;
    this.scopeId = options.scopeId;
    this.#directoryHandle = options.directoryHandle;
    this.#expectedArtifact = options.expectedArtifact;
    this.#expectedUserId = options.expectedUserId;
    this.#handle = options.handle;
    AUTHENTIC_PROFILE_SERVICE_LOCKS.add(this);
    Object.freeze(this);
  }

  release(): Promise<void> {
    if (this.#releasePromise !== null) return this.#releasePromise;
    if (this.#released) return Promise.resolve();
    this.#released = true;
    AUTHENTIC_PROFILE_SERVICE_LOCKS.delete(this);
    this.#releasePromise = this.#releaseOnce();
    return this.#releasePromise;
  }

  async #releaseOnce(): Promise<void> {
    try {
      await verifiedPrivateDirectoryHandle(
        dirname(this.artifactPath),
        this.#directoryHandle,
        this.#expectedUserId,
      );
      const { descriptor } = await verifiedOwnedEntry(
        this.artifactPath,
        this.#handle,
        this.#expectedUserId,
      );
      if (descriptor.size !== BigInt(this.#expectedArtifact.byteLength)) {
        throw ownershipFailure();
      }

      const actual = new Uint8Array(this.#expectedArtifact.byteLength);
      const { bytesRead } = await this.#handle.read(actual, 0, actual.byteLength, 0);
      if (
        bytesRead !== this.#expectedArtifact.byteLength ||
        !timingSafeEqual(actual, this.#expectedArtifact)
      ) {
        throw ownershipFailure();
      }

      await unlink(this.artifactPath);
      try {
        await this.#directoryHandle.sync();
      } catch {
        throw durabilityFailure();
      }
    } catch (error) {
      if (error instanceof ProfileServiceLockError) throw error;
      throw ownershipFailure();
    } finally {
      await Promise.all([
        this.#handle.close().catch(() => undefined),
        this.#directoryHandle.close().catch(() => undefined),
      ]);
    }
  }
}

/**
 * Atomically claims a single-writer scope without inspecting or reclaiming existing lock content.
 * The caller must acquire this before opening storage, recovering state, or touching credentials.
 */
export async function acquireProfileServiceLock(
  options: AcquireProfileServiceLockOptions,
): Promise<ProfileServiceLock> {
  const parsed = parseOptions(options);
  const expectedUserId = effectiveUserId();
  const directory = await canonicalPrivateDirectory(parsed.dataDirectory, expectedUserId);
  const artifactPath = join(directory, `.rsi-${parsed.scopeId}.lock`);
  const ownerToken = randomUUID();
  const expectedArtifact = new TextEncoder().encode(
    `${JSON.stringify({ ownerToken, schemaVersion: LOCK_SCHEMA_VERSION, scopeId: parsed.scopeId })}\n`,
  );
  const directoryHandle = await openVerifiedPrivateDirectory(directory, expectedUserId);

  let handle: FileHandle;
  try {
    handle = await open(
      artifactPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_RDWR,
      Number(PRIVATE_FILE_MODE),
    );
  } catch (error) {
    await directoryHandle.close().catch(() => undefined);
    if (errnoCode(error) === "EEXIST") {
      return classifyExistingArtifact(artifactPath, expectedUserId);
    }
    throw unsafe();
  }

  let artifactMustRemain = false;
  try {
    await verifiedPrivateDirectoryHandle(directory, directoryHandle, expectedUserId);
    await handle.chmod(Number(PRIVATE_FILE_MODE));
    await verifiedOwnedEntry(artifactPath, handle, expectedUserId);
    await handle.writeFile(expectedArtifact);
    await handle.sync();
    const verified = await verifiedOwnedEntry(artifactPath, handle, expectedUserId);
    if (verified.descriptor.size !== BigInt(expectedArtifact.byteLength)) throw unsafe();
    artifactMustRemain = true;
    await directoryHandle.sync();
    await verifiedPrivateDirectoryHandle(directory, directoryHandle, expectedUserId);
  } catch (error) {
    if (artifactMustRemain) {
      await handle.close().catch(() => undefined);
    } else {
      const descriptorEntry = await handle.stat({ bigint: true }).catch(() => null);
      const identity: LockIdentity =
        descriptorEntry === null
          ? { device: -1n, inode: -1n }
          : { device: descriptorEntry.dev, inode: descriptorEntry.ino };
      await removePartiallyOwnedArtifact(artifactPath, handle, identity, expectedUserId);
    }
    await directoryHandle.close().catch(() => undefined);
    if (error instanceof ProfileServiceLockError) throw unsafe();
    throw unsafe();
  }

  return Object.freeze(
    new OwnedProfileServiceLock({
      artifactPath,
      directoryHandle,
      expectedArtifact,
      expectedUserId,
      handle,
      scopeId: parsed.scopeId,
    }),
  );
}

/**
 * Host-core bridge with a fixed shared scope. The parent is created only so the lock can precede
 * every mutable database, recovery, and credential boundary.
 */
export async function acquireCanaryProfileLockForDatabasePath(
  databasePath: string,
): Promise<ProfileServiceLock> {
  if (
    typeof databasePath !== "string" ||
    !isAbsolute(databasePath) ||
    databasePath.includes("\0") ||
    databasePath === resolve(databasePath, "..")
  ) {
    throw unsafe();
  }
  const dataDirectory = dirname(resolve(databasePath));
  try {
    await mkdir(dataDirectory, {
      mode: Number(PRIVATE_DIRECTORY_MODE),
      recursive: true,
    });
  } catch {
    throw unsafe();
  }
  return acquireProfileServiceLock({ dataDirectory, scopeId: SHARED_CANARY_SCOPE_ID });
}

/** Proves that a host core received the authentic shared lease for its own fixed data directory. */
export async function assertCanaryProfileLockForDatabasePath(
  value: unknown,
  databasePath: string,
): Promise<void> {
  if (
    typeof value !== "object" ||
    value === null ||
    !AUTHENTIC_PROFILE_SERVICE_LOCKS.has(value) ||
    typeof databasePath !== "string" ||
    !isAbsolute(databasePath) ||
    databasePath.includes("\0")
  ) {
    throw unsafe();
  }
  const lock = value as ProfileServiceLock;
  let dataDirectory: string;
  try {
    dataDirectory = await realpath(dirname(resolve(databasePath)));
  } catch {
    throw unsafe();
  }
  const expectedArtifactPath = join(dataDirectory, `.rsi-${SHARED_CANARY_SCOPE_ID}.lock`);
  if (lock.scopeId !== SHARED_CANARY_SCOPE_ID || lock.artifactPath !== expectedArtifactPath) {
    throw unsafe();
  }
}

/**
 * Keeps the lock until the wrapped resource has completed its entire shutdown sequence.
 * Concurrent close calls share one result. A failed shutdown deliberately keeps the lock artifact
 * in place because releasing it would claim that single-writer state was safe to reopen.
 */
export function bindProfileServiceLock<T extends ProfileServiceLockBoundResource>(
  resource: T,
  lock: Pick<ProfileServiceLock, "release">,
): T {
  if (
    typeof resource !== "object" ||
    resource === null ||
    utilTypes.isProxy(resource) ||
    Object.getPrototypeOf(resource) !== Object.prototype
  ) {
    throw new TypeError("A plain profile-lock resource is required");
  }
  const descriptors = Object.getOwnPropertyDescriptors(resource);
  const keys = Reflect.ownKeys(descriptors);
  const closeDescriptor = descriptors.close;
  if (
    closeDescriptor === undefined ||
    !("value" in closeDescriptor) ||
    typeof closeDescriptor.value !== "function" ||
    keys.some((key) => {
      const descriptor = descriptors[key as keyof typeof descriptors];
      return (
        typeof key !== "string" ||
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      );
    })
  ) {
    throw new TypeError("A plain profile-lock resource is required");
  }
  let closePromise: Promise<void> | null = null;
  const close = (): Promise<void> => {
    closePromise ??= (async () => {
      await resource.close();
      await lock.release();
    })();
    return closePromise;
  };
  return Object.freeze(
    Object.defineProperties(Object.create(null) as object, {
      ...descriptors,
      close: { ...closeDescriptor, value: close },
    }),
  ) as T;
}
