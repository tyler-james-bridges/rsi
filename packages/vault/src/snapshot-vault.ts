import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { link, lstat, mkdir, open, unlink, type FileHandle } from "node:fs/promises";
import { dirname, join, parse, resolve } from "node:path";
import { TextDecoder } from "node:util";

import {
  SnapshotConflictError,
  SnapshotIntegrityError,
  SnapshotNotFoundError,
  SnapshotSecurityError,
  SnapshotValidationError,
  SnapshotVaultClosedError,
  SnapshotVaultError,
} from "./errors.js";
import { prepareMetadata, type PreparedMetadata } from "./metadata.js";
import type {
  PutSnapshotOptions,
  PutSnapshotResult,
  Snapshot,
  SnapshotAddress,
  SnapshotMetadata,
  SnapshotVaultOptions,
  SnapshotVerification,
} from "./types.js";

export const DEFAULT_MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024;
export const HARD_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024;
export const DEFAULT_MAX_METADATA_BYTES = 16 * 1024;
export const HARD_MAX_METADATA_BYTES = 64 * 1024;

const ADDRESS_PATTERN = /^[0-9a-f]{64}$/;
const MAGIC = Buffer.from("RSIVLT01", "ascii");
const VERSION = 1;
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const PREFIX_BYTES = MAGIC.byteLength + 1 + 4 + 4 + NONCE_BYTES;
const AAD_DOMAIN = Buffer.from("rsi.snapshot-vault.aad.v1\0", "ascii");
const FILE_SUFFIX = ".vault";
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const DIRECTORY_FLAG = fsConstants.O_DIRECTORY ?? 0;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const EFFECTIVE_USER_ID =
  typeof process.geteuid === "function" ? BigInt(process.geteuid()) : undefined;
const LINK_SETTLE_ATTEMPTS = 32;
const LINK_SETTLE_DELAY_MS = 1;

class SnapshotLinkSettlingError extends Error {}

interface DirectoryIdentity {
  readonly device: bigint;
  readonly inode: bigint;
}

interface VerifiedSnapshot {
  readonly address: SnapshotAddress;
  readonly metadata: SnapshotMetadata;
  readonly metadataBytes: Buffer;
  readonly plaintext: Buffer;
  readonly size: number;
}

type VaultState = "closed" | "closing" | "open";

export function isSnapshotAddress(value: string): value is SnapshotAddress {
  return ADDRESS_PATTERN.test(value);
}

export class SnapshotVault {
  readonly directory: string;
  readonly maxMetadataBytes: number;
  readonly maxSnapshotBytes: number;

  #activeOperations = 0;
  #closePromise: Promise<void> | undefined;
  #directoryHandle: FileHandle;
  #directoryIdentity: DirectoryIdentity;
  #drainOperation: (() => void) | undefined;
  #key: Buffer;
  #state: VaultState = "open";

  private constructor(
    directory: string,
    key: Buffer,
    maxSnapshotBytes: number,
    maxMetadataBytes: number,
    directoryHandle: FileHandle,
    directoryIdentity: DirectoryIdentity,
  ) {
    this.directory = directory;
    this.#key = key;
    this.maxSnapshotBytes = maxSnapshotBytes;
    this.maxMetadataBytes = maxMetadataBytes;
    this.#directoryHandle = directoryHandle;
    this.#directoryIdentity = directoryIdentity;
  }

  static async open(options: SnapshotVaultOptions): Promise<SnapshotVault> {
    const directory = validateDirectory(options.directory);
    const maxSnapshotBytes = validateLimit(
      options.maxSnapshotBytes ?? DEFAULT_MAX_SNAPSHOT_BYTES,
      1,
      HARD_MAX_SNAPSHOT_BYTES,
      "snapshot byte limit",
    );
    const maxMetadataBytes = validateLimit(
      options.maxMetadataBytes ?? DEFAULT_MAX_METADATA_BYTES,
      2,
      HARD_MAX_METADATA_BYTES,
      "metadata byte limit",
    );
    const key = copyKey(options.key);

    let directoryHandle: FileHandle | undefined;
    try {
      await mkdir(directory, { mode: DIRECTORY_MODE, recursive: true });
      const beforeOpen = await lstat(directory, { bigint: true });
      if (beforeOpen.isSymbolicLink() || !beforeOpen.isDirectory()) {
        throw new SnapshotSecurityError();
      }

      directoryHandle = await open(directory, fsConstants.O_RDONLY | DIRECTORY_FLAG | NOFOLLOW);
      const opened = await directoryHandle.stat({ bigint: true });
      if (
        !opened.isDirectory() ||
        opened.dev !== beforeOpen.dev ||
        opened.ino !== beforeOpen.ino ||
        opened.uid !== beforeOpen.uid ||
        (EFFECTIVE_USER_ID !== undefined && opened.uid !== EFFECTIVE_USER_ID)
      ) {
        throw new SnapshotSecurityError();
      }

      if ((opened.mode & 0o777n) !== BigInt(DIRECTORY_MODE)) {
        throw new SnapshotSecurityError();
      }
      await directoryHandle.sync();
      return new SnapshotVault(
        directory,
        key,
        maxSnapshotBytes,
        maxMetadataBytes,
        directoryHandle,
        { device: opened.dev, inode: opened.ino },
      );
    } catch (error) {
      key.fill(0);
      if (directoryHandle !== undefined) {
        await directoryHandle.close().catch(() => undefined);
      }
      if (error instanceof SnapshotVaultError) {
        throw error;
      }
      throw new SnapshotSecurityError("Unable to initialize snapshot vault safely");
    }
  }

  async put(bytes: Uint8Array, options: PutSnapshotOptions = {}): Promise<PutSnapshotResult> {
    const plaintext = copySnapshotBytes(bytes, this.maxSnapshotBytes);
    let metadata: PreparedMetadata | undefined;
    let key: Buffer | undefined;
    let operationStarted = false;
    try {
      try {
        metadata = prepareMetadata(options.metadata, this.maxMetadataBytes);
      } catch (error) {
        if (error instanceof SnapshotValidationError) {
          throw error;
        }
        throw new SnapshotValidationError("Snapshot metadata is invalid");
      }
      key = this.#beginOperation();
      operationStarted = true;
      const digest = createHash("sha256").update(plaintext).digest();
      const address = digest.toString("hex") as SnapshotAddress;
      digest.fill(0);

      let existing: VerifiedSnapshot | undefined;
      try {
        existing = await this.#readVerified(address, key);
      } catch (error) {
        if (!(error instanceof SnapshotNotFoundError)) {
          throw error;
        }
      }

      if (existing !== undefined) {
        try {
          assertSameObject(existing, plaintext, metadata.bytes);
          return makePutResult(existing, false);
        } finally {
          existing.plaintext.fill(0);
          existing.metadataBytes.fill(0);
        }
      }

      const envelope = encryptEnvelope(address, plaintext, metadata.bytes, key);
      const created = await this.#publish(address, envelope);
      const stored = await this.#readVerified(address, key).catch((error: unknown) => {
        if (error instanceof SnapshotNotFoundError) {
          throw new SnapshotIntegrityError();
        }
        throw error;
      });
      try {
        assertSameObject(stored, plaintext, metadata.bytes);
        return makePutResult(stored, created);
      } finally {
        stored.plaintext.fill(0);
        stored.metadataBytes.fill(0);
      }
    } finally {
      plaintext.fill(0);
      metadata?.bytes.fill(0);
      key?.fill(0);
      if (operationStarted) {
        this.#endOperation();
      }
    }
  }

  async get(address: string): Promise<Snapshot> {
    const validAddress = validateAddress(address);
    const key = this.#beginOperation();
    try {
      const stored = await this.#readVerified(validAddress, key);
      try {
        return Object.freeze({
          address: stored.address,
          bytes: new Uint8Array(stored.plaintext),
          metadata: stored.metadata,
          size: stored.size,
        });
      } finally {
        stored.plaintext.fill(0);
        stored.metadataBytes.fill(0);
      }
    } finally {
      key.fill(0);
      this.#endOperation();
    }
  }

  async verify(address: string): Promise<SnapshotVerification> {
    const validAddress = validateAddress(address);
    const key = this.#beginOperation();
    try {
      const stored = await this.#readVerified(validAddress, key);
      try {
        return Object.freeze({
          address: stored.address,
          metadata: stored.metadata,
          size: stored.size,
          valid: true as const,
        });
      } finally {
        stored.plaintext.fill(0);
        stored.metadataBytes.fill(0);
      }
    } finally {
      key.fill(0);
      this.#endOperation();
    }
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) {
      return this.#closePromise;
    }

    this.#state = "closing";
    this.#key.fill(0);
    this.#closePromise = this.#finishClose();
    return this.#closePromise;
  }

  async #finishClose(): Promise<void> {
    if (this.#activeOperations > 0) {
      await new Promise<void>((resolveDrain) => {
        this.#drainOperation = resolveDrain;
      });
    }
    try {
      await this.#directoryHandle.sync();
    } catch {
      // Closing still releases the descriptor; completed writes fsync independently.
    }
    await this.#directoryHandle.close().catch(() => undefined);
    this.#state = "closed";
  }

  #beginOperation(): Buffer {
    if (this.#state !== "open") {
      throw new SnapshotVaultClosedError();
    }
    const key = Buffer.from(this.#key);
    this.#activeOperations += 1;
    return key;
  }

  #endOperation(): void {
    this.#activeOperations -= 1;
    if (this.#activeOperations === 0 && this.#drainOperation !== undefined) {
      const resolveDrain = this.#drainOperation;
      this.#drainOperation = undefined;
      resolveDrain();
    }
  }

  async #assertDirectoryIdentity(): Promise<void> {
    let pathStats;
    try {
      pathStats = await lstat(this.directory, { bigint: true });
    } catch {
      throw new SnapshotSecurityError();
    }
    if (
      pathStats.isSymbolicLink() ||
      !pathStats.isDirectory() ||
      pathStats.dev !== this.#directoryIdentity.device ||
      pathStats.ino !== this.#directoryIdentity.inode ||
      (EFFECTIVE_USER_ID !== undefined && pathStats.uid !== EFFECTIVE_USER_ID) ||
      (pathStats.mode & 0o777n) !== BigInt(DIRECTORY_MODE)
    ) {
      throw new SnapshotSecurityError();
    }
  }

  async #publish(address: SnapshotAddress, envelope: Buffer): Promise<boolean> {
    await this.#assertDirectoryIdentity();
    const targetPath = this.#objectPath(address);
    let temporaryPath: string | undefined;
    let temporaryHandle: FileHandle | undefined;

    try {
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const temporaryName = `.tmp-${randomBytes(16).toString("hex")}`;
        temporaryPath = join(this.directory, temporaryName);
        if (dirname(temporaryPath) !== this.directory) {
          throw new SnapshotSecurityError();
        }
        try {
          temporaryHandle = await open(
            temporaryPath,
            fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NOFOLLOW,
            FILE_MODE,
          );
          break;
        } catch (error) {
          if (!isErrorCode(error, "EEXIST") || attempt === 3) {
            throw error;
          }
        }
      }
      if (temporaryHandle === undefined || temporaryPath === undefined) {
        throw new SnapshotSecurityError();
      }

      await writeAll(temporaryHandle, envelope);
      await temporaryHandle.sync();
      const writtenStats = await temporaryHandle.stat({ bigint: true });
      if (
        !writtenStats.isFile() ||
        writtenStats.nlink !== 1n ||
        writtenStats.size !== BigInt(envelope.byteLength) ||
        (EFFECTIVE_USER_ID !== undefined && writtenStats.uid !== EFFECTIVE_USER_ID) ||
        (writtenStats.mode & 0o777n) !== BigInt(FILE_MODE)
      ) {
        throw new SnapshotSecurityError();
      }
      await temporaryHandle.close();
      temporaryHandle = undefined;

      let created = true;
      try {
        await link(temporaryPath, targetPath);
      } catch (error) {
        if (!isErrorCode(error, "EEXIST")) {
          throw error;
        }
        created = false;
      }

      await unlink(temporaryPath);
      temporaryPath = undefined;
      await this.#directoryHandle.sync();
      await this.#assertDirectoryIdentity();
      return created;
    } catch (error) {
      if (temporaryHandle !== undefined) {
        await temporaryHandle.close().catch(() => undefined);
      }
      if (temporaryPath !== undefined) {
        await unlink(temporaryPath).catch(() => undefined);
      }
      if (error instanceof SnapshotVaultError) {
        throw error;
      }
      throw new SnapshotSecurityError("Unable to publish snapshot safely");
    }
  }

  async #readVerified(address: SnapshotAddress, key: Buffer): Promise<VerifiedSnapshot> {
    for (let attempt = 0; attempt < LINK_SETTLE_ATTEMPTS; attempt += 1) {
      try {
        return await this.#readVerifiedOnce(address, key);
      } catch (error) {
        if (!(error instanceof SnapshotLinkSettlingError)) throw error;
        if (attempt === LINK_SETTLE_ATTEMPTS - 1) throw new SnapshotSecurityError();
        await new Promise<void>((resolveDelay) => {
          setTimeout(resolveDelay, LINK_SETTLE_DELAY_MS);
        });
      }
    }
    throw new SnapshotSecurityError();
  }

  async #readVerifiedOnce(address: SnapshotAddress, key: Buffer): Promise<VerifiedSnapshot> {
    await this.#assertDirectoryIdentity();
    const path = this.#objectPath(address);
    let beforeOpen;
    try {
      beforeOpen = await lstat(path, { bigint: true });
    } catch (error) {
      if (isErrorCode(error, "ENOENT")) {
        throw new SnapshotNotFoundError();
      }
      throw new SnapshotSecurityError();
    }
    if (
      beforeOpen.isSymbolicLink() ||
      !beforeOpen.isFile() ||
      (EFFECTIVE_USER_ID !== undefined && beforeOpen.uid !== EFFECTIVE_USER_ID) ||
      (beforeOpen.mode & 0o777n) !== BigInt(FILE_MODE)
    ) {
      throw new SnapshotSecurityError();
    }
    assertSettledLinkCount(beforeOpen.nlink);

    let handle: FileHandle;
    try {
      handle = await open(path, fsConstants.O_RDONLY | NOFOLLOW);
    } catch (error) {
      if (isErrorCode(error, "ENOENT")) {
        throw new SnapshotNotFoundError();
      }
      throw new SnapshotSecurityError();
    }

    let envelope: Buffer;
    try {
      const opened = await handle.stat({ bigint: true });
      if (
        !opened.isFile() ||
        opened.dev !== beforeOpen.dev ||
        opened.ino !== beforeOpen.ino ||
        opened.uid !== beforeOpen.uid ||
        (opened.mode & 0o777n) !== BigInt(FILE_MODE)
      ) {
        throw new SnapshotSecurityError();
      }
      assertSettledLinkCount(opened.nlink);

      const maximumEnvelopeBytes =
        PREFIX_BYTES + AUTH_TAG_BYTES + this.maxSnapshotBytes + this.maxMetadataBytes;
      if (
        opened.size < BigInt(PREFIX_BYTES + AUTH_TAG_BYTES + 2) ||
        opened.size > BigInt(maximumEnvelopeBytes)
      ) {
        throw new SnapshotIntegrityError();
      }
      envelope = Buffer.alloc(Number(opened.size));
      await readAll(handle, envelope);

      const trailingByte = Buffer.allocUnsafe(1);
      const trailingRead = await handle.read(trailingByte, 0, 1, envelope.byteLength);
      const afterRead = await handle.stat({ bigint: true });
      if (
        trailingRead.bytesRead !== 0 ||
        afterRead.size !== opened.size ||
        afterRead.dev !== opened.dev ||
        afterRead.ino !== opened.ino ||
        afterRead.uid !== opened.uid ||
        (afterRead.mode & 0o777n) !== BigInt(FILE_MODE)
      ) {
        throw new SnapshotIntegrityError();
      }
      assertSettledLinkCount(afterRead.nlink);
    } catch (error) {
      if (error instanceof SnapshotVaultError || error instanceof SnapshotLinkSettlingError) {
        throw error;
      }
      throw new SnapshotIntegrityError();
    } finally {
      await handle.close().catch(() => undefined);
    }

    await this.#assertDirectoryIdentity();
    return decryptEnvelope(address, envelope, key, this.maxSnapshotBytes, this.maxMetadataBytes);
  }

  #objectPath(address: SnapshotAddress): string {
    const filename = `${address}${FILE_SUFFIX}`;
    const path = join(this.directory, filename);
    if (dirname(path) !== this.directory) {
      throw new SnapshotSecurityError();
    }
    return path;
  }
}

function assertSettledLinkCount(linkCount: bigint): void {
  if (linkCount === 1n) return;
  if (linkCount === 2n) throw new SnapshotLinkSettlingError();
  throw new SnapshotSecurityError();
}

function encryptEnvelope(
  address: SnapshotAddress,
  plaintext: Buffer,
  metadata: Buffer,
  key: Buffer,
): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const prefix = Buffer.alloc(PREFIX_BYTES);
  MAGIC.copy(prefix, 0);
  prefix.writeUInt8(VERSION, MAGIC.byteLength);
  prefix.writeUInt32BE(plaintext.byteLength, MAGIC.byteLength + 1);
  prefix.writeUInt32BE(metadata.byteLength, MAGIC.byteLength + 5);
  nonce.copy(prefix, MAGIC.byteLength + 9);

  const aad = makeAad(address, prefix);
  const payload = Buffer.concat([metadata, plaintext]);
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: AUTH_TAG_BYTES });
    cipher.setAAD(aad, { plaintextLength: payload.byteLength });
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([prefix, ciphertext, tag]);
  } catch {
    throw new SnapshotIntegrityError();
  } finally {
    payload.fill(0);
  }
}

function decryptEnvelope(
  address: SnapshotAddress,
  envelope: Buffer,
  key: Buffer,
  maxSnapshotBytes: number,
  maxMetadataBytes: number,
): VerifiedSnapshot {
  let metadataToWipe: Buffer | undefined;
  let plaintextToWipe: Buffer | undefined;
  try {
    if (!envelope.subarray(0, MAGIC.byteLength).equals(MAGIC)) {
      throw new SnapshotIntegrityError();
    }
    if (envelope.readUInt8(MAGIC.byteLength) !== VERSION) {
      throw new SnapshotIntegrityError();
    }

    const plaintextLength = envelope.readUInt32BE(MAGIC.byteLength + 1);
    const metadataLength = envelope.readUInt32BE(MAGIC.byteLength + 5);
    if (
      plaintextLength > maxSnapshotBytes ||
      metadataLength < 2 ||
      metadataLength > maxMetadataBytes
    ) {
      throw new SnapshotIntegrityError();
    }

    const expectedLength = PREFIX_BYTES + metadataLength + plaintextLength + AUTH_TAG_BYTES;
    if (envelope.byteLength !== expectedLength) {
      throw new SnapshotIntegrityError();
    }

    const prefix = envelope.subarray(0, PREFIX_BYTES);
    const ciphertext = envelope.subarray(
      PREFIX_BYTES,
      PREFIX_BYTES + metadataLength + plaintextLength,
    );
    const tag = envelope.subarray(expectedLength - AUTH_TAG_BYTES);

    const nonce = prefix.subarray(MAGIC.byteLength + 9, PREFIX_BYTES);
    const aad = makeAad(address, prefix);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTH_TAG_BYTES,
    });
    decipher.setAAD(aad, { plaintextLength: metadataLength + plaintextLength });
    decipher.setAuthTag(tag);
    const firstChunk = decipher.update(ciphertext);
    let finalChunk: Buffer | undefined;
    let decrypted: Buffer;
    try {
      finalChunk = decipher.final();
      decrypted = Buffer.concat([firstChunk, finalChunk]);
    } finally {
      firstChunk.fill(0);
      finalChunk?.fill(0);
    }
    if (decrypted.byteLength !== metadataLength + plaintextLength) {
      decrypted.fill(0);
      throw new SnapshotIntegrityError();
    }

    let preparedMetadata: PreparedMetadata;
    let plaintext: Buffer;
    try {
      const metadataBytes = decrypted.subarray(0, metadataLength);
      const decodedMetadata = UTF8_DECODER.decode(metadataBytes);
      const parsedMetadata: unknown = JSON.parse(decodedMetadata);
      preparedMetadata = prepareMetadata(parsedMetadata as SnapshotMetadata, maxMetadataBytes);
      metadataToWipe = preparedMetadata.bytes;
      if (!preparedMetadata.bytes.equals(metadataBytes)) {
        throw new SnapshotIntegrityError();
      }
      plaintext = Buffer.from(decrypted.subarray(metadataLength));
      plaintextToWipe = plaintext;
    } finally {
      decrypted.fill(0);
    }

    const actualDigest = createHash("sha256").update(plaintext).digest();
    const expectedDigest = Buffer.from(address, "hex");
    const matchesAddress = timingSafeEqual(actualDigest, expectedDigest);
    actualDigest.fill(0);
    expectedDigest.fill(0);
    if (!matchesAddress) {
      plaintext.fill(0);
      throw new SnapshotIntegrityError();
    }

    const verified: VerifiedSnapshot = {
      address,
      metadata: preparedMetadata.value,
      metadataBytes: preparedMetadata.bytes,
      plaintext,
      size: plaintextLength,
    };
    metadataToWipe = undefined;
    plaintextToWipe = undefined;
    return verified;
  } catch {
    throw new SnapshotIntegrityError();
  } finally {
    metadataToWipe?.fill(0);
    plaintextToWipe?.fill(0);
  }
}

function makeAad(address: SnapshotAddress, prefix: Buffer): Buffer {
  return Buffer.concat([AAD_DOMAIN, Buffer.from(address, "hex"), prefix]);
}

function assertSameObject(
  stored: VerifiedSnapshot,
  expectedPlaintext: Buffer,
  expectedMetadata: Buffer,
): void {
  if (
    stored.plaintext.byteLength !== expectedPlaintext.byteLength ||
    !timingSafeEqual(stored.plaintext, expectedPlaintext)
  ) {
    throw new SnapshotIntegrityError();
  }
  if (
    stored.metadataBytes.byteLength !== expectedMetadata.byteLength ||
    !timingSafeEqual(stored.metadataBytes, expectedMetadata)
  ) {
    throw new SnapshotConflictError();
  }
}

function makePutResult(stored: VerifiedSnapshot, created: boolean): PutSnapshotResult {
  return Object.freeze({
    address: stored.address,
    created,
    metadata: stored.metadata,
    size: stored.size,
  });
}

function copySnapshotBytes(value: Uint8Array, maxBytes: number): Buffer {
  try {
    if (!(value instanceof Uint8Array)) {
      throw new SnapshotValidationError("Snapshot content must be a Uint8Array");
    }
    if (value.byteLength > maxBytes) {
      throw new SnapshotValidationError("Snapshot content exceeds the configured byte limit");
    }
    return Buffer.from(value);
  } catch (error) {
    if (error instanceof SnapshotValidationError) {
      throw error;
    }
    throw new SnapshotValidationError("Snapshot content is invalid");
  }
}

function copyKey(value: Uint8Array): Buffer {
  try {
    if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
      throw new SnapshotValidationError("Snapshot vault key must contain exactly 32 bytes");
    }
    return Buffer.from(value);
  } catch (error) {
    if (error instanceof SnapshotValidationError) {
      throw error;
    }
    throw new SnapshotValidationError("Snapshot vault key is invalid");
  }
}

function validateAddress(value: string): SnapshotAddress {
  if (typeof value !== "string" || !isSnapshotAddress(value)) {
    throw new SnapshotValidationError(
      "Snapshot address must be 64 lowercase hexadecimal characters",
    );
  }
  return value;
}

function validateDirectory(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4_096 ||
    value.includes("\0")
  ) {
    throw new SnapshotValidationError("Snapshot vault directory is invalid");
  }
  const directory = resolve(value);
  if (directory === parse(directory).root) {
    throw new SnapshotValidationError("Snapshot vault directory must not be the filesystem root");
  }
  return directory;
}

function validateLimit(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new SnapshotValidationError(`Snapshot vault ${label} is outside the supported range`);
  }
  return value;
}

async function writeAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesWritten < 1) {
      throw new SnapshotSecurityError("Unable to write snapshot atomically");
    }
    offset += result.bytesWritten;
  }
}

async function readAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesRead < 1) {
      throw new SnapshotIntegrityError();
    }
    offset += result.bytesRead;
  }
}

function isErrorCode(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}
