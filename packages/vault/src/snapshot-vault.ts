import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { dirname, join, parse, resolve } from "node:path";

import {
  SnapshotConflictError,
  SnapshotIntegrityError,
  SnapshotNotFoundError,
  SnapshotSecurityError,
  SnapshotValidationError,
  SnapshotVaultClosedError,
  SnapshotVaultError,
} from "./errors.js";
import {
  decodeDeletionReceipt,
  decodeMetadata,
  prepareCaptureMetadata,
  prepareDeletionReceipt,
  validateCanonicalTimestamp,
  type PreparedDeletionReceipt,
  type PreparedMetadata,
} from "./metadata.js";
import type {
  Capture,
  CaptureDeletionReceiptV1,
  CaptureDescriptor,
  CaptureExpirySweepResultV1,
  CaptureId,
  CaptureOptions,
  CaptureRecoveryResultV1,
  CaptureReconciliationResultV1,
  CaptureVerification,
  DeleteCaptureOptions,
  RecoverCaptureVaultOptions,
  ReconcileRegisteredCapturesOptions,
  SnapshotVaultOptions,
  SweepExpiredOptions,
} from "./types.js";

export const DEFAULT_MAX_CAPTURE_BYTES = 16 * 1024 * 1024;
export const HARD_MAX_CAPTURE_BYTES = 16 * 1024 * 1024;
export const DEFAULT_MAX_METADATA_BYTES = 1_024;
export const HARD_MAX_METADATA_BYTES = 4_096;
export const DEFAULT_EXPIRY_SWEEP_LIMIT = 100;
export const HARD_MAX_EXPIRY_SWEEP_LIMIT = 1_000;

const CAPTURE_ID_PATTERN = /^[0-9a-f]{32}$/;
const NAMESPACE_ENTRY_PATTERN =
  /^(?:[0-9a-f]{32}\.(?:body|creating|dek|deleted|deleting)|\.tmp-[0-9a-f]{32})$/;
const TEMPORARY_ENTRY_PATTERN = /^\.tmp-[0-9a-f]{32}$/;
const BODY_MAGIC = Buffer.from("RSIBDY02", "ascii");
const DEK_MAGIC = Buffer.from("RSIDEK02", "ascii");
const MARKER_MAGIC = Buffer.from("RSIMRK02", "ascii");
const RECEIPT_MAGIC = Buffer.from("RSIRCP02", "ascii");
const FORMAT_VERSION = 2;
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const BODY_PREFIX_BYTES = BODY_MAGIC.byteLength + 1 + 4 + 4 + NONCE_BYTES;
const DEK_PREFIX_BYTES = DEK_MAGIC.byteLength + 1 + NONCE_BYTES;
const RECORD_PREFIX_BYTES = RECEIPT_MAGIC.byteLength + 1 + 2 + NONCE_BYTES;
const MARKER_PREFIX_BYTES = MARKER_MAGIC.byteLength + 1 + 2 + NONCE_BYTES;
const WRAPPED_DEK_PLAINTEXT_BYTES = 32 + 24 + 24;
const WRAPPED_DEK_FILE_BYTES = DEK_PREFIX_BYTES + WRAPPED_DEK_PLAINTEXT_BYTES + AUTH_TAG_BYTES;
const MAX_RECORD_BYTES = 512;
const MAX_MARKER_BYTES = 128;
const CREATE_MARKER = Buffer.from('{"schemaVersion":1,"state":"creating"}', "ascii");
const BODY_AAD_DOMAIN = Buffer.from("rsi.capture-vault.body.aad.v2\0", "ascii");
const DEK_AAD_DOMAIN = Buffer.from("rsi.capture-vault.dek.aad.v2\0", "ascii");
const CREATE_AAD_DOMAIN = Buffer.from("rsi.capture-vault.creating.aad.v2\0", "ascii");
const DELETE_INTENT_AAD_DOMAIN = Buffer.from("rsi.capture-vault.deleting.aad.v2\0", "ascii");
const DELETE_TOMBSTONE_AAD_DOMAIN = Buffer.from("rsi.capture-vault.deleted.aad.v2\0", "ascii");
const WRAPPING_KDF_SALT = Buffer.from("rsi.capture-vault.hkdf-sha256.salt.v2\0", "ascii");
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const DIRECTORY_FLAG = fsConstants.O_DIRECTORY ?? 0;
const EFFECTIVE_USER_ID =
  typeof process.geteuid === "function" ? BigInt(process.geteuid()) : undefined;
const LINK_SETTLE_ATTEMPTS = 32;
const LINK_SETTLE_DELAY_MS = 1;
const MAX_PENDING_OPERATIONS = 8;
const HARD_MAX_NAMESPACE_ENTRIES = 10_000;
const MIN_METADATA_BYTES = 129;
const OPEN_DIRECTORIES = new Set<string>();
const authenticSnapshotVaults = new WeakSet<object>();
const SNAPSHOT_VAULT_CONSTRUCTION_TOKEN = Object.freeze({});

type ArtifactKind = "body" | "creating" | "dek" | "deleted" | "deleting";
type VaultState = "closed" | "closing" | "open";

interface DirectoryIdentity {
  readonly device: bigint;
  readonly inode: bigint;
}

interface VerifiedCaptureInternal extends CaptureDescriptor {
  readonly metadataBytes: Buffer;
  readonly plaintext: Buffer;
}

interface UnwrappedDek {
  readonly acquiredAt: string;
  readonly dek: Buffer;
  readonly expiresAt: string;
}

class SnapshotLinkSettlingError extends Error {}

export function isCaptureId(value: string): value is CaptureId {
  return CAPTURE_ID_PATTERN.test(value);
}

/**
 * A single-writer encrypted capture store. `SnapshotVault` retains the package's
 * class name, but v2 IDs are random capture handles and are never content addresses.
 */
export class SnapshotVault {
  readonly directory: string;
  readonly maxCaptureBytes: number;
  readonly maxMetadataBytes: number;

  #activeOperations = 0;
  #closePromise: Promise<void> | undefined;
  #directoryHandle: FileHandle;
  #directoryIdentity: DirectoryIdentity;
  #drainOperation: (() => void) | undefined;
  #operationTail: Promise<void> = Promise.resolve();
  #state: VaultState = "open";
  #wrappingKey: Buffer;

  private constructor(
    directory: string,
    wrappingKey: Buffer,
    maxCaptureBytes: number,
    maxMetadataBytes: number,
    directoryHandle: FileHandle,
    directoryIdentity: DirectoryIdentity,
    constructionToken: unknown,
  ) {
    if (constructionToken !== SNAPSHOT_VAULT_CONSTRUCTION_TOKEN) {
      throw new SnapshotIntegrityError();
    }
    this.directory = directory;
    this.#wrappingKey = wrappingKey;
    this.maxCaptureBytes = maxCaptureBytes;
    this.maxMetadataBytes = maxMetadataBytes;
    this.#directoryHandle = directoryHandle;
    this.#directoryIdentity = directoryIdentity;
  }

  static async open(options: SnapshotVaultOptions): Promise<SnapshotVault> {
    const values = safeExactOptionsRecord(
      options,
      ["directory", "maxCaptureBytes", "maxMetadataBytes", "wrappingKey"],
      ["directory", "wrappingKey"],
      "Capture vault options",
    );
    const requestedDirectory = validateDirectory(values.directory as string);
    const maxCaptureBytes = validateLimit(
      values.maxCaptureBytes ?? DEFAULT_MAX_CAPTURE_BYTES,
      1,
      HARD_MAX_CAPTURE_BYTES,
      "capture byte limit",
    );
    const maxMetadataBytes = validateLimit(
      values.maxMetadataBytes ?? DEFAULT_MAX_METADATA_BYTES,
      MIN_METADATA_BYTES,
      HARD_MAX_METADATA_BYTES,
      "metadata byte limit",
    );
    const wrappingKey = copyWrappingKey(values.wrappingKey as Uint8Array);

    let directoryHandle: FileHandle | undefined;
    let registeredDirectory: string | undefined;
    try {
      await mkdir(requestedDirectory, { mode: DIRECTORY_MODE, recursive: true });
      const requestedStats = await lstat(requestedDirectory, { bigint: true });
      if (requestedStats.isSymbolicLink() || !requestedStats.isDirectory()) {
        throw new SnapshotSecurityError();
      }
      const directory = await realpath(requestedDirectory);
      const beforeOpen = await lstat(directory, { bigint: true });
      if (beforeOpen.isSymbolicLink() || !beforeOpen.isDirectory()) {
        throw new SnapshotSecurityError();
      }
      if (OPEN_DIRECTORIES.has(directory)) {
        throw new SnapshotConflictError();
      }
      OPEN_DIRECTORIES.add(directory);
      registeredDirectory = directory;

      directoryHandle = await open(directory, fsConstants.O_RDONLY | DIRECTORY_FLAG | NOFOLLOW);
      const opened = await directoryHandle.stat({ bigint: true });
      if (
        !opened.isDirectory() ||
        opened.dev !== beforeOpen.dev ||
        opened.ino !== beforeOpen.ino ||
        opened.uid !== beforeOpen.uid ||
        (EFFECTIVE_USER_ID !== undefined && opened.uid !== EFFECTIVE_USER_ID) ||
        (opened.mode & 0o777n) !== BigInt(DIRECTORY_MODE)
      ) {
        throw new SnapshotSecurityError();
      }

      const vault = new SnapshotVault(
        directory,
        wrappingKey,
        maxCaptureBytes,
        maxMetadataBytes,
        directoryHandle,
        { device: opened.dev, inode: opened.ino },
        SNAPSHOT_VAULT_CONSTRUCTION_TOKEN,
      );
      await vault.#assertNamespace();
      await directoryHandle.sync();
      authenticSnapshotVaults.add(vault);
      return vault;
    } catch (error) {
      wrappingKey.fill(0);
      if (directoryHandle !== undefined) {
        await directoryHandle.close().catch(() => undefined);
      }
      if (registeredDirectory !== undefined) {
        OPEN_DIRECTORIES.delete(registeredDirectory);
      }
      if (error instanceof SnapshotVaultError) throw error;
      throw new SnapshotSecurityError("Unable to initialize capture vault safely");
    }
  }

  async capture(bytes: Uint8Array, options: CaptureOptions): Promise<CaptureDescriptor> {
    const values = safeExactOptionsRecord(options, ["metadata"], ["metadata"], "Capture options");
    const plaintext = copyCaptureBytes(bytes, this.maxCaptureBytes);
    let metadata: PreparedMetadata | undefined;
    try {
      try {
        metadata = prepareCaptureMetadata(values.metadata, this.maxMetadataBytes);
      } catch (error) {
        if (error instanceof SnapshotValidationError) throw error;
        throw new SnapshotValidationError("Capture metadata is invalid");
      }
      return await this.#runOperation((wrappingKey) =>
        this.#captureInternal(plaintext, metadata!, wrappingKey),
      );
    } finally {
      plaintext.fill(0);
      metadata?.bytes.fill(0);
    }
  }

  async get(captureId: string): Promise<Capture> {
    const validCaptureId = validateCaptureId(captureId);
    return this.#runOperation(async (wrappingKey) => {
      const stored = await this.#readVerified(validCaptureId, wrappingKey);
      try {
        return Object.freeze({
          bytes: new Uint8Array(stored.plaintext),
          captureId: stored.captureId,
          metadata: stored.metadata,
          size: stored.size,
        });
      } finally {
        wipeVerifiedCapture(stored);
      }
    });
  }

  async verify(captureId: string): Promise<CaptureVerification> {
    const validCaptureId = validateCaptureId(captureId);
    return this.#runOperation(async (wrappingKey) => {
      const stored = await this.#readVerified(validCaptureId, wrappingKey);
      try {
        return Object.freeze({
          captureId: stored.captureId,
          metadata: stored.metadata,
          size: stored.size,
          valid: true as const,
        });
      } finally {
        wipeVerifiedCapture(stored);
      }
    });
  }

  async delete(
    captureId: string,
    options: DeleteCaptureOptions,
  ): Promise<CaptureDeletionReceiptV1> {
    const validCaptureId = validateCaptureId(captureId);
    const values = safeExactOptionsRecord(
      options,
      ["deletedAt", "reason"],
      ["deletedAt", "reason"],
      "Capture deletion options",
    );
    const prepared = prepareDeletionReceipt({
      captureId: validCaptureId,
      deletedAt: values.deletedAt,
      keyDestroyed: true,
      reason: values.reason,
      schemaVersion: 1,
      state: "deleted",
    });
    try {
      return await this.#runOperation((wrappingKey) =>
        this.#deleteInternal(validCaptureId, prepared, wrappingKey),
      );
    } finally {
      prepared.bytes.fill(0);
    }
  }

  async sweepExpired(options: SweepExpiredOptions): Promise<CaptureExpirySweepResultV1> {
    const values = safeExactOptionsRecord(
      options,
      ["limit", "now"],
      ["now"],
      "Capture expiry sweep options",
    );
    const now = validateCanonicalTimestamp(values.now, "now");
    const limit = validateLimit(
      values.limit ?? DEFAULT_EXPIRY_SWEEP_LIMIT,
      1,
      HARD_MAX_EXPIRY_SWEEP_LIMIT,
      "expiry sweep limit",
    );
    return this.#runOperation(async (wrappingKey) => {
      await this.#assertNamespace();
      const names = await this.#listNamespace();
      const candidateIds = names
        .filter((name) => name.endsWith(".dek"))
        .map((name) => name.slice(0, -4) as CaptureId)
        .sort();
      const receipts: CaptureDeletionReceiptV1[] = [];
      let examined = 0;
      let truncated = false;

      for (const captureId of candidateIds) {
        if (
          (await this.#artifactExists(captureId, "creating")) ||
          (await this.#artifactExists(captureId, "deleting")) ||
          (await this.#artifactExists(captureId, "deleted"))
        ) {
          throw new SnapshotIntegrityError();
        }
        const envelope = await this.#readRequiredArtifact(
          captureId,
          "dek",
          WRAPPED_DEK_FILE_BYTES,
          WRAPPED_DEK_FILE_BYTES,
        );
        let unwrapped: UnwrappedDek | undefined;
        try {
          unwrapped = unwrapDek(captureId, envelope, wrappingKey);
          examined += 1;
          if (Date.parse(unwrapped.expiresAt) <= Date.parse(now)) {
            if (receipts.length >= limit) {
              truncated = true;
              continue;
            }
            const prepared = prepareDeletionReceipt({
              captureId,
              deletedAt: now,
              keyDestroyed: true,
              reason: "expired",
              schemaVersion: 1,
              state: "deleted",
            });
            try {
              receipts.push(await this.#deleteInternal(captureId, prepared, wrappingKey));
            } finally {
              prepared.bytes.fill(0);
            }
          }
        } finally {
          envelope.fill(0);
          unwrapped?.dek.fill(0);
        }
      }

      return Object.freeze({
        examined,
        receipts: Object.freeze(receipts),
        schemaVersion: 1 as const,
        sweptAt: now,
        truncated,
      });
    });
  }

  async recover(options: RecoverCaptureVaultOptions): Promise<CaptureRecoveryResultV1> {
    const values = safeExactOptionsRecord(
      options,
      ["recoveredAt"],
      ["recoveredAt"],
      "Capture recovery options",
    );
    const recoveredAt = validateCanonicalTimestamp(values.recoveredAt, "recoveredAt");
    return this.#runOperation(async (wrappingKey) => {
      await this.#assertNamespace();
      let names = await this.#listNamespace();
      let removedTemporaryFiles = 0;
      let removedOrphanBodies = 0;
      const resumedDeletionReceipts: CaptureDeletionReceiptV1[] = [];

      for (const name of names.filter((candidate) => TEMPORARY_ENTRY_PATTERN.test(candidate))) {
        if (await this.#removeTemporary(name)) removedTemporaryFiles += 1;
      }

      names = await this.#listNamespace();
      const captureIds = new Set<CaptureId>();
      for (const name of names) {
        const match = /^([0-9a-f]{32})\./.exec(name);
        if (match !== null) captureIds.add(match[1] as CaptureId);
      }

      for (const captureId of [...captureIds].sort()) {
        const creating = await this.#artifactExists(captureId, "creating");
        const deleting = await this.#artifactExists(captureId, "deleting");
        const deleted = await this.#artifactExists(captureId, "deleted");

        if (creating) {
          if (deleting || deleted) throw new SnapshotIntegrityError();
          await this.#readCreatingMarker(captureId, wrappingKey);
          if (await this.#artifactExists(captureId, "dek")) {
            await this.#authenticateAndRemoveDek(captureId, wrappingKey);
          }
          if (await this.#removeArtifact(captureId, "body")) removedOrphanBodies += 1;
          await this.#removeArtifact(captureId, "creating", (envelope) => {
            decryptCreatingMarker(captureId, envelope, wrappingKey);
          });
          continue;
        }

        if (deleted) {
          const tombstone = await this.#readReceipt(captureId, "deleted", wrappingKey);
          try {
            if (await this.#artifactExists(captureId, "dek")) {
              await this.#authenticateAndRemoveDek(captureId, wrappingKey);
            }
            await this.#removeArtifact(captureId, "body");
            if (deleting) {
              const intent = await this.#readReceipt(captureId, "deleting", wrappingKey);
              try {
                if (!intent.bytes.equals(tombstone.bytes)) throw new SnapshotIntegrityError();
              } finally {
                intent.bytes.fill(0);
              }
              await this.#removeArtifact(captureId, "deleting", (envelope) => {
                const plaintext = decryptReceiptEnvelope(
                  captureId,
                  envelope,
                  wrappingKey,
                  DELETE_INTENT_AAD_DOMAIN,
                );
                plaintext.fill(0);
              });
            }
          } finally {
            tombstone.bytes.fill(0);
          }
          continue;
        }

        if (deleting) {
          const intent = await this.#readReceipt(captureId, "deleting", wrappingKey);
          try {
            resumedDeletionReceipts.push(
              await this.#completeDeletion(captureId, intent, wrappingKey),
            );
          } finally {
            intent.bytes.fill(0);
          }
          continue;
        }

        const hasBody = await this.#artifactExists(captureId, "body");
        const hasDek = await this.#artifactExists(captureId, "dek");
        if (hasBody && !hasDek) {
          if (await this.#removeArtifact(captureId, "body")) removedOrphanBodies += 1;
          continue;
        }
        if (!hasBody && hasDek) throw new SnapshotIntegrityError();
        if (hasBody && hasDek) {
          const verified = await this.#readVerified(captureId, wrappingKey);
          wipeVerifiedCapture(verified);
        }
      }

      await this.#assertNamespace();
      return Object.freeze({
        recoveredAt,
        removedOrphanBodies,
        removedTemporaryFiles,
        resumedDeletionReceipts: Object.freeze(resumedDeletionReceipts),
        schemaVersion: 1 as const,
      });
    });
  }

  async reconcileRegisteredCaptures(
    options: ReconcileRegisteredCapturesOptions,
  ): Promise<CaptureReconciliationResultV1> {
    const values = safeExactOptionsRecord(
      options,
      ["limit", "reconciledAt", "registeredCaptureIds"],
      ["reconciledAt", "registeredCaptureIds"],
      "Capture reconciliation options",
    );
    const reconciledAt = validateCanonicalTimestamp(values.reconciledAt, "reconciledAt");
    const limit = validateLimit(
      values.limit ?? DEFAULT_EXPIRY_SWEEP_LIMIT,
      1,
      HARD_MAX_EXPIRY_SWEEP_LIMIT,
      "capture reconciliation limit",
    );
    const registeredCaptureIds = validateRegisteredCaptureIds(values.registeredCaptureIds);

    return this.#runOperation(async (wrappingKey) => {
      await this.#assertNamespace();
      const names = await this.#listNamespace();
      const activeCaptureIds = names
        .filter((name) => name.endsWith(".dek"))
        .map((name) => name.slice(0, -4) as CaptureId)
        .sort();
      const activeSet = new Set(activeCaptureIds);

      // Validate the complete registry side before mutating any orphan. A missing
      // registered capture is an integrity failure, never a cleanup instruction.
      for (const captureId of registeredCaptureIds) {
        if (!activeSet.has(captureId)) throw new SnapshotIntegrityError();
        const verified = await this.#readVerified(captureId, wrappingKey);
        wipeVerifiedCapture(verified);
      }

      const registeredSet = new Set(registeredCaptureIds);
      const orphanCaptureIds = activeCaptureIds.filter(
        (captureId) => !registeredSet.has(captureId),
      );
      // Authenticate and time-check every orphan before deleting the first one.
      // This keeps a rejected reconciliation from partially mutating the vault,
      // even when the bounded deletion batch would not reach a later invalid ID.
      for (const captureId of orphanCaptureIds) {
        const verified = await this.#readVerified(captureId, wrappingKey);
        try {
          if (Date.parse(reconciledAt) < Date.parse(verified.metadata.acquiredAt)) {
            throw new SnapshotValidationError(
              "Capture reconciledAt must not precede any orphan acquisition",
            );
          }
        } finally {
          wipeVerifiedCapture(verified);
        }
      }
      const selectedOrphans = orphanCaptureIds.slice(0, limit);
      for (const captureId of selectedOrphans) {
        const prepared = prepareDeletionReceipt({
          captureId,
          deletedAt: reconciledAt,
          keyDestroyed: true,
          reason: "explicit",
          schemaVersion: 1,
          state: "deleted",
        });
        try {
          await this.#deleteInternal(captureId, prepared, wrappingKey);
        } finally {
          prepared.bytes.fill(0);
        }
      }

      await this.#assertNamespace();
      return Object.freeze({
        examined: activeCaptureIds.length,
        reconciledAt,
        removedOrphanCaptures: selectedOrphans.length,
        retainedRegisteredCaptures: registeredCaptureIds.length,
        schemaVersion: 1 as const,
        truncated: orphanCaptureIds.length > selectedOrphans.length,
      });
    });
  }

  close(): Promise<void> {
    this.#assertAuthentic();
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#state = "closing";
    this.#wrappingKey.fill(0);
    this.#closePromise = this.#finishClose();
    return this.#closePromise;
  }

  async #captureInternal(
    plaintext: Buffer,
    metadata: PreparedMetadata,
    wrappingKey: Buffer,
  ): Promise<CaptureDescriptor> {
    await this.#assertNamespace();
    const captureId = await this.#newCaptureId();
    const dek = randomBytes(32);
    let bodyEnvelope: Buffer | undefined;
    let dekEnvelope: Buffer | undefined;
    let creatingEnvelope: Buffer | undefined;
    let creatingPublished = false;
    try {
      creatingEnvelope = encryptCreatingMarker(captureId, wrappingKey);
      bodyEnvelope = encryptBody(captureId, plaintext, metadata.bytes, dek);
      dekEnvelope = wrapDek(captureId, dek, metadata.value, wrappingKey);

      if (
        !(await this.#publishExclusive(this.#artifactPath(captureId, "creating"), creatingEnvelope))
      ) {
        throw new SnapshotSecurityError();
      }
      creatingPublished = true;
      if (!(await this.#publishExclusive(this.#artifactPath(captureId, "body"), bodyEnvelope))) {
        throw new SnapshotSecurityError();
      }
      if (!(await this.#publishExclusive(this.#artifactPath(captureId, "dek"), dekEnvelope))) {
        throw new SnapshotSecurityError();
      }
      await this.#removeArtifact(captureId, "creating", (envelope) => {
        decryptCreatingMarker(captureId, envelope, wrappingKey);
      });
      creatingPublished = false;
      await this.#assertNamespace();
      return Object.freeze({
        captureId,
        metadata: metadata.value,
        size: plaintext.byteLength,
      });
    } catch (error) {
      if (creatingPublished) {
        await this.#discardCreatingCapture(captureId, wrappingKey).catch(() => undefined);
      }
      if (error instanceof SnapshotVaultError) throw error;
      throw new SnapshotSecurityError("Unable to publish capture safely");
    } finally {
      dek.fill(0);
      bodyEnvelope?.fill(0);
      dekEnvelope?.fill(0);
      creatingEnvelope?.fill(0);
    }
  }

  async #deleteInternal(
    captureId: CaptureId,
    requestedReceipt: PreparedDeletionReceipt,
    wrappingKey: Buffer,
  ): Promise<CaptureDeletionReceiptV1> {
    await this.#assertNamespace();
    const existingTombstone = await this.#readOptionalReceipt(captureId, "deleted", wrappingKey);
    if (existingTombstone !== undefined) {
      try {
        if (await this.#artifactExists(captureId, "dek")) {
          await this.#authenticateAndRemoveDek(captureId, wrappingKey);
        }
        await this.#removeArtifact(captureId, "body");
        const lingeringIntent = await this.#readOptionalReceipt(captureId, "deleting", wrappingKey);
        if (lingeringIntent !== undefined) {
          try {
            if (!lingeringIntent.bytes.equals(existingTombstone.bytes)) {
              throw new SnapshotIntegrityError();
            }
          } finally {
            lingeringIntent.bytes.fill(0);
          }
          await this.#removeArtifact(captureId, "deleting", (envelope) => {
            const plaintext = decryptReceiptEnvelope(
              captureId,
              envelope,
              wrappingKey,
              DELETE_INTENT_AAD_DOMAIN,
            );
            plaintext.fill(0);
          });
        }
        return existingTombstone.value;
      } finally {
        existingTombstone.bytes.fill(0);
      }
    }

    let intent = await this.#readOptionalReceipt(captureId, "deleting", wrappingKey);
    if (intent === undefined) {
      const verified = await this.#readVerified(captureId, wrappingKey);
      try {
        if (
          Date.parse(requestedReceipt.value.deletedAt) < Date.parse(verified.metadata.acquiredAt)
        ) {
          throw new SnapshotValidationError("Capture deletedAt must not precede acquiredAt");
        }
      } finally {
        wipeVerifiedCapture(verified);
      }
      const envelope = encryptReceiptEnvelope(
        captureId,
        requestedReceipt.bytes,
        wrappingKey,
        DELETE_INTENT_AAD_DOMAIN,
      );
      try {
        if (!(await this.#publishExclusive(this.#artifactPath(captureId, "deleting"), envelope))) {
          intent = await this.#readReceipt(captureId, "deleting", wrappingKey);
        } else {
          intent = {
            bytes: Buffer.from(requestedReceipt.bytes),
            value: requestedReceipt.value,
          };
        }
      } finally {
        envelope.fill(0);
      }
    }

    try {
      return await this.#completeDeletion(captureId, intent, wrappingKey);
    } finally {
      intent.bytes.fill(0);
    }
  }

  async #completeDeletion(
    captureId: CaptureId,
    receipt: PreparedDeletionReceipt,
    wrappingKey: Buffer,
  ): Promise<CaptureDeletionReceiptV1> {
    if (await this.#artifactExists(captureId, "dek")) {
      await this.#authenticateAndRemoveDek(captureId, wrappingKey);
    }

    const tombstoneEnvelope = encryptReceiptEnvelope(
      captureId,
      receipt.bytes,
      wrappingKey,
      DELETE_TOMBSTONE_AAD_DOMAIN,
    );
    try {
      const created = await this.#publishExclusive(
        this.#artifactPath(captureId, "deleted"),
        tombstoneEnvelope,
      );
      if (!created) {
        const existing = await this.#readReceipt(captureId, "deleted", wrappingKey);
        try {
          if (!existing.bytes.equals(receipt.bytes)) throw new SnapshotIntegrityError();
        } finally {
          existing.bytes.fill(0);
        }
      }
    } finally {
      tombstoneEnvelope.fill(0);
    }

    await this.#removeArtifact(captureId, "body");
    await this.#removeArtifact(captureId, "deleting", (envelope) => {
      const decrypted = decryptReceiptEnvelope(
        captureId,
        envelope,
        wrappingKey,
        DELETE_INTENT_AAD_DOMAIN,
      );
      decrypted.fill(0);
    });
    await this.#assertNamespace();
    return receipt.value;
  }

  async #discardCreatingCapture(captureId: CaptureId, wrappingKey: Buffer): Promise<void> {
    if (await this.#artifactExists(captureId, "creating")) {
      await this.#readCreatingMarker(captureId, wrappingKey);
      if (await this.#artifactExists(captureId, "dek")) {
        await this.#authenticateAndRemoveDek(captureId, wrappingKey);
      }
      await this.#removeArtifact(captureId, "body");
      await this.#removeArtifact(captureId, "creating", (envelope) => {
        decryptCreatingMarker(captureId, envelope, wrappingKey);
      });
    }
  }

  async #authenticateAndRemoveDek(captureId: CaptureId, wrappingKey: Buffer): Promise<void> {
    const envelope = await this.#readRequiredArtifact(
      captureId,
      "dek",
      WRAPPED_DEK_FILE_BYTES,
      WRAPPED_DEK_FILE_BYTES,
    );
    let unwrapped: UnwrappedDek | undefined;
    try {
      unwrapped = unwrapDek(captureId, envelope, wrappingKey);
    } finally {
      unwrapped?.dek.fill(0);
      envelope.fill(0);
    }
    await this.#removeArtifact(captureId, "dek", (candidate) => {
      const verified = unwrapDek(captureId, candidate, wrappingKey);
      verified.dek.fill(0);
    });
  }

  async #readVerified(captureId: CaptureId, wrappingKey: Buffer): Promise<VerifiedCaptureInternal> {
    await this.#assertNamespace();
    if (await this.#artifactExists(captureId, "creating")) {
      await this.#readCreatingMarker(captureId, wrappingKey);
      throw new SnapshotNotFoundError();
    }
    const deleting = await this.#readOptionalReceipt(captureId, "deleting", wrappingKey);
    if (deleting !== undefined) {
      deleting.bytes.fill(0);
      throw new SnapshotNotFoundError();
    }
    const deleted = await this.#readOptionalReceipt(captureId, "deleted", wrappingKey);
    if (deleted !== undefined) {
      deleted.bytes.fill(0);
      throw new SnapshotNotFoundError();
    }

    const dekEnvelope = await this.#readRequiredArtifact(
      captureId,
      "dek",
      WRAPPED_DEK_FILE_BYTES,
      WRAPPED_DEK_FILE_BYTES,
    );
    let unwrapped: UnwrappedDek | undefined;
    let bodyEnvelope: Buffer | undefined;
    try {
      unwrapped = unwrapDek(captureId, dekEnvelope, wrappingKey);
      try {
        bodyEnvelope = await this.#readRequiredArtifact(
          captureId,
          "body",
          BODY_PREFIX_BYTES + AUTH_TAG_BYTES + 2,
          BODY_PREFIX_BYTES + AUTH_TAG_BYTES + this.maxMetadataBytes + this.maxCaptureBytes,
        );
      } catch (error) {
        if (error instanceof SnapshotNotFoundError) throw new SnapshotIntegrityError();
        throw error;
      }
      const verified = decryptBody(
        captureId,
        bodyEnvelope,
        unwrapped.dek,
        this.maxCaptureBytes,
        this.maxMetadataBytes,
      );
      if (
        verified.metadata.acquiredAt !== unwrapped.acquiredAt ||
        verified.metadata.expiresAt !== unwrapped.expiresAt
      ) {
        wipeVerifiedCapture(verified);
        throw new SnapshotIntegrityError();
      }
      return verified;
    } finally {
      dekEnvelope.fill(0);
      bodyEnvelope?.fill(0);
      unwrapped?.dek.fill(0);
    }
  }

  async #readCreatingMarker(captureId: CaptureId, wrappingKey: Buffer): Promise<void> {
    const envelope = await this.#readRequiredArtifact(
      captureId,
      "creating",
      MARKER_PREFIX_BYTES + AUTH_TAG_BYTES + 2,
      MAX_MARKER_BYTES,
    );
    try {
      decryptCreatingMarker(captureId, envelope, wrappingKey);
    } finally {
      envelope.fill(0);
    }
  }

  async #readOptionalReceipt(
    captureId: CaptureId,
    kind: "deleted" | "deleting",
    wrappingKey: Buffer,
  ): Promise<PreparedDeletionReceipt | undefined> {
    const envelope = await this.#readOptionalArtifact(
      captureId,
      kind,
      RECORD_PREFIX_BYTES + AUTH_TAG_BYTES + 2,
      MAX_RECORD_BYTES,
    );
    if (envelope === undefined) return undefined;
    try {
      const plaintext = decryptReceiptEnvelope(
        captureId,
        envelope,
        wrappingKey,
        kind === "deleted" ? DELETE_TOMBSTONE_AAD_DOMAIN : DELETE_INTENT_AAD_DOMAIN,
      );
      try {
        return decodeDeletionReceipt(plaintext, captureId);
      } finally {
        plaintext.fill(0);
      }
    } finally {
      envelope.fill(0);
    }
  }

  async #readReceipt(
    captureId: CaptureId,
    kind: "deleted" | "deleting",
    wrappingKey: Buffer,
  ): Promise<PreparedDeletionReceipt> {
    const receipt = await this.#readOptionalReceipt(captureId, kind, wrappingKey);
    if (receipt === undefined) throw new SnapshotNotFoundError();
    return receipt;
  }

  async #newCaptureId(): Promise<CaptureId> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const captureId = randomBytes(16).toString("hex") as CaptureId;
      let occupied = false;
      for (const kind of ["body", "creating", "dek", "deleted", "deleting"] as const) {
        if (await this.#artifactExists(captureId, kind)) {
          occupied = true;
          break;
        }
      }
      if (!occupied) return captureId;
    }
    throw new SnapshotSecurityError("Unable to allocate an opaque capture ID safely");
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

  async #assertNamespace(): Promise<void> {
    await this.#assertDirectoryIdentity();
    const entries = await readdir(this.directory, { withFileTypes: true });
    if (entries.length > HARD_MAX_NAMESPACE_ENTRIES) throw new SnapshotSecurityError();
    for (const entry of entries) {
      if (!NAMESPACE_ENTRY_PATTERN.test(entry.name) || !entry.isFile()) {
        throw new SnapshotSecurityError();
      }
    }
    await this.#assertDirectoryIdentity();
  }

  async #listNamespace(): Promise<string[]> {
    await this.#assertDirectoryIdentity();
    const names = await readdir(this.directory);
    if (names.length > HARD_MAX_NAMESPACE_ENTRIES) throw new SnapshotSecurityError();
    if (names.some((name) => !NAMESPACE_ENTRY_PATTERN.test(name))) {
      throw new SnapshotSecurityError();
    }
    await this.#assertDirectoryIdentity();
    return names.sort();
  }

  async #artifactExists(captureId: CaptureId, kind: ArtifactKind): Promise<boolean> {
    const path = this.#artifactPath(captureId, kind);
    try {
      const stats = await lstat(path, { bigint: true });
      validateFileStats(stats);
      assertSettledLinkCount(stats.nlink);
      return true;
    } catch (error) {
      if (isErrorCode(error, "ENOENT")) return false;
      if (error instanceof SnapshotLinkSettlingError) {
        return this.#waitForSettledArtifact(captureId, kind);
      }
      if (error instanceof SnapshotVaultError) throw error;
      throw new SnapshotSecurityError();
    }
  }

  async #waitForSettledArtifact(captureId: CaptureId, kind: ArtifactKind): Promise<boolean> {
    for (let attempt = 0; attempt < LINK_SETTLE_ATTEMPTS; attempt += 1) {
      await shortDelay();
      try {
        const stats = await lstat(this.#artifactPath(captureId, kind), { bigint: true });
        validateFileStats(stats);
        if (stats.nlink === 1n) return true;
        if (stats.nlink > 2n) throw new SnapshotSecurityError();
      } catch (error) {
        if (isErrorCode(error, "ENOENT")) return false;
        if (error instanceof SnapshotVaultError) throw error;
        throw new SnapshotSecurityError();
      }
    }
    throw new SnapshotSecurityError();
  }

  async #publishExclusive(path: string, envelope: Buffer): Promise<boolean> {
    await this.#assertDirectoryIdentity();
    let temporaryPath: string | undefined;
    let temporaryHandle: FileHandle | undefined;
    try {
      for (let attempt = 0; attempt < 4; attempt += 1) {
        temporaryPath = join(this.directory, `.tmp-${randomBytes(16).toString("hex")}`);
        if (dirname(temporaryPath) !== this.directory) throw new SnapshotSecurityError();
        try {
          temporaryHandle = await open(
            temporaryPath,
            fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NOFOLLOW,
            FILE_MODE,
          );
          break;
        } catch (error) {
          if (!isErrorCode(error, "EEXIST") || attempt === 3) throw error;
        }
      }
      if (temporaryHandle === undefined || temporaryPath === undefined) {
        throw new SnapshotSecurityError();
      }
      await writeAll(temporaryHandle, envelope);
      await temporaryHandle.sync();
      const written = await temporaryHandle.stat({ bigint: true });
      validateFileStats(written);
      if (written.nlink !== 1n || written.size !== BigInt(envelope.byteLength)) {
        throw new SnapshotSecurityError();
      }
      await temporaryHandle.close();
      temporaryHandle = undefined;

      let created = true;
      try {
        await link(temporaryPath, path);
      } catch (error) {
        if (!isErrorCode(error, "EEXIST")) throw error;
        created = false;
      }
      await unlink(temporaryPath);
      temporaryPath = undefined;
      await this.#directoryHandle.sync();
      await this.#assertDirectoryIdentity();
      return created;
    } catch (error) {
      await temporaryHandle?.close().catch(() => undefined);
      if (temporaryPath !== undefined) await unlink(temporaryPath).catch(() => undefined);
      if (error instanceof SnapshotVaultError) throw error;
      throw new SnapshotSecurityError("Unable to publish capture artifact safely");
    }
  }

  async #readRequiredArtifact(
    captureId: CaptureId,
    kind: ArtifactKind,
    minimumBytes: number,
    maximumBytes: number,
  ): Promise<Buffer> {
    const bytes = await this.#readOptionalArtifact(captureId, kind, minimumBytes, maximumBytes);
    if (bytes === undefined) throw new SnapshotNotFoundError();
    return bytes;
  }

  async #readOptionalArtifact(
    captureId: CaptureId,
    kind: ArtifactKind,
    minimumBytes: number,
    maximumBytes: number,
  ): Promise<Buffer | undefined> {
    for (let attempt = 0; attempt < LINK_SETTLE_ATTEMPTS; attempt += 1) {
      try {
        return await this.#readOptionalFileOnce(
          this.#artifactPath(captureId, kind),
          minimumBytes,
          maximumBytes,
        );
      } catch (error) {
        if (!(error instanceof SnapshotLinkSettlingError)) throw error;
        if (attempt === LINK_SETTLE_ATTEMPTS - 1) throw new SnapshotSecurityError();
        await shortDelay();
      }
    }
    throw new SnapshotSecurityError();
  }

  async #readOptionalFileOnce(
    path: string,
    minimumBytes: number,
    maximumBytes: number,
  ): Promise<Buffer | undefined> {
    await this.#assertDirectoryIdentity();
    let beforeOpen;
    try {
      beforeOpen = await lstat(path, { bigint: true });
    } catch (error) {
      if (isErrorCode(error, "ENOENT")) return undefined;
      throw new SnapshotSecurityError();
    }
    validateFileStats(beforeOpen);
    assertSettledLinkCount(beforeOpen.nlink);

    let handle: FileHandle;
    try {
      handle = await open(path, fsConstants.O_RDONLY | NOFOLLOW);
    } catch (error) {
      if (isErrorCode(error, "ENOENT")) return undefined;
      throw new SnapshotSecurityError();
    }
    try {
      const opened = await handle.stat({ bigint: true });
      validateFileStats(opened);
      assertSameFile(opened, beforeOpen);
      assertSettledLinkCount(opened.nlink);
      if (opened.size < BigInt(minimumBytes) || opened.size > BigInt(maximumBytes)) {
        throw new SnapshotIntegrityError();
      }
      const bytes = Buffer.alloc(Number(opened.size));
      try {
        await readAll(handle, bytes);
        const trailing = Buffer.allocUnsafe(1);
        const trailingRead = await handle.read(trailing, 0, 1, bytes.byteLength);
        const afterRead = await handle.stat({ bigint: true });
        validateFileStats(afterRead);
        assertSameFile(afterRead, opened);
        assertSettledLinkCount(afterRead.nlink);
        if (trailingRead.bytesRead !== 0 || afterRead.size !== opened.size) {
          throw new SnapshotIntegrityError();
        }
        return bytes;
      } catch (error) {
        bytes.fill(0);
        throw error;
      }
    } catch (error) {
      if (error instanceof SnapshotVaultError || error instanceof SnapshotLinkSettlingError) {
        throw error;
      }
      throw new SnapshotIntegrityError();
    } finally {
      await handle.close().catch(() => undefined);
      await this.#assertDirectoryIdentity();
    }
  }

  async #removeArtifact(
    captureId: CaptureId,
    kind: ArtifactKind,
    verify?: (bytes: Buffer) => void,
  ): Promise<boolean> {
    const path = this.#artifactPath(captureId, kind);
    if (verify !== undefined) {
      const maximum =
        kind === "dek"
          ? WRAPPED_DEK_FILE_BYTES
          : kind === "creating"
            ? MAX_MARKER_BYTES
            : kind === "deleted" || kind === "deleting"
              ? MAX_RECORD_BYTES
              : BODY_PREFIX_BYTES + AUTH_TAG_BYTES + this.maxMetadataBytes + this.maxCaptureBytes;
      const bytes = await this.#readOptionalFileOnce(path, 1, maximum);
      if (bytes === undefined) return false;
      try {
        verify(bytes);
      } finally {
        bytes.fill(0);
      }
    } else {
      try {
        const stats = await lstat(path, { bigint: true });
        validateFileStats(stats);
        assertSettledLinkCount(stats.nlink);
      } catch (error) {
        if (isErrorCode(error, "ENOENT")) return false;
        if (error instanceof SnapshotVaultError) throw error;
        throw new SnapshotSecurityError();
      }
    }
    await this.#unlinkValidatedPath(path);
    return true;
  }

  async #removeTemporary(name: string): Promise<boolean> {
    if (!TEMPORARY_ENTRY_PATTERN.test(name)) throw new SnapshotSecurityError();
    const path = join(this.directory, name);
    if (dirname(path) !== this.directory) throw new SnapshotSecurityError();
    let linkCount: bigint;
    let temporaryStats;
    try {
      temporaryStats = await lstat(path, { bigint: true });
      validateFileStats(temporaryStats);
      linkCount = temporaryStats.nlink;
      if (linkCount !== 1n && linkCount !== 2n) throw new SnapshotSecurityError();
    } catch (error) {
      if (isErrorCode(error, "ENOENT")) return false;
      if (error instanceof SnapshotVaultError) throw error;
      throw new SnapshotSecurityError();
    }

    if (linkCount === 2n) {
      let inVaultSiblingCount = 0;
      for (const candidate of await this.#listNamespace()) {
        if (candidate === name || TEMPORARY_ENTRY_PATTERN.test(candidate)) continue;
        const candidateStats = await lstat(join(this.directory, candidate), { bigint: true });
        validateFileStats(candidateStats);
        if (
          candidateStats.dev === temporaryStats.dev &&
          candidateStats.ino === temporaryStats.ino
        ) {
          inVaultSiblingCount += 1;
        }
      }
      if (inVaultSiblingCount !== 1) throw new SnapshotSecurityError();
    }

    await this.#unlinkValidatedPath(path, linkCount, linkCount - 1n);
    return true;
  }

  async #unlinkValidatedPath(
    path: string,
    expectedLinksBefore = 1n,
    expectedLinksAfter = 0n,
  ): Promise<void> {
    await this.#assertDirectoryIdentity();
    const beforeOpen = await lstat(path, { bigint: true }).catch((error: unknown) => {
      if (isErrorCode(error, "ENOENT")) throw new SnapshotNotFoundError();
      throw new SnapshotSecurityError();
    });
    validateFileStats(beforeOpen);
    if (beforeOpen.nlink !== expectedLinksBefore) throw new SnapshotSecurityError();

    const handle = await open(path, fsConstants.O_RDONLY | NOFOLLOW).catch(() => {
      throw new SnapshotSecurityError();
    });
    try {
      const opened = await handle.stat({ bigint: true });
      validateFileStats(opened);
      assertSameFile(opened, beforeOpen);
      if (opened.nlink !== expectedLinksBefore) throw new SnapshotSecurityError();
      const beforeUnlink = await lstat(path, { bigint: true });
      validateFileStats(beforeUnlink);
      assertSameFile(beforeUnlink, opened);
      if (beforeUnlink.nlink !== expectedLinksBefore) throw new SnapshotSecurityError();
      await unlink(path);
      const afterUnlink = await handle.stat({ bigint: true });
      assertSameFile(afterUnlink, opened);
      if (afterUnlink.nlink !== expectedLinksAfter) throw new SnapshotSecurityError();
      await this.#directoryHandle.sync();
      await this.#assertDirectoryIdentity();
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  #artifactPath(captureId: CaptureId, kind: ArtifactKind): string {
    const path = join(this.directory, `${captureId}.${kind}`);
    if (dirname(path) !== this.directory) throw new SnapshotSecurityError();
    return path;
  }

  async #runOperation<T>(operation: (wrappingKey: Buffer) => Promise<T>): Promise<T> {
    const wrappingKey = this.#beginOperation();
    const previous = this.#operationTail;
    let release!: () => void;
    this.#operationTail = new Promise<void>((resolveRelease) => {
      release = resolveRelease;
    });
    try {
      await previous;
      return await operation(wrappingKey);
    } finally {
      wrappingKey.fill(0);
      release();
      this.#endOperation();
    }
  }

  #beginOperation(): Buffer {
    this.#assertAuthentic();
    if (this.#state !== "open") throw new SnapshotVaultClosedError();
    if (this.#activeOperations >= MAX_PENDING_OPERATIONS) {
      throw new SnapshotSecurityError("Capture vault operation queue limit reached");
    }
    const wrappingKey = Buffer.from(this.#wrappingKey);
    this.#activeOperations += 1;
    return wrappingKey;
  }

  #endOperation(): void {
    this.#activeOperations -= 1;
    if (this.#activeOperations === 0 && this.#drainOperation !== undefined) {
      const resolveDrain = this.#drainOperation;
      this.#drainOperation = undefined;
      resolveDrain();
    }
  }

  #assertAuthentic(): void {
    if (
      Object.getPrototypeOf(this) !== SnapshotVault.prototype ||
      !authenticSnapshotVaults.has(this)
    ) {
      throw new SnapshotIntegrityError();
    }
  }

  async #finishClose(): Promise<void> {
    if (this.#activeOperations > 0) {
      await new Promise<void>((resolveDrain) => {
        this.#drainOperation = resolveDrain;
      });
    }
    try {
      await this.#directoryHandle.sync().catch(() => undefined);
      await this.#directoryHandle.close().catch(() => undefined);
    } finally {
      this.#state = "closed";
      OPEN_DIRECTORIES.delete(this.directory);
    }
  }
}

function encryptBody(
  captureId: CaptureId,
  plaintext: Buffer,
  metadata: Buffer,
  dek: Buffer,
): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const prefix = Buffer.alloc(BODY_PREFIX_BYTES);
  BODY_MAGIC.copy(prefix, 0);
  prefix.writeUInt8(FORMAT_VERSION, BODY_MAGIC.byteLength);
  prefix.writeUInt32BE(plaintext.byteLength, BODY_MAGIC.byteLength + 1);
  prefix.writeUInt32BE(metadata.byteLength, BODY_MAGIC.byteLength + 5);
  nonce.copy(prefix, BODY_MAGIC.byteLength + 9);
  const payload = Buffer.concat([metadata, plaintext]);
  try {
    return Buffer.concat([
      prefix,
      encryptAesGcm(payload, dek, nonce, makeAad(BODY_AAD_DOMAIN, captureId, prefix)),
    ]);
  } finally {
    payload.fill(0);
  }
}

function decryptBody(
  captureId: CaptureId,
  envelope: Buffer,
  dek: Buffer,
  maxCaptureBytes: number,
  maxMetadataBytes: number,
): VerifiedCaptureInternal {
  let decrypted: Buffer | undefined;
  let metadata: PreparedMetadata | undefined;
  let plaintext: Buffer | undefined;
  try {
    assertMagicAndVersion(envelope, BODY_MAGIC);
    const captureBytes = envelope.readUInt32BE(BODY_MAGIC.byteLength + 1);
    const metadataBytes = envelope.readUInt32BE(BODY_MAGIC.byteLength + 5);
    if (
      captureBytes > maxCaptureBytes ||
      metadataBytes < 2 ||
      metadataBytes > maxMetadataBytes ||
      envelope.byteLength !== BODY_PREFIX_BYTES + metadataBytes + captureBytes + AUTH_TAG_BYTES
    ) {
      throw new SnapshotIntegrityError();
    }
    const prefix = envelope.subarray(0, BODY_PREFIX_BYTES);
    const nonce = prefix.subarray(BODY_MAGIC.byteLength + 9);
    decrypted = decryptAesGcm(
      envelope.subarray(BODY_PREFIX_BYTES),
      dek,
      nonce,
      makeAad(BODY_AAD_DOMAIN, captureId, prefix),
    );
    if (decrypted.byteLength !== metadataBytes + captureBytes) {
      throw new SnapshotIntegrityError();
    }
    metadata = decodeMetadata(decrypted.subarray(0, metadataBytes), maxMetadataBytes);
    plaintext = Buffer.from(decrypted.subarray(metadataBytes));
    const result: VerifiedCaptureInternal = {
      captureId,
      metadata: metadata.value,
      metadataBytes: metadata.bytes,
      plaintext,
      size: captureBytes,
    };
    metadata = undefined;
    plaintext = undefined;
    return result;
  } catch {
    throw new SnapshotIntegrityError();
  } finally {
    decrypted?.fill(0);
    metadata?.bytes.fill(0);
    plaintext?.fill(0);
  }
}

function wrapDek(
  captureId: CaptureId,
  dek: Buffer,
  metadata: CaptureDescriptor["metadata"],
  wrappingKey: Buffer,
): Buffer {
  const subkey = deriveWrappingSubkey(wrappingKey, DEK_AAD_DOMAIN);
  const nonce = randomBytes(NONCE_BYTES);
  const prefix = Buffer.alloc(DEK_PREFIX_BYTES);
  DEK_MAGIC.copy(prefix, 0);
  prefix.writeUInt8(FORMAT_VERSION, DEK_MAGIC.byteLength);
  nonce.copy(prefix, DEK_MAGIC.byteLength + 1);
  const payload = Buffer.alloc(WRAPPED_DEK_PLAINTEXT_BYTES);
  dek.copy(payload, 0);
  payload.write(metadata.acquiredAt, 32, 24, "ascii");
  payload.write(metadata.expiresAt, 56, 24, "ascii");
  try {
    return Buffer.concat([
      prefix,
      encryptAesGcm(payload, subkey, nonce, makeAad(DEK_AAD_DOMAIN, captureId, prefix)),
    ]);
  } finally {
    payload.fill(0);
    subkey.fill(0);
  }
}

function unwrapDek(captureId: CaptureId, envelope: Buffer, wrappingKey: Buffer): UnwrappedDek {
  const subkey = deriveWrappingSubkey(wrappingKey, DEK_AAD_DOMAIN);
  let payload: Buffer | undefined;
  let dek: Buffer | undefined;
  try {
    if (envelope.byteLength !== WRAPPED_DEK_FILE_BYTES) throw new SnapshotIntegrityError();
    assertMagicAndVersion(envelope, DEK_MAGIC);
    const prefix = envelope.subarray(0, DEK_PREFIX_BYTES);
    const nonce = prefix.subarray(DEK_MAGIC.byteLength + 1);
    payload = decryptAesGcm(
      envelope.subarray(DEK_PREFIX_BYTES),
      subkey,
      nonce,
      makeAad(DEK_AAD_DOMAIN, captureId, prefix),
    );
    if (payload.byteLength !== WRAPPED_DEK_PLAINTEXT_BYTES) throw new SnapshotIntegrityError();
    dek = Buffer.from(payload.subarray(0, 32));
    const acquiredAt = validateCanonicalTimestamp(payload.toString("ascii", 32, 56), "acquiredAt");
    const expiresAt = validateCanonicalTimestamp(payload.toString("ascii", 56, 80), "expiresAt");
    if (Date.parse(expiresAt) < Date.parse(acquiredAt)) throw new SnapshotIntegrityError();
    const result = { acquiredAt, dek, expiresAt };
    dek = undefined;
    return result;
  } catch {
    throw new SnapshotIntegrityError();
  } finally {
    payload?.fill(0);
    dek?.fill(0);
    subkey.fill(0);
  }
}

function encryptCreatingMarker(captureId: CaptureId, wrappingKey: Buffer): Buffer {
  return encryptSmallRecord(captureId, CREATE_MARKER, wrappingKey, MARKER_MAGIC, CREATE_AAD_DOMAIN);
}

function decryptCreatingMarker(captureId: CaptureId, envelope: Buffer, wrappingKey: Buffer): void {
  const plaintext = decryptSmallRecord(
    captureId,
    envelope,
    wrappingKey,
    MARKER_MAGIC,
    CREATE_AAD_DOMAIN,
    MARKER_PREFIX_BYTES,
    MAX_MARKER_BYTES,
  );
  try {
    if (!plaintext.equals(CREATE_MARKER)) throw new SnapshotIntegrityError();
  } finally {
    plaintext.fill(0);
  }
}

function encryptReceiptEnvelope(
  captureId: CaptureId,
  receipt: Buffer,
  wrappingKey: Buffer,
  domain: Buffer,
): Buffer {
  return encryptSmallRecord(captureId, receipt, wrappingKey, RECEIPT_MAGIC, domain);
}

function decryptReceiptEnvelope(
  captureId: CaptureId,
  envelope: Buffer,
  wrappingKey: Buffer,
  domain: Buffer,
): Buffer {
  return decryptSmallRecord(
    captureId,
    envelope,
    wrappingKey,
    RECEIPT_MAGIC,
    domain,
    RECORD_PREFIX_BYTES,
    MAX_RECORD_BYTES,
  );
}

function encryptSmallRecord(
  captureId: CaptureId,
  plaintext: Buffer,
  key: Buffer,
  magic: Buffer,
  domain: Buffer,
): Buffer {
  if (plaintext.byteLength > 0xffff) throw new SnapshotIntegrityError();
  const subkey = deriveWrappingSubkey(key, domain);
  const prefixBytes = magic.byteLength + 1 + 2 + NONCE_BYTES;
  const nonce = randomBytes(NONCE_BYTES);
  const prefix = Buffer.alloc(prefixBytes);
  magic.copy(prefix, 0);
  prefix.writeUInt8(FORMAT_VERSION, magic.byteLength);
  prefix.writeUInt16BE(plaintext.byteLength, magic.byteLength + 1);
  nonce.copy(prefix, magic.byteLength + 3);
  try {
    return Buffer.concat([
      prefix,
      encryptAesGcm(plaintext, subkey, nonce, makeAad(domain, captureId, prefix)),
    ]);
  } finally {
    subkey.fill(0);
  }
}

function decryptSmallRecord(
  captureId: CaptureId,
  envelope: Buffer,
  key: Buffer,
  magic: Buffer,
  domain: Buffer,
  prefixBytes: number,
  maximumBytes: number,
): Buffer {
  const subkey = deriveWrappingSubkey(key, domain);
  try {
    if (envelope.byteLength > maximumBytes) throw new SnapshotIntegrityError();
    assertMagicAndVersion(envelope, magic);
    const plaintextBytes = envelope.readUInt16BE(magic.byteLength + 1);
    if (envelope.byteLength !== prefixBytes + plaintextBytes + AUTH_TAG_BYTES) {
      throw new SnapshotIntegrityError();
    }
    const prefix = envelope.subarray(0, prefixBytes);
    const nonce = prefix.subarray(magic.byteLength + 3);
    const plaintext = decryptAesGcm(
      envelope.subarray(prefixBytes),
      subkey,
      nonce,
      makeAad(domain, captureId, prefix),
    );
    if (plaintext.byteLength !== plaintextBytes) {
      plaintext.fill(0);
      throw new SnapshotIntegrityError();
    }
    return plaintext;
  } catch {
    throw new SnapshotIntegrityError();
  } finally {
    subkey.fill(0);
  }
}

function deriveWrappingSubkey(wrappingKey: Buffer, purpose: Buffer): Buffer {
  try {
    return Buffer.from(hkdfSync("sha256", wrappingKey, WRAPPING_KDF_SALT, purpose, 32));
  } catch {
    throw new SnapshotIntegrityError();
  }
}

function encryptAesGcm(plaintext: Buffer, key: Buffer, nonce: Buffer, aad: Buffer): Buffer {
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: AUTH_TAG_BYTES });
    cipher.setAAD(aad, { plaintextLength: plaintext.byteLength });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([ciphertext, cipher.getAuthTag()]);
  } catch {
    throw new SnapshotIntegrityError();
  }
}

function decryptAesGcm(encrypted: Buffer, key: Buffer, nonce: Buffer, aad: Buffer): Buffer {
  let first: Buffer | undefined;
  let final: Buffer | undefined;
  try {
    if (encrypted.byteLength < AUTH_TAG_BYTES) throw new SnapshotIntegrityError();
    const ciphertext = encrypted.subarray(0, -AUTH_TAG_BYTES);
    const tag = encrypted.subarray(-AUTH_TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTH_TAG_BYTES,
    });
    decipher.setAAD(aad, { plaintextLength: ciphertext.byteLength });
    decipher.setAuthTag(tag);
    first = decipher.update(ciphertext);
    final = decipher.final();
    return Buffer.concat([first, final]);
  } catch {
    throw new SnapshotIntegrityError();
  } finally {
    first?.fill(0);
    final?.fill(0);
  }
}

function makeAad(domain: Buffer, captureId: CaptureId, prefix: Buffer): Buffer {
  return Buffer.concat([domain, Buffer.from(captureId, "hex"), prefix]);
}

function assertMagicAndVersion(envelope: Buffer, magic: Buffer): void {
  if (
    envelope.byteLength <= magic.byteLength ||
    !envelope.subarray(0, magic.byteLength).equals(magic) ||
    envelope.readUInt8(magic.byteLength) !== FORMAT_VERSION
  ) {
    throw new SnapshotIntegrityError();
  }
}

function copyCaptureBytes(value: Uint8Array, maxBytes: number): Buffer {
  try {
    if (!(value instanceof Uint8Array)) {
      throw new SnapshotValidationError("Capture content must be a Uint8Array");
    }
    if (value.byteLength > maxBytes) {
      throw new SnapshotValidationError("Capture content exceeds the configured byte limit");
    }
    return Buffer.from(value);
  } catch (error) {
    if (error instanceof SnapshotValidationError) throw error;
    throw new SnapshotValidationError("Capture content is invalid");
  }
}

function copyWrappingKey(value: Uint8Array): Buffer {
  try {
    if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
      throw new SnapshotValidationError("Capture vault wrapping key must contain exactly 32 bytes");
    }
    return Buffer.from(value);
  } catch (error) {
    if (error instanceof SnapshotValidationError) throw error;
    throw new SnapshotValidationError("Capture vault wrapping key is invalid");
  }
}

function validateCaptureId(value: string): CaptureId {
  if (typeof value !== "string" || !isCaptureId(value)) {
    throw new SnapshotValidationError("Capture ID must be 32 lowercase hexadecimal characters");
  }
  return value;
}

function validateRegisteredCaptureIds(value: unknown): readonly CaptureId[] {
  try {
    if (!Array.isArray(value) || value.length > HARD_MAX_NAMESPACE_ENTRIES) {
      throw new SnapshotValidationError("Registered capture IDs are invalid");
    }
    const captureIds = value.map((captureId) => validateCaptureId(captureId));
    if (new Set(captureIds).size !== captureIds.length) {
      throw new SnapshotValidationError("Registered capture IDs must be unique");
    }
    return Object.freeze(captureIds);
  } catch (error) {
    if (error instanceof SnapshotValidationError) throw error;
    throw new SnapshotValidationError("Registered capture IDs are invalid");
  }
}

function validateDirectory(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4_096 ||
    value.includes("\0")
  ) {
    throw new SnapshotValidationError("Capture vault directory is invalid");
  }
  const directory = resolve(value);
  if (directory === parse(directory).root) {
    throw new SnapshotValidationError("Capture vault directory must not be the filesystem root");
  }
  return directory;
}

function validateLimit(value: unknown, minimum: number, maximum: number, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new SnapshotValidationError(`Capture vault ${label} is outside the supported range`);
  }
  return value;
}

function exactOptionsRecord(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
  label: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SnapshotValidationError(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new SnapshotValidationError(`${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || !allowedKeys.includes(key)) ||
    !requiredKeys.every((key) => keys.includes(key))
  ) {
    throw new SnapshotValidationError(`${label} must match its exact schema`);
  }
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SnapshotValidationError(`${label} must contain enumerable data properties`);
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function safeExactOptionsRecord(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
  label: string,
): Readonly<Record<string, unknown>> {
  try {
    return exactOptionsRecord(value, allowedKeys, requiredKeys, label);
  } catch (error) {
    if (error instanceof SnapshotValidationError) throw error;
    throw new SnapshotValidationError(`${label} is invalid`);
  }
}

function validateFileStats(stats: {
  readonly isFile: () => boolean;
  readonly mode: bigint;
  readonly uid: bigint;
}): void {
  if (
    !stats.isFile() ||
    (EFFECTIVE_USER_ID !== undefined && stats.uid !== EFFECTIVE_USER_ID) ||
    (stats.mode & 0o777n) !== BigInt(FILE_MODE)
  ) {
    throw new SnapshotSecurityError();
  }
}

function assertSameFile(
  actual: { readonly dev: bigint; readonly ino: bigint; readonly uid: bigint },
  expected: { readonly dev: bigint; readonly ino: bigint; readonly uid: bigint },
): void {
  if (actual.dev !== expected.dev || actual.ino !== expected.ino || actual.uid !== expected.uid) {
    throw new SnapshotSecurityError();
  }
}

function assertSettledLinkCount(linkCount: bigint): void {
  if (linkCount === 1n) return;
  if (linkCount === 2n) throw new SnapshotLinkSettlingError();
  throw new SnapshotSecurityError();
}

function wipeVerifiedCapture(capture: VerifiedCaptureInternal): void {
  capture.metadataBytes.fill(0);
  capture.plaintext.fill(0);
}

async function writeAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesWritten < 1) throw new SnapshotSecurityError();
    offset += result.bytesWritten;
  }
}

/** Returns true only for a vault whose safe asynchronous open completed successfully. */
export function isSnapshotVault(value: unknown): value is SnapshotVault {
  return (
    typeof value === "object" &&
    value !== null &&
    authenticSnapshotVaults.has(value) &&
    Object.getPrototypeOf(value) === SnapshotVault.prototype
  );
}

async function readAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesRead < 1) throw new SnapshotIntegrityError();
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

async function shortDelay(): Promise<void> {
  await new Promise<void>((resolveDelay) => {
    setTimeout(resolveDelay, LINK_SETTLE_DELAY_MS);
  });
}
