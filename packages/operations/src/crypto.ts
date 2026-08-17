import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { canonicalJson, type JsonValue } from "@rsi/store";

import { OperationsIntegrityError, OperationsValidationError } from "./errors.js";

export interface EncryptedValue {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly tag: Uint8Array;
}

export interface WrappedCursorValue {
  readonly encrypted: EncryptedValue;
  readonly wrappedDek: EncryptedValue;
}

export interface OperationsKeys {
  readonly cursorWrappingKey: Buffer;
  readonly macKey: Buffer;
}

export function deriveOperationsKeys(key: Uint8Array): OperationsKeys {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new OperationsValidationError("stateKey must contain exactly 32 bytes");
  }
  const copied = Buffer.from(key);
  try {
    const salt = Buffer.from("rsi.operations.v1", "utf8");
    return Object.freeze({
      cursorWrappingKey: Buffer.from(
        hkdfSync("sha256", copied, salt, Buffer.from("cursor-dek-wrapping-v2", "utf8"), 32),
      ),
      macKey: Buffer.from(
        hkdfSync("sha256", copied, salt, Buffer.from("state-integrity", "utf8"), 32),
      ),
    });
  } finally {
    copied.fill(0);
  }
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function secureEqualHex(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function macJson(macKey: Uint8Array, domain: string, value: JsonValue): string {
  return createHmac("sha256", macKey)
    .update("rsi.operations.mac.v1\0", "utf8")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function encryptAesGcm(key: Uint8Array, aad: string, plaintext: Uint8Array): EncryptedValue {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, "utf8"), { plaintextLength: plaintext.byteLength });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Object.freeze({
    ciphertext,
    nonce,
    tag: cipher.getAuthTag(),
  });
}

function decryptAesGcm(key: Uint8Array, aad: string, encrypted: EncryptedValue): Buffer {
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, encrypted.nonce, {
      authTagLength: 16,
    });
    decipher.setAAD(Buffer.from(aad, "utf8"), {
      plaintextLength: encrypted.ciphertext.byteLength,
    });
    decipher.setAuthTag(encrypted.tag);
    return Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
  } catch {
    throw new OperationsIntegrityError("Encrypted cursor authentication failed");
  }
}

function wrappedDekAad(valueAad: string): string {
  return `rsi.operations.cursor-dek-wrap.aad.v2\n${valueAad}`;
}

/**
 * Encrypt a cursor under a fresh random DEK, then authenticate and wrap that DEK
 * under the long-lived operations cursor-wrapping key. The DEK is wiped before
 * returning. Callers must persist and later erase every wrappedDek component as
 * a unit to make stale value ciphertext cryptographically unreachable.
 */
export function encryptCursor(
  cursorWrappingKey: Uint8Array,
  valueAad: string,
  value: string,
): WrappedCursorValue {
  const dek = randomBytes(32);
  const plaintext = Buffer.from(value, "utf8");
  try {
    return Object.freeze({
      encrypted: encryptAesGcm(dek, valueAad, plaintext),
      wrappedDek: encryptAesGcm(cursorWrappingKey, wrappedDekAad(valueAad), dek),
    });
  } finally {
    dek.fill(0);
    plaintext.fill(0);
  }
}

export function decryptCursor(
  cursorWrappingKey: Uint8Array,
  valueAad: string,
  encrypted: EncryptedValue,
  wrappedDek: EncryptedValue,
): string {
  const dek = decryptAesGcm(cursorWrappingKey, wrappedDekAad(valueAad), wrappedDek);
  let plaintext: Buffer | undefined;
  try {
    if (dek.byteLength !== 32) {
      throw new OperationsIntegrityError("Wrapped cursor DEK has an invalid length");
    }
    plaintext = decryptAesGcm(dek, valueAad, encrypted);
    return plaintext.toString("utf8");
  } finally {
    dek.fill(0);
    plaintext?.fill(0);
  }
}
