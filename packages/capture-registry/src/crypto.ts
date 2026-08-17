import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { CaptureRegistryIntegrityError, CaptureRegistryValidationError } from "./errors.js";
import type { CaptureRegistryProfile } from "./types.js";

export interface CaptureRegistryKeys {
  readonly encryptionKey: Buffer;
  readonly lookupKey: Buffer;
  readonly macKey: Buffer;
}

export interface EncryptedRegistryValue {
  readonly ciphertext: Buffer;
  readonly nonce: Buffer;
  readonly tag: Buffer;
}

export function deriveCaptureRegistryKeys(
  registryKey: Uint8Array,
  profile: CaptureRegistryProfile,
): CaptureRegistryKeys {
  if (!(registryKey instanceof Uint8Array) || registryKey.byteLength !== 32) {
    throw new CaptureRegistryValidationError("registryKey must contain exactly 32 bytes");
  }
  const copied = Buffer.from(registryKey);
  const salt = Buffer.from("rsi.capture-registry.hkdf-sha256.salt.v1\0", "ascii");
  const profileDomain = Buffer.from(`${profile}\0`, "ascii");
  try {
    return Object.freeze({
      encryptionKey: Buffer.from(
        hkdfSync(
          "sha256",
          copied,
          salt,
          Buffer.concat([profileDomain, Buffer.from("record-encryption", "ascii")]),
          32,
        ),
      ),
      lookupKey: Buffer.from(
        hkdfSync(
          "sha256",
          copied,
          salt,
          Buffer.concat([profileDomain, Buffer.from("keyed-lookups", "ascii")]),
          32,
        ),
      ),
      macKey: Buffer.from(
        hkdfSync(
          "sha256",
          copied,
          salt,
          Buffer.concat([profileDomain, Buffer.from("database-authentication", "ascii")]),
          32,
        ),
      ),
    });
  } finally {
    copied.fill(0);
    salt.fill(0);
    profileDomain.fill(0);
  }
}

export function keyedLookupToken(
  lookupKey: Uint8Array,
  domain: "attempt" | "capture" | "session",
  value: string,
): string {
  return createHmac("sha256", lookupKey)
    .update("rsi.capture-registry.lookup.v1\0", "ascii")
    .update(domain, "ascii")
    .update("\0", "ascii")
    .update(value, "utf8")
    .digest("hex");
}

export function mac(
  macKey: Uint8Array,
  domain: string,
  parts: readonly (number | string | Uint8Array | null)[],
): string {
  const hmac = createHmac("sha256", macKey)
    .update("rsi.capture-registry.mac.v1\0", "ascii")
    .update(domain, "utf8")
    .update("\0", "ascii");
  for (const part of parts) {
    if (part === null) {
      hmac.update("null", "ascii");
    } else if (typeof part === "number") {
      hmac.update(String(part), "ascii");
    } else if (typeof part === "string") {
      hmac.update(part, "utf8");
    } else {
      hmac.update(part);
    }
    hmac.update("\0", "ascii");
  }
  return hmac.digest("hex");
}

export function secureMacEqual(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function encryptRegistryValue(
  encryptionKey: Uint8Array,
  aad: string,
  plaintext: Buffer,
): EncryptedRegistryValue {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, "utf8"), { plaintextLength: plaintext.byteLength });
  return Object.freeze({
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
    nonce,
    tag: cipher.getAuthTag(),
  });
}

export function decryptRegistryValue(
  encryptionKey: Uint8Array,
  aad: string,
  encrypted: Readonly<{ ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array }>,
): Buffer {
  try {
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey, encrypted.nonce, {
      authTagLength: 16,
    });
    decipher.setAAD(Buffer.from(aad, "utf8"), { plaintextLength: encrypted.ciphertext.byteLength });
    decipher.setAuthTag(encrypted.tag);
    return Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
  } catch {
    throw new CaptureRegistryIntegrityError();
  }
}
