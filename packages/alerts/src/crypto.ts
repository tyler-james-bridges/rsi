import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { canonicalJson, type JsonValue } from "@rsi/store";

import { AlertIntegrityError, AlertValidationError } from "./errors.js";

export interface AlertKeys {
  readonly encryptionKey: Buffer;
  readonly identityKey: Buffer;
  readonly macKey: Buffer;
}

export interface EncryptedValue {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly tag: Uint8Array;
}

export function deriveAlertKeys(stateKey: Uint8Array, profile: string): AlertKeys {
  if (!(stateKey instanceof Uint8Array) || stateKey.byteLength !== 32) {
    throw new AlertValidationError("stateKey must contain exactly 32 bytes");
  }
  const copied = Buffer.from(stateKey);
  try {
    const salt = Buffer.from(`rsi.alerts.v1:${profile}`, "utf8");
    return Object.freeze({
      encryptionKey: Buffer.from(
        hkdfSync("sha256", copied, salt, Buffer.from("outbox-encryption", "utf8"), 32),
      ),
      identityKey: Buffer.from(
        hkdfSync("sha256", copied, salt, Buffer.from("delivery-identity", "utf8"), 32),
      ),
      macKey: Buffer.from(
        hkdfSync("sha256", copied, salt, Buffer.from("state-integrity", "utf8"), 32),
      ),
    });
  } finally {
    copied.fill(0);
  }
}

export function keyedHex(key: Uint8Array, domain: string, value: JsonValue): string {
  return createHmac("sha256", key)
    .update("rsi.alerts.keyed.v1\0", "utf8")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

export function macJson(key: Uint8Array, domain: string, value: JsonValue): string {
  return createHmac("sha256", key)
    .update("rsi.alerts.mac.v1\0", "utf8")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

export function secureEqualHex(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function encryptValue(key: Uint8Array, aad: string, plaintext: string): EncryptedValue {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Object.freeze({ ciphertext, nonce, tag: cipher.getAuthTag() });
}

export function decryptValue(key: Uint8Array, aad: string, value: EncryptedValue): string {
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, value.nonce);
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(value.tag);
    return Buffer.concat([decipher.update(value.ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new AlertIntegrityError("Encrypted alert state authentication failed");
  }
}
