import { Buffer } from "node:buffer";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign,
  verify,
} from "node:crypto";

import { canonicalJson, decodeSignature, parseCheckpointPayload } from "./canonical.js";
import { InvalidCheckpointError } from "./errors.js";
import type {
  CheckpointPayload,
  Ed25519PrivateKeyMaterial,
  Ed25519PublicKeyMaterial,
} from "./types.js";

const SIGNATURE_DOMAIN = Buffer.from("rsi-store-checkpoint-signature-v1\0", "utf8");
const ENTRY_HASH_DOMAIN = Buffer.from("rsi-store-checkpoint-entry-v1\0", "utf8");

/** Returns the exact domain-separated bytes covered by the Ed25519 signature. */
export function encodeCheckpointPayload(payload: CheckpointPayload): Buffer {
  const validated = parseCheckpointPayload(payload);
  return Buffer.concat([SIGNATURE_DOMAIN, Buffer.from(canonicalJson(validated), "utf8")]);
}

/** Computes the journal-link hash over the canonical payload and its signature. */
export function computeCheckpointHash(payload: CheckpointPayload, signature: string): string {
  const validated = parseCheckpointPayload(payload);
  decodeSignature(signature);
  return createHash("sha256")
    .update(ENTRY_HASH_DOMAIN)
    .update(canonicalJson({ payload: validated, signature }), "utf8")
    .digest("hex");
}

export function importEd25519PrivateKey(material: Ed25519PrivateKeyMaterial): KeyObject {
  let key: KeyObject;
  try {
    key = isKeyObject(material)
      ? material
      : createPrivateKey(material as Parameters<typeof createPrivateKey>[0]);
  } catch (error) {
    throw new InvalidCheckpointError(
      `Unable to import checkpoint private key: ${error instanceof Error ? error.message : "invalid key"}`,
    );
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new InvalidCheckpointError("privateKey must be an Ed25519 private key");
  }
  return key;
}

export function importEd25519PublicKey(material: Ed25519PublicKeyMaterial): KeyObject {
  let key: KeyObject;
  try {
    key = isKeyObject(material)
      ? material
      : createPublicKey(material as Parameters<typeof createPublicKey>[0]);
  } catch (error) {
    throw new InvalidCheckpointError(
      `Unable to import expected public key: ${error instanceof Error ? error.message : "invalid key"}`,
    );
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new InvalidCheckpointError("expectedPublicKey must be an Ed25519 public key");
  }
  return key;
}

export function publicKeyForPrivateKey(privateKey: KeyObject): KeyObject {
  return createPublicKey(privateKey);
}

export function signCheckpointPayload(payload: CheckpointPayload, privateKey: KeyObject): string {
  return sign(null, encodeCheckpointPayload(payload), privateKey).toString("base64url");
}

export function verifyCheckpointSignature(
  payload: CheckpointPayload,
  signature: string,
  publicKey: KeyObject,
): boolean {
  return verify(null, encodeCheckpointPayload(payload), publicKey, decodeSignature(signature));
}

function isKeyObject(value: unknown): value is KeyObject {
  return value instanceof KeyObject;
}
