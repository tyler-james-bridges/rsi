import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

import { canonicalJson } from "./canonical.js";
import { ExternalAnchorValidationError } from "./errors.js";

export interface ExternalAnchorStateKeys {
  readonly macKey: Buffer;
}

export function deriveExternalAnchorStateKeys(stateKey: Uint8Array): ExternalAnchorStateKeys {
  if (!(stateKey instanceof Uint8Array) || stateKey.byteLength !== 32) {
    throw new ExternalAnchorValidationError("stateKey must contain exactly 32 bytes");
  }
  const copied = Buffer.from(stateKey);
  try {
    return Object.freeze({
      macKey: Buffer.from(
        hkdfSync(
          "sha256",
          copied,
          Buffer.from("rsi.external-anchor.hkdf.salt.v1\0", "ascii"),
          Buffer.from("durable-outbox-authentication", "ascii"),
          32,
        ),
      ),
    });
  } finally {
    copied.fill(0);
  }
}

export function macJson(macKey: Uint8Array, domain: string, value: unknown): string {
  return createHmac("sha256", macKey)
    .update("rsi.external-anchor.mac.v1\0", "ascii")
    .update(domain, "utf8")
    .update("\0", "ascii")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

export function secureMacEqual(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}
