import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import { failInput } from "./portable.js";

export { assertPlainData, canonicalBytes, canonicalJson } from "./portable.js";

export function sha256Hex(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function copyOrdinaryBytes(value: unknown): Uint8Array {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) {
    failInput();
  }
  const bytes = value as Uint8Array;
  if (
    !(bytes.buffer instanceof ArrayBuffer) ||
    Object.getPrototypeOf(bytes.buffer) !== ArrayBuffer.prototype ||
    bytes.byteOffset !== 0 ||
    bytes.byteLength !== bytes.buffer.byteLength ||
    Reflect.ownKeys(bytes).some((key) => typeof key !== "string" || !/^\d+$/.test(key))
  ) {
    failInput();
  }
  return Uint8Array.prototype.slice.call(bytes) as Uint8Array;
}

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{86}$/.test(value)) failInput();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength !== 64 || bytes.toString("base64url") !== value) failInput();
  return Uint8Array.from(bytes);
}
