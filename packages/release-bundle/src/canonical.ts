import { Buffer } from "node:buffer";
import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { types as utilTypes } from "node:util";

import { fail } from "./errors.js";

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const GIT_HASH_PATTERN = /^[0-9a-f]{40}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$/;
const SEMVER_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const BASE64URL_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const MAX_CANONICAL_DEPTH = 24;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype) as object;
const TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "buffer",
)!.get!;
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
)!.get!;
const TYPED_ARRAY_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteOffset",
)!.get!;

export function sha256(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function canonicalJson(value: unknown): string {
  return serialize(value, new WeakSet<object>(), 0);
}

function serialize(value: unknown, ancestors: WeakSet<object>, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) fail("INPUT_INVALID", "Canonical value is too deeply nested");
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("INPUT_INVALID", "Canonical numbers must be integers");
    return String(value);
  }
  if (typeof value !== "object" || utilTypes.isProxy(value)) {
    fail("INPUT_INVALID", "Canonical value has an unsupported type");
  }
  if (ancestors.has(value)) fail("INPUT_INVALID", "Canonical value is cyclic");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const values = exactArray(value, "Canonical array");
      return `[${values.map((entry) => serialize(entry, ancestors, depth + 1)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail("INPUT_INVALID", "Canonical objects must be plain records");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      fail("INPUT_INVALID", "Canonical objects may not have symbol fields");
    }
    return `{${(keys as string[])
      .sort()
      .map((key) => {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor)) {
          fail("INPUT_INVALID", "Canonical objects may not have accessors");
        }
        return `${JSON.stringify(key)}:${serialize(descriptor.value, ancestors, depth + 1)}`;
      })
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function exactObject(
  value: unknown,
  expectedKeys: readonly string[],
  safeName: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value)
  ) {
    fail("INPUT_INVALID", `${safeName} must be a plain record`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail("INPUT_INVALID", `${safeName} must be a plain record`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    fail("INPUT_INVALID", `${safeName} has unknown fields`);
  }
  const actual = (keys as string[]).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail("INPUT_INVALID", `${safeName} has unknown or missing fields`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor)) {
      fail("INPUT_INVALID", `${safeName} may not have accessors`);
    }
    copy[key] = descriptor.value;
  }
  return copy;
}

export function exactArray(value: unknown, safeName: string): readonly unknown[] {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) {
    fail("INPUT_INVALID", `${safeName} must be an array`);
  }
  const keys = Reflect.ownKeys(value);
  const allowed = new Set<string>(["length"]);
  for (let index = 0; index < value.length; index += 1) allowed.add(String(index));
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.length !== allowed.size ||
    keys.some((key) => !allowed.has(key as string))
  ) {
    fail("INPUT_INVALID", `${safeName} must be dense and field-free`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const copy: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor)) {
      fail("INPUT_INVALID", `${safeName} may not have accessors or holes`);
    }
    copy.push(descriptor.value);
  }
  return copy;
}

/** Copies only an exact ordinary Uint8Array backed by an ordinary ArrayBuffer. */
export function copyInputBytes(value: unknown, safeName: string, maximumBytes: number): Buffer {
  if (
    utilTypes.isProxy(value) ||
    !utilTypes.isUint8Array(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) {
    fail("INPUT_INVALID", `${safeName} must be an ordinary byte array`);
  }
  const bytes = value as Uint8Array;
  const forbiddenOwnFields = ["buffer", "byteLength", "byteOffset", "constructor", "length"];
  if (
    Object.getOwnPropertySymbols(bytes).length !== 0 ||
    forbiddenOwnFields.some((key) => Object.getOwnPropertyDescriptor(bytes, key) !== undefined)
  ) {
    fail("INPUT_INVALID", `${safeName} may not have extra fields or accessors`);
  }
  const buffer = TYPED_ARRAY_BUFFER_GETTER.call(bytes) as ArrayBufferLike;
  const byteLength = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(bytes) as number;
  const byteOffset = TYPED_ARRAY_BYTE_OFFSET_GETTER.call(bytes) as number;
  if (
    utilTypes.isSharedArrayBuffer(buffer) ||
    Object.getPrototypeOf(buffer) !== ArrayBuffer.prototype ||
    byteLength === 0 ||
    byteLength > maximumBytes
  ) {
    fail("INPUT_INVALID", `${safeName} is outside its byte bound`);
  }
  return Buffer.from(new Uint8Array(buffer, byteOffset, byteLength));
}

export function validateHash(value: unknown, safeName: string): string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be a lowercase SHA-256 digest`);
  }
  return value;
}

export function validateGitHash(value: unknown, safeName: string): string {
  if (typeof value !== "string" || !GIT_HASH_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be a lowercase Git object digest`);
  }
  return value;
}

export function validateUuidV4(value: unknown, safeName: string): string {
  if (typeof value !== "string" || !UUID_V4_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be a canonical UUIDv4`);
  }
  return value;
}

export function validateTimestamp(value: unknown, safeName: string): string {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be a canonical UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail("INPUT_INVALID", `${safeName} must be a valid canonical UTC timestamp`);
  }
  return value;
}

export function validateSafeInteger(
  value: unknown,
  safeName: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail("INPUT_INVALID", `${safeName} must be a bounded safe integer`);
  }
  return value as number;
}

export function validateIdentifier(value: unknown, safeName: string): string {
  if (
    typeof value !== "string" ||
    value.normalize("NFC") !== value ||
    !IDENTIFIER_PATTERN.test(value) ||
    /secret|token|password|credential|private|bearer|api[_-]?key|mnemonic|seed|https?:|@/i.test(
      value,
    )
  ) {
    fail("INPUT_INVALID", `${safeName} must be a sanitized ASCII identifier`);
  }
  return value;
}

export function validateSemver(value: unknown, safeName: string): string {
  if (typeof value !== "string" || value.length > 128 || !SEMVER_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be canonical SemVer`);
  }
  return value;
}

export function validateEnum<T extends string>(
  value: unknown,
  values: readonly T[],
  safeName: string,
): T {
  if (typeof value !== "string" || !values.includes(value as T)) {
    fail("INPUT_INVALID", `${safeName} is unsupported`);
  }
  return value as T;
}

export function decodeSignature(value: unknown): Buffer {
  if (typeof value !== "string" || !BASE64URL_SIGNATURE_PATTERN.test(value)) {
    fail("INPUT_INVALID", "Signature encoding is invalid");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    fail("INPUT_INVALID", "Signature encoding is invalid");
  }
  return bytes;
}

export function importEd25519PublicKey(spkiDer: Uint8Array, safeName: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey({ format: "der", key: Buffer.from(spkiDer), type: "spki" });
  } catch {
    fail("INPUT_INVALID", `${safeName} is not a valid public key`);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("INPUT_INVALID", `${safeName} must be an Ed25519 public key`);
  }
  const canonical = key.export({ format: "der", type: "spki" });
  if (!Buffer.from(canonical).equals(Buffer.from(spkiDer))) {
    fail("INPUT_INVALID", `${safeName} must use canonical SPKI DER`);
  }
  return key;
}

export function parseCanonicalJson(bytes: Buffer, safeName: string): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("ARCHIVE_FORMAT", `${safeName} must be UTF-8`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    fail("ARCHIVE_FORMAT", `${safeName} is not valid JSON`);
  }
  if (canonicalJson(value) !== text) {
    fail("ARCHIVE_FORMAT", `${safeName} is not canonical JSON`);
  }
  return value;
}
