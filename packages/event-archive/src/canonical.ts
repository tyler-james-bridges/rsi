import { Buffer } from "node:buffer";
import { createHash, createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";
import { TextDecoder, types as utilTypes } from "node:util";

import { fail } from "./errors.js";
import type { JsonValue } from "./types.js";

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$/;
const BASE64URL_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const SENSITIVE_IDENTIFIER_PATTERN =
  /secret|token|password|credential|private|bearer|api[_-]?key|mnemonic|seed|sk_live|xox|ghp_|https?:|@/i;
const MAX_CANONICAL_DEPTH = 32;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")!.get!;
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteLength",
)!.get!;
const typedArraySet = Uint8Array.prototype.set;

export function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function secureEqualHex(left: string, right: string): boolean {
  if (!HASH_PATTERN.test(left) || !HASH_PATTERN.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function canonicalJson(value: JsonValue): string {
  return serialize(value, new WeakSet<object>(), 0);
}

function serialize(value: unknown, ancestors: WeakSet<object>, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) fail("INPUT_INVALID", "Canonical JSON nesting is too deep");
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) fail("INPUT_INVALID", "Canonical JSON number is invalid");
      return JSON.stringify(value);
    case "bigint":
    case "function":
    case "symbol":
    case "undefined":
      fail("INPUT_INVALID", "Canonical JSON value type is unsupported");
    case "object":
      break;
  }
  if (utilTypes.isProxy(value)) fail("INPUT_INVALID", "Canonical JSON proxies are forbidden");
  if (ancestors.has(value)) fail("INPUT_INVALID", "Canonical JSON cycles are forbidden");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      assertExactArrayShape(value, "Canonical JSON array");
      const parts: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        parts.push(
          serialize(
            dataProperty(value, String(index), "Canonical JSON array"),
            ancestors,
            depth + 1,
          ),
        );
      }
      return `[${parts.join(",")}]`;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      fail("INPUT_INVALID", "Canonical JSON objects must be ordinary objects");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key === "symbol")) {
      fail("INPUT_INVALID", "Canonical JSON symbols are forbidden");
    }
    const stringKeys = (keys as string[]).sort();
    return `{${stringKeys
      .map(
        (key) =>
          `${JSON.stringify(key)}:${serialize(dataProperty(value, key, "Canonical JSON object"), ancestors, depth + 1)}`,
      )
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function exactObject(
  value: unknown,
  expectedKeys: readonly string[],
  safeName: string,
): Readonly<Record<string, unknown>> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail("INPUT_INVALID", `${safeName} must be an ordinary object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key === "symbol")) {
    fail("INPUT_INVALID", `${safeName} contains forbidden symbol keys`);
  }
  const actual = (keys as string[]).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail("INPUT_INVALID", `${safeName} has unknown or missing fields`);
  }
  const result: Record<string, unknown> = {};
  for (const key of expectedKeys) result[key] = dataProperty(value, key, safeName);
  return result;
}

export function exactArray(value: unknown, safeName: string): readonly unknown[] {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    !Array.isArray(value)
  ) {
    fail("INPUT_INVALID", `${safeName} must be an ordinary array`);
  }
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    fail("INPUT_INVALID", `${safeName} must be an ordinary array`);
  }
  assertExactArrayShape(value, safeName);
  const result: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    result.push(dataProperty(value, String(index), safeName));
  }
  return result;
}

function assertExactArrayShape(value: readonly unknown[], safeName: string): void {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key === "symbol")) {
    fail("INPUT_INVALID", `${safeName} contains forbidden symbol keys`);
  }
  if (keys.length !== value.length + 1 || !keys.includes("length")) {
    fail("INPUT_INVALID", `${safeName} is sparse or contains extra fields`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (Object.getOwnPropertyDescriptor(value, String(index)) === undefined) {
      fail("INPUT_INVALID", `${safeName} is sparse`);
    }
  }
}

function dataProperty(value: object, key: PropertyKey, safeName: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    fail("INPUT_INVALID", `${safeName} may not contain accessors`);
  }
  return descriptor.value;
}

export function validateEnum<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  safeName: string,
): T[number] {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    fail("INPUT_INVALID", `${safeName} is unsupported`);
  }
  return value as T[number];
}

export function validateLiteral<T extends string | number>(
  value: unknown,
  expected: T,
  safeName: string,
): T {
  if (value !== expected) fail("INPUT_INVALID", `${safeName} is unsupported`);
  return expected;
}

export function validateHash(value: unknown, safeName: string): string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be a lowercase SHA-256 digest`);
  }
  return value;
}

export function validateUuidV4(value: unknown, safeName: string): string {
  if (typeof value !== "string" || !UUID_V4_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${safeName} must be a canonical lowercase UUIDv4`);
  }
  return value;
}

export function validateTimestamp(value: unknown, safeName: string): string {
  if (
    typeof value !== "string" ||
    !TIMESTAMP_PATTERN.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    fail("INPUT_INVALID", `${safeName} must be a canonical UTC timestamp`);
  }
  return value;
}

export function validateIdentifier(value: unknown, safeName: string): string {
  if (
    typeof value !== "string" ||
    !IDENTIFIER_PATTERN.test(value) ||
    SENSITIVE_IDENTIFIER_PATTERN.test(value)
  ) {
    fail("INPUT_INVALID", `${safeName} is not an allowed identifier`);
  }
  return value;
}

export function validateSafeInteger(
  value: unknown,
  safeName: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail("INPUT_INVALID", `${safeName} is outside its integer bound`);
  }
  return value as number;
}

export function validateBoolean(value: unknown, safeName: string): boolean {
  if (typeof value !== "boolean") fail("INPUT_INVALID", `${safeName} must be boolean`);
  return value;
}

export function copyOrdinaryBytes(value: unknown, safeName: string, maximum: number): Uint8Array {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    !utilTypes.isUint8Array(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) {
    fail("INPUT_INVALID", `${safeName} must be an ordinary bounded Uint8Array`);
  }
  let backingBuffer: ArrayBufferLike;
  let byteLength: number;
  try {
    backingBuffer = Reflect.apply(typedArrayBufferGetter, value, []) as ArrayBufferLike;
    byteLength = Reflect.apply(typedArrayByteLengthGetter, value, []) as number;
  } catch {
    fail("INPUT_INVALID", `${safeName} must be an ordinary bounded Uint8Array`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    Object.getPrototypeOf(backingBuffer) !== ArrayBuffer.prototype ||
    byteLength === 0 ||
    byteLength > maximum ||
    ownKeys.length !== byteLength ||
    ownKeys.some((key, index) => key !== String(index))
  ) {
    fail("INPUT_INVALID", `${safeName} must be an ordinary bounded Uint8Array`);
  }
  const copy = new Uint8Array(byteLength);
  try {
    Reflect.apply(typedArraySet, copy, [value]);
  } catch {
    fail("INPUT_INVALID", `${safeName} must be an ordinary bounded Uint8Array`);
  }
  return copy;
}

export function importEd25519PublicKey(bytesValue: unknown, safeName: string): KeyObject {
  const bytes = copyOrdinaryBytes(bytesValue, safeName, 512);
  let key: KeyObject;
  try {
    key = createPublicKey({ format: "der", key: Buffer.from(bytes), type: "spki" });
  } catch {
    fail("INPUT_INVALID", `${safeName} is not a valid public key`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    fail("INPUT_INVALID", `${safeName} must be an Ed25519 public key`);
  }
  return key;
}

export function decodeSignature(value: unknown): Buffer {
  if (typeof value !== "string" || !BASE64URL_SIGNATURE_PATTERN.test(value)) {
    fail("ARCHIVE_FORMAT", "Archive signature encoding is invalid");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    fail("ARCHIVE_FORMAT", "Archive signature encoding is invalid");
  }
  return bytes;
}

export function parseCanonicalJsonBytes(bytes: Uint8Array, safeName: string): unknown {
  let text: string;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    fail("ARCHIVE_FORMAT", `${safeName} is not valid UTF-8`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    fail("ARCHIVE_FORMAT", `${safeName} is not valid JSON`);
  }
  if (canonicalJson(value as JsonValue) !== text) {
    fail("ARCHIVE_FORMAT", `${safeName} is not canonical JSON`);
  }
  return value;
}

export function deepFreezeJson<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object") {
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor !== undefined && "value" in descriptor) deepFreezeJson(descriptor.value);
    }
    Object.freeze(value);
  }
  return value;
}
