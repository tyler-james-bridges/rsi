import { types as utilTypes } from "node:util";

import { z } from "zod";

import { SourceContractError, type SourceContractErrorCode } from "./errors.js";

export const TimestampSchema = z
  .string()
  .max(32)
  .refine((value) => {
    const time = Date.parse(value);
    return Number.isFinite(time) && new Date(time).toISOString() === value;
  });
export const EvmAddressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
export const Bytes32Schema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
export const AtomicSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,77})$/)
  .refine((value) => {
    try {
      return BigInt(value) <= (1n << 256n) - 1n;
    } catch {
      return false;
    }
  });
export const HexQuantitySchema = z
  .string()
  .max(66)
  .regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/);

export function parsePlain<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    assertPlainData(value);
    const result = schema.safeParse(value);
    if (!result.success) fail("INPUT_INVALID");
    return result.data;
  } catch (error) {
    if (error instanceof SourceContractError) throw error;
    fail("INPUT_INVALID");
  }
}

export function parseJsonBytes<T>(schema: z.ZodType<T>, input: unknown, maximumBytes: number): T {
  const bytes = copyOrdinaryBytes(input);
  try {
    if (bytes.byteLength === 0 || bytes.byteLength > maximumBytes) fail("RESPONSE_INVALID");
    let decoded: unknown;
    try {
      decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      fail("RESPONSE_INVALID");
    }
    const result = schema.safeParse(decoded);
    if (!result.success) fail("RESPONSE_INVALID");
    return result.data;
  } finally {
    bytes.fill(0);
  }
}

export function copyOrdinaryBytes(value: unknown): Uint8Array {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) {
    fail("INPUT_INVALID");
  }
  const bytes = value as Uint8Array;
  if (
    !(bytes.buffer instanceof ArrayBuffer) ||
    Object.getPrototypeOf(bytes.buffer) !== ArrayBuffer.prototype ||
    bytes.byteOffset !== 0 ||
    bytes.byteLength !== bytes.buffer.byteLength
  ) {
    fail("INPUT_INVALID");
  }
  try {
    return Uint8Array.prototype.slice.call(bytes) as Uint8Array;
  } catch {
    fail("INPUT_INVALID");
  }
}

export function assertPlainData(value: unknown, ancestors = new WeakSet<object>()): void {
  if (value === null || typeof value !== "object") return;
  if (utilTypes.isProxy(value) || ancestors.has(value)) fail("INPUT_INVALID");
  if (
    Object.getPrototypeOf(value) !== (Array.isArray(value) ? Array.prototype : Object.prototype)
  ) {
    fail("INPUT_INVALID");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.some(
          (key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9]\d*)$/.test(key)),
        )
      ) {
        fail("INPUT_INVALID");
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          fail("INPUT_INVALID");
        }
        assertPlainData(descriptor.value, ancestors);
      }
      return;
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") fail("INPUT_INVALID");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        fail("INPUT_INVALID");
      }
      assertPlainData(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalTimestamp(value: string): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) fail("RESPONSE_INVALID");
  return new Date(time).toISOString();
}

export function fail(code: SourceContractErrorCode): never {
  throw new SourceContractError(code);
}

export function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function encodeCanonicalJson(value: unknown): Uint8Array {
  assertPlainData(value);
  return new TextEncoder().encode(JSON.stringify(sortValue(value)));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) fail("INPUT_INVALID");
      result[key] = sortValue(descriptor.value);
    }
    return result;
  }
  return value;
}
