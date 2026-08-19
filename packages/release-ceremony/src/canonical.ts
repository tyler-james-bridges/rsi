import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import { fail } from "./errors.js";

const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const GIT_HASH_PATTERN = /^[0-9a-f]{40}$/;

export function exactObject(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail("INPUT_INVALID", `${label} must be an ordinary object`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  ) {
    fail("INPUT_INVALID", `${label} has unsupported fields`);
  }
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      fail("INPUT_INVALID", `${label} contains an accessor`);
    }
  }
  return value as Record<string, unknown>;
}

export function exactArray(value: unknown, label: string, max: number): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > max
  ) {
    fail("INPUT_INVALID", `${label} must be a bounded array`);
  }
  const expectedKeys = new Set<string>(["length"]);
  for (let index = 0; index < value.length; index += 1) expectedKeys.add(String(index));
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.size ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.has(key))
  ) {
    fail("INPUT_INVALID", `${label} has unsupported fields`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !("value" in descriptor)) {
      fail("INPUT_INVALID", `${label} must be dense`);
    }
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return canonicalValue(value, new Set<object>(), 0);
}

function canonicalValue(value: unknown, seen: Set<object>, depth: number): string {
  if (depth > 32) fail("INPUT_INVALID", "Canonical value is too deeply nested");
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("INPUT_INVALID", "Canonical number is invalid");
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || utilTypes.isProxy(value)) {
    fail("INPUT_INVALID", "Canonical value contains unsupported data");
  }
  if (seen.has(value)) fail("INPUT_INVALID", "Canonical value contains a cycle");
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const values = exactArray(value, "Canonical array", 4_096);
      return `[${values.map((entry) => canonicalValue(entry, seen, depth + 1)).join(",")}]`;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      fail("INPUT_INVALID", "Canonical object has an unsupported prototype");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      fail("INPUT_INVALID", "Canonical object contains a symbol field");
    }
    const stringKeys = (keys as string[]).sort(compareAscii);
    const entries = stringKeys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        fail("INPUT_INVALID", "Canonical object contains an accessor");
      }
      return `${JSON.stringify(key)}:${canonicalValue(descriptor.value, seen, depth + 1)}`;
    });
    return `{${entries.join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function validateHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  return value;
}

export function validateGitHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !GIT_HASH_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  return value;
}

export function validateIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  return value;
}

export function validateCanonicalTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  return value;
}

export function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
