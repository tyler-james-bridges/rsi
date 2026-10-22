import { createHash } from "node:crypto";

import type { JsonValue } from "./json-types.js";

const MAX_CANONICAL_DEPTH = 32;

export function hashCanonical(domain: string, value: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

export function hashText(domain: string, value: string): string {
  return createHash("sha256").update(domain, "utf8").update(value, "utf8").digest("hex");
}

export function canonicalJson(value: JsonValue): string {
  return serialize(value, new WeakSet<object>(), 0);
}

function serialize(value: JsonValue, ancestors: WeakSet<object>, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) throw new TypeError("attention_canonical_value_invalid");
  if (value === null) return "null";

  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("attention_canonical_value_invalid");
    return JSON.stringify(value);
  }

  if (ancestors.has(value)) throw new TypeError("attention_canonical_value_invalid");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => serialize(entry, ancestors, depth + 1)).join(",")}]`;
    }
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw new TypeError("attention_canonical_value_invalid");
      }
      const child = jsonValue(descriptor.value);
      return `${JSON.stringify(key)}:${serialize(child, ancestors, depth + 1)}`;
    });
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function jsonValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) return value.map(jsonValue);
  if (
    typeof value === "object" &&
    value !== null &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  ) {
    const result: { [key: string]: JsonValue } = {};
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw new TypeError("attention_canonical_value_invalid");
      }
      result[key] = jsonValue(descriptor.value);
    }
    return result;
  }
  throw new TypeError("attention_canonical_value_invalid");
}
