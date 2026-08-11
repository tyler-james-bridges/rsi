import type { JsonValue } from "./types.js";

const MAX_CANONICAL_DEPTH = 100;

export class InvalidJsonValueError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidJsonValueError";
  }
}

/**
 * Serializes JSON with recursively sorted object keys. Arrays retain their
 * original order. Values that JSON would silently discard or coerce are
 * rejected so the persisted bytes cannot depend on caller-specific objects.
 */
export function canonicalJson(value: JsonValue): string {
  return serialize(value, new WeakSet<object>(), 0);
}

function serialize(value: unknown, ancestors: WeakSet<object>, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new InvalidJsonValueError(
      `JSON nesting exceeds the maximum depth of ${MAX_CANONICAL_DEPTH}`,
    );
  }

  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new InvalidJsonValueError("JSON numbers must be finite");
      }
      return JSON.stringify(value);
    case "bigint":
    case "function":
    case "symbol":
    case "undefined":
      throw new InvalidJsonValueError(`Unsupported JSON value: ${typeof value}`);
    case "object":
      break;
  }

  const objectValue = value as object;
  if (ancestors.has(objectValue)) {
    throw new InvalidJsonValueError("Circular JSON values are not supported");
  }
  ancestors.add(objectValue);

  try {
    if (Array.isArray(value)) {
      const parts: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new InvalidJsonValueError("Sparse arrays are not supported");
        }
        parts.push(serialize(value[index], ancestors, depth + 1));
      }
      return `[${parts.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new InvalidJsonValueError("JSON objects must be plain objects");
    }

    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const parts = keys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw new InvalidJsonValueError("JSON objects may not contain accessors");
      }
      return `${JSON.stringify(key)}:${serialize(descriptor.value, ancestors, depth + 1)}`;
    });
    return `{${parts.join(",")}}`;
  } finally {
    ancestors.delete(objectValue);
  }
}

export function deepFreezeJson(value: JsonValue): JsonValue {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) {
      deepFreezeJson(child);
    }
    Object.freeze(value);
  }
  return value;
}
