import { PublicProjectionError } from "./errors.js";

const textEncoder = new TextEncoder();

export function assertPlainData(value: unknown): void {
  inspectPlainData(value, new WeakSet<object>());

  // A transparent Proxy can imitate descriptors and prototypes. The structured-clone
  // algorithm rejects Proxy objects, while the descriptor walk above ensures getters
  // are never invoked before that check. JSON-originated browser data passes unchanged.
  if (value !== null && typeof value === "object" && typeof structuredClone === "function") {
    try {
      structuredClone(value);
    } catch {
      failInput();
    }
  }
}

export function canonicalJson(value: unknown): string {
  assertPlainData(value);
  return JSON.stringify(sortValue(value));
}

export function canonicalBytes(value: unknown): Uint8Array {
  return textEncoder.encode(canonicalJson(value));
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

export function hex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

export function failInput(): never {
  throw new PublicProjectionError("INPUT_INVALID");
}

function inspectPlainData(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (ancestors.has(value)) failInput();
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) failInput();
    const keys = Reflect.ownKeys(value);
    if (
      keys.some(
        (key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9]\d*)$/.test(key)),
      )
    ) {
      failInput();
    }
    ancestors.add(value);
    try {
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          failInput();
        }
        inspectPlainData(descriptor.value, ancestors);
      }
    } finally {
      ancestors.delete(value);
    }
    return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) failInput();
  ancestors.add(value);
  try {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") failInput();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        failInput();
      }
      inspectPlainData(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) failInput();
      result[key] = sortValue(descriptor.value);
    }
    return result;
  }
  return value;
}
