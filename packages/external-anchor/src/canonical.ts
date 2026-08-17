import { types as utilTypes } from "node:util";

import { ExternalAnchorValidationError } from "./errors.js";

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_DEPTH = 16;

export function assertNotProxy(value: object | Function, field: string): void {
  if (utilTypes.isProxy(value)) {
    throw new ExternalAnchorValidationError(`${field} may not be a Proxy`);
  }
}

export function strictRecord(
  value: unknown,
  expectedKeys: readonly string[],
  field: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ExternalAnchorValidationError(`${field} must be an object`);
  }
  assertNotProxy(value, field);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ExternalAnchorValidationError(`${field} must be a plain object`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new ExternalAnchorValidationError(`${field} may not contain symbol fields`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actualKeys = Object.keys(descriptors).sort();
  const expected = [...expectedKeys].sort();
  if (
    actualKeys.length !== expected.length ||
    actualKeys.some((key, index) => key !== expected[index])
  ) {
    throw new ExternalAnchorValidationError(`${field} has unknown or missing fields`);
  }
  const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new ExternalAnchorValidationError(`${field} may contain only enumerable data fields`);
    }
    record[key] = descriptor.value;
  }
  return Object.freeze(record);
}

export function strictArray(value: unknown, field: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new ExternalAnchorValidationError(`${field} must be an array`);
  assertNotProxy(value, field);
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new ExternalAnchorValidationError(`${field} may not contain symbol fields`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const expectedKeys = Array.from({ length: value.length }, (_, index) => String(index));
  const actualKeys = Object.keys(descriptors)
    .filter((key) => key !== "length")
    .sort((left, right) => Number(left) - Number(right));
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new ExternalAnchorValidationError(`${field} must be dense and have no extra fields`);
  }
  const result: unknown[] = [];
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new ExternalAnchorValidationError(`${field} may contain only enumerable data items`);
    }
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

export function canonicalJson(value: unknown): string {
  return serialize(value, new WeakSet<object>(), 0);
}

function serialize(value: unknown, ancestors: WeakSet<object>, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new ExternalAnchorValidationError(`Canonical JSON exceeds depth ${MAX_DEPTH}`);
  }
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new ExternalAnchorValidationError("Canonical JSON numbers must be finite");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new ExternalAnchorValidationError(
      `Canonical JSON does not support ${typeof value} values`,
    );
  }
  assertNotProxy(value, "Canonical JSON value");
  if (ancestors.has(value)) {
    throw new ExternalAnchorValidationError("Canonical JSON may not contain cycles");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${strictArray(value, "Canonical JSON array")
        .map((item) => serialize(item, ancestors, depth + 1))
        .join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new ExternalAnchorValidationError("Canonical JSON objects must be plain objects");
    }
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new ExternalAnchorValidationError("Canonical JSON objects may not contain symbols");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return `{${Object.keys(descriptors)
      .sort()
      .map((key) => {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new ExternalAnchorValidationError(
            "Canonical JSON objects may contain only enumerable data fields",
          );
        }
        return `${JSON.stringify(key)}:${serialize(descriptor.value, ancestors, depth + 1)}`;
      })
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function validateHash(value: unknown, field: string): string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new ExternalAnchorValidationError(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

export function validateIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new ExternalAnchorValidationError(`${field} must be a closed ASCII identifier`);
  }
  return value;
}

export function validateTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) {
    throw new ExternalAnchorValidationError(`${field} must be canonical UTC milliseconds`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new ExternalAnchorValidationError(`${field} must be a valid canonical timestamp`);
  }
  return value;
}

export function validateSafeInteger(value: unknown, field: string, minimum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new ExternalAnchorValidationError(`${field} must be a safe integer >= ${minimum}`);
  }
  return value as number;
}

export function validateString(value: unknown, field: string, maxBytes: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > maxBytes
  ) {
    throw new ExternalAnchorValidationError(`${field} must be a non-empty bounded string`);
  }
  return value;
}
