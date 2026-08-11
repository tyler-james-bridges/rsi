import { SnapshotValidationError } from "./errors.js";
import type { SnapshotMetadata, SnapshotMetadataValue } from "./types.js";

const MAX_METADATA_DEPTH = 16;
const MAX_METADATA_NODES = 2_048;
const MAX_METADATA_PROPERTIES = 256;
const MAX_METADATA_ARRAY_LENGTH = 256;
const MAX_METADATA_KEY_BYTES = 256;
const MAX_METADATA_STRING_BYTES = 16_384;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

interface ValidationState {
  readonly ancestors: WeakSet<object>;
  nodes: number;
}

export interface PreparedMetadata {
  readonly bytes: Buffer;
  readonly value: SnapshotMetadata;
}

export function prepareMetadata(
  metadata: SnapshotMetadata | undefined,
  maxBytes: number,
): PreparedMetadata {
  const source: unknown = metadata ?? {};
  if (!isPlainObject(source)) {
    throw new SnapshotValidationError("Snapshot metadata must be a plain object");
  }

  const state: ValidationState = { ancestors: new WeakSet(), nodes: 0 };
  const value = cloneValue(source, 0, state);
  if (!isPlainObject(value)) {
    throw new SnapshotValidationError("Snapshot metadata must be a plain object");
  }

  const canonical = canonicalJson(value);
  const bytes = Buffer.from(canonical, "utf8");
  if (bytes.byteLength > maxBytes) {
    throw new SnapshotValidationError("Snapshot metadata exceeds the configured byte limit");
  }

  return { bytes, value: value as SnapshotMetadata };
}

function cloneValue(value: unknown, depth: number, state: ValidationState): SnapshotMetadataValue {
  state.nodes += 1;
  if (state.nodes > MAX_METADATA_NODES || depth > MAX_METADATA_DEPTH) {
    throw new SnapshotValidationError("Snapshot metadata exceeds structural limits");
  }

  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new SnapshotValidationError("Snapshot metadata contains an unsupported number");
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_METADATA_STRING_BYTES) {
      throw new SnapshotValidationError("Snapshot metadata contains an oversized string");
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new SnapshotValidationError("Snapshot metadata contains an unsupported value");
  }
  if (state.ancestors.has(value)) {
    throw new SnapshotValidationError("Snapshot metadata must not contain cycles");
  }

  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return cloneArray(value, depth, state);
    }
    if (!isPlainObject(value)) {
      throw new SnapshotValidationError("Snapshot metadata must contain only plain JSON values");
    }
    return cloneObject(value, depth, state);
  } finally {
    state.ancestors.delete(value);
  }
}

function cloneArray(
  value: readonly unknown[],
  depth: number,
  state: ValidationState,
): readonly SnapshotMetadataValue[] {
  if (value.length > MAX_METADATA_ARRAY_LENGTH) {
    throw new SnapshotValidationError("Snapshot metadata array exceeds the item limit");
  }

  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.some(
      (key) =>
        typeof key !== "string" ||
        (key !== "length" &&
          (!/^(0|[1-9][0-9]*)$/.test(key) ||
            !Number.isSafeInteger(Number(key)) ||
            Number(key) >= value.length ||
            String(Number(key)) !== key)),
    )
  ) {
    throw new SnapshotValidationError("Snapshot metadata arrays must not have custom properties");
  }

  const result: SnapshotMetadataValue[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SnapshotValidationError("Snapshot metadata arrays must be dense data arrays");
    }
    result.push(cloneValue(descriptor.value, depth + 1, state));
  }
  return Object.freeze(result);
}

function cloneObject(
  value: Readonly<Record<string, unknown>>,
  depth: number,
  state: ValidationState,
): Readonly<Record<string, SnapshotMetadataValue>> {
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length > MAX_METADATA_PROPERTIES || ownKeys.some((key) => typeof key !== "string")) {
    throw new SnapshotValidationError("Snapshot metadata object exceeds the property limit");
  }

  const result: Record<string, SnapshotMetadataValue> = {};
  for (const key of (ownKeys as string[]).sort()) {
    if (UNSAFE_KEYS.has(key) || Buffer.byteLength(key, "utf8") > MAX_METADATA_KEY_BYTES) {
      throw new SnapshotValidationError("Snapshot metadata contains an unsafe property name");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SnapshotValidationError(
        "Snapshot metadata properties must be enumerable data values",
      );
    }
    result[key] = cloneValue(descriptor.value, depth + 1, state);
  }
  return Object.freeze(result);
}

function canonicalJson(value: SnapshotMetadataValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const objectValue = value as Readonly<Record<string, SnapshotMetadataValue>>;
  return `{${Object.keys(objectValue)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(objectValue[key]!)}`)
    .join(",")}}`;
}

function isPlainObject(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
