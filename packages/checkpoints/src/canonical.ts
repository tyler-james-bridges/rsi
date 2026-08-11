import { Buffer } from "node:buffer";

import { InvalidCheckpointError } from "./errors.js";
import {
  CHECKPOINT_PAYLOAD_VERSION,
  CHECKPOINT_TYPE,
  type CheckpointJournalHead,
  type CheckpointPayload,
  type SignedCheckpoint,
} from "./types.js";

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_CANONICAL_DEPTH = 16;

export function canonicalJson(value: unknown): string {
  return serialize(value, new WeakSet<object>(), 0);
}

function serialize(value: unknown, ancestors: WeakSet<object>, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new InvalidCheckpointError(
      `Canonical JSON nesting exceeds the maximum depth of ${MAX_CANONICAL_DEPTH}`,
    );
  }
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new InvalidCheckpointError("Numbers must be finite");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new InvalidCheckpointError(`Unsupported canonical JSON value: ${typeof value}`);
  }
  if (ancestors.has(value)) throw new InvalidCheckpointError("Circular values are not supported");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const parts: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new InvalidCheckpointError("Sparse arrays are not supported");
        }
        parts.push(serialize(value[index], ancestors, depth + 1));
      }
      return `[${parts.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new InvalidCheckpointError("Canonical JSON objects must be plain objects");
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(record, key);
        if (descriptor === undefined || !("value" in descriptor)) {
          throw new InvalidCheckpointError("Canonical JSON objects may not contain accessors");
        }
        return `${JSON.stringify(key)}:${serialize(descriptor.value, ancestors, depth + 1)}`;
      })
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function validateIdentifier(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new InvalidCheckpointError(
      `${field} must be 1-128 ASCII letters, digits, dots, underscores, colons, slashes, or hyphens`,
    );
  }
}

export function validateHash(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new InvalidCheckpointError(`${field} must be a lowercase SHA-256 digest`);
  }
}

export function validateCanonicalTimestamp(
  value: unknown,
  field = "createdAt",
): asserts value is string {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) {
    throw new InvalidCheckpointError(`${field} must be a canonical UTC ISO timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new InvalidCheckpointError(`${field} must be a valid canonical UTC ISO timestamp`);
  }
}

export function validateSafeInteger(
  value: unknown,
  field: string,
  minimum: number,
): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new InvalidCheckpointError(`${field} must be a safe integer of at least ${minimum}`);
  }
}

function assertExactKeys(
  record: Record<string, unknown>,
  expected: readonly string[],
  field: string,
): void {
  const actual = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new InvalidCheckpointError(`${field} has unknown or missing fields`);
  }
}

export function validateExactObjectKeys(
  value: object,
  expected: readonly string[],
  field: string,
): void {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new InvalidCheckpointError(`${field} must be a plain object`);
  }
  assertExactKeys(value as Record<string, unknown>, expected, field);
}

function asRecord(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidCheckpointError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function parseCheckpointPayload(value: unknown): CheckpointPayload {
  const record = asRecord(value, "payload");
  assertExactKeys(
    record,
    [
      "checkpointType",
      "createdAt",
      "journalSequence",
      "keyId",
      "previousCheckpointHash",
      "storeHeadHash",
      "storeHeadSequence",
      "storeId",
      "version",
    ],
    "payload",
  );
  if (record.version !== CHECKPOINT_PAYLOAD_VERSION) {
    throw new InvalidCheckpointError(
      `Unsupported checkpoint payload version: ${String(record.version)}`,
    );
  }
  if (record.checkpointType !== CHECKPOINT_TYPE) {
    throw new InvalidCheckpointError(`checkpointType must be ${CHECKPOINT_TYPE}`);
  }
  validateCanonicalTimestamp(record.createdAt);
  validateSafeInteger(record.journalSequence, "journalSequence", 1);
  validateIdentifier(record.keyId, "keyId");
  validateHash(record.previousCheckpointHash, "previousCheckpointHash");
  validateHash(record.storeHeadHash, "storeHeadHash");
  validateSafeInteger(record.storeHeadSequence, "storeHeadSequence", 0);
  validateIdentifier(record.storeId, "storeId");
  return Object.freeze({
    checkpointType: CHECKPOINT_TYPE,
    createdAt: record.createdAt,
    journalSequence: record.journalSequence,
    keyId: record.keyId,
    previousCheckpointHash: record.previousCheckpointHash,
    storeHeadHash: record.storeHeadHash,
    storeHeadSequence: record.storeHeadSequence,
    storeId: record.storeId,
    version: CHECKPOINT_PAYLOAD_VERSION,
  });
}

export function decodeSignature(value: unknown): Buffer {
  if (typeof value !== "string" || !SIGNATURE_PATTERN.test(value)) {
    throw new InvalidCheckpointError("signature must be an unpadded base64url Ed25519 signature");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 64 || decoded.toString("base64url") !== value) {
    throw new InvalidCheckpointError("signature is not canonical 64-byte base64url");
  }
  return decoded;
}

export function parseSignedCheckpoint(value: unknown): SignedCheckpoint {
  const record = asRecord(value, "journal entry");
  assertExactKeys(record, ["checkpointHash", "payload", "signature"], "journal entry");
  validateHash(record.checkpointHash, "checkpointHash");
  const payload = parseCheckpointPayload(record.payload);
  decodeSignature(record.signature);
  return Object.freeze({
    checkpointHash: record.checkpointHash,
    payload,
    signature: record.signature as string,
  });
}

export function validateJournalHead(value: unknown, field: string): CheckpointJournalHead {
  const record = asRecord(value, field);
  assertExactKeys(record, ["checkpointHash", "journalSequence"], field);
  validateHash(record.checkpointHash, `${field}.checkpointHash`);
  validateSafeInteger(record.journalSequence, `${field}.journalSequence`, 1);
  return Object.freeze({
    checkpointHash: record.checkpointHash,
    journalSequence: record.journalSequence,
  });
}

export function freezeCheckpoint(entry: SignedCheckpoint): SignedCheckpoint {
  Object.freeze(entry.payload);
  return Object.freeze(entry);
}
