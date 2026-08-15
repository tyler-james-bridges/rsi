import { SnapshotIntegrityError, SnapshotValidationError } from "./errors.js";
import type {
  CaptureDeletionReason,
  CaptureDeletionReceiptV1,
  CaptureId,
  CaptureMetadataV1,
  CaptureSource,
} from "./types.js";

const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MEDIA_TYPE =
  /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(?:; ?[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}=[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,127})*$/;
const SOURCES = new Set<CaptureSource>(["alchemy", "fixture", "opensea", "x"]);
const DELETION_REASONS = new Set<CaptureDeletionReason>(["expired", "explicit"]);
const METADATA_KEYS = ["acquiredAt", "expiresAt", "mediaType", "schemaVersion", "source"];
const RECEIPT_KEYS = ["captureId", "deletedAt", "keyDestroyed", "reason", "schemaVersion", "state"];

export interface PreparedMetadata {
  readonly bytes: Buffer;
  readonly value: CaptureMetadataV1;
}

export interface PreparedDeletionReceipt {
  readonly bytes: Buffer;
  readonly value: CaptureDeletionReceiptV1;
}

export function prepareCaptureMetadata(value: unknown, maxBytes: number): PreparedMetadata {
  const record = exactDataRecord(value, METADATA_KEYS, "Capture metadata");
  if (record.schemaVersion !== 1) {
    throw new SnapshotValidationError("Capture metadata schemaVersion must be 1");
  }
  if (typeof record.source !== "string" || !SOURCES.has(record.source as CaptureSource)) {
    throw new SnapshotValidationError("Capture metadata source is unsupported");
  }
  const acquiredAt = validateCanonicalTimestamp(record.acquiredAt, "acquiredAt");
  const expiresAt = validateCanonicalTimestamp(record.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) < Date.parse(acquiredAt)) {
    throw new SnapshotValidationError("Capture metadata expiresAt must not precede acquiredAt");
  }
  if (typeof record.mediaType !== "string" || !MEDIA_TYPE.test(record.mediaType)) {
    throw new SnapshotValidationError("Capture metadata mediaType is invalid");
  }

  const metadata: CaptureMetadataV1 = Object.freeze({
    acquiredAt,
    expiresAt,
    mediaType: record.mediaType,
    schemaVersion: 1,
    source: record.source as CaptureSource,
  });
  const bytes = Buffer.from(JSON.stringify(metadata), "utf8");
  if (bytes.byteLength > maxBytes) {
    bytes.fill(0);
    throw new SnapshotValidationError("Capture metadata exceeds the configured byte limit");
  }
  return { bytes, value: metadata };
}

export function prepareDeletionReceipt(
  value: unknown,
  expectedCaptureId?: CaptureId,
): PreparedDeletionReceipt {
  const record = exactDataRecord(value, RECEIPT_KEYS, "Capture deletion receipt");
  if (record.schemaVersion !== 1 || record.state !== "deleted" || record.keyDestroyed !== true) {
    throw new SnapshotValidationError("Capture deletion receipt has an invalid schema");
  }
  if (
    typeof record.captureId !== "string" ||
    (expectedCaptureId !== undefined && record.captureId !== expectedCaptureId)
  ) {
    throw new SnapshotValidationError("Capture deletion receipt has an invalid capture ID");
  }
  const deletedAt = validateCanonicalTimestamp(record.deletedAt, "deletedAt");
  if (
    typeof record.reason !== "string" ||
    !DELETION_REASONS.has(record.reason as CaptureDeletionReason)
  ) {
    throw new SnapshotValidationError("Capture deletion receipt reason is unsupported");
  }
  const receipt: CaptureDeletionReceiptV1 = Object.freeze({
    captureId: record.captureId as CaptureId,
    deletedAt,
    keyDestroyed: true,
    reason: record.reason as CaptureDeletionReason,
    schemaVersion: 1,
    state: "deleted",
  });
  return { bytes: Buffer.from(JSON.stringify(receipt), "utf8"), value: receipt };
}

export function decodeMetadata(bytes: Buffer, maxBytes: number): PreparedMetadata {
  return decodeCanonical(bytes, (parsed) => prepareCaptureMetadata(parsed, maxBytes));
}

export function decodeDeletionReceipt(
  bytes: Buffer,
  expectedCaptureId: CaptureId,
): PreparedDeletionReceipt {
  return decodeCanonical(bytes, (parsed) => prepareDeletionReceipt(parsed, expectedCaptureId));
}

export function validateCanonicalTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string" || !CANONICAL_TIMESTAMP.test(value)) {
    throw new SnapshotValidationError(`Capture ${field} must be a canonical UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new SnapshotValidationError(`Capture ${field} must be a canonical UTC timestamp`);
  }
  return value;
}

function decodeCanonical<T extends { readonly bytes: Buffer }>(
  bytes: Buffer,
  prepare: (parsed: unknown) => T,
): T {
  let prepared: T | undefined;
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    prepared = prepare(JSON.parse(decoded) as unknown);
    if (!prepared.bytes.equals(bytes)) {
      throw new SnapshotIntegrityError();
    }
    return prepared;
  } catch {
    prepared?.bytes.fill(0);
    throw new SnapshotIntegrityError();
  }
}

function exactDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SnapshotValidationError(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new SnapshotValidationError(`${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !(keys as string[]).every((key) => expectedKeys.includes(key))
  ) {
    throw new SnapshotValidationError(`${label} must match its exact schema`);
  }
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SnapshotValidationError(`${label} must contain enumerable data properties`);
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}
