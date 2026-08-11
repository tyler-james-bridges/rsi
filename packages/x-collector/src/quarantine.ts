import {
  X_JSON_CONTENT_TYPES,
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_MAX_RESULTS,
  X_RECENT_SEARCH_MIN_RESULTS,
  X_RECENT_SEARCH_QUARANTINE_VERSION,
} from "./constants.js";
import { XCollectorError } from "./errors.js";
import { isSha256, sha256, type Sha256 } from "./hash.js";
import type { PreparedXRecentSearchRequest } from "./query.js";
import { isCanonicalAcquiredAt } from "./time.js";

export type XResponseProvenance = "network" | "cassette";

export type XQuarantineMetadata = Readonly<{
  version: typeof X_RECENT_SEARCH_QUARANTINE_VERSION;
  endpoint: typeof X_RECENT_SEARCH_ENDPOINT;
  requestFingerprint: Sha256;
  maxResults: number;
  acquiredAt: string;
  status: 200;
  contentType: string;
  byteLength: number;
  responseHash: Sha256;
  provenance: XResponseProvenance;
}>;

const QUARANTINE_METADATA_FIELDS = [
  "version",
  "endpoint",
  "requestFingerprint",
  "maxResults",
  "acquiredAt",
  "status",
  "contentType",
  "byteLength",
  "responseHash",
  "provenance",
] as const;

type QuarantineMetadataField = (typeof QUARANTINE_METADATA_FIELDS)[number];

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function readExactMetadata(value: unknown): Record<QuarantineMetadataField, unknown> | undefined {
  if (!isPlainRecord(value)) return undefined;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== QUARANTINE_METADATA_FIELDS.length ||
    keys.some(
      (key) =>
        typeof key !== "string" || !(QUARANTINE_METADATA_FIELDS as readonly string[]).includes(key),
    )
  ) {
    return undefined;
  }

  const result = Object.create(null) as Record<QuarantineMetadataField, unknown>;
  for (const key of QUARANTINE_METADATA_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      return undefined;
    }
    result[key] = descriptor.value;
  }
  return result;
}

/**
 * Untrusted response bytes. JSON.stringify intentionally emits metadata only; callers must use
 * copyBytes() and route live bodies through the encrypted vault before durable storage.
 */
export class QuarantinedXRecentSearchResponse {
  readonly metadata: XQuarantineMetadata;
  readonly #bytes: Uint8Array;

  constructor(metadata: XQuarantineMetadata, bytes: Uint8Array) {
    const values = readExactMetadata(metadata);
    const copiedBytes = bytes instanceof Uint8Array ? bytes.slice() : undefined;
    if (
      values === undefined ||
      copiedBytes === undefined ||
      values.version !== X_RECENT_SEARCH_QUARANTINE_VERSION ||
      values.endpoint !== X_RECENT_SEARCH_ENDPOINT ||
      values.status !== 200 ||
      !Number.isSafeInteger(values.maxResults) ||
      (values.maxResults as number) < X_RECENT_SEARCH_MIN_RESULTS ||
      (values.maxResults as number) > X_RECENT_SEARCH_MAX_RESULTS ||
      !Number.isSafeInteger(values.byteLength) ||
      (values.byteLength as number) < 0 ||
      values.byteLength !== copiedBytes.byteLength ||
      !isSha256(values.requestFingerprint) ||
      !isSha256(values.responseHash) ||
      !isCanonicalAcquiredAt(values.acquiredAt) ||
      typeof values.contentType !== "string" ||
      !(X_JSON_CONTENT_TYPES as readonly string[]).includes(values.contentType) ||
      sha256(copiedBytes) !== values.responseHash ||
      (values.provenance !== "network" && values.provenance !== "cassette")
    ) {
      throw new XCollectorError("INVALID_RESPONSE_SCHEMA", "Invalid quarantine metadata.");
    }
    this.metadata = Object.freeze({
      version: X_RECENT_SEARCH_QUARANTINE_VERSION,
      endpoint: X_RECENT_SEARCH_ENDPOINT,
      requestFingerprint: values.requestFingerprint,
      maxResults: values.maxResults as number,
      acquiredAt: values.acquiredAt,
      status: 200,
      contentType: values.contentType,
      byteLength: values.byteLength as number,
      responseHash: values.responseHash,
      provenance: values.provenance,
    });
    this.#bytes = copiedBytes;
    Object.freeze(this);
  }

  copyBytes(): Uint8Array {
    return this.#bytes.slice();
  }

  toJSON(): Readonly<{ metadata: XQuarantineMetadata; body: "quarantined" }> {
    return { metadata: this.metadata, body: "quarantined" };
  }
}

export function quarantineNetworkResponse(
  request: PreparedXRecentSearchRequest,
  status: 200,
  contentType: string,
  bytes: Uint8Array,
  acquiredAt: string,
): QuarantinedXRecentSearchResponse {
  return new QuarantinedXRecentSearchResponse(
    {
      version: X_RECENT_SEARCH_QUARANTINE_VERSION,
      endpoint: X_RECENT_SEARCH_ENDPOINT,
      requestFingerprint: request.fingerprint,
      maxResults: request.query.maxResults,
      acquiredAt,
      status,
      contentType,
      byteLength: bytes.byteLength,
      responseHash: sha256(bytes),
      provenance: "network",
    },
    bytes,
  );
}

export function quarantineCassetteResponse(
  request: PreparedXRecentSearchRequest,
  contentType: string,
  responseHash: Sha256,
  bytes: Uint8Array,
  acquiredAt: string,
): QuarantinedXRecentSearchResponse {
  return new QuarantinedXRecentSearchResponse(
    {
      version: X_RECENT_SEARCH_QUARANTINE_VERSION,
      endpoint: X_RECENT_SEARCH_ENDPOINT,
      requestFingerprint: request.fingerprint,
      maxResults: request.query.maxResults,
      acquiredAt,
      status: 200,
      contentType,
      byteLength: bytes.byteLength,
      responseHash,
      provenance: "cassette",
    },
    bytes,
  );
}
