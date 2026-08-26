import {
  isNetworkAttemptDispatchReceipt,
  type NetworkAttemptBinding,
  type NetworkAttemptDispatchReceipt,
} from "@rsi/operations";

import {
  OPENSEA_JSON_CONTENT_TYPES,
  OPENSEA_TRENDING_CONTRACT_VERSION,
  OPENSEA_TRENDING_MAXIMUM_BYTES,
  OPENSEA_TRENDING_MAXIMUM_RESULTS,
  OPENSEA_TRENDING_OPERATION,
  OPENSEA_TRENDING_QUARANTINE_VERSION,
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  OPENSEA_TRENDING_URL,
} from "./constants.js";
import { OpenSeaCollectorError } from "./errors.js";
import { isSha256, sha256, type Sha256 } from "./hash.js";
import {
  isPreparedOpenSeaTrendingCollectorRequest,
  prepareOpenSeaTrendingCollectorRequest,
  type PreparedOpenSeaTrendingCollectorRequest,
} from "./request.js";
import {
  copyOpenSeaRateLimitReceipt,
  isOpenSeaRateLimitReceipt,
  type OpenSeaRateLimitReceipt,
} from "./rate-limit.js";
import { isCanonicalOpenSeaAcquiredAt } from "./time.js";

export type OpenSeaTrendingQuarantineMetadata = Readonly<{
  networkAttempt: Readonly<NetworkAttemptDispatchReceipt>;
  version: typeof OPENSEA_TRENDING_QUARANTINE_VERSION;
  contractVersion: typeof OPENSEA_TRENDING_CONTRACT_VERSION;
  endpoint: typeof OPENSEA_TRENDING_URL;
  requestFingerprint: Sha256;
  maximumResults: typeof OPENSEA_TRENDING_MAXIMUM_RESULTS;
  acquiredAt: string;
  status: 200;
  contentType: string;
  byteLength: number;
  responseHash: Sha256;
  rateLimit: OpenSeaRateLimitReceipt | undefined;
}>;

const METADATA_FIELDS = [
  "networkAttempt",
  "version",
  "contractVersion",
  "endpoint",
  "requestFingerprint",
  "maximumResults",
  "acquiredAt",
  "status",
  "contentType",
  "byteLength",
  "responseHash",
  "rateLimit",
] as const;
type MetadataField = (typeof METADATA_FIELDS)[number];
const CONSTRUCTION_TOKEN = Object.freeze({ quarantine: true });
const AUTHENTIC_QUARANTINES = new WeakSet<object>();

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactMetadata(value: unknown): Record<MetadataField, unknown> | undefined {
  if (!isPlainRecord(value)) return undefined;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== METADATA_FIELDS.length ||
    keys.some(
      (key) => typeof key !== "string" || !(METADATA_FIELDS as readonly string[]).includes(key),
    )
  ) {
    return undefined;
  }
  const result = Object.create(null) as Record<MetadataField, unknown>;
  for (const key of METADATA_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      return undefined;
    }
    result[key] = descriptor.value;
  }
  return result;
}

/** Untrusted OpenSea bytes. JSON serialization intentionally emits metadata only. */
export class QuarantinedOpenSeaTrendingResponse {
  readonly metadata: OpenSeaTrendingQuarantineMetadata;
  readonly #bytes: Uint8Array;
  #destroyed = false;

  constructor(token: unknown, metadata: OpenSeaTrendingQuarantineMetadata, bytes: Uint8Array) {
    const values = exactMetadata(metadata);
    const copiedBytes = bytes instanceof Uint8Array ? new Uint8Array(bytes) : undefined;
    if (
      token !== CONSTRUCTION_TOKEN ||
      values === undefined ||
      copiedBytes === undefined ||
      !isNetworkAttemptDispatchReceipt(values.networkAttempt) ||
      values.networkAttempt.binding.operation !== OPENSEA_TRENDING_OPERATION ||
      values.networkAttempt.binding.lane !== "marketplace" ||
      values.networkAttempt.binding.sourcePlane !== "marketplace" ||
      values.networkAttempt.binding.reservedAtomic !== OPENSEA_TRENDING_RESERVED_ATOMIC ||
      !isCanonicalOpenSeaAcquiredAt(values.networkAttempt.binding.authorizationExpiresAt) ||
      !isCanonicalOpenSeaAcquiredAt(values.networkAttempt.dispatchedAt) ||
      values.version !== OPENSEA_TRENDING_QUARANTINE_VERSION ||
      values.contractVersion !== OPENSEA_TRENDING_CONTRACT_VERSION ||
      values.endpoint !== OPENSEA_TRENDING_URL ||
      values.maximumResults !== OPENSEA_TRENDING_MAXIMUM_RESULTS ||
      values.status !== 200 ||
      !Number.isSafeInteger(values.byteLength) ||
      (values.byteLength as number) < 0 ||
      (values.byteLength as number) > OPENSEA_TRENDING_MAXIMUM_BYTES ||
      values.byteLength !== copiedBytes.byteLength ||
      !isSha256(values.requestFingerprint) ||
      values.requestFingerprint !== prepareOpenSeaTrendingCollectorRequest().fingerprint ||
      !isSha256(values.responseHash) ||
      !isCanonicalOpenSeaAcquiredAt(values.acquiredAt) ||
      Date.parse(values.networkAttempt.dispatchedAt) > Date.parse(values.acquiredAt) ||
      Date.parse(values.networkAttempt.dispatchedAt) >
        Date.parse(values.networkAttempt.binding.authorizationExpiresAt) ||
      typeof values.contentType !== "string" ||
      !(OPENSEA_JSON_CONTENT_TYPES as readonly string[]).includes(values.contentType) ||
      sha256(copiedBytes) !== values.responseHash ||
      (values.rateLimit !== undefined && !isOpenSeaRateLimitReceipt(values.rateLimit))
    ) {
      copiedBytes?.fill(0);
      throw new OpenSeaCollectorError("INVALID_RESPONSE_SCHEMA", "Invalid quarantine metadata.");
    }
    this.metadata = Object.freeze({
      networkAttempt: values.networkAttempt,
      version: OPENSEA_TRENDING_QUARANTINE_VERSION,
      contractVersion: OPENSEA_TRENDING_CONTRACT_VERSION,
      endpoint: OPENSEA_TRENDING_URL,
      requestFingerprint: values.requestFingerprint,
      maximumResults: OPENSEA_TRENDING_MAXIMUM_RESULTS,
      acquiredAt: values.acquiredAt,
      status: 200,
      contentType: values.contentType,
      byteLength: values.byteLength as number,
      responseHash: values.responseHash,
      rateLimit:
        values.rateLimit === undefined
          ? undefined
          : copyOpenSeaRateLimitReceipt(values.rateLimit as OpenSeaRateLimitReceipt),
    });
    this.#bytes = copiedBytes;
    AUTHENTIC_QUARANTINES.add(this);
    Object.freeze(this);
  }

  copyBytes(): Uint8Array {
    this.#assertAuthentic();
    if (this.#destroyed) {
      throw new OpenSeaCollectorError(
        "INVALID_RESPONSE_SCHEMA",
        "The quarantined response has been destroyed.",
      );
    }
    return this.#bytes.slice();
  }

  destroy(): void {
    this.#assertAuthentic();
    if (this.#destroyed) return;
    this.#bytes.fill(0);
    this.#destroyed = true;
  }

  toJSON(): Readonly<{
    metadata: OpenSeaTrendingQuarantineMetadata;
    body: "quarantined";
  }> {
    this.#assertAuthentic();
    return { metadata: this.metadata, body: "quarantined" };
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_QUARANTINES.has(this) ||
      Object.getPrototypeOf(this) !== QuarantinedOpenSeaTrendingResponse.prototype
    ) {
      throw new OpenSeaCollectorError(
        "INVALID_RESPONSE_SCHEMA",
        "An authentic quarantined response is required.",
      );
    }
  }
}

Object.freeze(QuarantinedOpenSeaTrendingResponse.prototype);
Object.freeze(QuarantinedOpenSeaTrendingResponse);

export function isQuarantinedOpenSeaTrendingResponse(
  value: unknown,
): value is QuarantinedOpenSeaTrendingResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHENTIC_QUARANTINES.has(value) &&
    Object.getPrototypeOf(value) === QuarantinedOpenSeaTrendingResponse.prototype
  );
}

export function quarantineOpenSeaTrendingNetworkResponse(
  request: PreparedOpenSeaTrendingCollectorRequest,
  expectedBinding: Readonly<NetworkAttemptBinding>,
  dispatchReceipt: Readonly<NetworkAttemptDispatchReceipt>,
  status: 200,
  contentType: string,
  bytes: Uint8Array,
  acquiredAt: string,
  rateLimit?: OpenSeaRateLimitReceipt,
): QuarantinedOpenSeaTrendingResponse {
  if (
    !isPreparedOpenSeaTrendingCollectorRequest(request) ||
    !isNetworkAttemptDispatchReceipt(dispatchReceipt) ||
    dispatchReceipt.binding.operation !== OPENSEA_TRENDING_OPERATION ||
    dispatchReceipt.binding.lane !== "marketplace" ||
    dispatchReceipt.binding.sourcePlane !== "marketplace" ||
    dispatchReceipt.binding.reservedAtomic !== OPENSEA_TRENDING_RESERVED_ATOMIC ||
    dispatchReceipt.binding.attemptId !== expectedBinding.attemptId ||
    dispatchReceipt.binding.authorizationExpiresAt !== expectedBinding.authorizationExpiresAt ||
    dispatchReceipt.binding.lane !== expectedBinding.lane ||
    dispatchReceipt.binding.operation !== expectedBinding.operation ||
    dispatchReceipt.binding.profile !== expectedBinding.profile ||
    dispatchReceipt.binding.reservedAtomic !== expectedBinding.reservedAtomic ||
    dispatchReceipt.binding.sessionId !== expectedBinding.sessionId ||
    dispatchReceipt.binding.sourcePlane !== expectedBinding.sourcePlane ||
    status !== 200
  ) {
    throw new OpenSeaCollectorError(
      "INVALID_RESPONSE_SCHEMA",
      "The response does not belong to the fixed OpenSea trending request.",
    );
  }
  return new QuarantinedOpenSeaTrendingResponse(
    CONSTRUCTION_TOKEN,
    {
      networkAttempt: dispatchReceipt,
      version: OPENSEA_TRENDING_QUARANTINE_VERSION,
      contractVersion: OPENSEA_TRENDING_CONTRACT_VERSION,
      endpoint: OPENSEA_TRENDING_URL,
      requestFingerprint: request.fingerprint,
      maximumResults: OPENSEA_TRENDING_MAXIMUM_RESULTS,
      acquiredAt,
      status: 200,
      contentType,
      byteLength: bytes.byteLength,
      responseHash: sha256(bytes),
      rateLimit: copyOpenSeaRateLimitReceipt(rateLimit),
    },
    bytes,
  );
}
