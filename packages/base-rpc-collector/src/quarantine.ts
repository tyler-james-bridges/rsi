import {
  isNetworkAttemptDispatchReceipt,
  type NetworkAttemptBinding,
  type NetworkAttemptDispatchReceipt,
} from "@rsi/operations";

import {
  BASE_RPC_ANCHOR_CONTRACT_VERSION,
  BASE_RPC_ANCHOR_LANE,
  BASE_RPC_ANCHOR_MAXIMUM_BYTES,
  BASE_RPC_ANCHOR_OPERATION,
  BASE_RPC_ANCHOR_QUARANTINE_VERSION,
  BASE_RPC_ANCHOR_RESERVED_ATOMIC,
  BASE_RPC_ANCHOR_SOURCE_PLANE,
  BASE_RPC_ANCHOR_URL,
  BASE_RPC_JSON_CONTENT_TYPES,
} from "./constants.js";
import { BaseRpcCollectorError } from "./errors.js";
import { isSha256, sha256, type Sha256 } from "./hash.js";
import {
  isPreparedBaseRpcAnchorCollectorRequest,
  prepareBaseRpcAnchorCollectorRequest,
  type PreparedBaseRpcAnchorCollectorRequest,
} from "./request.js";
import { isCanonicalBaseRpcAcquiredAt } from "./time.js";

export type BaseRpcAnchorQuarantineMetadata = Readonly<{
  networkAttempt: Readonly<NetworkAttemptDispatchReceipt>;
  version: typeof BASE_RPC_ANCHOR_QUARANTINE_VERSION;
  contractVersion: typeof BASE_RPC_ANCHOR_CONTRACT_VERSION;
  endpoint: typeof BASE_RPC_ANCHOR_URL;
  requestFingerprint: Sha256;
  acquiredAt: string;
  status: 200;
  contentType: string;
  byteLength: number;
  responseHash: Sha256;
}>;

const METADATA_FIELDS = [
  "networkAttempt",
  "version",
  "contractVersion",
  "endpoint",
  "requestFingerprint",
  "acquiredAt",
  "status",
  "contentType",
  "byteLength",
  "responseHash",
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

/** Untrusted provider bytes. JSON serialization intentionally emits metadata only. */
export class QuarantinedBaseRpcAnchorResponse {
  readonly metadata: BaseRpcAnchorQuarantineMetadata;
  readonly #bytes: Uint8Array;
  #destroyed = false;

  constructor(token: unknown, metadata: BaseRpcAnchorQuarantineMetadata, bytes: Uint8Array) {
    const values = exactMetadata(metadata);
    const copiedBytes = bytes instanceof Uint8Array ? new Uint8Array(bytes) : undefined;
    if (
      token !== CONSTRUCTION_TOKEN ||
      values === undefined ||
      copiedBytes === undefined ||
      !isNetworkAttemptDispatchReceipt(values.networkAttempt) ||
      values.networkAttempt.binding.operation !== BASE_RPC_ANCHOR_OPERATION ||
      values.networkAttempt.binding.lane !== BASE_RPC_ANCHOR_LANE ||
      values.networkAttempt.binding.sourcePlane !== BASE_RPC_ANCHOR_SOURCE_PLANE ||
      values.networkAttempt.binding.reservedAtomic !== BASE_RPC_ANCHOR_RESERVED_ATOMIC ||
      !isCanonicalBaseRpcAcquiredAt(values.networkAttempt.binding.authorizationExpiresAt) ||
      !isCanonicalBaseRpcAcquiredAt(values.networkAttempt.dispatchedAt) ||
      values.version !== BASE_RPC_ANCHOR_QUARANTINE_VERSION ||
      values.contractVersion !== BASE_RPC_ANCHOR_CONTRACT_VERSION ||
      values.endpoint !== BASE_RPC_ANCHOR_URL ||
      values.status !== 200 ||
      !Number.isSafeInteger(values.byteLength) ||
      (values.byteLength as number) < 1 ||
      (values.byteLength as number) > BASE_RPC_ANCHOR_MAXIMUM_BYTES ||
      values.byteLength !== copiedBytes.byteLength ||
      !isSha256(values.requestFingerprint) ||
      values.requestFingerprint !== prepareBaseRpcAnchorCollectorRequest().fingerprint ||
      !isSha256(values.responseHash) ||
      !isCanonicalBaseRpcAcquiredAt(values.acquiredAt) ||
      Date.parse(values.networkAttempt.dispatchedAt) > Date.parse(values.acquiredAt) ||
      Date.parse(values.networkAttempt.dispatchedAt) >
        Date.parse(values.networkAttempt.binding.authorizationExpiresAt) ||
      typeof values.contentType !== "string" ||
      !(BASE_RPC_JSON_CONTENT_TYPES as readonly string[]).includes(values.contentType) ||
      sha256(copiedBytes) !== values.responseHash
    ) {
      copiedBytes?.fill(0);
      throw new BaseRpcCollectorError("INVALID_RESPONSE_SCHEMA", "Invalid quarantine metadata.");
    }
    this.metadata = Object.freeze({
      networkAttempt: values.networkAttempt,
      version: BASE_RPC_ANCHOR_QUARANTINE_VERSION,
      contractVersion: BASE_RPC_ANCHOR_CONTRACT_VERSION,
      endpoint: BASE_RPC_ANCHOR_URL,
      requestFingerprint: values.requestFingerprint,
      acquiredAt: values.acquiredAt,
      status: 200,
      contentType: values.contentType,
      byteLength: values.byteLength as number,
      responseHash: values.responseHash,
    });
    this.#bytes = copiedBytes;
    AUTHENTIC_QUARANTINES.add(this);
    Object.freeze(this);
  }

  copyBytes(): Uint8Array {
    this.#assertAuthentic();
    if (this.#destroyed) {
      throw new BaseRpcCollectorError(
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
    metadata: BaseRpcAnchorQuarantineMetadata;
    body: "quarantined";
  }> {
    this.#assertAuthentic();
    return { metadata: this.metadata, body: "quarantined" };
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_QUARANTINES.has(this) ||
      Object.getPrototypeOf(this) !== QuarantinedBaseRpcAnchorResponse.prototype
    ) {
      throw new BaseRpcCollectorError(
        "INVALID_RESPONSE_SCHEMA",
        "An authentic quarantined response is required.",
      );
    }
  }
}

Object.freeze(QuarantinedBaseRpcAnchorResponse.prototype);
Object.freeze(QuarantinedBaseRpcAnchorResponse);

export function isQuarantinedBaseRpcAnchorResponse(
  value: unknown,
): value is QuarantinedBaseRpcAnchorResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHENTIC_QUARANTINES.has(value) &&
    Object.getPrototypeOf(value) === QuarantinedBaseRpcAnchorResponse.prototype
  );
}

export function quarantineBaseRpcAnchorNetworkResponse(
  request: PreparedBaseRpcAnchorCollectorRequest,
  expectedBinding: Readonly<NetworkAttemptBinding>,
  dispatchReceipt: Readonly<NetworkAttemptDispatchReceipt>,
  status: 200,
  contentType: string,
  bytes: Uint8Array,
  acquiredAt: string,
): QuarantinedBaseRpcAnchorResponse {
  if (
    !isPreparedBaseRpcAnchorCollectorRequest(request) ||
    !isNetworkAttemptDispatchReceipt(dispatchReceipt) ||
    dispatchReceipt.binding.operation !== BASE_RPC_ANCHOR_OPERATION ||
    dispatchReceipt.binding.lane !== BASE_RPC_ANCHOR_LANE ||
    dispatchReceipt.binding.sourcePlane !== BASE_RPC_ANCHOR_SOURCE_PLANE ||
    dispatchReceipt.binding.reservedAtomic !== BASE_RPC_ANCHOR_RESERVED_ATOMIC ||
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
    throw new BaseRpcCollectorError(
      "INVALID_RESPONSE_SCHEMA",
      "The response does not belong to the fixed Base RPC anchor request.",
    );
  }
  return new QuarantinedBaseRpcAnchorResponse(
    CONSTRUCTION_TOKEN,
    {
      networkAttempt: dispatchReceipt,
      version: BASE_RPC_ANCHOR_QUARANTINE_VERSION,
      contractVersion: BASE_RPC_ANCHOR_CONTRACT_VERSION,
      endpoint: BASE_RPC_ANCHOR_URL,
      requestFingerprint: request.fingerprint,
      acquiredAt,
      status: 200,
      contentType,
      byteLength: bytes.byteLength,
      responseHash: sha256(bytes),
    },
    bytes,
  );
}
