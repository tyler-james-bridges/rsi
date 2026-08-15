import {
  X_JSON_CONTENT_TYPES,
  X_RECENT_SEARCH_CASSETTE_VERSION,
  X_RECENT_SEARCH_MAX_RESPONSE_BYTES,
} from "./constants.js";
import { XCollectorError } from "./errors.js";
import { isSha256, sha256, type Sha256 } from "./hash.js";
import type { QuarantinedXRecentSearchResponse } from "./quarantine.js";
import { prepareRecentSearchRequest, type PreparedXRecentSearchRequest } from "./query.js";
import { isCanonicalAcquiredAt } from "./time.js";

export type XRecentSearchCassette = Readonly<{
  version: typeof X_RECENT_SEARCH_CASSETTE_VERSION;
  acquiredAt: string;
  request: Readonly<{
    fingerprint: Sha256;
    canonicalRequest: string;
  }>;
  response: Readonly<{
    status: 200;
    contentType: string;
    byteLength: number;
    bodySha256: Sha256;
    bodyBase64: string;
  }>;
  integritySha256: Sha256;
}>;

export interface XRecentSearchCassetteStore {
  get(fingerprint: Sha256): Promise<unknown | undefined>;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const ownKeys = Reflect.ownKeys(value);
  return (
    ownKeys.length === keys.length &&
    ownKeys.every((key) => typeof key === "string" && keys.includes(key))
  );
}

function invalidCassette(): never {
  throw new XCollectorError("INVALID_CASSETTE", "Cassette validation failed.");
}

function cassetteIntegrity(input: {
  version: string;
  acquiredAt: string;
  request: { fingerprint: string; canonicalRequest: string };
  response: {
    status: number;
    contentType: string;
    byteLength: number;
    bodySha256: string;
    bodyBase64: string;
  };
}): Sha256 {
  return sha256(
    [
      input.version,
      input.acquiredAt,
      input.request.fingerprint,
      input.request.canonicalRequest,
      String(input.response.status),
      input.response.contentType,
      String(input.response.byteLength),
      input.response.bodySha256,
      input.response.bodyBase64,
    ].join("\n"),
  );
}

function normalizedJsonContentType(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  return (X_JSON_CONTENT_TYPES as readonly string[]).includes(normalized) ? normalized : undefined;
}

function decodeCanonicalBase64(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    invalidCassette();
  }
  const decoded = Buffer.from(value, "base64");
  try {
    const bytes = new Uint8Array(decoded);
    if (
      Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64") !== value
    ) {
      bytes.fill(0);
      invalidCassette();
    }
    return bytes;
  } finally {
    decoded.fill(0);
  }
}

function validateCanonicalRequest(canonicalRequest: string, fingerprint: Sha256): void {
  const lines = canonicalRequest.split("\n");
  if (lines.length !== 3) invalidCassette();
  const queryLine = lines[2];
  if (queryLine === undefined) invalidCassette();
  const parameters = new URLSearchParams(queryLine);
  const entries = [...parameters.entries()];
  const requiredKeys = ["expansions", "max_results", "post.fields", "query", "user.fields"];
  const allowedKeys = new Set([...requiredKeys, "next_token"]);
  if (
    entries.some(([key]) => !allowedKeys.has(key)) ||
    requiredKeys.some((key) => parameters.getAll(key).length !== 1) ||
    parameters.getAll("next_token").length > 1
  ) {
    invalidCassette();
  }

  const maxResultsText = parameters.get("max_results");
  if (maxResultsText === null || !/^(?:0|[1-9][0-9]*)$/.test(maxResultsText)) invalidCassette();

  let prepared: PreparedXRecentSearchRequest;
  try {
    const nextToken = parameters.get("next_token");
    prepared = prepareRecentSearchRequest(
      nextToken === null
        ? { query: parameters.get("query"), maxResults: Number(maxResultsText) }
        : {
            query: parameters.get("query"),
            maxResults: Number(maxResultsText),
            nextToken,
          },
    );
  } catch {
    invalidCassette();
  }
  if (prepared.canonicalRequest !== canonicalRequest || prepared.fingerprint !== fingerprint) {
    invalidCassette();
  }
}

export function validateXRecentSearchCassette(input: unknown): XRecentSearchCassette {
  if (
    !isPlainRecord(input) ||
    !hasExactKeys(input, ["version", "acquiredAt", "request", "response", "integritySha256"])
  ) {
    invalidCassette();
  }
  if (
    input.version !== X_RECENT_SEARCH_CASSETTE_VERSION ||
    !isCanonicalAcquiredAt(input.acquiredAt) ||
    !isSha256(input.integritySha256)
  ) {
    invalidCassette();
  }

  const request = input.request;
  const response = input.response;
  if (
    !isPlainRecord(request) ||
    !hasExactKeys(request, ["fingerprint", "canonicalRequest"]) ||
    !isSha256(request.fingerprint) ||
    typeof request.canonicalRequest !== "string" ||
    sha256(request.canonicalRequest) !== request.fingerprint
  ) {
    invalidCassette();
  }
  validateCanonicalRequest(request.canonicalRequest, request.fingerprint);

  if (
    !isPlainRecord(response) ||
    !hasExactKeys(response, ["status", "contentType", "byteLength", "bodySha256", "bodyBase64"]) ||
    response.status !== 200 ||
    !Number.isSafeInteger(response.byteLength) ||
    (response.byteLength as number) < 0 ||
    (response.byteLength as number) > X_RECENT_SEARCH_MAX_RESPONSE_BYTES ||
    !isSha256(response.bodySha256)
  ) {
    invalidCassette();
  }
  const contentType = normalizedJsonContentType(response.contentType);
  if (contentType === undefined) invalidCassette();
  const bytes = decodeCanonicalBase64(response.bodyBase64);
  try {
    if (bytes.byteLength !== response.byteLength || sha256(bytes) !== response.bodySha256) {
      invalidCassette();
    }

    const integrityInput = {
      version: X_RECENT_SEARCH_CASSETTE_VERSION,
      acquiredAt: input.acquiredAt,
      request: {
        fingerprint: request.fingerprint,
        canonicalRequest: request.canonicalRequest,
      },
      response: {
        status: 200,
        contentType,
        byteLength: bytes.byteLength,
        bodySha256: response.bodySha256,
        bodyBase64: response.bodyBase64 as string,
      },
    };
    if (cassetteIntegrity(integrityInput) !== input.integritySha256) invalidCassette();

    return Object.freeze({
      version: X_RECENT_SEARCH_CASSETTE_VERSION,
      acquiredAt: input.acquiredAt,
      request: Object.freeze({
        fingerprint: request.fingerprint,
        canonicalRequest: request.canonicalRequest,
      }),
      response: Object.freeze({
        status: 200,
        contentType,
        byteLength: bytes.byteLength,
        bodySha256: response.bodySha256,
        bodyBase64: response.bodyBase64 as string,
      }),
      integritySha256: input.integritySha256,
    });
  } finally {
    bytes.fill(0);
  }
}

export function createXRecentSearchCassette(
  request: PreparedXRecentSearchRequest,
  response: QuarantinedXRecentSearchResponse,
): XRecentSearchCassette {
  if (response.metadata.requestFingerprint !== request.fingerprint) {
    throw new XCollectorError(
      "INVALID_CASSETTE",
      "The quarantined response does not match the prepared request.",
    );
  }
  const bytes = response.copyBytes();
  try {
    const cassette = {
      version: X_RECENT_SEARCH_CASSETTE_VERSION,
      acquiredAt: response.metadata.acquiredAt,
      request: {
        fingerprint: request.fingerprint,
        canonicalRequest: request.canonicalRequest,
      },
      response: {
        status: 200,
        contentType: response.metadata.contentType,
        byteLength: bytes.byteLength,
        bodySha256: response.metadata.responseHash,
        bodyBase64: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(
          "base64",
        ),
      },
    };
    return validateXRecentSearchCassette({
      ...cassette,
      integritySha256: cassetteIntegrity(cassette),
    });
  } finally {
    bytes.fill(0);
  }
}

export function decodeXRecentSearchCassetteBody(cassette: XRecentSearchCassette): Uint8Array {
  const validated = validateXRecentSearchCassette(cassette);
  return decodeCanonicalBase64(validated.response.bodyBase64);
}

function cloneCassette(cassette: XRecentSearchCassette): XRecentSearchCassette {
  return validateXRecentSearchCassette({
    version: cassette.version,
    acquiredAt: cassette.acquiredAt,
    request: { ...cassette.request },
    response: { ...cassette.response },
    integritySha256: cassette.integritySha256,
  });
}

function cassettesAreIdentical(left: XRecentSearchCassette, right: XRecentSearchCassette): boolean {
  return (
    left.request.canonicalRequest === right.request.canonicalRequest &&
    left.acquiredAt === right.acquiredAt &&
    left.response.status === right.response.status &&
    left.response.contentType === right.response.contentType &&
    left.response.byteLength === right.response.byteLength &&
    left.response.bodySha256 === right.response.bodySha256 &&
    left.response.bodyBase64 === right.response.bodyBase64 &&
    left.integritySha256 === right.integritySha256
  );
}

/** Pluggable volatile storage for tests and bounded sessions; no filesystem recorder is provided. */
export class MemoryCassetteStore implements XRecentSearchCassetteStore {
  readonly #cassettes = new Map<Sha256, XRecentSearchCassette>();

  constructor(seed: readonly unknown[] = []) {
    for (const candidate of seed) {
      const cassette = validateXRecentSearchCassette(candidate);
      const existing = this.#cassettes.get(cassette.request.fingerprint);
      if (existing !== undefined && !cassettesAreIdentical(existing, cassette)) {
        throw new XCollectorError(
          "INVALID_CASSETTE",
          "A conflicting cassette already exists for this request fingerprint.",
        );
      }
      this.#cassettes.set(cassette.request.fingerprint, cassette);
    }
  }

  async get(fingerprint: Sha256): Promise<unknown | undefined> {
    const cassette = this.#cassettes.get(fingerprint);
    return cassette === undefined ? undefined : cloneCassette(cassette);
  }

  snapshot(): readonly XRecentSearchCassette[] {
    return Object.freeze([...this.#cassettes.values()].map(cloneCassette));
  }
}
