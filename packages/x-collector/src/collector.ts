import {
  createXRecentSearchCassette,
  decodeXRecentSearchCassetteBody,
  validateXRecentSearchCassette,
  type XRecentSearchCassetteStore,
} from "./cassette.js";
import {
  X_JSON_CONTENT_TYPES,
  X_RECENT_SEARCH_DEFAULT_MAX_RESPONSE_BYTES,
  X_RECENT_SEARCH_DEFAULT_TIMEOUT_MS,
  X_RECENT_SEARCH_MAX_RESPONSE_BYTES,
  X_RECENT_SEARCH_MAX_TIMEOUT_MS,
} from "./constants.js";
import { XCollectorError } from "./errors.js";
import {
  quarantineCassetteResponse,
  quarantineNetworkResponse,
  type QuarantinedXRecentSearchResponse,
} from "./quarantine.js";
import { prepareRecentSearchRequest, type PreparedXRecentSearchRequest } from "./query.js";
import { readAcquiredAt, type XCollectorClock } from "./time.js";

export type XRecentSearchFetch = (request: Request) => Promise<Response>;

export type XRecentSearchLiveOptions = Readonly<{
  mode?: "live";
  bearerToken: string;
  fetch?: XRecentSearchFetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  now?: XCollectorClock;
}>;

export type XRecentSearchRecordOptions = Readonly<{
  mode: "record";
  bearerToken: string;
  cassetteStore: XRecentSearchCassetteStore;
  fetch?: XRecentSearchFetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  now?: XCollectorClock;
}>;

export type XRecentSearchReplayOptions = Readonly<{
  mode: "replay";
  cassetteStore: XRecentSearchCassetteStore;
  maxResponseBytes?: number;
}>;

export type XRecentSearchCollectorOptions =
  XRecentSearchLiveOptions | XRecentSearchRecordOptions | XRecentSearchReplayOptions;

export type XRecentSearchCollectOptions = Readonly<{
  signal?: AbortSignal;
}>;

export interface XRecentSearchCollector {
  readonly mode: "live" | "record" | "replay";
  collectRaw(
    query: unknown,
    options?: XRecentSearchCollectOptions,
  ): Promise<QuarantinedXRecentSearchResponse>;
}

type ValidatedCollectOptions = Readonly<{ signal?: AbortSignal }>;

const LIVE_KEYS = new Set(["mode", "bearerToken", "fetch", "timeoutMs", "maxResponseBytes", "now"]);
const RECORD_KEYS = new Set([
  "mode",
  "bearerToken",
  "cassetteStore",
  "fetch",
  "timeoutMs",
  "maxResponseBytes",
  "now",
]);
const REPLAY_KEYS = new Set(["mode", "cassetteStore", "maxResponseBytes"]);
const ABORT_SENTINEL = Object.freeze({ aborted: true });

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Reflect.ownKeys(value).every((key) => typeof key === "string" && allowed.has(key));
}

function invalidConfiguration(message: string): never {
  throw new XCollectorError("INVALID_CONFIGURATION", message);
}

function validatePositiveBoundedInteger(
  value: unknown,
  fallback: number,
  maximum: number,
  property: string,
): number {
  const resolved = value === undefined ? fallback : value;
  if (
    typeof resolved !== "number" ||
    !Number.isSafeInteger(resolved) ||
    resolved < 1 ||
    resolved > maximum
  ) {
    invalidConfiguration(`${property} must be a positive bounded integer.`);
  }
  return resolved;
}

function validateCredential(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4_096 ||
    !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new XCollectorError(
      "INVALID_CREDENTIAL",
      "The Bearer Token must be a non-empty visible-ASCII credential.",
    );
  }
  return value;
}

function validateStore(value: unknown): XRecentSearchCassetteStore {
  if (
    (typeof value !== "object" && typeof value !== "function") ||
    value === null ||
    typeof (value as Partial<XRecentSearchCassetteStore>).get !== "function" ||
    typeof (value as Partial<XRecentSearchCassetteStore>).put !== "function"
  ) {
    invalidConfiguration("cassetteStore must implement get() and put().");
  }
  return value as XRecentSearchCassetteStore;
}

function validateCollectOptions(value: unknown): ValidatedCollectOptions {
  if (value === undefined) return Object.freeze({});
  if (!isPlainRecord(value) || !hasOnlyKeys(value, new Set(["signal"]))) {
    invalidConfiguration("collectRaw options contain an unsupported property.");
  }
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) {
    invalidConfiguration("signal must be an AbortSignal.");
  }
  return Object.freeze(value.signal === undefined ? {} : { signal: value.signal });
}

function normalizeJsonContentType(value: string | null): string {
  if (value === null) {
    throw new XCollectorError(
      "UNSUPPORTED_CONTENT_TYPE",
      "The response Content-Type is not an allowed JSON media type.",
    );
  }
  const normalized = value.trim().toLowerCase();
  if (!(X_JSON_CONTENT_TYPES as readonly string[]).includes(normalized)) {
    throw new XCollectorError(
      "UNSUPPORTED_CONTENT_TYPE",
      "The response Content-Type is not an allowed JSON media type.",
    );
  }
  return normalized;
}

function includesBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.byteLength === 0 || needle.byteLength > haystack.byteLength) return false;
  outer: for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) continue outer;
    }
    return true;
  }
  return false;
}

function credentialRepresentations(bearerToken: string): readonly Uint8Array[] {
  const encoder = new TextEncoder();
  return [
    bearerToken,
    `Bearer ${bearerToken}`,
    encodeURIComponent(bearerToken),
    Buffer.from(bearerToken, "utf8").toString("base64"),
    JSON.stringify(bearerToken).slice(1, -1),
  ].map((representation) => encoder.encode(representation));
}

function containsCredential(bytes: Uint8Array, bearerToken: string): boolean {
  return credentialRepresentations(bearerToken).some((needle) => includesBytes(bytes, needle));
}

function assertCredentialAbsentFromResponse(bytes: Uint8Array, bearerToken: string): void {
  if (containsCredential(bytes, bearerToken)) {
    throw new XCollectorError(
      "CREDENTIAL_IN_RESPONSE",
      "The response was rejected because it contained credential material.",
    );
  }
}

function assertCredentialAbsentFromRequest(
  prepared: PreparedXRecentSearchRequest,
  bearerToken: string,
): void {
  if (containsCredential(new TextEncoder().encode(prepared.canonicalRequest), bearerToken)) {
    throw new XCollectorError(
      "CREDENTIAL_IN_REQUEST",
      "The request was rejected because a query field contained credential material.",
    );
  }
}

function abortGate(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    if (signal.aborted) {
      reject(ABORT_SENTINEL);
      return;
    }
    signal.addEventListener("abort", () => reject(ABORT_SENTINEL), { once: true });
  });
}

async function readBoundedBody(
  response: Response,
  limitBytes: number,
  gate: Promise<never>,
): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  let declaredLength: number | undefined;
  if (contentLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new XCollectorError("RESPONSE_TOO_LARGE", "The response length is invalid.", {
        limitBytes,
      });
    }
    declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > limitBytes) {
      throw new XCollectorError("RESPONSE_TOO_LARGE", "The response exceeds the byte limit.", {
        limitBytes,
      });
    }
  }

  if (response.body === null) {
    if (declaredLength !== undefined && declaredLength !== 0) {
      throw new XCollectorError(
        "CONTENT_LENGTH_MISMATCH",
        "The response length did not match Content-Length.",
      );
    }
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const result = await Promise.race([reader.read(), gate]);
    if (result.done) break;
    const chunk = result.value;
    total += chunk.byteLength;
    if (total > limitBytes) {
      void reader.cancel().catch(() => undefined);
      throw new XCollectorError("RESPONSE_TOO_LARGE", "The response exceeds the byte limit.", {
        limitBytes,
        receivedBytes: total,
      });
    }
    chunks.push(chunk.slice());
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (declaredLength !== undefined && declaredLength !== total) {
    throw new XCollectorError(
      "CONTENT_LENGTH_MISMATCH",
      "The response length did not match Content-Length.",
    );
  }
  return bytes;
}

async function executeNetworkRequest(
  prepared: PreparedXRecentSearchRequest,
  bearerToken: string,
  fetchImplementation: XRecentSearchFetch,
  timeoutMs: number,
  maxResponseBytes: number,
  externalSignal: AbortSignal | undefined,
  clock: XCollectorClock,
): Promise<QuarantinedXRecentSearchResponse> {
  if (externalSignal?.aborted === true) {
    throw new XCollectorError("ABORTED", "The recent-search request was aborted.");
  }

  const controller = new AbortController();
  let timedOut = false;
  let externallyAborted = false;
  const onExternalAbort = (): void => {
    externallyAborted = true;
    controller.abort();
  };
  externalSignal?.addEventListener("abort", onExternalAbort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const gate = abortGate(controller.signal);

  try {
    const request = new Request(prepared.url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${bearerToken}`,
      },
      body: null,
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });

    const response = await Promise.race([fetchImplementation(request), gate]);
    if (!(response instanceof Response)) {
      throw new XCollectorError("TRANSPORT_FAILURE", "The transport returned an invalid response.");
    }
    if (
      response.type === "opaqueredirect" ||
      response.redirected ||
      (response.status >= 300 && response.status <= 399) ||
      (response.url.length > 0 && response.url !== prepared.url)
    ) {
      throw new XCollectorError("REDIRECT_REFUSED", "Redirected X API responses are refused.", {
        status: response.status,
      });
    }
    if (response.status !== 200) {
      throw new XCollectorError("HTTP_STATUS", "The X API returned a non-success status.", {
        status: response.status,
      });
    }
    const contentType = normalizeJsonContentType(response.headers.get("content-type"));
    const bytes = await readBoundedBody(response, maxResponseBytes, gate);
    assertCredentialAbsentFromResponse(bytes, bearerToken);
    const acquiredAt = readAcquiredAt(clock);
    return quarantineNetworkResponse(prepared, 200, contentType, bytes, acquiredAt);
  } catch (error) {
    if (error instanceof XCollectorError) throw error;
    if (timedOut) {
      throw new XCollectorError("TIMEOUT", "The recent-search request timed out.");
    }
    if (externallyAborted) {
      throw new XCollectorError("ABORTED", "The recent-search request was aborted.");
    }
    throw new XCollectorError("TRANSPORT_FAILURE", "The recent-search transport failed.");
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

export function createXRecentSearchCollector(
  options: XRecentSearchCollectorOptions,
): XRecentSearchCollector;
export function createXRecentSearchCollector(options: unknown): XRecentSearchCollector {
  if (!isPlainRecord(options)) invalidConfiguration("Collector options must be a plain object.");
  const mode = options.mode === undefined ? "live" : options.mode;
  if (mode !== "live" && mode !== "record" && mode !== "replay") {
    invalidConfiguration("mode must be live, record, or replay.");
  }
  const allowed = mode === "live" ? LIVE_KEYS : mode === "record" ? RECORD_KEYS : REPLAY_KEYS;
  if (!hasOnlyKeys(options, allowed)) {
    invalidConfiguration("Collector options contain an unsupported property.");
  }

  const maxResponseBytes = validatePositiveBoundedInteger(
    options.maxResponseBytes,
    X_RECENT_SEARCH_DEFAULT_MAX_RESPONSE_BYTES,
    X_RECENT_SEARCH_MAX_RESPONSE_BYTES,
    "maxResponseBytes",
  );

  if (mode === "replay") {
    const cassetteStore = validateStore(options.cassetteStore);
    const collector: XRecentSearchCollector = {
      mode,
      async collectRaw(query, collectOptions) {
        const { signal } = validateCollectOptions(collectOptions);
        if (signal?.aborted === true) {
          throw new XCollectorError("ABORTED", "The recent-search replay was aborted.");
        }
        const prepared = prepareRecentSearchRequest(query);
        let candidate: unknown | undefined;
        try {
          candidate = await cassetteStore.get(prepared.fingerprint);
        } catch {
          throw new XCollectorError(
            "CASSETTE_STORAGE_FAILURE",
            "The cassette store could not read a replay.",
          );
        }
        if (candidate === undefined) {
          throw new XCollectorError("CASSETTE_MISS", "No cassette matches the canonical request.");
        }
        const cassette = validateXRecentSearchCassette(candidate);
        if (
          cassette.request.fingerprint !== prepared.fingerprint ||
          cassette.request.canonicalRequest !== prepared.canonicalRequest
        ) {
          throw new XCollectorError(
            "INVALID_CASSETTE",
            "The cassette does not match the canonical request.",
          );
        }
        const bytes = decodeXRecentSearchCassetteBody(cassette);
        if (bytes.byteLength > maxResponseBytes) {
          throw new XCollectorError("RESPONSE_TOO_LARGE", "The replay exceeds the byte limit.", {
            limitBytes: maxResponseBytes,
          });
        }
        return quarantineCassetteResponse(
          prepared,
          cassette.response.contentType,
          cassette.response.bodySha256,
          bytes,
          cassette.acquiredAt,
        );
      },
    };
    return Object.freeze(collector);
  }

  const bearerToken = validateCredential(options.bearerToken);
  const fetchImplementation =
    options.fetch === undefined
      ? globalThis.fetch.bind(globalThis)
      : typeof options.fetch === "function"
        ? (options.fetch as XRecentSearchFetch)
        : invalidConfiguration("fetch must be a fetch-compatible function.");
  const timeoutMs = validatePositiveBoundedInteger(
    options.timeoutMs,
    X_RECENT_SEARCH_DEFAULT_TIMEOUT_MS,
    X_RECENT_SEARCH_MAX_TIMEOUT_MS,
    "timeoutMs",
  );
  const clock =
    options.now === undefined
      ? () => new Date()
      : typeof options.now === "function"
        ? (options.now as XCollectorClock)
        : invalidConfiguration("now must be a clock function.");
  const cassetteStore = mode === "record" ? validateStore(options.cassetteStore) : undefined;

  const collector: XRecentSearchCollector = {
    mode,
    async collectRaw(query, collectOptions) {
      const { signal } = validateCollectOptions(collectOptions);
      const prepared = prepareRecentSearchRequest(query);
      assertCredentialAbsentFromRequest(prepared, bearerToken);
      const response = await executeNetworkRequest(
        prepared,
        bearerToken,
        fetchImplementation,
        timeoutMs,
        maxResponseBytes,
        signal,
        clock,
      );
      if (mode === "record" && cassetteStore !== undefined) {
        const cassette = createXRecentSearchCassette(prepared, response);
        try {
          await cassetteStore.put(cassette);
        } catch {
          throw new XCollectorError(
            "CASSETTE_STORAGE_FAILURE",
            "The cassette store could not record the response.",
          );
        }
      }
      return response;
    },
  };
  return Object.freeze(collector);
}
