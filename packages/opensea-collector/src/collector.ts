import { types as utilTypes } from "node:util";

import {
  isNetworkAttemptAuthorization,
  type NetworkAttemptBinding,
  type NetworkAttemptAuthorization,
  type NetworkAttemptDispatchReceipt,
} from "@rsi/operations";
import {
  isRuntimeBoundaryAuthorization,
  type RuntimeBoundaryAuthorization,
  type RuntimeBoundaryReceipt,
} from "@rsi/runtime";

import {
  OPENSEA_JSON_CONTENT_TYPES,
  OPENSEA_TRENDING_ACCEPT,
  OPENSEA_TRENDING_ACCEPT_ENCODING,
  OPENSEA_TRENDING_CREDENTIAL_HEADER,
  OPENSEA_TRENDING_MAXIMUM_BYTES,
  OPENSEA_TRENDING_OPERATION,
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  OPENSEA_TRENDING_TIMEOUT_MS,
  OPENSEA_TRENDING_URL,
} from "./constants.js";
import { OpenSeaCollectorError } from "./errors.js";
import {
  quarantineOpenSeaTrendingNetworkResponse,
  type QuarantinedOpenSeaTrendingResponse,
} from "./quarantine.js";
import {
  prepareOpenSeaTrendingCollectorRequest,
  type PreparedOpenSeaTrendingCollectorRequest,
} from "./request.js";
import { readOpenSeaRateLimitReceipt, requireOpenSeaRateLimitReceipt } from "./rate-limit.js";
import { readOpenSeaAcquiredAt, type OpenSeaCollectorClock } from "./time.js";

export type OpenSeaTrendingFetch = (request: Request) => Promise<Response>;

export type OpenSeaTrendingLiveOptions = Readonly<{
  apiKey: string;
  attemptAuthorization: NetworkAttemptAuthorization;
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">;
}>;

export type OpenSeaTrendingLiveTestingOptions = OpenSeaTrendingLiveOptions &
  Readonly<{
    fetch?: OpenSeaTrendingFetch;
    maxResponseBytes?: number;
    now?: OpenSeaCollectorClock;
    timeoutMs?: number;
  }>;

export type OpenSeaTrendingCollectOptions = Readonly<{ signal?: AbortSignal }>;

export interface OpenSeaTrendingCollector {
  readonly attemptBinding: NetworkAttemptBinding;
  readonly mode: "live";
  collectRaw(options?: OpenSeaTrendingCollectOptions): Promise<QuarantinedOpenSeaTrendingResponse>;
}

const AUTHENTIC_COLLECTORS = new WeakSet<object>();
const LIVE_KEYS = new Set(["apiKey", "attemptAuthorization", "runtimeAuthorization"]);
const LIVE_TESTING_KEYS = new Set([...LIVE_KEYS, "fetch", "maxResponseBytes", "now", "timeoutMs"]);
const REQUIRED_KEYS = ["apiKey", "attemptAuthorization", "runtimeAuthorization"] as const;
const ABORT_SENTINEL = Object.freeze({ aborted: true });

function cancelResponseBody(response: Response): void {
  try {
    const body = response.body;
    if (body !== null) void body.cancel().catch(() => undefined);
  } catch {
    // Cleanup is best-effort and must not replace the closed, redacted error.
  }
}

function rejectResponse(response: Response, error: OpenSeaCollectorError): never {
  cancelResponseBody(response);
  throw error;
}

function attachLateResponseCleanup(fetchPromise: Promise<Response>): void {
  void fetchPromise.then(
    (response) => {
      if (response instanceof Response) cancelResponseBody(response);
    },
    () => undefined,
  );
}

export function isOpenSeaTrendingCollector(value: unknown): value is OpenSeaTrendingCollector {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_COLLECTORS.has(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function invalidConfiguration(message: string): never {
  throw new OpenSeaCollectorError("INVALID_CONFIGURATION", message);
}

function exactOptionRecord(value: unknown, allowed: ReadonlySet<string>): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    invalidConfiguration("Collector options must be a plain object.");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    REQUIRED_KEYS.some((key) => !keys.includes(key))
  ) {
    invalidConfiguration("Collector options contain an unsupported or missing property.");
  }
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") invalidConfiguration("Collector options are invalid.");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      invalidConfiguration("Collector options must contain enumerable data properties only.");
    }
    result[key] = descriptor.value;
  }
  return result;
}

function validateBoundedInteger(
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

function validateApiKey(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4_096 ||
    !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new OpenSeaCollectorError(
      "INVALID_CREDENTIAL",
      "The OpenSea API key must be a non-empty visible-ASCII credential.",
    );
  }
  return value;
}

function validateCollectOptions(value: unknown): OpenSeaTrendingCollectOptions {
  if (value === undefined) return Object.freeze({});
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    invalidConfiguration("collectRaw options must be a plain object.");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => key !== "signal")) {
    invalidConfiguration("collectRaw options contain an unsupported property.");
  }
  let signal: unknown;
  if (keys.includes("signal")) {
    const descriptor = Object.getOwnPropertyDescriptor(value, "signal");
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      invalidConfiguration("collectRaw options must contain data properties only.");
    }
    signal = descriptor.value;
  }
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    invalidConfiguration("signal must be an AbortSignal.");
  }
  return Object.freeze(signal === undefined ? {} : { signal });
}

export function openSeaTrendingRuntimeActionId(
  attemptId: string,
  fingerprint: PreparedOpenSeaTrendingCollectorRequest["fingerprint"],
): string {
  return `opensea.tc:${attemptId}:${fingerprint.slice("sha256:".length)}`;
}

function assertRuntimeReceipt(
  receipt: Readonly<RuntimeBoundaryReceipt>,
  authorization: RuntimeBoundaryAuthorization<"research_collection">,
): void {
  if (
    receipt.actionId !== authorization.actionId ||
    receipt.authorizationId !== authorization.authorizationId ||
    receipt.boundary !== "research_collection" ||
    Date.parse(receipt.checkedAt) < Date.parse(authorization.requestedAt) ||
    receipt.decision !== "allowed" ||
    receipt.mode === "STOPPED" ||
    receipt.modeRevision !== authorization.requestedRevision ||
    receipt.processInstanceId !== authorization.processInstanceId ||
    receipt.reason !== "ALLOWED"
  ) {
    throw new OpenSeaCollectorError(
      "RUNTIME_AUTHORIZATION_FAILED",
      "The runtime collection authorization was refused.",
    );
  }
}

function normalizeJsonContentType(value: string | null): string {
  if (value === null) {
    throw new OpenSeaCollectorError(
      "UNSUPPORTED_CONTENT_TYPE",
      "The response Content-Type is not an allowed JSON media type.",
    );
  }
  const normalized = value.trim().toLowerCase();
  if (!(OPENSEA_JSON_CONTENT_TYPES as readonly string[]).includes(normalized)) {
    throw new OpenSeaCollectorError(
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

function credentialRepresentations(apiKey: string): readonly Uint8Array[] {
  const encoder = new TextEncoder();
  const keyBytes = Buffer.from(apiKey, "utf8");
  try {
    return [
      apiKey,
      `${OPENSEA_TRENDING_CREDENTIAL_HEADER}: ${apiKey}`,
      encodeURIComponent(apiKey),
      keyBytes.toString("base64"),
      JSON.stringify(apiKey).slice(1, -1),
    ].map((representation) => encoder.encode(representation));
  } finally {
    keyBytes.fill(0);
  }
}

function containsCredential(bytes: Uint8Array, apiKey: string): boolean {
  const representations = credentialRepresentations(apiKey);
  try {
    return representations.some((needle) => includesBytes(bytes, needle));
  } finally {
    for (const representation of representations) representation.fill(0);
  }
}

function assertCredentialAbsentFromRequest(
  prepared: PreparedOpenSeaTrendingCollectorRequest,
  apiKey: string,
): void {
  const bytes = new TextEncoder().encode(prepared.canonicalRequest);
  try {
    if (containsCredential(bytes, apiKey)) {
      throw new OpenSeaCollectorError(
        "CREDENTIAL_IN_REQUEST",
        "The fixed request was rejected because it contained credential material.",
      );
    }
  } finally {
    bytes.fill(0);
  }
}

function assertCredentialAbsentFromResponse(bytes: Uint8Array, apiKey: string): void {
  if (containsCredential(bytes, apiKey)) {
    throw new OpenSeaCollectorError(
      "CREDENTIAL_IN_RESPONSE",
      "The response was rejected because it contained credential material.",
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
      rejectResponse(
        response,
        new OpenSeaCollectorError("RESPONSE_TOO_LARGE", "The response length is invalid.", {
          limitBytes,
        }),
      );
    }
    declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > limitBytes) {
      rejectResponse(
        response,
        new OpenSeaCollectorError("RESPONSE_TOO_LARGE", "The response exceeds the byte limit.", {
          limitBytes,
        }),
      );
    }
  }
  if (response.body === null) {
    if (declaredLength !== undefined && declaredLength !== 0) {
      throw new OpenSeaCollectorError(
        "CONTENT_LENGTH_MISMATCH",
        "The response length did not match Content-Length.",
      );
    }
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let assembled: Uint8Array | undefined;
  try {
    while (true) {
      const result = await Promise.race([reader.read(), gate]);
      if (result.done) break;
      const sourceChunk = result.value;
      const chunk = new Uint8Array(sourceChunk);
      sourceChunk.fill(0);
      total += chunk.byteLength;
      if (total > limitBytes) {
        chunk.fill(0);
        void reader.cancel().catch(() => undefined);
        throw new OpenSeaCollectorError(
          "RESPONSE_TOO_LARGE",
          "The response exceeds the byte limit.",
          { limitBytes, receivedBytes: total },
        );
      }
      chunks.push(chunk);
    }
    assembled = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      assembled.set(chunk, offset);
      offset += chunk.byteLength;
    }
    if (declaredLength !== undefined && declaredLength !== total) {
      throw new OpenSeaCollectorError(
        "CONTENT_LENGTH_MISMATCH",
        "The response length did not match Content-Length.",
      );
    }
    return assembled;
  } catch (error) {
    assembled?.fill(0);
    void reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function executeNetworkRequest(
  prepared: PreparedOpenSeaTrendingCollectorRequest,
  apiKey: string,
  fetchImplementation: OpenSeaTrendingFetch,
  timeoutMs: number,
  maxResponseBytes: number,
  externalSignal: AbortSignal | undefined,
  clock: OpenSeaCollectorClock,
  expectedBinding: Readonly<NetworkAttemptBinding>,
  dispatchReceipt: Readonly<NetworkAttemptDispatchReceipt>,
): Promise<QuarantinedOpenSeaTrendingResponse> {
  if (externalSignal?.aborted === true) {
    throw new OpenSeaCollectorError("ABORTED", "The OpenSea trending request was aborted.");
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
        accept: OPENSEA_TRENDING_ACCEPT,
        "accept-encoding": OPENSEA_TRENDING_ACCEPT_ENCODING,
        "x-api-key": apiKey,
      },
      body: null,
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    const fetchPromise = Promise.resolve(fetchImplementation(request));
    let response: Response;
    try {
      response = await Promise.race([fetchPromise, gate]);
    } catch (error) {
      if (error === ABORT_SENTINEL) attachLateResponseCleanup(fetchPromise);
      throw error;
    }
    if (!(response instanceof Response)) {
      throw new OpenSeaCollectorError(
        "TRANSPORT_FAILURE",
        "The transport returned an invalid response.",
      );
    }
    if (
      response.type === "opaqueredirect" ||
      response.redirected ||
      (response.status >= 300 && response.status <= 399) ||
      (response.url.length > 0 && response.url !== prepared.url)
    ) {
      rejectResponse(
        response,
        new OpenSeaCollectorError("REDIRECT_REFUSED", "Redirected OpenSea responses are refused.", {
          status: response.status,
        }),
      );
    }
    if (response.status === 402) {
      let rateLimit;
      try {
        rateLimit = readOpenSeaRateLimitReceipt(response.headers);
      } catch {
        // A malformed optional receipt cannot obscure the payment refusal.
      }
      rejectResponse(
        response,
        new OpenSeaCollectorError(
          "PAYMENT_REQUIRED",
          "OpenSea requested payment; this read-only collector cannot pay.",
          rateLimit === undefined ? { status: 402 } : { status: 402, rateLimit },
        ),
      );
    }
    if (response.status !== 200) {
      let rateLimit;
      try {
        rateLimit = readOpenSeaRateLimitReceipt(response.headers);
      } catch (error) {
        cancelResponseBody(response);
        throw error;
      }
      rejectResponse(
        response,
        new OpenSeaCollectorError(
          "HTTP_STATUS",
          "OpenSea returned a non-success status.",
          rateLimit === undefined
            ? { status: response.status }
            : { status: response.status, rateLimit },
        ),
      );
    }
    let rateLimit;
    try {
      rateLimit = requireOpenSeaRateLimitReceipt(response.headers);
    } catch (error) {
      cancelResponseBody(response);
      throw error;
    }
    const contentEncoding = response.headers.get("content-encoding");
    if (contentEncoding !== null && contentEncoding.trim().toLowerCase() !== "identity") {
      rejectResponse(
        response,
        new OpenSeaCollectorError(
          "UNSUPPORTED_CONTENT_ENCODING",
          "OpenSea returned a compressed response despite the identity-only request.",
        ),
      );
    }
    let contentType: string;
    try {
      contentType = normalizeJsonContentType(response.headers.get("content-type"));
    } catch (error) {
      cancelResponseBody(response);
      throw error;
    }
    const bytes = await readBoundedBody(response, maxResponseBytes, gate);
    try {
      assertCredentialAbsentFromResponse(bytes, apiKey);
      const acquiredAt = readOpenSeaAcquiredAt(clock);
      if (Date.parse(acquiredAt) < Date.parse(dispatchReceipt.dispatchedAt)) {
        throw new OpenSeaCollectorError(
          "CLOCK_REGRESSION",
          "The collector clock moved backward during the request.",
        );
      }
      return quarantineOpenSeaTrendingNetworkResponse(
        prepared,
        expectedBinding,
        dispatchReceipt,
        200,
        contentType,
        bytes,
        acquiredAt,
        rateLimit,
      );
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof OpenSeaCollectorError) throw error;
    if (timedOut) {
      throw new OpenSeaCollectorError("TIMEOUT", "The OpenSea trending request timed out.");
    }
    if (externallyAborted) {
      throw new OpenSeaCollectorError("ABORTED", "The OpenSea trending request was aborted.");
    }
    throw new OpenSeaCollectorError("TRANSPORT_FAILURE", "The OpenSea trending transport failed.");
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

export function createOpenSeaTrendingCollector(
  options: OpenSeaTrendingLiveOptions,
): OpenSeaTrendingCollector;
export function createOpenSeaTrendingCollector(options: unknown): OpenSeaTrendingCollector {
  return createOpenSeaTrendingCollectorInternal(options, false);
}

/** Test-only transport and clock injection. Not exported from the production package entry. */
export function createOpenSeaTrendingCollectorForTesting(
  options: OpenSeaTrendingLiveTestingOptions,
): OpenSeaTrendingCollector;
export function createOpenSeaTrendingCollectorForTesting(
  options: unknown,
): OpenSeaTrendingCollector {
  return createOpenSeaTrendingCollectorInternal(options, true);
}

function createOpenSeaTrendingCollectorInternal(
  optionsValue: unknown,
  allowTestingHooks: boolean,
): OpenSeaTrendingCollector {
  const options = exactOptionRecord(
    optionsValue,
    allowTestingHooks ? LIVE_TESTING_KEYS : LIVE_KEYS,
  );
  const apiKey = validateApiKey(options.apiKey);
  const attemptAuthorization = options.attemptAuthorization;
  if (!isNetworkAttemptAuthorization(attemptAuthorization)) {
    invalidConfiguration(
      "Live collectors require a reserved one-shot network attempt authorization.",
    );
  }
  if (
    attemptAuthorization.binding.operation !== OPENSEA_TRENDING_OPERATION ||
    attemptAuthorization.binding.sourcePlane !== "marketplace" ||
    attemptAuthorization.binding.lane !== "marketplace" ||
    attemptAuthorization.binding.reservedAtomic !== OPENSEA_TRENDING_RESERVED_ATOMIC
  ) {
    invalidConfiguration(
      "The network attempt must be reserved for one OpenSea trending-collections call.",
    );
  }
  const runtimeAuthorization = options.runtimeAuthorization;
  if (
    !isRuntimeBoundaryAuthorization(runtimeAuthorization) ||
    runtimeAuthorization.boundary !== "research_collection" ||
    runtimeAuthorization.requestedMode === "STOPPED" ||
    runtimeAuthorization.expiresAt !== attemptAuthorization.binding.authorizationExpiresAt
  ) {
    invalidConfiguration(
      "Live collectors require a matching one-shot runtime collection authorization.",
    );
  }
  const runtimeCollectionAuthorization =
    runtimeAuthorization as RuntimeBoundaryAuthorization<"research_collection">;
  const fetchImplementation =
    options.fetch === undefined
      ? globalThis.fetch.bind(globalThis)
      : typeof options.fetch === "function" && !utilTypes.isProxy(options.fetch)
        ? (options.fetch as OpenSeaTrendingFetch)
        : invalidConfiguration("fetch must be a fetch-compatible function.");
  const timeoutMs = validateBoundedInteger(
    options.timeoutMs,
    OPENSEA_TRENDING_TIMEOUT_MS,
    OPENSEA_TRENDING_TIMEOUT_MS,
    "timeoutMs",
  );
  const maxResponseBytes = validateBoundedInteger(
    options.maxResponseBytes,
    OPENSEA_TRENDING_MAXIMUM_BYTES,
    OPENSEA_TRENDING_MAXIMUM_BYTES,
    "maxResponseBytes",
  );
  const clock =
    options.now === undefined
      ? () => new Date()
      : typeof options.now === "function" && !utilTypes.isProxy(options.now)
        ? (options.now as OpenSeaCollectorClock)
        : invalidConfiguration("now must be a clock function.");
  const collector: OpenSeaTrendingCollector = {
    attemptBinding: attemptAuthorization.binding,
    mode: "live",
    async collectRaw(collectOptionsValue) {
      if (arguments.length > 1) {
        invalidConfiguration("collectRaw accepts only an optional AbortSignal wrapper.");
      }
      const { signal } = validateCollectOptions(collectOptionsValue);
      const prepared = prepareOpenSeaTrendingCollectorRequest();
      assertCredentialAbsentFromRequest(prepared, apiKey);
      if (
        runtimeCollectionAuthorization.actionId !==
        openSeaTrendingRuntimeActionId(attemptAuthorization.binding.attemptId, prepared.fingerprint)
      ) {
        throw new OpenSeaCollectorError(
          "RUNTIME_AUTHORIZATION_FAILED",
          "The runtime collection authorization does not match this request.",
        );
      }
      if (signal?.aborted === true) {
        throw new OpenSeaCollectorError("ABORTED", "The OpenSea trending request was aborted.");
      }
      let responsePromise: Promise<QuarantinedOpenSeaTrendingResponse> | undefined;
      let runtimeDispatchFailure: unknown;
      try {
        runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {
          assertRuntimeReceipt(receipt, runtimeCollectionAuthorization);
          let dispatchReceipt: Readonly<NetworkAttemptDispatchReceipt>;
          try {
            dispatchReceipt = attemptAuthorization.consume();
          } catch {
            throw new OpenSeaCollectorError(
              "ATTEMPT_AUTHORIZATION_FAILED",
              "The reserved network attempt could not be authorized.",
            );
          }
          responsePromise = executeNetworkRequest(
            prepared,
            apiKey,
            fetchImplementation,
            timeoutMs,
            maxResponseBytes,
            signal,
            clock,
            attemptAuthorization.binding,
            dispatchReceipt,
          );
        });
      } catch (error) {
        if (responsePromise === undefined) {
          if (error instanceof OpenSeaCollectorError) throw error;
          throw new OpenSeaCollectorError(
            "RUNTIME_AUTHORIZATION_FAILED",
            "The runtime collection authorization could not protect dispatch.",
          );
        }
        runtimeDispatchFailure = error;
      }
      if (responsePromise === undefined) {
        throw new OpenSeaCollectorError(
          "RUNTIME_AUTHORIZATION_FAILED",
          "The runtime collection authorization did not invoke dispatch.",
        );
      }
      if (runtimeDispatchFailure !== undefined) {
        try {
          const abandoned = await responsePromise;
          abandoned.destroy();
        } catch {
          // The failed runtime commit remains authoritative, but the launched
          // response must still be drained and destroyed.
        }
        if (runtimeDispatchFailure instanceof OpenSeaCollectorError) {
          throw runtimeDispatchFailure;
        }
        throw new OpenSeaCollectorError(
          "RUNTIME_AUTHORIZATION_FAILED",
          "The runtime collection authorization could not commit protected dispatch.",
        );
      }
      return await responsePromise;
    },
  };
  AUTHENTIC_COLLECTORS.add(collector);
  return Object.freeze(collector);
}
