import { types as utilTypes } from "node:util";

import {
  isNetworkAttemptAuthorization,
  type NetworkAttemptAuthorization,
  type NetworkAttemptBinding,
  type NetworkAttemptDispatchReceipt,
} from "@rsi/operations";
import {
  isRuntimeBoundaryAuthorization,
  type RuntimeBoundaryAuthorization,
  type RuntimeBoundaryReceipt,
} from "@rsi/runtime";

import {
  BASE_RPC_ANCHOR_ACCEPT,
  BASE_RPC_ANCHOR_ACCEPT_ENCODING,
  BASE_RPC_ANCHOR_CONTENT_TYPE,
  BASE_RPC_ANCHOR_CREDENTIAL_HEADER,
  BASE_RPC_ANCHOR_CREDENTIAL_SCHEME,
  BASE_RPC_ANCHOR_LANE,
  BASE_RPC_ANCHOR_MAXIMUM_BYTES,
  BASE_RPC_ANCHOR_METHOD,
  BASE_RPC_ANCHOR_OPERATION,
  BASE_RPC_ANCHOR_RESERVED_ATOMIC,
  BASE_RPC_ANCHOR_SOURCE_PLANE,
  BASE_RPC_ANCHOR_TIMEOUT_MS,
  BASE_RPC_JSON_CONTENT_TYPES,
} from "./constants.js";
import { BaseRpcCollectorError } from "./errors.js";
import {
  quarantineBaseRpcAnchorNetworkResponse,
  type QuarantinedBaseRpcAnchorResponse,
} from "./quarantine.js";
import {
  prepareBaseRpcAnchorCollectorRequest,
  type PreparedBaseRpcAnchorCollectorRequest,
} from "./request.js";
import { readBaseRpcAcquiredAt, type BaseRpcCollectorClock } from "./time.js";

export type BaseRpcAnchorFetch = (request: Request) => Promise<Response>;

export type BaseRpcAnchorLiveOptions = Readonly<{
  apiKey: string;
  attemptAuthorization: NetworkAttemptAuthorization;
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">;
}>;

export type BaseRpcAnchorLiveTestingOptions = BaseRpcAnchorLiveOptions &
  Readonly<{
    fetch?: BaseRpcAnchorFetch;
    maxResponseBytes?: number;
    now?: BaseRpcCollectorClock;
    timeoutMs?: number;
  }>;

export type BaseRpcAnchorCollectOptions = Readonly<{ signal?: AbortSignal }>;

export interface BaseRpcAnchorCollector {
  readonly attemptBinding: NetworkAttemptBinding;
  readonly mode: "live";
  collectRaw(options?: BaseRpcAnchorCollectOptions): Promise<QuarantinedBaseRpcAnchorResponse>;
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

function rejectResponse(response: Response, error: BaseRpcCollectorError): never {
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

export function isBaseRpcAnchorCollector(value: unknown): value is BaseRpcAnchorCollector {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_COLLECTORS.has(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function invalidConfiguration(message: string): never {
  throw new BaseRpcCollectorError("INVALID_CONFIGURATION", message);
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
    throw new BaseRpcCollectorError(
      "INVALID_CREDENTIAL",
      "The Alchemy API key must be a non-empty visible-ASCII credential.",
    );
  }
  return value;
}

function validateCollectOptions(value: unknown): BaseRpcAnchorCollectOptions {
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

export function baseRpcAnchorRuntimeActionId(
  attemptId: string,
  fingerprint: PreparedBaseRpcAnchorCollectorRequest["fingerprint"],
): string {
  return `base.rpc-anchor:${attemptId}:${fingerprint.slice("sha256:".length)}`;
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
    throw new BaseRpcCollectorError(
      "RUNTIME_AUTHORIZATION_FAILED",
      "The runtime collection authorization was refused.",
    );
  }
}

function normalizeJsonContentType(value: string | null): string {
  if (value === null) {
    throw new BaseRpcCollectorError(
      "UNSUPPORTED_CONTENT_TYPE",
      "The response Content-Type is not an allowed JSON media type.",
    );
  }
  const normalized = value.trim().toLowerCase();
  if (!(BASE_RPC_JSON_CONTENT_TYPES as readonly string[]).includes(normalized)) {
    throw new BaseRpcCollectorError(
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
      `${BASE_RPC_ANCHOR_CREDENTIAL_SCHEME} ${apiKey}`,
      `${BASE_RPC_ANCHOR_CREDENTIAL_HEADER}: ${BASE_RPC_ANCHOR_CREDENTIAL_SCHEME} ${apiKey}`,
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
  prepared: PreparedBaseRpcAnchorCollectorRequest,
  apiKey: string,
): void {
  const bytes = new TextEncoder().encode(prepared.canonicalRequest);
  try {
    if (containsCredential(bytes, apiKey)) {
      throw new BaseRpcCollectorError(
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
    throw new BaseRpcCollectorError(
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
        new BaseRpcCollectorError("RESPONSE_TOO_LARGE", "The response length is invalid.", {
          limitBytes,
        }),
      );
    }
    declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > limitBytes) {
      rejectResponse(
        response,
        new BaseRpcCollectorError("RESPONSE_TOO_LARGE", "The response exceeds the byte limit.", {
          limitBytes,
        }),
      );
    }
  }
  if (response.body === null) {
    if (declaredLength !== undefined && declaredLength !== 0) {
      throw new BaseRpcCollectorError(
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
        throw new BaseRpcCollectorError(
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
      throw new BaseRpcCollectorError(
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
  prepared: PreparedBaseRpcAnchorCollectorRequest,
  apiKey: string,
  fetchImplementation: BaseRpcAnchorFetch,
  timeoutMs: number,
  maxResponseBytes: number,
  externalSignal: AbortSignal | undefined,
  clock: BaseRpcCollectorClock,
  expectedBinding: Readonly<NetworkAttemptBinding>,
  dispatchReceipt: Readonly<NetworkAttemptDispatchReceipt>,
): Promise<QuarantinedBaseRpcAnchorResponse> {
  if (externalSignal?.aborted === true) {
    throw new BaseRpcCollectorError("ABORTED", "The Base RPC anchor request was aborted.");
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
      method: BASE_RPC_ANCHOR_METHOD,
      headers: {
        accept: BASE_RPC_ANCHOR_ACCEPT,
        "accept-encoding": BASE_RPC_ANCHOR_ACCEPT_ENCODING,
        authorization: `${BASE_RPC_ANCHOR_CREDENTIAL_SCHEME} ${apiKey}`,
        "content-type": BASE_RPC_ANCHOR_CONTENT_TYPE,
      },
      body: prepared.body,
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
      throw new BaseRpcCollectorError(
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
        new BaseRpcCollectorError(
          "REDIRECT_REFUSED",
          "Redirected Base RPC responses are refused.",
          {
            status: response.status,
          },
        ),
      );
    }
    if (response.status === 402) {
      rejectResponse(
        response,
        new BaseRpcCollectorError(
          "PAYMENT_REQUIRED",
          "The provider requested payment; this read-only collector cannot pay.",
          { status: 402 },
        ),
      );
    }
    if (response.status === 429) {
      rejectResponse(
        response,
        new BaseRpcCollectorError(
          "RATE_LIMITED",
          "The provider rate-limited the request; this collector will not retry.",
          { status: 429 },
        ),
      );
    }
    if (response.status !== 200) {
      rejectResponse(
        response,
        new BaseRpcCollectorError("HTTP_STATUS", "The provider returned a non-success status.", {
          status: response.status,
        }),
      );
    }
    const contentEncoding = response.headers.get("content-encoding");
    if (contentEncoding !== null && contentEncoding.trim().toLowerCase() !== "identity") {
      rejectResponse(
        response,
        new BaseRpcCollectorError(
          "UNSUPPORTED_CONTENT_ENCODING",
          "The provider returned a compressed response despite the identity-only request.",
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
      const acquiredAt = readBaseRpcAcquiredAt(clock);
      if (Date.parse(acquiredAt) < Date.parse(dispatchReceipt.dispatchedAt)) {
        throw new BaseRpcCollectorError(
          "CLOCK_REGRESSION",
          "The collector clock moved backward during the request.",
        );
      }
      return quarantineBaseRpcAnchorNetworkResponse(
        prepared,
        expectedBinding,
        dispatchReceipt,
        200,
        contentType,
        bytes,
        acquiredAt,
      );
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof BaseRpcCollectorError) throw error;
    if (timedOut) {
      throw new BaseRpcCollectorError("TIMEOUT", "The Base RPC anchor request timed out.");
    }
    if (externallyAborted) {
      throw new BaseRpcCollectorError("ABORTED", "The Base RPC anchor request was aborted.");
    }
    throw new BaseRpcCollectorError("TRANSPORT_FAILURE", "The Base RPC transport failed.");
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

export function createBaseRpcAnchorCollector(
  options: BaseRpcAnchorLiveOptions,
): BaseRpcAnchorCollector;
export function createBaseRpcAnchorCollector(options: unknown): BaseRpcAnchorCollector {
  return createBaseRpcAnchorCollectorInternal(options, false);
}

/** Test-only transport and clock injection. Not exported from the production package entry. */
export function createBaseRpcAnchorCollectorForTesting(
  options: BaseRpcAnchorLiveTestingOptions,
): BaseRpcAnchorCollector;
export function createBaseRpcAnchorCollectorForTesting(options: unknown): BaseRpcAnchorCollector {
  return createBaseRpcAnchorCollectorInternal(options, true);
}

function createBaseRpcAnchorCollectorInternal(
  optionsValue: unknown,
  allowTestingHooks: boolean,
): BaseRpcAnchorCollector {
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
    attemptAuthorization.binding.operation !== BASE_RPC_ANCHOR_OPERATION ||
    attemptAuthorization.binding.sourcePlane !== BASE_RPC_ANCHOR_SOURCE_PLANE ||
    attemptAuthorization.binding.lane !== BASE_RPC_ANCHOR_LANE ||
    attemptAuthorization.binding.reservedAtomic !== BASE_RPC_ANCHOR_RESERVED_ATOMIC
  ) {
    invalidConfiguration("The network attempt must be reserved for one Base RPC anchor call.");
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
        ? (options.fetch as BaseRpcAnchorFetch)
        : invalidConfiguration("fetch must be a fetch-compatible function.");
  const timeoutMs = validateBoundedInteger(
    options.timeoutMs,
    BASE_RPC_ANCHOR_TIMEOUT_MS,
    BASE_RPC_ANCHOR_TIMEOUT_MS,
    "timeoutMs",
  );
  const maxResponseBytes = validateBoundedInteger(
    options.maxResponseBytes,
    BASE_RPC_ANCHOR_MAXIMUM_BYTES,
    BASE_RPC_ANCHOR_MAXIMUM_BYTES,
    "maxResponseBytes",
  );
  const clock =
    options.now === undefined
      ? () => new Date()
      : typeof options.now === "function" && !utilTypes.isProxy(options.now)
        ? (options.now as BaseRpcCollectorClock)
        : invalidConfiguration("now must be a clock function.");
  const collector: BaseRpcAnchorCollector = {
    attemptBinding: attemptAuthorization.binding,
    mode: "live",
    async collectRaw(collectOptionsValue) {
      if (arguments.length > 1) {
        invalidConfiguration("collectRaw accepts only an optional AbortSignal wrapper.");
      }
      const { signal } = validateCollectOptions(collectOptionsValue);
      const prepared = prepareBaseRpcAnchorCollectorRequest();
      assertCredentialAbsentFromRequest(prepared, apiKey);
      if (
        runtimeCollectionAuthorization.actionId !==
        baseRpcAnchorRuntimeActionId(attemptAuthorization.binding.attemptId, prepared.fingerprint)
      ) {
        throw new BaseRpcCollectorError(
          "RUNTIME_AUTHORIZATION_FAILED",
          "The runtime collection authorization does not match this request.",
        );
      }
      if (signal?.aborted === true) {
        throw new BaseRpcCollectorError("ABORTED", "The Base RPC anchor request was aborted.");
      }
      let responsePromise: Promise<QuarantinedBaseRpcAnchorResponse> | undefined;
      let runtimeDispatchFailure: unknown;
      try {
        runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {
          assertRuntimeReceipt(receipt, runtimeCollectionAuthorization);
          let dispatchReceipt: Readonly<NetworkAttemptDispatchReceipt>;
          try {
            dispatchReceipt = attemptAuthorization.consume();
          } catch {
            throw new BaseRpcCollectorError(
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
          if (error instanceof BaseRpcCollectorError) throw error;
          throw new BaseRpcCollectorError(
            "RUNTIME_AUTHORIZATION_FAILED",
            "The runtime collection authorization could not protect dispatch.",
          );
        }
        runtimeDispatchFailure = error;
      }
      if (responsePromise === undefined) {
        throw new BaseRpcCollectorError(
          "RUNTIME_AUTHORIZATION_FAILED",
          "The runtime collection authorization did not invoke dispatch.",
        );
      }
      if (runtimeDispatchFailure !== undefined) {
        try {
          const abandoned = await responsePromise;
          abandoned.destroy();
        } catch {
          // The failed runtime commit remains authoritative, but a launched
          // response must still be drained and destroyed.
        }
        if (runtimeDispatchFailure instanceof BaseRpcCollectorError) {
          throw runtimeDispatchFailure;
        }
        throw new BaseRpcCollectorError(
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
