import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { BlockList, isIP } from "node:net";
import { types as utilTypes } from "node:util";

import { BaseRpcReadCanaryConflictError } from "@rsi/read-canary/base-rpc";
import { RuntimeConflictError } from "@rsi/runtime";

import {
  BASE_RPC_OPERATOR_DASHBOARD_CSS,
  BASE_RPC_OPERATOR_DASHBOARD_HTML,
  BASE_RPC_OPERATOR_DASHBOARD_JS,
} from "./base-rpc-dashboard-assets.js";
import {
  parseOperatorBaseRpcReadCanaryCommand,
  parseOperatorBaseRpcReadCanaryProjection,
  parseOperatorBaseRpcReadCanaryReceipt,
  type OperatorBaseRpcReadCanaryProvider,
} from "./base-rpc-read-canary.js";
import type {
  OperatorRuntimeProvider,
  OperatorRuntimeSnapshotV1,
  RuntimeOperatorAction,
  RuntimeOperatorControlCommand,
} from "./runtime-types.js";

export interface BaseRpcOperatorServerOptions {
  readonly host?: string;
  readonly port?: number;
  readonly runtime: OperatorRuntimeProvider;
  readonly readCanary: OperatorBaseRpcReadCanaryProvider;
}

export interface RunningBaseRpcOperatorServer {
  readonly server: Server;
  readonly host: string;
  readonly port: number;
  readonly origin: string;
  close(): Promise<void>;
}

interface PublicRuntimeSnapshotV1 {
  readonly schemaVersion: 1;
  readonly mode: OperatorRuntimeSnapshotV1["mode"];
  readonly revision: number;
}

const MAX_REQUEST_TARGET_LENGTH = 2_048;
const MAX_CONTROL_BODY_BYTES = 4_096;
const CONTROL_BODY_TIMEOUT_MS = 5_000;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})Z$/;
const PUBLIC_RUNTIME_ACTIONS = Object.freeze([
  "runtime-enter-research",
  "runtime-stop",
] as const satisfies readonly RuntimeOperatorAction[]);

const BASE_HEADERS = Object.freeze({
  "cache-control": "no-store, max-age=0",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
});

const DASHBOARD_HEADERS = Object.freeze({
  ...BASE_HEADERS,
  "content-security-policy":
    "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; navigate-to 'none'",
});

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function strictRecord(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  const record = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError(`${label} is invalid`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`${label} is invalid`);
    }
    record[key] = descriptor.value;
  }
  return record;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_TIMESTAMP.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

export function parseBaseRpcOperatorRuntimeSnapshot(value: unknown): OperatorRuntimeSnapshotV1 {
  const record = strictRecord(
    value,
    [
      "schemaVersion",
      "mode",
      "revision",
      "modeChangedAt",
      "processInstanceId",
      "auditHead",
      "capabilities",
    ],
    "Runtime snapshot",
  );
  if (
    record.schemaVersion !== 1 ||
    (record.mode !== "STOPPED" && record.mode !== "RESEARCH" && record.mode !== "PROPOSE_ONLY") ||
    !Number.isSafeInteger(record.revision) ||
    Number(record.revision) < 1 ||
    !canonicalTimestamp(record.modeChangedAt) ||
    typeof record.processInstanceId !== "string" ||
    !UUID_V4.test(record.processInstanceId)
  ) {
    throw new TypeError("Runtime snapshot is invalid");
  }
  const auditHead = strictRecord(record.auditHead, ["sequence", "hash"], "Runtime audit head");
  if (
    !Number.isSafeInteger(auditHead.sequence) ||
    Number(auditHead.sequence) < 1 ||
    typeof auditHead.hash !== "string" ||
    !LOWER_HEX_64.test(auditHead.hash)
  ) {
    throw new TypeError("Runtime audit head is invalid");
  }
  const capabilities = strictRecord(
    record.capabilities,
    [
      "researchCollection",
      "proposalPersistence",
      "policyApproval",
      "paidRead",
      "transactionBroadcast",
      "walletSign",
      "executionAdapter",
      "externalPublish",
    ],
    "Runtime capabilities",
  );
  if (
    typeof capabilities.researchCollection !== "boolean" ||
    typeof capabilities.proposalPersistence !== "boolean" ||
    capabilities.policyApproval !== false ||
    capabilities.paidRead !== false ||
    capabilities.transactionBroadcast !== false ||
    capabilities.walletSign !== false ||
    capabilities.executionAdapter !== false ||
    capabilities.externalPublish !== false ||
    capabilities.researchCollection !== (record.mode !== "STOPPED") ||
    capabilities.proposalPersistence !== (record.mode === "PROPOSE_ONLY")
  ) {
    throw new TypeError("Runtime capabilities are invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    mode: record.mode,
    revision: Number(record.revision),
    modeChangedAt: record.modeChangedAt,
    processInstanceId: record.processInstanceId,
    auditHead: Object.freeze({
      sequence: Number(auditHead.sequence),
      hash: auditHead.hash,
    }),
    capabilities: Object.freeze({
      researchCollection: capabilities.researchCollection,
      proposalPersistence: capabilities.proposalPersistence,
      policyApproval: false,
      paidRead: false,
      transactionBroadcast: false,
      walletSign: false,
      executionAdapter: false,
      externalPublish: false,
    }),
  });
}

function publicRuntimeSnapshot(
  snapshot: OperatorRuntimeSnapshotV1,
): Readonly<PublicRuntimeSnapshotV1> {
  return Object.freeze({
    schemaVersion: 1,
    mode: snapshot.mode,
    revision: snapshot.revision,
  });
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Readonly<Record<string, string>> = {},
): void {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    ...BASE_HEADERS,
    ...extraHeaders,
    "content-length": Buffer.byteLength(encoded).toString(),
    "content-type": "application/json; charset=utf-8",
  });
  response.end(encoded);
}

function sendAsset(response: ServerResponse, contentType: string, body: string): void {
  response.writeHead(200, {
    ...DASHBOARD_HEADERS,
    "content-length": Buffer.byteLength(body).toString(),
    "content-type": contentType,
  });
  response.end(body);
}

function badRequest(message: string): never {
  throw new HttpError(400, "invalid_request", message);
}

const LOOPBACK_ADDRESSES = new BlockList();
LOOPBACK_ADDRESSES.addSubnet("127.0.0.0", 8, "ipv4");
LOOPBACK_ADDRESSES.addAddress("::1", "ipv6");

function rawHeaderValues(request: IncomingMessage, name: string): readonly string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      values.push(request.rawHeaders[index + 1] ?? "");
    }
  }
  return values;
}

function assertLoopbackLocalSocket(request: IncomingMessage): void {
  const localAddress = request.socket.localAddress ?? "";
  const family = isIP(localAddress);
  const isLoopback =
    family === 4
      ? LOOPBACK_ADDRESSES.check(localAddress, "ipv4")
      : family === 6
        ? LOOPBACK_ADDRESSES.check(localAddress, "ipv6")
        : false;
  if (!isLoopback) {
    throw new HttpError(
      403,
      "loopback_socket_required",
      "Operator requests require a loopback socket.",
    );
  }
}

function assertLoopbackHost(request: IncomingMessage): string {
  const hosts = rawHeaderValues(request, "host");
  if (hosts.length !== 1) {
    throw new HttpError(400, "invalid_host", "Exactly one loopback Host header is required.");
  }
  let parsed: URL;
  try {
    parsed = new URL(`http://${hosts[0]}`);
  } catch {
    throw new HttpError(400, "invalid_host", "The Host header is invalid.");
  }
  const hostname = parsed.hostname.toLowerCase();
  if (
    (hostname !== "127.0.0.1" && hostname !== "[::1]") ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new HttpError(400, "invalid_host", "The Host header must name loopback.");
  }
  const effectivePort = parsed.port === "" ? 80 : Number(parsed.port);
  if (effectivePort !== request.socket.localPort) {
    throw new HttpError(400, "invalid_host", "The Host header port is invalid.");
  }
  return `http://${hosts[0]}`;
}

function assertNoAuthorityHeaders(request: IncomingMessage): void {
  for (const name of ["authorization", "proxy-authorization", "cookie", "x-api-key"]) {
    if (rawHeaderValues(request, name).length !== 0) {
      throw new HttpError(400, "authority_header_rejected", "Authority headers are not accepted.");
    }
  }
}

function assertSameOriginControl(request: IncomingMessage, origin: string): void {
  const origins = rawHeaderValues(request, "origin");
  const markers = rawHeaderValues(request, "x-rsi-operator-request");
  const fetchSites = rawHeaderValues(request, "sec-fetch-site");
  if (origins.length !== 1 || origins[0] !== origin || markers.length !== 1 || markers[0] !== "1") {
    throw new HttpError(403, "control_origin_rejected", "Control request origin is invalid.");
  }
  if (fetchSites.length > 1 || (fetchSites.length === 1 && fetchSites[0] !== "same-origin")) {
    throw new HttpError(403, "control_origin_rejected", "Control request is not same-origin.");
  }
  assertNoAuthorityHeaders(request);
}

function assertEmptyControlBody(request: IncomingMessage): void {
  const lengths = rawHeaderValues(request, "content-length");
  if (
    lengths.length > 1 ||
    (lengths.length === 1 && lengths[0] !== "0") ||
    rawHeaderValues(request, "transfer-encoding").length !== 0 ||
    rawHeaderValues(request, "content-type").length !== 0 ||
    rawHeaderValues(request, "content-encoding").length !== 0
  ) {
    badRequest("This control route does not accept a request body.");
  }
}

async function readControlBody(request: IncomingMessage): Promise<unknown> {
  const contentTypes = rawHeaderValues(request, "content-type");
  const lengths = rawHeaderValues(request, "content-length");
  if (contentTypes.length !== 1 || contentTypes[0]?.trim().toLowerCase() !== "application/json") {
    throw new HttpError(415, "unsupported_media_type", "Control requests require exact JSON.");
  }
  if (
    lengths.length !== 1 ||
    !/^\d{1,5}$/.test(lengths[0] ?? "") ||
    Number(lengths[0]) === 0 ||
    Number(lengths[0]) > MAX_CONTROL_BODY_BYTES ||
    rawHeaderValues(request, "transfer-encoding").length !== 0 ||
    rawHeaderValues(request, "content-encoding").length !== 0
  ) {
    throw new HttpError(413, "invalid_body_framing", "Control request framing is invalid.");
  }
  const declared = Number(lengths[0]);
  const chunks: Buffer[] = [];
  let total = 0;
  const absoluteTimeout = setTimeout(() => {
    request.destroy(new Error("local control body timed out"));
  }, CONTROL_BODY_TIMEOUT_MS);
  absoluteTimeout.unref();
  try {
    for await (const chunk of request) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.byteLength;
      if (total > MAX_CONTROL_BODY_BYTES || total > declared) {
        throw new HttpError(413, "request_too_large", "Control request is too large.");
      }
      chunks.push(bytes);
    }
  } finally {
    clearTimeout(absoluteTimeout);
  }
  if (total !== declared) badRequest("Control request length is invalid.");
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
    return JSON.parse(decoded) as unknown;
  } catch {
    badRequest("Control request body is not valid JSON.");
  }
}

function parseRuntimeCommand(value: unknown): RuntimeOperatorControlCommand {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    badRequest("Runtime command is invalid.");
  }
  const record = value as Record<string, unknown>;
  const keys = Reflect.ownKeys(record);
  for (const key of keys) {
    if (typeof key !== "string") badRequest("Runtime command is invalid.");
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      badRequest("Runtime command is invalid.");
    }
  }
  if (record.action === "runtime-stop") {
    if (
      keys.length !== 2 ||
      !Object.hasOwn(record, "action") ||
      !Object.hasOwn(record, "requestId") ||
      typeof record.requestId !== "string" ||
      !UUID_V4.test(record.requestId)
    ) {
      badRequest("Runtime STOP command is invalid.");
    }
    return Object.freeze({ action: "runtime-stop", requestId: record.requestId });
  }
  if (record.action === "runtime-enter-research") {
    if (
      keys.length !== 4 ||
      !Object.hasOwn(record, "action") ||
      !Object.hasOwn(record, "expectedMode") ||
      !Object.hasOwn(record, "expectedRevision") ||
      !Object.hasOwn(record, "requestId") ||
      (record.expectedMode !== "STOPPED" && record.expectedMode !== "PROPOSE_ONLY") ||
      !Number.isSafeInteger(record.expectedRevision) ||
      Number(record.expectedRevision) < 1 ||
      typeof record.requestId !== "string" ||
      !UUID_V4.test(record.requestId)
    ) {
      badRequest("Runtime RESEARCH command is invalid.");
    }
    return Object.freeze({
      action: "runtime-enter-research",
      expectedMode: record.expectedMode,
      expectedRevision: Number(record.expectedRevision),
      requestId: record.requestId,
    });
  }
  badRequest("Only RESEARCH and STOP runtime controls are available.");
}

function validatedRuntimeActions(
  runtime: OperatorRuntimeProvider,
): readonly RuntimeOperatorAction[] {
  if (!Array.isArray(runtime.supportedActions) || utilTypes.isProxy(runtime.supportedActions)) {
    throw new TypeError("Runtime control capabilities are invalid");
  }
  const actions = PUBLIC_RUNTIME_ACTIONS.filter((action) =>
    runtime.supportedActions.includes(action),
  );
  if (!actions.includes("runtime-stop")) throw new TypeError("Durable STOP is required");
  return actions;
}

function parseRequestTarget(target: string): URL {
  if (
    target.length > MAX_REQUEST_TARGET_LENGTH ||
    !target.startsWith("/") ||
    target.startsWith("//") ||
    target.includes("#")
  ) {
    throw new HttpError(400, "invalid_request_target", "Request target is invalid.");
  }
  const url = new URL(target, "http://operator.invalid");
  if (url.origin !== "http://operator.invalid" || url.username !== "" || url.password !== "") {
    throw new HttpError(400, "invalid_request_target", "Request target is invalid.");
  }
  return url;
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  options: BaseRpcOperatorServerOptions,
  routeState: { running: boolean },
): Promise<void> {
  assertLoopbackLocalSocket(request);
  const origin = assertLoopbackHost(request);
  const url = parseRequestTarget(request.url ?? "/");

  if (request.method === "POST" && url.pathname === "/api/control") {
    if (url.search !== "") badRequest("The control route does not accept query parameters.");
    assertSameOriginControl(request, origin);
    const command = parseRuntimeCommand(await readControlBody(request));
    if (!validatedRuntimeActions(options.runtime).includes(command.action)) {
      throw new HttpError(501, "control_unavailable", "This local control is not configured.");
    }
    if (command.action === "runtime-stop") {
      try {
        options.readCanary.abortActive();
      } catch {
        // Provider interruption must never block durable STOP.
      }
    }
    const result = publicRuntimeSnapshot(
      parseBaseRpcOperatorRuntimeSnapshot(await options.runtime.executeRuntimeControl(command)),
    );
    sendJson(response, 200, { result });
    return;
  }

  if (
    request.method === "POST" &&
    url.pathname === "/api/base-rpc-read-canary/refresh-credential-status"
  ) {
    if (url.search !== "") badRequest("The credential route does not accept query parameters.");
    assertSameOriginControl(request, origin);
    assertEmptyControlBody(request);
    const projection = parseOperatorBaseRpcReadCanaryProjection(
      await options.readCanary.refreshBaseRpcCredentialStatus(),
    );
    sendJson(response, 200, { baseRpcReadCanary: projection });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/base-rpc-read-canary/run") {
    if (url.search !== "") badRequest("The canary route does not accept query parameters.");
    assertSameOriginControl(request, origin);
    const runtime = publicRuntimeSnapshot(
      parseBaseRpcOperatorRuntimeSnapshot(await options.runtime.getRuntimeSnapshot()),
    );
    if (runtime.mode !== "RESEARCH") {
      throw new HttpError(409, "runtime_not_research", "Enter RESEARCH before this canary.");
    }
    let command;
    try {
      command = parseOperatorBaseRpcReadCanaryCommand(await readControlBody(request));
    } catch (error) {
      if (error instanceof HttpError) throw error;
      badRequest("Base RPC read canary command is invalid.");
    }
    if (routeState.running) {
      throw new HttpError(409, "base_rpc_read_canary_conflict", "The canary is already running.");
    }
    routeState.running = true;
    try {
      const result = parseOperatorBaseRpcReadCanaryReceipt(
        await options.readCanary.executeBaseRpcReadCanary(command),
      );
      sendJson(response, 200, { result });
    } finally {
      routeState.running = false;
    }
    return;
  }

  if (request.method !== "GET") {
    sendJson(
      response,
      405,
      { error: { code: "method_not_allowed", message: "Only GET is supported." } },
      { allow: "GET" },
    );
    return;
  }
  assertNoAuthorityHeaders(request);

  if (url.pathname === "/") {
    if (url.search !== "") badRequest("The dashboard route does not accept query parameters.");
    sendAsset(response, "text/html; charset=utf-8", BASE_RPC_OPERATOR_DASHBOARD_HTML);
    return;
  }
  if (url.pathname === "/operator.css") {
    if (url.search !== "") badRequest("The stylesheet route does not accept query parameters.");
    sendAsset(response, "text/css; charset=utf-8", BASE_RPC_OPERATOR_DASHBOARD_CSS);
    return;
  }
  if (url.pathname === "/operator.js") {
    if (url.search !== "") badRequest("The script route does not accept query parameters.");
    sendAsset(response, "text/javascript; charset=utf-8", BASE_RPC_OPERATOR_DASHBOARD_JS);
    return;
  }
  if (url.pathname === "/health") {
    if (url.search !== "") badRequest("The readiness route does not accept query parameters.");
    sendJson(response, 200, { status: "ok", runtime: "persisted" });
    return;
  }
  if (url.pathname === "/api/runtime") {
    if (url.search !== "") badRequest("The runtime route does not accept query parameters.");
    const runtime = publicRuntimeSnapshot(
      parseBaseRpcOperatorRuntimeSnapshot(await options.runtime.getRuntimeSnapshot()),
    );
    sendJson(response, 200, { financialAuthority: false, runtime });
    return;
  }
  if (url.pathname === "/api/base-rpc-read-canary") {
    if (url.search !== "") badRequest("The canary route does not accept query parameters.");
    const projection = parseOperatorBaseRpcReadCanaryProjection(
      await options.readCanary.getBaseRpcReadCanaryProjection(),
    );
    sendJson(response, 200, { baseRpcReadCanary: projection });
    return;
  }
  if (url.pathname === "/api/control/capabilities") {
    if (url.search !== "") badRequest("The capabilities route does not accept query parameters.");
    sendJson(response, 200, {
      controls: {
        runtime: { actions: validatedRuntimeActions(options.runtime), enabled: true },
      },
      financialAuthority: false,
    });
    return;
  }
  throw new HttpError(404, "not_found", "Route was not found.");
}

export function createBaseRpcOperatorServer(options: BaseRpcOperatorServerOptions): Server {
  validatedRuntimeActions(options.runtime);
  const routeState = { running: false };
  const server = createServer((request, response) => {
    void route(request, response, options, routeState).catch((error: unknown) => {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (error instanceof HttpError) {
        sendJson(response, error.status, {
          error: { code: error.code, message: error.message },
        });
        return;
      }
      if (error instanceof RuntimeConflictError) {
        sendJson(response, 409, {
          error: {
            code: "runtime_conflict",
            message: "Runtime mode changed; refresh and try again.",
          },
        });
        return;
      }
      if (error instanceof BaseRpcReadCanaryConflictError) {
        sendJson(response, 409, {
          error: {
            code: "base_rpc_read_canary_conflict",
            message: "The Base RPC canary state changed; refresh and try again.",
          },
        });
        return;
      }
      sendJson(response, 500, {
        error: { code: "internal_error", message: "The local operator request failed." },
      });
    });
  });
  server.headersTimeout = CONTROL_BODY_TIMEOUT_MS;
  server.requestTimeout = CONTROL_BODY_TIMEOUT_MS;
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 25;
  server.on("upgrade", (_request, socket) => socket.destroy());
  server.on("clientError", (_error, socket) => {
    const encoded = JSON.stringify({
      error: { code: "malformed_request", message: "The HTTP request was malformed." },
    });
    socket.end(
      `HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(encoded)}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\r\n${encoded}`,
    );
  });
  return server;
}

function addressOrigin(host: string, port: number): string {
  return `http://${host.includes(":") ? `[${host}]` : host}:${port}`;
}

export async function startBaseRpcOperatorServer(
  options: BaseRpcOperatorServerOptions,
): Promise<RunningBaseRpcOperatorServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8_788;
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new RangeError("Base RPC operator host must be IPv4 or IPv6 loopback.");
  }
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new RangeError("Base RPC operator port must be an integer from 0 through 65535.");
  }
  const server = createBaseRpcOperatorServer(options);
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host, port });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error("Base RPC operator server did not bind to an IP socket.");
  }
  let closed = false;
  return Object.freeze({
    server,
    host: address.address,
    port: address.port,
    origin: addressOrigin(address.address, address.port),
    close: async () => {
      if (closed || !server.listening) return;
      closed = true;
      try {
        options.readCanary.abortActive();
      } catch {
        // Provider interruption must not prevent loopback shutdown.
      }
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
        server.closeAllConnections();
      });
    },
  });
}
