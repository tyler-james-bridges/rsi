import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { BlockList, isIP } from "node:net";
import { types as utilTypes } from "node:util";

import { OpenSeaReadCanaryConflictError } from "@rsi/read-canary/opensea";
import { RuntimeConflictError } from "@rsi/runtime";

import {
  OPENSEA_OPERATOR_DASHBOARD_CSS,
  OPENSEA_OPERATOR_DASHBOARD_HTML,
  OPENSEA_OPERATOR_DASHBOARD_JS,
} from "./opensea-dashboard-assets.js";
import {
  parseOperatorOpenSeaReadCanaryCommand,
  parseOperatorOpenSeaReadCanaryProjection,
  parseOperatorOpenSeaReadCanaryReceipt,
  type OperatorOpenSeaReadCanaryProvider,
} from "./opensea-read-canary.js";
import type {
  OperatorRuntimeProvider,
  OperatorRuntimeSnapshotV1,
  RuntimeOperatorAction,
  RuntimeOperatorControlCommand,
} from "./runtime-types.js";

export interface OpenSeaOperatorEventQuery {
  readonly limit: number;
  readonly cursor?: string;
  readonly type?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface OpenSeaOperatorEventPage {
  readonly items: readonly unknown[];
  readonly nextCursor?: string | null;
}

export interface OpenSeaOperatorSnapshotProvider {
  listEvents(
    query: Readonly<OpenSeaOperatorEventQuery>,
  ): Promise<OpenSeaOperatorEventPage> | OpenSeaOperatorEventPage;
}

export interface OpenSeaOperatorServerOptions {
  readonly host?: string;
  readonly port?: number;
  readonly runtime: OperatorRuntimeProvider;
  readonly readCanary: OperatorOpenSeaReadCanaryProvider;
}

export interface RunningOpenSeaOperatorServer {
  readonly server: Server;
  readonly host: string;
  readonly port: number;
  readonly origin: string;
  close(): Promise<void>;
}

interface PublicRuntimeEventV1 {
  readonly sequence: number;
  readonly type: string;
  readonly occurredAt: string;
}

interface PublicRuntimeSnapshotV1 {
  readonly schemaVersion: 1;
  readonly mode: OperatorRuntimeSnapshotV1["mode"];
  readonly revision: number;
  readonly modeChangedAt: string;
  readonly capabilities: OperatorRuntimeSnapshotV1["capabilities"];
}

const DEFAULT_EVENT_LIMIT = 50;
const MAX_EVENT_LIMIT = 100;
const MAX_REQUEST_TARGET_LENGTH = 2_048;
const MAX_CONTROL_BODY_BYTES = 4_096;
const CONTROL_BODY_TIMEOUT_MS = 5_000;
const SAFE_CURSOR = /^seq:[1-9]\d{0,15}$/;
const SAFE_EVENT_TYPE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const PUBLIC_RUNTIME_ACTIONS = Object.freeze([
  "runtime-enter-research",
  "runtime-stop",
] as const satisfies readonly RuntimeOperatorAction[]);

const BASE_HEADERS = Object.freeze({
  "cache-control": "no-store, max-age=0",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
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
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
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
  const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
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

export function parseOpenSeaOperatorRuntimeSnapshot(value: unknown): OperatorRuntimeSnapshotV1 {
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
    modeChangedAt: snapshot.modeChangedAt,
    capabilities: snapshot.capabilities,
  });
}

function parsePublicRuntimeEvent(value: unknown): Readonly<PublicRuntimeEventV1> {
  const event = strictRecord(value, ["sequence", "type", "occurredAt"], "Runtime event");
  if (
    !Number.isSafeInteger(event.sequence) ||
    Number(event.sequence) < 1 ||
    typeof event.type !== "string" ||
    !SAFE_EVENT_TYPE.test(event.type) ||
    !canonicalTimestamp(event.occurredAt)
  ) {
    throw new TypeError("Runtime event is invalid");
  }
  return Object.freeze({
    sequence: Number(event.sequence),
    type: event.type,
    occurredAt: event.occurredAt,
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

function oneQueryValue(url: URL, key: string): string | undefined {
  const values = url.searchParams.getAll(key);
  if (values.length > 1) badRequest(`Query parameter '${key}' may only appear once.`);
  return values[0];
}

function parseEventTimestamp(
  value: string | undefined,
  key: "since" | "until",
): string | undefined {
  if (value === undefined) return undefined;
  if (!canonicalTimestamp(value)) {
    badRequest(`Query parameter '${key}' must be a canonical UTC timestamp.`);
  }
  return value;
}

function isSafeCursor(value: string): boolean {
  return SAFE_CURSOR.test(value) && Number.isSafeInteger(Number(value.slice(4)));
}

function parseEventQuery(url: URL): OpenSeaOperatorEventQuery {
  const allowed = new Set(["limit", "cursor", "type", "since", "until"]);
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key)) badRequest(`Unsupported query parameter '${key}'.`);
  }
  const rawLimit = oneQueryValue(url, "limit");
  if (rawLimit !== undefined && !/^[1-9]\d{0,2}$/.test(rawLimit)) {
    badRequest("Query parameter 'limit' must be an integer from 1 through 100.");
  }
  const limit = rawLimit === undefined ? DEFAULT_EVENT_LIMIT : Number(rawLimit);
  if (limit < 1 || limit > MAX_EVENT_LIMIT) {
    badRequest("Query parameter 'limit' must be an integer from 1 through 100.");
  }
  const cursor = oneQueryValue(url, "cursor");
  if (cursor !== undefined && !isSafeCursor(cursor)) badRequest("Event cursor is invalid.");
  const type = oneQueryValue(url, "type");
  if (type !== undefined && !SAFE_EVENT_TYPE.test(type)) badRequest("Event type is invalid.");
  const since = parseEventTimestamp(oneQueryValue(url, "since"), "since");
  const until = parseEventTimestamp(oneQueryValue(url, "until"), "until");
  if (since !== undefined && until !== undefined && Date.parse(since) > Date.parse(until)) {
    badRequest("Query parameter 'since' must not be later than 'until'.");
  }
  return Object.freeze({
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(type === undefined ? {} : { type }),
    ...(since === undefined ? {} : { since }),
    ...(until === undefined ? {} : { until }),
  });
}

const LOOPBACK_ADDRESSES = new BlockList();
LOOPBACK_ADDRESSES.addSubnet("127.0.0.0", 8, "ipv4");
LOOPBACK_ADDRESSES.addAddress("::1", "ipv6");

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
  const hostHeaders: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === "host") {
      hostHeaders.push(request.rawHeaders[index + 1] ?? "");
    }
  }
  if (hostHeaders.length !== 1) {
    throw new HttpError(400, "invalid_host", "Exactly one loopback Host header is required.");
  }
  let parsed: URL;
  try {
    parsed = new URL(`http://${hostHeaders[0]}`);
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
  return `http://${hostHeaders[0]}`;
}

async function readControlBody(request: IncomingMessage): Promise<unknown> {
  const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "unsupported_media_type", "Control requests require JSON.");
  }
  const declared = request.headers["content-length"];
  if (
    declared !== undefined &&
    (!/^\d{1,5}$/.test(declared) || Number(declared) > MAX_CONTROL_BODY_BYTES)
  ) {
    throw new HttpError(413, "request_too_large", "Control request is too large.");
  }
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
      if (total > MAX_CONTROL_BODY_BYTES) {
        throw new HttpError(413, "request_too_large", "Control request is too large.");
      }
      chunks.push(bytes);
    }
  } finally {
    clearTimeout(absoluteTimeout);
  }
  if (total === 0) badRequest("Control request body is empty.");
  try {
    return JSON.parse(Buffer.concat(chunks, total).toString("utf8")) as unknown;
  } catch {
    badRequest("Control request body is not valid JSON.");
  }
}

function assertSameOriginControl(request: IncomingMessage, origin: string): void {
  if (request.headers.origin !== origin || request.headers["x-rsi-operator-request"] !== "1") {
    throw new HttpError(403, "control_origin_rejected", "Control request origin is invalid.");
  }
  const fetchSite = request.headers["sec-fetch-site"];
  if (fetchSite !== undefined && fetchSite !== "same-origin") {
    throw new HttpError(403, "control_origin_rejected", "Control request is not same-origin.");
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
  if (!actions.includes("runtime-stop")) {
    throw new TypeError("Durable STOP is required");
  }
  return actions;
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  provider: OpenSeaOperatorSnapshotProvider,
  options: OpenSeaOperatorServerOptions,
  routeState: { running: boolean },
): Promise<void> {
  assertLoopbackLocalSocket(request);
  const origin = assertLoopbackHost(request);
  const target = request.url ?? "/";
  if (target.length > MAX_REQUEST_TARGET_LENGTH) {
    throw new HttpError(414, "request_target_too_long", "Request target is too long.");
  }
  const url = new URL(target, "http://operator.invalid");

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
      parseOpenSeaOperatorRuntimeSnapshot(await options.runtime.executeRuntimeControl(command)),
    );
    sendJson(response, 200, { result });
    return;
  }

  if (
    request.method === "POST" &&
    url.pathname === "/api/opensea-read-canary/refresh-credential-status"
  ) {
    if (url.search !== "") badRequest("The credential route does not accept query parameters.");
    assertSameOriginControl(request, origin);
    if (
      (request.headers["content-length"] !== undefined &&
        request.headers["content-length"] !== "0") ||
      request.headers["transfer-encoding"] !== undefined
    ) {
      badRequest("The credential route does not accept a request body.");
    }
    const projection = parseOperatorOpenSeaReadCanaryProjection(
      await options.readCanary.refreshOpenSeaCredentialStatus(),
    );
    sendJson(response, 200, { openSeaReadCanary: projection });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/opensea-read-canary/run") {
    if (url.search !== "") badRequest("The canary route does not accept query parameters.");
    assertSameOriginControl(request, origin);
    const runtime = publicRuntimeSnapshot(
      parseOpenSeaOperatorRuntimeSnapshot(await options.runtime.getRuntimeSnapshot()),
    );
    if (runtime.mode !== "RESEARCH") {
      throw new HttpError(409, "runtime_not_research", "Enter RESEARCH before this canary.");
    }
    let command;
    try {
      command = parseOperatorOpenSeaReadCanaryCommand(await readControlBody(request));
    } catch (error) {
      if (error instanceof HttpError) throw error;
      badRequest("OpenSea read canary command is invalid.");
    }
    if (routeState.running) {
      throw new HttpError(409, "opensea_read_canary_conflict", "The canary is already running.");
    }
    routeState.running = true;
    try {
      const result = parseOperatorOpenSeaReadCanaryReceipt(
        await options.readCanary.executeOpenSeaReadCanary(command),
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

  if (url.pathname === "/") {
    if (url.search !== "") badRequest("The dashboard route does not accept query parameters.");
    sendAsset(response, "text/html; charset=utf-8", OPENSEA_OPERATOR_DASHBOARD_HTML);
    return;
  }
  if (url.pathname === "/operator.css") {
    if (url.search !== "") badRequest("The stylesheet route does not accept query parameters.");
    sendAsset(response, "text/css; charset=utf-8", OPENSEA_OPERATOR_DASHBOARD_CSS);
    return;
  }
  if (url.pathname === "/operator.js") {
    if (url.search !== "") badRequest("The script route does not accept query parameters.");
    sendAsset(response, "text/javascript; charset=utf-8", OPENSEA_OPERATOR_DASHBOARD_JS);
    return;
  }
  if (url.pathname === "/health") {
    if (url.search !== "") badRequest("The readiness route does not accept query parameters.");
    sendJson(response, 200, {
      status: "ok",
      runtime: "persisted",
    });
    return;
  }
  if (url.pathname === "/api/runtime") {
    if (url.search !== "") badRequest("The runtime route does not accept query parameters.");
    const runtime = publicRuntimeSnapshot(
      parseOpenSeaOperatorRuntimeSnapshot(await options.runtime.getRuntimeSnapshot()),
    );
    sendJson(response, 200, { financialAuthority: false, runtime });
    return;
  }
  if (url.pathname === "/api/opensea-read-canary") {
    if (url.search !== "") badRequest("The canary route does not accept query parameters.");
    const projection = parseOperatorOpenSeaReadCanaryProjection(
      await options.readCanary.getOpenSeaReadCanaryProjection(),
    );
    sendJson(response, 200, { openSeaReadCanary: projection });
    return;
  }
  if (url.pathname === "/api/control/capabilities") {
    if (url.search !== "") badRequest("The capabilities route does not accept query parameters.");
    sendJson(response, 200, {
      controls: {
        runtime: {
          actions: validatedRuntimeActions(options.runtime),
          enabled: true,
        },
      },
    });
    return;
  }
  if (url.pathname === "/api/events") {
    const query = parseEventQuery(url);
    const page = await provider.listEvents(query);
    if (
      page === null ||
      typeof page !== "object" ||
      utilTypes.isProxy(page) ||
      Object.getPrototypeOf(page) !== Object.prototype ||
      !Array.isArray(page.items)
    ) {
      throw new TypeError("Runtime event page is invalid");
    }
    const items = page.items.slice(0, query.limit).map(parsePublicRuntimeEvent);
    const nextCursor =
      typeof page.nextCursor === "string" && isSafeCursor(page.nextCursor) ? page.nextCursor : null;
    sendJson(response, 200, { events: items, page: { limit: query.limit, nextCursor } });
    return;
  }
  throw new HttpError(404, "not_found", "Route was not found.");
}

export function createOpenSeaOperatorServer(
  provider: OpenSeaOperatorSnapshotProvider,
  options: OpenSeaOperatorServerOptions,
): Server {
  validatedRuntimeActions(options.runtime);
  const routeState = { running: false };
  const server = createServer((request, response) => {
    void route(request, response, provider, options, routeState).catch((error: unknown) => {
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
      if (error instanceof OpenSeaReadCanaryConflictError) {
        sendJson(response, 409, {
          error: {
            code: "opensea_read_canary_conflict",
            message: "The OpenSea canary state changed; refresh and try again.",
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

export async function startOpenSeaOperatorServer(
  provider: OpenSeaOperatorSnapshotProvider,
  options: OpenSeaOperatorServerOptions,
): Promise<RunningOpenSeaOperatorServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8_787;
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new RangeError("OpenSea operator host must be IPv4 or IPv6 loopback.");
  }
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new RangeError("OpenSea operator port must be an integer from 0 through 65535.");
  }
  const server = createOpenSeaOperatorServer(provider, options);
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
    throw new Error("OpenSea operator server did not bind to an IP socket.");
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
