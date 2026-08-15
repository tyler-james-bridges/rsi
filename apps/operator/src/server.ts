import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  OPERATOR_DASHBOARD_CSS,
  OPERATOR_DASHBOARD_HTML,
  OPERATOR_DASHBOARD_JS,
} from "./dashboard-assets.js";

export type PublicJsonValue =
  null | boolean | number | string | PublicJsonValue[] | { [key: string]: PublicJsonValue };

export interface OperatorEventQuery {
  readonly limit: number;
  readonly cursor?: string;
  readonly type?: string;
  readonly decisionId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface OperatorEventPage {
  readonly items: readonly unknown[];
  readonly nextCursor?: string | null;
}

/**
 * Read-only boundary between the operator service and a durable event store.
 * Implementations must parameterize their own database queries; all values passed
 * here have already been syntactically validated and bounded by the HTTP layer.
 */
export interface OperatorSnapshotProvider {
  getSummary(): Promise<unknown> | unknown;
  listEvents(query: Readonly<OperatorEventQuery>): Promise<OperatorEventPage> | OperatorEventPage;
  getDecision(id: string): Promise<unknown | null> | unknown | null;
}

export type OperatorControlCommand =
  | Readonly<{ action: "plan"; sessionId: string }>
  | Readonly<{
      action: "start";
      observerOnlyAcknowledgement: true;
      sessionId: string;
      typedSessionIdAcknowledgement: string;
    }>
  | Readonly<{
      action: "acknowledge";
      checkpoint: "minute-45" | "minute-90";
      sessionId: string;
    }>
  | Readonly<{ action: "abort" | "close"; sessionId: string }>
  | Readonly<{
      action: "label";
      findingId: string;
      label: "misleading" | "noise" | "unclear" | "useful";
    }>
  | Readonly<{ action: "prepare-candidate"; findingId: string }>;

export interface OperatorControlProvider {
  readonly supportedActions: readonly OperatorControlCommand["action"][];
  executeControl(command: OperatorControlCommand): Promise<unknown> | unknown;
}

export interface OperatorServerOptions {
  /** Defaults to IPv4 loopback. Only 127.0.0.1 and ::1 are accepted. */
  readonly host?: string;
  /** Defaults to 8787. Use 0 to ask the operating system for an ephemeral port. */
  readonly port?: number;
  /** Omit to serve the dashboard in read-only mode. */
  readonly controls?: OperatorControlProvider;
}

export interface RunningOperatorServer {
  readonly server: Server;
  readonly host: string;
  readonly port: number;
  readonly origin: string;
  close(): Promise<void>;
}

const DEFAULT_EVENT_LIMIT = 50;
const MAX_EVENT_LIMIT = 100;
const MAX_REQUEST_TARGET_LENGTH = 2_048;
const MAX_CONTROL_BODY_BYTES = 4_096;
const MAX_PROJECTION_DEPTH = 24;
const MAX_PROJECTED_ARRAY_LENGTH = 1_000;
const MAX_PROJECTED_OBJECT_KEYS = 512;

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

const FORBIDDEN_FIELD_NAMES = new Set([
  "raw",
  "rawbody",
  "rawpayload",
  "rawtext",
  "bytes",
  "content",
  "posttext",
  "html",
  "markdown",
  "privatekey",
  "seedphrase",
  "recoveryphrase",
  "recoverycode",
  "mnemonic",
  "password",
  "passphrase",
  "apikey",
  "secret",
  "secretkey",
  "clientsecret",
  "accesstoken",
  "refreshtoken",
  "sessiontoken",
  "authtoken",
  "bearertoken",
  "idtoken",
  "jwt",
  "cookie",
  "setcookie",
  "accountnumber",
  "cardnumber",
  "cvv",
  "cvc",
  "pin",
  "authorization",
  "credentials",
]);

const UNSAFE_META_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const QUERY_KEYS = new Set(["limit", "cursor", "type", "decisionId", "since", "until"]);
const SAFE_CURSOR = /^seq:[1-9]\d{0,15}$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_EVENT_TYPE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function normalizedFieldName(name: string): string {
  return name.replaceAll(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function isForbiddenField(name: string): boolean {
  const normalized = normalizedFieldName(name);
  return (
    FORBIDDEN_FIELD_NAMES.has(normalized) ||
    normalized.endsWith("privatekey") ||
    normalized.endsWith("apikey") ||
    normalized.endsWith("accesstoken") ||
    normalized.endsWith("refreshtoken") ||
    normalized.endsWith("sessiontoken") ||
    normalized.endsWith("clientsecret") ||
    normalized.endsWith("bearertoken") ||
    normalized.endsWith("idtoken") ||
    normalized.endsWith("password") ||
    normalized.endsWith("secret") ||
    UNSAFE_META_KEYS.has(name)
  );
}

/**
 * Projects arbitrary provider data into a deliberately small, JSON-only public
 * representation. Sensitive field names are removed recursively and binary,
 * executable, accessor, cyclic, or excessively deep values are never traversed.
 */
export function projectPublicJson(value: unknown): PublicJsonValue {
  return projectValue(value, new WeakSet<object>(), 0) ?? null;
}

function projectValue(
  value: unknown,
  ancestors: WeakSet<object>,
  depth: number,
): PublicJsonValue | undefined {
  if (value === null) return null;

  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      return Number.isFinite(value) ? value : null;
    case "bigint":
      return value.toString();
    case "undefined":
    case "function":
    case "symbol":
      return undefined;
    case "object":
      break;
  }

  if (depth >= MAX_PROJECTION_DEPTH) return undefined;
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp) ? value.toISOString() : null;
  }
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return undefined;
  if (ancestors.has(value)) return undefined;

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const projected: PublicJsonValue[] = [];
      for (const item of value.slice(0, MAX_PROJECTED_ARRAY_LENGTH)) {
        const next = projectValue(item, ancestors, depth + 1);
        if (next !== undefined) projected.push(next);
      }
      return projected;
    }

    const projected: { [key: string]: PublicJsonValue } = Object.create(null) as {
      [key: string]: PublicJsonValue;
    };
    let projectedKeys = 0;

    for (const key of Object.keys(value)) {
      if (projectedKeys >= MAX_PROJECTED_OBJECT_KEYS) break;
      if (isForbiddenField(key)) continue;

      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) continue;
      const next = projectValue(descriptor.value, ancestors, depth + 1);
      if (next === undefined) continue;

      projected[key] = next;
      projectedKeys += 1;
    }
    return projected;
  } finally {
    ancestors.delete(value);
  }
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders = {},
): void {
  const encoded = JSON.stringify(projectPublicJson(body));
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

function parseTimestamp(value: string | undefined, key: "since" | "until"): string | undefined {
  if (value === undefined) return undefined;
  if (!UTC_TIMESTAMP.test(value))
    badRequest(`Query parameter '${key}' must be a UTC ISO timestamp.`);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) badRequest(`Query parameter '${key}' is not a valid timestamp.`);
  const normalized = new Date(timestamp).toISOString();
  if (normalized.slice(0, 19) !== value.slice(0, 19)) {
    badRequest(`Query parameter '${key}' is not a valid calendar timestamp.`);
  }
  return normalized;
}

function isSafeCursor(value: string): boolean {
  return SAFE_CURSOR.test(value) && Number.isSafeInteger(Number(value.slice(4)));
}

function parseEventQuery(url: URL): OperatorEventQuery {
  for (const key of url.searchParams.keys()) {
    if (!QUERY_KEYS.has(key)) badRequest(`Unsupported query parameter '${key}'.`);
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
  if (cursor !== undefined && !isSafeCursor(cursor)) {
    badRequest("Query parameter 'cursor' is invalid.");
  }

  const type = oneQueryValue(url, "type");
  if (type !== undefined && !SAFE_EVENT_TYPE.test(type)) {
    badRequest("Query parameter 'type' is invalid.");
  }

  const decisionId = oneQueryValue(url, "decisionId");
  if (decisionId !== undefined && !SAFE_IDENTIFIER.test(decisionId)) {
    badRequest("Query parameter 'decisionId' is invalid.");
  }

  const since = parseTimestamp(oneQueryValue(url, "since"), "since");
  const until = parseTimestamp(oneQueryValue(url, "until"), "until");
  if (since !== undefined && until !== undefined && Date.parse(since) > Date.parse(until)) {
    badRequest("Query parameter 'since' must not be later than 'until'.");
  }

  return {
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(type === undefined ? {} : { type }),
    ...(decisionId === undefined ? {} : { decisionId }),
    ...(since === undefined ? {} : { since }),
    ...(until === undefined ? {} : { until }),
  };
}

function parseDecisionId(pathname: string): string | null {
  const match = /^\/api\/decisions\/([^/]+)$/.exec(pathname);
  if (match === null) return null;

  let id: string;
  try {
    id = decodeURIComponent(match[1] ?? "");
  } catch {
    badRequest("Decision id is not valid URL encoding.");
  }
  if (!SAFE_IDENTIFIER.test(id)) badRequest("Decision id is invalid.");
  return id;
}

function outputCursor(value: unknown): string | null {
  return typeof value === "string" && isSafeCursor(value) ? value : null;
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

function exactJsonRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    badRequest("Control body must be an object.");
  if (Object.getPrototypeOf(value) !== Object.prototype) badRequest("Control body is invalid.");
  const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") badRequest("Control body is invalid.");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      badRequest("Control body is invalid.");
    }
    record[key] = descriptor.value;
  }
  return record;
}

function assertExactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    badRequest("Control body has unsupported or missing fields.");
  }
}

function parseControlCommand(value: unknown): OperatorControlCommand {
  const record = exactJsonRecord(value);
  if (record.action === "plan") {
    assertExactKeys(record, ["action", "sessionId"]);
    if (typeof record.sessionId !== "string" || !UUID_V4.test(record.sessionId)) {
      badRequest("Session id is invalid.");
    }
    return Object.freeze({ action: "plan", sessionId: record.sessionId });
  }
  if (record.action === "start") {
    assertExactKeys(record, [
      "action",
      "observerOnlyAcknowledgement",
      "sessionId",
      "typedSessionIdAcknowledgement",
    ]);
    if (
      record.observerOnlyAcknowledgement !== true ||
      typeof record.sessionId !== "string" ||
      !UUID_V4.test(record.sessionId) ||
      record.typedSessionIdAcknowledgement !== record.sessionId
    ) {
      badRequest("Start acknowledgement is invalid.");
    }
    return Object.freeze({
      action: "start",
      observerOnlyAcknowledgement: true,
      sessionId: record.sessionId,
      typedSessionIdAcknowledgement: record.sessionId,
    });
  }
  if (record.action === "acknowledge") {
    assertExactKeys(record, ["action", "checkpoint", "sessionId"]);
    if (
      (record.checkpoint !== "minute-45" && record.checkpoint !== "minute-90") ||
      typeof record.sessionId !== "string" ||
      !UUID_V4.test(record.sessionId)
    ) {
      badRequest("Supervision acknowledgement is invalid.");
    }
    return Object.freeze({
      action: "acknowledge",
      checkpoint: record.checkpoint,
      sessionId: record.sessionId,
    });
  }
  if (record.action === "abort" || record.action === "close") {
    assertExactKeys(record, ["action", "sessionId"]);
    if (typeof record.sessionId !== "string" || !UUID_V4.test(record.sessionId)) {
      badRequest("Session id is invalid.");
    }
    return Object.freeze({ action: record.action, sessionId: record.sessionId });
  }
  if (record.action === "label") {
    assertExactKeys(record, ["action", "findingId", "label"]);
    if (
      typeof record.findingId !== "string" ||
      !SAFE_IDENTIFIER.test(record.findingId) ||
      (record.label !== "useful" &&
        record.label !== "unclear" &&
        record.label !== "noise" &&
        record.label !== "misleading")
    ) {
      badRequest("Feedback command is invalid.");
    }
    return Object.freeze({
      action: "label",
      findingId: record.findingId,
      label: record.label,
    });
  }
  if (record.action === "prepare-candidate") {
    assertExactKeys(record, ["action", "findingId"]);
    if (typeof record.findingId !== "string" || !SAFE_IDENTIFIER.test(record.findingId)) {
      badRequest("Candidate command is invalid.");
    }
    return Object.freeze({ action: "prepare-candidate", findingId: record.findingId });
  }
  badRequest("Control action is unsupported.");
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
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_CONTROL_BODY_BYTES) {
      throw new HttpError(413, "request_too_large", "Control request is too large.");
    }
    chunks.push(bytes);
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

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  provider: OperatorSnapshotProvider,
  controls: OperatorControlProvider | undefined,
): Promise<void> {
  const origin = assertLoopbackHost(request);
  const target = request.url ?? "/";
  if (target.length > MAX_REQUEST_TARGET_LENGTH) {
    throw new HttpError(414, "request_target_too_long", "Request target is too long.");
  }
  const url = new URL(target, "http://operator.invalid");

  if (request.method === "POST" && url.pathname === "/api/control") {
    if (url.search !== "") badRequest("The control route does not accept query parameters.");
    if (controls === undefined) {
      throw new HttpError(501, "controls_unavailable", "Session controls are not configured.");
    }
    assertSameOriginControl(request, origin);
    const command = parseControlCommand(await readControlBody(request));
    if (!controls.supportedActions.includes(command.action)) {
      throw new HttpError(501, "control_unavailable", "This local control is not configured.");
    }
    const result = await controls.executeControl(command);
    sendJson(response, 200, { result });
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
    sendAsset(response, "text/html; charset=utf-8", OPERATOR_DASHBOARD_HTML);
    return;
  }

  if (url.pathname === "/operator.css") {
    if (url.search !== "") badRequest("The stylesheet route does not accept query parameters.");
    sendAsset(response, "text/css; charset=utf-8", OPERATOR_DASHBOARD_CSS);
    return;
  }

  if (url.pathname === "/operator.js") {
    if (url.search !== "") badRequest("The script route does not accept query parameters.");
    sendAsset(response, "text/javascript; charset=utf-8", OPERATOR_DASHBOARD_JS);
    return;
  }

  if (url.pathname === "/health") {
    if (url.search !== "") badRequest("The health route does not accept query parameters.");
    sendJson(response, 200, { status: "ok" });
    return;
  }

  if (url.pathname === "/api/summary") {
    if (url.search !== "") badRequest("The summary route does not accept query parameters.");
    const summary = await provider.getSummary();
    sendJson(response, 200, { summary });
    return;
  }

  if (url.pathname === "/api/control/capabilities") {
    if (url.search !== "") badRequest("The capabilities route does not accept query parameters.");
    sendJson(response, 200, {
      controls: {
        actions: controls?.supportedActions ?? [],
        enabled: controls !== undefined,
      },
    });
    return;
  }

  if (url.pathname === "/api/events") {
    const query = parseEventQuery(url);
    const page = await provider.listEvents(query);
    if (page === null || typeof page !== "object" || !Array.isArray(page.items)) {
      throw new Error("Operator provider returned an invalid event page.");
    }
    sendJson(response, 200, {
      events: page.items.slice(0, query.limit),
      page: {
        limit: query.limit,
        nextCursor: outputCursor(page.nextCursor),
      },
    });
    return;
  }

  const decisionId = parseDecisionId(url.pathname);
  if (decisionId !== null) {
    if (url.search !== "") badRequest("The decision route does not accept query parameters.");
    const decision = await provider.getDecision(decisionId);
    if (decision === null || decision === undefined) {
      throw new HttpError(404, "not_found", "Decision was not found.");
    }
    sendJson(response, 200, { decision });
    return;
  }

  throw new HttpError(404, "not_found", "Route was not found.");
}

export function createOperatorServer(
  provider: OperatorSnapshotProvider,
  controls?: OperatorControlProvider,
): Server {
  const server = createServer((request, response) => {
    void route(request, response, provider, controls).catch((error: unknown) => {
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
      sendJson(response, 500, {
        error: { code: "internal_error", message: "The operator snapshot could not be read." },
      });
    });
  });

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

export async function startOperatorServer(
  provider: OperatorSnapshotProvider,
  options: OperatorServerOptions = {},
): Promise<RunningOperatorServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8_787;
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new RangeError("Operator server host must be IPv4 or IPv6 loopback.");
  }
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new RangeError("Operator server port must be an integer from 0 through 65535.");
  }

  const server = createOperatorServer(provider, options.controls);
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
    throw new Error("Operator server did not bind to an IP socket.");
  }

  let closed = false;
  return {
    server,
    host: address.address,
    port: address.port,
    origin: addressOrigin(address.address, address.port),
    close: async () => {
      if (closed || !server.listening) return;
      closed = true;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    },
  };
}
