import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

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

export interface OperatorServerOptions {
  /** Defaults to IPv4 loopback. Only 127.0.0.1 and ::1 are accepted. */
  readonly host?: string;
  /** Defaults to 8787. Use 0 to ask the operating system for an ephemeral port. */
  readonly port?: number;
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

function assertLoopbackHost(request: IncomingMessage): void {
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
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  provider: OperatorSnapshotProvider,
): Promise<void> {
  assertLoopbackHost(request);
  if (request.method !== "GET") {
    sendJson(
      response,
      405,
      { error: { code: "method_not_allowed", message: "Only GET is supported." } },
      { allow: "GET" },
    );
    return;
  }

  const target = request.url ?? "/";
  if (target.length > MAX_REQUEST_TARGET_LENGTH) {
    throw new HttpError(414, "request_target_too_long", "Request target is too long.");
  }
  const url = new URL(target, "http://operator.invalid");

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

export function createOperatorServer(provider: OperatorSnapshotProvider): Server {
  const server = createServer((request, response) => {
    void route(request, response, provider).catch((error: unknown) => {
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

  const server = createOperatorServer(provider);
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
