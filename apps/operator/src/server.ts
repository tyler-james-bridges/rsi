import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { BlockList, isIP } from "node:net";
import { types as utilTypes } from "node:util";

import { ResearchProposalV1Schema, type ResearchProposalV1 } from "@rsi/domain/proposals";
import { RuntimeConflictError } from "@rsi/runtime";

import {
  OPERATOR_DASHBOARD_CSS,
  OPERATOR_DASHBOARD_HTML,
  OPERATOR_DASHBOARD_JS,
} from "./dashboard-assets.js";
import {
  parseOperatorReadCanaryCommand,
  parseOperatorReadCanaryProjection,
  parseOperatorReadCanaryReceipt,
} from "./read-canary.js";
import type { OperatorReadCanaryProvider } from "./read-canary.js";

export type { OperatorReadCanaryProvider } from "./read-canary.js";

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

export type RuntimeOperatorAction =
  "runtime-enter-propose-only" | "runtime-enter-research" | "runtime-stop";

export type RuntimeOperatorControlCommand =
  | Readonly<{ action: "runtime-stop"; requestId: string }>
  | Readonly<{
      action: "runtime-enter-research";
      expectedMode: "PROPOSE_ONLY" | "STOPPED";
      expectedRevision: number;
      requestId: string;
    }>
  | Readonly<{
      action: "runtime-enter-propose-only";
      expectedMode: "RESEARCH";
      expectedRevision: number;
      requestId: string;
    }>;

export interface OperatorRuntimeProvider {
  readonly supportedActions: readonly RuntimeOperatorAction[];
  executeRuntimeControl(command: RuntimeOperatorControlCommand): Promise<unknown> | unknown;
  getRuntimeSnapshot(): Promise<unknown> | unknown;
}

export interface OperatorResearchProvider {
  getResearchProjection(): Promise<unknown> | unknown;
}

export interface OperatorResearchProposalRecordV1 {
  readonly schemaVersion: 1;
  readonly eventHash: string;
  readonly eventSequence: number;
  readonly persistedAt: string;
  readonly proposal: Readonly<ResearchProposalV1>;
}

export interface OperatorResearchProjectionV1 {
  readonly schemaVersion: 1;
  readonly candidateCount: number;
  readonly abstentionCount: number;
  readonly proposals: readonly Readonly<OperatorResearchProposalRecordV1>[];
}

export interface OperatorRuntimeSnapshotV1 {
  readonly schemaVersion: 1;
  readonly mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED";
  readonly revision: number;
  readonly modeChangedAt: string;
  readonly processInstanceId: string;
  readonly auditHead: Readonly<{
    sequence: number;
    hash: string;
  }>;
  readonly capabilities: Readonly<{
    researchCollection: boolean;
    proposalPersistence: boolean;
    policyApproval: false;
    paidRead: false;
    transactionBroadcast: false;
    walletSign: false;
    executionAdapter: false;
    externalPublish: false;
  }>;
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
  /** Omit when the persisted Stage 0 runtime is not configured. */
  readonly runtime?: OperatorRuntimeProvider;
  /** Omit when no content-free research ledger is configured. */
  readonly research?: OperatorResearchProvider;
  /** Omit when the bounded Stage 1 X read canary is not configured. */
  readonly readCanary?: OperatorReadCanaryProvider;
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
const CONTROL_BODY_TIMEOUT_MS = 5_000;
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
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const RUNTIME_MODES = new Set(["STOPPED", "RESEARCH", "PROPOSE_ONLY"]);
const RUNTIME_ACTIONS = new Set<RuntimeOperatorAction>([
  "runtime-enter-propose-only",
  "runtime-enter-research",
  "runtime-stop",
]);

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function strictDataRecord(
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

/**
 * Accepts only the closed, content-free projection produced by the persisted
 * runtime controller. This deliberately rejects provider additions rather than
 * trying to redact arbitrary external text after the fact.
 */
export function parseOperatorRuntimeSnapshot(value: unknown): OperatorRuntimeSnapshotV1 {
  const record = strictDataRecord(
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
    typeof record.mode !== "string" ||
    !RUNTIME_MODES.has(record.mode) ||
    !Number.isSafeInteger(record.revision) ||
    Number(record.revision) < 1 ||
    !canonicalTimestamp(record.modeChangedAt) ||
    typeof record.processInstanceId !== "string" ||
    !UUID_V4.test(record.processInstanceId)
  ) {
    throw new TypeError("Runtime snapshot is invalid");
  }

  const auditHead = strictDataRecord(record.auditHead, ["sequence", "hash"], "Runtime audit head");
  if (
    !Number.isSafeInteger(auditHead.sequence) ||
    Number(auditHead.sequence) < 1 ||
    typeof auditHead.hash !== "string" ||
    !LOWER_HEX_64.test(auditHead.hash)
  ) {
    throw new TypeError("Runtime audit head is invalid");
  }

  const capabilities = strictDataRecord(
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
    capabilities.externalPublish !== false
  ) {
    throw new TypeError("Runtime capabilities are invalid");
  }
  const expectedResearch = record.mode !== "STOPPED";
  const expectedProposal = record.mode === "PROPOSE_ONLY";
  if (
    capabilities.researchCollection !== expectedResearch ||
    capabilities.proposalPersistence !== expectedProposal
  ) {
    throw new TypeError("Runtime mode and capabilities disagree");
  }

  return Object.freeze({
    schemaVersion: 1,
    mode: record.mode as OperatorRuntimeSnapshotV1["mode"],
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

function assertPlainDataTree(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null) return;
  if (typeof value !== "object") {
    if (
      typeof value !== "string" &&
      typeof value !== "number" &&
      typeof value !== "boolean" &&
      value !== undefined
    ) {
      throw new TypeError("Research projection is invalid");
    }
    return;
  }
  if (utilTypes.isProxy(value) || ancestors.has(value)) {
    throw new TypeError("Research projection is invalid");
  }
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== value.length + 1 ||
      keys.at(-1) !== "length" ||
      keys.slice(0, -1).some((key, index) => key !== String(index))
    ) {
      throw new TypeError("Research projection is invalid");
    }
    ancestors.add(value);
    try {
      for (const item of value) assertPlainDataTree(item, ancestors);
    } finally {
      ancestors.delete(value);
    }
    return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("Research projection is invalid");
  }
  ancestors.add(value);
  try {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new TypeError("Research projection is invalid");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("Research projection is invalid");
      }
      assertPlainDataTree(descriptor.value, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function deepFreezePlainData<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreezePlainData(item);
    Object.freeze(value);
  }
  return value;
}

/** Validates the complete content-free research projection at the HTTP boundary. */
export function parseOperatorResearchProjection(value: unknown): OperatorResearchProjectionV1 {
  const record = strictDataRecord(
    value,
    ["schemaVersion", "candidateCount", "abstentionCount", "proposals"],
    "Research projection",
  );
  if (
    record.schemaVersion !== 1 ||
    !Number.isSafeInteger(record.candidateCount) ||
    Number(record.candidateCount) < 0 ||
    !Number.isSafeInteger(record.abstentionCount) ||
    Number(record.abstentionCount) < 0 ||
    !Array.isArray(record.proposals) ||
    record.proposals.length > 100
  ) {
    throw new TypeError("Research projection is invalid");
  }

  const proposals: OperatorResearchProposalRecordV1[] = [];
  const proposalIds = new Set<string>();
  const eventHashes = new Set<string>();
  let previousSequence = Number.POSITIVE_INFINITY;
  let projectedCandidates = 0;
  let projectedAbstentions = 0;

  for (const value of record.proposals) {
    const proposalRecord = strictDataRecord(
      value,
      ["schemaVersion", "eventHash", "eventSequence", "persistedAt", "proposal"],
      "Research proposal record",
    );
    if (
      proposalRecord.schemaVersion !== 1 ||
      typeof proposalRecord.eventHash !== "string" ||
      !LOWER_HEX_64.test(proposalRecord.eventHash) ||
      eventHashes.has(proposalRecord.eventHash) ||
      !Number.isSafeInteger(proposalRecord.eventSequence) ||
      Number(proposalRecord.eventSequence) < 1 ||
      Number(proposalRecord.eventSequence) >= previousSequence ||
      !canonicalTimestamp(proposalRecord.persistedAt)
    ) {
      throw new TypeError("Research proposal record is invalid");
    }
    assertPlainDataTree(proposalRecord.proposal, new WeakSet<object>());
    const parsed = ResearchProposalV1Schema.safeParse(proposalRecord.proposal);
    if (!parsed.success) throw new TypeError("Research proposal is invalid");
    if (
      proposalIds.has(parsed.data.proposalId) ||
      Date.parse(proposalRecord.persistedAt) < Date.parse(parsed.data.createdAt) ||
      Date.parse(proposalRecord.persistedAt) > Date.parse(parsed.data.expiresAt)
    ) {
      throw new TypeError("Research proposal record is invalid");
    }

    previousSequence = Number(proposalRecord.eventSequence);
    eventHashes.add(proposalRecord.eventHash);
    proposalIds.add(parsed.data.proposalId);
    if (parsed.data.disposition.kind === "candidate") projectedCandidates += 1;
    else projectedAbstentions += 1;
    proposals.push(
      Object.freeze({
        schemaVersion: 1,
        eventHash: proposalRecord.eventHash,
        eventSequence: Number(proposalRecord.eventSequence),
        persistedAt: proposalRecord.persistedAt,
        proposal: deepFreezePlainData(parsed.data),
      }),
    );
  }

  const candidateCount = Number(record.candidateCount);
  const abstentionCount = Number(record.abstentionCount);
  if (candidateCount < projectedCandidates || abstentionCount < projectedAbstentions) {
    throw new TypeError("Research projection counts are invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    candidateCount,
    abstentionCount,
    proposals: Object.freeze(proposals),
  });
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

  if (utilTypes.isProxy(value)) return undefined;
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

function parseControlCommand(
  value: unknown,
): OperatorControlCommand | RuntimeOperatorControlCommand {
  const record = exactJsonRecord(value);
  if (record.action === "runtime-stop") {
    assertExactKeys(record, ["action", "requestId"]);
    if (typeof record.requestId !== "string" || !UUID_V4.test(record.requestId)) {
      badRequest("Runtime stop request id is invalid.");
    }
    return Object.freeze({ action: "runtime-stop", requestId: record.requestId });
  }
  if (record.action === "runtime-enter-research") {
    assertExactKeys(record, ["action", "expectedMode", "expectedRevision", "requestId"]);
    if (
      (record.expectedMode !== "STOPPED" && record.expectedMode !== "PROPOSE_ONLY") ||
      !Number.isSafeInteger(record.expectedRevision) ||
      Number(record.expectedRevision) < 1 ||
      typeof record.requestId !== "string" ||
      !UUID_V4.test(record.requestId)
    ) {
      badRequest("Runtime research transition is invalid.");
    }
    return Object.freeze({
      action: "runtime-enter-research",
      expectedMode: record.expectedMode,
      expectedRevision: Number(record.expectedRevision),
      requestId: record.requestId,
    });
  }
  if (record.action === "runtime-enter-propose-only") {
    assertExactKeys(record, ["action", "expectedMode", "expectedRevision", "requestId"]);
    if (
      record.expectedMode !== "RESEARCH" ||
      !Number.isSafeInteger(record.expectedRevision) ||
      Number(record.expectedRevision) < 1 ||
      typeof record.requestId !== "string" ||
      !UUID_V4.test(record.requestId)
    ) {
      badRequest("Runtime proposal transition is invalid.");
    }
    return Object.freeze({
      action: "runtime-enter-propose-only",
      expectedMode: "RESEARCH",
      expectedRevision: Number(record.expectedRevision),
      requestId: record.requestId,
    });
  }
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

function isRuntimeControlCommand(
  command: OperatorControlCommand | RuntimeOperatorControlCommand,
): command is RuntimeOperatorControlCommand {
  return RUNTIME_ACTIONS.has(command.action as RuntimeOperatorAction);
}

function validatedRuntimeActions(
  runtime: OperatorRuntimeProvider,
): readonly RuntimeOperatorAction[] {
  const actions = runtime.supportedActions;
  if (
    !Array.isArray(actions) ||
    utilTypes.isProxy(actions) ||
    actions.length > RUNTIME_ACTIONS.size ||
    new Set(actions).size !== actions.length ||
    actions.some(
      (action) =>
        typeof action !== "string" || !RUNTIME_ACTIONS.has(action as RuntimeOperatorAction),
    )
  ) {
    throw new TypeError("Runtime control capabilities are invalid");
  }
  return Object.freeze([...actions]) as readonly RuntimeOperatorAction[];
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

function isReadCanaryConflictError(error: unknown): boolean {
  if (!(error instanceof Error) || utilTypes.isProxy(error)) return false;
  const descriptor = Object.getOwnPropertyDescriptor(error, "name");
  return (
    descriptor !== undefined &&
    "value" in descriptor &&
    descriptor.value === "XReadCanaryConflictError"
  );
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  provider: OperatorSnapshotProvider,
  controls: OperatorControlProvider | undefined,
  runtime: OperatorRuntimeProvider | undefined,
  research: OperatorResearchProvider | undefined,
  readCanary: OperatorReadCanaryProvider | undefined,
  readCanaryRouteState: { running: boolean },
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
    const command = parseControlCommand(await readControlBody(request));
    if (isRuntimeControlCommand(command)) {
      if (runtime === undefined) {
        throw new HttpError(501, "runtime_unavailable", "Runtime controls are not configured.");
      }
      if (!validatedRuntimeActions(runtime).includes(command.action)) {
        throw new HttpError(501, "control_unavailable", "This local control is not configured.");
      }
      if (command.action === "runtime-stop" && readCanary !== undefined) {
        // Interruption is intentionally synchronous, local, and attempted before
        // the durable runtime transition. A provider failure must never block STOP.
        try {
          readCanary.abortActive();
        } catch {
          // Durable STOP remains the controlling safety boundary.
        }
      }
      const result = parseOperatorRuntimeSnapshot(await runtime.executeRuntimeControl(command));
      sendJson(response, 200, { result });
      return;
    }
    if (controls === undefined) {
      throw new HttpError(501, "controls_unavailable", "Session controls are not configured.");
    }
    if (!controls.supportedActions.includes(command.action)) {
      throw new HttpError(501, "control_unavailable", "This local control is not configured.");
    }
    const result = await controls.executeControl(command);
    sendJson(response, 200, { result });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/read-canary/run") {
    if (url.search !== "") badRequest("The read canary route does not accept query parameters.");
    assertSameOriginControl(request, origin);
    if (readCanary === undefined) {
      throw new HttpError(501, "read_canary_unavailable", "The X read canary is not configured.");
    }
    let command;
    try {
      command = parseOperatorReadCanaryCommand(await readControlBody(request));
    } catch (error) {
      if (error instanceof HttpError) throw error;
      badRequest("Read canary command is invalid.");
    }
    if (readCanaryRouteState.running) {
      throw new HttpError(409, "read_canary_conflict", "The X read canary is already running.");
    }
    readCanaryRouteState.running = true;
    try {
      const result = parseOperatorReadCanaryReceipt(await readCanary.executeReadCanary(command));
      sendJson(response, 200, { result });
    } finally {
      readCanaryRouteState.running = false;
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

  if (url.pathname === "/api/runtime") {
    if (url.search !== "") badRequest("The runtime route does not accept query parameters.");
    if (runtime === undefined) {
      throw new HttpError(501, "runtime_unavailable", "The persisted runtime is not configured.");
    }
    const snapshot = parseOperatorRuntimeSnapshot(await runtime.getRuntimeSnapshot());
    sendJson(response, 200, { financialAuthority: false, runtime: snapshot });
    return;
  }

  if (url.pathname === "/api/research") {
    if (url.search !== "") badRequest("The research route does not accept query parameters.");
    if (research === undefined) {
      throw new HttpError(
        501,
        "research_unavailable",
        "The content-free research projection is not configured.",
      );
    }
    const projection = parseOperatorResearchProjection(await research.getResearchProjection());
    sendJson(response, 200, { research: projection });
    return;
  }

  if (url.pathname === "/api/read-canary") {
    if (url.search !== "") badRequest("The read canary route does not accept query parameters.");
    if (readCanary === undefined) {
      throw new HttpError(501, "read_canary_unavailable", "The X read canary is not configured.");
    }
    const projection = parseOperatorReadCanaryProjection(
      await readCanary.getReadCanaryProjection(),
    );
    sendJson(response, 200, { readCanary: projection });
    return;
  }

  if (url.pathname === "/api/control/capabilities") {
    if (url.search !== "") badRequest("The capabilities route does not accept query parameters.");
    const legacyActions = controls?.supportedActions ?? [];
    const runtimeActions = runtime === undefined ? [] : validatedRuntimeActions(runtime);
    sendJson(response, 200, {
      controls: {
        actions: [...legacyActions, ...runtimeActions],
        enabled: controls !== undefined || runtime !== undefined,
        legacy: {
          actions: legacyActions,
          enabled: controls !== undefined,
        },
        runtime: {
          actions: runtimeActions,
          enabled: runtime !== undefined,
        },
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
  runtime?: OperatorRuntimeProvider,
  research?: OperatorResearchProvider,
  readCanary?: OperatorReadCanaryProvider,
): Server {
  const readCanaryRouteState = { running: false };
  const server = createServer((request, response) => {
    void route(
      request,
      response,
      provider,
      controls,
      runtime,
      research,
      readCanary,
      readCanaryRouteState,
    ).catch((error: unknown) => {
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
      if (isReadCanaryConflictError(error)) {
        sendJson(response, 409, {
          error: {
            code: "read_canary_conflict",
            message: "The X read canary state changed; refresh and try again.",
          },
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
  server.headersTimeout = CONTROL_BODY_TIMEOUT_MS;
  server.requestTimeout = CONTROL_BODY_TIMEOUT_MS;
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 25;
  server.on("upgrade", (_request, socket) => socket.destroy());

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

  const server = createOperatorServer(
    provider,
    options.controls,
    options.runtime,
    options.research,
    options.readCanary,
  );
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
      try {
        options.readCanary?.abortActive();
      } catch {
        // An optional canary provider must not prevent local server shutdown.
      }
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
        server.closeAllConnections();
      });
    },
  };
}
