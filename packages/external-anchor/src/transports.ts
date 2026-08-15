import {
  assertNotProxy,
  canonicalJson,
  strictRecord,
  validateHash,
  validateSafeInteger,
  validateString,
  validateTimestamp,
} from "./canonical.js";
import { ExternalAnchorConflictError, ExternalAnchorValidationError } from "./errors.js";
import { parseObjectKey, retentionPolicy, sha256 } from "./protocol.js";
import {
  EXTERNAL_ANCHOR_CONTENT_TYPE,
  EXTERNAL_ANCHOR_MAX_BYTES,
  type AnchorObjectSummary,
  type AnchorPublisherTransport,
  type AnchorRetentionPolicy,
  type AnchorVerifierTransport,
  type CreateAnchorObjectRequest,
  type CreateAnchorObjectResult,
  type PreparedExternalAnchorObject,
  type ReadAnchorObjectResult,
} from "./types.js";

const IDEMPOTENCY_KEY_PATTERN = /^anchor-[0-9a-f]{64}$/;
const MAX_RETENTION_SKEW_MS = 1_000;

export function createObjectRequest(
  prepared: PreparedExternalAnchorObject,
): CreateAnchorObjectRequest {
  return Object.freeze({
    body: prepared.body,
    contentSha256: prepared.contentSha256,
    contentType: EXTERNAL_ANCHOR_CONTENT_TYPE,
    idempotencyKey: `anchor-${prepared.contentSha256}`,
    objectKey: prepared.objectKey,
    retention: Object.freeze({ ...prepared.retention }),
    sizeBytes: prepared.sizeBytes,
  });
}

export function parseCreateRequest(value: unknown): CreateAnchorObjectRequest {
  const record = strictRecord(
    value,
    [
      "body",
      "contentSha256",
      "contentType",
      "idempotencyKey",
      "objectKey",
      "retention",
      "sizeBytes",
    ],
    "create anchor request",
  );
  const body = validateString(record.body, "body", EXTERNAL_ANCHOR_MAX_BYTES);
  const contentSha256 = validateHash(record.contentSha256, "contentSha256");
  if (sha256(body) !== contentSha256) {
    throw new ExternalAnchorValidationError("create request content hash is invalid");
  }
  if (record.contentType !== EXTERNAL_ANCHOR_CONTENT_TYPE) {
    throw new ExternalAnchorValidationError("create request content type is invalid");
  }
  if (
    typeof record.idempotencyKey !== "string" ||
    !IDEMPOTENCY_KEY_PATTERN.test(record.idempotencyKey) ||
    record.idempotencyKey !== `anchor-${contentSha256}`
  ) {
    throw new ExternalAnchorValidationError("create request idempotency key is invalid");
  }
  const objectKey = parseObjectKey(record.objectKey);
  const retention = parseRetentionPolicy(record.retention);
  const sizeBytes = validateSafeInteger(record.sizeBytes, "sizeBytes", 1);
  if (sizeBytes > EXTERNAL_ANCHOR_MAX_BYTES || sizeBytes !== Buffer.byteLength(body, "utf8")) {
    throw new ExternalAnchorValidationError("create request size is invalid");
  }
  return Object.freeze({
    body,
    contentSha256,
    contentType: EXTERNAL_ANCHOR_CONTENT_TYPE,
    idempotencyKey: record.idempotencyKey,
    objectKey: objectKeyForParsed(record.objectKey, objectKey),
    retention,
    sizeBytes,
  });
}

export function parseCreateResult(value: unknown): CreateAnchorObjectResult {
  const record = strictRecord(
    value,
    [
      "contentSha256",
      "disposition",
      "objectKey",
      "retainedUntil",
      "retentionMode",
      "sizeBytes",
      "storedAt",
    ],
    "create anchor result",
  );
  const summary = parseSummaryRecord(record, "create anchor result");
  if (record.disposition !== "created" && record.disposition !== "already_exists") {
    throw new ExternalAnchorValidationError("create result disposition is invalid");
  }
  return Object.freeze({ ...summary, disposition: record.disposition });
}

export function parseAnchorSummary(value: unknown): AnchorObjectSummary {
  const record = strictRecord(
    value,
    ["contentSha256", "objectKey", "retainedUntil", "retentionMode", "sizeBytes", "storedAt"],
    "anchor object summary",
  );
  return parseSummaryRecord(record, "anchor object summary");
}

export function parseReadResult(value: unknown): ReadAnchorObjectResult {
  const record = strictRecord(
    value,
    [
      "body",
      "contentSha256",
      "objectKey",
      "retainedUntil",
      "retentionMode",
      "sizeBytes",
      "storedAt",
    ],
    "anchor object read result",
  );
  const summary = parseSummaryRecord(record, "anchor object read result");
  const body = validateString(record.body, "anchor body", EXTERNAL_ANCHOR_MAX_BYTES);
  if (
    Buffer.byteLength(body, "utf8") !== summary.sizeBytes ||
    sha256(body) !== summary.contentSha256
  ) {
    throw new ExternalAnchorValidationError("anchor read body does not match its metadata");
  }
  return Object.freeze({ ...summary, body });
}

export function parseRetentionPolicy(value: unknown): AnchorRetentionPolicy {
  const record = strictRecord(value, ["days", "mode"], "anchor retention policy");
  const expected = retentionPolicy(record.mode);
  if (record.days !== expected.days) {
    throw new ExternalAnchorValidationError("retention days do not match retention mode");
  }
  return expected;
}

export function assertRetentionResult(
  policy: AnchorRetentionPolicy,
  result: AnchorObjectSummary,
): void {
  if (result.retentionMode !== policy.mode) {
    throw new ExternalAnchorValidationError("provider retention mode does not match the request");
  }
  const required = Date.parse(result.storedAt) + policy.days * 24 * 60 * 60 * 1_000;
  if (Date.parse(result.retainedUntil) + MAX_RETENTION_SKEW_MS < required) {
    throw new ExternalAnchorValidationError("provider retention period is too short");
  }
}

export function normalizePublisherTransport(value: unknown): AnchorPublisherTransport {
  const record = strictRecord(value, ["create"], "publisher transport capability");
  if (typeof record.create !== "function") {
    throw new ExternalAnchorValidationError("publisher transport create must be a function");
  }
  assertNotProxy(record.create, "publisher transport create");
  const create = record.create as AnchorPublisherTransport["create"];
  return Object.freeze({ create });
}

export function normalizeVerifierTransport(value: unknown): AnchorVerifierTransport {
  const record = strictRecord(value, ["list", "read"], "verifier transport capability");
  if (typeof record.list !== "function" || typeof record.read !== "function") {
    throw new ExternalAnchorValidationError("verifier transport methods must be functions");
  }
  assertNotProxy(record.list, "verifier transport list");
  assertNotProxy(record.read, "verifier transport read");
  return Object.freeze({
    list: record.list as AnchorVerifierTransport["list"],
    read: record.read as AnchorVerifierTransport["read"],
  });
}

interface StoredObject {
  readonly request: CreateAnchorObjectRequest;
  readonly summary: AnchorObjectSummary;
}

/** Offline capability-separation fake. It performs no I/O outside process memory. */
export class InMemoryAnchorObjectStore {
  readonly #clock: () => string;
  readonly #objects = new Map<string, StoredObject>();

  constructor(options: Readonly<{ clock: () => string }>) {
    const record = strictRecord(options, ["clock"], "in-memory anchor store options");
    if (typeof record.clock !== "function") {
      throw new ExternalAnchorValidationError("in-memory anchor clock must be a function");
    }
    assertNotProxy(record.clock, "in-memory anchor clock");
    this.#clock = record.clock as () => string;
  }

  publisherTransport(): AnchorPublisherTransport {
    return Object.freeze({
      create: async (input: CreateAnchorObjectRequest) => this.create(input),
    });
  }

  verifierTransport(): AnchorVerifierTransport {
    return Object.freeze({
      list: async (input: Readonly<{ prefix: string }>) => this.list(input),
      read: async (input: Readonly<{ objectKey: string }>) => this.read(input),
    });
  }

  private create(input: CreateAnchorObjectRequest): CreateAnchorObjectResult {
    const request = parseCreateRequest(input);
    const existing = this.#objects.get(request.objectKey);
    if (existing !== undefined) {
      if (canonicalJson(existing.request) !== canonicalJson(request)) {
        throw new ExternalAnchorConflictError(
          "OBJECT_CONFLICT",
          "create-only object key already exists with different content or retention",
        );
      }
      return Object.freeze({ ...existing.summary, disposition: "already_exists" });
    }
    const storedAt = validateTimestamp(this.#clock(), "fake transport storedAt");
    const retainedUntil = new Date(
      Date.parse(storedAt) + request.retention.days * 24 * 60 * 60 * 1_000,
    ).toISOString();
    const summary: AnchorObjectSummary = Object.freeze({
      contentSha256: request.contentSha256,
      objectKey: request.objectKey,
      retainedUntil,
      retentionMode: request.retention.mode,
      sizeBytes: request.sizeBytes,
      storedAt,
    });
    this.#objects.set(request.objectKey, Object.freeze({ request, summary }));
    return Object.freeze({ ...summary, disposition: "created" });
  }

  private list(input: Readonly<{ prefix: string }>): readonly AnchorObjectSummary[] {
    const record = strictRecord(input, ["prefix"], "list anchor objects input");
    const prefix = validateString(record.prefix, "prefix", 128);
    return Object.freeze(
      [...this.#objects.values()]
        .filter((stored) => stored.summary.objectKey.startsWith(prefix))
        .map((stored) => stored.summary)
        .sort((left, right) => left.objectKey.localeCompare(right.objectKey)),
    );
  }

  private read(input: Readonly<{ objectKey: string }>): ReadAnchorObjectResult | undefined {
    const record = strictRecord(input, ["objectKey"], "read anchor object input");
    parseObjectKey(record.objectKey);
    const stored = this.#objects.get(record.objectKey as string);
    if (stored === undefined) return undefined;
    return Object.freeze({ ...stored.summary, body: stored.request.body });
  }
}

function parseSummaryRecord(
  record: Readonly<Record<string, unknown>>,
  field: string,
): AnchorObjectSummary {
  const objectKey = parseObjectKey(record.objectKey);
  const sizeBytes = validateSafeInteger(record.sizeBytes, `${field}.sizeBytes`, 1);
  if (sizeBytes > EXTERNAL_ANCHOR_MAX_BYTES) {
    throw new ExternalAnchorValidationError(`${field} exceeds the 4 KiB contract`);
  }
  const retention = retentionPolicy(record.retentionMode);
  const storedAt = validateTimestamp(record.storedAt, `${field}.storedAt`);
  const retainedUntil = validateTimestamp(record.retainedUntil, `${field}.retainedUntil`);
  if (Date.parse(retainedUntil) <= Date.parse(storedAt)) {
    throw new ExternalAnchorValidationError(`${field} retention is not after storage`);
  }
  return Object.freeze({
    contentSha256: validateHash(record.contentSha256, `${field}.contentSha256`),
    objectKey: objectKeyForParsed(record.objectKey, objectKey),
    retainedUntil,
    retentionMode: retention.mode,
    sizeBytes,
    storedAt,
  });
}

function objectKeyForParsed(
  raw: unknown,
  parsed: Readonly<{ checkpointHash: string; journalSequence: number; profile: string }>,
): string {
  if (typeof raw !== "string") throw new ExternalAnchorValidationError("objectKey is invalid");
  void parsed;
  return raw;
}
