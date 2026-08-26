import { X_RECENT_SEARCH_NEXT_TOKEN_MAX_LENGTH } from "./constants.js";
import { XCollectorError } from "./errors.js";
import { sha256 } from "./hash.js";
import { QuarantinedXRecentSearchResponse } from "./quarantine.js";
import type { XRateLimitReceipt } from "./rate-limit.js";

export type XStableId = string;

/** The deliberately minimal trusted projection of an untrusted X Post. */
export type XRecentSearchPost = Readonly<{
  id: XStableId;
  text: string;
}>;

export type XRecentSearchMeta = Readonly<{
  result_count: number;
  newest_id?: XStableId;
  oldest_id?: XStableId;
  next_token?: string;
}>;

export type XRecentSearchResult = Readonly<{
  posts: readonly XRecentSearchPost[];
  meta: XRecentSearchMeta;
  requestFingerprint: string;
  responseHash: string;
  acquiredAt: string;
  rateLimit: XRateLimitReceipt | undefined;
}>;

const X_ID_PATTERN = /^[1-9][0-9]{0,18}$/;
const PAGE_TOKEN_PATTERN = new RegExp(
  `^[A-Za-z0-9._~-]{1,${X_RECENT_SEARCH_NEXT_TOKEN_MAX_LENGTH}}$`,
);

function schemaFailure(path: string, message = "Response schema validation failed."): never {
  throw new XCollectorError("INVALID_RESPONSE_SCHEMA", message, { path });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertObject(value: unknown, path: string): asserts value is Record<string, unknown> {
  if (!isPlainRecord(value)) schemaFailure(path);
}

function assertExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  path: string,
): void {
  const allowed = new Set([...required, ...optional]);
  const ownKeys = Reflect.ownKeys(value);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    ownKeys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    schemaFailure(path);
  }
}

function parseId(value: unknown, path: string): XStableId {
  if (typeof value !== "string" || !X_ID_PATTERN.test(value)) schemaFailure(path);
  return value;
}

function parseText(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length > 25_000) schemaFailure(path);
  return value;
}

function validateOptionalEditHistory(
  value: Record<string, unknown>,
  postId: XStableId,
  path: string,
): void {
  const postDialect = value.edit_history_post_ids;
  const tweetDialect = value.edit_history_tweet_ids;
  if (postDialect !== undefined && tweetDialect !== undefined) schemaFailure(path);
  const history = postDialect ?? tweetDialect;
  if (history === undefined) return;
  if (!Array.isArray(history) || history.length < 1 || history.length > 100) {
    schemaFailure(path);
  }
  const ids = history.map((candidate, index) => parseId(candidate, `${path}[${index}]`));
  if (new Set(ids).size !== ids.length || !ids.includes(postId)) schemaFailure(path);
}

function parsePost(value: unknown, index: number): XRecentSearchPost {
  const path = `data[${index}]`;
  assertObject(value, path);
  assertExactKeys(value, ["id", "text"], ["edit_history_post_ids", "edit_history_tweet_ids"], path);
  const id = parseId(value.id, `${path}.id`);
  validateOptionalEditHistory(value, id, `${path}.edit_history`);
  return Object.freeze({ id, text: parseText(value.text, `${path}.text`) });
}

function parseMeta(value: unknown, maximumResults: number): XRecentSearchMeta {
  const path = "meta";
  assertObject(value, path);
  assertExactKeys(value, ["result_count"], ["newest_id", "oldest_id", "next_token"], path);
  if (
    typeof value.result_count !== "number" ||
    !Number.isInteger(value.result_count) ||
    value.result_count < 0 ||
    value.result_count > maximumResults
  ) {
    schemaFailure(`${path}.result_count`);
  }
  const result: {
    result_count: number;
    newest_id?: XStableId;
    oldest_id?: XStableId;
    next_token?: string;
  } = { result_count: value.result_count };
  if (value.newest_id !== undefined) {
    result.newest_id = parseId(value.newest_id, `${path}.newest_id`);
  }
  if (value.oldest_id !== undefined) {
    result.oldest_id = parseId(value.oldest_id, `${path}.oldest_id`);
  }
  if (value.next_token !== undefined) {
    if (typeof value.next_token !== "string" || !PAGE_TOKEN_PATTERN.test(value.next_token)) {
      schemaFailure(`${path}.next_token`);
    }
    result.next_token = value.next_token;
  }
  return Object.freeze(result);
}

function compareIds(left: XStableId, right: XStableId): number {
  const leftValue = BigInt(left);
  const rightValue = BigInt(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function rejectPartialErrors(value: unknown): void {
  if (!Array.isArray(value) || value.length > 100) schemaFailure("errors");
  if (value.length > 0) {
    throw new XCollectorError(
      "PARTIAL_RESPONSE",
      "The X response contains partial errors and remains quarantined.",
    );
  }
}

export function parseXRecentSearchResponse(
  quarantine: QuarantinedXRecentSearchResponse,
): XRecentSearchResult {
  if (!(quarantine instanceof QuarantinedXRecentSearchResponse)) {
    schemaFailure("quarantine", "A quarantined recent-search response is required.");
  }
  const bytes = quarantine.copyBytes();
  try {
    if (sha256(bytes) !== quarantine.metadata.responseHash) {
      schemaFailure("quarantine", "Quarantined response integrity validation failed.");
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new XCollectorError("MALFORMED_JSON", "The response body is not valid UTF-8 JSON.");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(text) as unknown;
    } catch {
      throw new XCollectorError("MALFORMED_JSON", "The response body is not valid JSON.");
    }

    assertObject(decoded, "response");
    assertExactKeys(decoded, ["meta"], ["data", "errors"], "response");
    if (decoded.errors !== undefined) rejectPartialErrors(decoded.errors);
    const meta = parseMeta(decoded.meta, quarantine.metadata.maxResults);

    let posts: readonly XRecentSearchPost[];
    if (decoded.data === undefined) {
      if (meta.result_count !== 0) schemaFailure("data");
      posts = Object.freeze([]);
    } else {
      if (!Array.isArray(decoded.data) || decoded.data.length > quarantine.metadata.maxResults) {
        schemaFailure("data");
      }
      posts = Object.freeze(decoded.data.map(parsePost));
    }
    if (meta.result_count !== posts.length) schemaFailure("meta.result_count");
    if (new Set(posts.map((post) => post.id)).size !== posts.length) schemaFailure("data");

    if (posts.length === 0) {
      if (
        meta.newest_id !== undefined ||
        meta.oldest_id !== undefined ||
        meta.next_token !== undefined
      ) {
        schemaFailure("meta");
      }
    } else {
      if (meta.newest_id === undefined || meta.oldest_id === undefined) schemaFailure("meta");
      const sortedIds = posts.map((post) => post.id).sort(compareIds);
      if (meta.oldest_id !== sortedIds[0] || meta.newest_id !== sortedIds.at(-1)) {
        schemaFailure("meta");
      }
    }

    return Object.freeze({
      posts,
      meta,
      requestFingerprint: quarantine.metadata.requestFingerprint,
      responseHash: quarantine.metadata.responseHash,
      acquiredAt: quarantine.metadata.acquiredAt,
      rateLimit: quarantine.metadata.rateLimit,
    });
  } finally {
    bytes.fill(0);
  }
}
