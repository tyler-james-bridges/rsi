import { XCollectorError } from "./errors.js";
import { sha256 } from "./hash.js";
import { QuarantinedXRecentSearchResponse } from "./quarantine.js";

export type XStableId = string;

export type XRecentSearchPost = Readonly<{
  id: XStableId;
  text: string;
  author_id: XStableId;
  created_at: string;
  edit_history_post_ids: readonly XStableId[];
}>;

export type XRecentSearchUser = Readonly<{
  id: XStableId;
  name: string;
  username: string;
  created_at: string;
}>;

export type XRecentSearchMeta = Readonly<{
  result_count: number;
  newest_id?: XStableId;
  oldest_id?: XStableId;
  next_token?: string;
  previous_token?: string;
}>;

export type XRecentSearchResult = Readonly<{
  posts: readonly XRecentSearchPost[];
  users: readonly XRecentSearchUser[];
  usersById: Readonly<Record<XStableId, XRecentSearchUser>>;
  meta: XRecentSearchMeta;
  requestFingerprint: string;
  responseHash: string;
  acquiredAt: string;
}>;

const X_ID_PATTERN = /^[1-9][0-9]{0,18}$/;
const USERNAME_PATTERN = /^[A-Za-z0-9_]{1,15}$/;
const PAGE_TOKEN_PATTERN = /^[A-Za-z0-9._~-]{1,2048}$/;
const UTC_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/;

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

function parseTimestamp(value: unknown, path: string): string {
  if (typeof value !== "string") schemaFailure(path);
  const match = UTC_TIMESTAMP_PATTERN.exec(value);
  if (match === null) schemaFailure(path);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) schemaFailure(path);
  const canonical = new Date(milliseconds).toISOString();
  const normalized = match[7] === undefined ? value.replace(/Z$/, ".000Z") : value;
  if (canonical !== normalized) schemaFailure(path);
  return value;
}

function parseBoundedString(
  value: unknown,
  minimum: number,
  maximum: number,
  path: string,
): string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum) {
    schemaFailure(path);
  }
  return value;
}

function parsePost(value: unknown, index: number): XRecentSearchPost {
  const path = `data[${index}]`;
  assertObject(value, path);
  assertExactKeys(
    value,
    ["id", "text", "author_id", "created_at", "edit_history_post_ids"],
    [],
    path,
  );
  const id = parseId(value.id, `${path}.id`);
  const text = parseBoundedString(value.text, 1, 25_000, `${path}.text`);
  const authorId = parseId(value.author_id, `${path}.author_id`);
  const createdAt = parseTimestamp(value.created_at, `${path}.created_at`);
  if (
    !Array.isArray(value.edit_history_post_ids) ||
    value.edit_history_post_ids.length < 1 ||
    value.edit_history_post_ids.length > 100
  ) {
    schemaFailure(`${path}.edit_history_post_ids`);
  }
  const editHistory = value.edit_history_post_ids.map((candidate, editIndex) =>
    parseId(candidate, `${path}.edit_history_post_ids[${editIndex}]`),
  );
  if (new Set(editHistory).size !== editHistory.length || !editHistory.includes(id)) {
    schemaFailure(`${path}.edit_history_post_ids`);
  }
  return Object.freeze({
    id,
    text,
    author_id: authorId,
    created_at: createdAt,
    edit_history_post_ids: Object.freeze(editHistory),
  });
}

function parseUser(value: unknown, index: number): XRecentSearchUser {
  const path = `includes.users[${index}]`;
  assertObject(value, path);
  assertExactKeys(value, ["id", "name", "username", "created_at"], [], path);
  const username = parseBoundedString(value.username, 1, 15, `${path}.username`);
  if (!USERNAME_PATTERN.test(username)) schemaFailure(`${path}.username`);
  return Object.freeze({
    id: parseId(value.id, `${path}.id`),
    name: parseBoundedString(value.name, 1, 200, `${path}.name`),
    username,
    created_at: parseTimestamp(value.created_at, `${path}.created_at`),
  });
}

function parseMeta(value: unknown): XRecentSearchMeta {
  const path = "meta";
  assertObject(value, path);
  assertExactKeys(
    value,
    ["result_count"],
    ["newest_id", "oldest_id", "next_token", "previous_token"],
    path,
  );
  if (
    typeof value.result_count !== "number" ||
    !Number.isInteger(value.result_count) ||
    value.result_count < 0 ||
    value.result_count > 100
  ) {
    schemaFailure(`${path}.result_count`);
  }
  const result: {
    result_count: number;
    newest_id?: XStableId;
    oldest_id?: XStableId;
    next_token?: string;
    previous_token?: string;
  } = { result_count: value.result_count };
  if (value.newest_id !== undefined)
    result.newest_id = parseId(value.newest_id, `${path}.newest_id`);
  if (value.oldest_id !== undefined)
    result.oldest_id = parseId(value.oldest_id, `${path}.oldest_id`);
  for (const key of ["next_token", "previous_token"] as const) {
    const token = value[key];
    if (token !== undefined) {
      if (typeof token !== "string" || !PAGE_TOKEN_PATTERN.test(token))
        schemaFailure(`${path}.${key}`);
      result[key] = token;
    }
  }
  return Object.freeze(result);
}

function compareIds(left: XStableId, right: XStableId): number {
  const leftValue = BigInt(left);
  const rightValue = BigInt(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
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
    assertExactKeys(decoded, ["meta"], ["data", "includes"], "response");
    const meta = parseMeta(decoded.meta);

    const posts =
      decoded.data === undefined
        ? []
        : (() => {
            if (
              !Array.isArray(decoded.data) ||
              decoded.data.length < 1 ||
              decoded.data.length > quarantine.metadata.maxResults
            ) {
              schemaFailure("data");
            }
            return decoded.data.map(parsePost);
          })();
    if (meta.result_count !== posts.length) schemaFailure("meta.result_count");

    let users: readonly XRecentSearchUser[] = [];
    if (decoded.includes !== undefined) {
      assertObject(decoded.includes, "includes");
      assertExactKeys(decoded.includes, ["users"], [], "includes");
      if (
        !Array.isArray(decoded.includes.users) ||
        decoded.includes.users.length < 1 ||
        decoded.includes.users.length > 100
      ) {
        schemaFailure("includes.users");
      }
      users = Object.freeze(decoded.includes.users.map(parseUser));
    }

    if ((posts.length === 0) !== (users.length === 0)) schemaFailure("includes.users");
    if (posts.length === 0) {
      if (meta.newest_id !== undefined || meta.oldest_id !== undefined) schemaFailure("meta");
    } else {
      if (meta.newest_id === undefined || meta.oldest_id === undefined) schemaFailure("meta");
      const sortedIds = posts.map((post) => post.id).sort(compareIds);
      if (meta.oldest_id !== sortedIds[0] || meta.newest_id !== sortedIds.at(-1)) {
        schemaFailure("meta");
      }
    }

    if (new Set(posts.map((post) => post.id)).size !== posts.length) schemaFailure("data");
    if (new Set(users.map((user) => user.id)).size !== users.length)
      schemaFailure("includes.users");

    const referencedAuthors = new Set(posts.map((post) => post.author_id));
    const usersById: Record<XStableId, XRecentSearchUser> = Object.create(null) as Record<
      XStableId,
      XRecentSearchUser
    >;
    for (const user of users) {
      if (!referencedAuthors.has(user.id)) schemaFailure("includes.users");
      usersById[user.id] = user;
    }
    for (const post of posts) {
      const author = usersById[post.author_id];
      if (author === undefined || Date.parse(author.created_at) > Date.parse(post.created_at)) {
        schemaFailure("includes.users");
      }
      if (Date.parse(post.created_at) > Date.parse(quarantine.metadata.acquiredAt)) {
        schemaFailure("data");
      }
    }

    return Object.freeze({
      posts: Object.freeze(posts),
      users: Object.freeze(users),
      usersById: Object.freeze(usersById),
      meta,
      requestFingerprint: quarantine.metadata.requestFingerprint,
      responseHash: quarantine.metadata.responseHash,
      acquiredAt: quarantine.metadata.acquiredAt,
    });
  } finally {
    bytes.fill(0);
  }
}
