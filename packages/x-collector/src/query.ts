import {
  X_API_ORIGIN,
  X_RECENT_SEARCH_DEFAULT_RESULTS,
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_EXPANSIONS,
  X_RECENT_SEARCH_MAX_RESULTS,
  X_RECENT_SEARCH_METHOD,
  X_RECENT_SEARCH_MIN_RESULTS,
  X_RECENT_SEARCH_NEXT_TOKEN_MAX_LENGTH,
  X_RECENT_SEARCH_PATH,
  X_RECENT_SEARCH_POST_FIELDS,
  X_RECENT_SEARCH_QUERY_MAX_LENGTH,
  X_RECENT_SEARCH_USER_FIELDS,
} from "./constants.js";
import { XCollectorError } from "./errors.js";
import { sha256, type Sha256 } from "./hash.js";

export type XRecentSearchQuery = Readonly<{
  query: string;
  maxResults?: number;
  nextToken?: string;
}>;

export type ValidatedXRecentSearchQuery = Readonly<{
  query: string;
  maxResults: number;
  nextToken?: string;
}>;

export type PreparedXRecentSearchRequest = Readonly<{
  method: typeof X_RECENT_SEARCH_METHOD;
  endpoint: typeof X_RECENT_SEARCH_ENDPOINT;
  url: string;
  canonicalRequest: string;
  fingerprint: Sha256;
  query: ValidatedXRecentSearchQuery;
}>;

const QUERY_KEYS = new Set(["query", "maxResults", "nextToken"]);
const NEXT_TOKEN_PATTERN = /^[A-Za-z0-9._~-]+$/;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalidQuery(message: string): never {
  throw new XCollectorError("INVALID_QUERY", message);
}

export function validateXRecentSearchQuery(input: unknown): ValidatedXRecentSearchQuery {
  if (!isPlainRecord(input)) invalidQuery("The recent-search query must be a plain object.");

  const ownKeys = Reflect.ownKeys(input);
  if (
    ownKeys.some((key) => typeof key !== "string" || !QUERY_KEYS.has(key)) ||
    ownKeys.length > QUERY_KEYS.size
  ) {
    invalidQuery("The recent-search query contains an unsupported property.");
  }

  const queryDescriptor = Object.getOwnPropertyDescriptor(input, "query");
  if (queryDescriptor === undefined || !("value" in queryDescriptor)) {
    invalidQuery("query is required and must be a data property.");
  }
  const query = queryDescriptor.value;
  if (
    typeof query !== "string" ||
    query.length < 1 ||
    query.length > X_RECENT_SEARCH_QUERY_MAX_LENGTH ||
    query.trim().length === 0 ||
    /[\u0000-\u001f\u007f]/u.test(query)
  ) {
    invalidQuery(
      `query must contain 1-${X_RECENT_SEARCH_QUERY_MAX_LENGTH} non-control characters.`,
    );
  }

  const maxResultsDescriptor = Object.getOwnPropertyDescriptor(input, "maxResults");
  if (maxResultsDescriptor !== undefined && !("value" in maxResultsDescriptor)) {
    invalidQuery("maxResults must be a data property.");
  }
  const maxResults =
    maxResultsDescriptor === undefined
      ? X_RECENT_SEARCH_DEFAULT_RESULTS
      : maxResultsDescriptor.value;
  if (
    typeof maxResults !== "number" ||
    !Number.isInteger(maxResults) ||
    maxResults < X_RECENT_SEARCH_MIN_RESULTS ||
    maxResults > X_RECENT_SEARCH_MAX_RESULTS
  ) {
    invalidQuery(
      `maxResults must be an integer from ${X_RECENT_SEARCH_MIN_RESULTS} through ${X_RECENT_SEARCH_MAX_RESULTS}.`,
    );
  }

  const nextTokenDescriptor = Object.getOwnPropertyDescriptor(input, "nextToken");
  if (nextTokenDescriptor !== undefined && !("value" in nextTokenDescriptor)) {
    invalidQuery("nextToken must be a data property.");
  }
  const nextToken = nextTokenDescriptor?.value;
  if (
    nextToken !== undefined &&
    (typeof nextToken !== "string" ||
      nextToken.length < 1 ||
      nextToken.length > X_RECENT_SEARCH_NEXT_TOKEN_MAX_LENGTH ||
      !NEXT_TOKEN_PATTERN.test(nextToken))
  ) {
    invalidQuery("nextToken must be a bounded URL-safe opaque token.");
  }

  return Object.freeze(
    nextToken === undefined
      ? { query, maxResults }
      : { query, maxResults, nextToken: nextToken as string },
  );
}

function canonicalizeQuery(parameters: URLSearchParams): string {
  return [...parameters.entries()]
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => {
      if (leftKey < rightKey) return -1;
      if (leftKey > rightKey) return 1;
      if (leftValue < rightValue) return -1;
      if (leftValue > rightValue) return 1;
      return 0;
    })
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}

export function prepareRecentSearchRequest(input: unknown): PreparedXRecentSearchRequest {
  const query = validateXRecentSearchQuery(input);
  const url = new URL(X_RECENT_SEARCH_PATH, X_API_ORIGIN);
  url.searchParams.set("query", query.query);
  url.searchParams.set("max_results", String(query.maxResults));
  url.searchParams.set("post.fields", X_RECENT_SEARCH_POST_FIELDS.join(","));
  url.searchParams.set("expansions", X_RECENT_SEARCH_EXPANSIONS.join(","));
  url.searchParams.set("user.fields", X_RECENT_SEARCH_USER_FIELDS.join(","));
  if (query.nextToken !== undefined) url.searchParams.set("next_token", query.nextToken);

  const canonicalRequest = `${X_RECENT_SEARCH_METHOD}\n${X_RECENT_SEARCH_ENDPOINT}\n${canonicalizeQuery(url.searchParams)}`;
  return Object.freeze({
    method: X_RECENT_SEARCH_METHOD,
    endpoint: X_RECENT_SEARCH_ENDPOINT,
    url: url.href,
    canonicalRequest,
    fingerprint: sha256(canonicalRequest),
    query,
  });
}
