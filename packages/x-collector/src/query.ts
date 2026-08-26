import {
  X_API_ORIGIN,
  X_RECENT_SEARCH_DEFAULT_RESULTS,
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_METHOD,
  X_RECENT_SEARCH_PATH,
  X_RECENT_SEARCH_QUERY_MAX_LENGTH,
  X_RECENT_SEARCH_SORT_ORDER,
} from "./constants.js";
import { XCollectorError } from "./errors.js";
import { sha256, type Sha256 } from "./hash.js";

export type XRecentSearchQuery = Readonly<{
  query: string;
}>;

export type ValidatedXRecentSearchQuery = Readonly<{
  query: string;
  maxResults: number;
}>;

export type PreparedXRecentSearchRequest = Readonly<{
  method: typeof X_RECENT_SEARCH_METHOD;
  endpoint: typeof X_RECENT_SEARCH_ENDPOINT;
  url: string;
  canonicalRequest: string;
  fingerprint: Sha256;
  query: ValidatedXRecentSearchQuery;
}>;

const QUERY_KEYS = new Set(["query"]);

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

  return Object.freeze({ query, maxResults: X_RECENT_SEARCH_DEFAULT_RESULTS });
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
  url.searchParams.set("sort_order", X_RECENT_SEARCH_SORT_ORDER);

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
