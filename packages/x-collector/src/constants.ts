/**
 * Contract verified against the endpoint-specific X API reference on 2026-08-25.
 * Bump this value only after a deliberate review of an upstream contract change.
 */
export const X_RECENT_SEARCH_API_CONTRACT_VERSION =
  "x-api-v2-recent-search.2026-08-25.minimal-one-request-v2" as const;

export const X_API_ORIGIN = "https://api.x.com" as const;
export const X_RECENT_SEARCH_PATH = "/2/tweets/search/recent" as const;
export const X_RECENT_SEARCH_ENDPOINT = `${X_API_ORIGIN}${X_RECENT_SEARCH_PATH}` as const;
export const X_RECENT_SEARCH_METHOD = "GET" as const;
export const X_RECENT_SEARCH_SORT_ORDER = "recency" as const;

export const X_RECENT_SEARCH_MIN_RESULTS = 10 as const;
export const X_RECENT_SEARCH_MAX_RESULTS = 10 as const;
export const X_RECENT_SEARCH_DEFAULT_RESULTS = 10 as const;
/** Ten Post resources at the reviewed $0.005 public rate. */
export const X_RECENT_SEARCH_RESERVED_USD_MICRO = "50000" as const;
export const X_RECENT_SEARCH_QUERY_MAX_LENGTH = 512 as const;
export const X_RECENT_SEARCH_NEXT_TOKEN_MAX_LENGTH = 2_048 as const;

export const X_RECENT_SEARCH_DEFAULT_TIMEOUT_MS = 15_000 as const;
export const X_RECENT_SEARCH_MAX_TIMEOUT_MS = 15_000 as const;
export const X_RECENT_SEARCH_DEFAULT_MAX_RESPONSE_BYTES = 1_048_576 as const;
export const X_RECENT_SEARCH_MAX_RESPONSE_BYTES = 1_048_576 as const;

export const X_JSON_CONTENT_TYPES = [
  "application/json",
  "application/json; charset=utf-8",
  "application/json;charset=utf-8",
] as const;

export const X_RECENT_SEARCH_CASSETTE_VERSION = "rsi.x-recent-search.cassette.v2" as const;
export const X_RECENT_SEARCH_QUARANTINE_VERSION = "rsi.x-recent-search.quarantine.v2" as const;
