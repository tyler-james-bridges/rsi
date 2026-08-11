/**
 * Contract verified against the endpoint-specific X API reference on 2026-08-11.
 * Bump this value only after a deliberate review of an upstream contract change.
 */
export const X_RECENT_SEARCH_API_CONTRACT_VERSION =
  "x-api-v2-recent-search.endpoint-reference.2026-08-11.post-fields-v1" as const;

export const X_API_ORIGIN = "https://api.x.com" as const;
export const X_RECENT_SEARCH_PATH = "/2/tweets/search/recent" as const;
export const X_RECENT_SEARCH_ENDPOINT = `${X_API_ORIGIN}${X_RECENT_SEARCH_PATH}` as const;
export const X_RECENT_SEARCH_METHOD = "GET" as const;

export const X_RECENT_SEARCH_POST_FIELDS = ["id", "text", "created_at"] as const;

export const X_RECENT_SEARCH_USER_FIELDS = ["id", "name", "username", "created_at"] as const;
export const X_RECENT_SEARCH_EXPANSIONS = ["author_id"] as const;

export const X_RECENT_SEARCH_MIN_RESULTS = 10 as const;
export const X_RECENT_SEARCH_MAX_RESULTS = 100 as const;
export const X_RECENT_SEARCH_DEFAULT_RESULTS = 10 as const;
export const X_RECENT_SEARCH_QUERY_MAX_LENGTH = 4_096 as const;
export const X_RECENT_SEARCH_NEXT_TOKEN_MAX_LENGTH = 2_048 as const;

export const X_RECENT_SEARCH_DEFAULT_TIMEOUT_MS = 15_000 as const;
export const X_RECENT_SEARCH_MAX_TIMEOUT_MS = 60_000 as const;
export const X_RECENT_SEARCH_DEFAULT_MAX_RESPONSE_BYTES = 1_048_576 as const;
export const X_RECENT_SEARCH_MAX_RESPONSE_BYTES = 8_388_608 as const;

export const X_JSON_CONTENT_TYPES = [
  "application/json",
  "application/json; charset=utf-8",
  "application/json;charset=utf-8",
] as const;

export const X_RECENT_SEARCH_CASSETTE_VERSION = "rsi.x-recent-search.cassette.v1" as const;
export const X_RECENT_SEARCH_QUARANTINE_VERSION = "rsi.x-recent-search.quarantine.v1" as const;

export type XRecentSearchPostField = (typeof X_RECENT_SEARCH_POST_FIELDS)[number];
export type XRecentSearchUserField = (typeof X_RECENT_SEARCH_USER_FIELDS)[number];
