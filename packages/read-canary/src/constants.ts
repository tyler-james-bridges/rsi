import {
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_RESERVED_USD_MICRO,
  X_RECENT_SEARCH_SORT_ORDER,
  prepareRecentSearchRequest,
} from "@rsi/x-collector";

export const X_READ_CANARY_PLAN_ID = "x-nft-market-pulse-v1" as const;
export const X_READ_CANARY_PROVIDER_ID = "x-api-v2" as const;
export const X_READ_CANARY_OPERATION = "x.recent-search.v1" as const;
export const X_READ_CANARY_MAXIMUM_REQUESTS = 1 as const;
export const X_READ_CANARY_MAXIMUM_RESULTS = 10 as const;
export const X_READ_CANARY_MAXIMUM_CHARGE_USD_MICRO = X_RECENT_SEARCH_RESERVED_USD_MICRO;

// This query is code-owned and deliberately absent from every public projection.
// Changing it requires a reviewed source change and a new request fingerprint.
export const X_READ_CANARY_QUERY =
  '(NFT OR OpenSea OR "Robinhood Chain" OR "Base chain") lang:en -is:retweet' as const;

const prepared = prepareRecentSearchRequest({ query: X_READ_CANARY_QUERY });

export const X_READ_CANARY_REQUEST_FINGERPRINT = prepared.fingerprint;
export const X_READ_CANARY_ENDPOINT = X_RECENT_SEARCH_ENDPOINT;
export const X_READ_CANARY_SORT_ORDER = X_RECENT_SEARCH_SORT_ORDER;

export function xReadCanaryQuery(): Readonly<{ query: string }> {
  return Object.freeze({ query: X_READ_CANARY_QUERY });
}
