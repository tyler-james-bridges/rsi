export {
  OPENSEA_TRENDING_CONTRACT_REVIEW_DATE,
  OPENSEA_TRENDING_CONTRACT_VERSION,
  OPENSEA_TRENDING_MAXIMUM_BYTES,
  OPENSEA_TRENDING_MAXIMUM_RESULTS,
  OPENSEA_TRENDING_ORIGIN,
  OPENSEA_TRENDING_PATH,
  OPENSEA_TRENDING_QUERY,
  OPENSEA_TRENDING_TIMEOUT_MS,
  OPENSEA_TRENDING_URL,
} from "@rsi/source-contracts/opensea-trending";

export const OPENSEA_TRENDING_OPERATION = "opensea.trending-collections.v1" as const;
/** One non-payment request slot. This is not a provider charge estimate. */
export const OPENSEA_TRENDING_RESERVED_ATOMIC = "1" as const;

export const OPENSEA_TRENDING_METHOD = "GET" as const;
export const OPENSEA_TRENDING_ACCEPT = "application/json" as const;
export const OPENSEA_TRENDING_ACCEPT_ENCODING = "identity" as const;
export const OPENSEA_TRENDING_CREDENTIAL_HEADER = "x-api-key" as const;

export const OPENSEA_JSON_CONTENT_TYPES = [
  "application/json",
  "application/json; charset=utf-8",
  "application/json;charset=utf-8",
] as const;

export const OPENSEA_TRENDING_QUARANTINE_VERSION = "rsi.opensea-trending.quarantine.v1" as const;
