import {
  OPENSEA_TRENDING_MAXIMUM_RESULTS,
  OPENSEA_TRENDING_OPERATION,
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  OPENSEA_TRENDING_URL,
  prepareOpenSeaTrendingCollectorRequest,
} from "@rsi/opensea-collector";

export const OPENSEA_READ_CANARY_PLAN_ID = "opensea-base-trending-collections-v1" as const;
export const OPENSEA_READ_CANARY_PROVIDER_ID = "opensea-api-v2" as const;
export const OPENSEA_READ_CANARY_OPERATION = OPENSEA_TRENDING_OPERATION;
export const OPENSEA_READ_CANARY_PROFILE = "canary" as const;
export const OPENSEA_READ_CANARY_MAXIMUM_REQUESTS = 1 as const;
export const OPENSEA_READ_CANARY_MAXIMUM_RESULTS = OPENSEA_TRENDING_MAXIMUM_RESULTS;
/** Minimum nonzero USD_MICRO operations-ledger reserve; not an OpenSea price estimate. */
export const OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO = OPENSEA_TRENDING_RESERVED_ATOMIC;
export const OPENSEA_READ_CANARY_ENDPOINT = OPENSEA_TRENDING_URL;

const prepared = prepareOpenSeaTrendingCollectorRequest();

export const OPENSEA_READ_CANARY_REQUEST_FINGERPRINT = prepared.fingerprint;
