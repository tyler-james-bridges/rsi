import { prepareOpenSeaTrendingRequest } from "@rsi/source-contracts/opensea-trending";

import {
  OPENSEA_TRENDING_ACCEPT,
  OPENSEA_TRENDING_ACCEPT_ENCODING,
  OPENSEA_TRENDING_CONTRACT_REVIEW_DATE,
  OPENSEA_TRENDING_CONTRACT_VERSION,
  OPENSEA_TRENDING_CREDENTIAL_HEADER,
  OPENSEA_TRENDING_MAXIMUM_BYTES,
  OPENSEA_TRENDING_MAXIMUM_RESULTS,
  OPENSEA_TRENDING_METHOD,
  OPENSEA_TRENDING_OPERATION,
  OPENSEA_TRENDING_ORIGIN,
  OPENSEA_TRENDING_PATH,
  OPENSEA_TRENDING_QUERY,
  OPENSEA_TRENDING_TIMEOUT_MS,
  OPENSEA_TRENDING_URL,
} from "./constants.js";
import { OpenSeaCollectorError } from "./errors.js";
import { sha256, type Sha256 } from "./hash.js";

export type PreparedOpenSeaTrendingCollectorRequest = Readonly<{
  method: typeof OPENSEA_TRENDING_METHOD;
  origin: typeof OPENSEA_TRENDING_ORIGIN;
  path: typeof OPENSEA_TRENDING_PATH;
  query: typeof OPENSEA_TRENDING_QUERY;
  url: typeof OPENSEA_TRENDING_URL;
  canonicalRequest: string;
  fingerprint: Sha256;
}>;

const CANONICAL_REQUEST = [
  OPENSEA_TRENDING_METHOD,
  `origin:${OPENSEA_TRENDING_ORIGIN}`,
  `path:${OPENSEA_TRENDING_PATH}`,
  `query:${OPENSEA_TRENDING_QUERY}`,
  OPENSEA_TRENDING_URL,
  `accept:${OPENSEA_TRENDING_ACCEPT}`,
  `accept-encoding:${OPENSEA_TRENDING_ACCEPT_ENCODING}`,
  `credential-header:${OPENSEA_TRENDING_CREDENTIAL_HEADER}`,
].join("\n");

const FIXED_REQUEST: PreparedOpenSeaTrendingCollectorRequest = Object.freeze({
  method: OPENSEA_TRENDING_METHOD,
  origin: OPENSEA_TRENDING_ORIGIN,
  path: OPENSEA_TRENDING_PATH,
  query: OPENSEA_TRENDING_QUERY,
  url: OPENSEA_TRENDING_URL,
  canonicalRequest: CANONICAL_REQUEST,
  fingerprint: sha256(CANONICAL_REQUEST),
});

/** Returns the one code-owned request. It accepts no provider-controlled input. */
export function prepareOpenSeaTrendingCollectorRequest(): PreparedOpenSeaTrendingCollectorRequest {
  if (arguments.length !== 0) {
    throw new OpenSeaCollectorError(
      "INVALID_CONFIGURATION",
      "The OpenSea trending request accepts no caller input.",
    );
  }
  const descriptor = prepareOpenSeaTrendingRequest();
  if (
    descriptor.accept !== OPENSEA_TRENDING_ACCEPT ||
    descriptor.contractReviewDate !== OPENSEA_TRENDING_CONTRACT_REVIEW_DATE ||
    descriptor.contractVersion !== OPENSEA_TRENDING_CONTRACT_VERSION ||
    descriptor.maximumResponseBytes !== OPENSEA_TRENDING_MAXIMUM_BYTES ||
    descriptor.maximumResults !== OPENSEA_TRENDING_MAXIMUM_RESULTS ||
    descriptor.method !== OPENSEA_TRENDING_METHOD ||
    descriptor.operation !== OPENSEA_TRENDING_OPERATION ||
    descriptor.origin !== OPENSEA_TRENDING_ORIGIN ||
    descriptor.path !== OPENSEA_TRENDING_PATH ||
    descriptor.query !== OPENSEA_TRENDING_QUERY ||
    descriptor.redirect !== "reject" ||
    descriptor.retryAttempts !== 0 ||
    descriptor.timeoutMs !== OPENSEA_TRENDING_TIMEOUT_MS ||
    descriptor.url !== OPENSEA_TRENDING_URL ||
    descriptor.credentialHeader !== OPENSEA_TRENDING_CREDENTIAL_HEADER
  ) {
    throw new OpenSeaCollectorError(
      "INVALID_CONFIGURATION",
      "The reviewed OpenSea trending request contract changed.",
    );
  }
  return FIXED_REQUEST;
}

/** Runtime identity check for the single request object issued by this module. */
export function isPreparedOpenSeaTrendingCollectorRequest(
  value: unknown,
): value is PreparedOpenSeaTrendingCollectorRequest {
  return value === FIXED_REQUEST;
}
