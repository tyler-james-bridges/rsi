import { prepareBaseRpcAnchorRequest } from "@rsi/source-contracts/base-rpc-anchor";

import {
  BASE_RPC_ANCHOR_ACCEPT,
  BASE_RPC_ANCHOR_ACCEPT_ENCODING,
  BASE_RPC_ANCHOR_BODY,
  BASE_RPC_ANCHOR_CONTENT_TYPE,
  BASE_RPC_ANCHOR_CONTRACT_REVIEW_DATE,
  BASE_RPC_ANCHOR_CONTRACT_VERSION,
  BASE_RPC_ANCHOR_CREDENTIAL_HEADER,
  BASE_RPC_ANCHOR_CREDENTIAL_SCHEME,
  BASE_RPC_ANCHOR_MAXIMUM_BYTES,
  BASE_RPC_ANCHOR_METHOD,
  BASE_RPC_ANCHOR_OPERATION,
  BASE_RPC_ANCHOR_ORIGIN,
  BASE_RPC_ANCHOR_PATH,
  BASE_RPC_ANCHOR_TIMEOUT_MS,
  BASE_RPC_ANCHOR_URL,
} from "./constants.js";
import { BaseRpcCollectorError } from "./errors.js";
import { sha256, type Sha256 } from "./hash.js";

export type PreparedBaseRpcAnchorCollectorRequest = Readonly<{
  method: typeof BASE_RPC_ANCHOR_METHOD;
  origin: typeof BASE_RPC_ANCHOR_ORIGIN;
  path: typeof BASE_RPC_ANCHOR_PATH;
  url: typeof BASE_RPC_ANCHOR_URL;
  body: typeof BASE_RPC_ANCHOR_BODY;
  canonicalRequest: string;
  fingerprint: Sha256;
}>;

const CANONICAL_REQUEST = [
  BASE_RPC_ANCHOR_METHOD,
  `origin:${BASE_RPC_ANCHOR_ORIGIN}`,
  `path:${BASE_RPC_ANCHOR_PATH}`,
  `url:${BASE_RPC_ANCHOR_URL}`,
  `accept:${BASE_RPC_ANCHOR_ACCEPT}`,
  `accept-encoding:${BASE_RPC_ANCHOR_ACCEPT_ENCODING}`,
  `content-type:${BASE_RPC_ANCHOR_CONTENT_TYPE}`,
  `credential-header:${BASE_RPC_ANCHOR_CREDENTIAL_HEADER}`,
  `credential-scheme:${BASE_RPC_ANCHOR_CREDENTIAL_SCHEME}`,
  `body:${BASE_RPC_ANCHOR_BODY}`,
].join("\n");

const FIXED_REQUEST: PreparedBaseRpcAnchorCollectorRequest = Object.freeze({
  method: BASE_RPC_ANCHOR_METHOD,
  origin: BASE_RPC_ANCHOR_ORIGIN,
  path: BASE_RPC_ANCHOR_PATH,
  url: BASE_RPC_ANCHOR_URL,
  body: BASE_RPC_ANCHOR_BODY,
  canonicalRequest: CANONICAL_REQUEST,
  fingerprint: sha256(CANONICAL_REQUEST),
});

/** Returns the one code-owned request. It accepts no provider- or caller-controlled input. */
export function prepareBaseRpcAnchorCollectorRequest(): PreparedBaseRpcAnchorCollectorRequest {
  if (arguments.length !== 0) {
    throw new BaseRpcCollectorError(
      "INVALID_CONFIGURATION",
      "The Base RPC anchor request accepts no caller input.",
    );
  }
  const descriptor = prepareBaseRpcAnchorRequest();
  if (
    descriptor.accept !== BASE_RPC_ANCHOR_ACCEPT ||
    descriptor.body !== BASE_RPC_ANCHOR_BODY ||
    descriptor.chainId !== "8453" ||
    descriptor.contentType !== BASE_RPC_ANCHOR_CONTENT_TYPE ||
    descriptor.contractReviewDate !== BASE_RPC_ANCHOR_CONTRACT_REVIEW_DATE ||
    descriptor.contractVersion !== BASE_RPC_ANCHOR_CONTRACT_VERSION ||
    descriptor.credentialHeader !== BASE_RPC_ANCHOR_CREDENTIAL_HEADER ||
    descriptor.credentialScheme !== BASE_RPC_ANCHOR_CREDENTIAL_SCHEME ||
    descriptor.maximumHttpRequests !== 1 ||
    descriptor.maximumResponseBytes !== BASE_RPC_ANCHOR_MAXIMUM_BYTES ||
    descriptor.method !== BASE_RPC_ANCHOR_METHOD ||
    descriptor.operation !== BASE_RPC_ANCHOR_OPERATION ||
    descriptor.origin !== BASE_RPC_ANCHOR_ORIGIN ||
    descriptor.path !== BASE_RPC_ANCHOR_PATH ||
    descriptor.redirect !== "reject" ||
    descriptor.retryAttempts !== 0 ||
    descriptor.timeoutMs !== BASE_RPC_ANCHOR_TIMEOUT_MS ||
    descriptor.url !== BASE_RPC_ANCHOR_URL
  ) {
    throw new BaseRpcCollectorError(
      "INVALID_CONFIGURATION",
      "The reviewed Base RPC anchor request contract changed.",
    );
  }
  return FIXED_REQUEST;
}

export function isPreparedBaseRpcAnchorCollectorRequest(
  value: unknown,
): value is PreparedBaseRpcAnchorCollectorRequest {
  return value === FIXED_REQUEST;
}
