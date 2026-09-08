export {
  BASE_RPC_ANCHOR_BODY,
  BASE_RPC_ANCHOR_CONTRACT_REVIEW_DATE,
  BASE_RPC_ANCHOR_CONTRACT_VERSION,
  BASE_RPC_ANCHOR_MAXIMUM_AGE_MS,
  BASE_RPC_ANCHOR_MAXIMUM_BYTES,
  BASE_RPC_ANCHOR_ORIGIN,
  BASE_RPC_ANCHOR_PATH,
  BASE_RPC_ANCHOR_TIMEOUT_MS,
  BASE_RPC_ANCHOR_URL,
} from "@rsi/source-contracts/base-rpc-anchor";

export const BASE_RPC_ANCHOR_OPERATION = "alchemy.json-rpc.v1" as const;
/** One non-payment request slot. This is not a provider charge estimate. */
export const BASE_RPC_ANCHOR_RESERVED_ATOMIC = "1" as const;
export const BASE_RPC_ANCHOR_SOURCE_PLANE = "canonical_chain" as const;
export const BASE_RPC_ANCHOR_LANE = "contract" as const;

export const BASE_RPC_ANCHOR_METHOD = "POST" as const;
export const BASE_RPC_ANCHOR_ACCEPT = "application/json" as const;
export const BASE_RPC_ANCHOR_CONTENT_TYPE = "application/json" as const;
export const BASE_RPC_ANCHOR_ACCEPT_ENCODING = "identity" as const;
export const BASE_RPC_ANCHOR_CREDENTIAL_HEADER = "authorization" as const;
export const BASE_RPC_ANCHOR_CREDENTIAL_SCHEME = "Bearer" as const;

export const BASE_RPC_JSON_CONTENT_TYPES = [
  "application/json",
  "application/json; charset=utf-8",
  "application/json;charset=utf-8",
] as const;

export const BASE_RPC_ANCHOR_QUARANTINE_VERSION = "rsi.base-rpc-anchor.quarantine.v1" as const;
