export const BASE_RPC_READ_CANARY_PLAN_ID = "base-mainnet-finalized-anchor-v1" as const;
export const BASE_RPC_READ_CANARY_PROVIDER_ID = "alchemy-base-mainnet" as const;
export const BASE_RPC_READ_CANARY_OPERATION = "alchemy.json-rpc.v1" as const;
export const BASE_RPC_READ_CANARY_PROFILE = "canary" as const;
export const BASE_RPC_READ_CANARY_ENDPOINT = "https://base-mainnet.g.alchemy.com/v2" as const;
export const BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS = 1 as const;
export const BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS = 1 as const;
export const BASE_RPC_READ_CANARY_MAXIMUM_BYTES = 1_024 * 1_024;
/** Minimum nonzero USD_MICRO operations-ledger reserve; not a provider price estimate. */
export const BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO = "1" as const;
export const BASE_RPC_READ_CANARY_RPC_METHODS = Object.freeze([
  "eth_chainId",
  "eth_getBlockByNumber",
] as const);
export const BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT =
  "eth_chainId[]+eth_getBlockByNumber[finalized,false]" as const;

export const BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT =
  "sha256:63cde192b3f9f2aaab24e5a01b66c538acf98eb697ba4b45d86de25b99d1901f" as const;

export function baseRpcReadCanaryRuntimeActionId(attemptId: string): string {
  return `base.rpc-anchor:${attemptId}:${BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT.slice("sha256:".length)}`;
}
