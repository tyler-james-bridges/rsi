import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  BASE_RPC_ANCHOR_BODY,
  BASE_RPC_ANCHOR_CONTRACT_VERSION,
  BASE_RPC_ANCHOR_ORIGIN,
  BASE_RPC_ANCHOR_PATH,
  BASE_RPC_ANCHOR_URL,
  prepareBaseRpcAnchorRequest,
} from "@rsi/source-contracts/base-rpc-anchor";

export const BASE_RPC_INGESTION_SOURCE = "alchemy" as const;
export const BASE_RPC_INGESTION_SOURCE_PLANE = "canonical_chain" as const;
export const BASE_RPC_INGESTION_LANE = "contract" as const;
export const BASE_RPC_INGESTION_OPERATION = "alchemy.json-rpc.v1" as const;
export const BASE_RPC_INGESTION_RESERVED_ATOMIC = "1" as const;
export const BASE_RPC_INGESTION_ADAPTER_ID = "alchemy.base-rpc-anchor" as const;

export const BASE_RPC_INGESTION_JSON_CONTENT_TYPES = Object.freeze([
  "application/json",
  "application/json; charset=utf-8",
  "application/json;charset=utf-8",
] as const);

export const BASE_RPC_INGESTION_REQUEST_BODY =
  '[{"id":"rsi-base-chain-id-v1","jsonrpc":"2.0","method":"eth_chainId","params":[]},{"id":"rsi-base-finalized-block-v1","jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}]' as const;

export const BASE_RPC_INGESTION_CANONICAL_REQUEST = [
  "POST",
  `origin:${BASE_RPC_ANCHOR_ORIGIN}`,
  `path:${BASE_RPC_ANCHOR_PATH}`,
  `url:${BASE_RPC_ANCHOR_URL}`,
  "accept:application/json",
  "accept-encoding:identity",
  "content-type:application/json",
  "credential-header:authorization",
  "credential-scheme:Bearer",
  `body:${BASE_RPC_INGESTION_REQUEST_BODY}`,
].join("\n");

export const BASE_RPC_INGESTION_REQUEST_FINGERPRINT =
  "sha256:63cde192b3f9f2aaab24e5a01b66c538acf98eb697ba4b45d86de25b99d1901f" as const;

export interface BaseRpcAnchorRequestIdentity {
  readonly body: typeof BASE_RPC_INGESTION_REQUEST_BODY;
  readonly canonicalRequest: typeof BASE_RPC_INGESTION_CANONICAL_REQUEST;
  readonly fingerprint: typeof BASE_RPC_INGESTION_REQUEST_FINGERPRINT;
  readonly method: "POST";
  readonly origin: typeof BASE_RPC_ANCHOR_ORIGIN;
  readonly path: typeof BASE_RPC_ANCHOR_PATH;
  readonly url: typeof BASE_RPC_ANCHOR_URL;
}

function requestFingerprint(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function assertPinnedContract(): void {
  const descriptor = prepareBaseRpcAnchorRequest();
  if (
    BASE_RPC_ANCHOR_BODY !== BASE_RPC_INGESTION_REQUEST_BODY ||
    descriptor.body !== BASE_RPC_INGESTION_REQUEST_BODY ||
    descriptor.contractVersion !== BASE_RPC_ANCHOR_CONTRACT_VERSION ||
    descriptor.maximumHttpRequests !== 1 ||
    descriptor.method !== "POST" ||
    descriptor.operation !== BASE_RPC_INGESTION_OPERATION ||
    descriptor.origin !== BASE_RPC_ANCHOR_ORIGIN ||
    descriptor.path !== BASE_RPC_ANCHOR_PATH ||
    descriptor.url !== BASE_RPC_ANCHOR_URL ||
    requestFingerprint(BASE_RPC_INGESTION_CANONICAL_REQUEST) !==
      BASE_RPC_INGESTION_REQUEST_FINGERPRINT
  ) {
    throw new Error("the pinned Base RPC ingestion request contract changed");
  }
}

assertPinnedContract();

export function assertBaseRpcAnchorRequestIdentity(
  value: unknown,
): asserts value is Readonly<BaseRpcAnchorRequestIdentity> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error("the Base RPC collector request is not authentic");
  }
  const expected = Object.freeze({
    body: BASE_RPC_INGESTION_REQUEST_BODY,
    canonicalRequest: BASE_RPC_INGESTION_CANONICAL_REQUEST,
    fingerprint: BASE_RPC_INGESTION_REQUEST_FINGERPRINT,
    method: "POST",
    origin: BASE_RPC_ANCHOR_ORIGIN,
    path: BASE_RPC_ANCHOR_PATH,
    url: BASE_RPC_ANCHOR_URL,
  } as const);
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== Reflect.ownKeys(expected).length ||
    keys.some((key) => typeof key !== "string" || !(key in expected))
  ) {
    throw new Error("the Base RPC collector request changed");
  }
  for (const [key, expectedValue] of Object.entries(expected)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      descriptor.value !== expectedValue
    ) {
      throw new Error("the Base RPC collector request changed");
    }
  }
}

export { BASE_RPC_ANCHOR_CONTRACT_VERSION, BASE_RPC_ANCHOR_URL };
