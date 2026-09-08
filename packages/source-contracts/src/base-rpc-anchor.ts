import { z } from "zod";

import {
  Bytes32Schema,
  HexQuantitySchema,
  TimestampSchema,
  fail,
  parseJsonBytes,
  parsePlain,
} from "./common.js";

/**
 * Reviewed against Base's JSON-RPC reference and Alchemy's header-authentication
 * guidance on 2026-09-05. This contract intentionally describes one provider,
 * one chain, one block tag, and one two-call batch.
 */
export const BASE_RPC_ANCHOR_CONTRACT_VERSION =
  "alchemy-base-mainnet-finalized-anchor.2026-09-05.v1" as const;
export const BASE_RPC_ANCHOR_CONTRACT_REVIEW_DATE = "2026-09-05" as const;
export const BASE_RPC_ANCHOR_ORIGIN = "https://base-mainnet.g.alchemy.com" as const;
export const BASE_RPC_ANCHOR_PATH = "/v2" as const;
export const BASE_RPC_ANCHOR_URL = `${BASE_RPC_ANCHOR_ORIGIN}${BASE_RPC_ANCHOR_PATH}` as const;
export const BASE_RPC_ANCHOR_MAXIMUM_BYTES = 1_024 * 1_024;
export const BASE_RPC_ANCHOR_TIMEOUT_MS = 10_000 as const;
export const BASE_RPC_ANCHOR_MAXIMUM_AGE_MS = 2 * 60 * 60 * 1_000;
export const BASE_RPC_ANCHOR_BODY =
  '[{"id":"rsi-base-chain-id-v1","jsonrpc":"2.0","method":"eth_chainId","params":[]},{"id":"rsi-base-finalized-block-v1","jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}]' as const;

const UINT256_MAX = (1n << 256n) - 1n;
const EMPTY_UNCLES_HASH =
  "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347" as const;
const CONSTRUCTION_TOKEN = Object.freeze({ baseRpcAnchor: true });
const AUTHENTIC_ANCHORS = new WeakSet<object>();

const EvmAddressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const ExtraDataSchema = z
  .string()
  .max(66)
  .regex(/^0x(?:[0-9a-fA-F]{2})*$/);
const LogsBloomSchema = z.string().regex(/^0x[0-9a-fA-F]{512}$/);
const EmptyHashArraySchema = z.array(Bytes32Schema).length(0);
const EmptyWithdrawalArraySchema = z.array(z.never()).length(0);

/**
 * Exact accepted key set for a finalized Base block requested with
 * fullTransactions=false. Fork-dependent fields are optional, but unknown keys,
 * transaction objects, uncles, and withdrawals fail closed.
 */
const BlockResultSchema = z.strictObject({
  baseFeePerGas: HexQuantitySchema,
  blobGasUsed: HexQuantitySchema.optional(),
  difficulty: z.literal("0x0"),
  excessBlobGas: HexQuantitySchema.optional(),
  extraData: ExtraDataSchema,
  gasLimit: HexQuantitySchema,
  gasUsed: HexQuantitySchema,
  hash: Bytes32Schema,
  logsBloom: LogsBloomSchema,
  miner: EvmAddressSchema,
  mixHash: Bytes32Schema.optional(),
  nonce: z.literal("0x0000000000000000"),
  number: HexQuantitySchema,
  parentBeaconBlockRoot: Bytes32Schema.optional(),
  parentHash: Bytes32Schema,
  receiptsRoot: Bytes32Schema,
  requestsHash: Bytes32Schema.optional(),
  sha3Uncles: z.literal(EMPTY_UNCLES_HASH),
  size: HexQuantitySchema,
  stateRoot: Bytes32Schema,
  timestamp: HexQuantitySchema,
  totalDifficulty: z.literal("0x0"),
  transactions: z.array(Bytes32Schema),
  transactionsRoot: Bytes32Schema,
  uncles: EmptyHashArraySchema,
  withdrawals: EmptyWithdrawalArraySchema,
  withdrawalsRoot: Bytes32Schema.optional(),
});

const AnchorResponseSchema = z
  .array(
    z.discriminatedUnion("id", [
      z.strictObject({
        id: z.literal("rsi-base-chain-id-v1"),
        jsonrpc: z.literal("2.0"),
        result: HexQuantitySchema,
      }),
      z.strictObject({
        id: z.literal("rsi-base-finalized-block-v1"),
        jsonrpc: z.literal("2.0"),
        result: BlockResultSchema,
      }),
    ]),
  )
  .length(2);

export interface BaseRpcAnchorRequestV1 {
  readonly accept: "application/json";
  readonly body: typeof BASE_RPC_ANCHOR_BODY;
  readonly chainId: "8453";
  readonly contentType: "application/json";
  readonly contractReviewDate: typeof BASE_RPC_ANCHOR_CONTRACT_REVIEW_DATE;
  readonly contractVersion: typeof BASE_RPC_ANCHOR_CONTRACT_VERSION;
  readonly credentialHeader: "authorization";
  readonly credentialScheme: "Bearer";
  readonly maximumHttpRequests: 1;
  readonly maximumResponseBytes: typeof BASE_RPC_ANCHOR_MAXIMUM_BYTES;
  readonly method: "POST";
  readonly operation: "alchemy.json-rpc.v1";
  readonly origin: typeof BASE_RPC_ANCHOR_ORIGIN;
  readonly path: typeof BASE_RPC_ANCHOR_PATH;
  readonly redirect: "reject";
  readonly retryAttempts: 0;
  readonly timeoutMs: typeof BASE_RPC_ANCHOR_TIMEOUT_MS;
  readonly url: typeof BASE_RPC_ANCHOR_URL;
}

type AnchorValues = Readonly<{
  acquiredAt: string;
  blockHash: string;
  blockNumber: string;
  blockTimestamp: string;
  parentHash: string;
}>;

/**
 * A provider-reported finalized Base head. Private fields and toJSON keep block
 * identifiers out of logs and generic serialization unless a trusted caller
 * deliberately reads an individual property.
 */
export class BaseRpcFinalizedAnchor {
  readonly acquiredAt: string;
  readonly chainId = "8453" as const;
  readonly network = "base-mainnet" as const;
  readonly providerReportedFinalized = true as const;
  readonly #blockHash: string;
  readonly #blockNumber: string;
  readonly #blockTimestamp: string;
  readonly #parentHash: string;

  constructor(token: unknown, values: AnchorValues) {
    if (token !== CONSTRUCTION_TOKEN) fail("INPUT_INVALID");
    this.acquiredAt = values.acquiredAt;
    this.#blockHash = values.blockHash;
    this.#blockNumber = values.blockNumber;
    this.#blockTimestamp = values.blockTimestamp;
    this.#parentHash = values.parentHash;
    AUTHENTIC_ANCHORS.add(this);
    Object.freeze(this);
  }

  get blockHash(): string {
    this.#assertAuthentic();
    return this.#blockHash;
  }

  get blockNumber(): string {
    this.#assertAuthentic();
    return this.#blockNumber;
  }

  get blockTimestamp(): string {
    this.#assertAuthentic();
    return this.#blockTimestamp;
  }

  get parentHash(): string {
    this.#assertAuthentic();
    return this.#parentHash;
  }

  toJSON(): Readonly<{
    acquiredAt: string;
    chainId: "8453";
    evidence: "base-rpc-finalized-anchor";
    network: "base-mainnet";
    providerReportedFinalized: true;
  }> {
    this.#assertAuthentic();
    return Object.freeze({
      acquiredAt: this.acquiredAt,
      chainId: this.chainId,
      evidence: "base-rpc-finalized-anchor",
      network: this.network,
      providerReportedFinalized: true,
    });
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_ANCHORS.has(this) ||
      Object.getPrototypeOf(this) !== BaseRpcFinalizedAnchor.prototype
    ) {
      fail("INPUT_INVALID");
    }
  }
}

Object.freeze(BaseRpcFinalizedAnchor.prototype);
Object.freeze(BaseRpcFinalizedAnchor);

/** Prepare the single code-owned Base Mainnet request. Caller input is forbidden. */
export function prepareBaseRpcAnchorRequest(): Readonly<BaseRpcAnchorRequestV1> {
  if (arguments.length !== 0) fail("INPUT_INVALID");
  return Object.freeze({
    accept: "application/json",
    body: BASE_RPC_ANCHOR_BODY,
    chainId: "8453",
    contentType: "application/json",
    contractReviewDate: BASE_RPC_ANCHOR_CONTRACT_REVIEW_DATE,
    contractVersion: BASE_RPC_ANCHOR_CONTRACT_VERSION,
    credentialHeader: "authorization",
    credentialScheme: "Bearer",
    maximumHttpRequests: 1,
    maximumResponseBytes: BASE_RPC_ANCHOR_MAXIMUM_BYTES,
    method: "POST",
    operation: "alchemy.json-rpc.v1",
    origin: BASE_RPC_ANCHOR_ORIGIN,
    path: BASE_RPC_ANCHOR_PATH,
    redirect: "reject",
    retryAttempts: 0,
    timeoutMs: BASE_RPC_ANCHOR_TIMEOUT_MS,
    url: BASE_RPC_ANCHOR_URL,
  });
}

/**
 * Validate a two-envelope JSON-RPC response and project only a fresh Base
 * provider-reported finalized anchor. Batch response order may vary.
 */
export function parseBaseRpcFinalizedAnchor(
  bytes: unknown,
  acquiredAtValue: unknown,
): Readonly<BaseRpcFinalizedAnchor> {
  if (arguments.length !== 2) fail("INPUT_INVALID");
  const acquiredAt = parsePlain(TimestampSchema, acquiredAtValue);
  const response = parseJsonBytes(AnchorResponseSchema, bytes, BASE_RPC_ANCHOR_MAXIMUM_BYTES);
  const chainEntries = response.filter((entry) => entry.id === "rsi-base-chain-id-v1");
  const blockEntries = response.filter((entry) => entry.id === "rsi-base-finalized-block-v1");
  if (chainEntries.length !== 1 || blockEntries.length !== 1) fail("RESPONSE_INVALID");

  let chainId: bigint;
  try {
    chainId = BigInt(chainEntries[0]!.result);
  } catch {
    fail("RESPONSE_INVALID");
  }
  if (chainId !== 8_453n) fail("ASSET_MISMATCH");

  const block = blockEntries[0]!.result;
  let blockNumber: bigint;
  let blockTimestampSeconds: bigint;
  try {
    blockNumber = BigInt(block.number);
    blockTimestampSeconds = BigInt(block.timestamp);
  } catch {
    fail("RESPONSE_INVALID");
  }
  if (blockNumber === 0n || blockNumber > UINT256_MAX) fail("RESPONSE_INVALID");

  const blockTimestamp = blockTimestampIso(blockTimestampSeconds);
  const ageMs = Date.parse(acquiredAt) - Date.parse(blockTimestamp);
  if (ageMs < 0 || ageMs > BASE_RPC_ANCHOR_MAXIMUM_AGE_MS) fail("STALE_RESPONSE");

  return new BaseRpcFinalizedAnchor(CONSTRUCTION_TOKEN, {
    acquiredAt,
    blockHash: block.hash.toLowerCase(),
    blockNumber: blockNumber.toString(10),
    blockTimestamp,
    parentHash: block.parentHash.toLowerCase(),
  });
}

export function isBaseRpcFinalizedAnchor(value: unknown): value is BaseRpcFinalizedAnchor {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHENTIC_ANCHORS.has(value) &&
    Object.getPrototypeOf(value) === BaseRpcFinalizedAnchor.prototype
  );
}

function blockTimestampIso(seconds: bigint): string {
  const milliseconds = seconds * 1_000n;
  if (milliseconds > 8_640_000_000_000_000n) fail("RESPONSE_INVALID");
  try {
    return new Date(Number(milliseconds)).toISOString();
  } catch {
    fail("RESPONSE_INVALID");
  }
}
