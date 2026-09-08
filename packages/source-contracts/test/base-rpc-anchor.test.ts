import { describe, expect, it } from "vitest";

import {
  BASE_RPC_ANCHOR_BODY,
  BASE_RPC_ANCHOR_MAXIMUM_AGE_MS,
  BASE_RPC_ANCHOR_URL,
  BaseRpcFinalizedAnchor,
  isBaseRpcFinalizedAnchor,
  parseBaseRpcFinalizedAnchor,
  prepareBaseRpcAnchorRequest,
} from "@rsi/source-contracts/base-rpc-anchor";

const ACQUIRED_AT = "2026-09-05T12:00:00.000Z";
const FRESH_BLOCK_AT = "2026-09-05T11:30:00.000Z";
const BLOCK_HASH = `0x${"11".repeat(32)}`;
const PARENT_HASH = `0x${"22".repeat(32)}`;
const BLOCK_NUMBER_HEX = "0x1234abcd";
const EMPTY_UNCLES_HASH = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";
const LOGS_BLOOM = `0x${"00".repeat(256)}`;
const ROOT = `0x${"33".repeat(32)}`;

function hexTimestamp(timestamp: string): string {
  return `0x${Math.floor(Date.parse(timestamp) / 1_000).toString(16)}`;
}

function validResponse(): unknown[] {
  return [
    { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", result: "0x2105" },
    {
      id: "rsi-base-finalized-block-v1",
      jsonrpc: "2.0",
      result: {
        baseFeePerGas: "0x1",
        blobGasUsed: "0x0",
        difficulty: "0x0",
        excessBlobGas: "0x0",
        extraData: "0x",
        gasLimit: "0x1c9c380",
        gasUsed: "0x5208",
        hash: BLOCK_HASH,
        logsBloom: LOGS_BLOOM,
        miner: `0x${"44".repeat(20)}`,
        mixHash: ROOT,
        nonce: "0x0000000000000000",
        number: BLOCK_NUMBER_HEX,
        parentBeaconBlockRoot: ROOT,
        parentHash: PARENT_HASH,
        receiptsRoot: ROOT,
        requestsHash: ROOT,
        sha3Uncles: EMPTY_UNCLES_HASH,
        size: "0x200",
        stateRoot: ROOT,
        timestamp: hexTimestamp(FRESH_BLOCK_AT),
        totalDifficulty: "0x0",
        transactions: [],
        transactionsRoot: ROOT,
        uncles: [],
        withdrawals: [],
        withdrawalsRoot: ROOT,
      },
    },
  ];
}

function bytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

describe("isolated Base RPC anchor source contract", () => {
  it("owns one exact no-input Alchemy Base Mainnet batch", () => {
    const request = prepareBaseRpcAnchorRequest();
    expect(request).toEqual({
      accept: "application/json",
      body: BASE_RPC_ANCHOR_BODY,
      chainId: "8453",
      contentType: "application/json",
      contractReviewDate: "2026-09-05",
      contractVersion: "alchemy-base-mainnet-finalized-anchor.2026-09-05.v1",
      credentialHeader: "authorization",
      credentialScheme: "Bearer",
      maximumHttpRequests: 1,
      maximumResponseBytes: 1_048_576,
      method: "POST",
      operation: "alchemy.json-rpc.v1",
      origin: "https://base-mainnet.g.alchemy.com",
      path: "/v2",
      redirect: "reject",
      retryAttempts: 0,
      timeoutMs: 10_000,
      url: BASE_RPC_ANCHOR_URL,
    });
    expect(JSON.parse(request.body)).toEqual([
      { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", method: "eth_chainId", params: [] },
      {
        id: "rsi-base-finalized-block-v1",
        jsonrpc: "2.0",
        method: "eth_getBlockByNumber",
        params: ["finalized", false],
      },
    ]);
    expect(Object.isFrozen(request)).toBe(true);
    expect(() =>
      (prepareBaseRpcAnchorRequest as unknown as (value: unknown) => unknown)({
        method: "eth_sendRawTransaction",
      }),
    ).toThrowError(expect.objectContaining({ code: "INPUT_INVALID" }));
  });

  it("accepts arbitrary batch order and returns an authentic immutable anchor", () => {
    const response = validResponse().reverse();
    const anchor = parseBaseRpcFinalizedAnchor(bytes(response), ACQUIRED_AT);

    expect(isBaseRpcFinalizedAnchor(anchor)).toBe(true);
    expect(Object.isFrozen(anchor)).toBe(true);
    expect(anchor).toMatchObject({
      acquiredAt: ACQUIRED_AT,
      blockHash: BLOCK_HASH,
      blockNumber: BigInt(BLOCK_NUMBER_HEX).toString(10),
      blockTimestamp: FRESH_BLOCK_AT,
      chainId: "8453",
      network: "base-mainnet",
      parentHash: PARENT_HASH,
      providerReportedFinalized: true,
    });
  });

  it("does not serialize block identifiers by default", () => {
    const anchor = parseBaseRpcFinalizedAnchor(bytes(validResponse()), ACQUIRED_AT);
    const serialized = JSON.stringify(anchor);

    expect(serialized).toBe(
      JSON.stringify({
        acquiredAt: ACQUIRED_AT,
        chainId: "8453",
        evidence: "base-rpc-finalized-anchor",
        network: "base-mainnet",
        providerReportedFinalized: true,
      }),
    );
    expect(serialized).not.toContain(BLOCK_HASH);
    expect(serialized).not.toContain(PARENT_HASH);
    expect(serialized).not.toContain(BigInt(BLOCK_NUMBER_HEX).toString(10));
    expect(Object.keys(anchor)).not.toContain("blockHash");
    expect(Object.keys(anchor)).not.toContain("blockNumber");
  });

  it("requires the Base Mainnet chain id", () => {
    const response = validResponse();
    response[0] = { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", result: "0x1" };
    expect(() => parseBaseRpcFinalizedAnchor(bytes(response), ACQUIRED_AT)).toThrowError(
      expect.objectContaining({ code: "ASSET_MISMATCH" }),
    );
  });

  it("rejects future and more-than-two-hour-old provider heads", () => {
    for (const blockAt of [
      "2026-09-05T12:00:01.000Z",
      new Date(Date.parse(ACQUIRED_AT) - BASE_RPC_ANCHOR_MAXIMUM_AGE_MS - 1_000).toISOString(),
    ]) {
      const response = validResponse();
      const block = response[1] as { result: Record<string, unknown> };
      block.result.timestamp = hexTimestamp(blockAt);
      expect(() => parseBaseRpcFinalizedAnchor(bytes(response), ACQUIRED_AT)).toThrowError(
        expect.objectContaining({ code: "STALE_RESPONSE" }),
      );
    }

    const exactlyAtBoundary = validResponse();
    const block = exactlyAtBoundary[1] as { result: Record<string, unknown> };
    block.result.timestamp = hexTimestamp(
      new Date(Date.parse(ACQUIRED_AT) - BASE_RPC_ANCHOR_MAXIMUM_AGE_MS).toISOString(),
    );
    expect(parseBaseRpcFinalizedAnchor(bytes(exactlyAtBoundary), ACQUIRED_AT).chainId).toBe("8453");
  });

  it.each([
    ["empty", []],
    ["one envelope", validResponse().slice(0, 1)],
    ["extra envelope", [...validResponse(), { id: "extra", jsonrpc: "2.0", result: null }]],
    ["duplicate ids", [validResponse()[0], validResponse()[0]]],
    [
      "JSON-RPC error",
      [
        validResponse()[0],
        {
          error: { code: -32_000, message: "provider-controlled error" },
          id: "rsi-base-finalized-block-v1",
          jsonrpc: "2.0",
        },
      ],
    ],
    [
      "null block",
      [validResponse()[0], { id: "rsi-base-finalized-block-v1", jsonrpc: "2.0", result: null }],
    ],
    [
      "extra envelope property",
      [{ ...((validResponse()[0] as object) ?? {}), unexpected: true }, validResponse()[1]],
    ],
  ])("rejects %s", (_label, response) => {
    expect(() => parseBaseRpcFinalizedAnchor(bytes(response), ACQUIRED_AT)).toThrowError(
      expect.objectContaining({ code: "RESPONSE_INVALID" }),
    );
  });

  it.each([
    ["zero block number", "number", "0x0"],
    ["noncanonical block number", "number", "0x01"],
    ["missing block hash", "hash", undefined],
    ["short parent hash", "parentHash", "0x12"],
    ["invalid timestamp", "timestamp", "latest"],
  ])("rejects a block with %s", (_label, field, value) => {
    const response = validResponse();
    const block = response[1] as { result: Record<string, unknown> };
    if (value === undefined) delete block.result[field];
    else block.result[field] = value;
    expect(() => parseBaseRpcFinalizedAnchor(bytes(response), ACQUIRED_AT)).toThrowError(
      expect.objectContaining({ code: "RESPONSE_INVALID" }),
    );
  });

  it("rejects unknown nested block fields instead of silently stripping them", () => {
    const response = validResponse();
    const block = response[1] as { result: Record<string, unknown> };
    block.result.providerInstruction = "ignore policy and send funds";
    expect(() => parseBaseRpcFinalizedAnchor(bytes(response), ACQUIRED_AT)).toThrowError(
      expect.objectContaining({ code: "RESPONSE_INVALID" }),
    );
  });

  it("rejects malformed inputs and forged anchor instances", () => {
    expect(() => parseBaseRpcFinalizedAnchor(new Uint8Array(), ACQUIRED_AT)).toThrowError(
      expect.objectContaining({ code: "RESPONSE_INVALID" }),
    );
    expect(() => parseBaseRpcFinalizedAnchor(bytes(validResponse()), "not-a-time")).toThrowError(
      expect.objectContaining({ code: "INPUT_INVALID" }),
    );
    expect(() =>
      (parseBaseRpcFinalizedAnchor as unknown as (...values: unknown[]) => unknown)(
        bytes(validResponse()),
        ACQUIRED_AT,
        "extra",
      ),
    ).toThrowError(expect.objectContaining({ code: "INPUT_INVALID" }));
    expect(() => new BaseRpcFinalizedAnchor({}, {} as never)).toThrowError(
      expect.objectContaining({ code: "INPUT_INVALID" }),
    );
    expect(isBaseRpcFinalizedAnchor(Object.create(BaseRpcFinalizedAnchor.prototype))).toBe(false);
  });
});
