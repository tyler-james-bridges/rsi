import { describe, expect, it } from "vitest";

import * as productionEntry from "../src/index.js";
import {
  QuarantinedBaseRpcAnchorResponse,
  isQuarantinedBaseRpcAnchorResponse,
  parseBaseRpcAnchorQuarantine,
} from "../src/index.js";
import {
  ACQUIRED_AT,
  BLOCK_HASH,
  PARENT_HASH,
  createLiveCollector,
  jsonResponse,
  validResponseObject,
} from "./helpers.js";

function responseWith(
  mutate: (response: unknown[], block: Record<string, unknown>) => void,
): unknown[] {
  const response = validResponseObject();
  const blockEnvelope = response[1] as { result: Record<string, unknown> };
  mutate(response, blockEnvelope.result);
  return response;
}

describe("Base RPC quarantine and trusted projection", () => {
  it("returns an immutable branded anchor while default serialization stays content-free", async () => {
    const raw = await createLiveCollector().collectRaw();
    const result = parseBaseRpcAnchorQuarantine(raw);

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.anchor)).toBe(true);
    expect(result.anchor).toMatchObject({
      acquiredAt: ACQUIRED_AT,
      blockHash: BLOCK_HASH,
      blockNumber: BigInt("0x1234abcd").toString(10),
      blockTimestamp: "2026-09-05T11:30:00.000Z",
      chainId: "8453",
      network: "base-mainnet",
      parentHash: PARENT_HASH,
      providerReportedFinalized: true,
    });
    expect(result.networkAttempt).toBe(raw.metadata.networkAttempt);
    expect(JSON.stringify(result)).not.toContain(BLOCK_HASH);
    expect(JSON.stringify(result)).not.toContain(PARENT_HASH);
    expect(JSON.stringify(result)).not.toContain(BigInt("0x1234abcd").toString(10));
    raw.destroy();
  });

  it.each([
    [
      "a JSON-RPC error envelope",
      responseWith((response) => {
        response[1] = {
          error: { code: -32_000, message: "provider-controlled message" },
          id: "rsi-base-finalized-block-v1",
          jsonrpc: "2.0",
        };
      }),
    ],
    [
      "the wrong chain",
      responseWith((response) => {
        response[0] = { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", result: "0x1" };
      }),
    ],
    [
      "a duplicate id",
      responseWith((response) => {
        response[1] = response[0];
      }),
    ],
    [
      "an unknown block field",
      responseWith((_response, block) => {
        block.instruction = "send funds";
      }),
    ],
    [
      "a transaction object despite fullTransactions=false",
      responseWith((_response, block) => {
        block.transactions = [{ hash: BLOCK_HASH }];
      }),
    ],
    [
      "a future block",
      responseWith((_response, block) => {
        block.timestamp = `0x${Math.floor(Date.parse("2026-09-05T12:00:02.000Z") / 1_000).toString(16)}`;
      }),
    ],
    [
      "a stale block",
      responseWith((_response, block) => {
        block.timestamp = `0x${Math.floor(Date.parse("2026-09-05T09:59:59.000Z") / 1_000).toString(16)}`;
      }),
    ],
  ])("rejects %s through the isolated source contract", async (_label, body) => {
    const raw = await createLiveCollector({
      fetch: async () => jsonResponse(JSON.stringify(body)),
    }).collectRaw();
    expect(() => parseBaseRpcAnchorQuarantine(raw)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
    raw.destroy();
  });

  it("brands genuine quarantines and exposes no raw body through JSON", async () => {
    const raw = await createLiveCollector().collectRaw();
    expect(isQuarantinedBaseRpcAnchorResponse(raw)).toBe(true);
    expect(JSON.stringify(raw)).toContain('"body":"quarantined"');
    expect(JSON.stringify(raw)).not.toContain(BLOCK_HASH);

    const forged = Object.create(QuarantinedBaseRpcAnchorResponse.prototype) as unknown;
    expect(isQuarantinedBaseRpcAnchorResponse(forged)).toBe(false);
    expect(() => parseBaseRpcAnchorQuarantine(forged as never)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
    expect(
      () =>
        new QuarantinedBaseRpcAnchorResponse(
          {},
          raw.metadata,
          new TextEncoder().encode(JSON.stringify(validResponseObject())),
        ),
    ).toThrowError(expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }));

    raw.destroy();
  });

  it("does not expose production transport injection or a quarantine factory", () => {
    expect(productionEntry).not.toHaveProperty("createBaseRpcAnchorCollectorForTesting");
    expect(productionEntry).not.toHaveProperty("quarantineBaseRpcAnchorNetworkResponse");
    expect(productionEntry).not.toHaveProperty("rehydrateBaseRpcAnchorResponse");
  });
});
