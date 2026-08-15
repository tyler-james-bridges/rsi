import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  SourceContractError,
  corroborateOpenSeaListing,
  parseCanonicalAssetFixture,
  parseFinalizedBlockFixture,
  parseOpenSeaRestFixture,
  parseOpenSeaStreamFixture,
  prepareCanonicalAssetRequest,
  prepareFinalizedBlockRequest,
  prepareOpenSeaRestRequest,
  prepareOpenSeaStreamSubscription,
} from "../src/index.js";

const CONTRACT = `0x${"11".repeat(20)}`;
const PROTOCOL = `0x${"22".repeat(20)}`;
const ORDER = `0x${"33".repeat(32)}`;
const CURRENCY = `0x${"44".repeat(20)}`;
const OWNER = `0x${"55".repeat(20)}`;
const BLOCK = `0x${"66".repeat(32)}`;
const PARENT = `0x${"77".repeat(32)}`;
const ACQUIRED = "2026-08-15T12:00:00.000Z";
const BLOCK_TIME = "2026-08-15T11:40:00.000Z";
const RUNTIME_CODE = "0x60006000";
const IMPLEMENTATION_CODE = "0x60016001";

describe("OpenSea offline contracts", () => {
  it("prepares only fixed read-only descriptors without credential values", () => {
    const rest = prepareOpenSeaRestRequest(restExpected());
    expect(rest).toMatchObject({
      credentialHeader: "x-api-key",
      maximumResponseBytes: 2_097_152,
      method: "GET",
      operation: "opensea.rest.v1",
      origin: "https://api.opensea.io",
      redirect: "reject",
      timeoutMs: 10_000,
    });
    expect(rest.path).toBe(`/api/v2/orders/chain/base/protocol/${PROTOCOL}/${ORDER}`);
    const stream = prepareOpenSeaStreamSubscription({ collectionSlug: "fictional-collection" });
    expect(stream).toMatchObject({
      credentialPlacement: "query-token",
      maximumEventBytes: 262_144,
      operation: "opensea.stream.v1",
      reconnectAttempts: 1,
      topic: "collection:fictional-collection",
    });
    const serialized = JSON.stringify([rest, stream]);
    for (const forbidden of ["credentialValue", "?token=", "YOUR_API_KEY", "bearer ", "secret="]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("binds a fresh normalized REST order and provisional Stream trigger", () => {
    const rest = parseOpenSeaRestFixture(jsonBytes(restFixture()), restExpected(), ACQUIRED);
    const stream = parseOpenSeaStreamFixture(
      jsonBytes(streamFixture()),
      { collectionSlug: "fictional-collection" },
      ACQUIRED,
    );
    expect(rest).toMatchObject({
      asset: { chain: "base", contract: CONTRACT, tokenId: "7" },
      orderHash: ORDER,
      protocolAddress: PROTOCOL,
      validUntil: "2026-08-15T12:02:00.000Z",
    });
    expect(stream).toMatchObject({
      asset: { chain: "base", contract: CONTRACT, tokenId: "7" },
      collectionSlug: "fictional-collection",
      eventObservedAt: "2026-08-15T11:59:30.000Z",
    });
    const corroborated = corroborateOpenSeaListing(stream, rest, ACQUIRED);
    expect(corroborated.collectionSlug).toBe("fictional-collection");
    expect(corroborated.orderHash).toBe(ORDER);
    for (const forbidden of ["metadata", "image", "permalink", "maker", "signature", "https://"]) {
      expect(JSON.stringify(corroborated)).not.toContain(forbidden);
    }
    expect(() =>
      corroborateOpenSeaListing(
        JSON.parse(JSON.stringify(stream)),
        JSON.parse(JSON.stringify(rest)),
        ACQUIRED,
      ),
    ).toThrowError(SourceContractError);
  });

  it("rejects stale, substituted, extra-field, Buffer, proxy, and accessor inputs", () => {
    const substituted = restFixture();
    substituted.asset.contract = `0x${"99".repeat(20)}`;
    expect(() =>
      parseOpenSeaRestFixture(jsonBytes(substituted), restExpected(), ACQUIRED),
    ).toThrowError(SourceContractError);
    const stale = streamFixture();
    stale.payload.event_timestamp = "2026-08-15T11:57:59Z";
    expect(() =>
      parseOpenSeaStreamFixture(
        jsonBytes(stale),
        { collectionSlug: "fictional-collection" },
        ACQUIRED,
      ),
    ).toThrowError(SourceContractError);
    const extra = streamFixture() as Record<string, unknown>;
    extra.metadata = { name: "must remain quarantined" };
    expect(() =>
      parseOpenSeaStreamFixture(
        jsonBytes(extra),
        { collectionSlug: "fictional-collection" },
        ACQUIRED,
      ),
    ).toThrowError(SourceContractError);
    expect(() =>
      parseOpenSeaRestFixture(Buffer.from(JSON.stringify(restFixture())), restExpected(), ACQUIRED),
    ).toThrowError(SourceContractError);
    expect(() => prepareOpenSeaRestRequest(new Proxy(restExpected(), {}))).toThrowError(
      SourceContractError,
    );
    let called = false;
    const accessor = { ...restExpected() } as Record<string, unknown>;
    Object.defineProperty(accessor, "orderHash", {
      enumerable: true,
      get() {
        called = true;
        return ORDER;
      },
    });
    expect(() => prepareOpenSeaRestRequest(accessor)).toThrowError(SourceContractError);
    expect(called).toBe(false);
  });
});

describe("finalized canonical-chain contracts", () => {
  it.each([
    ["base", "0x2105", "8453", "base-mainnet.g.alchemy.com"],
    ["robinhood", "0x1237", "4663", "robinhood-mainnet.g.alchemy.com"],
  ] as const)(
    "anchors %s to its expected chain and finalized block",
    (network, chainHex, chainId, host) => {
      const request = prepareFinalizedBlockRequest({ network });
      expect(request.providerHost).toBe(host);
      expect(request.credentialPlacement).toBe("path-segment");
      const body = JSON.parse(request.body) as unknown[];
      expect(body).toEqual([
        { id: "rsi-chain-id-v1", jsonrpc: "2.0", method: "eth_chainId", params: [] },
        {
          id: "rsi-anchor-v1",
          jsonrpc: "2.0",
          method: "eth_getBlockByNumber",
          params: ["finalized", false],
        },
      ]);
      const anchor = parseFinalizedBlockFixture(
        jsonBytes(anchorFixture(chainHex)),
        { network },
        ACQUIRED,
      );
      expect(anchor).toMatchObject({ blockHash: BLOCK, blockNumber: "16", chainId, network });
    },
  );

  it("prepares and verifies a block-pinned ERC-721 identity read", () => {
    const anchor = parseFinalizedBlockFixture(
      jsonBytes(anchorFixture("0x2105")),
      { network: "base" },
      ACQUIRED,
    );
    const expected = {
      anchor,
      asset: { contract: CONTRACT, tokenId: "7" },
      expectedOwner: null,
      expectedRuntimeCodeSha256: bytecodeSha256(RUNTIME_CODE),
      proxy: { kind: "eip1967-slot-empty" },
      standard: "ERC721",
    } as const;
    const request = prepareCanonicalAssetRequest(expected);
    const bodyText = request.body;
    expect(bodyText).toContain('"eth_getCode"');
    expect(bodyText).toContain('"eth_call"');
    expect(bodyText).toContain('"eth_getStorageAt"');
    expect(bodyText).toContain('"0x10"');
    expect(bodyText).toContain(`01ffc9a780ac58cd${"0".repeat(56)}`);
    expect(bodyText).not.toMatch(/tokenURI|metadata|image|sendTransaction|private/iu);

    const evidence = parseCanonicalAssetFixture(jsonBytes(assetFixture()), expected);
    expect(evidence).toMatchObject({
      asset: { contract: CONTRACT, tokenId: "7" },
      blockHash: BLOCK,
      codePresent: true,
      observedOwner: OWNER,
      proxy: {
        implementation: null,
        implementationCodeSha256: null,
        kind: "eip1967-slot-empty",
      },
      runtimeCodeSha256: bytecodeSha256(RUNTIME_CODE),
      standard: "ERC721",
    });
    expect(() => prepareCanonicalAssetRequest({ ...expected, anchor: { ...anchor } })).toThrowError(
      SourceContractError,
    );
  });

  it("supports an explicitly owner-scoped ERC-1155 balance read", () => {
    const anchor = parseFinalizedBlockFixture(
      jsonBytes(anchorFixture("0x1237")),
      { network: "robinhood" },
      ACQUIRED,
    );
    const expected = {
      anchor,
      asset: { contract: CONTRACT, tokenId: "9" },
      expectedOwner: OWNER,
      expectedRuntimeCodeSha256: bytecodeSha256(RUNTIME_CODE),
      proxy: { kind: "eip1967-slot-empty" },
      standard: "ERC1155",
    } as const;
    const request = prepareCanonicalAssetRequest(expected);
    expect(request.body).toContain("00fdd58e");
    const fixture = assetFixture();
    fixture[3]!.result = `0x${"0".repeat(63)}2`;
    const evidence = parseCanonicalAssetFixture(jsonBytes(fixture), expected);
    expect(evidence.observedOwner).toBe(OWNER);
    expect(evidence.standard).toBe("ERC1155");
  });

  it("binds an EIP-1967 proxy to the explicitly approved implementation", () => {
    const implementation = `0x${"88".repeat(20)}`;
    const anchor = parseFinalizedBlockFixture(
      jsonBytes(anchorFixture("0x2105")),
      { network: "base" },
      ACQUIRED,
    );
    const expected = {
      anchor,
      asset: { contract: CONTRACT, tokenId: "7" },
      expectedOwner: null,
      expectedRuntimeCodeSha256: bytecodeSha256(RUNTIME_CODE),
      proxy: {
        expectedImplementation: implementation,
        expectedImplementationCodeSha256: bytecodeSha256(IMPLEMENTATION_CODE),
        kind: "eip1967",
      },
      standard: "ERC721",
    } as const;
    const request = prepareCanonicalAssetRequest(expected);
    expect(request.body).toContain(implementation);
    const fixture = assetFixture();
    fixture[4]!.result = `0x${"0".repeat(24)}${implementation.slice(2)}`;
    fixture.push({
      id: "rsi-asset-implementation-code-v1",
      jsonrpc: "2.0",
      result: IMPLEMENTATION_CODE,
    });
    expect(parseCanonicalAssetFixture(jsonBytes(fixture), expected).proxy).toEqual({
      implementation,
      implementationCodeSha256: bytecodeSha256(IMPLEMENTATION_CODE),
      kind: "eip1967",
    });
    fixture[4]!.result = `0x${"0".repeat(24)}${"99".repeat(20)}`;
    expect(() => parseCanonicalAssetFixture(jsonBytes(fixture), expected)).toThrowError(
      SourceContractError,
    );
  });

  it("fails closed for a wrong chain, moved block, missing code, or false interface", () => {
    expect(() =>
      parseFinalizedBlockFixture(jsonBytes(anchorFixture("0x1237")), { network: "base" }, ACQUIRED),
    ).toThrowError(SourceContractError);
    const anchor = parseFinalizedBlockFixture(
      jsonBytes(anchorFixture("0x2105")),
      { network: "base" },
      ACQUIRED,
    );
    const expected = {
      anchor,
      asset: { contract: CONTRACT, tokenId: "7" },
      expectedOwner: null,
      expectedRuntimeCodeSha256: bytecodeSha256(RUNTIME_CODE),
      proxy: { kind: "eip1967-slot-empty" },
      standard: "ERC721",
    } as const;
    const moved = assetFixture();
    if (typeof moved[0]!.result !== "object") throw new Error("fixture");
    moved[0]!.result.hash = `0x${"99".repeat(32)}`;
    expect(() => parseCanonicalAssetFixture(jsonBytes(moved), expected)).toThrowError(
      SourceContractError,
    );
    const noCode = assetFixture();
    noCode[1]!.result = "0x";
    expect(() => parseCanonicalAssetFixture(jsonBytes(noCode), expected)).toThrowError(
      SourceContractError,
    );
    const unsupported = assetFixture();
    unsupported[2]!.result = `0x${"0".repeat(64)}`;
    expect(() => parseCanonicalAssetFixture(jsonBytes(unsupported), expected)).toThrowError(
      SourceContractError,
    );
  });
});

function restExpected() {
  return {
    asset: { chain: "base" as const, contract: CONTRACT, tokenId: "7" },
    orderHash: ORDER,
    protocolAddress: PROTOCOL,
  };
}

function restFixture() {
  return {
    asset: { contract: CONTRACT, identifier: "7" },
    chain: "base" as const,
    order_created_at: Date.parse("2026-08-15T11:59:00.000Z") / 1_000,
    order_hash: ORDER,
    price: { currencyAddress: CURRENCY, decimals: 18, value: "1000000000000000000" },
    protocol_address: PROTOCOL,
    protocol_data: {
      parameters: {
        endTime: String(Date.parse("2026-08-15T13:00:00.000Z") / 1_000),
        startTime: String(Date.parse("2026-08-15T11:58:00.000Z") / 1_000),
      },
    },
    remaining_quantity: 1,
    status: "ACTIVE" as const,
  };
}

function streamFixture() {
  return {
    event_type: "item_listed" as const,
    payload: {
      base_price: "1000000000000000000",
      collection: { slug: "fictional-collection" },
      event_timestamp: "2026-08-15T11:59:30Z",
      item: { chain: { name: "base" as const }, nft_id: `base/${CONTRACT}/7` },
      payment_token: { address: CURRENCY, decimals: 18, symbol: "ETH" },
    },
    sent_at: "2026-08-15T11:59:31Z",
  };
}

function anchorFixture(chainId: string) {
  return [
    {
      id: "rsi-anchor-v1",
      jsonrpc: "2.0",
      result: {
        extraData: "0x",
        hash: BLOCK,
        number: "0x10",
        parentHash: PARENT,
        timestamp: `0x${Math.floor(Date.parse(BLOCK_TIME) / 1_000).toString(16)}`,
      },
    },
    { id: "rsi-chain-id-v1", jsonrpc: "2.0", result: chainId },
  ];
}

type AssetFixture = Array<{
  id: string;
  jsonrpc: "2.0";
  result: string | { hash: string; number: string; parentHash: string; timestamp: string };
}>;

function assetFixture(): AssetFixture {
  return [
    {
      id: "rsi-asset-block-v1",
      jsonrpc: "2.0",
      result: {
        hash: BLOCK,
        number: "0x10",
        parentHash: PARENT,
        timestamp: `0x${Math.floor(Date.parse(BLOCK_TIME) / 1_000).toString(16)}`,
      },
    },
    { id: "rsi-asset-code-v1", jsonrpc: "2.0", result: RUNTIME_CODE },
    { id: "rsi-asset-interface-v1", jsonrpc: "2.0", result: `0x${"0".repeat(63)}1` },
    {
      id: "rsi-asset-owner-v1",
      jsonrpc: "2.0",
      result: `0x${"0".repeat(24)}${OWNER.slice(2)}`,
    },
    { id: "rsi-asset-proxy-slot-v1", jsonrpc: "2.0", result: `0x${"0".repeat(64)}` },
  ];
}

function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function bytecodeSha256(value: string): string {
  return createHash("sha256")
    .update(Buffer.from(value.slice(2), "hex"))
    .digest("hex");
}
