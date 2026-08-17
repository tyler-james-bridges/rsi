import { createHash } from "node:crypto";

import { z } from "zod";

import {
  AtomicSchema,
  Bytes32Schema,
  EvmAddressSchema,
  HexQuantitySchema,
  TimestampSchema,
  deepFreeze,
  encodeCanonicalJson,
  fail,
  parseJsonBytes,
  parsePlain,
} from "./common.js";

export const CANONICAL_CHAIN_CONTRACT_REVIEW_DATE = "2026-08-15";
export const CANONICAL_CHAIN_MAXIMUM_BYTES = 1_024 * 1_024;

const NetworkSchema = z.enum(["base", "robinhood"]);
const StandardSchema = z.enum(["ERC721", "ERC1155"]);
const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const ProxySchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("eip1967-slot-empty") }),
  z.strictObject({
    expectedImplementation: EvmAddressSchema,
    expectedImplementationCodeSha256: Sha256Schema,
    kind: z.literal("eip1967"),
  }),
]);
const AnchorRequestInputSchema = z.strictObject({ network: NetworkSchema });
const AssetSchema = z.strictObject({ contract: EvmAddressSchema, tokenId: AtomicSchema });
const AssetRequestInputSchema = z
  .strictObject({
    anchor: z.strictObject({
      acquiredAt: TimestampSchema,
      blockHash: Bytes32Schema,
      blockNumber: AtomicSchema,
      blockTimestamp: TimestampSchema,
      chainId: z.union([z.literal("8453"), z.literal("4663")]),
      network: NetworkSchema,
    }),
    asset: AssetSchema,
    expectedOwner: EvmAddressSchema.nullable(),
    expectedRuntimeCodeSha256: Sha256Schema,
    proxy: ProxySchema,
    standard: StandardSchema,
  })
  .superRefine((value, context) => {
    if ((value.standard === "ERC1155") !== (value.expectedOwner !== null)) {
      context.addIssue({ code: "custom", message: "ERC1155 requires one expected owner" });
    }
    if (
      (value.anchor.network === "base" && value.anchor.chainId !== "8453") ||
      (value.anchor.network === "robinhood" && value.anchor.chainId !== "4663") ||
      Date.parse(value.anchor.blockTimestamp) > Date.parse(value.anchor.acquiredAt)
    ) {
      context.addIssue({ code: "custom", message: "anchor binding is inconsistent" });
    }
  });

const BlockResultSchema = z.object({
  hash: Bytes32Schema,
  number: HexQuantitySchema,
  parentHash: Bytes32Schema,
  timestamp: HexQuantitySchema,
});
const AnchorResponseSchema = z
  .array(
    z.discriminatedUnion("id", [
      z.strictObject({
        id: z.literal("rsi-chain-id-v1"),
        jsonrpc: z.literal("2.0"),
        result: HexQuantitySchema,
      }),
      z.strictObject({
        id: z.literal("rsi-anchor-v1"),
        jsonrpc: z.literal("2.0"),
        result: BlockResultSchema,
      }),
    ]),
  )
  .length(2);
const BatchResultSchema = z
  .array(
    z.discriminatedUnion("id", [
      z.strictObject({
        id: z.literal("rsi-asset-block-v1"),
        jsonrpc: z.literal("2.0"),
        result: BlockResultSchema,
      }),
      z.strictObject({
        id: z.literal("rsi-asset-code-v1"),
        jsonrpc: z.literal("2.0"),
        result: z.string().max(CANONICAL_CHAIN_MAXIMUM_BYTES),
      }),
      z.strictObject({
        id: z.literal("rsi-asset-interface-v1"),
        jsonrpc: z.literal("2.0"),
        result: z.string().max(66),
      }),
      z.strictObject({
        id: z.literal("rsi-asset-owner-v1"),
        jsonrpc: z.literal("2.0"),
        result: z.string().max(66),
      }),
      z.strictObject({
        id: z.literal("rsi-asset-proxy-slot-v1"),
        jsonrpc: z.literal("2.0"),
        result: z.string().max(66),
      }),
      z.strictObject({
        id: z.literal("rsi-asset-implementation-code-v1"),
        jsonrpc: z.literal("2.0"),
        result: z.string().max(CANONICAL_CHAIN_MAXIMUM_BYTES),
      }),
    ]),
  )
  .min(5)
  .max(6);

const UINT256_MAX = (1n << 256n) - 1n;
const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const anchorInstances = new WeakSet<object>();
const assetEvidenceInstances = new WeakSet<object>();

export interface CanonicalBlockAnchorV1 {
  readonly acquiredAt: string;
  readonly blockHash: string;
  readonly blockNumber: string;
  readonly blockTimestamp: string;
  readonly chainId: "8453" | "4663";
  readonly network: "base" | "robinhood";
}

export interface CanonicalRpcRequestV1 {
  readonly archiveAccessRequired: true;
  readonly body: string;
  readonly contractReviewDate: typeof CANONICAL_CHAIN_CONTRACT_REVIEW_DATE;
  readonly credentialPlacement: "path-segment";
  readonly maximumResponseBytes: typeof CANONICAL_CHAIN_MAXIMUM_BYTES;
  readonly method: "POST";
  readonly operation: "alchemy.json-rpc.v1";
  readonly providerHost: "base-mainnet.g.alchemy.com" | "robinhood-mainnet.g.alchemy.com";
  readonly redirect: "reject";
  readonly timeoutMs: 10_000;
}

export interface CanonicalAssetEvidenceV1 extends CanonicalBlockAnchorV1 {
  readonly asset: Readonly<{ contract: string; tokenId: string }>;
  readonly codePresent: true;
  readonly observedOwner: string;
  readonly proxy: Readonly<
    | { kind: "eip1967-slot-empty"; implementation: null; implementationCodeSha256: null }
    | { kind: "eip1967"; implementation: string; implementationCodeSha256: string }
  >;
  readonly runtimeCodeSha256: string;
  readonly standard: "ERC721" | "ERC1155";
}

export function prepareFinalizedBlockRequest(value: unknown): Readonly<CanonicalRpcRequestV1> {
  const input = parsePlain(AnchorRequestInputSchema, value);
  return requestFor(
    input.network,
    encodeCanonicalJson([
      { id: "rsi-chain-id-v1", jsonrpc: "2.0", method: "eth_chainId", params: [] },
      {
        id: "rsi-anchor-v1",
        jsonrpc: "2.0",
        method: "eth_getBlockByNumber",
        params: ["finalized", false],
      },
    ]),
  );
}

export function parseFinalizedBlockFixture(
  bytes: unknown,
  expectedValue: unknown,
  acquiredAtValue: unknown,
): Readonly<CanonicalBlockAnchorV1> {
  const expected = parsePlain(AnchorRequestInputSchema, expectedValue);
  const acquiredAt = parsePlain(TimestampSchema, acquiredAtValue);
  const response = parseJsonBytes(AnchorResponseSchema, bytes, CANONICAL_CHAIN_MAXIMUM_BYTES);
  const chainEntries = response.filter((entry) => entry.id === "rsi-chain-id-v1");
  const blockEntries = response.filter((entry) => entry.id === "rsi-anchor-v1");
  if (chainEntries.length !== 1 || blockEntries.length !== 1) fail("RESPONSE_INVALID");
  const chainId = BigInt(chainEntries[0]!.result).toString(10);
  const expectedChainId: "8453" | "4663" = expected.network === "base" ? "8453" : "4663";
  if (chainId !== expectedChainId) fail("ASSET_MISMATCH");
  const block = blockEntries[0]!.result;
  const number = BigInt(block.number);
  const timestamp = BigInt(block.timestamp);
  if (number < 0n || number > UINT256_MAX) fail("RESPONSE_INVALID");
  const blockTimestamp = blockTimestampIso(timestamp);
  if (Date.parse(blockTimestamp) > Date.parse(acquiredAt)) fail("STALE_RESPONSE");
  const anchor = deepFreeze({
    acquiredAt,
    blockHash: block.hash.toLowerCase(),
    blockNumber: number.toString(10),
    blockTimestamp,
    chainId: expectedChainId,
    network: expected.network,
  });
  anchorInstances.add(anchor);
  return anchor;
}

export function prepareCanonicalAssetRequest(value: unknown): Readonly<CanonicalRpcRequestV1> {
  assertBrandedAnchor(value);
  const input = parsePlain(AssetRequestInputSchema, value);
  const blockTag = toHexQuantity(input.anchor.blockNumber);
  const interfaceId = input.standard === "ERC721" ? "80ac58cd" : "d9b67a26";
  const ownershipCall =
    input.standard === "ERC721"
      ? `0x6352211e${uint256Word(input.asset.tokenId)}`
      : `0x00fdd58e${addressWord(input.expectedOwner!)}${uint256Word(input.asset.tokenId)}`;
  const requests: Record<string, unknown>[] = [
    {
      id: "rsi-asset-block-v1",
      jsonrpc: "2.0",
      method: "eth_getBlockByNumber",
      params: [blockTag, false],
    },
    {
      id: "rsi-asset-code-v1",
      jsonrpc: "2.0",
      method: "eth_getCode",
      params: [input.asset.contract.toLowerCase(), blockTag],
    },
    {
      id: "rsi-asset-interface-v1",
      jsonrpc: "2.0",
      method: "eth_call",
      params: [
        {
          data: `0x01ffc9a7${interfaceId.padEnd(64, "0")}`,
          to: input.asset.contract.toLowerCase(),
        },
        blockTag,
      ],
    },
    {
      id: "rsi-asset-owner-v1",
      jsonrpc: "2.0",
      method: "eth_call",
      params: [{ data: ownershipCall, to: input.asset.contract.toLowerCase() }, blockTag],
    },
    {
      id: "rsi-asset-proxy-slot-v1",
      jsonrpc: "2.0",
      method: "eth_getStorageAt",
      params: [input.asset.contract.toLowerCase(), EIP1967_IMPLEMENTATION_SLOT, blockTag],
    },
  ];
  if (input.proxy.kind === "eip1967") {
    requests.push({
      id: "rsi-asset-implementation-code-v1",
      jsonrpc: "2.0",
      method: "eth_getCode",
      params: [input.proxy.expectedImplementation.toLowerCase(), blockTag],
    });
  }
  return requestFor(input.anchor.network, encodeCanonicalJson(requests));
}

export function parseCanonicalAssetFixture(
  bytes: unknown,
  expectedValue: unknown,
): Readonly<CanonicalAssetEvidenceV1> {
  assertBrandedAnchor(expectedValue);
  const expected = parsePlain(AssetRequestInputSchema, expectedValue);
  const response = parseJsonBytes(BatchResultSchema, bytes, CANONICAL_CHAIN_MAXIMUM_BYTES);
  const byId = new Map(response.map((entry) => [entry.id, entry] as const));
  const expectedResultCount = expected.proxy.kind === "eip1967" ? 6 : 5;
  if (byId.size !== expectedResultCount || response.length !== expectedResultCount) {
    fail("RESPONSE_INVALID");
  }
  const blockEntry = byId.get("rsi-asset-block-v1");
  const codeEntry = byId.get("rsi-asset-code-v1");
  const interfaceEntry = byId.get("rsi-asset-interface-v1");
  const ownerEntry = byId.get("rsi-asset-owner-v1");
  const proxySlotEntry = byId.get("rsi-asset-proxy-slot-v1");
  const implementationCodeEntry = byId.get("rsi-asset-implementation-code-v1");
  if (
    blockEntry?.id !== "rsi-asset-block-v1" ||
    codeEntry?.id !== "rsi-asset-code-v1" ||
    interfaceEntry?.id !== "rsi-asset-interface-v1" ||
    ownerEntry?.id !== "rsi-asset-owner-v1" ||
    proxySlotEntry?.id !== "rsi-asset-proxy-slot-v1" ||
    (expected.proxy.kind === "eip1967") !==
      (implementationCodeEntry?.id === "rsi-asset-implementation-code-v1")
  ) {
    fail("RESPONSE_INVALID");
  }
  const block = blockEntry.result;
  const blockTimestampSeconds = BigInt(block.timestamp);
  if (
    BigInt(block.number).toString(10) !== expected.anchor.blockNumber ||
    block.hash.toLowerCase() !== expected.anchor.blockHash.toLowerCase() ||
    blockTimestampIso(blockTimestampSeconds) !== expected.anchor.blockTimestamp
  ) {
    fail("ASSET_MISMATCH");
  }
  const code = codeEntry.result;
  const supported = interfaceEntry.result;
  const ownership = ownerEntry.result;
  if (!isBytecode(code) || !isTrueWord(supported)) {
    fail("UNSUPPORTED_SOURCE");
  }
  const runtimeCodeSha256 = sha256Bytecode(code);
  if (runtimeCodeSha256 !== expected.expectedRuntimeCodeSha256) fail("ASSET_MISMATCH");
  let observedOwner: string;
  if (expected.standard === "ERC721") {
    if (!/^0x0{24}[0-9a-fA-F]{40}$/.test(ownership)) fail("RESPONSE_INVALID");
    observedOwner = `0x${ownership.slice(-40)}`.toLowerCase();
    if (/^0x0{40}$/.test(observedOwner)) fail("RESPONSE_INVALID");
  } else {
    if (!/^0x[0-9a-fA-F]{64}$/.test(ownership) || BigInt(ownership) <= 0n) {
      fail("ASSET_MISMATCH");
    }
    observedOwner = expected.expectedOwner!.toLowerCase();
  }
  const proxySlot = proxySlotEntry.result;
  if (!/^0x[0-9a-fA-F]{64}$/.test(proxySlot)) fail("RESPONSE_INVALID");
  let proxy: CanonicalAssetEvidenceV1["proxy"];
  if (expected.proxy.kind === "eip1967-slot-empty") {
    if (!/^0x0{64}$/.test(proxySlot)) fail("ASSET_MISMATCH");
    proxy = {
      implementation: null,
      implementationCodeSha256: null,
      kind: "eip1967-slot-empty",
    };
  } else {
    if (!/^0x0{24}[0-9a-fA-F]{40}$/.test(proxySlot)) fail("RESPONSE_INVALID");
    if (implementationCodeEntry?.id !== "rsi-asset-implementation-code-v1") {
      fail("RESPONSE_INVALID");
    }
    const implementation = `0x${proxySlot.slice(-40)}`.toLowerCase();
    if (
      implementation !== expected.proxy.expectedImplementation.toLowerCase() ||
      /^0x0{40}$/.test(implementation) ||
      !isBytecode(implementationCodeEntry.result) ||
      sha256Bytecode(implementationCodeEntry.result) !==
        expected.proxy.expectedImplementationCodeSha256
    ) {
      fail("ASSET_MISMATCH");
    }
    proxy = {
      implementation,
      implementationCodeSha256: expected.proxy.expectedImplementationCodeSha256,
      kind: "eip1967",
    };
  }
  const evidence = deepFreeze({
    ...expected.anchor,
    asset: {
      contract: expected.asset.contract.toLowerCase(),
      tokenId: expected.asset.tokenId,
    },
    codePresent: true as const,
    observedOwner,
    proxy,
    runtimeCodeSha256,
    standard: expected.standard,
  });
  assetEvidenceInstances.add(evidence);
  return evidence;
}

export function isCanonicalAssetEvidence(
  value: unknown,
): value is Readonly<CanonicalAssetEvidenceV1> {
  return typeof value === "object" && value !== null && assetEvidenceInstances.has(value);
}

function requestFor(
  network: "base" | "robinhood",
  bodyBytes: Uint8Array,
): Readonly<CanonicalRpcRequestV1> {
  const body = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
  bodyBytes.fill(0);
  return Object.freeze({
    archiveAccessRequired: true,
    body,
    contractReviewDate: CANONICAL_CHAIN_CONTRACT_REVIEW_DATE,
    credentialPlacement: "path-segment",
    maximumResponseBytes: CANONICAL_CHAIN_MAXIMUM_BYTES,
    method: "POST",
    operation: "alchemy.json-rpc.v1",
    providerHost:
      network === "base" ? "base-mainnet.g.alchemy.com" : "robinhood-mainnet.g.alchemy.com",
    redirect: "reject",
    timeoutMs: 10_000,
  });
}

function toHexQuantity(value: string): string {
  return `0x${BigInt(value).toString(16)}`;
}

function uint256Word(value: string): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

function addressWord(value: string): string {
  return value.slice(2).toLowerCase().padStart(64, "0");
}

function isTrueWord(value: string): boolean {
  return /^0x0{63}1$/i.test(value);
}

function isBytecode(value: string): boolean {
  return /^0x[0-9a-fA-F]+$/.test(value) && value !== "0x" && (value.length - 2) % 2 === 0;
}

function sha256Bytecode(value: string): string {
  return createHash("sha256")
    .update(Buffer.from(value.slice(2), "hex"))
    .digest("hex");
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

function assertBrandedAnchor(value: unknown): void {
  if (typeof value !== "object" || value === null) fail("INPUT_INVALID");
  const descriptor = Object.getOwnPropertyDescriptor(value, "anchor");
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    typeof descriptor.value !== "object" ||
    descriptor.value === null ||
    !anchorInstances.has(descriptor.value)
  ) {
    fail("INPUT_INVALID");
  }
}
