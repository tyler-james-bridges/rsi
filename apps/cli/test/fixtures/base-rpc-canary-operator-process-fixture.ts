import { Buffer } from "node:buffer";

import { createDarwinBaseRpcKeychainForTesting } from "@rsi/credential-host/base-rpc-testing";
import { createDarwinOneShotClaimHostForTesting } from "@rsi/credential-host/one-shot-claim-testing";

import { startBaseRpcCanaryOperatorForTesting } from "../../src/base-rpc-canary-operator-host.testing.js";

const [runtimePath] = process.argv.slice(2);
if (runtimePath === undefined) throw new TypeError("fixture runtime path is required");

const body =
  '[{"id":"rsi-base-chain-id-v1","jsonrpc":"2.0","method":"eth_chainId","params":[]},{"id":"rsi-base-finalized-block-v1","jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}]';
const services = Object.freeze([
  "dev.rsi.canary.alchemy-base-read",
  "dev.rsi.canary.base-rpc-operations-state",
  "dev.rsi.canary.base-rpc-capture-registry",
  "dev.rsi.canary.base-rpc-vault-wrapping",
] as const);
const values = Object.freeze([
  "offline-process-alchemy-api-key",
  Buffer.alloc(32, 0x81).toString("base64url"),
  Buffer.alloc(32, 0x82).toString("base64url"),
  Buffer.alloc(32, 0x83).toString("base64url"),
] as const);

let credentialCommands = 0;
let credentialValueReads = 0;
let apiKeyValueReads = 0;
const credentialHost = createDarwinBaseRpcKeychainForTesting({
  platform: "darwin",
  executor: async (request) => {
    credentialCommands += 1;
    const reveal = request.args.at(-1) === "-w";
    if (reveal) credentialValueReads += 1;
    const service = request.args[4];
    if (reveal && service === services[0]) apiKeyValueReads += 1;
    const index = services.indexOf(service as (typeof services)[number]);
    return {
      exitCode: index < 0 ? 44 : 0,
      stdout: new TextEncoder().encode(reveal ? `${values[index]!}\n` : "present\n"),
      stderr: new Uint8Array(),
      timedOut: false,
    };
  },
});

let markerPresent = false;
let claimCommands = 0;
let claimStatusCommands = 0;
const claimHost = createDarwinOneShotClaimHostForTesting("baseRpc", {
  executor: async (request) => {
    const claiming = request.args[0] === "add-generic-password";
    if (claiming) claimCommands += 1;
    else claimStatusCommands += 1;
    const exitCode = claiming ? (markerPresent ? 45 : 0) : markerPresent ? 0 : 44;
    if (claiming && exitCode === 0) markerPresent = true;
    return {
      exitCode,
      stdout: new Uint8Array(),
      stderr: new Uint8Array(),
      timedOut: false,
    };
  },
  platform: "darwin",
});

function validResponse(): unknown[] {
  const root = `0x${"33".repeat(32)}`;
  const timestamp = Math.floor((Date.now() - 30 * 60 * 1_000) / 1_000).toString(16);
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
        hash: `0x${"11".repeat(32)}`,
        logsBloom: `0x${"00".repeat(256)}`,
        miner: `0x${"44".repeat(20)}`,
        mixHash: root,
        nonce: "0x0000000000000000",
        number: "0x1234abcd",
        parentBeaconBlockRoot: root,
        parentHash: `0x${"22".repeat(32)}`,
        receiptsRoot: root,
        requestsHash: root,
        sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        size: "0x200",
        stateRoot: root,
        timestamp: `0x${timestamp}`,
        totalDifficulty: "0x0",
        transactions: [],
        transactionsRoot: root,
        uncles: [],
        withdrawals: [],
        withdrawalsRoot: root,
      },
    },
  ];
}

let baseRpcRequests = 0;
globalThis.fetch = async (request): Promise<Response> => {
  const value = request instanceof Request ? request : new Request(request);
  if (
    value.url !== "https://base-mainnet.g.alchemy.com/v2" ||
    value.method !== "POST" ||
    value.redirect !== "error" ||
    value.credentials !== "omit" ||
    value.headers.get("authorization") !== `Bearer ${values[0]}` ||
    value.headers.get("accept-encoding") !== "identity" ||
    (await value.text()) !== body
  ) {
    throw new Error("unexpected external destination or request shape");
  }
  baseRpcRequests += 1;
  return new Response(JSON.stringify(validResponse()), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
};

const operator = await startBaseRpcCanaryOperatorForTesting({
  claimHost,
  credentialHost,
  databasePath: runtimePath,
  port: 0,
});
console.log(
  JSON.stringify({
    apiKeyValueReads,
    baseRpcRequests,
    claimCommands,
    claimStatusCommands,
    credentialCommands,
    credentialValueReads,
    executionEnabled: false,
    financialAuthority: false,
    mode: "stage1-base-rpc-read-canary-test-fixture",
    origin: operator.origin,
    paymentCapability: false,
    runtimeMode: operator.runtime.getSnapshot().mode,
  }),
);

let closing = false;
const close = (): void => {
  if (closing) return;
  closing = true;
  void operator
    .close()
    .then(() =>
      console.log(
        JSON.stringify({
          apiKeyValueReads,
          baseRpcRequests,
          claimCommands,
          claimStatusCommands,
          closed: true,
          credentialCommands,
          credentialValueReads,
        }),
      ),
    )
    .catch(() => {
      process.exitCode = 1;
    });
};
process.once("SIGINT", close);
process.once("SIGTERM", close);
