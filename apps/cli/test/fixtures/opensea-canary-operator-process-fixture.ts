import { Buffer } from "node:buffer";

import { createDarwinOpenSeaTrendingKeychainForTesting } from "@rsi/credential-host/opensea-trending-testing";

import { startOpenSeaCanaryOperatorForTesting } from "../../src/opensea-canary-operator-host.testing.js";

const [runtimePath] = process.argv.slice(2);
if (runtimePath === undefined) throw new TypeError("fixture runtime path is required");

const services = Object.freeze([
  "dev.rsi.canary.opensea-read",
  "dev.rsi.canary.operations-state",
  "dev.rsi.canary.capture-registry",
  "dev.rsi.canary.vault-wrapping",
] as const);
const values = Object.freeze([
  "offline-process-opensea-api-key",
  Buffer.alloc(32, 0x61).toString("base64url"),
  Buffer.alloc(32, 0x62).toString("base64url"),
  Buffer.alloc(32, 0x63).toString("base64url"),
] as const);

let credentialCommands = 0;
let credentialValueReads = 0;
let apiKeyValueReads = 0;
const credentialHost = createDarwinOpenSeaTrendingKeychainForTesting({
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

let openSeaRequests = 0;
globalThis.fetch = async (request): Promise<Response> => {
  const value = request instanceof Request ? request : new Request(request);
  const url = new URL(value.url);
  if (
    url.origin !== "https://api.opensea.io" ||
    url.pathname !== "/api/v2/collections/trending" ||
    url.search !== "?timeframe=one_day&chains=base&limit=10" ||
    value.method !== "GET"
  ) {
    throw new Error("unexpected external destination");
  }
  openSeaRequests += 1;
  return new Response(
    JSON.stringify({
      collections: [
        {
          collection: "untrusted-process-collection",
          collection_offers_enabled: true,
          contracts: [{ address: `0x${"d".repeat(40)}`, chain: "base" }],
          description: "UNTRUSTED PROCESS OPENSEA CONTENT",
          is_disabled: false,
          is_nsfw: false,
          name: "Untrusted process collection",
          opensea_url: "https://opensea.io/collection/untrusted-process-collection",
          safelist_status: "verified",
          trait_offers_enabled: true,
        },
      ],
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-ratelimit-limit": "100",
        "x-ratelimit-remaining": "99",
        "x-ratelimit-reset": "1787685600",
      },
    },
  );
};

const operator = await startOpenSeaCanaryOperatorForTesting({
  credentialHost,
  databasePath: runtimePath,
  port: 0,
});
console.log(
  JSON.stringify({
    apiKeyValueReads,
    credentialCommands,
    credentialValueReads,
    executionEnabled: false,
    financialAuthority: false,
    mode: "stage1-opensea-read-canary-test-fixture",
    openSeaRequests,
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
          closed: true,
          credentialCommands,
          credentialValueReads,
          openSeaRequests,
        }),
      ),
    )
    .catch(() => {
      process.exitCode = 1;
    });
};
process.once("SIGINT", close);
process.once("SIGTERM", close);
