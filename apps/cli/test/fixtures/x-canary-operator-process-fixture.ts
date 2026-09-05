import { Buffer } from "node:buffer";

import {
  createDarwinXReadCanaryKeychainForTesting,
  type CredentialCommandExecutor,
} from "@rsi/credential-host/testing";
import { createDarwinOneShotClaimHostForTesting } from "@rsi/credential-host/one-shot-claim-testing";

import { startXCanaryOperatorForTesting } from "../../src/x-canary-operator-host.testing.js";

const [runtimePath, researchPath] = process.argv.slice(2);
if (runtimePath === undefined || researchPath === undefined) {
  throw new TypeError("fixture paths are required");
}

const services = Object.freeze([
  "dev.rsi.canary.x-read",
  "dev.rsi.canary.operations-state",
  "dev.rsi.canary.capture-registry",
  "dev.rsi.canary.vault-wrapping",
] as const);
const values = Object.freeze([
  "offline-process-canary-token",
  Buffer.alloc(32, 0x41).toString("base64url"),
  Buffer.alloc(32, 0x42).toString("base64url"),
  Buffer.alloc(32, 0x43).toString("base64url"),
] as const);
const executor: CredentialCommandExecutor = async (request) => {
  const service = request.args[4];
  const index = services.indexOf(service as (typeof services)[number]);
  return {
    exitCode: index < 0 ? 44 : 0,
    stdout: new TextEncoder().encode(
      request.args.at(-1) === "-w" ? `${values[index]!}\n` : "present\n",
    ),
    stderr: new Uint8Array(),
    timedOut: false,
  };
};

let xRequests = 0;
globalThis.fetch = async (request): Promise<Response> => {
  const url = request instanceof Request ? request.url : String(request);
  if (new URL(url).hostname !== "api.x.com") throw new Error("unexpected external destination");
  xRequests += 1;
  return new Response(
    JSON.stringify({
      data: [{ id: "1900000000000000001", text: "UNTRUSTED PROCESS FIXTURE TEXT" }],
      meta: {
        newest_id: "1900000000000000001",
        oldest_id: "1900000000000000001",
        result_count: 1,
      },
    }),
    { headers: { "content-type": "application/json" }, status: 200 },
  );
};

const operator = await startXCanaryOperatorForTesting({
  claimHost: createDarwinOneShotClaimHostForTesting("x", {
    executor: async () => ({
      exitCode: 0,
      stdout: new Uint8Array(),
      stderr: new Uint8Array(),
      timedOut: false,
    }),
    platform: "darwin",
  }),
  credentialHost: createDarwinXReadCanaryKeychainForTesting({
    executor,
    platform: "darwin",
  }),
  databasePath: runtimePath,
  port: 0,
  researchDatabasePath: researchPath,
});
console.log(
  JSON.stringify({
    executionEnabled: false,
    financialAuthority: false,
    mode: "stage1-x-read-canary-test-fixture",
    origin: operator.origin,
    runtimeMode: operator.runtime.getSnapshot().mode,
  }),
);

let closing = false;
const close = (): void => {
  if (closing) return;
  closing = true;
  void operator
    .close()
    .then(() => console.log(JSON.stringify({ closed: true, xRequests })))
    .catch(() => {
      process.exitCode = 1;
    });
};
process.once("SIGINT", close);
process.once("SIGTERM", close);
