import assert from "node:assert/strict";
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  BaseRpcReadCanaryVerificationFailure,
  verifyBaseRpcReadCanaryBoundary,
} from "./verify-base-rpc-read-canary-boundary.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function copyWorkspaceFixture() {
  const root = mkdtempSync(join(tmpdir(), "rsi-base-rpc-read-canary-gate-"));
  for (const parentName of ["apps", "packages"]) {
    const sourceParent = join(REPOSITORY_ROOT, parentName);
    const targetParent = join(root, parentName);
    mkdirSync(targetParent, { recursive: true });
    for (const entry of readdirSync(sourceParent, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const sourceDirectory = join(sourceParent, entry.name);
      const manifest = join(sourceDirectory, "package.json");
      if (!existsSync(manifest)) continue;
      const targetDirectory = join(targetParent, entry.name);
      mkdirSync(targetDirectory, { recursive: true });
      cpSync(manifest, join(targetDirectory, "package.json"));
      const source = join(sourceDirectory, "src");
      if (existsSync(source)) cpSync(source, join(targetDirectory, "src"), { recursive: true });
    }
  }
  cpSync(join(REPOSITORY_ROOT, "package.json"), join(root, "package.json"));
  mkdirSync(join(root, ".github", "workflows"), { recursive: true });
  cpSync(
    join(REPOSITORY_ROOT, ".github", "workflows", "ci.yml"),
    join(root, ".github", "workflows", "ci.yml"),
  );
  return root;
}

function withFixture(operation) {
  const root = copyWorkspaceFixture();
  try {
    operation(root);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

function replace(root, path, needle, replacement) {
  const target = join(root, path);
  const source = readFileSync(target, "utf8");
  const occurrences = source.split(needle).length - 1;
  assert.ok(occurrences >= 1, `${path} fixture does not contain mutation target: ${needle}`);
  writeFileSync(target, source.replace(needle, replacement));
}

function mutate(root, path, operation) {
  const target = join(root, path);
  writeFileSync(target, operation(readFileSync(target, "utf8")));
}

function append(root, path, source) {
  appendFileSync(join(root, path), source);
}

function expectFailure(root, expression) {
  assert.throws(
    () => verifyBaseRpcReadCanaryBoundary({ root }),
    (error) =>
      error instanceof BaseRpcReadCanaryVerificationFailure && expression.test(error.message),
  );
}

test("accepts the reviewed production Base RPC READ_CANARY graph", () => {
  const result = verifyBaseRpcReadCanaryBoundary({ root: REPOSITORY_ROOT });
  assert.equal(result.endpoint, "https://base-mainnet.g.alchemy.com/v2");
  assert.equal(result.maximumAnchors, 1);
  assert.equal(result.maximumHttpRequests, 1);
  assert.deepEqual(result.rpcMethods, ["eth_chainId", "eth_getBlockByNumber"]);
  assert.equal(result.paymentCapability, false);
  assert.equal(result.transactionCapability, false);
  assert.equal(result.status, "pass");
});

test("rejects endpoint, query, method, retry, and exact JSON-RPC body mutations", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      '"https://base-mainnet.g.alchemy.com"',
      '"https://eth-mainnet.g.alchemy.com"',
    );
    expectFailure(root, /fixed HTTPS origin|fixed endpoint|unreviewed network origin/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      '"/v2"',
      '"/v2?network=base"',
    );
    expectFailure(root, /fixed query-free path|permits a query/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      'method: "POST",',
      'method: "GET",',
    );
    expectFailure(root, /POST-only method/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "retryAttempts: 0,",
      "retryAttempts: 1,",
    );
    expectFailure(root, /zero retries/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "maximumHttpRequests: 1,",
      "maximumHttpRequests: 2,",
    );
    expectFailure(root, /one HTTP request/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      '"eth_chainId"',
      '"eth_blockNumber"',
    );
    expectFailure(root, /exact two-method JSON-RPC body|fixed chain response ID/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      '["finalized",false]',
      '["latest",true]',
    );
    expectFailure(root, /exact two-method JSON-RPC body/u);
  });
});

test("rejects transport, redirect, Bearer header, and second-fetch mutations", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "method: BASE_RPC_ANCHOR_METHOD,",
      'method: "GET",',
    );
    expectFailure(root, /fixed POST method/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "authorization: `${BASE_RPC_ANCHOR_CREDENTIAL_SCHEME} ${apiKey}`",
      '"x-api-key": apiKey',
    );
    expectFailure(root, /Bearer authorization header/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      'redirect: "error",',
      'redirect: "follow",',
    );
    expectFailure(root, /transport redirect refusal/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "response.url !== prepared.url",
      "false",
    );
    expectFailure(root, /response URL drift refusal/u);
  });
  withFixture((root) => {
    append(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "\nvoid globalThis.fetch; // forbidden second transport capability\n",
    );
    expectFailure(
      root,
      /exact production global fetch binding|exactly one Base graph fetch site|only two global-object references/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "const fetchPromise = Promise.resolve(fetchImplementation(request));",
      "const fetchPromise = Promise.resolve(fetchImplementation(request));\n    void fetchImplementation(request);",
    );
    expectFailure(root, /only transport invocation/u);
  });
});

test("pins runtime authorization, durable attempt consumption, and exact attempt binding", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {",
      "runtimeCollectionAuthorization.unsafeDispatch((receipt) => {",
    );
    expectFailure(root, /consume runtime then durable attempt authority exactly once/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "dispatchReceipt = attemptAuthorization.consume();",
      "dispatchReceipt = {} as never;",
    );
    expectFailure(root, /consume runtime then durable attempt authority exactly once/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "attemptAuthorization.binding.sourcePlane !== BASE_RPC_ANCHOR_SOURCE_PLANE",
      "false",
    );
    expectFailure(root, /authenticate the exact Base one-shot attempt binding/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/base-rpc-read-canary-controller.ts",
      'sourcePlane: "canonical_chain",',
      'sourcePlane: "research",',
    );
    expectFailure(root, /durably claim and bind one exact runtime-authorized Base request/u);
  });
});

test("rejects chain, freshness, finality, and strict-response-parser mutations", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "chainId !== 8_453n",
      "chainId !== 1n",
    );
    expectFailure(root, /Base chain ID 8453/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "ageMs < 0 || ageMs > BASE_RPC_ANCHOR_MAXIMUM_AGE_MS",
      "ageMs > BASE_RPC_ANCHOR_MAXIMUM_AGE_MS",
    );
    expectFailure(root, /nonfuture bounded freshness/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "readonly providerReportedFinalized = true as const;",
      "readonly providerReportedFinalized = false as const;",
    );
    expectFailure(root, /provider-reported finality semantics/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "z.strictObject({",
      "z.object({",
    );
    expectFailure(root, /strict block result|all three JSON-RPC response objects strict/u);
  });
  withFixture((root) => {
    replace(root, "packages/source-contracts/src/base-rpc-anchor.ts", ".length(2);", ".min(1);");
    expectFailure(root, /exact two-envelope response/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/base-rpc-anchor.ts",
      "parseJsonBytes(AnchorResponseSchema, bytes, BASE_RPC_ANCHOR_MAXIMUM_BYTES)",
      "JSON.parse(new TextDecoder().decode(bytes as Uint8Array))",
    );
    expectFailure(root, /strict bounded JSON byte parser/u);
  });
});

test("rejects credential reflection and broken STOP signal propagation", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "assertCredentialAbsentFromRequest(prepared, apiKey);",
      "void prepared;",
    );
    expectFailure(root, /reject credentials embedded in the fixed request/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "assertCredentialAbsentFromResponse(bytes, apiKey);",
      "void bytes;",
    );
    expectFailure(root, /reject provider responses containing credential representations/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/base-rpc-collector/src/collector.ts",
      "signal: controller.signal,",
      "signal: undefined,",
    );
    expectFailure(root, /propagate STOP aborts through its only request/u);
  });
});

test("pins encrypt-before-parse, raw destruction, and uncommitted crypto-shredding", () => {
  withFixture((root) => {
    mutate(root, "packages/ingestion/src/base-rpc-anchor.ts", (source) => {
      const withoutDeclaration = source.replace(
        "    const projection = projectResponse(response);",
        "    projection = projectResponse(response);",
      );
      return withoutDeclaration.replace(
        "    const capture = await dependencies.vault.capture(bytes, {",
        "    let projection = projectResponse(response);\n    const capture = await dependencies.vault.capture(bytes, {",
      );
    });
    expectFailure(root, /encrypt raw provider bytes before parse/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/ingestion/src/base-rpc-anchor.ts",
      "    response?.destroy();",
      "    void response;",
    );
    expectFailure(root, /destroy the quarantined raw response/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/ingestion/src/base-rpc-anchor.ts",
      "await dependencies.vault.delete(captureId,",
      "await Promise.resolve(captureId,",
    );
    expectFailure(root, /crypto-shred every uncommitted capture/u);
  });
});

test("rejects unauthenticated removed-state recovery tombstones", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/ingestion/src/base-rpc-anchor-storage.ts",
      'existingAttempt.removalReason !== "capture_deleted_explicit"',
      "false",
    );
    expectFailure(root, /pending, or predating removed-state recovery tombstones/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/ingestion/src/base-rpc-anchor-storage.ts",
      "Date.parse(existingAttempt.removedAt) < Date.parse(result.acquiredAt)",
      "false",
    );
    expectFailure(root, /pending, or predating removed-state recovery tombstones/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/ingestion/src/base-rpc-anchor-storage.ts",
      'binding.outcome === "succeeded" || binding.outcome === "failed"',
      'binding.outcome === "succeeded" || binding.outcome === "aborted"',
    );
    expectFailure(root, /bind recovered events to closed attempt outcome and time/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/ingestion/src/base-rpc-anchor-storage.ts",
      'if (binding.state === "closed") {\n    throw new SnapshotIntegrityError();',
      "if (false) {\n    throw new SnapshotIntegrityError();",
    );
    expectFailure(root, /refuse a closed attempt with no event/u);
  });
});

test("pins durable singleton preparation and STOP-aware completion", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/base-rpc-read-canary-controller.ts",
      "idempotencyKey: PREPARED_KEY,",
      "idempotencyKey: command.requestId,",
    );
    expectFailure(root, /durably claim and bind one exact runtime-authorized Base request/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/base-rpc-read-canary-controller.ts",
      "this.#operationsStore.reserveAttempt({",
      "this.#operationsStore.unsafeReserveAttempt({",
    );
    expectFailure(root, /durably claim and bind one exact runtime-authorized Base request/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/base-rpc-recovery-core.ts",
      "runtimeAuthorization.guardCompletion(() => {",
      "runtimeAuthorization.unsafeCompletion(() => {",
    );
    expectFailure(root, /STOP-aware live completion guard|inside the STOP completion guard/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/base-rpc-recovery-core.ts",
      "  await destroyResultCapture(dependencies, result);",
      "  void result;",
    );
    expectFailure(root, /close, crypto-shred, verify deletion, then append/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/base-rpc-recovery-core.ts",
      "  removePendingCaptureAfterFailure(",
      "  void removePendingCaptureAfterFailure;",
    );
    expectFailure(root, /reconcile and remove capture state before any failure receipt/u);
  });
});

test("keeps the recovery subpath collectorless, credentialless, and egress-free", () => {
  withFixture((root) => {
    append(
      root,
      "packages/read-canary/src/base-rpc-recovery.ts",
      '\nimport "@rsi/base-rpc-collector";\n',
    );
    expectFailure(
      root,
      /recovery subpath reaches (?:live authority source|collector or credential import)/u,
    );
  });
  withFixture((root) => {
    append(root, "packages/read-canary/src/base-rpc-recovery.ts", "\nvoid globalThis.fetch;\n");
    expectFailure(root, /recovery subpath reaches network fetch|global fetch/u);
  });
  withFixture((root) => {
    append(
      root,
      "packages/read-canary/src/base-rpc-recovery.ts",
      '\nimport "@rsi/credential-host/base-rpc";\n',
    );
    expectFailure(
      root,
      /recovery subpath reaches (?:live authority source|collector or credential import)/u,
    );
  });
});

test("requires the Base permanent marker before credential reveal and forbids marker mutation", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-host-core.ts",
      "    await this.claimHost.claim();",
      "    void this.claimHost;",
    );
    expectFailure(root, /recheck exact runtime\/revision immediately before marker claim/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-host.ts",
      "createDarwinBaseRpcOneShotClaimHost",
      "createDarwinXOneShotClaimHost",
    );
    expectFailure(root, /code-owned Base production host and marker/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/credential-host/src/one-shot-claim-keychain.ts",
      'Object.freeze(["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", SERVICES[target]])',
      'Object.freeze(["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", SERVICES[target], "-w"])',
    );
    expectFailure(root, /presence-only and never reveal a value/u);
  });
  withFixture((root) => {
    append(
      root,
      "packages/credential-host/src/one-shot-claim-keychain.ts",
      '\nconst forbiddenMarkerUpdate = "-U"; void forbiddenMarkerUpdate;\n',
    );
    expectFailure(root, /forbidden marker update\/delete\/reset capability/u);
  });
});

test("pins pre-claim and post-claim runtime revision checks plus marker-storage agreement", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-host-core.ts",
      'runtimeBeforeClaim.mode !== "RESEARCH"',
      "false",
    );
    expectFailure(root, /recheck exact runtime\/revision immediately before marker claim/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-host-core.ts",
      "runtimeAfterClaim.revision !== command.expectedRuntimeRevision",
      "false",
    );
    expectFailure(root, /recheck exact runtime\/revision immediately before marker claim/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-host-core.ts",
      'projection.lastReceipt === null && claimStatus === "present"',
      "false",
    );
    expectFailure(
      root,
      /exact agreement between durable receipt state and the permanent Base marker/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-host-core.ts",
      'projection.lastReceipt !== null && claimStatus !== "present"',
      "false",
    );
    expectFailure(
      root,
      /exact agreement between durable receipt state and the permanent Base marker/u,
    );
  });
});

test("pins exact production runtime, canonical storage, fixed port, and redacted startup", () => {
  withFixture((root) => {
    replace(root, "apps/cli/src/production-runtime.ts", '"24.19.0"', '"24.x"');
    expectFailure(root, /Node 24\.19\.0 and pnpm 11\.20\.0 assertion exact/u);
  });
  withFixture((root) => {
    replace(root, "apps/cli/src/production-canary-config.ts", "8_787 as const", "0 as const");
    expectFailure(root, /fixed loopback port 8787/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator-options.ts",
      'if (argument === "--help" || argument === "-h") return null;',
      'if (argument === "--port") return true;\n    if (argument === "--help" || argument === "-h") return null;',
    );
    expectFailure(root, /reject every production path, endpoint, and port override/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator.ts",
      "        origin: running.origin,",
      "        origin: running.origin,\n        paths: running.paths,",
    );
    expectFailure(root, /fixed redacted startup\/failure output/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/base-rpc-canary-operator.ts",
      "    assertActiveProductionRuntime();\n    runtimeVerified = true;",
      "    runtimeVerified = true;",
    );
    expectFailure(root, /options then exact runtime guard before host start/u);
  });
});

test("exposes only the five content-free public receipt fields", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/base-rpc-read-canary.ts",
      '  readonly freshnessVerdict: "fresh" | null;',
      '  readonly freshnessVerdict: "fresh" | null;\n  readonly requestId: string;',
    );
    expectFailure(root, /only the five reviewed content-free receipt fields/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/base-rpc-read-canary.ts",
      "    freshnessVerdict: receipt.freshnessVerdict,",
      "    freshnessVerdict: receipt.freshnessVerdict,\n    requestFingerprint: receipt.requestFingerprint,",
    );
    expectFailure(root, /only the five reviewed content-free receipt fields/u);
  });
});

test("pins server STOP ordering, browser one-shot latch, and charge honesty", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/base-rpc-server.ts",
      "        options.readCanary.abortActive();",
      "        void options.readCanary;",
    );
    expectFailure(root, /abort before durable STOP/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/base-rpc-dashboard-assets.ts",
      "    canarySubmitted = true;",
      "    void canarySubmitted;",
    );
    expectFailure(root, /latch the first browser submission/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/base-rpc-dashboard-assets.ts",
      "<dt>Actual charge</dt><dd>UNKNOWN — PROVIDER ACCOUNT</dd>",
      "<dt>Actual charge</dt><dd>NONE</dd>",
    );
    expectFailure(root, /provider-billed actual charge as unknown/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/base-rpc-dashboard-assets.ts",
      '<meta name="color-scheme" content="dark">',
      '<meta name="color-scheme" content="dark"><meta http-equiv="refresh" content="0;url=https://attacker.invalid">',
    );
    expectFailure(root, /exact reviewed HTML asset/u);
  });
});

test("rejects test hooks, wallets, signers, payment, arbitrary RPC, and WebSockets", () => {
  for (const [source, expression] of [
    ['import "@rsi/base-rpc-collector/testing";', /test-only import/u],
    ['import "x402";', /financial\/network package x402/u],
    [
      "const sendTransaction = undefined; void sendTransaction;",
      /financial authority identifier sendTransaction/u,
    ],
    [
      'const arbitraryRpc = "eth_sendTransaction"; void arbitraryRpc;',
      /forbidden RPC or transaction literal/u,
    ],
    [
      "const socket = new WebSocket('wss://attacker.invalid'); void socket;",
      /unapproved network global WebSocket/u,
    ],
  ]) {
    withFixture((root) => {
      append(root, "apps/cli/src/base-rpc-canary-operator.ts", `\n${source}\n`);
      expectFailure(root, expression);
    });
  }
  withFixture((root) => {
    append(root, "apps/cli/src/base-rpc-canary-operator.ts", '\nimport "@rsi/adapters";\n');
    expectFailure(root, /execution-adapter import/u);
  });
  withFixture((root) => {
    append(root, "apps/cli/src/base-rpc-canary-operator.ts", '\nimport "@rsi/policy";\n');
    expectFailure(root, /policy authority import/u);
  });
});

test("pins the root command and exact GitHub CI step", () => {
  withFixture((root) => {
    const manifestPath = join(root, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.scripts["ci:base-rpc"] = "node scripts/ci/verify-base-rpc-read-canary-boundary.mjs";
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    expectFailure(root, /exact ci:base-rpc authority and mutation gate/u);
  });
  withFixture((root) => {
    replace(root, ".github/workflows/ci.yml", "run: pnpm ci:base-rpc", "run: pnpm test");
    expectFailure(root, /exact pinned pnpm ci:base-rpc step once/u);
  });
});
