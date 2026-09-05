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
  OpenSeaReadCanaryVerificationFailure,
  verifyOpenSeaReadCanaryBoundary,
} from "./verify-opensea-read-canary-boundary.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function copyWorkspaceFixture() {
  const root = mkdtempSync(join(tmpdir(), "rsi-opensea-read-canary-gate-"));
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

function append(root, path, source) {
  appendFileSync(join(root, path), source);
}

function expectFailure(root, expression) {
  assert.throws(
    () => verifyOpenSeaReadCanaryBoundary({ root }),
    (error) =>
      error instanceof OpenSeaReadCanaryVerificationFailure && expression.test(error.message),
  );
}

test("accepts the reviewed production OpenSea READ_CANARY graph", () => {
  const result = verifyOpenSeaReadCanaryBoundary({ root: REPOSITORY_ROOT });
  assert.equal(
    result.endpoint,
    "https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10",
  );
  assert.equal(result.maximumRequests, 1);
  assert.equal(result.maximumResults, 10);
  assert.equal(result.paymentCapability, false);
  assert.equal(result.status, "pass");
});

test("pins OpenSea production options and both pre-Keychain runtime guards", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-options.ts",
      'if (argument === "--help" || argument === "-h") return null;',
      'if (argument === "--port") return productionOpenSeaCanaryHostOptions();\n    if (argument === "--help" || argument === "-h") return null;',
    );
    expectFailure(root, /must reject all production path and port overrides/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      "    assertActiveProductionRuntime();\n    runtimeVerified = true;",
      "    runtimeVerified = true;",
    );
    expectFailure(root, /sanitize option, runtime, and host startup failures/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      "    } catch {\n      process.stderr.write(STARTUP_FAILURE_MESSAGE);",
      "    } catch (error) {\n      throw error;",
    );
    expectFailure(root, /sanitize option, runtime, and host startup failures/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host.ts",
      "    options.port !== productionOptions.port",
      "    false",
    );
    expectFailure(root, /reject injected production paths and ports before Keychain access/u);
  });
});

test("rejects request, chain, retry, fetch-count, and payment mutations", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/opensea-trending.ts",
      '"timeframe=one_day&chains=base&limit=10"',
      '"timeframe=one_day&chains=ethereum&limit=10"',
    );
    expectFailure(root, /Base-only one-day query with limit 10/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/source-contracts/src/opensea-trending.ts",
      "retryAttempts: 0,",
      "retryAttempts: 1,",
    );
    expectFailure(root, /zero retries/u);
  });
  withFixture((root) => {
    append(
      root,
      "packages/opensea-collector/src/collector.ts",
      "\nvoid globalThis.fetch; // forbidden second transport capability\n",
    );
    expectFailure(
      root,
      /exactly one (?:production global fetch binding|OpenSea graph fetch site)/u,
    );
  });
  withFixture((root) => {
    append(root, "apps/cli/src/opensea-canary-operator.ts", '\nimport "agentcash";\n');
    expectFailure(root, /financial\/network package agentcash/u);
  });
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      "\nconst alternateTransport = fetch.bind(globalThis); void alternateTransport;\n",
    );
    expectFailure(root, /unaudited bare fetch capability/u);
  });
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      '\nconst alternateTransport = Reflect.get(globalThis, "fetch"); void alternateTransport;\n',
    );
    expectFailure(root, /reflected global fetch capability/u);
  });
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      '\nconst DynamicCtor = (() => {}).constructor as FunctionConstructor;\nconst hiddenTransport = DynamicCtor("return globalThis.fetch")() as typeof JSON.stringify;\nvoid hiddenTransport("https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10");\n',
    );
    expectFailure(
      root,
      /dynamic constructor bridge|dynamic code identifier FunctionConstructor|capability-bearing executable string/u,
    );
  });
});

test("parses embedded dashboard JavaScript and rejects wallet transaction authority", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      "  void refresh();\n})();",
      '  void window.ethereum.request({ method: "eth_sendTransaction" });\n  void refresh();\n})();',
    );
    expectFailure(
      root,
      /embedded JavaScript references financial authority identifier ethereum|embedded JavaScript declares forbidden transaction literal eth_sendTransaction/u,
    );
  });
});

test("rejects aliased globals, reflection, and computed dashboard authority", () => {
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      "\nconst root = globalThis; const extra = root.fetch.bind(root); void extra;\n",
    );
    expectFailure(root, /only two global-object references|exact globalThis\.fetch binding/u);
  });
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      '\nconst reflection = Reflect; const root = globalThis; const extra = reflection.get(root, "fetch"); void extra;\n',
    );
    expectFailure(root, /Reflect capability other than direct Reflect\.ownKeys|global-object/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      "  void refresh();\n})();",
      '  const root = window;\n  const extra = root.fetch.bind(root);\n  void extra("/api/runtime");\n  void refresh();\n})();',
    );
    expectFailure(root, /embedded JavaScript must have exactly one relative same-origin fetch/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      "  void refresh();\n})();",
      '  void window["eth" + "ereum"].request({ method: "eth_send" + "Transaction" });\n  void refresh();\n})();',
    );
    expectFailure(root, /embedded JavaScript must have exactly one relative same-origin fetch/u);
  });
});

test("pins the exact reviewed dashboard assets against navigation, style, and code drift", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      '    <meta name="color-scheme" content="dark">',
      '    <meta name="color-scheme" content="dark">\n    <meta http-equiv="refresh" content="0;url=https&#58;//attacker.example/">',
    );
    expectFailure(root, /exact reviewed HTML with SHA-256/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      ".masthead, main {",
      "body { opacity: 0; }\n.masthead, main {",
    );
    expectFailure(root, /exact reviewed CSS with SHA-256/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      "  updateButtons();\n  void refresh();",
      "  updateButtons();\n  void 0;\n  void refresh();",
    );
    expectFailure(root, /exact reviewed module JavaScript with SHA-256/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-dashboard-assets.ts",
      '<script type="module" src="/operator.js"></script>',
      '<script src="/operator.js" defer></script>',
    );
    expectFailure(root, /exact reviewed module JavaScript with SHA-256/u);
  });
});

test("rejects every forbidden OpenSea testing subpath from production", () => {
  for (const specifier of [
    "@rsi/credential-host/opensea-trending-testing",
    "@rsi/opensea-collector/testing",
    "@rsi/read-canary/opensea-testing",
  ]) {
    withFixture((root) => {
      append(root, "apps/cli/src/opensea-canary-operator.ts", `\nimport "${specifier}";\n`);
      expectFailure(root, /test-only import/u);
    });
  }
});

test("rejects wallet, signer, policy, adapter, order, Stream, transaction, and x402 reachability", () => {
  for (const [specifier, expression] of [
    ["@rsi/adapters", /execution-adapter import/u],
    ["@rsi/policy", /policy authority import/u],
    ["x402", /financial\/network package x402/u],
    ["viem", /financial\/network package viem/u],
  ]) {
    withFixture((root) => {
      append(root, "apps/cli/src/opensea-canary-operator.ts", `\nimport "${specifier}";\n`);
      expectFailure(root, expression);
    });
  }
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      "\nconst sendTransaction = undefined; void sendTransaction;\n",
    );
    expectFailure(root, /financial authority identifier sendTransaction/u);
  });
  withFixture((root) => {
    append(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      '\nimport "../../../packages/source-contracts/src/opensea.js";\n',
    );
    expectFailure(root, /forbidden authority source|unreviewed or test-only source/u);
  });
});

test("rejects reachability to the legacy X operator and CLI graph", () => {
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      '\nimport "../../operator/src/server.js";\n',
    );
    expectFailure(root, /unreviewed or test-only source apps\/operator\/src\/server\.ts/u);
  });
  withFixture((root) => {
    append(root, "apps/cli/src/opensea-canary-operator.ts", '\nimport "@rsi/operator";\n');
    expectFailure(root, /unreviewed workspace import @rsi\/operator/u);
  });
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator.ts",
      '\nimport "./x-canary-operator-host.js";\n',
    );
    expectFailure(
      root,
      /unreviewed or test-only source apps\/cli\/src\/x-canary-operator-host\.ts/u,
    );
  });
});

test("pins genuine runtime and operations one-shot authorization before the only dispatch", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/opensea-collector/src/collector.ts",
      "runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {",
      "runtimeCollectionAuthorization.unsafeDispatch((receipt) => {",
    );
    expectFailure(root, /consume genuine runtime and operations authority exactly once/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/opensea-collector/src/collector.ts",
      "attemptAuthorization.consume();",
      "void attemptAuthorization.binding;",
    );
    expectFailure(root, /consume genuine runtime and operations authority exactly once/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/opensea-collector/src/collector.ts",
      'attemptAuthorization.binding.sourcePlane !== "marketplace"',
      "false",
    );
    expectFailure(root, /authenticate the exact one-shot attempt binding/u);
  });
  withFixture((root) => {
    append(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "\nvoid ({} as { reserveAttempt(): void }).reserveAttempt();\n",
    );
    expectFailure(root, /reserve exactly one OpenSea attempt/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/opensea-collector/src/collector.ts",
      "const fetchPromise = Promise.resolve(fetchImplementation(request));",
      "const fetchPromise = Promise.resolve(fetchImplementation(request));\n    void fetchImplementation(request);",
    );
    expectFailure(root, /only transport invocation/u);
  });
});

test("rejects STOP and guarded-completion bypasses", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "runtimeAuthorization.guardCompletion(() => {",
      "runtimeAuthorization.consumeAndDispatch(() => {",
    );
    expectFailure(
      root,
      /STOP-aware completion guard|append the durable result inside guardCompletion/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/sqlite-runtime-controller.ts",
      'if (facts.decision === "allowed") completion(facts);',
      "completion(facts);",
    );
    expectFailure(root, /shared runtime\/STOP authority gate failed/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-server.ts",
      "        options.readCanary.abortActive();",
      "        void options.readCanary;",
    );
    expectFailure(root, /abort the canary before durable STOP/u);
  });
});

test("keeps the operator loopback-only with no second network client", () => {
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-server.ts",
      'import { BlockList, isIP } from "node:net";',
      'import { BlockList, connect, isIP } from "node:net";',
    );
    expectFailure(root, /node:net capability beyond the exact loopback server surface/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-server.ts",
      'if (host !== "127.0.0.1" && host !== "::1") {',
      "if (false) {",
    );
    expectFailure(root, /same-origin and loopback-only/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-server.ts",
      "        server.closeAllConnections();",
      "        void server;",
    );
    expectFailure(root, /protect credential refresh and bound request\/shutdown availability/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/opensea-server.ts",
      '    if (url.search !== "") badRequest("The credential route does not accept query parameters.");\n    assertSameOriginControl(request, origin);',
      '    if (url.search !== "") badRequest("The credential route does not accept query parameters.");\n    void origin;',
    );
    expectFailure(root, /protect credential refresh and bound request\/shutdown availability/u);
  });
});

test("rejects deletion, tombstone verification, and receipt-order bypasses", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  await destroyResultCapture(dependencies, result);",
      "  void result;",
    );
    expectFailure(
      root,
      /close, crypto-shred, verify the registry tombstone, then append the receipt/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  dependencies.captureRegistry.recordVerifiedDeletion({",
      "  void ({",
    );
    expectFailure(
      root,
      /close, crypto-shred, verify the registry tombstone, then append the receipt/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "!removed.keyDestroyed",
      "false",
    );
    expectFailure(
      root,
      /close, crypto-shred, verify the registry tombstone, then append the receipt/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      `  await destroyResultCapture(dependencies, result);
  return appendReceipt(dependencies.eventStore, receiptFromResult(dependencies, prepared, result));`,
      `  const receipt = appendReceipt(dependencies.eventStore, receiptFromResult(dependencies, prepared, result));
  await destroyResultCapture(dependencies, result);
  return receipt;`,
    );
    expectFailure(
      root,
      /close, crypto-shred, verify the registry tombstone, then append the receipt/u,
    );
  });
});

test("rejects durable failure checkpoint and recovery bypasses", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  const failure = persistFailureCheckpoint(dependencies, prepared, error, overrideCode);",
      "  const failure = failureCandidate(dependencies, prepared, error, overrideCode);",
    );
    expectFailure(
      root,
      /checkpoint exact content-free failures, reconcile registry\/Vault storage/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "    const persisted = appendFailure(dependencies.eventStore, candidate);",
      "    const persisted = candidate;",
    );
    expectFailure(
      root,
      /checkpoint exact content-free failures, reconcile registry\/Vault storage/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  if (durableFailure !== null) {",
      "  if (false) {",
    );
    expectFailure(
      root,
      /checkpoint exact content-free failures, reconcile registry\/Vault storage/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  removePendingCaptureAfterFailure(\n    dependencies.captureRegistry,",
      "  void (\n    dependencies.captureRegistry,",
    );
    expectFailure(
      root,
      /checkpoint exact content-free failures, reconcile registry\/Vault storage/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  await recoverCaptureStorage({",
      "  void ({",
    );
    expectFailure(
      root,
      /checkpoint exact content-free failures, reconcile registry\/Vault storage/u,
    );
  });
});

test("keeps restart recovery credentialless, collectorless, and egress-free", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "  readonly vault: SnapshotVault;\n}\n\nconst PREPARED_KEY",
      "  readonly vault: SnapshotVault;\n  readonly apiKey: string;\n}\n\nconst PREPARED_KEY",
    );
    expectFailure(root, /recovery must be credentialless, collectorless, and egress-free/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      "        captureRegistry: dependencies.captureRegistry,\n        operationsStore:",
      "        captureRegistry: dependencies.captureRegistry,\n        collector: dependencies.collector,\n        operationsStore:",
    );
    expectFailure(root, /recovery must be credentialless, collectorless, and egress-free/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host-core.ts",
      "        await recoverCaptureStorage({",
      "        void ({",
    );
    expectFailure(root, /repair capture storage before both live and restart canary recovery/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host-core.ts",
      "    return readOpenSeaReadCanaryProjection(this.eventStore, this.#credentialStatus);",
      "    void this.credentialHost;\n    return readOpenSeaReadCanaryProjection(this.eventStore, this.#credentialStatus);",
    );
    expectFailure(root, /passive projection must not read Keychain values or mutate recovery/u);
  });
});

test("keeps public receipts content-free and provider charge unknown", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-schemas.ts",
      "    capture: CaptureReceiptSchema.nullable(),",
      "    capture: CaptureReceiptSchema.nullable(),\n    captureId: z.string(),",
    );
    expectFailure(root, /receipt strict, content-free, and actual charge unknown/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-schemas.ts",
      "    actualChargeUsdMicros: z.null(),",
      "    actualChargeUsdMicros: z.literal(1),",
    );
    expectFailure(root, /receipt strict, content-free, and actual charge unknown/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-schemas.ts",
      "  nonPaymentReadAcknowledgement: z.literal(true),",
      "  nonPaymentReadAcknowledgement: z.literal(false),",
    );
    expectFailure(root, /non-payment, no-retry, no-pagination plan/u);
  });
});

test("pins singleton, published plan ID, and production-only operator credentials", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-read-canary-controller.ts",
      '"opensea-read-canary-prepared-v1:singleton"',
      '"opensea-read-canary-prepared-v1:per-request"',
    );
    expectFailure(root, /durable singleton prepared key/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/opensea-constants.ts",
      '"opensea-base-trending-collections-v1"',
      '"opensea-base-trending-v1"',
    );
    expectFailure(root, /published plan ID/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host.ts",
      '"@rsi/credential-host/opensea-trending"',
      '"@rsi/credential-host/opensea-trending-testing"',
    );
    expectFailure(root, /test-only import|option-free production Keychain starter/u);
  });
  withFixture((root) => {
    append(
      root,
      "apps/cli/src/opensea-canary-operator-host-core.ts",
      "\nvoid process.env.OPENSEA_API_KEY;\n",
    );
    expectFailure(root, /ambient process\.env/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host-core.ts",
      "    await this.claimHost.claim();\n",
      "    void this.claimHost;\n",
    );
    expectFailure(root, /claim before API-key access and require a value-free marker check/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host-core.ts",
      '(await this.claimHost.status()) !== "present"',
      '"missing" !== "present"',
    );
    expectFailure(root, /claim before API-key access and require a value-free marker check/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/opensea-canary-operator-host.ts",
      "    createDarwinOpenSeaOneShotClaimHost(),",
      "    createDarwinXOneShotClaimHost(),",
    );
    expectFailure(root, /only the option-free OpenSea one-shot claim host/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/credential-host/src/one-shot-claim-keychain.ts",
      '      "add-generic-password",\n',
      '      "add-generic-password",\n      "-U",\n',
    );
    expectFailure(root, /only create-once claims and value-free presence checks/u);
  });
});
