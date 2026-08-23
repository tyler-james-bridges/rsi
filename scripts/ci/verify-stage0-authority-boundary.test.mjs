import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  VerificationFailure,
  verifyStage0AuthorityBoundary,
} from "./verify-stage0-authority-boundary.mjs";

function write(root, path, contents) {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function manifest(name, dependencies = {}, exports = { ".": "./src/index.ts" }) {
  return `${JSON.stringify({ name, type: "module", exports, dependencies }, null, 2)}\n`;
}

function makeFixture() {
  const root = mkdtempSync(join(tmpdir(), "rsi-stage0-authority-gate-"));
  write(
    root,
    "packages/runtime/package.json",
    manifest("@rsi/runtime", { "@rsi/store": "workspace:*", zod: "1.0.0" }),
  );
  write(
    root,
    "packages/runtime/src/index.ts",
    `import { safeStore } from "@rsi/store";
import { z } from "zod";

// Comments are deliberately ignored: sendTransaction via x402 wallet signer.
export const boundaries = z.enum([
  "policy_approval",
  "paid_read",
  "wallet_sign",
  "execution_adapter",
  "transaction_broadcast",
  "external_publish",
]);
export const denial = "PERMANENTLY_FORBIDDEN";
export const runtime = safeStore;
`,
  );
  write(
    root,
    "packages/runtime/test/runtime.test.ts",
    `import { strictEqual } from "node:assert";
import { denial } from "../src/index.js";

strictEqual(denial, "PERMANENTLY_FORBIDDEN");
for (const boundary of [
  "policy_approval",
  "paid_read",
  "wallet_sign",
  "execution_adapter",
  "transaction_broadcast",
  "external_publish",
]) {
  strictEqual(typeof boundary, "string");
}
`,
  );
  write(root, "packages/store/package.json", manifest("@rsi/store"));
  write(
    root,
    "packages/store/src/index.ts",
    `import { createHash } from "node:crypto";
export const safeStore = createHash("sha256").update("safe").digest("hex");
`,
  );
  write(root, "apps/operator/package.json", manifest("@rsi/operator"));
  write(
    root,
    "apps/operator/src/index.ts",
    `export const startOperatorServer = () => undefined;\n`,
  );
  write(root, "apps/cli/package.json", manifest("@rsi/cli"));
  write(
    root,
    "apps/cli/src/operator.ts",
    `import { startOperatorServer } from "@rsi/operator";
import { runtime } from "@rsi/runtime";
startOperatorServer();
void runtime;
`,
  );
  // Explicit offline entrypoints may retain authority-bearing imports when unreachable.
  write(root, "packages/policy/package.json", manifest("@rsi/policy"));
  write(root, "packages/policy/src/index.ts", `export const approve = () => true;\n`);
  write(
    root,
    "apps/cli/src/pipeline.ts",
    `import { approve } from "@rsi/policy";
approve();
`,
  );
  return root;
}

function withFixture(operation) {
  const root = makeFixture();
  try {
    return operation(root);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

function expectFailure(root, pattern) {
  assert.throws(
    () => verifyStage0AuthorityBoundary({ root }),
    (error) => error instanceof VerificationFailure && pattern.test(error.message),
  );
}

test("accepts the signer-blind graph while ignoring comments and disconnected demos", () => {
  withFixture((root) => {
    assert.deepEqual(verifyStage0AuthorityBoundary({ root }), {
      deniedBoundaries: [
        "policy_approval",
        "paid_read",
        "wallet_sign",
        "execution_adapter",
        "transaction_broadcast",
        "external_publish",
      ],
      operatorFiles: 4,
      runtimeFiles: 2,
      status: "pass",
    });
  });
});

test("rejects a reachable policy approval path from the active operator", () => {
  withFixture((root) => {
    write(root, "apps/cli/src/operator.ts", `import "@rsi/policy";\n`);
    expectFailure(root, /operator graph: .*imports forbidden workspace package @rsi\/policy/u);

    write(root, "apps/cli/src/operator.ts", `import "../../../packages/policy/src/index.js";\n`);
    expectFailure(root, /reaches policy approval package packages\/policy\/src\/index\.ts/u);
  });
});

test("allows only the isolated proposal subpath and still traverses its implementation", () => {
  withFixture((root) => {
    write(
      root,
      "packages/domain/package.json",
      manifest(
        "@rsi/domain",
        { viem: "1.0.0", zod: "1.0.0" },
        { ".": "./src/index.ts", "./proposals": "./src/proposals.ts" },
      ),
    );
    write(root, "packages/domain/src/index.ts", `import "viem";\nexport const intent = true;\n`);
    write(
      root,
      "packages/domain/src/proposals.ts",
      `import { z } from "zod";\nexport const proposal = z.literal("candidate");\n`,
    );
    write(
      root,
      "apps/cli/src/operator.ts",
      `import { proposal } from "@rsi/domain/proposals";
import { runtime } from "@rsi/runtime";
void proposal;
void runtime;
`,
    );

    assert.equal(verifyStage0AuthorityBoundary({ root }).status, "pass");

    write(root, "packages/domain/src/proposals.ts", `import "viem";\n`);
    expectFailure(root, /wallet\/transaction-capable package viem/u);
  });
});

test("rejects non-literal module loading and financial-authority identifiers", () => {
  withFixture((root) => {
    write(
      root,
      "packages/runtime/src/index.ts",
      `const moduleName = "./safe.js";
void import(moduleName);
export const boundaries = [
  "policy_approval",
  "paid_read",
  "wallet_sign",
  "execution_adapter",
  "transaction_broadcast",
  "external_publish",
];
export const denial = "PERMANENTLY_FORBIDDEN";
export function sendTransaction() {}
`,
    );
    expectFailure(root, /non-literal import\/require/u);
    expectFailure(root, /financial-authority identifier\(s\): sendTransaction/u);
  });
});

test("rejects createRequire even when the imported callable is aliased", () => {
  withFixture((root) => {
    write(
      root,
      "apps/cli/src/operator.ts",
      `import { createRequire as makeLoader } from "node:module";
const load = makeLoader(import.meta.url);
load("@rsi/policy");
`,
    );
    expectFailure(root, /platform module node:module \(alternate module loading\)/u);
    expectFailure(root, /alternate module-loader API\(s\): createRequire/u);
  });
});

test("rejects process.getBuiltinModule even when the method is destructured and aliased", () => {
  withFixture((root) => {
    write(
      root,
      "apps/cli/src/operator.ts",
      `const { getBuiltinModule: loadBuiltin } = process;
const load = loadBuiltin("node:module").createRequire(import.meta.url);
load("@rsi/policy");
`,
    );
    expectFailure(root, /alternate module-loader API\(s\): createRequire, getBuiltinModule/u);
  });
});

test("rejects direct eval and Function module-loading routes", () => {
  withFixture((root) => {
    write(root, "apps/cli/src/operator.ts", `eval("import('@rsi/policy')");\n`);
    expectFailure(root, /dynamic-code API\(s\): eval/u);

    write(
      root,
      "apps/cli/src/operator.ts",
      `const load = Function("return import('@rsi/policy')");
void load();
`,
    );
    expectFailure(root, /dynamic-code API\(s\): Function/u);
  });
});

test("rejects an unreviewed or forbidden runtime production dependency", () => {
  withFixture((root) => {
    write(
      root,
      "packages/runtime/package.json",
      manifest("@rsi/runtime", {
        "@rsi/store": "workspace:*",
        "@coinbase/x402": "1.0.0",
        zod: "1.0.0",
      }),
    );
    expectFailure(root, /financial-authority package @coinbase\/x402/u);
  });
});

test("requires explicit permanent-denial evidence in runtime tests", () => {
  withFixture((root) => {
    write(
      root,
      "packages/runtime/test/runtime.test.ts",
      `import { denial } from "../src/index.js";
void denial;
`,
    );
    expectFailure(root, /runtime tests do not exercise permanently denied boundary paid_read/u);
    expectFailure(root, /runtime tests do not assert denial reason PERMANENTLY_FORBIDDEN/u);
  });
});
