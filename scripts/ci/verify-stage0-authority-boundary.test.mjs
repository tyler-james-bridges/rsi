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
    `export { safeStore } from "./sqlite-event-store.js";\n`,
  );
  write(
    root,
    "packages/store/src/sqlite-event-store.ts",
    `import { createHash, randomUUID } from "node:crypto";
void randomUUID;
export const safeStore = createHash("sha256").update("safe").digest("hex");
`,
  );
  write(root, "apps/operator/package.json", manifest("@rsi/operator"));
  write(root, "apps/operator/src/index.ts", `export { startOperatorServer } from "./server.js";\n`);
  write(
    root,
    "apps/operator/src/server.ts",
    `import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { BlockList, isIP } from "node:net";

void createServer;
void BlockList;
void isIP;
export const startOperatorServer = (
  _request?: IncomingMessage,
  _response?: ServerResponse,
): Server | undefined => undefined;
`,
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
      operatorFiles: 6,
      runtimeFiles: 3,
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

test("rejects constructor-chain access to the Function constructor", () => {
  withFixture((root) => {
    write(
      root,
      "apps/cli/src/operator.ts",
      `void ({}).constructor.constructor("return process['getBuiltin' + 'Module']('node:https')")();\n`,
    );
    expectFailure(root, /dynamic-code API\(s\): constructor/u);

    write(
      root,
      "apps/cli/src/operator.ts",
      `void module.constructor.constructor("return globalThis['fetch']")();\n`,
    );
    expectFailure(root, /dynamic-code API\(s\): constructor/u);

    write(
      root,
      "apps/cli/src/operator.ts",
      `void ({})["constructor"]["constructor"]("return globalThis['fetch']")();\n`,
    );
    expectFailure(root, /dynamic-code API\(s\): constructor/u);
  });
});

for (const [label, source, api] of [
  ["direct require", `void require("./late-loader.cjs");\n`, "require"],
  ["computed module require", `void module["require"]("./late-loader.cjs");\n`, "require"],
  [
    "computed internal CommonJS loader",
    `void module.constructor["_load"]("./late-loader.cjs");\n`,
    "_load",
  ],
  [
    "process main-module require",
    `void process.mainModule.require("./late-loader.cjs");\n`,
    "require",
  ],
]) {
  test(`rejects ${label}`, () => {
    withFixture((root) => {
      write(root, "apps/cli/src/operator.ts", source);
      write(root, "apps/cli/src/late-loader.cjs", `module.exports = Object.freeze({});\n`);
      expectFailure(root, new RegExp(`alternate module-loader API\\(s\\): ${api}`, "u"));
    });
  });
}

test("rejects filesystem self-modification followed by a literal runtime import", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/src/index.ts",
      `import { writeFileSync } from "node:fs";
writeFileSync(new URL("./late-loader.ts", import.meta.url), 'import "node:https";');
export const safeStore = import("./late-loader.ts");
`,
    );
    write(root, "packages/store/src/late-loader.ts", `export const initiallyBenign = true;\n`);
    expectFailure(
      root,
      /node:fs is allowed only in packages\/session-lifecycle\/src\/sqlite-session-coordinator\.ts/u,
    );
    expectFailure(root, /contains a runtime import\(\) expression/u);
  });
});

for (const [moduleName, api] of [
  ["node:http", "request"],
  ["node:http", "get"],
  ["node:net", "connect"],
  ["node:net", "createConnection"],
]) {
  test(`rejects outbound ${moduleName} ${api} even in the reviewed server file`, () => {
    withFixture((root) => {
      write(
        root,
        "apps/operator/src/server.ts",
        `import { ${api} } from ${JSON.stringify(moduleName)};\nvoid ${api};\nexport const startOperatorServer = () => undefined;\n`,
      );
      expectFailure(root, new RegExp(`${moduleName} imports must be exactly`, "u"));
    });
  });
}

test("rejects reviewed server-platform imports from every other source file", () => {
  withFixture((root) => {
    write(
      root,
      "apps/cli/src/operator.ts",
      `import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
void createServer;
void (undefined as IncomingMessage | Server | ServerResponse | undefined);
`,
    );
    expectFailure(root, /node:http is allowed only in apps\/operator\/src\/server\.ts/u);
  });
});

test("rejects asymmetric key generation and signing through node:crypto", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/src/sqlite-event-store.ts",
      `import { generateKeyPairSync, sign } from "node:crypto";
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
export const safeStore = sign(null, Buffer.alloc(32), privateKey);
`,
    );
    expectFailure(root, /node:crypto imports must be exactly createHash, randomUUID/u);
    expectFailure(
      root,
      /cryptographic signing\/key-authority API\(s\): generateKeyPairSync, sign/u,
    );
  });
});

test("rejects computed WebCrypto key generation", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/src/index.ts",
      `export const safeStore = globalThis.crypto["subtle"]["generateKey"];
`,
    );
    expectFailure(root, /cryptographic signing\/key-authority API\(s\): generateKey, subtle/u);
  });
});

for (const moduleName of ["http", "node:https", "node:http2", "node:tls", "node:dns"]) {
  test(`rejects unapproved network platform module ${moduleName}`, () => {
    withFixture((root) => {
      write(root, "apps/cli/src/operator.ts", `import ${JSON.stringify(moduleName)};\n`);
      expectFailure(root, new RegExp(`unapproved network platform module ${moduleName}`, "u"));
    });
  });
}

for (const [label, source, pattern] of [
  ["bare fetch", `void fetch("/local-only");\n`, /unaudited bare fetch call/u],
  ["globalThis.fetch", `void globalThis.fetch;\n`, /unapproved network global: fetch/u],
  ["computed globalThis fetch", `void globalThis["fetch"];\n`, /globalThis\[fetch\]/u],
  ["computed window fetch", `void window["fetch"];\n`, /window\[fetch\]/u],
  ["computed Node global fetch", `void global["fetch"];\n`, /global\[fetch\]/u],
  [
    "Reflect.get fetch",
    `void Reflect.get(globalThis, "fetch");\n`,
    /unapproved network global: Reflect\.get\(globalThis, fetch\)/u,
  ],
]) {
  test(`rejects ${label}`, () => {
    withFixture((root) => {
      write(root, "apps/cli/src/operator.ts", source);
      expectFailure(root, pattern);
    });
  });
}

for (const [label, source] of [
  ["WebSocket", `void WebSocket;\n`],
  ["WebSocketStream", `void WebSocketStream;\n`],
  ["WebTransport", `void WebTransport;\n`],
  ["EventSource", `void EventSource;\n`],
  ["XMLHttpRequest", `void XMLHttpRequest;\n`],
  ["sendBeacon", `void navigator.sendBeacon("/local-only");\n`],
]) {
  test(`rejects network global ${label}`, () => {
    withFixture((root) => {
      write(root, "apps/cli/src/operator.ts", source);
      expectFailure(root, new RegExp(`unapproved network global: ${label}`, "u"));
    });
  });
}

for (const name of [
  "WebSocket",
  "WebSocketStream",
  "WebTransport",
  "EventSource",
  "XMLHttpRequest",
  "sendBeacon",
]) {
  test(`rejects computed network global ${name}`, () => {
    withFixture((root) => {
      write(root, "apps/cli/src/operator.ts", `void globalThis[${JSON.stringify(name)}];\n`);
      expectFailure(root, new RegExp(`computed ${name}`, "u"));
    });
  });
}

for (const name of ["eval", "Function", "AsyncFunction", "GeneratorFunction"]) {
  test(`rejects computed dynamic-code global ${name}`, () => {
    withFixture((root) => {
      write(
        root,
        "apps/cli/src/operator.ts",
        `void globalThis[${JSON.stringify(name)}]("return undefined");\n`,
      );
      expectFailure(root, new RegExp(`dynamic-code API\\(s\\): ${name}`, "u"));
    });
  });
}

test("rejects SQLite native-extension loading options and methods", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/src/index.ts",
      `import { DatabaseSync } from "node:sqlite";
const database = new DatabaseSync(":memory:", { allowExtension: true });
database.enableLoadExtension(true);
database.loadExtension("/tmp/unreviewed-extension.dylib");
export const safeStore = database;
`,
    );
    expectFailure(
      root,
      /alternate module-loader API\(s\): allowExtension, enableLoadExtension, loadExtension/u,
    );
  });
});

for (const api of ["dlopen", "binding", "_linkedBinding"]) {
  test(`rejects direct process.${api} native loading`, () => {
    withFixture((root) => {
      write(
        root,
        "packages/store/src/index.ts",
        `void process.${api};\nexport const safeStore = 1;\n`,
      );
      expectFailure(root, new RegExp(`alternate module-loader API\\(s\\): process\\.${api}`, "u"));
    });
  });

  test(`rejects computed process ${api} native loading`, () => {
    withFixture((root) => {
      write(
        root,
        "packages/store/src/index.ts",
        `void process[${JSON.stringify(api)}];\nexport const safeStore = 1;\n`,
      );
      expectFailure(root, new RegExp(`alternate module-loader API\\(s\\): process\\.${api}`, "u"));
    });
  });

  test(`rejects destructured process ${api} native loading`, () => {
    withFixture((root) => {
      write(
        root,
        "packages/store/src/index.ts",
        `const { ${api}: nativeLoader } = process;\nvoid nativeLoader;\nexport const safeStore = 1;\n`,
      );
      expectFailure(root, new RegExp(`alternate module-loader API\\(s\\): process\\.${api}`, "u"));
    });
  });
}

test("allows an ordinary local variable named binding", () => {
  withFixture((root) => {
    write(
      root,
      "apps/cli/src/operator.ts",
      `import { startOperatorServer } from "@rsi/operator";
import { runtime } from "@rsi/runtime";
const binding = "local-state";
startOperatorServer();
void binding;
void runtime;
`,
    );
    assert.equal(verifyStage0AuthorityBoundary({ root }).status, "pass");
  });
});

test("rejects unreviewed HTTP and WebSocket origin literals", () => {
  withFixture((root) => {
    write(
      root,
      "apps/cli/src/operator.ts",
      `const endpoint = "https://unreviewed.invalid/v1";\nvoid endpoint;\n`,
    );
    expectFailure(root, /unreviewed network origin https:\/\/unreviewed\.invalid\/v1/u);

    write(
      root,
      "apps/cli/src/operator.ts",
      "const endpoint = `wss://unreviewed.invalid/socket`;\nvoid endpoint;\n",
    );
    expectFailure(root, /unreviewed network origin wss:\/\/unreviewed\.invalid\/socket/u);

    write(
      root,
      "apps/cli/src/operator.ts",
      `const endpoint = "HTTPS://unreviewed.invalid/v2";\nvoid endpoint;\n`,
    );
    expectFailure(root, /unreviewed network origin HTTPS:\/\/unreviewed\.invalid\/v2/u);
  });
});

test("rejects divergent type and runtime package exports", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/package.json",
      manifest(
        "@rsi/store",
        {},
        {
          ".": {
            types: "./src/index.ts",
            import: "./src/runtime-entry.ts",
          },
        },
      ),
    );
    write(root, "packages/store/src/runtime-entry.ts", `import "@rsi/policy";\n`);
    expectFailure(root, /workspace export has divergent runtime targets/u);
  });
});

test("rejects a module-sync runtime target hidden by safe direct root conditions", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/package.json",
      manifest(
        "@rsi/store",
        {},
        {
          types: "./src/index.ts",
          import: "./src/index.ts",
          "module-sync": "./src/module-sync.ts",
        },
      ),
    );
    write(root, "packages/store/src/module-sync.ts", `import "@rsi/policy";\n`);
    expectFailure(root, /workspace export has divergent runtime targets/u);
  });
});

test("rejects a module-sync target hidden in a named subpath export", () => {
  withFixture((root) => {
    write(
      root,
      "packages/domain/package.json",
      manifest(
        "@rsi/domain",
        {},
        {
          ".": "./src/index.ts",
          "./proposals": {
            types: "./src/proposals.ts",
            import: "./src/proposals.ts",
            "module-sync": "./src/module-sync-proposals.ts",
          },
        },
      ),
    );
    write(root, "packages/domain/src/proposals.ts", `export const proposal = true;\n`);
    write(
      root,
      "packages/domain/src/module-sync-proposals.ts",
      `import "@rsi/policy";\nexport const proposal = true;\n`,
    );
    write(
      root,
      "apps/cli/src/operator.ts",
      `import { proposal } from "@rsi/domain/proposals";\nvoid proposal;\n`,
    );
    expectFailure(root, /workspace export has divergent runtime targets/u);
  });
});

test("rejects wildcard workspace exports instead of falling back to a benign legacy file", () => {
  withFixture((root) => {
    write(
      root,
      "packages/domain/package.json",
      manifest(
        "@rsi/domain",
        {},
        {
          ".": "./src/index.ts",
          "./*": "./src/runtime/*.ts",
        },
      ),
    );
    write(root, "packages/domain/src/proposals.ts", `export const proposal = "legacy-safe";\n`);
    write(
      root,
      "packages/domain/src/runtime/proposals.ts",
      `import "@rsi/policy";\nexport const proposal = "unsafe-runtime";\n`,
    );
    write(
      root,
      "apps/cli/src/operator.ts",
      `import { proposal } from "@rsi/domain/proposals";\nvoid proposal;\n`,
    );
    expectFailure(root, /unsupported wildcard\/folder key \.\/\*/u);
  });
});

test("rejects null and array workspace-export fallbacks", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/package.json",
      manifest("@rsi/store", {}, { ".": [null, "./src/runtime-entry.ts"] }),
    );
    write(root, "packages/store/src/runtime-entry.ts", `import "@rsi/policy";\n`);
    expectFailure(root, /unsupported fallback array/u);

    write(root, "packages/store/package.json", manifest("@rsi/store", {}, { ".": null }));
    expectFailure(root, /contains a null target/u);
  });
});

test("rejects custom export conditions that NODE_OPTIONS could activate", () => {
  withFixture((root) => {
    write(
      root,
      "packages/store/package.json",
      manifest(
        "@rsi/store",
        {},
        {
          ".": {
            types: "./src/index.ts",
            import: "./src/index.ts",
            development: "./src/development.ts",
          },
        },
      ),
    );
    write(root, "packages/store/src/development.ts", `import "@rsi/policy";\n`);
    expectFailure(root, /unreviewed condition development/u);
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
