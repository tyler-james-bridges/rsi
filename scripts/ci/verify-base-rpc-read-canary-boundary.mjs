#!/usr/bin/env node

import { createHash } from "node:crypto";
import { builtinModules } from "node:module";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import * as ts from "typescript/unstable/ast";

import { verifyStage1ReadCanaryBoundary } from "./verify-stage1-read-canary-boundary.mjs";

const THIS_FILE = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = resolve(dirname(THIS_FILE), "../..");
const ENTRY = "apps/cli/src/base-rpc-canary-operator.ts";

const SOURCE_CONTRACT_FILE = "packages/source-contracts/src/base-rpc-anchor.ts";
const COLLECTOR_FILE = "packages/base-rpc-collector/src/collector.ts";
const COLLECTOR_INDEX_FILE = "packages/base-rpc-collector/src/index.ts";
const COLLECTOR_REQUEST_FILE = "packages/base-rpc-collector/src/request.ts";
const INGESTION_FILE = "packages/ingestion/src/base-rpc-anchor.ts";
const INGESTION_STORAGE_FILE = "packages/ingestion/src/base-rpc-anchor-storage.ts";
const INGESTION_RECOVERY_FILE = "packages/ingestion/src/base-rpc-anchor-recovery.ts";
const READ_CANARY_FILE = "packages/read-canary/src/base-rpc-read-canary-controller.ts";
const RECOVERY_CORE_FILE = "packages/read-canary/src/base-rpc-recovery-core.ts";
const RECOVERY_ENTRY_FILE = "packages/read-canary/src/base-rpc-recovery.ts";
const SCHEMAS_FILE = "packages/read-canary/src/base-rpc-schemas.ts";
const CONSTANTS_FILE = "packages/read-canary/src/base-rpc-constants.ts";
const CREDENTIAL_FILE = "packages/credential-host/src/base-rpc-keychain.ts";
const CREDENTIAL_ENTRY_FILE = "packages/credential-host/src/base-rpc.ts";
const CLAIM_FILE = "packages/credential-host/src/one-shot-claim-keychain.ts";
const CLAIM_ENTRY_FILE = "packages/credential-host/src/one-shot-claim.ts";
const OPERATOR_PROJECTION_FILE = "apps/operator/src/base-rpc-read-canary.ts";
const OPERATOR_SERVER_FILE = "apps/operator/src/base-rpc-server.ts";
const OPERATOR_DASHBOARD_FILE = "apps/operator/src/base-rpc-dashboard-assets.ts";
const OPTIONS_FILE = "apps/cli/src/base-rpc-canary-operator-options.ts";
const HOST_FILE = "apps/cli/src/base-rpc-canary-operator-host.ts";
const HOST_CORE_FILE = "apps/cli/src/base-rpc-canary-operator-host-core.ts";
const PRODUCTION_CONFIG_FILE = "apps/cli/src/production-canary-config.ts";
const PRODUCTION_RUNTIME_FILE = "apps/cli/src/production-runtime.ts";
const CANARY_STARTUP_CLEANUP_FILE = "apps/cli/src/canary-operator-startup-cleanup.ts";
const PROFILE_LOCK_FILE = "apps/cli/src/profile-service-lock.ts";
const PROFILE_LOCK_CORE_FILE = "apps/cli/src/profile-service-lock-core.ts";
const PRODUCTION_FACADE_FILE = "apps/cli/src/production-canary-operator-facade.ts";
const ROOT_PACKAGE_FILE = "package.json";
const CI_WORKFLOW_FILE = ".github/workflows/ci.yml";

const EXACT_ENDPOINT = "https://base-mainnet.g.alchemy.com/v2";
const EXACT_BODY =
  '[{"id":"rsi-base-chain-id-v1","jsonrpc":"2.0","method":"eth_chainId","params":[]},{"id":"rsi-base-finalized-block-v1","jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}]';
const EXACT_ROOT_SCRIPT =
  "node scripts/ci/verify-base-rpc-read-canary-boundary.mjs && node --test scripts/ci/verify-base-rpc-read-canary-boundary.test.mjs";
const EXACT_WORKFLOW_STEP = `      - name: Prove the Base RPC read canary has only its reviewed read authority
        run: pnpm ci:base-rpc`;
const REVIEWED_DASHBOARD_HTML_SHA256 =
  "b32bbe376d328c374cd116c70fdc3a49d872cd61307dee8553e57ca920d55152";
const REVIEWED_DASHBOARD_CSS_SHA256 =
  "6d555b50ef137bfdb07a2b31fa918fdd2674f972e7c00608fc7d6de031111876";
const REVIEWED_DASHBOARD_JS_SHA256 =
  "8321245094c54a3543902caba065ee23d22659ebfb2f64a08df383c7a680914a";

const REQUIRED_IMPORTS = Object.freeze([
  "@rsi/base-rpc-collector",
  "@rsi/capture-registry",
  "@rsi/credential-host/base-rpc",
  "@rsi/credential-host/one-shot-claim",
  "@rsi/ingestion/base-rpc-anchor",
  "@rsi/ingestion/base-rpc-anchor-recovery",
  "@rsi/ingestion/capture-storage-recovery",
  "@rsi/operations",
  "@rsi/operator/base-rpc",
  "@rsi/read-canary/base-rpc",
  "@rsi/read-canary/base-rpc-recovery",
  "@rsi/runtime",
  "@rsi/source-contracts/base-rpc-anchor",
  "@rsi/store",
  "@rsi/vault",
]);
const REVIEWED_WORKSPACE_IMPORTS = new Set(REQUIRED_IMPORTS);

const REVIEWED_PREFIXES = Object.freeze([
  "packages/capture-registry/src/",
  "packages/operations/src/",
  "packages/runtime/src/",
  "packages/store/src/",
  "packages/vault/src/",
]);
const REVIEWED_EXACT_FILES = new Set([
  ENTRY,
  CANARY_STARTUP_CLEANUP_FILE,
  PROFILE_LOCK_FILE,
  PROFILE_LOCK_CORE_FILE,
  PRODUCTION_FACADE_FILE,
  OPTIONS_FILE,
  HOST_FILE,
  HOST_CORE_FILE,
  PRODUCTION_CONFIG_FILE,
  PRODUCTION_RUNTIME_FILE,
  "apps/operator/src/base-rpc.ts",
  OPERATOR_PROJECTION_FILE,
  OPERATOR_SERVER_FILE,
  OPERATOR_DASHBOARD_FILE,
  "apps/operator/src/runtime-controls.ts",
  "apps/operator/src/runtime-types.ts",
  CREDENTIAL_ENTRY_FILE,
  CREDENTIAL_FILE,
  CLAIM_ENTRY_FILE,
  CLAIM_FILE,
  COLLECTOR_INDEX_FILE,
  COLLECTOR_FILE,
  "packages/base-rpc-collector/src/constants.ts",
  "packages/base-rpc-collector/src/errors.ts",
  "packages/base-rpc-collector/src/hash.ts",
  "packages/base-rpc-collector/src/quarantine.ts",
  COLLECTOR_REQUEST_FILE,
  "packages/base-rpc-collector/src/schema.ts",
  "packages/base-rpc-collector/src/time.ts",
  INGESTION_FILE,
  "packages/ingestion/src/base-rpc-anchor-contract.ts",
  INGESTION_RECOVERY_FILE,
  "packages/ingestion/src/base-rpc-anchor-storage.ts",
  "packages/ingestion/src/capture-storage-recovery.ts",
  "packages/read-canary/src/base-rpc.ts",
  CONSTANTS_FILE,
  "packages/read-canary/src/base-rpc-errors.ts",
  READ_CANARY_FILE,
  RECOVERY_CORE_FILE,
  RECOVERY_ENTRY_FILE,
  SCHEMAS_FILE,
  "packages/read-canary/src/base-rpc-types.ts",
  SOURCE_CONTRACT_FILE,
  "packages/source-contracts/src/common.ts",
  "packages/source-contracts/src/errors.ts",
]);

const FORBIDDEN_TEST_SPECIFIERS = Object.freeze([
  "@rsi/base-rpc-collector/testing",
  "@rsi/credential-host/base-rpc-testing",
  "@rsi/credential-host/one-shot-claim-testing",
]);
const FORBIDDEN_LOCAL_FILE = /(?:^|\/)(?:testing|[^/]+\.testing)\.(?:[cm]?[jt]sx?)$/u;
const FORBIDDEN_AUTHORITY_PATH =
  /(?:^|[/._-])(?:adapters?|agentcash|agentpay|arbitrary[-_]?calls?|bridges?|broadcast(?:er)?|calldata|deploy(?:er|ment)?|execution|executors?|lending|leverage|orders?|payments?|policy|publications?|signers?|transactions?|wallets?|withdrawals?|x402)(?:$|[/._-])/iu;
const FORBIDDEN_EXTERNAL_PACKAGE =
  /(?:^|[/@._-])(?:agentcash|agentpay|axios|ethers|got|ky|node-fetch|permissionless|pimlico|safe-global|superagent|undici|viem|wagmi|walletconnect|web3|ws|x402)(?:$|[/@._-])/iu;
const FORBIDDEN_IDENTIFIERS = new Set([
  "AgentCash",
  "ExecutionAdapter",
  "PrivateKeyAccount",
  "WalletClient",
  "arbitraryCall",
  "broadcastTransaction",
  "createWalletClient",
  "delegatecall",
  "deployContract",
  "ethereum",
  "executeUserOperation",
  "hdKeyToAccount",
  "mnemonicToAccount",
  "privateKeyToAccount",
  "sendRawTransaction",
  "sendTransaction",
  "sendUserOperation",
  "signMessage",
  "signTransaction",
  "signTypedData",
  "walletClient",
  "writeContract",
]);
const FORBIDDEN_LITERALS = new Set([
  "arbitrary-call",
  "arbitrary_call",
  "eth_call",
  "eth_estimateGas",
  "eth_sendRawTransaction",
  "eth_sendTransaction",
  "wallet_sendCalls",
]);
const FORBIDDEN_NETWORK_MODULES = new Set([
  "http",
  "https",
  "net",
  "tls",
  "dns",
  "dns/promises",
  "dgram",
  "http2",
  "node:https",
  "node:tls",
  "node:dns",
  "node:dns/promises",
  "node:dgram",
  "node:http2",
]);
const FORBIDDEN_PROCESS_MODULES = new Set([
  "child_process",
  "cluster",
  "module",
  "node:cluster",
  "node:child_process",
  "node:module",
  "node:vm",
  "node:worker_threads",
  "vm",
  "worker_threads",
]);
const NODE_BUILTINS = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);
const SAFE_EXTERNAL_MODULES = new Set(["zod"]);
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];
const REVIEWED_PROCESS_PROPERTIES = new Map([
  [ENTRY, new Set(["argv", "exitCode", "off", "once", "stderr", "stdout"])],
  [PROFILE_LOCK_CORE_FILE, new Set(["geteuid"])],
  [PRODUCTION_RUNTIME_FILE, new Set(["env", "versions"])],
  [HOST_CORE_FILE, new Set(["geteuid"])],
  [CREDENTIAL_FILE, new Set(["platform"])],
  [CLAIM_FILE, new Set(["platform"])],
  ["packages/capture-registry/src/sqlite-capture-registry.ts", new Set(["geteuid"])],
  ["packages/vault/src/snapshot-vault.ts", new Set(["geteuid"])],
]);

export class BaseRpcReadCanaryVerificationFailure extends Error {
  constructor(violations) {
    super(
      `Base RPC read-canary authority isolation failed:\n${violations
        .map((violation, index) => `${index + 1}. ${violation}`)
        .join("\n")}`,
    );
    this.name = "BaseRpcReadCanaryVerificationFailure";
    this.violations = Object.freeze([...violations]);
  }
}

function canonicalRelative(root, path) {
  return relative(root, path).split(sep).join("/");
}

function isInside(root, path) {
  const candidate = relative(root, path);
  return candidate === "" || (!candidate.startsWith(`..${sep}`) && candidate !== "..");
}

function readJson(path, label) {
  const value = JSON.parse(readFileSync(path, "utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value;
}

function directDirectories(path) {
  if (!existsSync(path)) return [];
  return readdirSync(path, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() || entry.isSymbolicLink())
    .map((entry) => join(path, entry.name));
}

function discoverWorkspacePackages(root) {
  const packages = new Map();
  for (const parent of [join(root, "apps"), join(root, "packages")]) {
    for (const directory of directDirectories(parent)) {
      const manifestPath = join(directory, "package.json");
      if (!existsSync(manifestPath)) continue;
      const manifest = readJson(manifestPath, canonicalRelative(root, manifestPath));
      if (typeof manifest.name !== "string" || manifest.name.length === 0) {
        throw new Error(`${canonicalRelative(root, manifestPath)} has no package name`);
      }
      packages.set(manifest.name, { directory, manifest });
    }
  }
  return packages;
}

function conditionTarget(value) {
  if (typeof value === "string") {
    if (value.includes("*") || value.endsWith("/")) {
      throw new Error("workspace export target cannot use a wildcard or folder");
    }
    return value;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("workspace export target is invalid");
  }
  const reviewedConditions = new Set([
    "node-addons",
    "node",
    "import",
    "module-sync",
    "require",
    "types",
    "default",
  ]);
  const targets = [];
  for (const [condition, target] of Object.entries(value)) {
    if (!reviewedConditions.has(condition)) {
      throw new Error(`workspace export uses unreviewed condition ${condition}`);
    }
    targets.push(conditionTarget(target));
  }
  const unique = [...new Set(targets)];
  if (unique.length !== 1) throw new Error("workspace export has divergent runtime targets");
  return unique[0];
}

function exportTarget(exportsValue, subpath) {
  if (typeof exportsValue === "string") return subpath === "" ? exportsValue : undefined;
  if (exportsValue === null || typeof exportsValue !== "object" || Array.isArray(exportsValue)) {
    throw new Error("workspace exports must be a closed object or string");
  }
  const keys = Object.keys(exportsValue);
  if (keys.some((key) => key.includes("*") || key.endsWith("/"))) {
    throw new Error("workspace exports cannot use wildcard or folder targets");
  }
  const subpathKeys = keys.filter((key) => key.startsWith("."));
  if (subpathKeys.length > 0) {
    if (subpathKeys.length !== keys.length) {
      throw new Error("workspace exports cannot mix subpaths and conditions");
    }
    const value = exportsValue[subpath === "" ? "." : `./${subpath}`];
    return value === undefined ? undefined : conditionTarget(value);
  }
  return subpath === "" ? conditionTarget(exportsValue) : undefined;
}

function packageForSpecifier(specifier, packages) {
  const names = [...packages.keys()]
    .filter((name) => specifier === name || specifier.startsWith(`${name}/`))
    .sort((left, right) => right.length - left.length);
  if (names.length === 0) return undefined;
  const name = names[0];
  return {
    name,
    subpath: specifier === name ? "" : specifier.slice(name.length + 1),
    workspacePackage: packages.get(name),
  };
}

function packageTarget(workspacePackage, subpath) {
  const { manifest } = workspacePackage;
  if (manifest.exports !== undefined) return exportTarget(manifest.exports, subpath);
  if (subpath !== "") return `./src/${subpath}`;
  return typeof manifest.main === "string" ? manifest.main : "./src/index.ts";
}

function resolveSourceFile(candidate) {
  const attempts = [candidate];
  const extension = extname(candidate);
  if (extension !== "") {
    const stem = candidate.slice(0, -extension.length);
    for (const sourceExtension of SOURCE_EXTENSIONS) attempts.push(`${stem}${sourceExtension}`);
  } else {
    for (const sourceExtension of SOURCE_EXTENSIONS)
      attempts.push(`${candidate}${sourceExtension}`);
  }
  for (const sourceExtension of SOURCE_EXTENSIONS)
    attempts.push(join(candidate, `index${sourceExtension}`));
  for (const attempt of attempts) {
    if (existsSync(attempt) && statSync(attempt).isFile()) return realpathSync(attempt);
  }
  return undefined;
}

function scanSource(path) {
  const scanner = ts.createScanner(true, ts.LanguageVariant.Standard, readFileSync(path, "utf8"));
  const tokens = [];
  const templates = [];
  let previousKind;
  const expressionEndingTokens = new Set([
    ts.SyntaxKind.Identifier,
    ts.SyntaxKind.StringLiteral,
    ts.SyntaxKind.NumericLiteral,
    ts.SyntaxKind.NoSubstitutionTemplateLiteral,
    ts.SyntaxKind.RegularExpressionLiteral,
    ts.SyntaxKind.TrueKeyword,
    ts.SyntaxKind.FalseKeyword,
    ts.SyntaxKind.NullKeyword,
    ts.SyntaxKind.CloseParenToken,
    ts.SyntaxKind.CloseBracketToken,
    ts.SyntaxKind.CloseBraceToken,
    ts.SyntaxKind.TemplateTail,
  ]);
  for (;;) {
    let kind = scanner.scan();
    if (
      kind === ts.SyntaxKind.SlashToken &&
      (previousKind === undefined || !expressionEndingTokens.has(previousKind))
    ) {
      kind = scanner.reScanSlashToken();
    }
    if (kind === ts.SyntaxKind.TemplateHead) templates.push({ depth: 0 });
    else if (kind === ts.SyntaxKind.OpenBraceToken && templates.length > 0) {
      templates[templates.length - 1].depth += 1;
    } else if (kind === ts.SyntaxKind.CloseBraceToken && templates.length > 0) {
      const template = templates[templates.length - 1];
      if (template.depth > 0) template.depth -= 1;
      else {
        kind = scanner.reScanTemplateToken(false);
        if (kind === ts.SyntaxKind.TemplateTail) templates.pop();
      }
    }
    if (kind === ts.SyntaxKind.EndOfFile) break;
    if (kind === ts.SyntaxKind.Unknown) {
      throw new Error(`unrecognized token at byte ${scanner.getTokenStart()}`);
    }
    tokens.push({ kind, text: scanner.getTokenText(), value: scanner.getTokenValue() });
    previousKind = kind;
  }
  return { path, text: readFileSync(path, "utf8"), tokens };
}

function analyzeSource(source) {
  const imports = [];
  const identifiers = new Set();
  const literals = new Set();
  const violations = [];
  const globalFetchReferences = [];
  const globalObjectReferences = [];
  const processProperties = [];
  const literal = (token) =>
    token?.kind === ts.SyntaxKind.StringLiteral ||
    token?.kind === ts.SyntaxKind.NoSubstitutionTemplateLiteral
      ? token.value
      : undefined;
  const statementEnd = (start) => {
    for (let index = start; index < source.tokens.length; index += 1) {
      if (source.tokens[index].kind === ts.SyntaxKind.SemicolonToken) return index;
      if (
        index > start &&
        (source.tokens[index].kind === ts.SyntaxKind.ImportKeyword ||
          source.tokens[index].kind === ts.SyntaxKind.ExportKeyword)
      ) {
        return index;
      }
    }
    return source.tokens.length;
  };

  for (let index = 0; index < source.tokens.length; index += 1) {
    const token = source.tokens[index];
    const identifier = token.kind === ts.SyntaxKind.Identifier ? token.value : undefined;
    if (identifier !== undefined) {
      identifiers.add(identifier);
      if (FORBIDDEN_IDENTIFIERS.has(identifier)) {
        violations.push(`references financial authority identifier ${identifier}`);
      }
      if (
        ["eval", "Function", "FunctionConstructor", "AsyncFunction", "GeneratorFunction"].includes(
          identifier,
        )
      ) {
        violations.push(`references dynamic code identifier ${identifier}`);
      }
      if (
        [
          "WebSocket",
          "WebSocketStream",
          "WebTransport",
          "XMLHttpRequest",
          "EventSource",
          "sendBeacon",
        ].includes(identifier)
      ) {
        violations.push(`references unapproved network global ${identifier}`);
      }
      if (
        identifier === "Reflect" &&
        !(
          source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
          (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "ownKeys"
        )
      ) {
        violations.push("references Reflect capability other than direct Reflect.ownKeys");
      }
    }

    const literalValue = literal(token);
    if (literalValue !== undefined) {
      literals.add(literalValue);
      if (FORBIDDEN_LITERALS.has(literalValue)) {
        violations.push(`declares forbidden RPC or transaction literal ${literalValue}`);
      }
      if (
        /\b(?:import|require)\s*\(/u.test(literalValue) ||
        /\breturn\s+(?:global|globalThis|self|window)\b/u.test(literalValue) ||
        /\b(?:global|globalThis|self|window)\s*(?:\.|\[)[\s\S]*\bfetch\b/u.test(literalValue)
      ) {
        violations.push("declares a capability-bearing executable string");
      }
      let concatenated = literalValue;
      let cursor = index;
      let parts = 1;
      while (
        source.tokens[cursor + 1]?.kind === ts.SyntaxKind.PlusToken &&
        literal(source.tokens[cursor + 2]) !== undefined
      ) {
        concatenated += literal(source.tokens[cursor + 2]);
        cursor += 2;
        parts += 1;
      }
      if (
        parts > 1 &&
        (/eth_(?:call|estimateGas|sendRawTransaction|sendTransaction)/u.test(concatenated) ||
          /\breturn\s+(?:global|globalThis|self|window)\b/u.test(concatenated))
      ) {
        violations.push("constructs a forbidden RPC or capability-bearing string");
      }
    }

    if (
      token.kind === ts.SyntaxKind.ConstructorKeyword &&
      (source.tokens[index - 1]?.kind === ts.SyntaxKind.DotToken ||
        source.tokens[index - 1]?.kind === ts.SyntaxKind.QuestionDotToken ||
        source.tokens[index + 1]?.kind !== ts.SyntaxKind.OpenParenToken)
    ) {
      violations.push("references a dynamic constructor bridge");
    }

    if (identifier === "process") {
      const accessor = source.tokens[index + 1];
      const property = source.tokens[index + 2];
      processProperties.push(
        (accessor?.kind === ts.SyntaxKind.DotToken ||
          accessor?.kind === ts.SyntaxKind.QuestionDotToken) &&
          property?.kind === ts.SyntaxKind.Identifier
          ? property.value
          : accessor?.kind === ts.SyntaxKind.OpenBracketToken && literal(property) !== undefined
            ? literal(property)
            : "<aliased-or-computed>",
      );
    }

    const globalObject =
      token.kind === ts.SyntaxKind.Identifier || token.kind === ts.SyntaxKind.GlobalKeyword
        ? (token.value ?? token.text)
        : undefined;
    if (["global", "globalThis", "self", "window"].includes(globalObject)) {
      globalObjectReferences.push({ globalObject, index });
    }
    if (
      ["global", "globalThis", "self", "window"].includes(globalObject) &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenBracketToken &&
      ["fetch", "process", "WebSocket", "XMLHttpRequest"].includes(
        literal(source.tokens[index + 2]),
      )
    ) {
      violations.push(
        `references computed ${globalObject} capability ${literal(source.tokens[index + 2])}`,
      );
    }
    if (
      ["global", "globalThis", "self", "window"].includes(globalObject) &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      source.tokens[index + 2]?.value === "fetch"
    ) {
      globalFetchReferences.push({ globalObject, index });
    }
    if (
      identifier === "Reflect" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      source.tokens[index + 2]?.value === "get" &&
      literal(source.tokens[index + 6]) === "fetch"
    ) {
      violations.push("references reflected global fetch capability");
    }
    if (
      identifier === "fetch" &&
      source.tokens[index - 1]?.kind !== ts.SyntaxKind.DotToken &&
      source.tokens[index - 1]?.kind !== ts.SyntaxKind.QuestionDotToken &&
      !(
        source.tokens[index + 1]?.kind === ts.SyntaxKind.QuestionToken &&
        source.tokens[index + 2]?.kind === ts.SyntaxKind.ColonToken
      )
    ) {
      violations.push("contains unaudited bare fetch capability");
    }

    if (token.kind === ts.SyntaxKind.ImportKeyword) {
      const next = source.tokens[index + 1];
      if (next?.kind === ts.SyntaxKind.DotToken) continue;
      if (next?.kind === ts.SyntaxKind.OpenParenToken) {
        violations.push("contains dynamic import()");
        continue;
      }
      const end = statementEnd(index + 1);
      const typeOnly = next?.kind === ts.SyntaxKind.TypeKeyword;
      const sideEffect = literal(next);
      if (sideEffect !== undefined) {
        imports.push({ names: [], specifier: sideEffect, typeOnly: false });
        continue;
      }
      let from = -1;
      for (let cursor = index + 1; cursor < end; cursor += 1) {
        if (source.tokens[cursor].kind === ts.SyntaxKind.FromKeyword) {
          from = cursor;
          break;
        }
      }
      if (from < 0 || literal(source.tokens[from + 1]) === undefined) {
        violations.push("contains a non-literal import");
        continue;
      }
      const names = [];
      for (let cursor = index + 1; cursor < from; cursor += 1) {
        if (source.tokens[cursor].kind === ts.SyntaxKind.Identifier)
          names.push(source.tokens[cursor].value);
      }
      imports.push({ names, specifier: literal(source.tokens[from + 1]), typeOnly });
      continue;
    }

    if (token.kind === ts.SyntaxKind.ExportKeyword) {
      const next = source.tokens[index + 1];
      const declarationStart = next?.kind === ts.SyntaxKind.TypeKeyword ? index + 2 : index + 1;
      if (
        source.tokens[declarationStart]?.kind !== ts.SyntaxKind.OpenBraceToken &&
        source.tokens[declarationStart]?.kind !== ts.SyntaxKind.AsteriskToken
      ) {
        continue;
      }
      const end = statementEnd(index + 1);
      for (let cursor = index + 1; cursor < end; cursor += 1) {
        if (source.tokens[cursor].kind !== ts.SyntaxKind.FromKeyword) continue;
        const specifier = literal(source.tokens[cursor + 1]);
        if (specifier === undefined) violations.push("contains a non-literal re-export");
        else
          imports.push({
            names: [],
            specifier,
            typeOnly: next?.kind === ts.SyntaxKind.TypeKeyword,
          });
        break;
      }
    }

    if (
      identifier === "require" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenParenToken
    ) {
      violations.push("contains CommonJS require()");
    }
  }
  return {
    globalFetchReferences,
    globalObjectReferences,
    identifiers,
    imports,
    literals,
    processProperties,
    violations,
  };
}

function allowedFile(relativeFile) {
  if (FORBIDDEN_LOCAL_FILE.test(relativeFile)) return false;
  return (
    REVIEWED_EXACT_FILES.has(relativeFile) ||
    REVIEWED_PREFIXES.some((prefix) => relativeFile.startsWith(prefix))
  );
}

function classifySpecifier(specifier, relativeFile, names) {
  if (
    FORBIDDEN_TEST_SPECIFIERS.some(
      (value) => specifier === value || specifier.startsWith(`${value}/`),
    )
  ) {
    return `test-only import ${specifier}`;
  }
  if (
    ["@rsi/credential-host", "@rsi/ingestion", "@rsi/operator", "@rsi/read-canary"].includes(
      specifier,
    )
  ) {
    return `generic package root ${specifier} instead of the dedicated Base subpath`;
  }
  if (specifier === "@rsi/adapters" || specifier.startsWith("@rsi/adapters/"))
    return `execution-adapter import ${specifier}`;
  if (specifier === "@rsi/policy" || specifier.startsWith("@rsi/policy/"))
    return `policy authority import ${specifier}`;
  if (FORBIDDEN_EXTERNAL_PACKAGE.test(specifier)) return `financial/network package ${specifier}`;
  if (FORBIDDEN_NETWORK_MODULES.has(specifier)) return `unapproved network module ${specifier}`;
  if (specifier === "node:http" || specifier === "node:net") {
    if (relativeFile !== OPERATOR_SERVER_FILE)
      return `loopback server module ${specifier} outside ${OPERATOR_SERVER_FILE}`;
    const expected =
      specifier === "node:http"
        ? ["IncomingMessage", "Server", "ServerResponse", "createServer"]
        : ["BlockList", "isIP"];
    const imported = [...new Set(names)].sort();
    const reviewed = [...expected].sort();
    return imported.length === reviewed.length &&
      imported.every((value, index) => value === reviewed[index])
      ? undefined
      : `${specifier} capability beyond the exact loopback server surface`;
  }
  if (FORBIDDEN_PROCESS_MODULES.has(specifier)) {
    if (
      specifier === "node:child_process" &&
      (relativeFile === CREDENTIAL_FILE || relativeFile === CLAIM_FILE)
    ) {
      const imported = [...new Set(names)].sort();
      return imported.length === 1 && imported[0] === "execFile"
        ? undefined
        : "node:child_process capability other than exact execFile";
    }
    return `unapproved process module ${specifier}`;
  }
  if (specifier === "node:crypto") {
    const forbidden = names.filter((name) =>
      [
        "createPrivateKey",
        "generateKey",
        "generateKeyPair",
        "generateKeyPairSync",
        "privateDecrypt",
        "privateEncrypt",
        "sign",
      ].includes(name),
    );
    if (forbidden.length > 0)
      return `signing/private-key crypto capability ${forbidden.join(", ")}`;
  }
  return undefined;
}

function inspectGraph(root, packages, entryFile = ENTRY) {
  const violations = [];
  const analyses = new Map();
  const files = new Set();
  const imports = new Set();
  const entry = resolveSourceFile(join(root, entryFile));
  if (entry === undefined)
    return {
      analyses,
      files,
      imports,
      violations: [`production entrypoint ${entryFile} is missing`],
    };
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop();
    if (files.has(file)) continue;
    files.add(file);
    const relativeFile = canonicalRelative(root, file);
    if (!allowedFile(relativeFile))
      violations.push(`production graph reaches unreviewed or test-only source ${relativeFile}`);
    if (FORBIDDEN_AUTHORITY_PATH.test(relativeFile))
      violations.push(`production graph reaches forbidden authority source ${relativeFile}`);
    let analysis;
    try {
      analysis = analyzeSource(scanSource(file));
      analyses.set(file, analysis);
    } catch (error) {
      violations.push(`${relativeFile} cannot be parsed: ${error.message}`);
      continue;
    }
    for (const violation of analysis.violations) violations.push(`${relativeFile} ${violation}`);
    const allowedProcess = REVIEWED_PROCESS_PROPERTIES.get(relativeFile);
    const unreviewedProcess = analysis.processProperties.filter(
      (property) => allowedProcess === undefined || !allowedProcess.has(property),
    );
    if (unreviewedProcess.length > 0)
      violations.push(
        `${relativeFile} references unapproved process capability ${[...new Set(unreviewedProcess)].join(", ")}`,
      );
    for (const literalValue of analysis.literals) {
      for (const match of literalValue.matchAll(/\b(?:https?|wss?):\/\/[^"'`\s)<]*/gu)) {
        if (
          match[0] !== "http://operator.invalid" &&
          match[0] !== EXACT_ENDPOINT &&
          match[0] !== "https://base-mainnet.g.alchemy.com"
        ) {
          violations.push(`${relativeFile} declares unreviewed network origin ${match[0]}`);
        }
      }
    }
    for (const dependency of analysis.imports) {
      if (dependency.typeOnly) continue;
      const classification = classifySpecifier(
        dependency.specifier,
        relativeFile,
        dependency.names,
      );
      if (classification !== undefined) {
        violations.push(`${relativeFile} imports ${classification}`);
        continue;
      }
      let resolvedDependency;
      if (dependency.specifier.startsWith(".") || isAbsolute(dependency.specifier)) {
        resolvedDependency = resolveSourceFile(
          isAbsolute(dependency.specifier)
            ? dependency.specifier
            : resolve(dirname(file), dependency.specifier),
        );
        if (resolvedDependency === undefined) {
          violations.push(`${relativeFile} has unresolved local import ${dependency.specifier}`);
          continue;
        }
      } else {
        const workspace = packageForSpecifier(dependency.specifier, packages);
        if (workspace !== undefined) {
          imports.add(dependency.specifier);
          if (!REVIEWED_WORKSPACE_IMPORTS.has(dependency.specifier)) {
            violations.push(
              `${relativeFile} reaches unreviewed workspace import ${dependency.specifier}`,
            );
            continue;
          }
          let target;
          try {
            target = packageTarget(workspace.workspacePackage, workspace.subpath);
          } catch (error) {
            violations.push(
              `${relativeFile} cannot resolve ${dependency.specifier}: ${error.message}`,
            );
            continue;
          }
          if (target === undefined) {
            violations.push(
              `${relativeFile} cannot resolve workspace export ${dependency.specifier}`,
            );
            continue;
          }
          resolvedDependency = resolveSourceFile(
            resolve(workspace.workspacePackage.directory, target),
          );
          if (resolvedDependency === undefined) {
            violations.push(
              `${relativeFile} cannot resolve workspace source ${dependency.specifier}`,
            );
            continue;
          }
        } else if (
          SAFE_EXTERNAL_MODULES.has(dependency.specifier) ||
          NODE_BUILTINS.has(dependency.specifier)
        ) {
          continue;
        } else {
          violations.push(
            `${relativeFile} imports unreviewed external module ${dependency.specifier}`,
          );
          continue;
        }
      }
      if (!isInside(root, resolvedDependency)) {
        violations.push(
          `${relativeFile} resolves outside the repository via ${dependency.specifier}`,
        );
      } else if (FORBIDDEN_LOCAL_FILE.test(canonicalRelative(root, resolvedDependency))) {
        violations.push(
          `${relativeFile} reaches test-only source ${canonicalRelative(root, resolvedDependency)}`,
        );
      } else {
        pending.push(resolvedDependency);
      }
    }
  }
  return { analyses, files, imports, violations };
}

function requireSource(root, relativeFile, graph, violations) {
  const path = resolveSourceFile(join(root, relativeFile));
  if (path === undefined) {
    violations.push(`required reviewed source ${relativeFile} is missing`);
    return undefined;
  }
  if (!graph.files.has(path))
    violations.push(`production graph does not reach reviewed source ${relativeFile}`);
  return readFileSync(path, "utf8");
}

function countMatches(text, expression) {
  return [...text.matchAll(expression)].length;
}

function functionSlice(source, name) {
  const start = source.search(
    new RegExp(`\\b(?:export\\s+)?(?:async\\s+)?function\\s+${name}\\s*\\(`, "u"),
  );
  if (start < 0) return "";
  const next = source.slice(start + 1).search(/\n(?:export\s+)?(?:async\s+)?function\s+/u);
  return source.slice(start, next < 0 ? source.length : start + 1 + next);
}

function classMethodSlice(source, className, methodName) {
  const classStart = source.search(new RegExp(`\\bclass\\s+${className}\\b`, "u"));
  if (classStart < 0) return "";
  const classSource = source.slice(classStart);
  const methodStart = classSource.search(
    new RegExp(`\\n  (?:static\\s+)?(?:async\\s+)?#?${methodName}\\s*\\(`, "u"),
  );
  if (methodStart < 0) return "";
  const methodEnd = classSource.indexOf("\n  }\n", methodStart);
  return classSource.slice(
    methodStart,
    methodEnd < 0 ? classSource.length : methodEnd + "\n  }".length,
  );
}

function extractNoSubstitutionTemplate(source, exportName) {
  const marker = `export const ${exportName} = \``;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`missing ${exportName} template`);
  const bodyStart = start + marker.length;
  const end = source.indexOf("`;", bodyStart);
  if (end < 0) throw new Error(`unterminated ${exportName} template`);
  const body = source.slice(bodyStart, end);
  if (body.includes("${")) throw new Error(`${exportName} must not interpolate executable source`);
  return body;
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function verifyRequiredImports(graph, violations) {
  for (const specifier of REQUIRED_IMPORTS) {
    if (!graph.imports.has(specifier)) {
      violations.push(`production graph does not reach required reviewed import ${specifier}`);
    }
  }
}

function verifyFixedRequest(root, graph, violations) {
  const contract = requireSource(root, SOURCE_CONTRACT_FILE, graph, violations);
  const request = requireSource(root, COLLECTOR_REQUEST_FILE, graph, violations);
  if (contract !== undefined) {
    const prepared = functionSlice(contract, "prepareBaseRpcAnchorRequest");
    const requirements = [
      [
        /BASE_RPC_ANCHOR_ORIGIN\s*=\s*"https:\/\/base-mainnet\.g\.alchemy\.com"\s+as\s+const/u,
        "fixed HTTPS origin",
      ],
      [/BASE_RPC_ANCHOR_PATH\s*=\s*"\/v2"\s+as\s+const/u, "fixed query-free path"],
      [/maximumHttpRequests:\s*1/u, "one HTTP request"],
      [/credentialHeader:\s*"authorization"/u, "Authorization credential header"],
      [/credentialScheme:\s*"Bearer"/u, "Bearer credential scheme"],
      [/redirect:\s*"reject"/u, "redirect refusal"],
      [/retryAttempts:\s*0/u, "zero retries"],
      [/if\s*\(arguments\.length\s*!==\s*0\)/u, "zero caller request arguments"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(contract))
        violations.push(`${SOURCE_CONTRACT_FILE} does not enforce ${label}`);
    }
    const preparedRequirements = [
      [/method:\s*"POST"/u, "POST-only method"],
      [/maximumHttpRequests:\s*1/u, "one HTTP request"],
      [/redirect:\s*"reject"/u, "redirect refusal"],
      [/retryAttempts:\s*0/u, "zero retries"],
      [/credentialHeader:\s*"authorization"/u, "Authorization credential header"],
      [/credentialScheme:\s*"Bearer"/u, "Bearer credential scheme"],
    ];
    for (const [pattern, label] of preparedRequirements) {
      if (!pattern.test(prepared))
        violations.push(`${SOURCE_CONTRACT_FILE} does not enforce ${label}`);
    }
    const body = contract.match(/BASE_RPC_ANCHOR_BODY\s*=\s*\n?\s*'([^']+)'\s+as\s+const/u)?.[1];
    if (body !== EXACT_BODY) {
      violations.push(`${SOURCE_CONTRACT_FILE} must pin the exact two-method JSON-RPC body`);
    }
    if (
      /\?|URLSearchParams|searchParams|query\s*[:=]/u.test(
        functionSlice(contract, "prepareBaseRpcAnchorRequest"),
      )
    ) {
      violations.push(
        `${SOURCE_CONTRACT_FILE} permits a query or caller-controlled request material`,
      );
    }

    const parserRequirements = [
      [
        /AnchorResponseSchema\s*=\s*z\s*\.array\([\s\S]{0,1200}?\.length\(2\)/u,
        "exact two-envelope response",
      ],
      [/z\.discriminatedUnion\("id"/u, "ID-discriminated response envelopes"],
      [/BlockResultSchema\s*=\s*z\.strictObject\(\{/u, "strict block result"],
      [/z\.literal\("rsi-base-chain-id-v1"\)/u, "fixed chain response ID"],
      [/z\.literal\("rsi-base-finalized-block-v1"\)/u, "fixed finalized-block response ID"],
      [
        /parseJsonBytes\(AnchorResponseSchema,\s*bytes,\s*BASE_RPC_ANCHOR_MAXIMUM_BYTES\)/u,
        "strict bounded JSON byte parser",
      ],
      [
        /chainEntries\.length\s*!==\s*1\s*\|\|\s*blockEntries\.length\s*!==\s*1/u,
        "exactly one response per ID",
      ],
      [/chainId\s*!==\s*8_453n/u, "Base chain ID 8453"],
      [
        /ageMs\s*<\s*0\s*\|\|\s*ageMs\s*>\s*BASE_RPC_ANCHOR_MAXIMUM_AGE_MS/u,
        "nonfuture bounded freshness",
      ],
      [
        /readonly providerReportedFinalized\s*=\s*true\s+as\s+const/u,
        "provider-reported finality semantics",
      ],
      [/transactions:\s*z\.array\(Bytes32Schema\)/u, "hash-only block transactions"],
    ];
    for (const [pattern, label] of parserRequirements) {
      if (!pattern.test(contract))
        violations.push(`${SOURCE_CONTRACT_FILE} does not enforce ${label}`);
    }
    if (countMatches(contract, /z\.strictObject\s*\(\s*\{/gu) !== 3) {
      violations.push(
        `${SOURCE_CONTRACT_FILE} must keep all three JSON-RPC response objects strict`,
      );
    }
  }

  if (request !== undefined) {
    const requirements = [
      [/prepareBaseRpcAnchorRequest\(\)/u, "source-contract request"],
      [/descriptor\.body\s*!==\s*BASE_RPC_ANCHOR_BODY/u, "body drift check"],
      [/descriptor\.chainId\s*!==\s*"8453"/u, "chain drift check"],
      [
        /descriptor\.credentialHeader\s*!==\s*BASE_RPC_ANCHOR_CREDENTIAL_HEADER/u,
        "credential-header drift check",
      ],
      [
        /descriptor\.credentialScheme\s*!==\s*BASE_RPC_ANCHOR_CREDENTIAL_SCHEME/u,
        "credential-scheme drift check",
      ],
      [/descriptor\.maximumHttpRequests\s*!==\s*1/u, "one-request drift check"],
      [/descriptor\.method\s*!==\s*BASE_RPC_ANCHOR_METHOD/u, "method drift check"],
      [/descriptor\.origin\s*!==\s*BASE_RPC_ANCHOR_ORIGIN/u, "origin drift check"],
      [/descriptor\.path\s*!==\s*BASE_RPC_ANCHOR_PATH/u, "path drift check"],
      [/descriptor\.redirect\s*!==\s*"reject"/u, "redirect drift check"],
      [/descriptor\.retryAttempts\s*!==\s*0/u, "retry drift check"],
      [/descriptor\.url\s*!==\s*BASE_RPC_ANCHOR_URL/u, "URL drift check"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(request)) violations.push(`${COLLECTOR_REQUEST_FILE} lacks ${label}`);
    }
  }
}

function verifyCollectorBoundary(root, graph, violations) {
  const collector = requireSource(root, COLLECTOR_FILE, graph, violations);
  const index = requireSource(root, COLLECTOR_INDEX_FILE, graph, violations);
  if (collector !== undefined) {
    const analysis = graph.analyses.get(resolveSourceFile(join(root, COLLECTOR_FILE)));
    const collectStart = collector.indexOf("async collectRaw(");
    const collect = collectStart < 0 ? "" : collector.slice(collectStart);
    const runtimeAuthorization = collect.indexOf(
      "runtimeCollectionAuthorization.consumeAndDispatch",
    );
    const runtimeReceipt = collect.indexOf("assertRuntimeReceipt(", runtimeAuthorization);
    const durableAttempt = collect.indexOf("attemptAuthorization.consume()", runtimeReceipt);
    const transport = collect.indexOf("executeNetworkRequest(", durableAttempt);
    if (
      runtimeAuthorization < 0 ||
      runtimeReceipt < runtimeAuthorization ||
      durableAttempt < runtimeReceipt ||
      transport < durableAttempt ||
      countMatches(collect, /runtimeCollectionAuthorization\.consumeAndDispatch\s*\(/gu) !== 1 ||
      countMatches(collect, /attemptAuthorization\.consume\s*\(\)/gu) !== 1 ||
      countMatches(collect, /executeNetworkRequest\s*\(/gu) !== 1 ||
      countMatches(collector, /fetchImplementation\s*\(\s*request\s*\)/gu) !== 1
    ) {
      violations.push(
        `${COLLECTOR_FILE} must consume runtime then durable attempt authority exactly once before its only transport invocation`,
      );
    }
    if (
      analysis === undefined ||
      analysis.globalFetchReferences.length !== 1 ||
      !/globalThis\.fetch\.bind\(globalThis\)/u.test(collector)
    ) {
      violations.push(`${COLLECTOR_FILE} must own the exact production global fetch binding`);
    }
    const requestRequirements = [
      [/new\s+Request\s*\(\s*prepared\.url/u, "fixed prepared URL"],
      [/method:\s*BASE_RPC_ANCHOR_METHOD/u, "fixed POST method"],
      [
        /authorization:\s*`\$\{BASE_RPC_ANCHOR_CREDENTIAL_SCHEME\} \$\{apiKey\}`/u,
        "Bearer authorization header",
      ],
      [/body:\s*prepared\.body/u, "exact prepared body"],
      [/credentials:\s*"omit"/u, "credential isolation"],
      [/redirect:\s*"error"/u, "transport redirect refusal"],
      [/referrerPolicy:\s*"no-referrer"/u, "referrer refusal"],
      [/response\.redirected/u, "redirect flag refusal"],
      [
        /response\.url\.length\s*>\s*0\s*&&\s*response\.url\s*!==\s*prepared\.url/u,
        "response URL drift refusal",
      ],
      [/response\.status\s*===\s*402/u, "payment-required refusal"],
      [/response\.status\s*===\s*429/u, "rate-limit terminal handling"],
      [/will not retry/u, "no retry semantics"],
    ];
    for (const [pattern, label] of requestRequirements) {
      if (!pattern.test(collector)) violations.push(`${COLLECTOR_FILE} lacks ${label}`);
    }
    if (
      !/attemptAuthorization\.binding\.operation\s*!==\s*BASE_RPC_ANCHOR_OPERATION/u.test(
        collector,
      ) ||
      !/attemptAuthorization\.binding\.sourcePlane\s*!==\s*BASE_RPC_ANCHOR_SOURCE_PLANE/u.test(
        collector,
      ) ||
      !/attemptAuthorization\.binding\.lane\s*!==\s*BASE_RPC_ANCHOR_LANE/u.test(collector) ||
      !/attemptAuthorization\.binding\.reservedAtomic\s*!==\s*BASE_RPC_ANCHOR_RESERVED_ATOMIC/u.test(
        collector,
      )
    ) {
      violations.push(
        `${COLLECTOR_FILE} must authenticate the exact Base one-shot attempt binding`,
      );
    }
    const requestCredentialCheck = collect.indexOf(
      "assertCredentialAbsentFromRequest(prepared, apiKey)",
    );
    if (requestCredentialCheck < 0 || requestCredentialCheck > runtimeAuthorization) {
      violations.push(
        `${COLLECTOR_FILE} must reject credentials embedded in the fixed request before authorization or transport`,
      );
    }
    const execute = functionSlice(collector, "executeNetworkRequest");
    const responseCredentialCheck = execute.indexOf(
      "assertCredentialAbsentFromResponse(bytes, apiKey)",
    );
    const quarantine = execute.indexOf(
      "quarantineBaseRpcAnchorNetworkResponse(",
      responseCredentialCheck,
    );
    if (responseCredentialCheck < 0 || quarantine < responseCredentialCheck) {
      violations.push(
        `${COLLECTOR_FILE} must reject provider responses containing credential representations before quarantine`,
      );
    }
    if (
      !/signal:\s*controller\.signal/u.test(execute) ||
      !/Promise\.race\(\[fetchPromise,\s*gate\]\)/u.test(execute) ||
      !/externalSignal\?\.addEventListener\("abort",\s*onExternalAbort/u.test(execute)
    ) {
      violations.push(
        `${COLLECTOR_FILE} must propagate STOP aborts through its only request and bounded response read`,
      );
    }
  }
  if (
    index !== undefined &&
    (/ForTesting|TestingOptions|\.\/testing/u.test(index) ||
      !/createBaseRpcAnchorCollector/u.test(index))
  ) {
    violations.push(
      `${COLLECTOR_INDEX_FILE} exposes a testing transport or lacks the production collector`,
    );
  }

  const fetchSites = [];
  const globalSites = [];
  for (const [path, analysis] of graph.analyses) {
    for (const reference of analysis.globalFetchReferences)
      fetchSites.push(canonicalRelative(root, path));
    for (const reference of analysis.globalObjectReferences)
      globalSites.push({
        file: canonicalRelative(root, path),
        globalObject: reference.globalObject,
      });
  }
  if (fetchSites.length !== 1 || fetchSites[0] !== COLLECTOR_FILE) {
    violations.push(
      `expected exactly one Base graph fetch site in ${COLLECTOR_FILE}; found ${fetchSites.length}`,
    );
  }
  if (
    globalSites.length !== 2 ||
    globalSites.some((site) => site.file !== COLLECTOR_FILE || site.globalObject !== "globalThis")
  ) {
    violations.push(
      `${COLLECTOR_FILE} must own the graph's only two global-object references in its exact fetch binding`,
    );
  }
}

function verifyIngestionBoundary(root, graph, violations) {
  const ingestion = requireSource(root, INGESTION_FILE, graph, violations);
  const storage = requireSource(root, INGESTION_STORAGE_FILE, graph, violations);
  if (ingestion === undefined) return;
  const capture = functionSlice(ingestion, "captureAndCommit");
  const copy = capture.indexOf("response.copyBytes()");
  const encryption = capture.indexOf("await dependencies.vault.capture(bytes", copy);
  const parse = capture.indexOf("const projection = projectResponse(response)", encryption);
  const commit = capture.indexOf("dependencies.captureRegistry.commitCapture(", parse);
  const event = capture.indexOf("appendBaseRpcAnchorProjection(", commit);
  if (
    copy < 0 ||
    encryption < copy ||
    parse < encryption ||
    commit < parse ||
    event < commit ||
    countMatches(capture, /projectResponse\s*\(\s*response\s*\)/gu) !== 1
  ) {
    violations.push(
      `${INGESTION_FILE} must encrypt raw provider bytes before parse, commit, and content-free event publication`,
    );
  }
  const ingest = functionSlice(ingestion, "ingestBaseRpcAnchor");
  if (
    !/response\s*=\s*await\s+collector\.collectRaw/u.test(ingest) ||
    !/finally\s*\{\s*response\?\.destroy\(\)\s*;/u.test(ingest) ||
    countMatches(ingest, /response\?\.destroy\(\)/gu) !== 1
  ) {
    violations.push(
      `${INGESTION_FILE} must destroy the quarantined raw response on every live exit`,
    );
  }
  const deleteUncommitted = functionSlice(ingestion, "deleteUncommittedCapture");
  if (
    !/await\s+dependencies\.vault\.delete\(/u.test(deleteUncommitted) ||
    !/throw\s+primaryError/u.test(deleteUncommitted)
  ) {
    violations.push(
      `${INGESTION_FILE} must crypto-shred every uncommitted capture before surfacing failure`,
    );
  }
  if (storage !== undefined) {
    const recover = functionSlice(storage, "recoverBaseRpcAnchorFromStorage");
    const closedResult = functionSlice(storage, "assertResultMatchesClosedAttempt");
    const resume = functionSlice(storage, "resumeBaseRpcAnchorCommittedAttempt");
    if (
      !/existingAttempt\.state\s*===\s*"removed"/u.test(recover) ||
      !/existingAttempt\.removalReason\s*!==\s*"capture_deleted_explicit"/u.test(recover) ||
      !/existingAttempt\.removalReason\s*!==\s*"capture_deleted_expired"/u.test(recover) ||
      !/Date\.parse\(existingAttempt\.removedAt\)\s*<\s*Date\.parse\(result\.acquiredAt\)/u.test(
        recover,
      )
    ) {
      violations.push(
        `${INGESTION_STORAGE_FILE} must reject unauthenticated, pending, or predating removed-state recovery tombstones`,
      );
    }
    if (
      !/binding\.state\s*!==\s*"closed"/u.test(closedResult) ||
      !/const\s+outcomeMatches\s*=\s*result\.status\s*===\s*"accepted"\s*\?\s*binding\.outcome\s*===\s*"succeeded"\s*\|\|\s*binding\.outcome\s*===\s*"failed"\s*:\s*binding\.outcome\s*===\s*"failed"/u.test(
        closedResult,
      ) ||
      !/!outcomeMatches/u.test(closedResult) ||
      !/binding\.closedAt\s*===\s*null/u.test(closedResult) ||
      !/Date\.parse\(binding\.closedAt\)\s*<\s*Date\.parse\(result\.acquiredAt\)/u.test(
        closedResult,
      ) ||
      !/if\s*\(binding\.state\s*===\s*"closed"\)\s*\{\s*throw\s+new\s+SnapshotIntegrityError/u.test(
        resume,
      ) ||
      !/assertResultMatchesClosedAttempt\(result,\s*durable\)/u.test(recover)
    ) {
      violations.push(
        `${INGESTION_STORAGE_FILE} must bind recovered events to closed attempt outcome and time, and refuse a closed attempt with no event`,
      );
    }
  }
}

function verifyControllerAndRecoveryBoundary(root, graph, packages, violations) {
  const controller = requireSource(root, READ_CANARY_FILE, graph, violations);
  const recovery = requireSource(root, RECOVERY_CORE_FILE, graph, violations);
  const schemas = requireSource(root, SCHEMAS_FILE, graph, violations);
  const constants = requireSource(root, CONSTANTS_FILE, graph, violations);

  if (constants !== undefined) {
    const requirements = [
      [
        /BASE_RPC_READ_CANARY_PLAN_ID\s*=\s*"base-mainnet-finalized-anchor-v1"\s+as\s+const/u,
        "published plan ID",
      ],
      [
        /BASE_RPC_READ_CANARY_ENDPOINT\s*=\s*"https:\/\/base-mainnet\.g\.alchemy\.com\/v2"\s+as\s+const/u,
        "fixed endpoint",
      ],
      [/BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS\s*=\s*1\s+as\s+const/u, "one-request maximum"],
      [/BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS\s*=\s*1\s+as\s+const/u, "one-anchor maximum"],
      [
        /BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO\s*=\s*"1"\s+as\s+const/u,
        "one-unit internal reserve",
      ],
      [/"eth_chainId"[\s\S]{0,80}?"eth_getBlockByNumber"/u, "exact RPC method set"],
      [
        /"eth_chainId\[\]\+eth_getBlockByNumber\[finalized,false\]"/u,
        "exact typed method acknowledgement",
      ],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(constants)) violations.push(`${CONSTANTS_FILE} does not enforce ${label}`);
    }
  }

  if (schemas !== undefined) {
    const planRequirements = [
      [/BaseRpcReadCanaryPlanSchema\s*=\s*z\.strictObject/u, "strict public plan"],
      [/method:\s*z\.literal\("POST"\)/u, "POST plan"],
      [/chain:\s*z\.literal\("base-mainnet"\)/u, "Base-only chain"],
      [/blockTag:\s*z\.literal\("finalized"\)/u, "finalized tag"],
      [/automaticRetries:\s*z\.literal\(0\)/u, "zero retries"],
      [/automaticFallback:\s*z\.literal\(false\)/u, "zero fallback"],
      [/paymentAuthority:\s*z\.literal\("none"\)/u, "no payment authority"],
      [/transactionAuthority:\s*z\.literal\("none"\)/u, "no transaction authority"],
      [/BaseRpcReadCanaryRunCommandSchema\s*=\s*z\.strictObject/u, "strict run command"],
      [
        /typedPlanIdAcknowledgement:\s*z\.literal\(BASE_RPC_READ_CANARY_PLAN_ID\)/u,
        "typed plan acknowledgement",
      ],
      [/oneRequestAcknowledgement:\s*z\.literal\(true\)/u, "one-request acknowledgement"],
      [/nonPaymentReadAcknowledgement:\s*z\.literal\(true\)/u, "nonpayment acknowledgement"],
      [
        /noTransactionAuthorityAcknowledgement:\s*z\.literal\(true\)/u,
        "no-transaction acknowledgement",
      ],
      [/finalizedAnchorAcknowledgement:\s*z\.literal\(true\)/u, "finality acknowledgement"],
      [
        /methodSetAcknowledgement:\s*z\.literal\(BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT\)/u,
        "method-set acknowledgement",
      ],
    ];
    for (const [pattern, label] of planRequirements) {
      if (!pattern.test(schemas)) violations.push(`${SCHEMAS_FILE} does not enforce ${label}`);
    }
  }

  if (controller !== undefined) {
    const runStart = controller.indexOf("async #run(");
    const runEnd = controller.indexOf("\n  async #resume(", runStart);
    const run = runStart < 0 || runEnd < 0 ? "" : controller.slice(runStart, runEnd);
    const snapshot = run.indexOf("const snapshot = this.#runtime.getSnapshot()");
    const boundaryAuthorization = run.indexOf(
      "this.#runtime.requestBoundaryAuthorization(",
      snapshot,
    );
    const durablePrepared = run.indexOf("this.#eventStore.append({", boundaryAuthorization);
    const budget = run.indexOf("this.#operationsStore.createBudget({", durablePrepared);
    const reserve = run.indexOf("this.#operationsStore.reserveAttempt({", budget);
    const networkAuthorization = run.indexOf(
      "this.#operationsStore.createNetworkAttemptAuthorization(permit)",
      reserve,
    );
    const collector = run.indexOf("createBaseRpcAnchorCollector({", networkAuthorization);
    const ingestion = run.indexOf("await ingestBaseRpcAnchor(", collector);
    if (
      snapshot < 0 ||
      boundaryAuthorization < snapshot ||
      durablePrepared < boundaryAuthorization ||
      budget < durablePrepared ||
      reserve < budget ||
      networkAuthorization < reserve ||
      collector < networkAuthorization ||
      ingestion < collector ||
      countMatches(run, /\.reserveAttempt\s*\(/gu) !== 1 ||
      countMatches(run, /createBaseRpcAnchorCollector\s*\(/gu) !== 1 ||
      !/snapshot\.mode\s*!==\s*"RESEARCH"\s*\|\|\s*snapshot\.revision\s*!==\s*command\.expectedRuntimeRevision/u.test(
        run,
      ) ||
      !/runtimeAuthorization\.requestedRevision\s*!==\s*command\.expectedRuntimeRevision/u.test(
        run,
      ) ||
      !/runtimeAuthorization\.requestedMode\s*!==\s*"RESEARCH"/u.test(run) ||
      !/idempotencyKey:\s*PREPARED_KEY/u.test(run) ||
      !/maxAttempts:\s*1/u.test(run) ||
      !/lane:\s*"contract"/u.test(run) ||
      !/operation:\s*BASE_RPC_READ_CANARY_OPERATION/u.test(run) ||
      !/reservedAtomic:\s*BASE_RPC_ANCHOR_RESERVED_ATOMIC/u.test(run) ||
      !/sourcePlane:\s*"canonical_chain"/u.test(run)
    ) {
      violations.push(
        `${READ_CANARY_FILE} must durably claim and bind one exact runtime-authorized Base request before collection`,
      );
    }
    if (!/The one-shot Base RPC read canary was claimed concurrently/u.test(run)) {
      violations.push(
        `${READ_CANARY_FILE} must fail closed on concurrent durable singleton claims`,
      );
    }
  }

  if (recovery !== undefined) {
    if (countMatches(recovery, /runtimeAuthorization\.guardCompletion\s*\(/gu) !== 1) {
      violations.push(
        `${RECOVERY_CORE_FILE} must retain exactly one STOP-aware live completion guard`,
      );
    }
    const persist = functionSlice(recovery, "persistLiveResult");
    if (
      !/guardCompletion\s*\(\s*\(\)\s*=>\s*\{\s*persisted\s*=\s*appendResult/u.test(persist) ||
      !/completion\.decision\s*!==\s*"allowed"\s*\|\|\s*persisted\s*===\s*undefined/u.test(
        persist,
      ) ||
      !/return\s+persistRecoveryResult/u.test(persist)
    ) {
      violations.push(
        `${RECOVERY_CORE_FILE} must keep live result publication inside the STOP completion guard`,
      );
    }
    const finalize = functionSlice(recovery, "finalizeResult");
    const close = finalize.indexOf("closeAttemptForResult(");
    const destroy = finalize.indexOf("await destroyResultCapture(", close);
    const receipt = finalize.indexOf("appendReceipt(", destroy);
    const destruction = functionSlice(recovery, "destroyResultCapture");
    const vaultDelete = destruction.indexOf("await dependencies.vault.delete(");
    const tombstone = destruction.indexOf(
      "dependencies.captureRegistry.recordVerifiedDeletion(",
      vaultDelete,
    );
    const verifyDeletion = destruction.indexOf(
      "dependencies.captureRegistry.getAttempt(",
      tombstone,
    );
    if (
      close < 0 ||
      destroy < close ||
      receipt < destroy ||
      vaultDelete < 0 ||
      tombstone < vaultDelete ||
      verifyDeletion < tombstone ||
      !/removed\?\.state\s*!==\s*"removed"\s*\|\|\s*!removed\.keyDestroyed/u.test(destruction)
    ) {
      violations.push(
        `${RECOVERY_CORE_FILE} must close, crypto-shred, verify deletion, then append the publicable receipt`,
      );
    }
    const failureFinalize = functionSlice(recovery, "finalizeFailureCheckpoint");
    const repair = failureFinalize.indexOf("await recoverCaptureStorage(");
    const failureClose = failureFinalize.indexOf("closeAttemptForFailure(", repair);
    const cleanup = failureFinalize.indexOf("removePendingCaptureAfterFailure(", failureClose);
    const activeCheck = failureFinalize.indexOf('captureAttempt?.state === "pending"', cleanup);
    const failureReceipt = failureFinalize.indexOf("appendReceipt(", activeCheck);
    if (
      repair < 0 ||
      failureClose < repair ||
      cleanup < failureClose ||
      activeCheck < cleanup ||
      failureReceipt < activeCheck
    ) {
      violations.push(
        `${RECOVERY_CORE_FILE} must reconcile and remove capture state before any failure receipt`,
      );
    }
  }

  const recoveryGraph = inspectGraph(root, packages, RECOVERY_ENTRY_FILE);
  violations.push(...recoveryGraph.violations.map((value) => `recovery subpath: ${value}`));
  for (const path of recoveryGraph.files) {
    const relativeFile = canonicalRelative(root, path);
    if (
      relativeFile.includes("base-rpc-collector") ||
      relativeFile.includes("credential-host") ||
      relativeFile === INGESTION_FILE
    ) {
      violations.push(`recovery subpath reaches live authority source ${relativeFile}`);
    }
    const analysis = recoveryGraph.analyses.get(path);
    if ((analysis?.globalFetchReferences.length ?? 0) > 0)
      violations.push(`recovery subpath reaches network fetch in ${relativeFile}`);
  }
  for (const specifier of recoveryGraph.imports) {
    if (specifier === "@rsi/base-rpc-collector" || specifier.startsWith("@rsi/credential-host")) {
      violations.push(`recovery subpath reaches collector or credential import ${specifier}`);
    }
  }
  const recoveryEntry = requireSource(root, RECOVERY_ENTRY_FILE, graph, violations);
  if (
    recoveryEntry !== undefined &&
    /collector|credential|fetch|apiKey/iu.test(
      recoveryEntry.replace(/Credentialless, collectorless/gu, ""),
    )
  ) {
    violations.push(
      `${RECOVERY_ENTRY_FILE} must expose only credentialless, collectorless recovery`,
    );
  }
}

function verifyCredentialAndHostBoundary(root, graph, violations) {
  const credential = requireSource(root, CREDENTIAL_FILE, graph, violations);
  const credentialEntry = requireSource(root, CREDENTIAL_ENTRY_FILE, graph, violations);
  const claim = requireSource(root, CLAIM_FILE, graph, violations);
  const host = requireSource(root, HOST_FILE, graph, violations);
  const core = requireSource(root, HOST_CORE_FILE, graph, violations);

  if (credential !== undefined) {
    const requirements = [
      [/SECURITY\s*=\s*"\/usr\/bin\/security"\s+as\s+const/u, "fixed Keychain executable"],
      [
        /KEYCHAIN_ACCOUNT\s*=\s*"rsi-stage1-base-rpc-read-canary"\s+as\s+const/u,
        "dedicated Keychain account",
      ],
      [/apiKey:\s*"dev\.rsi\.canary\.alchemy-base-read"/u, "dedicated Alchemy credential service"],
      [/"find-generic-password"/u, "read-only Keychain lookup"],
      [/shell:\s*false/u, "shell-free execution"],
      [/async\s+withSecrets/u, "scoped provider credential reveal"],
      [/async\s+withStorageSecrets/u, "credentialless recovery storage reveal"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(credential)) violations.push(`${CREDENTIAL_FILE} lacks ${label}`);
    }
    for (const command of [
      "add-generic-password",
      "delete-generic-password",
      "set-keychain-settings",
    ]) {
      if (credential.includes(`"${command}"`) || credential.includes(`'${command}'`)) {
        violations.push(`${CREDENTIAL_FILE} contains mutating Keychain command ${command}`);
      }
    }
  }
  if (
    credentialEntry !== undefined &&
    /ForTesting|TestingOptions|\.\/base-rpc-testing/u.test(credentialEntry)
  ) {
    violations.push(`${CREDENTIAL_ENTRY_FILE} exports test-only credential injection`);
  }

  if (claim !== undefined) {
    if (
      !/baseRpc:\s*"dev\.rsi\.canary\.one-shot\.base-mainnet-finalized-anchor-v1"/u.test(claim) ||
      !/createDarwinBaseRpcOneShotClaimHost\(\)[\s\S]{0,260}?productionHost\("baseRpc"\)/u.test(
        claim,
      ) ||
      countMatches(claim, /"add-generic-password"/gu) !== 1 ||
      countMatches(claim, /"find-generic-password"/gu) !== 1 ||
      !/DUPLICATE_ITEM_EXIT_CODE\s*=\s*45/u.test(claim) ||
      !/ITEM_NOT_FOUND_EXIT_CODE\s*=\s*44/u.test(claim)
    ) {
      violations.push(
        `${CLAIM_FILE} must implement the target-fixed permanent Base marker with duplicate refusal and presence-only status`,
      );
    }
    const status = functionSlice(claim, "statusCommand");
    if (
      status.length === 0 ||
      !/"find-generic-password"/u.test(status) ||
      /["']-w["']/u.test(status)
    ) {
      violations.push(`${CLAIM_FILE} marker status must be presence-only and never reveal a value`);
    }
    for (const forbidden of ["-U", "delete-generic-password", "update-generic-password", "reset"]) {
      if (claim.includes(`"${forbidden}"`) || claim.includes(`'${forbidden}'`)) {
        violations.push(
          `${CLAIM_FILE} contains forbidden marker update/delete/reset capability ${forbidden}`,
        );
      }
    }
  }

  if (host !== undefined) {
    if (
      countMatches(host, /createDarwinBaseRpcOneShotClaimHost\s*\(\s*\)/gu) !== 1 ||
      /createDarwin(?:X|OpenSea)OneShotClaimHost/u.test(host)
    ) {
      violations.push(`${HOST_FILE} must keep the code-owned Base production host and marker`);
    }
    const runtime = host.indexOf("assertActiveProductionRuntime();");
    const fixedArguments = host.indexOf("arguments.length !== 0", runtime);
    const profileLock = host.indexOf("await acquireProductionCanaryProfileLock()", fixedArguments);
    const trackedOperatorMatch = host.match(
      /let\s+([A-Za-z_$][\w$]*)\s*:\s*InternalRunningBaseRpcCanaryOperator\s*\|\s*undefined/u,
    );
    const trackedOperator = trackedOperatorMatch?.[1];
    const dispatch =
      trackedOperator === undefined
        ? -1
        : host.search(
            new RegExp(
              `${trackedOperator}\\s*=\\s*await\\s+startBaseRpcCanaryOperatorWithHost\\(`,
              "u",
            ),
          );
    const options = host.indexOf("productionBaseRpcCanaryHostOptions()", dispatch);
    const credentialConstructor = host.indexOf("new DarwinBaseRpcKeychain()", options);
    const claimConstructor = host.indexOf("createDarwinBaseRpcOneShotClaimHost()", options);
    const wrappedReturn =
      trackedOperator === undefined
        ? -1
        : host.search(
            new RegExp(
              `return\\s+createProductionCanaryOperatorFacade\\(\\s*bindProfileServiceLock\\(\\s*${trackedOperator}\\s*,\\s*profileLock\\s*\\)\\s*\\)`,
              "u",
            ),
          );
    const catchStart = host.indexOf("} catch (error)", wrappedReturn);
    const postStartClose =
      trackedOperator === undefined
        ? -1
        : host.search(new RegExp(`await\\s+${trackedOperator}\\.close\\(\\)`, "u"));
    const incompleteCleanup = host.indexOf(
      "new IncompleteCanaryOperatorStartupCleanupError(error, cleanupError)",
      postStartClose,
    );
    const retainedLockDecision = host.lastIndexOf(
      "return rethrowCanaryStartupFailureAfterProfileLockDecision(",
      incompleteCleanup,
    );
    const cleanLockDecision = host.indexOf(
      "return rethrowCanaryStartupFailureAfterProfileLockDecision(",
      incompleteCleanup,
    );
    if (
      runtime < 0 ||
      fixedArguments < runtime ||
      profileLock < fixedArguments ||
      dispatch < profileLock ||
      options < dispatch ||
      credentialConstructor < options ||
      claimConstructor < options ||
      wrappedReturn < claimConstructor ||
      catchStart < wrappedReturn ||
      postStartClose < catchStart ||
      retainedLockDecision < postStartClose ||
      incompleteCleanup < retainedLockDecision ||
      cleanLockDecision < incompleteCleanup ||
      countMatches(host, /assertActiveProductionRuntime\s*\(\s*\)/gu) !== 1 ||
      countMatches(host, /acquireProductionCanaryProfileLock\s*\(\s*\)/gu) !== 1 ||
      countMatches(host, /bindProfileServiceLock\s*\(/gu) !== 1 ||
      !/startBaseRpcCanaryOperatorWithHost\s*\(\s*productionBaseRpcCanaryHostOptions\s*\(\s*\)\s*,\s*new\s+DarwinBaseRpcKeychain\s*\(\s*\)\s*,\s*createDarwinBaseRpcOneShotClaimHost\s*\(\s*\)\s*,\s*profileLock\s*,?\s*\)/u.test(
        host,
      ) ||
      countMatches(
        host,
        /rethrowCanaryStartupFailureAfterProfileLockDecision\s*\(\s*error\s*,\s*profileLock\s*,\s*"RSI Base RPC canary startup and lock release both failed"\s*,?\s*\)/gu,
      ) !== 1 ||
      countMatches(
        host,
        /rethrowCanaryStartupFailureAfterProfileLockDecision\s*\(\s*new\s+IncompleteCanaryOperatorStartupCleanupError\(\s*error\s*,\s*cleanupError\s*\)\s*,\s*profileLock\s*,\s*"RSI Base RPC canary startup and lock release both failed"\s*,?\s*\)/gu,
      ) !== 1 ||
      countMatches(host, /profileLock\.release\s*\(\s*\)/gu) !== 0 ||
      !/IncompleteCanaryOperatorStartupCleanupError[\s\S]{0,200}?rethrowCanaryStartupFailureAfterProfileLockDecision/u.test(
        host,
      ) ||
      /\.runtime\.(?:close|listAudit|requestBoundaryAuthorization|stop|transition)\b/u.test(host) ||
      /ForTesting|TestingOptions|credentialHost\s*[:?]|claimHost\s*[:?]|fetch\s*[:?]|\/testing/u.test(
        host,
      )
    ) {
      violations.push(
        `${HOST_FILE} must validate its option-free API, acquire the shared lock before Keychain/core access, wrap the result in the read-only facade, and prove post-start cleanup before releasing its lock`,
      );
    }
  }

  if (core !== undefined) {
    const startCore = functionSlice(core, "startBaseRpcCanaryOperatorWithHost");
    const abortActive = classMethodSlice(core, "KeychainBaseRpcReadCanaryProvider", "abortActive");
    const beginClosing = classMethodSlice(
      core,
      "KeychainBaseRpcReadCanaryProvider",
      "beginClosing",
    );
    const providerClose = classMethodSlice(core, "KeychainBaseRpcReadCanaryProvider", "close");
    const guardedRuntimeControls = functionSlice(core, "createHostClosingRuntimeControls");
    const leaseAssertion = startCore.indexOf(
      "await assertCanaryProfileLockForDatabasePath(profileLock, options.databasePath)",
    );
    const requestedPaths = startCore.indexOf("const requested = requestedPaths(options)");
    const storageInspection = startCore.indexOf("resolveDatabaseIdentity(", requestedPaths);
    const runtimeOpen = startCore.indexOf("SqliteRuntimeController.open(", storageInspection);
    const closeGuard = startCore.indexOf("if (closePromise === null)");
    const closingStateMatch = startCore
      .slice(0, closeGuard < 0 ? undefined : closeGuard)
      .match(/let\s+([A-Za-z_$][\w$]*)\s*=\s*false;\s*$/mu);
    const closingState = closingStateMatch?.[1];
    const activateClosing =
      closingState === undefined ? -1 : startCore.indexOf(`${closingState} = true`, closeGuard);
    const closeProviderAdmission = startCore.indexOf("canary?.beginClosing()", activateClosing);
    const outerClose = startCore.indexOf(
      "closePromise = closeCanaryResourceSet(",
      closeProviderAdmission,
    );
    const initialStop = startCore.indexOf("runtime?.stop(", outerClose);
    const initialStopCallback = startCore.lastIndexOf("() => {", initialStop);
    const firstCleanupCallback = startCore.indexOf("() =>", outerClose);
    const stopAdmission = startCore.indexOf("() => operator?.close()", initialStop);
    const drainProvider = startCore.indexOf("() => canary?.close()", initialStop);
    const closeEventStore = startCore.indexOf("() => eventStore?.close()", drainProvider);
    const finalStop = startCore.indexOf("runtime?.stop(", closeEventStore);
    const closeRuntime = startCore.indexOf("runtime?.close()", finalStop);
    const finalRuntimeShutdown = startCore.slice(
      startCore.lastIndexOf("() => {", finalStop),
      startCore.indexOf("        },", closeRuntime) + "        },".length,
    );
    const closeSetEnd = startCore.indexOf("      ]);", closeRuntime);
    const finalRuntimeShutdownEnd =
      finalRuntimeShutdown.length === 0
        ? -1
        : startCore.lastIndexOf("() => {", finalStop) + finalRuntimeShutdown.length;
    const guardedControlsConstruction =
      closingState === undefined
        ? -1
        : startCore.search(
            new RegExp(
              `createHostClosingRuntimeControls\\(runtime,\\s*\\(\\)\\s*=>\\s*${closingState}\\)`,
              "u",
            ),
          );
    const cleanlyRethrow = startCore.indexOf(
      "return rethrowCanaryStartupFailureAfterCleanup(error, close)",
      runtimeOpen,
    );
    if (
      !/import\s+\{[\s\S]{0,300}?\bIncompleteCanaryCleanupError\b[\s\S]{0,300}?\bacquireCanaryResource\b[\s\S]{0,200}?\bacquireCanaryResourceAsync\b[\s\S]{0,200}?\bcloseCanaryResourceSet\b[\s\S]{0,200}?\brethrowCanaryStartupFailureAfterCleanup\b[\s\S]{0,120}?\}\s+from\s+"\.\/canary-operator-startup-cleanup\.js"/u.test(
        core,
      ) ||
      !/import\s+\{[\s\S]{0,180}?\bassertCanaryProfileLockForDatabasePath\b[\s\S]{0,180}?\btype\s+CanaryProfileLockLease\b[\s\S]{0,100}?\}\s+from\s+"\.\/profile-service-lock-core\.js"/u.test(
        core,
      ) ||
      !/startBaseRpcCanaryOperatorWithHost\s*\([\s\S]{0,500}?profileLock\s*:\s*CanaryProfileLockLease/u.test(
        startCore,
      ) ||
      leaseAssertion < 0 ||
      requestedPaths < leaseAssertion ||
      storageInspection < requestedPaths ||
      runtimeOpen < storageInspection ||
      cleanlyRethrow < runtimeOpen ||
      closeGuard < storageInspection ||
      activateClosing < closeGuard ||
      closeProviderAdmission < activateClosing ||
      outerClose < closeProviderAdmission ||
      initialStop < outerClose ||
      initialStopCallback !== firstCleanupCallback ||
      stopAdmission < initialStop ||
      drainProvider < stopAdmission ||
      closeEventStore < drainProvider ||
      finalStop < closeEventStore ||
      closeRuntime < finalStop ||
      closeSetEnd < closeRuntime ||
      !/^\s*$/u.test(startCore.slice(finalRuntimeShutdownEnd, closeSetEnd)) ||
      finalRuntimeShutdown.length === 0 ||
      /\bawait\b/u.test(finalRuntimeShutdown) ||
      !/const\s+failures\s*:\s*unknown\[\]\s*=\s*\[\];[\s\S]{0,160}?try\s*\{\s*runtime\?\.stop\([\s\S]{0,180}?\}\s*catch\s*\(error\)\s*\{\s*failures\.push\(error\);?\s*\}[\s\S]{0,120}?try\s*\{\s*runtime\?\.close\(\);?\s*\}\s*catch\s*\(error\)\s*\{\s*failures\.push\(error\);?\s*\}[\s\S]{0,180}?throw\s+new\s+AggregateError\(failures,/u.test(
        finalRuntimeShutdown,
      ) ||
      guardedControlsConstruction < runtimeOpen ||
      guardedRuntimeControls.length === 0 ||
      !/const\s+controls\s*=\s*createRuntimeOperatorControls\(\{\s*controller\s*\}\)/u.test(
        guardedRuntimeControls,
      ) ||
      !/if\s*\(isHostClosing\(\)\)\s*\{\s*throw\s+new\s+RuntimeConflictError\(\s*"STALE_STATE"/u.test(
        guardedRuntimeControls,
      ) ||
      countMatches(guardedRuntimeControls, /assertHostOpen\(\)/gu) !== 2 ||
      !/executeRuntimeControl\([^)]*\)[\s\S]{0,160}?assertHostOpen\(\);[\s\S]{0,160}?controls\.executeRuntimeControl/u.test(
        guardedRuntimeControls,
      ) ||
      !/getRuntimeSnapshot\(\)[\s\S]{0,120}?assertHostOpen\(\);[\s\S]{0,120}?controls\.getRuntimeSnapshot/u.test(
        guardedRuntimeControls,
      ) ||
      countMatches(startCore, /runtime\?\.stop\s*\(/gu) !== 2 ||
      countMatches(startCore, /canary\?\.beginClosing\s*\(\s*\)/gu) !== 1 ||
      countMatches(startCore, /createHostClosingRuntimeControls\s*\(/gu) !== 1 ||
      countMatches(
        startCore,
        /assertCanaryProfileLockForDatabasePath\s*\(\s*profileLock\s*,\s*options\.databasePath\s*\)/gu,
      ) !== 1 ||
      countMatches(
        startCore,
        /return\s+rethrowCanaryStartupFailureAfterCleanup\s*\(\s*error\s*,\s*close\s*\)/gu,
      ) !== 1 ||
      countMatches(core, /acquireCanaryResource\s*\(/gu) !== 8 ||
      countMatches(core, /acquireCanaryResourceAsync\s*\(/gu) !== 3 ||
      countMatches(core, /closeCanaryResourceSet\s*\(/gu) !== 4 ||
      !/#incompleteCleanupError\s*:\s*IncompleteCanaryCleanupError\s*\|\s*null\s*=\s*null/u.test(
        core,
      ) ||
      !/#activeStatus\s*:\s*Promise<Readonly<BaseRpcReadCanaryProjectionV1>>\s*\|\s*null\s*=\s*null/u.test(
        core,
      ) ||
      !/if\s*\(this\.#activeStatus\s*!==\s*null\)\s*return\s+this\.#activeStatus/u.test(core) ||
      !/this\.#activeStatus\s*=\s*status/u.test(core) ||
      !/if\s*\(this\.#activeStatus\s*===\s*status\)\s*this\.#activeStatus\s*=\s*null/u.test(core) ||
      !/void\s+status\.then\(clear,\s*\(error:\s*unknown\)\s*=>\s*\{\s*this\.#latchIncompleteCleanupError\(error\);\s*clear\(\);\s*\}\)/u.test(
        core,
      ) ||
      !/const\s+activeStatus\s*=\s*this\.#activeStatus/u.test(core) ||
      !/await\s+Promise\.all\(\s*\[\s*this\.#awaitActiveWork\(activeRun\),\s*this\.#awaitActiveWork\(activeRecovery\),\s*this\.#awaitActiveWork\(activeStatus\),?\s*\]\s*\)/u.test(
        core,
      ) ||
      !/if\s*\(this\.#incompleteCleanupError\s*!==\s*null\)\s*throw\s+this\.#incompleteCleanupError/u.test(
        core,
      ) ||
      !/if\s*\(error\s+instanceof\s+IncompleteCanaryCleanupError\)\s*\{\s*this\.#closing\s*=\s*true;\s*this\.#incompleteCleanupError\s*\?\?=\s*error/u.test(
        core,
      ) ||
      abortActive.length === 0 ||
      !/this\.#abortEpoch\s*\+=\s*1;\s*this\.#activeController\?\.abortActive\(\)/u.test(
        abortActive,
      ) ||
      beginClosing.length === 0 ||
      !/beginClosing\(\)\s*:\s*void\s*\{\s*if\s*\(this\.#closingBegan\)\s*return;\s*this\.#closingBegan\s*=\s*true;\s*this\.#closing\s*=\s*true;\s*try\s*\{\s*this\.abortActive\(\);\s*\}\s*catch\s*\(error\)\s*\{\s*this\.#latchIncompleteCleanupError\(error\);\s*this\.#admissionAbortFailure\s*\?\?=\s*error/u.test(
        beginClosing,
      ) ||
      providerClose.length === 0 ||
      !/async\s+close\(\)\s*:\s*Promise<void>\s*\{\s*this\.beginClosing\(\)/u.test(providerClose) ||
      !/await\s+Promise\.all\([\s\S]{0,300}?activeRun[\s\S]{0,160}?activeRecovery[\s\S]{0,160}?activeStatus[\s\S]{0,200}?\);[\s\S]{0,160}?if\s*\(this\.#incompleteCleanupError\s*!==\s*null\)[\s\S]{0,200}?if\s*\(this\.#admissionAbortFailure\s*!==\s*undefined\)/u.test(
        providerClose,
      )
    ) {
      violations.push(
        `${HOST_CORE_FILE} must assert its authentic lease before storage, single-flight and drain status work, synchronously close provider admission and runtime control before STOP, drain server/provider/storage, then synchronously STOP-and-close runtime while retaining the lock across uncertain cleanup`,
      );
    }
    const executeCanary = classMethodSlice(
      core,
      "KeychainBaseRpcReadCanaryProvider",
      "executeBaseRpcReadCanary",
    );
    const afterRecovery = classMethodSlice(
      core,
      "KeychainBaseRpcReadCanaryProvider",
      "executeAfterRecovery",
    );
    const liveStart = core.indexOf("async #runWithKeychain(");
    const liveEnd = core.indexOf("\n  async #recoverInterruptedIfPossible(", liveStart);
    const live = liveStart < 0 || liveEnd < 0 ? "" : core.slice(liveStart, liveEnd);
    const executeSnapshot = executeCanary.indexOf("const runtime = this.runtime.getSnapshot()");
    const executeMode = executeCanary.indexOf('runtime.mode !== "RESEARCH"', executeSnapshot);
    const executeRevision = executeCanary.indexOf(
      "runtime.revision !== command.expectedRuntimeRevision",
      executeMode,
    );
    const executeReceipt = executeCanary.indexOf("this.#existingReceipt()", executeRevision);
    const executeEpoch = executeCanary.indexOf(
      "this.#executeAfterRecovery(command, this.#abortEpoch)",
      executeReceipt,
    );
    const recoveryCall = afterRecovery.indexOf("await this.#recoverInterruptedIfPossible(false)");
    const recoveryClosing = afterRecovery.indexOf("this.#closing", recoveryCall);
    const recoveryEpoch = afterRecovery.indexOf("this.#abortEpoch !== abortEpoch", recoveryClosing);
    const recoveryReceipt = afterRecovery.indexOf("this.#existingReceipt()", recoveryEpoch);
    const recoveryRun = afterRecovery.indexOf(
      "this.#runWithKeychain(command, abortEpoch)",
      recoveryReceipt,
    );
    const preSnapshot = live.indexOf("const runtimeBeforeClaim = this.runtime.getSnapshot()");
    const preMode = live.indexOf('runtimeBeforeClaim.mode !== "RESEARCH"', preSnapshot);
    const preRevision = live.indexOf(
      "runtimeBeforeClaim.revision !== command.expectedRuntimeRevision",
      preMode,
    );
    const claimCall = live.indexOf("await this.claimHost.claim()", preRevision);
    const ownership = live.indexOf("this.#ownedCanaryClaim = true", claimCall);
    const postSnapshot = live.indexOf(
      "const runtimeAfterClaim = this.runtime.getSnapshot()",
      ownership,
    );
    const postClosing = live.indexOf("this.#closing", postSnapshot);
    const postEpoch = live.indexOf("this.#abortEpoch !== abortEpoch", postClosing);
    const postMode = live.indexOf('runtimeAfterClaim.mode !== "RESEARCH"', postEpoch);
    const postRevision = live.indexOf(
      "runtimeAfterClaim.revision !== command.expectedRuntimeRevision",
      postMode,
    );
    const reveal = live.indexOf("this.credentialHost.withSecrets(", postRevision);
    if (
      executeCanary.length === 0 ||
      executeSnapshot < 0 ||
      executeMode < executeSnapshot ||
      executeRevision < executeMode ||
      executeReceipt < executeRevision ||
      executeEpoch < executeReceipt ||
      afterRecovery.length === 0 ||
      recoveryCall < 0 ||
      recoveryClosing < recoveryCall ||
      recoveryEpoch < recoveryClosing ||
      recoveryReceipt < recoveryEpoch ||
      recoveryRun < recoveryReceipt ||
      preSnapshot < 0 ||
      preMode < preSnapshot ||
      preRevision < preMode ||
      claimCall < preRevision ||
      ownership < claimCall ||
      postSnapshot < ownership ||
      postClosing < postSnapshot ||
      postEpoch < postClosing ||
      postMode < postEpoch ||
      postRevision < postMode ||
      reveal < postRevision ||
      !/await\s+this\.claimHost\.claim\(\);(?:\s*\/\/[^\n]*)?\s*this\.#ownedCanaryClaim\s*=\s*true;\s*const\s+runtimeAfterClaim/u.test(
        live,
      ) ||
      countMatches(live, /this\.claimHost\.claim\(\)/gu) !== 1 ||
      countMatches(live, /this\.credentialHost\.withSecrets\s*\(/gu) !== 1
    ) {
      violations.push(
        `${HOST_CORE_FILE} must reject stale runtime state before admission and claim, carry the abort epoch, own the marker immediately after claim, then recheck closing/runtime before provider credentials`,
      );
    }
    const initializeStart = core.indexOf("async initialize(");
    const initializeEnd = core.indexOf("\n  async #executeAfterRecovery(", initializeStart);
    const initialize =
      initializeStart < 0 || initializeEnd < 0 ? "" : core.slice(initializeStart, initializeEnd);
    if (
      !/const\s+claimStatus\s*=\s*await\s+this\.claimHost\.status\(\)/u.test(initialize) ||
      !/projection\.lastReceipt\s*===\s*null\s*&&\s*claimStatus\s*===\s*"present"/u.test(
        initialize,
      ) ||
      !/projection\.lastReceipt\s*!==\s*null\s*&&\s*claimStatus\s*!==\s*"present"/u.test(
        initialize,
      ) ||
      /(?:withSecrets|fetch\s*\(|BaseRpcReadCanaryController)/u.test(initialize)
    ) {
      violations.push(
        `${HOST_CORE_FILE} must require exact agreement between durable receipt state and the permanent Base marker`,
      );
    }
    const storageStart = core.indexOf("async #recoverWithStorageSecrets(");
    const storageEnd = core.indexOf("\n}", storageStart);
    const storageRecovery =
      storageStart < 0 || storageEnd < 0 ? "" : core.slice(storageStart, storageEnd);
    if (
      !/withStorageSecrets\s*\(/u.test(storageRecovery) ||
      /claimHost|secrets\.apiKey|createBaseRpcAnchorCollector|withSecrets/u.test(storageRecovery)
    ) {
      violations.push(
        `${HOST_CORE_FILE} restart recovery must remain marker-free, API-key-free, collectorless, and storage-only`,
      );
    }
    if (
      !/PRIVATE_DIRECTORY_MODE\s*=\s*0o700n/u.test(core) ||
      !/parentEntry\.uid\s*!==\s*EFFECTIVE_USER_ID/u.test(core)
    ) {
      violations.push(`${HOST_CORE_FILE} must verify an owner-owned mode-0700 data directory`);
    }
    const databaseIdentity = functionSlice(core, "resolveDatabaseIdentity");
    const databaseFileRequirements = [
      /lstat\(canonicalPath,\s*\{\s*bigint:\s*true\s*\}\)/u,
      /entry\.isSymbolicLink\(\)/u,
      /!entry\.isFile\(\)/u,
      /entry\.nlink\s*!==\s*1n/u,
      /entry\.uid\s*!==\s*EFFECTIVE_USER_ID/u,
      /stat\(canonicalPath,\s*\{\s*bigint:\s*true\s*\}\)/u,
      /!identity\.isFile\(\)/u,
      /identity\.nlink\s*!==\s*1n/u,
      /identity\.uid\s*!==\s*EFFECTIVE_USER_ID/u,
      /identity\.dev\s*!==\s*entry\.dev/u,
      /identity\.ino\s*!==\s*entry\.ino/u,
    ];
    if (
      databaseIdentity.length === 0 ||
      databaseFileRequirements.some((pattern) => !pattern.test(databaseIdentity))
    ) {
      violations.push(
        `${HOST_CORE_FILE} must accept only owner-owned, single-link database files with stable identity`,
      );
    }
  }
}

function interfacePropertyNames(source, interfaceName) {
  const start = source.indexOf(`export interface ${interfaceName}`);
  if (start < 0) return [];
  const end = source.indexOf("\n}", start);
  if (end < 0) return [];
  return [...source.slice(start, end).matchAll(/^\s+readonly\s+([A-Za-z_$][\w$]*)\s*[?:]/gmu)]
    .map((match) => match[1])
    .sort();
}

function verifyOperatorBoundary(root, graph, violations) {
  const projection = requireSource(root, OPERATOR_PROJECTION_FILE, graph, violations);
  const server = requireSource(root, OPERATOR_SERVER_FILE, graph, violations);
  const dashboard = requireSource(root, OPERATOR_DASHBOARD_FILE, graph, violations);

  if (projection !== undefined) {
    const actual = interfacePropertyNames(projection, "OperatorBaseRpcReadCanaryReceiptV1");
    const expected = [
      "freshnessVerdict",
      "outcome",
      "planId",
      "providerReportedFinalized",
      "schemaVersion",
    ].sort();
    const parseReceipt = functionSlice(projection, "parseOperatorBaseRpcReadCanaryReceipt");
    if (
      actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index]) ||
      !/return\s+Object\.freeze\(\{[\s\S]{0,500}?schemaVersion:\s*1,[\s\S]{0,500}?planId:\s*BASE_RPC_READ_CANARY_PLAN_ID,[\s\S]{0,500}?outcome:\s*receipt\.outcome,[\s\S]{0,500}?providerReportedFinalized:\s*receipt\.providerReportedFinalized,[\s\S]{0,500}?freshnessVerdict:\s*receipt\.freshnessVerdict/u.test(
        parseReceipt,
      ) ||
      /\b(?:requestId|attemptId|captureId|eventHash|blockHash|parentHash|blockNumber|raw|byteLength|ledgerReserve|actualCharge|requestFingerprint|completedAt)\s*:/iu.test(
        parseReceipt,
      )
    ) {
      violations.push(
        `${OPERATOR_PROJECTION_FILE} must expose only the five reviewed content-free receipt fields`,
      );
    }
  }

  if (server !== undefined) {
    const routeStart = server.indexOf("async function route(");
    const routeEnd = server.indexOf(
      "\nexport async function startBaseRpcOperatorServer",
      routeStart,
    );
    const route = routeStart < 0 || routeEnd < 0 ? "" : server.slice(routeStart, routeEnd);
    const stop = route.indexOf('command.action === "runtime-stop"');
    const abort = route.indexOf("options.readCanary.abortActive()", stop);
    const durableStop = route.indexOf("options.runtime.executeRuntimeControl(command)", abort);
    const runRoute = route.indexOf('url.pathname === "/api/base-rpc-read-canary/run"');
    const parseCommand = route.indexOf("parseOperatorBaseRpcReadCanaryCommand(", runRoute);
    const runningGuard = route.indexOf("if (routeState.running)", parseCommand);
    const dispatch = route.indexOf(
      "options.readCanary.executeBaseRpcReadCanary(command)",
      runningGuard,
    );
    const publicParse = route.indexOf("parseOperatorBaseRpcReadCanaryReceipt(", runningGuard);
    if (
      stop < 0 ||
      abort < stop ||
      durableStop < abort ||
      runRoute < 0 ||
      parseCommand < runRoute ||
      runningGuard < parseCommand ||
      publicParse < runningGuard ||
      dispatch < runningGuard ||
      !/runtime\.mode\s*!==\s*"RESEARCH"/u.test(route) ||
      !/sendJson\(response,\s*200,\s*\{\s*result\s*\}\)/u.test(route)
    ) {
      violations.push(
        `${OPERATOR_SERVER_FILE} must abort before durable STOP and expose only parsed public one-shot Base results`,
      );
    }
    const start = functionSlice(server, "startBaseRpcOperatorServer");
    if (
      !/"default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; "/u.test(
        server,
      ) ||
      !/"permissions-policy":\s*"camera=\(\), microphone=\(\), geolocation=\(\), payment=\(\)"/u.test(
        server,
      ) ||
      !/const\s+host\s*=\s*options\.host\s*\?\?\s*"127\.0\.0\.1"/u.test(start) ||
      !/host\s*!==\s*"127\.0\.0\.1"\s*&&\s*host\s*!==\s*"::1"/u.test(start) ||
      !/server\.listen\s*\(\s*\{\s*host\s*,\s*port\s*\}\s*\)/u.test(start)
    ) {
      violations.push(
        `${OPERATOR_SERVER_FILE} must remain CSP-constrained, payment-disabled, and loopback-only`,
      );
    }
  }

  if (dashboard !== undefined) {
    try {
      const html = extractNoSubstitutionTemplate(dashboard, "BASE_RPC_OPERATOR_DASHBOARD_HTML");
      const css = extractNoSubstitutionTemplate(dashboard, "BASE_RPC_OPERATOR_DASHBOARD_CSS");
      const javaScript = extractNoSubstitutionTemplate(dashboard, "BASE_RPC_OPERATOR_DASHBOARD_JS");
      if (sha256(html) !== REVIEWED_DASHBOARD_HTML_SHA256) {
        violations.push(`${OPERATOR_DASHBOARD_FILE} must serve the exact reviewed HTML asset`);
      }
      if (sha256(css) !== REVIEWED_DASHBOARD_CSS_SHA256) {
        violations.push(`${OPERATOR_DASHBOARD_FILE} must serve the exact reviewed CSS asset`);
      }
      if (sha256(javaScript) !== REVIEWED_DASHBOARD_JS_SHA256) {
        violations.push(
          `${OPERATOR_DASHBOARD_FILE} must serve the exact reviewed JavaScript asset`,
        );
      }
    } catch (error) {
      violations.push(`${OPERATOR_DASHBOARD_FILE} ${error.message}`);
    }
    const runStart = dashboard.indexOf("async function runCanary()");
    const runEnd = dashboard.indexOf("\n  async function refreshCredentialStatus", runStart);
    const run = runStart < 0 || runEnd < 0 ? "" : dashboard.slice(runStart, runEnd);
    const latch = run.indexOf("canarySubmitted = true");
    const request = run.indexOf('requestJson("/api/base-rpc-read-canary/run"', latch);
    if (
      countMatches(dashboard, /let\s+canarySubmitted\s*=\s*false/gu) !== 1 ||
      countMatches(dashboard, /canarySubmitted\s*=\s*true/gu) !== 1 ||
      !/byId\("canary-run"\)\.disabled\s*=\s*canarySubmitted\s*\|\|\s*pendingCanary/u.test(
        dashboard,
      ) ||
      latch < 0 ||
      request < latch ||
      /canarySubmitted\s*=\s*false/u.test(run) ||
      /https?:\/\/|wss?:\/\/|WebSocket|eth_sendTransaction|wallet_sendCalls|window\.ethereum/u.test(
        dashboard,
      )
    ) {
      violations.push(
        `${OPERATOR_DASHBOARD_FILE} must latch the first browser submission before its only relative one-shot command and expose no wallet/network authority`,
      );
    }
    if (
      !/<dt>Actual charge<\/dt><dd>UNKNOWN — PROVIDER ACCOUNT<\/dd>/u.test(dashboard) ||
      /<dt>Actual charge<\/dt><dd>NONE<\/dd>/u.test(dashboard)
    ) {
      violations.push(
        `${OPERATOR_DASHBOARD_FILE} must describe provider-billed actual charge as unknown, never none`,
      );
    }
  }
}

function verifyEarlySignalCleanup(entry, violations) {
  const operator = entry.indexOf("let operator:");
  const closeOperator = entry.indexOf("const closeOperator =");
  const signalHandler = entry.indexOf("const handleSignal =");
  const armInterrupt = entry.indexOf('process.once("SIGINT", handleSignal)');
  const armTerminate = entry.indexOf('process.once("SIGTERM", handleSignal)');
  const start = entry.indexOf("operator = await startBaseRpcCanaryOperator()");
  const firstShutdownCheck = entry.indexOf("if (shutdownRequested)", start);
  const startupLine = entry.indexOf("const startupLine", firstShutdownCheck);
  const secondShutdownCheck = entry.indexOf("if (shutdownRequested)", startupLine);
  const output = entry.indexOf("process.stdout.write(startupLine)", secondShutdownCheck);
  const catchStart = entry.indexOf("} catch {", start);
  const catchClose = entry.indexOf("await closeOperator().catch(() => undefined)", catchStart);
  const catchRemove = entry.indexOf("removeSignalHandlers();", catchClose);
  if (
    operator < 0 ||
    closeOperator < operator ||
    signalHandler < closeOperator ||
    armInterrupt < signalHandler ||
    armTerminate < signalHandler ||
    start < armInterrupt ||
    start < armTerminate ||
    firstShutdownCheck < start ||
    startupLine < firstShutdownCheck ||
    secondShutdownCheck < startupLine ||
    output < secondShutdownCheck ||
    catchStart < start ||
    catchClose < catchStart ||
    catchRemove < catchClose ||
    countMatches(entry, /process\.once\(\s*"SIGINT"\s*,\s*handleSignal\s*\)/gu) !== 1 ||
    countMatches(entry, /process\.once\(\s*"SIGTERM"\s*,\s*handleSignal\s*\)/gu) !== 1 ||
    countMatches(entry, /process\.off\(\s*"SIG(?:INT|TERM)"\s*,\s*handleSignal\s*\)/gu) !== 2 ||
    countMatches(entry, /operator\.close\(\)/gu) !== 1 ||
    !/closePromise\s*\?\?=\s*operator\.close\(\)/u.test(entry) ||
    !/const\s+handleSignal\s*=\s*\(\)\s*:\s*void\s*=>\s*\{\s*shutdownRequested\s*=\s*true;\s*if\s*\(operator\s*===\s*undefined\)\s*return;/u.test(
      entry,
    )
  ) {
    violations.push(
      `${ENTRY} must latch early signals and finish lock-bearing shutdown before exit`,
    );
  }
}

function verifyProductionLaunchBoundary(root, graph, violations) {
  const options = requireSource(root, OPTIONS_FILE, graph, violations);
  const entry = requireSource(root, ENTRY, graph, violations);
  const config = requireSource(root, PRODUCTION_CONFIG_FILE, graph, violations);
  const runtime = requireSource(root, PRODUCTION_RUNTIME_FILE, graph, violations);
  requireSource(root, CANARY_STARTUP_CLEANUP_FILE, graph, violations);
  requireSource(root, PROFILE_LOCK_FILE, graph, violations);
  requireSource(root, PROFILE_LOCK_CORE_FILE, graph, violations);
  if (options !== undefined) {
    if (
      !/argument\s*===\s*"--help"\s*\|\|\s*argument\s*===\s*"-h"/u.test(options) ||
      !/throw\s+new\s+Error\("Base RPC canary production options are fixed"\)/u.test(options) ||
      /["']--(?:db|research-db|port)["']/u.test(options) ||
      /\b(?:cwd|env|homedir)\s*\(/u.test(options) ||
      /\bprocess\b/u.test(options)
    ) {
      violations.push(
        `${OPTIONS_FILE} must reject every production path, endpoint, and port override`,
      );
    }
  }
  if (config !== undefined) {
    const baseOptions = functionSlice(config, "productionBaseRpcCanaryHostOptions");
    if (
      !/CLI_PACKAGE_DIRECTORY\s*=\s*resolve\(import\.meta\.dirname,\s*"\.\."\)/u.test(config) ||
      !/PRODUCTION_DATA_DIRECTORY\s*=\s*resolve\(CLI_PACKAGE_DIRECTORY,\s*"\.local"\)/u.test(
        config,
      ) ||
      !/PRODUCTION_CANARY_PORT\s*=\s*8_787\s+as\s+const/u.test(config) ||
      !/databasePath:\s*resolve\(PRODUCTION_DATA_DIRECTORY,\s*"rsi-base-rpc-canary-runtime\.sqlite"\)/u.test(
        baseOptions,
      ) ||
      !/port:\s*PRODUCTION_CANARY_PORT/u.test(baseOptions) ||
      /\b(?:cwd|homedir|process\.env)\b/u.test(baseOptions)
    ) {
      violations.push(
        `${PRODUCTION_CONFIG_FILE} must own the absolute Base storage path and fixed loopback port 8787`,
      );
    }
  }
  if (runtime !== undefined) {
    if (
      !/PRODUCTION_NODE_VERSION\s*=\s*"24\.19\.0"\s+as\s+const/u.test(runtime) ||
      !/PRODUCTION_PNPM_VERSION\s*=\s*"11\.20\.0"\s+as\s+const/u.test(runtime) ||
      !/value\.nodeVersion\s*!==\s*PRODUCTION_NODE_VERSION/u.test(runtime) ||
      !/pnpmVersionFromUserAgent\(value\.packageManagerUserAgent\)\s*!==\s*PRODUCTION_PNPM_VERSION/u.test(
        runtime,
      )
    ) {
      violations.push(
        `${PRODUCTION_RUNTIME_FILE} must make the Node 24.19.0 and pnpm 11.20.0 assertion exact and fail closed`,
      );
    }
  }
  if (entry !== undefined) {
    const parse = entry.indexOf("parseBaseRpcCanaryOperatorOptions(process.argv.slice(2))");
    const runtimeCheck = entry.indexOf("assertActiveProductionRuntime();", parse);
    const start = entry.indexOf("await startBaseRpcCanaryOperator()", runtimeCheck);
    if (
      parse < 0 ||
      runtimeCheck < parse ||
      start < runtimeCheck ||
      countMatches(entry, /assertActiveProductionRuntime\s*\(\s*\)/gu) !== 1 ||
      !/STARTUP_FAILURE_MESSAGE\s*=\s*"RSI Base RPC read canary startup was refused\.\\n"/u.test(
        entry,
      ) ||
      countMatches(entry, /process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)/gu) !== 2 ||
      !/catch\s*\{[\s\S]{0,120}?process\.stderr\.write\(PRODUCTION_RUNTIME_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      !/catch\s*\{[\s\S]{0,180}?await\s+closeOperator\(\)\.catch\(\(\)\s*=>\s*undefined\)[\s\S]{0,180}?process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)/u.test(
        entry,
      ) ||
      /\bpaths\s*:/u.test(entry) ||
      /console\.(?:error|log)\(error|error\.(?:message|stack)|JSON\.stringify\(error/u.test(entry)
    ) {
      violations.push(
        `${ENTRY} must run options then exact runtime guard before host start and emit only fixed redacted startup/failure output`,
      );
    }
    verifyEarlySignalCleanup(entry, violations);
  }
}

function verifyCiBoundary(root, violations) {
  const packagePath = join(root, ROOT_PACKAGE_FILE);
  const workflowPath = join(root, CI_WORKFLOW_FILE);
  if (!existsSync(packagePath)) {
    violations.push(`${ROOT_PACKAGE_FILE} is missing`);
  } else {
    try {
      const manifest = readJson(packagePath, ROOT_PACKAGE_FILE);
      if (manifest.scripts?.["ci:base-rpc"] !== EXACT_ROOT_SCRIPT) {
        violations.push(
          `${ROOT_PACKAGE_FILE} must expose the exact ci:base-rpc authority and mutation gate`,
        );
      }
    } catch (error) {
      violations.push(`${ROOT_PACKAGE_FILE} cannot be parsed: ${error.message}`);
    }
  }
  if (!existsSync(workflowPath)) {
    violations.push(`${CI_WORKFLOW_FILE} is missing`);
  } else {
    const workflow = readFileSync(workflowPath, "utf8");
    if (
      countMatches(
        workflow,
        new RegExp(EXACT_WORKFLOW_STEP.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "gu"),
      ) !== 1
    ) {
      violations.push(`${CI_WORKFLOW_FILE} must run the exact pinned pnpm ci:base-rpc step once`);
    }
    const install = workflow.indexOf("run: pnpm install --frozen-lockfile");
    const step = workflow.indexOf(EXACT_WORKFLOW_STEP);
    const check = workflow.indexOf("run: pnpm check", step);
    if (install < 0 || step < install || check < step) {
      violations.push(
        `${CI_WORKFLOW_FILE} must run ci:base-rpc after locked install and before the general check`,
      );
    }
  }
}

export function verifyBaseRpcReadCanaryBoundary(options = {}) {
  const root = realpathSync(options.root ?? DEFAULT_ROOT);
  const violations = [];
  try {
    verifyStage1ReadCanaryBoundary({ root });
  } catch (error) {
    violations.push(`shared runtime/STOP/one-shot authority gate failed: ${error.message}`);
  }
  let packages;
  try {
    packages = discoverWorkspacePackages(root);
  } catch (error) {
    violations.push(error instanceof Error ? error.message : String(error));
    packages = new Map();
  }
  const graph = inspectGraph(root, packages);
  violations.push(...graph.violations);
  verifyRequiredImports(graph, violations);
  verifyFixedRequest(root, graph, violations);
  verifyCollectorBoundary(root, graph, violations);
  verifyIngestionBoundary(root, graph, violations);
  verifyControllerAndRecoveryBoundary(root, graph, packages, violations);
  verifyCredentialAndHostBoundary(root, graph, violations);
  verifyOperatorBoundary(root, graph, violations);
  verifyProductionLaunchBoundary(root, graph, violations);
  verifyCiBoundary(root, violations);
  const unique = [...new Set(violations)].sort();
  if (unique.length > 0) throw new BaseRpcReadCanaryVerificationFailure(unique);
  return Object.freeze({
    endpoint: EXACT_ENDPOINT,
    files: graph.files.size,
    maximumAnchors: 1,
    maximumHttpRequests: 1,
    paymentCapability: false,
    rpcMethods: Object.freeze(["eth_chainId", "eth_getBlockByNumber"]),
    status: "pass",
    transactionCapability: false,
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(THIS_FILE);
}

if (isMainModule()) {
  try {
    const result = verifyBaseRpcReadCanaryBoundary();
    console.log(
      `Base RPC READ_CANARY authority gate passed (${result.files} files, exactly ${result.maximumHttpRequests} fixed POST, two reviewed read methods, no payment or transaction authority).`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
