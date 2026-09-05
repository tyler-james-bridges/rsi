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
const ENTRY = "apps/cli/src/opensea-canary-operator.ts";

const SOURCE_CONTRACT_FILE = "packages/source-contracts/src/opensea-trending.ts";
const COLLECTOR_INDEX_FILE = "packages/opensea-collector/src/index.ts";
const COLLECTOR_FILE = "packages/opensea-collector/src/collector.ts";
const COLLECTOR_CONSTANTS_FILE = "packages/opensea-collector/src/constants.ts";
const COLLECTOR_REQUEST_FILE = "packages/opensea-collector/src/request.ts";
const CAPTURE_STORAGE_RECOVERY_FILE = "packages/ingestion/src/capture-storage-recovery.ts";
const INGESTION_FILE = "packages/ingestion/src/opensea-trending.ts";
const CONTROLLER_FILE = "packages/read-canary/src/opensea-read-canary-controller.ts";
const CONTROLLER_ENTRY_FILE = "packages/read-canary/src/opensea.ts";
const CONTROLLER_SCHEMA_FILE = "packages/read-canary/src/opensea-schemas.ts";
const CONTROLLER_CONSTANTS_FILE = "packages/read-canary/src/opensea-constants.ts";
const CREDENTIAL_ENTRY_FILE = "packages/credential-host/src/opensea-trending.ts";
const CREDENTIAL_FILE = "packages/credential-host/src/opensea-trending-keychain.ts";
const ONE_SHOT_CLAIM_FILE = "packages/credential-host/src/one-shot-claim-keychain.ts";
const ONE_SHOT_CLAIM_ENTRY_FILE = "packages/credential-host/src/one-shot-claim.ts";
const PRODUCTION_CONFIG_FILE = "apps/cli/src/production-canary-config.ts";
const PRODUCTION_RUNTIME_FILE = "apps/cli/src/production-runtime.ts";
const OPERATOR_OPTIONS_FILE = "apps/cli/src/opensea-canary-operator-options.ts";
const OPERATOR_HOST_FILE = "apps/cli/src/opensea-canary-operator-host.ts";
const OPERATOR_HOST_CORE_FILE = "apps/cli/src/opensea-canary-operator-host-core.ts";
const OPERATOR_SERVER_FILE = "apps/operator/src/opensea-server.ts";
const OPERATOR_DASHBOARD_FILE = "apps/operator/src/opensea-dashboard-assets.ts";
const EXACT_ENDPOINT =
  "https://api.opensea.io/api/v2/collections/trending?timeframe=one_day&chains=base&limit=10";
const REVIEWED_DASHBOARD_HTML_SHA256 =
  "bd8adb9cd8c7ba9ea2601a4968b693160d6a2f738f9c55b432af7dbc1965662b";
const REVIEWED_DASHBOARD_CSS_SHA256 =
  "e868fa83b7f44e014071ad05db9e97d92d39f4774ccb594bd83f5ce70f7595b3";
const REVIEWED_DASHBOARD_JS_SHA256 =
  "e28d6cf14db96547143c688d39d3a95875cff8df97b08e8670137111faf213b3";

const REQUIRED_IMPORTS = Object.freeze([
  "@rsi/capture-registry",
  "@rsi/credential-host/opensea-trending",
  "@rsi/credential-host/one-shot-claim",
  "@rsi/ingestion/capture-storage-recovery",
  "@rsi/ingestion/opensea-trending",
  "@rsi/operations",
  "@rsi/operator/opensea",
  "@rsi/opensea-collector",
  "@rsi/read-canary/opensea",
  "@rsi/runtime",
  "@rsi/source-contracts/opensea-trending",
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
  "apps/cli/src/opensea-canary-operator-options.ts",
  PRODUCTION_CONFIG_FILE,
  PRODUCTION_RUNTIME_FILE,
  OPERATOR_HOST_FILE,
  OPERATOR_HOST_CORE_FILE,
  "apps/operator/src/opensea.ts",
  OPERATOR_DASHBOARD_FILE,
  "apps/operator/src/opensea-read-canary.ts",
  OPERATOR_SERVER_FILE,
  "apps/operator/src/runtime-controls.ts",
  "apps/operator/src/runtime-types.ts",
  CREDENTIAL_ENTRY_FILE,
  CREDENTIAL_FILE,
  ONE_SHOT_CLAIM_ENTRY_FILE,
  ONE_SHOT_CLAIM_FILE,
  CAPTURE_STORAGE_RECOVERY_FILE,
  INGESTION_FILE,
  CONTROLLER_FILE,
  CONTROLLER_ENTRY_FILE,
  CONTROLLER_SCHEMA_FILE,
  CONTROLLER_CONSTANTS_FILE,
  "packages/read-canary/src/opensea-errors.ts",
  "packages/read-canary/src/opensea-types.ts",
  SOURCE_CONTRACT_FILE,
  "packages/source-contracts/src/common.ts",
  "packages/source-contracts/src/errors.ts",
]);

const FORBIDDEN_TEST_SPECIFIERS = Object.freeze([
  "@rsi/credential-host/opensea-trending-testing",
  "@rsi/opensea-collector/testing",
  "@rsi/read-canary/opensea-testing",
]);

const FORBIDDEN_LOCAL_FILE = /(?:^|\/)(?:testing|[^/]+\.testing)\.(?:[cm]?[jt]sx?)$/u;
const FORBIDDEN_AUTHORITY_PATH =
  /(?:^|[/._-])(?:adapters?|agentcash|agentpay|arbitrary[-_]?calls?|broadcast(?:er)?|calldata|deploy(?:er|ment)?|execution|executors?|orders?|payments?|policy|publications?|signers?|stream|transactions?|wallets?|x402)(?:$|[/._-])/iu;
const FORBIDDEN_EXTERNAL_PACKAGE =
  /(?:^|[/@._-])(?:agentcash|agentpay|axios|ethers|got|ky|node-fetch|permissionless|pimlico|safe-global|superagent|undici|viem|wagmi|walletconnect|web3|ws|x402)(?:$|[/@._-])/iu;
const FORBIDDEN_IDENTIFIERS = new Set([
  "AgentCash",
  "ExecutionAdapter",
  "PrivateKeyAccount",
  "WalletClient",
  "ethereum",
  "arbitraryCall",
  "broadcastTransaction",
  "createWalletClient",
  "delegatecall",
  "deployContract",
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
  "eth_sendRawTransaction",
  "eth_sendTransaction",
  "wallet_sendCalls",
]);
const FORBIDDEN_DYNAMIC_MEMBER_LITERALS = new Set([
  "AsyncFunction",
  "Function",
  "GeneratorFunction",
  "__proto__",
  "constructor",
  "eval",
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
  [ENTRY, new Set(["argv", "exitCode", "once", "stderr"])],
  [PRODUCTION_RUNTIME_FILE, new Set(["env", "versions"])],
  [OPERATOR_HOST_CORE_FILE, new Set(["geteuid"])],
  [CREDENTIAL_FILE, new Set(["platform"])],
  [ONE_SHOT_CLAIM_FILE, new Set(["platform"])],
  ["packages/capture-registry/src/sqlite-capture-registry.ts", new Set(["geteuid"])],
  ["packages/vault/src/snapshot-vault.ts", new Set(["geteuid"])],
]);

export class OpenSeaReadCanaryVerificationFailure extends Error {
  constructor(violations) {
    super(
      `OpenSea read-canary authority isolation failed:\n${violations
        .map((violation, index) => `${index + 1}. ${violation}`)
        .join("\n")}`,
    );
    this.name = "OpenSeaReadCanaryVerificationFailure";
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
    if (value === undefined) return undefined;
    return conditionTarget(value);
  }
  return subpath === "" ? conditionTarget(exportsValue) : undefined;
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
  for (const sourceExtension of SOURCE_EXTENSIONS) {
    attempts.push(join(candidate, `index${sourceExtension}`));
  }
  for (const attempt of attempts) {
    if (existsSync(attempt) && statSync(attempt).isFile()) return realpathSync(attempt);
  }
  return undefined;
}

function scanText(path, text) {
  const scanner = ts.createScanner(true, ts.LanguageVariant.Standard, text);
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
  return { path, text, tokens };
}

function scanSource(path) {
  return scanText(path, readFileSync(path, "utf8"));
}

function forbiddenExecutableString(value) {
  return (
    FORBIDDEN_DYNAMIC_MEMBER_LITERALS.has(value) ||
    /\b(?:import|require)\s*\(/u.test(value) ||
    /\bprocess\s*(?:\.|\[)/u.test(value) ||
    /\breturn\s+(?:global|globalThis|self|window)\b/u.test(value) ||
    /\b(?:global|globalThis|self|window)\s*(?:\.|\[)[\s\S]*\bfetch\b/u.test(value)
  );
}

function analyzeSource(source) {
  const imports = [];
  const identifiers = new Set();
  const literals = new Set();
  const violations = [];
  const globalFetchReferences = [];
  const globalObjectReferences = [];
  const bareFetchReferences = [];
  const fetchReferences = [];
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
      if (identifier === "fetch") fetchReferences.push(index);
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
      if (["WebSocket", "EventSource", "XMLHttpRequest", "sendBeacon"].includes(identifier)) {
        violations.push(`references unapproved network global ${identifier}`);
      }
      if (
        [
          "WebSocketStream",
          "WebTransport",
          "Worker",
          "SharedWorker",
          "RTCPeerConnection",
          "Image",
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
        violations.push(`declares forbidden transaction literal ${literalValue}`);
      }
      if (forbiddenExecutableString(literalValue)) {
        violations.push("declares a dynamic-code or capability-bearing executable string");
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
      if (parts > 1 && forbiddenExecutableString(concatenated)) {
        violations.push("constructs a dynamic-code or capability-bearing executable string");
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
    if (
      identifier === "process" &&
      ((source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
        source.tokens[index + 2]?.value === "env") ||
        (source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenBracketToken &&
          literal(source.tokens[index + 2]) === "env"))
    ) {
      violations.push("references ambient process.env");
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
      ["fetch", "process", "WebSocket", "EventSource", "XMLHttpRequest"].includes(
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
      (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "get" &&
      source.tokens[index + 3]?.kind === ts.SyntaxKind.OpenParenToken &&
      ["global", "globalThis", "self", "window"].includes(
        source.tokens[index + 4]?.value ?? source.tokens[index + 4]?.text,
      ) &&
      source.tokens[index + 5]?.kind === ts.SyntaxKind.CommaToken &&
      literal(source.tokens[index + 6]) === "fetch"
    ) {
      violations.push("references reflected global fetch capability");
    }
    if (
      identifier === "fetch" &&
      source.tokens[index - 1]?.kind !== ts.SyntaxKind.DotToken &&
      !(
        source.tokens[index + 1]?.kind === ts.SyntaxKind.QuestionToken &&
        source.tokens[index + 2]?.kind === ts.SyntaxKind.ColonToken
      )
    ) {
      bareFetchReferences.push(index);
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
      if (from < 0) {
        violations.push("contains a non-literal import");
        continue;
      }
      const specifier = literal(source.tokens[from + 1]);
      if (specifier === undefined) {
        violations.push("contains a non-literal import");
        continue;
      }
      const names = [];
      for (let cursor = index + 1; cursor < from; cursor += 1) {
        if (source.tokens[cursor].kind === ts.SyntaxKind.Identifier) {
          names.push(source.tokens[cursor].value);
        }
      }
      imports.push({ names, specifier, typeOnly });
      continue;
    }

    if (token.kind === ts.SyntaxKind.ExportKeyword) {
      const next = source.tokens[index + 1];
      const typeOnly = next?.kind === ts.SyntaxKind.TypeKeyword;
      const declarationStart = typeOnly ? index + 2 : index + 1;
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
        else imports.push({ names: [], specifier, typeOnly });
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
    bareFetchReferences,
    fetchReferences,
    globalFetchReferences,
    globalObjectReferences,
    identifiers,
    imports,
    literals,
    processProperties,
    tokens: source.tokens,
    violations,
  };
}

function allowedFile(relativeFile) {
  if (FORBIDDEN_LOCAL_FILE.test(relativeFile)) return false;
  if (relativeFile.startsWith("packages/opensea-collector/src/")) {
    return relativeFile !== "packages/opensea-collector/src/testing.ts";
  }
  return (
    REVIEWED_EXACT_FILES.has(relativeFile) ||
    REVIEWED_PREFIXES.some((prefix) => relativeFile.startsWith(prefix))
  );
}

function classifySpecifier(specifier, relativeFile, names) {
  if (
    FORBIDDEN_TEST_SPECIFIERS.some(
      (forbidden) => specifier === forbidden || specifier.startsWith(`${forbidden}/`),
    )
  ) {
    return `test-only import ${specifier}`;
  }
  if (specifier === "@rsi/credential-host") {
    return "generic credential-host root instead of the dedicated OpenSea entry";
  }
  if (specifier === "@rsi/read-canary") {
    return "generic read-canary root instead of the dedicated OpenSea entry";
  }
  if (specifier === "@rsi/ingestion") {
    return "generic ingestion root instead of the dedicated OpenSea entry";
  }
  if (specifier === "@rsi/adapters" || specifier.startsWith("@rsi/adapters/")) {
    return `execution-adapter import ${specifier}`;
  }
  if (specifier === "@rsi/policy" || specifier.startsWith("@rsi/policy/")) {
    return `policy authority import ${specifier}`;
  }
  if (FORBIDDEN_EXTERNAL_PACKAGE.test(specifier)) return `financial/network package ${specifier}`;
  if (FORBIDDEN_NETWORK_MODULES.has(specifier)) return `unapproved network module ${specifier}`;
  if (specifier === "node:http" || specifier === "node:net") {
    if (relativeFile !== OPERATOR_SERVER_FILE) {
      return `loopback server module ${specifier} outside ${OPERATOR_SERVER_FILE}`;
    }
    const expected =
      specifier === "node:http"
        ? ["IncomingMessage", "Server", "ServerResponse", "createServer"]
        : ["BlockList", "isIP"];
    const imported = [...new Set(names)].sort();
    return imported.length === expected.length &&
      imported.every((name, index) => name === [...expected].sort()[index])
      ? undefined
      : `${specifier} capability beyond the exact loopback server surface`;
  }
  if (FORBIDDEN_PROCESS_MODULES.has(specifier)) {
    if (
      specifier === "node:child_process" &&
      (relativeFile === CREDENTIAL_FILE || relativeFile === ONE_SHOT_CLAIM_FILE)
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
        "KeyObject",
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

function inspectGraph(root, packages) {
  const violations = [];
  const analyses = new Map();
  const files = new Set();
  const imports = new Set();
  const entry = resolveSourceFile(join(root, ENTRY));
  if (entry === undefined) {
    return { analyses, files, imports, violations: [`production entrypoint ${ENTRY} is missing`] };
  }
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop();
    if (files.has(file)) continue;
    files.add(file);
    const relativeFile = canonicalRelative(root, file);
    if (!allowedFile(relativeFile)) {
      violations.push(`production graph reaches unreviewed or test-only source ${relativeFile}`);
    }
    if (FORBIDDEN_AUTHORITY_PATH.test(relativeFile)) {
      violations.push(`production graph reaches forbidden authority source ${relativeFile}`);
    }
    let analysis;
    try {
      analysis = analyzeSource(scanSource(file));
      analyses.set(file, analysis);
    } catch (error) {
      violations.push(`${relativeFile} cannot be parsed: ${error.message}`);
      continue;
    }
    for (const violation of analysis.violations) {
      if (
        relativeFile !== PRODUCTION_RUNTIME_FILE ||
        violation !== "references ambient process.env"
      ) {
        violations.push(`${relativeFile} ${violation}`);
      }
    }
    const allowedProcess = REVIEWED_PROCESS_PROPERTIES.get(relativeFile);
    const unreviewedProcess = analysis.processProperties.filter(
      (property) => allowedProcess === undefined || !allowedProcess.has(property),
    );
    if (unreviewedProcess.length > 0) {
      violations.push(
        `${relativeFile} references unapproved process capability ${[...new Set(unreviewedProcess)].join(", ")}`,
      );
    }
    for (const literalValue of analysis.literals) {
      for (const match of literalValue.matchAll(/\b(?:https?|wss?):\/\/[^"'`\s)<]*/gu)) {
        const origin = match[0];
        if (
          origin !== "http://operator.invalid" &&
          origin !== "https://api.opensea.io" &&
          origin !== EXACT_ENDPOINT
        ) {
          violations.push(`${relativeFile} declares unreviewed network origin ${origin}`);
        }
      }
    }

    for (const dependency of analysis.imports) {
      if (dependency.typeOnly) continue;
      const { specifier } = dependency;
      const classification = classifySpecifier(specifier, relativeFile, dependency.names);
      if (classification !== undefined) {
        violations.push(`${relativeFile} imports ${classification}`);
        continue;
      }
      let resolvedDependency;
      if (specifier.startsWith(".") || isAbsolute(specifier)) {
        resolvedDependency = resolveSourceFile(
          isAbsolute(specifier) ? specifier : resolve(dirname(file), specifier),
        );
        if (resolvedDependency === undefined) {
          violations.push(`${relativeFile} has unresolved local import ${specifier}`);
          continue;
        }
      } else {
        const workspace = packageForSpecifier(specifier, packages);
        if (workspace !== undefined) {
          imports.add(specifier);
          if (!REVIEWED_WORKSPACE_IMPORTS.has(specifier)) {
            violations.push(`${relativeFile} reaches unreviewed workspace import ${specifier}`);
            continue;
          }
          let target;
          try {
            target = packageTarget(workspace.workspacePackage, workspace.subpath);
          } catch (error) {
            violations.push(`${relativeFile} cannot resolve ${specifier}: ${error.message}`);
            continue;
          }
          if (target === undefined) {
            violations.push(`${relativeFile} cannot resolve workspace export ${specifier}`);
            continue;
          }
          resolvedDependency = resolveSourceFile(
            resolve(workspace.workspacePackage.directory, target),
          );
          if (resolvedDependency === undefined) {
            violations.push(`${relativeFile} cannot resolve workspace source ${specifier}`);
            continue;
          }
        } else if (SAFE_EXTERNAL_MODULES.has(specifier) || NODE_BUILTINS.has(specifier)) {
          continue;
        } else {
          violations.push(`${relativeFile} imports unreviewed external module ${specifier}`);
          continue;
        }
      }
      if (!isInside(root, resolvedDependency)) {
        violations.push(`${relativeFile} resolves outside the repository via ${specifier}`);
        continue;
      }
      const resolvedRelative = canonicalRelative(root, resolvedDependency);
      if (FORBIDDEN_LOCAL_FILE.test(resolvedRelative)) {
        violations.push(`${relativeFile} reaches test-only source ${resolvedRelative}`);
        continue;
      }
      pending.push(resolvedDependency);
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
  if (!graph.files.has(path)) {
    violations.push(`production graph does not reach reviewed source ${relativeFile}`);
  }
  return readFileSync(path, "utf8");
}

function countMatches(text, expression) {
  return [...text.matchAll(expression)].length;
}

function functionSlice(source, name) {
  const start = source.search(new RegExp(`\\b(?:async\\s+)?function\\s+${name}\\s*\\(`, "u"));
  if (start < 0) return "";
  const next = source.slice(start + 1).search(/\n(?:export\s+)?(?:async\s+)?function\s+/u);
  return source.slice(start, next < 0 ? source.length : start + 1 + next);
}

function extractNoSubstitutionTemplate(source, exportName) {
  const marker = `export const ${exportName} = \``;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`missing ${exportName} template`);
  const bodyStart = start + marker.length;
  const end = source.indexOf("`;", bodyStart);
  if (end < 0) throw new Error(`unterminated ${exportName} template`);
  const body = source.slice(bodyStart, end);
  if (body.includes("${")) {
    throw new Error(`${exportName} must not interpolate executable source`);
  }
  return body;
}

function hasComputedMemberAccess(tokens) {
  const expressionEnd = new Set([
    ts.SyntaxKind.Identifier,
    ts.SyntaxKind.StringLiteral,
    ts.SyntaxKind.NumericLiteral,
    ts.SyntaxKind.NoSubstitutionTemplateLiteral,
    ts.SyntaxKind.CloseParenToken,
    ts.SyntaxKind.CloseBracketToken,
    ts.SyntaxKind.ThisKeyword,
  ]);
  return tokens.some((token, index) => {
    if (token.kind !== ts.SyntaxKind.OpenBracketToken) return false;
    const previous = tokens[index - 1];
    if (previous !== undefined && expressionEnd.has(previous.kind)) return true;
    return (
      previous?.kind === ts.SyntaxKind.QuestionDotToken &&
      tokens[index - 2] !== undefined &&
      expressionEnd.has(tokens[index - 2].kind)
    );
  });
}

function hasBareIdentifier(tokens, name) {
  return tokens.some(
    (token, index) =>
      token.kind === ts.SyntaxKind.Identifier &&
      token.value === name &&
      tokens[index - 1]?.kind !== ts.SyntaxKind.DotToken &&
      tokens[index - 1]?.kind !== ts.SyntaxKind.QuestionDotToken,
  );
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
    const preparedRequest = functionSlice(contract, "prepareOpenSeaTrendingRequest");
    const requirements = [
      [
        /OPENSEA_TRENDING_ORIGIN\s*=\s*"https:\/\/api\.opensea\.io"\s+as\s+const/u,
        "fixed HTTPS origin",
      ],
      [
        /OPENSEA_TRENDING_PATH\s*=\s*"\/api\/v2\/collections\/trending"\s+as\s+const/u,
        "fixed trending path",
      ],
      [
        /OPENSEA_TRENDING_QUERY\s*=\s*"timeframe=one_day&chains=base&limit=10"\s+as\s+const/u,
        "Base-only one-day query with limit 10",
      ],
      [/OPENSEA_TRENDING_MAXIMUM_RESULTS\s*=\s*10\s+as\s+const/u, "maximum 10 results"],
      [/method:\s*"GET"/u, "GET-only method"],
      [/redirect:\s*"reject"/u, "redirect refusal"],
      [/retryAttempts:\s*0/u, "zero retries"],
      [/credentialHeader:\s*"x-api-key"/u, "fixed credential header"],
      [/if\s*\(arguments\.length\s*!==\s*0\)/u, "zero caller request arguments"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(contract))
        violations.push(`${SOURCE_CONTRACT_FILE} does not enforce ${label}`);
    }
    if (
      !/method:\s*"GET"/u.test(preparedRequest) ||
      !/redirect:\s*"reject"/u.test(preparedRequest) ||
      !/retryAttempts:\s*0/u.test(preparedRequest) ||
      !/credentialHeader:\s*"x-api-key"/u.test(preparedRequest)
    ) {
      violations.push(
        `${SOURCE_CONTRACT_FILE} prepared request must be GET-only with zero retries, rejected redirects, and one fixed credential header`,
      );
    }
    if (
      /URLSearchParams|cursor\s*[:=]/u.test(
        functionSlice(contract, "prepareOpenSeaTrendingRequest"),
      )
    ) {
      violations.push(
        `${SOURCE_CONTRACT_FILE} permits pagination or caller-controlled query material`,
      );
    }
  }
  if (request !== undefined) {
    const requirements = [
      [/prepareOpenSeaTrendingRequest\(\)/u, "source-contract request"],
      [/descriptor\.redirect\s*!==\s*"reject"/u, "redirect drift check"],
      [/descriptor\.retryAttempts\s*!==\s*0/u, "retry drift check"],
      [
        /descriptor\.maximumResults\s*!==\s*OPENSEA_TRENDING_MAXIMUM_RESULTS/u,
        "result-limit drift check",
      ],
      [/descriptor\.query\s*!==\s*OPENSEA_TRENDING_QUERY/u, "query drift check"],
      [/descriptor\.url\s*!==\s*OPENSEA_TRENDING_URL/u, "URL drift check"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(request)) violations.push(`${COLLECTOR_REQUEST_FILE} lacks ${label}`);
    }
  }
}

function verifyCollectorBoundary(root, graph, violations) {
  const collector = requireSource(root, COLLECTOR_FILE, graph, violations);
  const constants = requireSource(root, COLLECTOR_CONSTANTS_FILE, graph, violations);
  const index = requireSource(root, COLLECTOR_INDEX_FILE, graph, violations);
  if (constants !== undefined) {
    if (
      !/OPENSEA_TRENDING_RESERVED_ATOMIC\s*=\s*"1"\s+as\s+const/u.test(constants) ||
      !/One non-payment request slot\. This is not a provider charge estimate\./u.test(constants)
    ) {
      violations.push(
        `${COLLECTOR_CONSTANTS_FILE} must keep one USD_MICRO only as a non-payment ledger reserve`,
      );
    }
  }
  if (collector !== undefined) {
    const path = resolveSourceFile(join(root, COLLECTOR_FILE));
    const analysis = path === undefined ? undefined : graph.analyses.get(path);
    if (
      analysis === undefined ||
      analysis.globalFetchReferences.length !== 1 ||
      analysis.globalFetchReferences[0]?.globalObject !== "globalThis"
    ) {
      violations.push(`${COLLECTOR_FILE} must contain exactly one production global fetch binding`);
    }
    const collectStart = collector.indexOf("async collectRaw(");
    const collect = collectStart < 0 ? "" : collector.slice(collectStart);
    const authorization = collect.indexOf("runtimeCollectionAuthorization.consumeAndDispatch");
    const runtimeReceipt = collect.indexOf("assertRuntimeReceipt(", authorization);
    const attempt = collect.indexOf("attemptAuthorization.consume()", runtimeReceipt);
    const dispatch = collect.indexOf("executeNetworkRequest(", attempt);
    if (
      authorization < 0 ||
      runtimeReceipt < authorization ||
      attempt < runtimeReceipt ||
      dispatch < attempt ||
      countMatches(collect, /runtimeCollectionAuthorization\.consumeAndDispatch\s*\(/gu) !== 1 ||
      countMatches(collect, /attemptAuthorization\.consume\s*\(\)/gu) !== 1 ||
      countMatches(collect, /executeNetworkRequest\s*\(/gu) !== 1 ||
      countMatches(collector, /fetchImplementation\s*\(\s*request\s*\)/gu) !== 1
    ) {
      violations.push(
        `${COLLECTOR_FILE} must consume genuine runtime and operations authority exactly once before its only transport invocation`,
      );
    }
    const requestRequirements = [
      [/new\s+Request\s*\(\s*prepared\.url/u, "fixed prepared URL"],
      [/method:\s*"GET"/u, "GET method"],
      [/body:\s*null/u, "empty body"],
      [/credentials:\s*"omit"/u, "credential isolation"],
      [/redirect:\s*"error"/u, "transport redirect refusal"],
      [/"x-api-key":\s*apiKey/u, "dedicated API-key header"],
      [/response\.status\s*===\s*402/u, "HTTP 402 detection"],
      [/"PAYMENT_REQUIRED"/u, "terminal payment-required classification"],
      [/cannot pay/u, "no-pay response"],
    ];
    for (const [pattern, label] of requestRequirements) {
      if (!pattern.test(collector)) violations.push(`${COLLECTOR_FILE} lacks ${label}`);
    }
    if (
      !/isNetworkAttemptAuthorization\s*\(\s*attemptAuthorization\s*\)/u.test(collector) ||
      !/isRuntimeBoundaryAuthorization\s*\(\s*runtimeAuthorization\s*\)/u.test(collector) ||
      !/attemptAuthorization\.binding\.operation\s*!==\s*OPENSEA_TRENDING_OPERATION/u.test(
        collector,
      ) ||
      !/attemptAuthorization\.binding\.sourcePlane\s*!==\s*"marketplace"/u.test(collector) ||
      !/attemptAuthorization\.binding\.lane\s*!==\s*"marketplace"/u.test(collector) ||
      !/attemptAuthorization\.binding\.reservedAtomic\s*!==\s*OPENSEA_TRENDING_RESERVED_ATOMIC/u.test(
        collector,
      )
    ) {
      violations.push(`${COLLECTOR_FILE} does not authenticate the exact one-shot attempt binding`);
    }
  }
  if (index !== undefined) {
    if (
      /ForTesting|TestingOptions|\.\/testing/u.test(index) ||
      !/createOpenSeaTrendingCollector/u.test(index)
    ) {
      violations.push(
        `${COLLECTOR_INDEX_FILE} exposes a testing transport or lacks production collector`,
      );
    }
  }
  const fetchSites = [];
  const globalObjectSites = [];
  for (const [path, analysis] of graph.analyses) {
    for (const _reference of analysis.globalFetchReferences) {
      fetchSites.push(canonicalRelative(root, path));
    }
    for (const reference of analysis.globalObjectReferences) {
      globalObjectSites.push({
        file: canonicalRelative(root, path),
        globalObject: reference.globalObject,
      });
    }
  }
  if (fetchSites.length !== 1 || fetchSites[0] !== COLLECTOR_FILE) {
    violations.push(
      `expected exactly one OpenSea graph fetch site in ${COLLECTOR_FILE}; found ${fetchSites.length}`,
    );
  }
  if (
    globalObjectSites.length !== 2 ||
    globalObjectSites.some(
      (site) => site.file !== COLLECTOR_FILE || site.globalObject !== "globalThis",
    ) ||
    !/globalThis\.fetch\.bind\(globalThis\)/u.test(collector ?? "")
  ) {
    violations.push(
      `${COLLECTOR_FILE} must own the production graph's only two global-object references in the exact globalThis.fetch binding`,
    );
  }
}

function verifyDashboardBoundary(root, graph, violations) {
  const dashboard = requireSource(root, OPERATOR_DASHBOARD_FILE, graph, violations);
  if (dashboard === undefined) return;
  let embeddedHtml;
  let embeddedCss;
  let embeddedJavaScript;
  try {
    embeddedHtml = extractNoSubstitutionTemplate(dashboard, "OPENSEA_OPERATOR_DASHBOARD_HTML");
    embeddedCss = extractNoSubstitutionTemplate(dashboard, "OPENSEA_OPERATOR_DASHBOARD_CSS");
    embeddedJavaScript = extractNoSubstitutionTemplate(dashboard, "OPENSEA_OPERATOR_DASHBOARD_JS");
  } catch (error) {
    violations.push(`${OPERATOR_DASHBOARD_FILE} ${error.message}`);
    return;
  }
  if (sha256(embeddedHtml) !== REVIEWED_DASHBOARD_HTML_SHA256) {
    violations.push(
      `${OPERATOR_DASHBOARD_FILE} must serve the exact reviewed HTML with SHA-256 ${REVIEWED_DASHBOARD_HTML_SHA256}`,
    );
  }
  if (sha256(embeddedCss) !== REVIEWED_DASHBOARD_CSS_SHA256) {
    violations.push(
      `${OPERATOR_DASHBOARD_FILE} must serve the exact reviewed CSS with SHA-256 ${REVIEWED_DASHBOARD_CSS_SHA256}`,
    );
  }
  if (
    !/<script\s+type="module"\s+src="\/operator\.js"><\/script>/u.test(dashboard) ||
    sha256(embeddedJavaScript) !== REVIEWED_DASHBOARD_JS_SHA256
  ) {
    violations.push(
      `${OPERATOR_DASHBOARD_FILE} must serve the exact reviewed module JavaScript with SHA-256 ${REVIEWED_DASHBOARD_JS_SHA256}`,
    );
  }

  let analysis;
  try {
    analysis = analyzeSource(
      scanText(`${OPERATOR_DASHBOARD_FILE}#OPENSEA_OPERATOR_DASHBOARD_JS`, embeddedJavaScript),
    );
  } catch (error) {
    violations.push(
      `${OPERATOR_DASHBOARD_FILE} embedded JavaScript cannot be parsed: ${error.message}`,
    );
    return;
  }

  const nonLocalFetchViolations = analysis.violations.filter(
    (violation) => violation !== "contains unaudited bare fetch capability",
  );
  for (const violation of nonLocalFetchViolations) {
    violations.push(`${OPERATOR_DASHBOARD_FILE} embedded JavaScript ${violation}`);
  }
  if (
    analysis.bareFetchReferences.length !== 1 ||
    analysis.fetchReferences.length !== 1 ||
    analysis.globalFetchReferences.length !== 0 ||
    analysis.globalObjectReferences.length !== 0 ||
    analysis.imports.length !== 0 ||
    analysis.processProperties.length !== 0 ||
    hasComputedMemberAccess(analysis.tokens) ||
    analysis.tokens.some((token) => token.kind === ts.SyntaxKind.ThisKeyword) ||
    [
      "Event",
      "Object",
      "Reflect",
      "__proto__",
      "constructor",
      "contentWindow",
      "defaultView",
      "dispatchEvent",
      "frames",
      "getOwnPropertyDescriptor",
      "getOwnPropertyDescriptors",
      "getPrototypeOf",
      "location",
      "navigator",
      "opener",
      "parent",
      "prototype",
      "setPrototypeOf",
      "top",
    ].some((identifier) => analysis.identifiers.has(identifier)) ||
    hasBareIdentifier(analysis.tokens, "addEventListener") ||
    countMatches(embeddedJavaScript, /\bfetch\s*\(/gu) !== 1 ||
    !/async\s+function\s+requestJson\s*\(\s*path\s*,\s*init\s*\)[\s\S]{0,500}?fetch\s*\(\s*path\s*,\s*\{\s*cache:\s*"no-store",\s*credentials:\s*"same-origin",\s*\.\.\.init\s*\}\s*\)/u.test(
      embeddedJavaScript,
    )
  ) {
    violations.push(
      `${OPERATOR_DASHBOARD_FILE} embedded JavaScript must have exactly one relative same-origin fetch wrapper and no other network capability`,
    );
  }
}

function verifyControllerBoundary(root, graph, violations) {
  const controller = requireSource(root, CONTROLLER_FILE, graph, violations);
  const entry = requireSource(root, CONTROLLER_ENTRY_FILE, graph, violations);
  const schemas = requireSource(root, CONTROLLER_SCHEMA_FILE, graph, violations);
  const constants = requireSource(root, CONTROLLER_CONSTANTS_FILE, graph, violations);
  const ingestion = requireSource(root, INGESTION_FILE, graph, violations);
  if (entry !== undefined) {
    if (/testing|ForTesting|@rsi\/read-canary\/opensea-testing/iu.test(entry)) {
      violations.push(`${CONTROLLER_ENTRY_FILE} exposes a testing controller surface`);
    }
    const reviewedReexports = [
      "./opensea-constants.js",
      "./opensea-errors.js",
      "./opensea-schemas.js",
      "./opensea-types.js",
      "./opensea-read-canary-controller.js",
    ];
    const actualReexports = [...entry.matchAll(/export\s+\*\s+from\s+"([^"]+)"/gu)].map(
      (match) => match[1],
    );
    if (
      actualReexports.length !== reviewedReexports.length ||
      actualReexports.some((value, index) => value !== reviewedReexports[index])
    ) {
      violations.push(`${CONTROLLER_ENTRY_FILE} must keep the closed production OpenSea exports`);
    }
  }
  if (controller !== undefined) {
    const requirements = [
      [/PREPARED_KEY\s*=\s*[^\n]*singleton/u, "durable singleton prepared key"],
      [/\.reserveAttempt\s*\(/u, "durable operations reservation"],
      [/operation:\s*"opensea\.trending-collections\.v1"/u, "fixed OpenSea operation"],
      [/sourcePlane:\s*"marketplace"/u, "marketplace source plane"],
      [/lane:\s*"marketplace"/u, "marketplace lane"],
      [/profile:\s*"canary"/u, "canary profile"],
      [/reservedAtomic:\s*OPENSEA_TRENDING_RESERVED_ATOMIC/u, "nonzero internal USD-micro reserve"],
      [/\.createNetworkAttemptAuthorization\s*\(/u, "operations one-shot authorization"],
      [/\.requestBoundaryAuthorization\s*\(/u, "runtime one-shot authorization"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(controller)) violations.push(`${CONTROLLER_FILE} lacks ${label}`);
    }
    if (countMatches(controller, /\.reserveAttempt\s*\(/gu) !== 1) {
      violations.push(`${CONTROLLER_FILE} must reserve exactly one OpenSea attempt`);
    }
    const runStart = controller.indexOf("async #run(");
    const runEnd = controller.indexOf("\n  async #resume(", runStart);
    const run = runStart < 0 || runEnd < 0 ? "" : controller.slice(runStart, runEnd);
    const reservationStart = run.indexOf("this.#operationsStore.reserveAttempt({");
    const reservationEnd = run.indexOf("\n      });", reservationStart);
    const reservation =
      reservationStart < 0 || reservationEnd < 0 ? "" : run.slice(reservationStart, reservationEnd);
    const reservationRequirements = [
      /attemptId:\s*permit\.attemptId/u,
      /authorizationExpiresAt:\s*runtimeAuthorization\.expiresAt/u,
      /budgetId\s*,/u,
      /createdAt:\s*runtimeAuthorization\.requestedAt/u,
      /idempotencyKey:\s*`opensea-read-canary:\$\{command\.requestId\}`/u,
      /lane:\s*"marketplace"/u,
      /operation:\s*"opensea\.trending-collections\.v1"/u,
      /permitToken:\s*permit\.token/u,
      /reservedAtomic:\s*OPENSEA_TRENDING_RESERVED_ATOMIC/u,
      /sessionId:\s*command\.requestId/u,
      /sourcePlane:\s*"marketplace"/u,
    ];
    const durableClaim = run.indexOf("this.#eventStore.append({");
    const durablePreparedKey = run.indexOf("idempotencyKey: PREPARED_KEY", durableClaim);
    const createBudget = run.indexOf("this.#operationsStore.createBudget({", durablePreparedKey);
    const reserveAttempt = run.indexOf("this.#operationsStore.reserveAttempt({", createBudget);
    if (
      run.length === 0 ||
      durableClaim < 0 ||
      durablePreparedKey < durableClaim ||
      createBudget < durablePreparedKey ||
      reserveAttempt < createBudget ||
      !/catch\s*\{\s*throw\s+new\s+OpenSeaReadCanaryConflictError\s*\(\s*"The one-shot OpenSea read canary was claimed concurrently"/u.test(
        run,
      ) ||
      reservationRequirements.some((pattern) => !pattern.test(reservation)) ||
      !/this\.#operationsStore\.createBudget\s*\(\s*\{[\s\S]{0,700}?currency:\s*"USD_MICRO"[\s\S]{0,700}?maxAtomic:\s*OPENSEA_TRENDING_RESERVED_ATOMIC[\s\S]{0,700}?maxAttempts:\s*1[\s\S]{0,700}?profile:\s*"canary"/u.test(
        run,
      ) ||
      !/const\s+networkAuthorization\s*=\s*this\.#operationsStore\.createNetworkAttemptAuthorization\s*\(\s*permit\s*\)/u.test(
        run,
      ) ||
      !/createOpenSeaTrendingCollector\s*\(\s*\{\s*attemptAuthorization:\s*networkAuthorization,\s*apiKey,\s*runtimeAuthorization,?\s*\}\s*\)/u.test(
        run,
      ) ||
      !/return\s+await\s+this\.#complete\s*\(\s*prepared\s*,\s*result\s*,\s*runtimeAuthorization\s*\)/u.test(
        run,
      )
    ) {
      violations.push(
        `${CONTROLLER_FILE} must bind the same one-shot runtime and operations authorization through collection and completion`,
      );
    }
    const binding = functionSlice(controller, "assertOperationsAttemptBinding");
    const bindingRequirements = [
      /binding\.attemptId\s*!==\s*prepared\.attemptId/u,
      /binding\.authorizationExpiresAt\s*!==\s*prepared\.expiresAt/u,
      /binding\.budgetId\s*!==\s*prepared\.budgetId/u,
      /binding\.createdAt\s*!==\s*prepared\.preparedAt/u,
      /binding\.idempotencyKey\s*!==\s*`opensea-read-canary:\$\{prepared\.requestId\}`/u,
      /binding\.lane\s*!==\s*"marketplace"/u,
      /binding\.operation\s*!==\s*OPENSEA_READ_CANARY_OPERATION/u,
      /binding\.profile\s*!==\s*"canary"/u,
      /binding\.reservedAtomic\s*!==\s*OPENSEA_TRENDING_RESERVED_ATOMIC/u,
      /binding\.sessionId\s*!==\s*prepared\.requestId/u,
      /binding\.sourcePlane\s*!==\s*"marketplace"/u,
    ];
    if (binding.length === 0 || bindingRequirements.some((pattern) => !pattern.test(binding))) {
      violations.push(`${CONTROLLER_FILE} must authenticate every durable OpenSea attempt field`);
    }
    if (countMatches(controller, /runtimeAuthorization\.guardCompletion\s*\(/gu) !== 1) {
      violations.push(`${CONTROLLER_FILE} must retain exactly one STOP-aware completion guard`);
    }
    if (!/guardCompletion\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,800}?append/u.test(controller)) {
      violations.push(`${CONTROLLER_FILE} must append the durable result inside guardCompletion`);
    }
    const recoveryResult = functionSlice(controller, "persistRecoveryResult");
    const liveResult = functionSlice(controller, "persistLiveResult");
    if (
      !/resultCandidate\s*\(\s*dependencies\s*,\s*prepared\s*,\s*ingestion\s*,\s*true\s*\)/u.test(
        recoveryResult,
      ) ||
      !/resultCandidate\s*\(\s*dependencies\s*,\s*prepared\s*,\s*ingestion\s*,\s*false\s*\)/u.test(
        liveResult,
      ) ||
      !/if\s*\(completion\.decision\s*!==\s*"allowed"\s*\|\|\s*persisted\s*===\s*undefined\)\s*\{\s*return\s+persistRecoveryResult/u.test(
        liveResult,
      )
    ) {
      violations.push(
        `${CONTROLLER_FILE} must convert denied or interrupted completion into a recovery-safe rejected result`,
      );
    }
    const failurePersistence = functionSlice(controller, "persistFailureCheckpoint");
    const terminalFailure = functionSlice(controller, "terminalizeFailure");
    const finalizeFailure = functionSlice(controller, "finalizeFailureCheckpoint");
    const failurePersist = terminalFailure.indexOf("persistFailureCheckpoint(");
    const failureFinalize = terminalFailure.indexOf("finalizeFailureCheckpoint(", failurePersist);
    const failureReconciliation = finalizeFailure.indexOf("await recoverCaptureStorage(");
    const failureClose = finalizeFailure.indexOf("closeAttemptForFailure(", failureReconciliation);
    const failureCleanup = finalizeFailure.indexOf(
      "removePendingCaptureAfterFailure(",
      failureClose,
    );
    const failureReceipt = finalizeFailure.indexOf("appendReceipt(", failureCleanup);
    const preparedRecovery = functionSlice(controller, "recoverPreparedCanary");
    if (
      failurePersistence.length === 0 ||
      !/appendFailure\s*\(\s*dependencies\.eventStore\s*,\s*candidate\s*\)/u.test(
        failurePersistence,
      ) ||
      terminalFailure.length === 0 ||
      failurePersist < 0 ||
      failureFinalize < failurePersist ||
      finalizeFailure.length === 0 ||
      failureReconciliation < 0 ||
      failureClose < failureReconciliation ||
      failureCleanup < failureClose ||
      failureReceipt < failureCleanup ||
      !/from\s+"@rsi\/ingestion\/capture-storage-recovery"/u.test(controller) ||
      !/const\s+durableFailure\s*=\s*loadFailure\s*\(/u.test(preparedRecovery) ||
      !/if\s*\(durableFailure\s*!==\s*null\)\s*\{\s*return\s+finalizeFailureCheckpoint/u.test(
        preparedRecovery,
      )
    ) {
      violations.push(
        `${CONTROLLER_FILE} must checkpoint exact content-free failures, reconcile registry/Vault storage, then close, clean up, and publish the receipt with exact recovery replay`,
      );
    }
    const finalize = functionSlice(controller, "finalizeResult");
    const close = finalize.indexOf("closeAttemptForResult(");
    const destroy = finalize.indexOf("await destroyResultCapture(", close);
    const receipt = finalize.indexOf("appendReceipt(", destroy);
    const destruction = functionSlice(controller, "destroyResultCapture");
    const vaultDelete = destruction.indexOf("await dependencies.vault.delete(");
    const recordDeletion = destruction.indexOf(
      "dependencies.captureRegistry.recordVerifiedDeletion(",
      vaultDelete,
    );
    const verifyTombstone = destruction.indexOf(
      "dependencies.captureRegistry.getAttempt(",
      recordDeletion,
    );
    if (
      finalize.length === 0 ||
      close < 0 ||
      destroy < close ||
      receipt < destroy ||
      destruction.length === 0 ||
      vaultDelete < 0 ||
      recordDeletion < vaultDelete ||
      verifyTombstone < recordDeletion ||
      !/removed\?\.state\s*!==\s*"removed"\s*\|\|\s*!removed\.keyDestroyed/u.test(destruction)
    ) {
      violations.push(
        `${CONTROLLER_FILE} must close, crypto-shred, verify the registry tombstone, then append the receipt`,
      );
    }
    const recoveryOptionsStart = controller.indexOf(
      "export interface OpenSeaReadCanaryRecoveryOptions",
    );
    const recoveryOptionsEnd = controller.indexOf("\n}", recoveryOptionsStart);
    const recoveryOptions =
      recoveryOptionsStart < 0 || recoveryOptionsEnd < 0
        ? ""
        : controller.slice(recoveryOptionsStart, recoveryOptionsEnd + 2);
    const recoveryOptionNames = [
      ...recoveryOptions.matchAll(/^\s+readonly\s+([A-Za-z_$][\w$]*)\s*:/gmu),
    ]
      .map((match) => match[1])
      .sort();
    const expectedRecoveryOptions = [
      "captureRegistry",
      "eventStore",
      "operationsStore",
      "runtime",
      "vault",
    ];
    const publicRecovery = functionSlice(controller, "recoverOpenSeaReadCanary");
    const capturePreparedRecovery = preparedRecovery;
    if (
      recoveryOptionNames.length !== expectedRecoveryOptions.length ||
      recoveryOptionNames.some((value, index) => value !== expectedRecoveryOptions[index]) ||
      publicRecovery.length === 0 ||
      !/const\s+dependencies\s*=\s*exactRecoveryOptions\s*\(\s*optionsValue\s*\)/u.test(
        publicRecovery,
      ) ||
      !/return\s+recoverPreparedCanary\s*\(\s*dependencies\s*,\s*prepared\s*\)/u.test(
        publicRecovery,
      ) ||
      capturePreparedRecovery.length === 0 ||
      !/const\s+ingestion\s*=\s*await\s+ingestOpenSeaTrending\s*\(\s*\{\s*captureRegistry:\s*dependencies\.captureRegistry,\s*operationsStore:\s*dependencies\.operationsStore,\s*store:\s*dependencies\.eventStore,\s*vault:\s*dependencies\.vault,?\s*\}/u.test(
        capturePreparedRecovery,
      ) ||
      /\b(?:apiKey|collector|fetch)\s*:/u.test(capturePreparedRecovery)
    ) {
      violations.push(
        `${CONTROLLER_FILE} recovery must be credentialless, collectorless, and egress-free`,
      );
    }
    if (
      /actualCharge(?:UsdMicros|Atomic)?\s*:\s*(?:OPENSEA_TRENDING_RESERVED_ATOMIC|"1"|1)\b/u.test(
        controller,
      ) ||
      /maximumCharge(?:UsdMicros|Atomic)?\s*:\s*(?:OPENSEA_TRENDING_RESERVED_ATOMIC|"1"|1)\b/u.test(
        controller,
      )
    ) {
      violations.push(
        `${CONTROLLER_FILE} misrepresents the internal one-micro reserve as a provider charge`,
      );
    }
  }
  if (constants !== undefined) {
    const requirements = [
      [
        /OPENSEA_READ_CANARY_PLAN_ID\s*=\s*"opensea-base-trending-collections-v1"\s+as\s+const/u,
        "published plan ID",
      ],
      [/OPENSEA_READ_CANARY_MAXIMUM_REQUESTS\s*=\s*1\s+as\s+const/u, "one-request maximum"],
      [
        /OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO\s*=\s*OPENSEA_TRENDING_RESERVED_ATOMIC/u,
        "internal nonzero ledger reserve",
      ],
      [/not an OpenSea price estimate/u, "non-price reserve semantics"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(constants)) {
        violations.push(`${CONTROLLER_CONSTANTS_FILE} does not enforce ${label}`);
      }
    }
  }
  if (schemas !== undefined) {
    const receiptStart = schemas.indexOf("export const OpenSeaReadCanaryReceiptSchema");
    const receiptEnd = schemas.indexOf(".superRefine", receiptStart);
    const receiptSchema =
      receiptStart < 0
        ? ""
        : schemas.slice(receiptStart, receiptEnd < 0 ? schemas.length : receiptEnd);
    const publicFields = [...receiptSchema.matchAll(/^\s{4}([A-Za-z_$][\w$]*)\s*:/gmu)]
      .map((match) => match[1])
      .sort();
    const expectedFields = [
      "acquiredAt",
      "actualChargeUsdMicros",
      "byteLength",
      "capture",
      "collectionCount",
      "completedAt",
      "failureCode",
      "hasNextPage",
      "ledgerReserveUsdMicros",
      "maximumRequests",
      "maximumResults",
      "outcome",
      "planId",
      "providerId",
      "rateLimit",
      "receiptId",
      "requestFingerprint",
      "requestId",
      "runtime",
      "schemaVersion",
    ].sort();
    if (
      !/OpenSeaReadCanaryReceiptSchema\s*=\s*z\s*\.strictObject\s*\(/u.test(receiptSchema) ||
      publicFields.length !== expectedFields.length ||
      publicFields.some((value, index) => value !== expectedFields[index]) ||
      !/actualChargeUsdMicros:\s*z\.null\(\)/u.test(receiptSchema) ||
      /\b(?:attemptId|captureId|slug|address|raw|content)\s*:/iu.test(receiptSchema)
    ) {
      violations.push(
        `${CONTROLLER_SCHEMA_FILE} must keep the receipt strict, content-free, and actual charge unknown`,
      );
    }
    if (
      !/nonPaymentReadAcknowledgement:\s*z\.literal\(true\)/u.test(schemas) ||
      !/automaticRetries:\s*z\.literal\(0\)/u.test(schemas) ||
      !/automaticPagination:\s*z\.literal\(false\)/u.test(schemas)
    ) {
      violations.push(
        `${CONTROLLER_SCHEMA_FILE} must pin the non-payment, no-retry, no-pagination plan`,
      );
    }
    const failureCheckpointStart = schemas.indexOf(
      "export const OpenSeaReadCanaryFailureEventPayloadSchema",
    );
    const failureCheckpointEnd = schemas.indexOf(
      "\n\nexport const OpenSeaReadCanaryProjectionSchema",
      failureCheckpointStart,
    );
    const failureCheckpoint =
      failureCheckpointStart < 0 || failureCheckpointEnd < 0
        ? ""
        : schemas.slice(failureCheckpointStart, failureCheckpointEnd);
    if (
      !/OpenSeaReadCanaryFailureEventPayloadSchema\s*=\s*z\.strictObject\s*\(/u.test(
        failureCheckpoint,
      ) ||
      !/failureCode:\s*OpenSeaReadCanaryFailureCodeSchema/u.test(failureCheckpoint) ||
      !/rateLimit:\s*RateLimitSchema\.nullable\(\)/u.test(failureCheckpoint) ||
      !/runtime:\s*RuntimeReceiptSchema\.nullable\(\)/u.test(failureCheckpoint) ||
      /\b(?:apiKey|captureId|slug|address|raw|content)\s*:/iu.test(failureCheckpoint)
    ) {
      violations.push(
        `${CONTROLLER_SCHEMA_FILE} must keep the durable failure checkpoint strict and content-free`,
      );
    }
  }
  if (ingestion !== undefined) {
    if (
      !/export\s+async\s+function\s+ingestOpenSeaTrending/u.test(ingestion) ||
      !/if\s*\(existingAttempt\?\.state\s*===\s*"committed"\)[\s\S]{0,900}?return\s+resumeCommittedAttempt/u.test(
        ingestion,
      )
    ) {
      violations.push(`${INGESTION_FILE} recovery must not hold collector or egress capability`);
    }
  }
}

function verifyCredentialAndOperatorBoundary(root, graph, violations) {
  const credential = requireSource(root, CREDENTIAL_FILE, graph, violations);
  const credentialEntry = requireSource(root, CREDENTIAL_ENTRY_FILE, graph, violations);
  const host = requireSource(root, OPERATOR_HOST_FILE, graph, violations);
  const core = requireSource(root, OPERATOR_HOST_CORE_FILE, graph, violations);
  const server = requireSource(root, OPERATOR_SERVER_FILE, graph, violations);
  if (credential !== undefined) {
    const requirements = [
      [
        /KEYCHAIN_ACCOUNT\s*=\s*"rsi-stage1-opensea-read-canary"\s+as\s+const/u,
        "dedicated account",
      ],
      [/apiKey:\s*"dev\.rsi\.canary\.opensea-read"/u, "dedicated API-key service"],
      [/SECURITY\s*=\s*"\/usr\/bin\/security"\s+as\s+const/u, "fixed security executable"],
      [/shell:\s*false/u, "shell-free execution"],
      [/"find-generic-password"/u, "read-only Keychain command"],
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
  if (credentialEntry !== undefined) {
    if (/ForTesting|TestingOptions|\.\/opensea-trending-testing/u.test(credentialEntry)) {
      violations.push(`${CREDENTIAL_ENTRY_FILE} exports test-only credential injection`);
    }
  }
  if (host !== undefined) {
    if (
      !/from\s+"@rsi\/credential-host\/opensea-trending"/u.test(host) ||
      !/new\s+DarwinOpenSeaTrendingKeychain\s*\(\s*\)/u.test(host) ||
      /ForTesting|TestingOptions|credentialHost\s*[:?]|fetch\s*[:?]|\/testing/u.test(host)
    ) {
      violations.push(
        `${OPERATOR_HOST_FILE} must expose only the option-free production Keychain starter`,
      );
    }
    if (
      !/from\s+"@rsi\/credential-host\/one-shot-claim"/u.test(host) ||
      countMatches(host, /createDarwinOpenSeaOneShotClaimHost\s*\(\s*\)/gu) !== 1 ||
      /createDarwin(?:X|BaseRpc)OneShotClaimHost\s*\(\s*\)/u.test(host)
    ) {
      violations.push(
        `${OPERATOR_HOST_FILE} must use only the option-free OpenSea one-shot claim host`,
      );
    }
  }
  if (core !== undefined) {
    const liveStart = core.indexOf("async #runWithKeychain(");
    const liveEnd = core.indexOf("\n  async #recoverInterruptedIfPossible(", liveStart);
    const liveRecovery = liveStart < 0 || liveEnd < 0 ? "" : core.slice(liveStart, liveEnd);
    const storageStart = core.indexOf("async #recoverWithStorageSecrets(");
    const storageEnd = core.indexOf("\n}\n\nfunction requestedPaths", storageStart);
    const storageRecovery =
      storageStart < 0 || storageEnd < 0 ? "" : core.slice(storageStart, storageEnd);
    const liveStorageRepair = liveRecovery.indexOf("await recoverCaptureStorage({");
    const liveCanaryRecovery = liveRecovery.indexOf(
      "const recovered = await recoverOpenSeaReadCanary({",
      liveStorageRepair,
    );
    const restartStorageRepair = storageRecovery.indexOf("await recoverCaptureStorage({");
    const restartCanaryRecovery = storageRecovery.indexOf(
      "await recoverOpenSeaReadCanary({",
      restartStorageRepair,
    );
    if (
      !/from\s+"@rsi\/read-canary\/opensea"/u.test(core) ||
      !/from\s+"@rsi\/ingestion\/capture-storage-recovery"/u.test(core) ||
      !/withSecrets\s*\(/u.test(core) ||
      !/withStorageSecrets\s*\(/u.test(core) ||
      !/await\s+this\.claimHost\.claim\(\)\s*;[\s\S]{0,120}?return\s+this\.credentialHost\.withSecrets/u.test(
        liveRecovery,
      ) ||
      !/apiKey:\s*secrets\.apiKey/u.test(core) ||
      countMatches(core, /await\s+recoverCaptureStorage\s*\(/gu) !== 2 ||
      liveStorageRepair < 0 ||
      liveCanaryRecovery < liveStorageRepair ||
      restartStorageRepair < 0 ||
      restartCanaryRecovery < restartStorageRepair
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must repair capture storage before both live and restart canary recovery while isolating Keychain authority`,
      );
    }
    if (
      countMatches(core, /this\.claimHost\.claim\(\)/gu) !== 1 ||
      countMatches(core, /this\.claimHost\.status\(\)/gu) !== 1 ||
      /claimHost/u.test(storageRecovery) ||
      !/projection\.lastReceipt\s*!==\s*null\s*&&\s*\(await\s+this\.claimHost\.status\(\)\)\s*!==\s*"present"/u.test(
        core,
      )
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must claim before API-key access and require a value-free marker check for completed receipts`,
      );
    }
    const passiveProjectionStart = core.indexOf("getOpenSeaReadCanaryProjection():");
    const passiveProjectionEnd = core.indexOf(
      "\n  async refreshOpenSeaCredentialStatus():",
      passiveProjectionStart,
    );
    const passiveProjection =
      passiveProjectionStart < 0 || passiveProjectionEnd < 0
        ? ""
        : core.slice(passiveProjectionStart, passiveProjectionEnd);
    if (
      passiveProjection.length === 0 ||
      /credentialHost|recover|withSecrets|withStorageSecrets|await\b/u.test(passiveProjection)
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} passive projection must not read Keychain values or mutate recovery`,
      );
    }
    const recovery = core.search(/recoverWithStorageSecrets/u);
    if (recovery >= 0) {
      const recoverySource = core.slice(recovery, core.indexOf("\n  }", recovery) + 4 || undefined);
      if (/secrets\.apiKey|createOpenSeaTrendingCollector/u.test(recoverySource)) {
        violations.push(
          `${OPERATOR_HOST_CORE_FILE} gives API-key or collector authority to recovery`,
        );
      }
    }
    if (
      !/PRIVATE_DIRECTORY_MODE\s*=\s*0o700n/u.test(core) ||
      !/parentEntry\.uid\s*!==\s*EFFECTIVE_USER_ID/u.test(core)
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must verify an owner-owned mode-0700 data directory`,
      );
    }
  }
  if (server !== undefined) {
    const route = functionSlice(server, "route");
    const stop = route.indexOf('command.action === "runtime-stop"');
    const abort = route.indexOf("options.readCanary.abortActive()", stop);
    const durableStop = route.indexOf("options.runtime.executeRuntimeControl(command)", abort);
    const start = functionSlice(server, "startOpenSeaOperatorServer");
    const refreshRoute = route.indexOf(
      'url.pathname === "/api/opensea-read-canary/refresh-credential-status"',
    );
    const refreshOrigin = route.indexOf("assertSameOriginControl(request, origin);", refreshRoute);
    const refreshAction = route.indexOf(
      "options.readCanary.refreshOpenSeaCredentialStatus()",
      refreshOrigin,
    );
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
      violations.push(`${OPERATOR_SERVER_FILE} must remain same-origin and loopback-only`);
    }
    if (
      stop < 0 ||
      abort < stop ||
      durableStop < abort ||
      !/runtime\.mode\s*!==\s*"RESEARCH"[\s\S]{0,1600}?executeOpenSeaReadCanary\s*\(/u.test(route)
    ) {
      violations.push(
        `${OPERATOR_SERVER_FILE} must abort the canary before durable STOP and require RESEARCH for launch`,
      );
    }
    if (
      refreshRoute < 0 ||
      refreshOrigin < refreshRoute ||
      refreshAction < refreshOrigin ||
      !/server\.headersTimeout\s*=\s*CONTROL_BODY_TIMEOUT_MS/u.test(server) ||
      !/server\.requestTimeout\s*=\s*CONTROL_BODY_TIMEOUT_MS/u.test(server) ||
      !/server\.close\([\s\S]{0,300}?server\.closeAllConnections\(\)/u.test(start)
    ) {
      violations.push(
        `${OPERATOR_SERVER_FILE} must protect credential refresh and bound request/shutdown availability`,
      );
    }
  }
}

function verifyProductionLaunchBoundary(root, graph, violations) {
  const options = requireSource(root, OPERATOR_OPTIONS_FILE, graph, violations);
  const entry = requireSource(root, ENTRY, graph, violations);
  const host = requireSource(root, OPERATOR_HOST_FILE, graph, violations);
  requireSource(root, PRODUCTION_CONFIG_FILE, graph, violations);
  requireSource(root, PRODUCTION_RUNTIME_FILE, graph, violations);

  if (options !== undefined) {
    if (
      !/return\s+productionOpenSeaCanaryHostOptions\(\)/u.test(options) ||
      !/argument\s*===\s*"--help"\s*\|\|\s*argument\s*===\s*"-h"/u.test(options) ||
      !/throw\s+new\s+Error\("OpenSea canary production options are fixed"\)/u.test(options) ||
      /["']--(?:db|research-db|port)["']/u.test(options) ||
      /\b(?:cwd|env|homedir)\s*\(/u.test(options) ||
      /\bprocess\b/u.test(options)
    ) {
      violations.push(
        `${OPERATOR_OPTIONS_FILE} must reject all production path and port overrides`,
      );
    }
  }

  if (entry !== undefined) {
    const parseOptions = entry.indexOf("parseOpenSeaCanaryOperatorOptions(process.argv.slice(2))");
    const runtimeCheck = entry.indexOf("assertActiveProductionRuntime();");
    const hostStart = entry.indexOf("await startOpenSeaCanaryOperator(options)");
    const startupFailure = entry.indexOf(
      "process.stderr.write(STARTUP_FAILURE_MESSAGE)",
      hostStart,
    );
    if (
      parseOptions < 0 ||
      runtimeCheck < 0 ||
      hostStart < 0 ||
      parseOptions > runtimeCheck ||
      runtimeCheck > hostStart ||
      startupFailure < hostStart ||
      countMatches(entry, /assertActiveProductionRuntime\s*\(\s*\)/gu) !== 1 ||
      !/STARTUP_FAILURE_MESSAGE\s*=\s*"RSI OpenSea canary startup was refused\.\\n"\s+as\s+const/u.test(
        entry,
      ) ||
      countMatches(entry, /process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)/gu) !== 2 ||
      !/try\s*\{[\s\S]{0,300}?options\s*=\s*parseOpenSeaCanaryOperatorOptions\(process\.argv\.slice\(2\)\)[\s\S]{0,180}?catch\s*\{[\s\S]{0,100}?process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      !/try\s*\{[\s\S]{0,180}?const\s+operator\s*=\s*await\s+startOpenSeaCanaryOperator\(options\)[\s\S]{0,2600}?catch\s*\{[\s\S]{0,100}?process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      !/catch\s*\{[\s\S]{0,180}?process\.stderr\.write\(PRODUCTION_RUNTIME_FAILURE_MESSAGE\)[\s\S]{0,120}?process\.exitCode\s*=\s*1/u.test(
        entry,
      )
    ) {
      violations.push(
        `${ENTRY} must sanitize option, runtime, and host startup failures before emitting output`,
      );
    }
  }

  if (host !== undefined) {
    const runtimeCheck = host.indexOf("assertActiveProductionRuntime();");
    const canonicalOptions = host.indexOf("productionOpenSeaCanaryHostOptions();");
    const keychain = host.indexOf("new DarwinOpenSeaTrendingKeychain()");
    const claimHost = host.indexOf("createDarwinOpenSeaOneShotClaimHost()");
    const dispatch = host.indexOf("return startOpenSeaCanaryOperatorWithHost(");
    if (
      runtimeCheck < 0 ||
      canonicalOptions < runtimeCheck ||
      keychain < canonicalOptions ||
      claimHost < canonicalOptions ||
      dispatch < canonicalOptions ||
      countMatches(host, /assertActiveProductionRuntime\s*\(\s*\)/gu) !== 1 ||
      !/options\.databasePath\s*!==\s*productionOptions\.databasePath/u.test(host) ||
      !/options\.port\s*!==\s*productionOptions\.port/u.test(host)
    ) {
      violations.push(
        `${OPERATOR_HOST_FILE} must reject injected production paths and ports before Keychain access`,
      );
    }
  }
}

export function verifyOpenSeaReadCanaryBoundary(options = {}) {
  const root = realpathSync(options.root ?? DEFAULT_ROOT);
  const violations = [];
  try {
    verifyStage1ReadCanaryBoundary({ root });
  } catch (error) {
    violations.push(`shared runtime/STOP authority gate failed: ${error.message}`);
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
  verifyControllerBoundary(root, graph, violations);
  verifyDashboardBoundary(root, graph, violations);
  verifyCredentialAndOperatorBoundary(root, graph, violations);
  verifyProductionLaunchBoundary(root, graph, violations);
  const unique = [...new Set(violations)].sort();
  if (unique.length > 0) throw new OpenSeaReadCanaryVerificationFailure(unique);
  return Object.freeze({
    endpoint: EXACT_ENDPOINT,
    files: graph.files.size,
    maximumRequests: 1,
    maximumResults: 10,
    paymentCapability: false,
    status: "pass",
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(THIS_FILE);
}

if (isMainModule()) {
  try {
    const result = verifyOpenSeaReadCanaryBoundary();
    console.log(
      `OpenSea READ_CANARY authority gate passed (${result.files} files, exactly ${result.maximumRequests} fixed GET, maximum ${result.maximumResults} Base collections, no payment authority).`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
