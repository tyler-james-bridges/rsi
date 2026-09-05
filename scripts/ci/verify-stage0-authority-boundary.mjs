#!/usr/bin/env node

import { builtinModules } from "node:module";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import * as ts from "typescript/unstable/ast";

const THIS_FILE = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = resolve(dirname(THIS_FILE), "../..");

const RUNTIME_DIRECTORY = "packages/runtime";
const RUNTIME_ENTRY = "packages/runtime/src/index.ts";
const OPERATOR_ENTRY = "apps/cli/src/operator.ts";

const REQUIRED_DENIED_BOUNDARIES = Object.freeze([
  "policy_approval",
  "paid_read",
  "wallet_sign",
  "execution_adapter",
  "transaction_broadcast",
  "external_publish",
]);
const REQUIRED_DENIAL_REASON = "PERMANENTLY_FORBIDDEN";

const ALLOWED_RUNTIME_DEPENDENCIES = new Set(["@rsi/store", "zod"]);
const FORBIDDEN_WORKSPACE_PACKAGES = new Map([
  ["@rsi/adapters", "execution-adapter interfaces"],
  ["@rsi/domain", "executable intent and EIP-712 transaction modules"],
  ["@rsi/policy", "policy approval authority"],
]);
const REVIEWED_SIGNER_BLIND_SUBPATHS = new Set(["@rsi/domain/proposals"]);
const FORBIDDEN_LOCAL_PREFIXES = new Map([
  ["packages/adapters/", "execution-adapter package"],
  ["packages/policy/", "policy approval package"],
  ["packages/domain/src/index.ts", "executable domain root"],
  ["packages/domain/src/eip712.ts", "EIP-712 executable-intent module"],
  ["packages/domain/src/schemas.ts", "executable transaction schema module"],
]);
const OFFLINE_ONLY_ENTRYPOINTS = new Set([
  "apps/cli/src/index.ts",
  "apps/cli/src/ingestion-demo.ts",
  "apps/cli/src/ingestion.ts",
  "apps/cli/src/pipeline.ts",
]);

const SAFE_EXTERNAL_MODULES = new Set(["zod"]);
const SAFE_PLATFORM_MODULES = new Set([
  "node:async_hooks",
  "node:path",
  "node:perf_hooks",
  "node:sqlite",
  "node:util",
]);
const SPECIAL_PLATFORM_IMPORTS = new Map([
  [
    "node:crypto",
    Object.freeze({
      files: new Map([
        ["apps/cli/src/operator.ts", Object.freeze(["randomUUID"])],
        [
          "packages/session-lifecycle/src/sqlite-session-coordinator.ts",
          Object.freeze(["createHmac", "hkdfSync", "timingSafeEqual"]),
        ],
        ["packages/store/src/sqlite-event-store.ts", Object.freeze(["createHash", "randomUUID"])],
      ]),
    }),
  ],
  [
    "node:fs",
    Object.freeze({
      files: new Map([
        [
          "packages/session-lifecycle/src/sqlite-session-coordinator.ts",
          Object.freeze(["chmodSync", "existsSync", "lstatSync", "mkdirSync"]),
        ],
      ]),
    }),
  ],
  [
    "node:fs/promises",
    Object.freeze({
      files: new Map([
        ["apps/cli/src/operator.ts", Object.freeze(["lstat", "mkdir", "realpath", "stat"])],
        ["apps/cli/src/operator-options.ts", Object.freeze(["realpath"])],
      ]),
    }),
  ],
  [
    "node:http",
    Object.freeze({
      file: "apps/operator/src/server.ts",
      names: Object.freeze(["IncomingMessage", "Server", "ServerResponse", "createServer"]),
    }),
  ],
  [
    "node:net",
    Object.freeze({
      file: "apps/operator/src/server.ts",
      names: Object.freeze(["BlockList", "isIP"]),
    }),
  ],
]);
const FORBIDDEN_NETWORK_MODULES = new Set([
  "dgram",
  "dns",
  "dns/promises",
  "http",
  "http2",
  "https",
  "net",
  "node:dgram",
  "node:dns",
  "node:dns/promises",
  "node:http2",
  "node:https",
  "node:tls",
  "tls",
]);
const FORBIDDEN_PLATFORM_MODULES = new Map([
  ["child_process", "arbitrary process execution"],
  ["node:child_process", "arbitrary process execution"],
  ["module", "alternate module loading"],
  ["node:module", "alternate module loading"],
  ["node:vm", "dynamic code execution"],
  ["vm", "dynamic code execution"],
]);
const NODE_BUILTINS = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);

// This is a deliberately syntactic review gate, not a general proof against
// intentionally obfuscated JavaScript. Reject every loader entry point the
// scanner can identify, including property/destructuring aliases.
const FORBIDDEN_MODULE_LOADER_IDENTIFIERS = new Set([
  "_load",
  "allowExtension",
  "createRequire",
  "enableLoadExtension",
  "getBuiltinModule",
  "loadExtension",
  "require",
]);
const FORBIDDEN_MODULE_LOADER_LITERALS = new Set([
  "_load",
  "allowExtension",
  "createRequire",
  "enableLoadExtension",
  "getBuiltinModule",
  "loadExtension",
  "require",
]);
const FORBIDDEN_PROCESS_LOADER_APIS = new Set(["_linkedBinding", "binding", "dlopen"]);
const FORBIDDEN_DYNAMIC_CODE_IDENTIFIERS = new Set([
  "AsyncFunction",
  "eval",
  "Function",
  "GeneratorFunction",
  "constructor",
]);
const FORBIDDEN_DYNAMIC_CODE_LITERALS = new Set(
  [...FORBIDDEN_DYNAMIC_CODE_IDENTIFIERS].filter((name) => name !== "constructor"),
);
const FORBIDDEN_NETWORK_GLOBALS = new Set([
  "EventSource",
  "WebSocketStream",
  "WebTransport",
  "WebSocket",
  "XMLHttpRequest",
  "sendBeacon",
]);
const FORBIDDEN_CRYPTO_AUTHORITY_IDENTIFIERS = new Set([
  "CryptoKey",
  "ECDH",
  "SubtleCrypto",
  "createECDH",
  "createPrivateKey",
  "createPublicKey",
  "createSign",
  "deriveBits",
  "deriveKey",
  "diffieHellman",
  "exportKey",
  "generateKey",
  "generateKeyPair",
  "generateKeyPairSync",
  "generateKeySync",
  "importKey",
  "privateDecrypt",
  "privateEncrypt",
  "sign",
  "subtle",
  "unwrapKey",
  "webcrypto",
  "wrapKey",
]);
const FORBIDDEN_CRYPTO_AUTHORITY_LITERALS = new Set(FORBIDDEN_CRYPTO_AUTHORITY_IDENTIFIERS);
const REVIEWED_NETWORK_URL_LITERALS = new Set([
  // Local URL parsing sentinel; it is never a routable destination.
  "http://operator.invalid",
  // A content-free plan/receipt discriminator, not a transport implementation.
  "https://api.x.com/2/tweets/search/recent",
]);
const NETWORK_URL_LITERAL = /\b(?:https?|wss?):\/\/[A-Za-z0-9][^"'`\s)<]*/giu;

const FORBIDDEN_EXTERNAL_PACKAGE =
  /(?:^|[/@._-])(?:agentcash|agentpay|x402|walletconnect|metamask|wagmi|ethers|web3|permissionless|pimlico|account-abstraction|safe-global)(?:$|[/@._-])/iu;
const FORBIDDEN_LOCAL_MODULE =
  /(?:^|[/._-])(?:wallets?|transactions?|broadcast(?:er)?|deploy(?:er|ment)?|execution|executors?|x402|agentcash|agentpay|arbitrary[-_]?calls?|calldata)(?:$|[/._-])/iu;
const FINANCIAL_SIGNER_MODULE = /(?:^|[/._-])signers?(?:$|[/._-])/iu;
const INTEGRITY_SIGNER_PREFIXES = [
  "packages/checkpoints/",
  "packages/external-anchor/",
  "packages/release-bundle/",
];

const FORBIDDEN_CODE_IDENTIFIERS = new Set([
  "AgentCash",
  "ExecutionAdapter",
  "PolicyApproval",
  "PrivateKeyAccount",
  "WalletClient",
  "arbitraryCall",
  "broadcastTransaction",
  "calldata",
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
const FORBIDDEN_PROTOCOL_LITERALS = new Set([
  "arbitrary-call",
  "arbitrary_call",
  "eth_sendRawTransaction",
  "eth_sendTransaction",
  "wallet_sendCalls",
]);

class VerificationFailure extends Error {
  constructor(violations) {
    super(
      `Stage 0 authority isolation failed:\n${violations
        .map((violation, index) => `${index + 1}. ${violation}`)
        .join("\n")}`,
    );
    this.name = "VerificationFailure";
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
  let value;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${label} is unavailable or invalid JSON: ${error.message}`);
  }
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
      if (packages.has(manifest.name)) {
        throw new Error(`duplicate workspace package name: ${manifest.name}`);
      }
      packages.set(manifest.name, { directory, manifest, manifestPath });
    }
  }
  return packages;
}

const ACTIVE_RUNTIME_EXPORT_CONDITIONS = new Set([
  "node-addons",
  "node",
  "module-sync",
  "import",
  "require",
  // A caller can activate this normally tooling-only branch with
  // `--conditions=types`; require it to agree with every executable target.
  "types",
  "default",
]);
const REVIEWED_EXPORT_CONDITIONS = new Set(ACTIVE_RUNTIME_EXPORT_CONDITIONS);

function validateWorkspaceExports(value, label = "workspace exports") {
  if (typeof value === "string") {
    if (!value.startsWith("./")) {
      throw new Error(`${label} target must be a relative package path`);
    }
    if (value.includes("*") || value.endsWith("/")) {
      throw new Error(`${label} contains an unsupported wildcard/folder target ${value}`);
    }
    return;
  }
  if (value === null) {
    throw new Error(`${label} contains a null target`);
  }
  if (Array.isArray(value)) {
    throw new Error(`${label} contains an unsupported fallback array`);
  }
  if (typeof value !== "object") {
    throw new Error(`${label} contains an invalid target`);
  }
  const entries = Object.entries(value);
  const subpathEntries = entries.filter(([key]) => key.startsWith("."));
  if (subpathEntries.length > 0 && subpathEntries.length !== entries.length) {
    throw new Error(`${label} cannot mix subpath and condition keys`);
  }
  if (subpathEntries.length > 0) {
    for (const [key, target] of subpathEntries) {
      if ((key !== "." && !key.startsWith("./")) || key.includes("*") || key.endsWith("/")) {
        throw new Error(`${label} contains an unsupported wildcard/folder key ${key}`);
      }
      validateWorkspaceExports(target, `${label}[${key}]`);
    }
    return;
  }
  for (const [condition, target] of entries) {
    if (!REVIEWED_EXPORT_CONDITIONS.has(condition)) {
      throw new Error(`${label} contains unreviewed condition ${condition}`);
    }
    validateWorkspaceExports(target, `${label}[${condition}]`);
  }
}

function runtimeConditionTargets(value, targets = []) {
  if (typeof value === "string") {
    targets.push(value);
    return targets;
  }
  if (Array.isArray(value)) {
    for (const item of value) runtimeConditionTargets(item, targets);
    return targets;
  }
  if (value !== null && typeof value === "object") {
    for (const [condition, target] of Object.entries(value)) {
      if (ACTIVE_RUNTIME_EXPORT_CONDITIONS.has(condition)) {
        runtimeConditionTargets(target, targets);
      }
    }
  }
  return targets;
}

function conditionTarget(value) {
  const targets = [...new Set(runtimeConditionTargets(value))];
  if (targets.length > 1) {
    throw new Error(`workspace export has divergent runtime targets: ${targets.join(", ")}`);
  }
  if (targets.length === 1) return targets[0];
  if (typeof value === "string") return value;
  return undefined;
}

function exportValueForSubpath(exportsValue, subpath) {
  if (exportsValue !== undefined) validateWorkspaceExports(exportsValue);
  if (typeof exportsValue === "string" || Array.isArray(exportsValue)) {
    return subpath === "" ? exportsValue : undefined;
  }
  if (exportsValue === null || typeof exportsValue !== "object") return undefined;
  const keys = Object.keys(exportsValue);
  const subpathKeys = keys.filter((key) => key.startsWith("."));
  if (subpathKeys.length > 0 && subpathKeys.length !== keys.length) {
    throw new Error("workspace exports cannot mix subpath and condition keys");
  }
  if (subpathKeys.length > 0) {
    const exportKey = subpath === "" ? "." : `./${subpath}`;
    return exportsValue[exportKey];
  }
  return subpath === "" ? exportsValue : undefined;
}

function packageTarget(workspacePackage, subpath) {
  const { manifest } = workspacePackage;
  if (manifest.exports !== undefined) {
    const exportValue = exportValueForSubpath(manifest.exports, subpath);
    const target = conditionTarget(exportValue);
    if (target !== undefined) return target;
    return undefined;
  }
  if (subpath !== "") return `./src/${subpath}`;
  for (const field of ["main", "module"]) {
    if (typeof manifest[field] === "string") return manifest[field];
  }
  return "./src/index.ts";
}

const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

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

function packageForSpecifier(specifier, packages) {
  const candidates = [...packages.keys()]
    .filter((name) => specifier === name || specifier.startsWith(`${name}/`))
    .sort((left, right) => right.length - left.length);
  if (candidates.length === 0) return undefined;
  const name = candidates[0];
  return { name, workspacePackage: packages.get(name), subpath: specifier.slice(name.length + 1) };
}

function parseSource(path) {
  const text = readFileSync(path, "utf8");
  const scanner = ts.createScanner(true, ts.LanguageVariant.Standard, text);
  const tokens = [];
  const templateExpressions = [];
  const expressionEndingTokens = new Set(
    [
      ts.SyntaxKind.Identifier,
      ts.SyntaxKind.PrivateIdentifier,
      ts.SyntaxKind.NumericLiteral,
      ts.SyntaxKind.BigIntLiteral,
      ts.SyntaxKind.StringLiteral,
      ts.SyntaxKind.NoSubstitutionTemplateLiteral,
      ts.SyntaxKind.RegularExpressionLiteral,
      ts.SyntaxKind.TrueKeyword,
      ts.SyntaxKind.FalseKeyword,
      ts.SyntaxKind.NullKeyword,
      ts.SyntaxKind.ThisKeyword,
      ts.SyntaxKind.CloseParenToken,
      ts.SyntaxKind.CloseBracketToken,
      ts.SyntaxKind.CloseBraceToken,
      ts.SyntaxKind.PlusPlusToken,
      ts.SyntaxKind.MinusMinusToken,
      ts.SyntaxKind.TemplateTail,
    ].filter((kind) => kind !== undefined),
  );
  let previousKind;
  for (;;) {
    let kind = scanner.scan();
    if (
      kind === ts.SyntaxKind.SlashToken &&
      (previousKind === undefined || !expressionEndingTokens.has(previousKind))
    ) {
      kind = scanner.reScanSlashToken();
    }
    if (kind === ts.SyntaxKind.TemplateHead) {
      templateExpressions.push({ braceDepth: 0 });
    } else if (kind === ts.SyntaxKind.OpenBraceToken && templateExpressions.length > 0) {
      templateExpressions[templateExpressions.length - 1].braceDepth += 1;
    } else if (kind === ts.SyntaxKind.CloseBraceToken && templateExpressions.length > 0) {
      const template = templateExpressions[templateExpressions.length - 1];
      if (template.braceDepth > 0) {
        template.braceDepth -= 1;
      } else {
        kind = scanner.reScanTemplateToken(false);
        if (kind === ts.SyntaxKind.TemplateTail) templateExpressions.pop();
      }
    }
    if (kind === ts.SyntaxKind.EndOfFile) break;
    if (kind === ts.SyntaxKind.Unknown) {
      throw new Error(`unrecognized token at byte ${scanner.getTokenStart()}`);
    }
    tokens.push(
      Object.freeze({
        kind,
        text: scanner.getTokenText(),
        value: scanner.getTokenValue(),
      }),
    );
    previousKind = kind;
  }
  return Object.freeze({ path, text, tokens: Object.freeze(tokens) });
}

function analyzeSource(source) {
  const imports = [];
  const bareFetchIndexes = [];
  const runtimeDynamicImportIndexes = [];
  const forbiddenIdentifiers = [];
  const forbiddenLiterals = [];
  const forbiddenCryptoAuthority = new Set();
  const forbiddenDynamicCode = [];
  const forbiddenModuleLoaders = [];
  const forbiddenNetworkGlobals = new Set();
  const allLiterals = new Set();

  const isLiteral = (token) =>
    token?.kind === ts.SyntaxKind.StringLiteral ||
    token?.kind === ts.SyntaxKind.NoSubstitutionTemplateLiteral;
  const isTemplateFragment = (token) =>
    token?.kind === ts.SyntaxKind.TemplateHead ||
    token?.kind === ts.SyntaxKind.TemplateMiddle ||
    token?.kind === ts.SyntaxKind.TemplateTail;
  const moduleLiteral = (token) => (isLiteral(token) ? token.value : undefined);
  const statementEnd = (start) => {
    for (let index = start; index < source.tokens.length; index += 1) {
      if (source.tokens[index].kind === ts.SyntaxKind.SemicolonToken) return index;
      if (index > start && source.tokens[index].kind === ts.SyntaxKind.ImportKeyword) return index;
      if (index > start && source.tokens[index].kind === ts.SyntaxKind.ExportKeyword) return index;
      if (index - start >= 256) return index;
    }
    return source.tokens.length;
  };
  const destructuresFromProcess = (propertyIndex) => {
    let openBrace = -1;
    for (let cursor = propertyIndex - 1; cursor >= Math.max(0, propertyIndex - 64); cursor -= 1) {
      const kind = source.tokens[cursor].kind;
      if (kind === ts.SyntaxKind.SemicolonToken || kind === ts.SyntaxKind.EqualsToken) break;
      if (kind === ts.SyntaxKind.OpenBraceToken) {
        openBrace = cursor;
        break;
      }
    }
    if (openBrace < 0) return false;
    let closeBrace = -1;
    for (
      let cursor = propertyIndex + 1;
      cursor < Math.min(source.tokens.length, propertyIndex + 64);
      cursor += 1
    ) {
      const kind = source.tokens[cursor].kind;
      if (kind === ts.SyntaxKind.SemicolonToken || kind === ts.SyntaxKind.EqualsToken) break;
      if (kind === ts.SyntaxKind.CloseBraceToken) {
        closeBrace = cursor;
        break;
      }
    }
    if (closeBrace < 0) return false;
    for (
      let cursor = closeBrace + 1;
      cursor < Math.min(source.tokens.length - 1, closeBrace + 32);
      cursor += 1
    ) {
      if (source.tokens[cursor].kind === ts.SyntaxKind.SemicolonToken) return false;
      if (source.tokens[cursor].kind !== ts.SyntaxKind.EqualsToken) continue;
      return (
        source.tokens[cursor + 1]?.kind === ts.SyntaxKind.Identifier &&
        source.tokens[cursor + 1]?.value === "process"
      );
    }
    return false;
  };

  for (let index = 0; index < source.tokens.length; index += 1) {
    const token = source.tokens[index];
    const identifier =
      token.kind === ts.SyntaxKind.Identifier || token.kind === ts.SyntaxKind.RequireKeyword
        ? (token.value ?? token.text)
        : undefined;
    const networkGlobalObject =
      token.kind === ts.SyntaxKind.Identifier || token.kind === ts.SyntaxKind.GlobalKeyword
        ? (token.value ?? token.text)
        : undefined;
    if (token.kind === ts.SyntaxKind.Identifier && FORBIDDEN_CODE_IDENTIFIERS.has(token.value)) {
      forbiddenIdentifiers.push(token.value);
    }
    if (
      token.kind === ts.SyntaxKind.Identifier &&
      FORBIDDEN_CRYPTO_AUTHORITY_IDENTIFIERS.has(token.value)
    ) {
      forbiddenCryptoAuthority.add(token.value);
    }
    if (identifier !== undefined && FORBIDDEN_MODULE_LOADER_IDENTIFIERS.has(identifier)) {
      forbiddenModuleLoaders.push(identifier);
    }
    if (
      token.kind === ts.SyntaxKind.Identifier &&
      FORBIDDEN_DYNAMIC_CODE_IDENTIFIERS.has(token.value)
    ) {
      forbiddenDynamicCode.push(token.value);
    }
    if (
      token.kind === ts.SyntaxKind.ConstructorKeyword &&
      source.tokens[index - 1]?.kind === ts.SyntaxKind.DotToken
    ) {
      forbiddenDynamicCode.push("constructor");
    }
    if (identifier !== undefined && FORBIDDEN_NETWORK_GLOBALS.has(identifier)) {
      forbiddenNetworkGlobals.add(identifier);
    }
    if (isLiteral(token) || isTemplateFragment(token)) {
      allLiterals.add(token.value);
    }
    if (isLiteral(token)) {
      if (token.value === "fetch" || FORBIDDEN_NETWORK_GLOBALS.has(token.value)) {
        forbiddenNetworkGlobals.add(`computed ${token.value}`);
      }
      if (FORBIDDEN_DYNAMIC_CODE_LITERALS.has(token.value)) {
        forbiddenDynamicCode.push(token.value);
      }
      if (
        token.value === "constructor" &&
        source.tokens[index - 1]?.kind === ts.SyntaxKind.OpenBracketToken &&
        source.tokens[index + 1]?.kind === ts.SyntaxKind.CloseBracketToken
      ) {
        forbiddenDynamicCode.push("constructor");
      }
      if (FORBIDDEN_CRYPTO_AUTHORITY_LITERALS.has(token.value)) {
        forbiddenCryptoAuthority.add(token.value);
      }
      if (
        FORBIDDEN_PROTOCOL_LITERALS.has(token.value) ||
        FORBIDDEN_CODE_IDENTIFIERS.has(token.value)
      ) {
        forbiddenLiterals.push(token.value);
      }
      if (FORBIDDEN_MODULE_LOADER_LITERALS.has(token.value)) {
        forbiddenModuleLoaders.push(token.value);
      }
    }

    if (identifier === "fetch") {
      forbiddenNetworkGlobals.add("fetch");
      if (source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenParenToken) {
        bareFetchIndexes.push(index);
      }
    }
    if (
      ["global", "globalThis", "self", "window"].includes(networkGlobalObject) &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenBracketToken &&
      moduleLiteral(source.tokens[index + 2]) === "fetch"
    ) {
      forbiddenNetworkGlobals.add(`${networkGlobalObject}[fetch]`);
    }
    if (
      identifier === "Reflect" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      (source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier ||
        source.tokens[index + 2]?.kind === ts.SyntaxKind.GetKeyword) &&
      (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "get" &&
      source.tokens[index + 3]?.kind === ts.SyntaxKind.OpenParenToken &&
      source.tokens[index + 4]?.kind === ts.SyntaxKind.Identifier &&
      ["global", "globalThis", "self", "window"].includes(source.tokens[index + 4]?.value) &&
      source.tokens[index + 5]?.kind === ts.SyntaxKind.CommaToken &&
      moduleLiteral(source.tokens[index + 6]) === "fetch"
    ) {
      forbiddenNetworkGlobals.add(`Reflect.get(${source.tokens[index + 4].value}, fetch)`);
    }
    if (
      identifier === "process" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier &&
      FORBIDDEN_PROCESS_LOADER_APIS.has(source.tokens[index + 2]?.value)
    ) {
      forbiddenModuleLoaders.push(`process.${source.tokens[index + 2].value}`);
    }
    if (
      identifier === "process" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenBracketToken &&
      FORBIDDEN_PROCESS_LOADER_APIS.has(moduleLiteral(source.tokens[index + 2]))
    ) {
      forbiddenModuleLoaders.push(`process.${moduleLiteral(source.tokens[index + 2])}`);
    }
    if (
      identifier === "Reflect" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      (source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier ||
        source.tokens[index + 2]?.kind === ts.SyntaxKind.GetKeyword) &&
      (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "get" &&
      source.tokens[index + 3]?.kind === ts.SyntaxKind.OpenParenToken &&
      source.tokens[index + 4]?.kind === ts.SyntaxKind.Identifier &&
      source.tokens[index + 4]?.value === "process" &&
      source.tokens[index + 5]?.kind === ts.SyntaxKind.CommaToken &&
      FORBIDDEN_PROCESS_LOADER_APIS.has(moduleLiteral(source.tokens[index + 6]))
    ) {
      forbiddenModuleLoaders.push(`process.${moduleLiteral(source.tokens[index + 6])}`);
    }
    if (
      identifier !== undefined &&
      FORBIDDEN_PROCESS_LOADER_APIS.has(identifier) &&
      destructuresFromProcess(index)
    ) {
      forbiddenModuleLoaders.push(`process.${identifier}`);
    }

    if (token.kind === ts.SyntaxKind.ImportKeyword) {
      const next = source.tokens[index + 1];
      if (next?.kind === ts.SyntaxKind.DotToken) continue;
      if (next?.kind === ts.SyntaxKind.OpenParenToken) {
        runtimeDynamicImportIndexes.push(index);
        const specifier = moduleLiteral(source.tokens[index + 2]);
        const closed = source.tokens[index + 3]?.kind === ts.SyntaxKind.CloseParenToken;
        imports.push(
          specifier !== undefined && closed
            ? { dynamic: false, names: [], specifier }
            : { dynamic: true, names: [], specifier: null },
        );
        continue;
      }

      // Type-only imports are erased by TypeScript and grant no runtime authority.
      if (next?.kind === ts.SyntaxKind.TypeKeyword) continue;

      const end = statementEnd(index + 1);
      const sideEffectSpecifier = moduleLiteral(next);
      if (sideEffectSpecifier !== undefined) {
        imports.push({ dynamic: false, names: [], specifier: sideEffectSpecifier });
        continue;
      }
      let fromIndex = -1;
      let containsRequire = false;
      for (let cursor = index + 1; cursor < end; cursor += 1) {
        if (
          (source.tokens[cursor].kind === ts.SyntaxKind.Identifier ||
            source.tokens[cursor].kind === ts.SyntaxKind.RequireKeyword) &&
          (source.tokens[cursor].value ?? source.tokens[cursor].text) === "require"
        ) {
          containsRequire = true;
        }
        if (source.tokens[cursor].kind !== ts.SyntaxKind.FromKeyword) continue;
        fromIndex = cursor;
        break;
      }
      if (fromIndex >= 0) {
        const specifier = moduleLiteral(source.tokens[fromIndex + 1]);
        const names = [];
        for (let cursor = index + 1; cursor < fromIndex; cursor += 1) {
          const candidate = source.tokens[cursor];
          if (candidate.kind === ts.SyntaxKind.Identifier) names.push(candidate.value);
          if (candidate.kind === ts.SyntaxKind.StringLiteral) names.push(candidate.value);
        }
        imports.push(
          specifier === undefined
            ? { dynamic: true, names, specifier: null }
            : { dynamic: false, names, specifier },
        );
      } else if (!containsRequire) {
        imports.push({ dynamic: true, names: [], specifier: null });
      }
      continue;
    }

    if (token.kind === ts.SyntaxKind.ExportKeyword) {
      let declarationStart = index + 1;
      if (source.tokens[declarationStart]?.kind === ts.SyntaxKind.TypeKeyword) {
        // `export type ... from` is also erased from the runtime graph.
        continue;
      }
      if (
        source.tokens[declarationStart]?.kind !== ts.SyntaxKind.OpenBraceToken &&
        source.tokens[declarationStart]?.kind !== ts.SyntaxKind.AsteriskToken
      ) {
        continue;
      }
      const end = statementEnd(index + 1);
      for (let cursor = declarationStart + 1; cursor < end; cursor += 1) {
        if (source.tokens[cursor].kind !== ts.SyntaxKind.FromKeyword) continue;
        const specifier = moduleLiteral(source.tokens[cursor + 1]);
        imports.push(
          specifier === undefined
            ? { dynamic: true, names: [], specifier: null }
            : { dynamic: false, names: [], specifier },
        );
        break;
      }
      continue;
    }

    if (
      identifier === "require" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenParenToken
    ) {
      const specifier = moduleLiteral(source.tokens[index + 2]);
      const closed = source.tokens[index + 3]?.kind === ts.SyntaxKind.CloseParenToken;
      imports.push(
        specifier !== undefined && closed
          ? { dynamic: false, names: [], specifier }
          : { dynamic: true, names: [], specifier: null },
      );
    }
  }
  return {
    bareFetchIndexes,
    imports,
    forbiddenCryptoAuthority: [...forbiddenCryptoAuthority].sort(),
    forbiddenDynamicCode: [...new Set(forbiddenDynamicCode)].sort(),
    forbiddenIdentifiers: [...new Set(forbiddenIdentifiers)].sort(),
    forbiddenLiterals: [...new Set(forbiddenLiterals)].sort(),
    forbiddenModuleLoaders: [...new Set(forbiddenModuleLoaders)].sort(),
    forbiddenNetworkGlobals: [...forbiddenNetworkGlobals].sort(),
    literals: allLiterals,
    runtimeDynamicImportIndexes,
  };
}

function classifyModuleSpecifier(specifier, relativeFile, names = []) {
  if (FORBIDDEN_NETWORK_MODULES.has(specifier)) {
    return `unapproved network platform module ${specifier}`;
  }
  if (FORBIDDEN_PLATFORM_MODULES.has(specifier)) {
    return `platform module ${specifier} (${FORBIDDEN_PLATFORM_MODULES.get(specifier)})`;
  }
  const special = SPECIAL_PLATFORM_IMPORTS.get(specifier);
  if (special !== undefined) {
    const actualNames = [...new Set(names)].sort();
    const allowedNames =
      special.files instanceof Map
        ? special.files.get(relativeFile)
        : relativeFile === special.file
          ? special.names
          : undefined;
    if (allowedNames === undefined) {
      const allowedFiles =
        special.files instanceof Map ? [...special.files.keys()].sort().join(", ") : special.file;
      return `${specifier} is allowed only in ${allowedFiles}`;
    }
    if (
      actualNames.length !== allowedNames.length ||
      actualNames.some((name, index) => name !== allowedNames[index])
    ) {
      return `${specifier} imports must be exactly ${allowedNames.join(", ")}`;
    }
    return undefined;
  }
  if (REVIEWED_SIGNER_BLIND_SUBPATHS.has(specifier)) return undefined;
  if (FORBIDDEN_WORKSPACE_PACKAGES.has(specifier)) {
    return `forbidden workspace package ${specifier} (${FORBIDDEN_WORKSPACE_PACKAGES.get(specifier)})`;
  }
  for (const [name, reason] of FORBIDDEN_WORKSPACE_PACKAGES) {
    if (specifier.startsWith(`${name}/`)) return `forbidden workspace package ${name} (${reason})`;
  }
  if (specifier === "viem" || specifier.startsWith("viem/")) {
    return `wallet/transaction-capable package ${specifier}`;
  }
  if (FORBIDDEN_EXTERNAL_PACKAGE.test(specifier)) {
    return `financial-authority package ${specifier}`;
  }
  return undefined;
}

function classifyLocalPath(root, path) {
  const relativePath = canonicalRelative(root, path);
  for (const [prefix, reason] of FORBIDDEN_LOCAL_PREFIXES) {
    if (relativePath === prefix || relativePath.startsWith(prefix)) {
      return `${reason} ${relativePath}`;
    }
  }
  if (OFFLINE_ONLY_ENTRYPOINTS.has(relativePath)) {
    return `offline-only CLI entrypoint ${relativePath}`;
  }
  if (FORBIDDEN_LOCAL_MODULE.test(relativePath)) {
    return `financial-authority module path ${relativePath}`;
  }
  if (
    FINANCIAL_SIGNER_MODULE.test(relativePath) &&
    !INTEGRITY_SIGNER_PREFIXES.some((prefix) => relativePath.startsWith(prefix))
  ) {
    return `signer module path ${relativePath}`;
  }
  return undefined;
}

function importPath(parentByFile, root, from, to) {
  const chain = [to];
  let cursor = from;
  while (cursor !== undefined) {
    chain.push(cursor);
    cursor = parentByFile.get(cursor);
  }
  return chain
    .reverse()
    .map((path) => canonicalRelative(root, path))
    .join(" -> ");
}

function inspectModuleGraph(root, roots, packages, label) {
  const violations = [];
  const visited = new Set();
  const parentByFile = new Map();
  const pending = [];
  for (const rootPath of roots) {
    const resolvedRoot = resolveSourceFile(join(root, rootPath));
    if (resolvedRoot === undefined) {
      violations.push(`${label}: required entrypoint ${rootPath} is missing`);
    } else {
      pending.push(resolvedRoot);
    }
  }

  while (pending.length > 0) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    const relativeFile = canonicalRelative(root, file);
    const localClassification = classifyLocalPath(root, file);
    if (localClassification !== undefined) {
      violations.push(`${label}: reached ${localClassification}`);
    }

    let analysis;
    try {
      analysis = analyzeSource(parseSource(file));
    } catch (error) {
      violations.push(`${label}: cannot parse ${relativeFile}: ${error.message}`);
      continue;
    }
    if (analysis.forbiddenIdentifiers.length > 0) {
      violations.push(
        `${label}: ${relativeFile} references financial-authority identifier(s): ${analysis.forbiddenIdentifiers.join(", ")}`,
      );
    }
    if (analysis.forbiddenCryptoAuthority.length > 0) {
      violations.push(
        `${label}: ${relativeFile} references cryptographic signing/key-authority API(s): ${analysis.forbiddenCryptoAuthority.join(", ")}`,
      );
    }
    if (analysis.forbiddenLiterals.length > 0) {
      violations.push(
        `${label}: ${relativeFile} declares financial-authority/arbitrary-call capability literal(s): ${analysis.forbiddenLiterals.join(", ")}`,
      );
    }
    if (analysis.forbiddenModuleLoaders.length > 0) {
      violations.push(
        `${label}: ${relativeFile} references alternate module-loader API(s): ${analysis.forbiddenModuleLoaders.join(", ")}`,
      );
    }
    if (analysis.forbiddenDynamicCode.length > 0) {
      violations.push(
        `${label}: ${relativeFile} references dynamic-code API(s): ${analysis.forbiddenDynamicCode.join(", ")}`,
      );
    }
    if (analysis.forbiddenNetworkGlobals.length > 0) {
      violations.push(
        `${label}: ${relativeFile} references an unapproved network global: ${analysis.forbiddenNetworkGlobals.join(", ")}`,
      );
    }
    if (analysis.bareFetchIndexes.length > 0) {
      violations.push(`${label}: ${relativeFile} contains an unaudited bare fetch call`);
    }
    if (analysis.runtimeDynamicImportIndexes.length > 0) {
      violations.push(`${label}: ${relativeFile} contains a runtime import() expression`);
    }
    for (const literal of analysis.literals) {
      if (typeof literal !== "string") continue;
      for (const match of literal.matchAll(NETWORK_URL_LITERAL)) {
        const url = match[0];
        if (!REVIEWED_NETWORK_URL_LITERALS.has(url)) {
          violations.push(`${label}: ${relativeFile} declares unreviewed network origin ${url}`);
        }
      }
    }

    for (const dependency of analysis.imports) {
      if (dependency.dynamic) {
        violations.push(`${label}: ${relativeFile} contains a non-literal import/require`);
        continue;
      }
      const specifier = dependency.specifier;
      const classification = classifyModuleSpecifier(specifier, relativeFile, dependency.names);
      if (classification !== undefined) {
        violations.push(`${label}: ${relativeFile} imports ${classification}`);
        continue;
      }
      if (SPECIAL_PLATFORM_IMPORTS.has(specifier)) continue;

      let resolvedDependency;
      if (specifier.startsWith(".") || isAbsolute(specifier)) {
        const candidate = isAbsolute(specifier) ? specifier : resolve(dirname(file), specifier);
        resolvedDependency = resolveSourceFile(candidate);
        if (resolvedDependency === undefined) {
          violations.push(`${label}: ${relativeFile} has unresolved local import ${specifier}`);
          continue;
        }
      } else {
        const workspace = packageForSpecifier(specifier, packages);
        if (workspace !== undefined) {
          let target;
          try {
            target = packageTarget(workspace.workspacePackage, workspace.subpath);
          } catch (error) {
            violations.push(
              `${relativeFile} cannot resolve runtime workspace export ${specifier}: ${error.message}`,
            );
            continue;
          }
          if (target === undefined) {
            violations.push(
              `${label}: ${relativeFile} cannot resolve workspace export ${specifier}`,
            );
            continue;
          }
          resolvedDependency = resolveSourceFile(
            resolve(workspace.workspacePackage.directory, target),
          );
          if (resolvedDependency === undefined) {
            violations.push(
              `${label}: ${relativeFile} cannot resolve workspace import ${specifier}`,
            );
            continue;
          }
        } else if (SAFE_PLATFORM_MODULES.has(specifier) || SAFE_EXTERNAL_MODULES.has(specifier)) {
          continue;
        } else if (NODE_BUILTINS.has(specifier)) {
          violations.push(
            `${label}: ${relativeFile} reaches unreviewed platform module ${specifier}`,
          );
          continue;
        } else {
          violations.push(
            `${label}: ${relativeFile} reaches unreviewed external module ${specifier}`,
          );
          continue;
        }
      }

      if (!isInside(root, resolvedDependency)) {
        violations.push(
          `${label}: ${relativeFile} resolves outside the repository via ${specifier}`,
        );
        continue;
      }
      const resolvedClassification = classifyLocalPath(root, resolvedDependency);
      if (resolvedClassification !== undefined) {
        violations.push(
          `${label}: ${importPath(parentByFile, root, file, resolvedDependency)} reaches ${resolvedClassification}`,
        );
        continue;
      }
      if (!parentByFile.has(resolvedDependency)) parentByFile.set(resolvedDependency, file);
      pending.push(resolvedDependency);
    }
  }

  return { files: Object.freeze([...visited].sort()), violations };
}

function listSourceFiles(directory) {
  if (!existsSync(directory)) return [];
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...listSourceFiles(path));
    else if (entry.isFile() && SOURCE_EXTENSIONS.includes(extname(entry.name))) files.push(path);
  }
  return files.sort();
}

function verifyRuntimeManifest(root, violations) {
  const path = join(root, RUNTIME_DIRECTORY, "package.json");
  if (!existsSync(path)) {
    violations.push(`runtime manifest is missing: ${canonicalRelative(root, path)}`);
    return;
  }
  let manifest;
  try {
    manifest = readJson(path, canonicalRelative(root, path));
  } catch (error) {
    violations.push(error.message);
    return;
  }
  if (manifest.name !== "@rsi/runtime") {
    violations.push(`runtime manifest name must be @rsi/runtime`);
  }
  const dependencies = manifest.dependencies ?? {};
  if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies)) {
    violations.push(`@rsi/runtime dependencies must be an object`);
    return;
  }
  const names = Object.keys(dependencies).sort();
  for (const name of names) {
    const classification = classifyModuleSpecifier(name);
    if (classification !== undefined) {
      violations.push(`@rsi/runtime manifest reaches ${classification}`);
    } else if (!ALLOWED_RUNTIME_DEPENDENCIES.has(name)) {
      violations.push(`@rsi/runtime manifest has unreviewed production dependency ${name}`);
    }
  }
  for (const required of ALLOWED_RUNTIME_DEPENDENCIES) {
    if (!Object.hasOwn(dependencies, required)) {
      violations.push(`@rsi/runtime manifest is missing reviewed dependency ${required}`);
    }
  }
  let exportTarget;
  try {
    exportTarget = conditionTarget(exportValueForSubpath(manifest.exports, ""));
  } catch (error) {
    violations.push(`@rsi/runtime has an invalid runtime export: ${error.message}`);
  }
  if (exportTarget !== "./src/index.ts") {
    violations.push(`@rsi/runtime must export only ./src/index.ts from its root entrypoint`);
  }
  if (
    typeof manifest.exports === "object" &&
    manifest.exports !== null &&
    !Array.isArray(manifest.exports) &&
    Object.keys(manifest.exports).some((key) => key.startsWith(".") && key !== ".")
  ) {
    violations.push(`@rsi/runtime must not expose authority bypass subpath exports`);
  }
}

function literalCorpus(files, violations, label) {
  const literals = new Set();
  for (const file of files) {
    try {
      for (const literal of analyzeSource(parseSource(file)).literals) literals.add(literal);
    } catch (error) {
      violations.push(`${label}: cannot parse ${file}: ${error.message}`);
    }
  }
  return literals;
}

function verifyPermanentDenials(root, violations) {
  const sourceFiles = listSourceFiles(join(root, RUNTIME_DIRECTORY, "src"));
  const testFiles = listSourceFiles(join(root, RUNTIME_DIRECTORY, "test"));
  if (sourceFiles.length === 0) violations.push(`@rsi/runtime has no source files`);
  if (testFiles.length === 0) violations.push(`@rsi/runtime has no adversarial test files`);
  const sourceLiterals = literalCorpus(sourceFiles, violations, "runtime source");
  const testLiterals = literalCorpus(testFiles, violations, "runtime tests");

  for (const boundary of REQUIRED_DENIED_BOUNDARIES) {
    if (!sourceLiterals.has(boundary)) {
      violations.push(`runtime source does not declare permanently denied boundary ${boundary}`);
    }
    if (!testLiterals.has(boundary)) {
      violations.push(`runtime tests do not exercise permanently denied boundary ${boundary}`);
    }
  }
  if (!sourceLiterals.has(REQUIRED_DENIAL_REASON)) {
    violations.push(`runtime source does not declare denial reason ${REQUIRED_DENIAL_REASON}`);
  }
  if (!testLiterals.has(REQUIRED_DENIAL_REASON)) {
    violations.push(`runtime tests do not assert denial reason ${REQUIRED_DENIAL_REASON}`);
  }
}

export function verifyStage0AuthorityBoundary(options = {}) {
  const root = realpathSync(options.root ?? DEFAULT_ROOT);
  const violations = [];

  verifyRuntimeManifest(root, violations);
  let packages;
  try {
    packages = discoverWorkspacePackages(root);
  } catch (error) {
    violations.push(error.message);
    packages = new Map();
  }

  const runtimeGraph = inspectModuleGraph(root, [RUNTIME_ENTRY], packages, "runtime graph");
  const operatorGraph = inspectModuleGraph(root, [OPERATOR_ENTRY], packages, "operator graph");
  violations.push(...runtimeGraph.violations, ...operatorGraph.violations);
  verifyPermanentDenials(root, violations);

  const uniqueViolations = [...new Set(violations)].sort();
  if (uniqueViolations.length > 0) throw new VerificationFailure(uniqueViolations);
  return Object.freeze({
    deniedBoundaries: REQUIRED_DENIED_BOUNDARIES,
    operatorFiles: operatorGraph.files.length,
    runtimeFiles: runtimeGraph.files.length,
    status: "pass",
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(THIS_FILE);
}

if (isMainModule()) {
  try {
    const report = verifyStage0AuthorityBoundary();
    console.log(
      `Stage 0 authority isolation passed: ${report.runtimeFiles} runtime graph files, ` +
        `${report.operatorFiles} operator graph files, ${report.deniedBoundaries.length} permanent denials.`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

export { VerificationFailure };
