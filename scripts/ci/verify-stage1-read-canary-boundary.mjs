#!/usr/bin/env node

import { builtinModules } from "node:module";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import * as ts from "typescript/unstable/ast";

const THIS_FILE = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = resolve(dirname(THIS_FILE), "../..");
const ENTRY = "apps/cli/src/x-canary-operator.ts";

const REQUIRED_PACKAGES = Object.freeze([
  "@rsi/capture-registry",
  "@rsi/credential-host",
  "@rsi/ingestion",
  "@rsi/operations",
  "@rsi/operator",
  "@rsi/read-canary",
  "@rsi/research-ledger",
  "@rsi/runtime",
  "@rsi/store",
  "@rsi/vault",
  "@rsi/x-collector",
]);

const REVIEWED_WORKSPACE_IMPORTS = new Set([
  ...REQUIRED_PACKAGES,
  "@rsi/credential-host/one-shot-claim",
  // These two signer-blind support surfaces are already part of the operator and
  // research-ledger implementation. The executable @rsi/domain root is denied.
  "@rsi/domain/proposals",
  "@rsi/session-lifecycle",
]);

const ALLOWED_SOURCE_PREFIXES = Object.freeze([
  "apps/operator/src/",
  "packages/capture-registry/src/",
  "packages/credential-host/src/",
  "packages/ingestion/src/",
  "packages/operations/src/",
  "packages/read-canary/src/",
  "packages/research-ledger/src/",
  "packages/runtime/src/",
  "packages/session-lifecycle/src/",
  "packages/store/src/",
  "packages/vault/src/",
  "packages/x-collector/src/",
]);

const EXACT_ALLOWED_SOURCE_FILES = new Set([
  ENTRY,
  "apps/cli/src/production-canary-config.ts",
  "apps/cli/src/production-runtime.ts",
  "apps/cli/src/x-canary-operator-options.ts",
  "apps/cli/src/x-canary-operator-host.ts",
  "apps/cli/src/x-canary-operator-host-core.ts",
  "packages/domain/src/proposals.ts",
]);
const FORBIDDEN_EXACT_SOURCE_FILES = new Map([
  ["packages/x-collector/src/testing.ts", "test-only transport injection source"],
  ["packages/credential-host/src/testing.ts", "test-only credential injection source"],
]);
const CREDENTIAL_TEST_ONLY_IDENTIFIERS = new Set([
  "CredentialCommandExecutor",
  "CredentialCommandRequest",
  "CredentialCommandResult",
  "DarwinXReadCanaryKeychainTestingOptions",
  "createDarwinXReadCanaryKeychainForTesting",
]);
const COLLECTOR_TEST_ONLY_IDENTIFIERS = new Set([
  "XRecentSearchCollectorTestingOptions",
  "XRecentSearchFetch",
  "XRecentSearchLiveTestingOptions",
  "createXRecentSearchCollectorForTesting",
]);

const SAFE_EXTERNAL_MODULES = new Set(["zod"]);
const SAFE_PLATFORM_MODULES = new Set([
  "node:async_hooks",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:path",
  "node:perf_hooks",
  "node:sqlite",
  "node:util",
]);
const REVIEWED_CRYPTO_IMPORTS = new Map([
  ["apps/cli/src/x-canary-operator-host-core.ts", Object.freeze(["randomUUID"])],
  [
    "packages/capture-registry/src/crypto.ts",
    Object.freeze([
      "createCipheriv",
      "createDecipheriv",
      "createHmac",
      "hkdfSync",
      "randomBytes",
      "timingSafeEqual",
    ]),
  ],
  ["packages/capture-registry/src/sqlite-capture-registry.ts", Object.freeze(["randomBytes"])],
  ["packages/ingestion/src/x-ingestion.ts", Object.freeze(["createHash"])],
  [
    "packages/operations/src/crypto.ts",
    Object.freeze([
      "createCipheriv",
      "createDecipheriv",
      "createHash",
      "createHmac",
      "hkdfSync",
      "randomBytes",
      "timingSafeEqual",
    ]),
  ],
  [
    "packages/operations/src/sqlite-operations-store.ts",
    Object.freeze(["randomBytes", "randomUUID"]),
  ],
  ["packages/read-canary/src/x-read-canary-controller.ts", Object.freeze(["randomUUID"])],
  [
    "packages/session-lifecycle/src/sqlite-session-coordinator.ts",
    Object.freeze(["createHmac", "hkdfSync", "timingSafeEqual"]),
  ],
  ["packages/store/src/sqlite-event-store.ts", Object.freeze(["createHash", "randomUUID"])],
  [
    "packages/vault/src/snapshot-vault.ts",
    Object.freeze(["createCipheriv", "createDecipheriv", "hkdfSync", "randomBytes"]),
  ],
  ["packages/x-collector/src/hash.ts", Object.freeze(["createHash"])],
]);
const REVIEWED_FS_IMPORTS = new Map([
  [
    "node:fs\0packages/capture-registry/src/sqlite-capture-registry.ts",
    Object.freeze([
      "Stats",
      "closeSync",
      "constants",
      "fchmodSync",
      "fstatSync",
      "lstatSync",
      "mkdirSync",
      "openSync",
      "realpathSync",
    ]),
  ],
  [
    "node:fs\0packages/session-lifecycle/src/sqlite-session-coordinator.ts",
    Object.freeze(["chmodSync", "existsSync", "lstatSync", "mkdirSync"]),
  ],
  ["node:fs\0packages/vault/src/snapshot-vault.ts", Object.freeze(["constants", "fsConstants"])],
  [
    "node:fs/promises\0apps/cli/src/x-canary-operator-host-core.ts",
    Object.freeze(["lstat", "mkdir", "realpath", "stat"]),
  ],
  [
    "node:fs/promises\0packages/vault/src/snapshot-vault.ts",
    Object.freeze([
      "FileHandle",
      "link",
      "lstat",
      "mkdir",
      "open",
      "readdir",
      "realpath",
      "unlink",
    ]),
  ],
]);
const SPECIAL_PLATFORM_IMPORTS = new Map([
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
  [
    "node:child_process",
    Object.freeze({
      file: "packages/credential-host/src/x-read-canary-keychain.ts",
      names: Object.freeze(["execFile"]),
    }),
  ],
]);
const REVIEWED_PROCESS_PROPERTIES = new Map([
  ["apps/cli/src/x-canary-operator.ts", new Set(["argv", "exitCode", "once", "stderr"])],
  ["apps/cli/src/production-runtime.ts", new Set(["env", "versions"])],
  ["apps/cli/src/x-canary-operator-host-core.ts", new Set(["geteuid"])],
  ["packages/capture-registry/src/sqlite-capture-registry.ts", new Set(["geteuid"])],
  ["packages/credential-host/src/x-read-canary-keychain.ts", new Set(["platform"])],
  ["packages/credential-host/src/one-shot-claim-keychain.ts", new Set(["platform"])],
  ["packages/vault/src/snapshot-vault.ts", new Set(["geteuid"])],
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
const FORBIDDEN_PLATFORM_MODULES = new Set([
  "child_process",
  "cluster",
  "module",
  "node:cluster",
  "node:module",
  "node:vm",
  "node:worker_threads",
  "vm",
  "worker_threads",
]);
const NODE_BUILTINS = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);

const FORBIDDEN_EXTERNAL_PACKAGE =
  /(?:^|[/@._-])(?:agentcash|agentpay|axios|ethers|got|graphql-request|ky|node-fetch|permissionless|pimlico|safe-global|superagent|undici|viem|wagmi|walletconnect|web3|ws|x402)(?:$|[/@._-])/iu;
const FORBIDDEN_LOCAL_PATH =
  /(?:^|[/._-])(?:adapters?|agentcash|agentpay|arbitrary[-_]?calls?|broadcast(?:er)?|calldata|deploy(?:er|ment)?|execution|executors?|payments?|policy|publications?|signers?|transactions?|wallets?|x402)(?:$|[/._-])/iu;

const FORBIDDEN_AUTHORITY_IDENTIFIERS = new Set([
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
const FORBIDDEN_DYNAMIC_IDENTIFIERS = new Set([
  "AsyncFunction",
  "eval",
  "Function",
  "GeneratorFunction",
]);
const FORBIDDEN_LOADER_IDENTIFIERS = new Set([
  "_load",
  "_linkedBinding",
  "allowExtension",
  "createRequire",
  "dlopen",
  "enableLoadExtension",
  "getBuiltinModule",
  "loadExtension",
  "mainModule",
]);
const FORBIDDEN_LOADER_LITERALS = new Set([...FORBIDDEN_LOADER_IDENTIFIERS, "binding", "require"]);
const FORBIDDEN_NETWORK_GLOBALS = new Set([
  "EventSource",
  "WebSocket",
  "XMLHttpRequest",
  "sendBeacon",
]);
const FORBIDDEN_CRYPTO_CAPABILITIES = new Set([
  "KeyObject",
  "createPrivateKey",
  "createPublicKey",
  "generateKey",
  "generateKeyPair",
  "generateKeyPairSync",
  "importKey",
  "privateDecrypt",
  "privateEncrypt",
  "sign",
  "subtle",
]);
const FORBIDDEN_CHILD_PROCESS_APIS = new Set([
  "exec",
  "execFileSync",
  "execSync",
  "fork",
  "spawn",
  "spawnSync",
]);

const COLLECTOR_FILE = "packages/x-collector/src/collector.ts";
const COLLECTOR_INDEX_FILE = "packages/x-collector/src/index.ts";
const CONSTANTS_FILE = "packages/x-collector/src/constants.ts";
const QUERY_FILE = "packages/x-collector/src/query.ts";
const CANARY_CONSTANTS_FILE = "packages/read-canary/src/constants.ts";
const READ_CANARY_CONTROLLER_FILE = "packages/read-canary/src/x-read-canary-controller.ts";
const READ_CANARY_SCHEMAS_FILE = "packages/read-canary/src/schemas.ts";
const RUNTIME_AUTHORIZATION_FILE = "packages/runtime/src/boundary-authorization.ts";
const RUNTIME_CONTROLLER_FILE = "packages/runtime/src/sqlite-runtime-controller.ts";
const OPERATIONS_STORE_FILE = "packages/operations/src/sqlite-operations-store.ts";
const KEYCHAIN_FILE = "packages/credential-host/src/x-read-canary-keychain.ts";
const KEYCHAIN_INDEX_FILE = "packages/credential-host/src/index.ts";
const ONE_SHOT_CLAIM_FILE = "packages/credential-host/src/one-shot-claim-keychain.ts";
const ONE_SHOT_CLAIM_ENTRY_FILE = "packages/credential-host/src/one-shot-claim.ts";
const OPERATOR_SERVER_FILE = "apps/operator/src/server.ts";
const PRODUCTION_CONFIG_FILE = "apps/cli/src/production-canary-config.ts";
const PRODUCTION_RUNTIME_FILE = "apps/cli/src/production-runtime.ts";
const OPERATOR_OPTIONS_FILE = "apps/cli/src/x-canary-operator-options.ts";
const CLAIM_BACKFILL_ENTRY_FILE = "apps/cli/src/x-canary-claim-backfill.ts";
const CLAIM_BACKFILL_HOST_FILE = "apps/cli/src/x-canary-claim-backfill-host.ts";
const CLAIM_BACKFILL_CORE_FILE = "apps/cli/src/x-canary-claim-backfill-core.ts";
const CLAIM_BACKFILL_OPTIONS_FILE = "apps/cli/src/x-canary-claim-backfill-options.ts";
const OPERATOR_HOST_FILE = "apps/cli/src/x-canary-operator-host.ts";
const OPERATOR_HOST_CORE_FILE = "apps/cli/src/x-canary-operator-host-core.ts";
const EXACT_X_ENDPOINT = "https://api.x.com/2/tweets/search/recent";
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

class Stage1VerificationFailure extends Error {
  constructor(violations) {
    super(
      `Stage 1 X read-canary authority isolation failed:\n${violations
        .map((violation, index) => `${index + 1}. ${violation}`)
        .join("\n")}`,
    );
    this.name = "Stage1VerificationFailure";
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
      if (packages.has(manifest.name))
        throw new Error(`duplicate workspace package ${manifest.name}`);
      packages.set(manifest.name, { directory, manifest });
    }
  }
  return packages;
}

const ACTIVE_RUNTIME_EXPORT_CONDITIONS = new Set([
  "node-addons",
  "node",
  "import",
  "module-sync",
  "require",
  // `--conditions=types` can make this otherwise tooling-only branch selectable
  // by the production Node process, so it must agree with every runtime target.
  "types",
  "default",
]);
const REVIEWED_EXPORT_CONDITIONS = new Set(ACTIVE_RUNTIME_EXPORT_CONDITIONS);

function validateRuntimeExportTarget(value, label) {
  if (typeof value === "string") {
    if (value.includes("*") || value.endsWith("/")) {
      throw new Error(`${label} contains an unsupported wildcard or folder target`);
    }
    return;
  }
  if (Array.isArray(value)) {
    throw new Error(`${label} uses an unsupported export fallback array`);
  }
  if (value === null || typeof value !== "object") {
    throw new Error(`${label} has a null or invalid export target`);
  }
  for (const [condition, target] of Object.entries(value)) {
    if (!REVIEWED_EXPORT_CONDITIONS.has(condition)) {
      throw new Error(`${label} uses unreviewed export condition ${condition}`);
    }
    validateRuntimeExportTarget(target, `${label}.${condition}`);
  }
}

function validateWorkspaceExports(exportsValue) {
  if (
    typeof exportsValue === "string" ||
    Array.isArray(exportsValue) ||
    exportsValue === null ||
    typeof exportsValue !== "object"
  ) {
    validateRuntimeExportTarget(exportsValue, "workspace exports");
    return;
  }
  const keys = Object.keys(exportsValue);
  const subpathKeys = keys.filter((key) => key.startsWith("."));
  if (subpathKeys.length > 0 && subpathKeys.length !== keys.length) {
    throw new Error("workspace exports cannot mix subpath and condition keys");
  }
  if (subpathKeys.length === 0) {
    validateRuntimeExportTarget(exportsValue, "workspace exports");
    return;
  }
  for (const [subpath, target] of Object.entries(exportsValue)) {
    if (subpath.includes("*") || subpath.endsWith("/")) {
      throw new Error(`workspace exports contains unsupported subpath pattern ${subpath}`);
    }
    validateRuntimeExportTarget(target, `workspace exports[${subpath}]`);
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
    validateWorkspaceExports(manifest.exports);
    const exportValue = exportValueForSubpath(manifest.exports, subpath);
    if (exportValue === undefined) return undefined;
    const target = conditionTarget(exportValue);
    if (target !== undefined) return target;
    throw new Error("workspace export has no reviewed runtime target");
  }
  if (subpath !== "") return `./src/${subpath}`;
  for (const field of ["main", "module"]) {
    if (typeof manifest[field] === "string") return manifest[field];
  }
  return "./src/index.ts";
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
      if (template.braceDepth > 0) template.braceDepth -= 1;
      else {
        kind = scanner.reScanTemplateToken(false);
        if (kind === ts.SyntaxKind.TemplateTail) templateExpressions.pop();
      }
    }
    if (kind === ts.SyntaxKind.EndOfFile) break;
    if (kind === ts.SyntaxKind.Unknown) {
      throw new Error(`unrecognized token at byte ${scanner.getTokenStart()}`);
    }
    tokens.push(
      Object.freeze({ kind, text: scanner.getTokenText(), value: scanner.getTokenValue() }),
    );
    previousKind = kind;
  }
  return Object.freeze({ path, text, tokens: Object.freeze(tokens) });
}

function analyzeSource(source) {
  const imports = [];
  const forbiddenAuthority = new Set();
  const forbiddenDynamic = new Set();
  const forbiddenCrypto = new Set();
  const forbiddenEnvironment = new Set();
  const forbiddenLoaders = new Set();
  const forbiddenNetworkGlobals = new Set();
  const forbiddenChildApis = new Set();
  const forbiddenLiterals = new Set();
  const globalFetchIndexes = [];
  const bareFetchIndexes = [];
  const literals = new Set();
  const identifiers = new Set();
  const processProperties = [];

  const isLiteral = (token) =>
    token?.kind === ts.SyntaxKind.StringLiteral ||
    token?.kind === ts.SyntaxKind.NoSubstitutionTemplateLiteral;
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

  for (let index = 0; index < source.tokens.length; index += 1) {
    const token = source.tokens[index];
    const identifier = token.kind === ts.SyntaxKind.Identifier ? token.value : undefined;
    if (identifier !== undefined) identifiers.add(identifier);
    if (identifier === "process") {
      const accessor = source.tokens[index + 1];
      const property = source.tokens[index + 2];
      processProperties.push(
        (accessor?.kind === ts.SyntaxKind.DotToken ||
          accessor?.kind === ts.SyntaxKind.QuestionDotToken) &&
          property?.kind === ts.SyntaxKind.Identifier
          ? property.value
          : "<aliased-or-computed>",
      );
    }
    if (identifier !== undefined && FORBIDDEN_AUTHORITY_IDENTIFIERS.has(identifier)) {
      forbiddenAuthority.add(identifier);
    }
    if (identifier !== undefined && FORBIDDEN_DYNAMIC_IDENTIFIERS.has(identifier)) {
      forbiddenDynamic.add(identifier);
    }
    if (identifier !== undefined && FORBIDDEN_CRYPTO_CAPABILITIES.has(identifier)) {
      forbiddenCrypto.add(identifier);
    }
    if (identifier !== undefined && FORBIDDEN_LOADER_IDENTIFIERS.has(identifier)) {
      forbiddenLoaders.add(identifier);
    }
    if (identifier !== undefined && FORBIDDEN_NETWORK_GLOBALS.has(identifier)) {
      forbiddenNetworkGlobals.add(identifier);
    }
    if (identifier !== undefined && FORBIDDEN_CHILD_PROCESS_APIS.has(identifier)) {
      // SQLite's database.exec is unrelated. These APIs are only relevant in an
      // import clause or as unqualified calls; special child imports are checked below.
      const previous = source.tokens[index - 1];
      if (previous?.kind !== ts.SyntaxKind.DotToken) forbiddenChildApis.add(identifier);
    }
    if (isLiteral(token)) {
      literals.add(token.value);
      if (
        token.value === "process" &&
        source.tokens[index - 1]?.kind === ts.SyntaxKind.OpenBracketToken
      ) {
        processProperties.push("<aliased-or-computed>");
      }
      if (FORBIDDEN_PROTOCOL_LITERALS.has(token.value)) forbiddenLiterals.add(token.value);
      if (FORBIDDEN_DYNAMIC_IDENTIFIERS.has(token.value)) forbiddenDynamic.add(token.value);
      if (FORBIDDEN_CRYPTO_CAPABILITIES.has(token.value)) forbiddenCrypto.add(token.value);
      if (FORBIDDEN_LOADER_LITERALS.has(token.value)) forbiddenLoaders.add(token.value);
      if (FORBIDDEN_NETWORK_GLOBALS.has(token.value)) forbiddenNetworkGlobals.add(token.value);
      if (
        token.value === "constructor" &&
        source.tokens[index - 1]?.kind === ts.SyntaxKind.OpenBracketToken
      ) {
        forbiddenDynamic.add("constructor");
      }
    }
    if (
      (token.value ?? token.text) === "constructor" &&
      (source.tokens[index - 1]?.kind === ts.SyntaxKind.DotToken ||
        source.tokens[index - 1]?.kind === ts.SyntaxKind.QuestionDotToken)
    ) {
      forbiddenDynamic.add("constructor");
    }

    if (
      identifier === "globalThis" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier &&
      source.tokens[index + 2]?.value === "fetch"
    ) {
      globalFetchIndexes.push(index);
    }
    if (identifier === "fetch" && source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenParenToken) {
      bareFetchIndexes.push(index);
    }
    if (
      identifier === "globalThis" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenBracketToken
    ) {
      const property = moduleLiteral(source.tokens[index + 2]);
      if (property === "fetch" || FORBIDDEN_NETWORK_GLOBALS.has(property)) {
        forbiddenNetworkGlobals.add(`globalThis[${property}]`);
      }
    }
    if (
      identifier === "Reflect" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      (source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier ||
        source.tokens[index + 2]?.kind === ts.SyntaxKind.GetKeyword) &&
      (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "get" &&
      source.tokens[index + 3]?.kind === ts.SyntaxKind.OpenParenToken &&
      source.tokens[index + 4]?.kind === ts.SyntaxKind.Identifier &&
      source.tokens[index + 4]?.value === "globalThis" &&
      source.tokens[index + 5]?.kind === ts.SyntaxKind.CommaToken &&
      (moduleLiteral(source.tokens[index + 6]) === "fetch" ||
        FORBIDDEN_NETWORK_GLOBALS.has(moduleLiteral(source.tokens[index + 6])))
    ) {
      forbiddenNetworkGlobals.add(
        `Reflect.get(globalThis, ${moduleLiteral(source.tokens[index + 6])})`,
      );
    }
    if (
      identifier === "Reflect" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "get" &&
      source.tokens[index + 3]?.kind === ts.SyntaxKind.OpenParenToken &&
      source.tokens[index + 4]?.kind === ts.SyntaxKind.Identifier &&
      source.tokens[index + 4]?.value === "globalThis" &&
      source.tokens[index + 5]?.kind === ts.SyntaxKind.CommaToken &&
      moduleLiteral(source.tokens[index + 6]) === "process"
    ) {
      processProperties.push("<aliased-or-computed>");
    }
    if (
      identifier === "process" &&
      (source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken ||
        source.tokens[index + 1]?.kind === ts.SyntaxKind.QuestionDotToken) &&
      source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier &&
      ["_linkedBinding", "binding", "dlopen"].includes(source.tokens[index + 2]?.value)
    ) {
      forbiddenLoaders.add(`process.${source.tokens[index + 2].value}`);
    }
    if (
      identifier === "process" &&
      ((source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
        source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier &&
        source.tokens[index + 2]?.value === "env") ||
        (source.tokens[index + 1]?.kind === ts.SyntaxKind.QuestionDotToken &&
          source.tokens[index + 2]?.kind === ts.SyntaxKind.Identifier &&
          source.tokens[index + 2]?.value === "env") ||
        (source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenBracketToken &&
          moduleLiteral(source.tokens[index + 2]) === "env"))
    ) {
      forbiddenEnvironment.add("process.env");
    }
    if (
      identifier === "Reflect" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.DotToken &&
      (source.tokens[index + 2]?.value ?? source.tokens[index + 2]?.text) === "get" &&
      source.tokens[index + 3]?.kind === ts.SyntaxKind.OpenParenToken &&
      source.tokens[index + 4]?.kind === ts.SyntaxKind.Identifier &&
      source.tokens[index + 4]?.value === "process" &&
      source.tokens[index + 5]?.kind === ts.SyntaxKind.CommaToken &&
      moduleLiteral(source.tokens[index + 6]) === "env"
    ) {
      forbiddenEnvironment.add("process.env");
    }

    if (token.kind === ts.SyntaxKind.ImportKeyword) {
      const next = source.tokens[index + 1];
      if (next?.kind === ts.SyntaxKind.DotToken) continue;
      if (next?.kind === ts.SyntaxKind.OpenParenToken) {
        forbiddenDynamic.add("import()");
        const specifier = moduleLiteral(source.tokens[index + 2]);
        const closed = source.tokens[index + 3]?.kind === ts.SyntaxKind.CloseParenToken;
        imports.push(
          specifier !== undefined && closed
            ? { dynamic: false, names: [], specifier }
            : { dynamic: true, names: [], specifier: null },
        );
        continue;
      }
      const end = statementEnd(index + 1);
      const sideEffect = moduleLiteral(next);
      if (sideEffect !== undefined) {
        imports.push({ dynamic: false, names: [], specifier: sideEffect });
        continue;
      }
      let fromIndex = -1;
      let containsRequire = false;
      for (let cursor = index + 1; cursor < end; cursor += 1) {
        if (
          source.tokens[cursor].kind === ts.SyntaxKind.Identifier &&
          source.tokens[cursor].value === "require"
        ) {
          containsRequire = true;
        }
        if (source.tokens[cursor].kind === ts.SyntaxKind.FromKeyword) {
          fromIndex = cursor;
          break;
        }
      }
      if (fromIndex >= 0) {
        const specifier = moduleLiteral(source.tokens[fromIndex + 1]);
        const names = [];
        for (let cursor = index + 1; cursor < fromIndex; cursor += 1) {
          const candidate = source.tokens[cursor];
          if (candidate.kind === ts.SyntaxKind.Identifier) names.push(candidate.value);
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
      let start = index + 1;
      if (source.tokens[start]?.kind === ts.SyntaxKind.TypeKeyword) start += 1;
      if (
        source.tokens[start]?.kind !== ts.SyntaxKind.OpenBraceToken &&
        source.tokens[start]?.kind !== ts.SyntaxKind.AsteriskToken
      ) {
        continue;
      }
      const end = statementEnd(index + 1);
      for (let cursor = start + 1; cursor < end; cursor += 1) {
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

  return Object.freeze({
    bareFetchIndexes,
    forbiddenAuthority: [...forbiddenAuthority].sort(),
    forbiddenChildApis: [...forbiddenChildApis].sort(),
    forbiddenCrypto: [...forbiddenCrypto].sort(),
    forbiddenDynamic: [...forbiddenDynamic].sort(),
    forbiddenEnvironment: [...forbiddenEnvironment].sort(),
    forbiddenLiterals: [...forbiddenLiterals].sort(),
    forbiddenLoaders: [...forbiddenLoaders].sort(),
    forbiddenNetworkGlobals: [...forbiddenNetworkGlobals].sort(),
    globalFetchIndexes,
    imports,
    identifiers,
    literals,
    processProperties,
  });
}

function workspaceSourceRoot(relativeFile) {
  return /^(?:apps|packages)\/[^/]+\//u.exec(relativeFile)?.[0];
}

function allowedLocalFile(relativeFile) {
  return (
    EXACT_ALLOWED_SOURCE_FILES.has(relativeFile) ||
    ALLOWED_SOURCE_PREFIXES.some((prefix) => relativeFile.startsWith(prefix))
  );
}

function classifyLocalFile(relativeFile) {
  if (FORBIDDEN_EXACT_SOURCE_FILES.has(relativeFile)) {
    return `${FORBIDDEN_EXACT_SOURCE_FILES.get(relativeFile)} ${relativeFile}`;
  }
  if (/(?:^|\/)[^/]+\.testing\.(?:[cm]?[jt]sx?)$/u.test(relativeFile)) {
    return `test-only wrapper source ${relativeFile}`;
  }
  if (/\.(?:cjs|cts)$/u.test(relativeFile)) {
    return `CommonJS runtime source ${relativeFile}`;
  }
  if (!allowedLocalFile(relativeFile)) return `unreviewed local source ${relativeFile}`;
  if (FORBIDDEN_LOCAL_PATH.test(relativeFile)) return `forbidden authority source ${relativeFile}`;
  return undefined;
}

function classifyModuleSpecifier(specifier, relativeFile, names) {
  if (FORBIDDEN_NETWORK_MODULES.has(specifier)) {
    return `unapproved network platform module ${specifier}`;
  }
  if (FORBIDDEN_PLATFORM_MODULES.has(specifier)) {
    return `unapproved process/module platform module ${specifier}`;
  }
  if (specifier === "node:crypto") {
    const allowedNames = REVIEWED_CRYPTO_IMPORTS.get(relativeFile);
    const actualNames = [...new Set(names)].sort();
    if (allowedNames === undefined) {
      return `node:crypto is not approved in ${relativeFile}`;
    }
    if (
      actualNames.length !== allowedNames.length ||
      actualNames.some((name, index) => name !== allowedNames[index])
    ) {
      return `node:crypto imports must be exactly ${allowedNames.join(", ")}`;
    }
    return undefined;
  }
  if (specifier === "node:fs" || specifier === "node:fs/promises") {
    const allowedNames = REVIEWED_FS_IMPORTS.get(`${specifier}\0${relativeFile}`);
    const actualNames = [...new Set(names)].sort();
    if (allowedNames === undefined) {
      return `${specifier} is not approved in ${relativeFile}`;
    }
    if (
      actualNames.length !== allowedNames.length ||
      actualNames.some((name, index) => name !== allowedNames[index])
    ) {
      return `${specifier} imports must be exactly ${allowedNames.join(", ")}`;
    }
    return undefined;
  }
  if (specifier === "node:child_process" && relativeFile === ONE_SHOT_CLAIM_FILE) {
    const actualNames = [...new Set(names)].sort();
    return actualNames.length === 1 && actualNames[0] === "execFile"
      ? undefined
      : "node:child_process imports must be exactly execFile";
  }
  const special = SPECIAL_PLATFORM_IMPORTS.get(specifier);
  if (special !== undefined) {
    const actualNames = [...new Set(names)].sort();
    if (relativeFile !== special.file) {
      return `${specifier} is allowed only in ${special.file}`;
    }
    if (
      actualNames.length !== special.names.length ||
      actualNames.some((name, index) => name !== special.names[index])
    ) {
      return `${specifier} imports must be exactly ${special.names.join(", ")}`;
    }
    return undefined;
  }
  if (specifier === "@rsi/domain" || specifier.startsWith("@rsi/domain/")) {
    if (specifier === "@rsi/domain/proposals") return undefined;
    return `executable domain import ${specifier}`;
  }
  if (specifier === "@rsi/adapters" || specifier.startsWith("@rsi/adapters/")) {
    return `execution-adapter import ${specifier}`;
  }
  if (specifier === "@rsi/policy" || specifier.startsWith("@rsi/policy/")) {
    return `policy authority import ${specifier}`;
  }
  if (
    specifier === "@rsi/x-collector/testing" ||
    specifier.startsWith("@rsi/x-collector/testing/")
  ) {
    return `test-only transport import ${specifier}`;
  }
  if (
    specifier === "@rsi/credential-host/testing" ||
    specifier.startsWith("@rsi/credential-host/testing/")
  ) {
    return `test-only credential injection import ${specifier}`;
  }
  if (FORBIDDEN_EXTERNAL_PACKAGE.test(specifier)) return `financial/network package ${specifier}`;
  return undefined;
}

function inspectGraph(root, packages) {
  const violations = [];
  const visited = new Set();
  const reachedPackages = new Set();
  const analyses = new Map();
  const entry = resolveSourceFile(join(root, ENTRY));
  if (entry === undefined) {
    return {
      analyses,
      files: visited,
      reachedPackages,
      violations: [`production entrypoint ${ENTRY} is missing`],
    };
  }
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    const relativeFile = canonicalRelative(root, file);
    const localViolation = classifyLocalFile(relativeFile);
    if (localViolation !== undefined) violations.push(localViolation);
    let analysis;
    try {
      analysis = analyzeSource(parseSource(file));
      analyses.set(file, analysis);
    } catch (error) {
      violations.push(`cannot parse ${relativeFile}: ${error.message}`);
      continue;
    }
    if (analysis.forbiddenAuthority.length > 0) {
      violations.push(
        `${relativeFile} references financial authority: ${analysis.forbiddenAuthority.join(", ")}`,
      );
    }
    if (analysis.forbiddenDynamic.length > 0) {
      violations.push(
        `${relativeFile} references dynamic code: ${analysis.forbiddenDynamic.join(", ")}`,
      );
    }
    if (analysis.forbiddenEnvironment.length > 0 && relativeFile !== PRODUCTION_RUNTIME_FILE) {
      violations.push(
        `${relativeFile} references an unapproved ambient credential source: ${analysis.forbiddenEnvironment.join(", ")}`,
      );
    }
    if (analysis.processProperties.length > 0) {
      const allowed = REVIEWED_PROCESS_PROPERTIES.get(relativeFile);
      const unreviewed = analysis.processProperties.filter(
        (property) => allowed === undefined || !allowed.has(property),
      );
      if (unreviewed.length > 0) {
        violations.push(
          `${relativeFile} references an unapproved process capability: ${[...new Set(unreviewed)].join(", ")}`,
        );
      }
    }
    if (analysis.forbiddenCrypto.length > 0) {
      violations.push(
        `${relativeFile} references an unapproved asymmetric/signing crypto capability: ${analysis.forbiddenCrypto.join(", ")}`,
      );
    }
    if (analysis.forbiddenLoaders.length > 0) {
      violations.push(
        `${relativeFile} references an alternate module loader: ${analysis.forbiddenLoaders.join(", ")}`,
      );
    }
    if (analysis.forbiddenNetworkGlobals.length > 0) {
      violations.push(
        `${relativeFile} references an unapproved network global: ${analysis.forbiddenNetworkGlobals.join(", ")}`,
      );
    }
    if (analysis.forbiddenChildApis.length > 0) {
      violations.push(
        `${relativeFile} references an unapproved child-process API: ${analysis.forbiddenChildApis.join(", ")}`,
      );
    }
    if (analysis.forbiddenLiterals.length > 0) {
      violations.push(`${relativeFile} declares a forbidden transaction capability literal`);
    }
    if (analysis.bareFetchIndexes.length > 0) {
      violations.push(`${relativeFile} contains an unaudited bare fetch call`);
    }
    if (relativeFile !== KEYCHAIN_FILE) {
      const testOnlyReferences = [...CREDENTIAL_TEST_ONLY_IDENTIFIERS].filter(
        (name) => analysis.identifiers.has(name) || analysis.literals.has(name),
      );
      if (testOnlyReferences.length > 0) {
        violations.push(
          `${relativeFile} references test-only credential injection: ${testOnlyReferences.join(", ")}`,
        );
      }
    }
    if (relativeFile !== COLLECTOR_FILE) {
      const testOnlyReferences = [...COLLECTOR_TEST_ONLY_IDENTIFIERS].filter(
        (name) => analysis.identifiers.has(name) || analysis.literals.has(name),
      );
      if (testOnlyReferences.length > 0) {
        violations.push(
          `${relativeFile} references test-only collector injection: ${testOnlyReferences.join(", ")}`,
        );
      }
    }

    for (const dependency of analysis.imports) {
      if (dependency.dynamic) {
        violations.push(`${relativeFile} contains a non-literal import/require`);
        continue;
      }
      const specifier = dependency.specifier;
      const classification = classifyModuleSpecifier(specifier, relativeFile, dependency.names);
      if (classification !== undefined) {
        violations.push(`${relativeFile} imports ${classification}`);
        continue;
      }
      if (SPECIAL_PLATFORM_IMPORTS.has(specifier)) continue;

      let resolvedDependency;
      if (specifier.startsWith(".") || isAbsolute(specifier)) {
        const candidate = isAbsolute(specifier) ? specifier : resolve(dirname(file), specifier);
        resolvedDependency = resolveSourceFile(candidate);
        if (resolvedDependency === undefined) {
          violations.push(`${relativeFile} has unresolved local import ${specifier}`);
          continue;
        }
      } else {
        const workspace = packageForSpecifier(specifier, packages);
        if (workspace !== undefined) {
          if (!REVIEWED_WORKSPACE_IMPORTS.has(specifier)) {
            violations.push(`${relativeFile} reaches unreviewed workspace import ${specifier}`);
            continue;
          }
          reachedPackages.add(workspace.name);
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
            violations.push(`${relativeFile} cannot resolve workspace export ${specifier}`);
            continue;
          }
          resolvedDependency = resolveSourceFile(
            resolve(workspace.workspacePackage.directory, target),
          );
          if (resolvedDependency === undefined) {
            violations.push(`${relativeFile} cannot resolve workspace import ${specifier}`);
            continue;
          }
        } else if (SAFE_PLATFORM_MODULES.has(specifier) || SAFE_EXTERNAL_MODULES.has(specifier)) {
          continue;
        } else if (NODE_BUILTINS.has(specifier)) {
          violations.push(`${relativeFile} imports unreviewed platform module ${specifier}`);
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
      const importerRoot = workspaceSourceRoot(relativeFile);
      const dependencyRoot = workspaceSourceRoot(resolvedRelative);
      if (
        (specifier.startsWith(".") || isAbsolute(specifier)) &&
        importerRoot !== undefined &&
        dependencyRoot !== undefined &&
        importerRoot !== dependencyRoot
      ) {
        violations.push(
          `${relativeFile} uses a cross-package relative import to ${resolvedRelative}`,
        );
      }
      if (resolvedRelative === OPERATOR_HOST_CORE_FILE && relativeFile !== OPERATOR_HOST_FILE) {
        violations.push(
          `${relativeFile} imports the credential-injecting host core outside ${OPERATOR_HOST_FILE}`,
        );
      }
      if (resolvedRelative === KEYCHAIN_FILE && relativeFile !== KEYCHAIN_INDEX_FILE) {
        violations.push(
          `${relativeFile} imports the credential implementation outside ${KEYCHAIN_INDEX_FILE}`,
        );
      }
      if (resolvedRelative === COLLECTOR_FILE && relativeFile !== COLLECTOR_INDEX_FILE) {
        violations.push(
          `${relativeFile} imports the collector implementation outside ${COLLECTOR_INDEX_FILE}`,
        );
      }
      const resolvedClassification = classifyLocalFile(resolvedRelative);
      if (resolvedClassification !== undefined) {
        violations.push(`${relativeFile} reaches ${resolvedClassification}`);
        continue;
      }
      pending.push(resolvedDependency);
    }
  }
  return { analyses, files: visited, reachedPackages, violations };
}

function requireSource(root, relativeFile, visited, violations) {
  const path = resolveSourceFile(join(root, relativeFile));
  if (path === undefined) {
    violations.push(`required reviewed source ${relativeFile} is missing`);
    return undefined;
  }
  if (!visited.has(path))
    violations.push(`production graph does not reach reviewed source ${relativeFile}`);
  return readFileSync(path, "utf8");
}

function countMatches(text, expression) {
  return [...text.matchAll(expression)].length;
}

function staticExportNames(source) {
  const names = new Set();
  for (const match of source.matchAll(
    /\bexport\s+(?:declare\s+)?(?:async\s+)?(?:class|const|enum|function|interface|let|type|var)\s+([A-Za-z_$][\w$]*)/gu,
  )) {
    names.add(match[1]);
  }
  for (const match of source.matchAll(/\bexport\s+(?:type\s+)?\{([^}]*)\}/gu)) {
    for (const entry of match[1].split(",")) {
      const normalized = entry.trim().replace(/^type\s+/u, "");
      if (normalized.length === 0) continue;
      const parts = normalized.split(/\s+as\s+/u);
      const exported = (parts[1] ?? parts[0]).trim();
      if (/^[A-Za-z_$][\w$]*$/u.test(exported)) names.add(exported);
      else names.add("<unparsed>");
    }
  }
  if (/\bexport\s*\*/u.test(source)) names.add("*");
  if (/\bexport\s+default\b/u.test(source)) names.add("default");
  return [...names].sort();
}

function hasExactNames(actual, expected) {
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((name, index) => name === sortedExpected[index])
  );
}

function namedFunctionSource(source, name) {
  const start = source.search(new RegExp(`\\bfunction\\s+${name}\\s*\\(`, "u"));
  if (start < 0) return "";
  const next = source.indexOf("\nfunction ", start + name.length + 1);
  return source.slice(start, next < 0 ? source.length : next);
}

function namedClassMethodSource(source, name) {
  const start = source.search(
    new RegExp(`\\n  (?:static\\s+)?(?:async\\s+)?#?${name}\\s*\\(`, "u"),
  );
  if (start < 0) return "";
  const end = source.indexOf("\n  }\n", start);
  return source.slice(start, end < 0 ? source.length : end + "\n  }".length);
}

function verifyFetchBoundary(root, graph, violations) {
  const fetchSites = [];
  for (const [path, analysis] of graph.analyses) {
    for (const _index of analysis.globalFetchIndexes)
      fetchSites.push(canonicalRelative(root, path));
  }
  if (fetchSites.length !== 1 || fetchSites[0] !== COLLECTOR_FILE) {
    violations.push(
      `expected exactly one audited global fetch site in ${COLLECTOR_FILE}; found ${fetchSites.length}${
        fetchSites.length === 0 ? "" : ` in ${fetchSites.join(", ")}`
      }`,
    );
  }
}

function verifyXContract(root, graph, violations) {
  const index = requireSource(root, COLLECTOR_INDEX_FILE, graph.files, violations);
  const constants = requireSource(root, CONSTANTS_FILE, graph.files, violations);
  const query = requireSource(root, QUERY_FILE, graph.files, violations);
  const collector = requireSource(root, COLLECTOR_FILE, graph.files, violations);
  const canaryConstants = requireSource(root, CANARY_CONSTANTS_FILE, graph.files, violations);
  const runtimeAuthorization = requireSource(
    root,
    RUNTIME_AUTHORIZATION_FILE,
    graph.files,
    violations,
  );
  const runtimeController = requireSource(root, RUNTIME_CONTROLLER_FILE, graph.files, violations);
  if (constants !== undefined) {
    const requirements = [
      [/X_API_ORIGIN\s*=\s*"https:\/\/api\.x\.com"\s+as\s+const/u, "fixed X API origin"],
      [
        /X_RECENT_SEARCH_PATH\s*=\s*"\/2\/tweets\/search\/recent"\s+as\s+const/u,
        "fixed recent-search path",
      ],
      [/X_RECENT_SEARCH_METHOD\s*=\s*"GET"\s+as\s+const/u, "GET-only method"],
      [/X_RECENT_SEARCH_SORT_ORDER\s*=\s*"recency"\s+as\s+const/u, "recency sort order"],
      [/X_RECENT_SEARCH_MIN_RESULTS\s*=\s*10\s+as\s+const/u, "minimum results of 10"],
      [/X_RECENT_SEARCH_MAX_RESULTS\s*=\s*10\s+as\s+const/u, "maximum results of 10"],
      [/X_RECENT_SEARCH_DEFAULT_RESULTS\s*=\s*10\s+as\s+const/u, "default results of 10"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(constants)) violations.push(`${CONSTANTS_FILE} does not enforce ${label}`);
    }
    const httpsOrigins = [...constants.matchAll(/https:\/\/[^"'`\s]+/gu)].map((match) => match[0]);
    if (httpsOrigins.length !== 1 || httpsOrigins[0] !== "https://api.x.com") {
      violations.push(`${CONSTANTS_FILE} declares an unreviewed HTTPS origin`);
    }
  }
  if (index !== undefined) {
    const productionExports = [
      "*",
      "XRecentSearchCollectOptions",
      "XRecentSearchCollector",
      "XRecentSearchCollectorOptions",
      "XRecentSearchLiveOptions",
      "XRecentSearchReplayOptions",
      "createXRecentSearchCollector",
      "isXRecentSearchCollector",
      "xRecentSearchRuntimeActionId",
    ];
    const allowedReexports = new Set([
      "./cassette.js",
      "./collector.js",
      "./constants.js",
      "./errors.js",
      "./hash.js",
      "./quarantine.js",
      "./query.js",
      "./rate-limit.js",
      "./schema.js",
      "./time.js",
    ]);
    const indexPath = resolveSourceFile(join(root, COLLECTOR_INDEX_FILE));
    const analysis = indexPath === undefined ? undefined : graph.analyses.get(indexPath);
    if (!hasExactNames(staticExportNames(index), productionExports)) {
      violations.push(`${COLLECTOR_INDEX_FILE} may export only the reviewed production surface`);
    }
    if (
      /\bimport\b/u.test(index) ||
      /(?:createXRecentSearchCollectorForTesting|XRecentSearchFetch|XRecentSearchLiveTestingOptions|\.\/testing)/u.test(
        index,
      ) ||
      analysis === undefined ||
      analysis.imports.some(
        (dependency) =>
          dependency.dynamic ||
          dependency.specifier === null ||
          !allowedReexports.has(dependency.specifier),
      )
    ) {
      violations.push(
        `${COLLECTOR_INDEX_FILE} must be the closed static re-export of the production collector surface`,
      );
    }
  }
  if (query !== undefined) {
    const setCalls = [...query.matchAll(/\.searchParams\.set\(\s*"([^"]+)"/gu)].map(
      (match) => match[1],
    );
    if (
      setCalls.length !== 3 ||
      setCalls[0] !== "query" ||
      setCalls[1] !== "max_results" ||
      setCalls[2] !== "sort_order" ||
      countMatches(query, /\.searchParams\.(?:append|delete)\s*\(/gu) !== 0
    ) {
      violations.push(
        `${QUERY_FILE} must set exactly query, max_results, and sort_order once with no other parameters`,
      );
    }
    if (!/const\s+QUERY_KEYS\s*=\s*new\s+Set\(\["query"\]\)/u.test(query)) {
      violations.push(`${QUERY_FILE} must accept only the code-owned query field`);
    }
    const fixedBuilder = [
      /new\s+URL\(\s*X_RECENT_SEARCH_PATH\s*,\s*X_API_ORIGIN\s*\)/u,
      /\.searchParams\.set\(\s*"query"\s*,\s*query\.query\s*\)/u,
      /\.searchParams\.set\(\s*"max_results"\s*,\s*String\(query\.maxResults\)\s*\)/u,
      /\.searchParams\.set\(\s*"sort_order"\s*,\s*X_RECENT_SEARCH_SORT_ORDER\s*\)/u,
      /`\$\{X_RECENT_SEARCH_METHOD\}\\n\$\{X_RECENT_SEARCH_ENDPOINT\}\\n\$\{canonicalizeQuery\(url\.searchParams\)\}`/u,
      /method:\s*X_RECENT_SEARCH_METHOD/u,
      /endpoint:\s*X_RECENT_SEARCH_ENDPOINT/u,
      /maxResults:\s*X_RECENT_SEARCH_DEFAULT_RESULTS/u,
    ];
    if (fixedBuilder.some((pattern) => !pattern.test(query))) {
      violations.push(
        `${QUERY_FILE} must derive the request only from reviewed X contract constants`,
      );
    }
    const forbiddenParameters = [
      "next_token",
      "pagination_token",
      "since_id",
      "until_id",
      "start_time",
      "end_time",
      "tweet.fields",
      "expansions",
      "media.fields",
      "place.fields",
      "poll.fields",
      "user.fields",
    ];
    for (const parameter of forbiddenParameters) {
      if (query.includes(`"${parameter}"`) || query.includes(`'${parameter}'`)) {
        violations.push(`${QUERY_FILE} includes forbidden pagination/field parameter ${parameter}`);
      }
    }
  }
  if (collector !== undefined) {
    const requirements = [
      [/from\s+"@rsi\/operations"/u, "genuine operations authorization import"],
      [/from\s+"@rsi\/runtime"/u, "genuine runtime authorization import"],
      [
        /isNetworkAttemptAuthorization\s*\(\s*attemptAuthorization\s*\)/u,
        "operations authorization authenticity check",
      ],
      [
        /isRuntimeBoundaryAuthorization\s*\(\s*runtimeAuthorization\s*\)/u,
        "runtime authorization authenticity check",
      ],
      [
        /runtimeCollectionAuthorization\.consumeAndDispatch\s*\(\s*\(receipt\)\s*=>\s*\{/u,
        "write-locked runtime dispatch consumption",
      ],
      [/attemptAuthorization\.consume\s*\(\s*\)/u, "operations authorization consumption"],
      [/new\s+Request\s*\(\s*prepared\.url/u, "prepared fixed request URL"],
      [/method:\s*"GET"/u, "GET request method"],
      [/body:\s*null/u, "bodyless GET request"],
      [/redirect:\s*"error"/u, "redirect refusal"],
      [/credentials:\s*"omit"/u, "ambient credential refusal"],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(collector)) violations.push(`${COLLECTOR_FILE} lacks ${label}`);
    }
    const runtimeDispatch = collector.indexOf(
      "runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {",
    );
    const attemptConsume = collector.indexOf("attemptAuthorization.consume()", runtimeDispatch);
    const networkCall = collector.indexOf(
      "responsePromise = executeNetworkRequest(",
      attemptConsume,
    );
    if (
      runtimeDispatch < 0 ||
      attemptConsume < 0 ||
      networkCall < 0 ||
      runtimeDispatch >= attemptConsume ||
      attemptConsume >= networkCall
    ) {
      violations.push(
        `${COLLECTOR_FILE} must consume operations authority and invoke transport inside consumeAndDispatch`,
      );
    }
    if (
      !/runtimeCollectionAuthorization\.consumeAndDispatch\s*\(\s*\(receipt\)\s*=>\s*\{[\s\S]{0,3000}?assertRuntimeReceipt\s*\(\s*receipt[\s\S]{0,3000}?attemptAuthorization\.consume\s*\(\s*\)[\s\S]{0,3000}?responsePromise\s*=\s*executeNetworkRequest\s*\(/u.test(
        collector,
      )
    ) {
      violations.push(
        `${COLLECTOR_FILE} does not keep receipt validation, attempt consumption, and transport invocation in the protected callback`,
      );
    }
    const directPostDispatchDrain =
      /catch\s*\(\s*error\s*\)\s*\{\s*if\s*\(\s*responsePromise\s*!==\s*undefined\s*\)\s*\{[\s\S]{0,2500}?await\s+responsePromise\b[\s\S]{0,2500}?\}[\s\S]{0,1000}?throw\b/u.test(
        collector,
      );
    const deferredPostDispatchDrain =
      /catch\s*\(\s*error\s*\)\s*\{\s*if\s*\(\s*responsePromise\s*===\s*undefined\s*\)\s*\{[\s\S]{0,2500}?\}[\s\S]{0,1000}?runtimeDispatchFailure\s*=\s*error\s*;?\s*\}[\s\S]{0,1500}?if\s*\(\s*runtimeDispatchFailure\s*!==\s*undefined\s*\)\s*\{[\s\S]{0,1500}?await\s+responsePromise\b[\s\S]{0,1000}?\.destroy\s*\(\s*\)[\s\S]{0,2000}?throw\b/u.test(
        collector,
      );
    if (!directPostDispatchDrain && !deferredPostDispatchDrain) {
      violations.push(
        `${COLLECTOR_FILE} must await the launched response before reporting a post-dispatch runtime failure`,
      );
    }
    if (/runtimeCollectionAuthorization\.consume\s*\(/u.test(collector)) {
      violations.push(
        `${COLLECTOR_FILE} uses the unprotected runtime consume path for a network boundary`,
      );
    }
    if (countMatches(collector, /globalThis\.fetch\b/gu) !== 1) {
      violations.push(`${COLLECTOR_FILE} must contain exactly one globalThis.fetch site`);
    }
    if (
      countMatches(collector, /runtimeCollectionAuthorization\.consumeAndDispatch\s*\(/gu) !== 1 ||
      countMatches(collector, /attemptAuthorization\.consume\s*\(\s*\)/gu) !== 1 ||
      countMatches(collector, /fetchImplementation\s*\(\s*request\s*\)/gu) !== 1
    ) {
      violations.push(
        `${COLLECTOR_FILE} must have exactly one protected runtime dispatch, attempt consume, and transport invocation`,
      );
    }
  }
  if (canaryConstants !== undefined) {
    const requirements = [
      [/X_READ_CANARY_MAXIMUM_REQUESTS\s*=\s*1\s+as\s+const/u, "exactly one request"],
      [/X_READ_CANARY_MAXIMUM_RESULTS\s*=\s*10\s+as\s+const/u, "at most ten results"],
      [
        /X_READ_CANARY_QUERY\s*=\s*\n?\s*'\(NFT OR OpenSea OR "Robinhood Chain" OR "Base chain"\) lang:en -is:retweet'\s+as\s+const/u,
        "the reviewed code-owned query",
      ],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(canaryConstants)) {
        violations.push(`${CANARY_CONSTANTS_FILE} does not enforce ${label}`);
      }
    }
  }
  if (runtimeAuthorization !== undefined) {
    const networkBranch = runtimeAuthorization.indexOf(
      'if (parts.boundary === "research_collection") {',
    );
    const nonNetworkBranch = runtimeAuthorization.indexOf("} else {", networkBranch);
    const branchEnd = runtimeAuthorization.indexOf("\n  }", nonNetworkBranch + 1);
    const dispatchProperty = runtimeAuthorization.indexOf(
      "properties.consumeAndDispatch",
      networkBranch,
    );
    const completionProperty = runtimeAuthorization.indexOf(
      "properties.guardCompletion",
      networkBranch,
    );
    const consumeProperty = runtimeAuthorization.indexOf("properties.consume", nonNetworkBranch);
    const completionSet =
      /const\s+([A-Z0-9_]*COMPLET[A-Z0-9_]*)\s*=\s*new\s+WeakSet<object>\s*\(\s*\)/u.exec(
        runtimeAuthorization,
      );
    const completionSetName = completionSet?.[1];
    const guardStart = runtimeAuthorization.indexOf("const guardCompletion");
    const guardSource =
      guardStart >= 0 && networkBranch > guardStart
        ? runtimeAuthorization.slice(guardStart, networkBranch)
        : "";
    const completionSetIsTerminal =
      completionSetName !== undefined &&
      guardSource.includes(`${completionSetName}.has(authorization)`) &&
      guardSource.includes(`${completionSetName}.add(authorization)`);
    const completionValidationPatterns = [
      /AUTHENTIC_AUTHORIZATIONS\.has\s*\(\s*authorization\s*\)/u,
      /arguments_\.length\s*!==\s*1/u,
      /typeof\s+callback\s*!==\s*"function"/u,
      /utilTypes\.isProxy\s*\(\s*callback\s*\)/u,
      /utilTypes\.isAsyncFunction\s*\(\s*callback\s*\)/u,
      /utilTypes\.isGeneratorFunction\s*\(\s*callback\s*\)/u,
      /Object\.prototype\.toString\.call\s*\(\s*callback\s*\)\s*!==\s*"\[object Function\]"/u,
      /guardBoundaryCompletion\s*\(\s*callback/u,
    ];
    const inlineCompletionValidation = completionValidationPatterns.every((pattern) =>
      pattern.test(guardSource),
    );
    const helperCompletionValidation =
      /function\s+isSynchronousCallback\s*\([\s\S]{0,1000}?typeof\s+value\s*===\s*"function"[\s\S]{0,1000}?!utilTypes\.isProxy\s*\(\s*value\s*\)[\s\S]{0,1000}?!utilTypes\.isAsyncFunction\s*\(\s*value\s*\)[\s\S]{0,1000}?!utilTypes\.isGeneratorFunction\s*\(\s*value\s*\)[\s\S]{0,1000}?Object\.prototype\.toString\.call\s*\(\s*value\s*\)\s*===\s*"\[object Function\]"/u.test(
        runtimeAuthorization,
      ) &&
      /arguments_\.length\s*!==\s*1\s*\|\|\s*!isSynchronousCallback\s*\(\s*completion\s*\)/u.test(
        guardSource,
      ) &&
      /guardBoundaryCompletion\s*\(\s*completion/u.test(guardSource);
    const completionValidation = inlineCompletionValidation || helperCompletionValidation;
    if (
      networkBranch < 0 ||
      nonNetworkBranch < 0 ||
      branchEnd < 0 ||
      dispatchProperty < networkBranch ||
      dispatchProperty >= nonNetworkBranch ||
      completionProperty < networkBranch ||
      completionProperty >= nonNetworkBranch ||
      consumeProperty < nonNetworkBranch ||
      consumeProperty >= branchEnd ||
      countMatches(runtimeAuthorization, /properties\.guardCompletion\s*=/gu) !== 1 ||
      !/CONSUMED_AUTHORIZATIONS\.add\s*\(\s*authorization\s*\)/u.test(runtimeAuthorization)
    ) {
      violations.push(
        `${RUNTIME_AUTHORIZATION_FILE} must expose dispatch and completion guards only for network collection authority`,
      );
    }
    if (!completionSetIsTerminal || !completionValidation) {
      violations.push(
        `${RUNTIME_AUTHORIZATION_FILE} must make completion guarding authentic, terminal, synchronous, and proxy-resistant`,
      );
    }
  }
  if (
    runtimeController !== undefined &&
    !/#consumeBoundaryAuthorizationAndDispatch\s*\([\s\S]{0,1000}?this\.#store\.withExclusiveTransaction\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,3000}?appendBoundaryCheck\s*\([\s\S]{0,1000}?checked\.decision\s*===\s*"allowed"\s*\)\s*dispatch\s*\(\s*checked\s*\)/u.test(
      runtimeController,
    )
  ) {
    violations.push(
      `${RUNTIME_CONTROLLER_FILE} must hold the SQLite write lock from revalidation through synchronous dispatch`,
    );
  }
  if (runtimeController !== undefined) {
    const completionGuardStart = runtimeController.indexOf("\n  #guardBoundaryCompletion(");
    const completionTransactionStart = runtimeController.indexOf(
      "this.#store.withExclusiveTransaction(() => {",
      completionGuardStart,
    );
    const allowedCallbackMatch =
      /if\s*\(\s*(facts|completion)\.decision\s*===\s*"allowed"\s*\)\s*(?:completion|callback)\s*\(\s*\1\s*\)/u.exec(
        runtimeController.slice(completionTransactionStart),
      );
    const completionCallback =
      allowedCallbackMatch === null ? -1 : completionTransactionStart + allowedCallbackMatch.index;
    const completionTransactionEnd = runtimeController.indexOf(
      "\n    });",
      completionTransactionStart,
    );
    const durableGuardCall = [
      runtimeController.indexOf(
        "assertDurableAllowedBoundary(this.#store, requested)",
        completionTransactionStart,
      ),
      runtimeController.indexOf("this.#store.getByIdempotencyKey(", completionTransactionStart),
    ].find((index) => index >= completionTransactionStart && index < completionTransactionEnd);
    const durableLookup =
      /(?:this\.#store|store)\.getByIdempotencyKey\s*\(\s*`runtime-boundary-v1:\$\{requested\.authorizationId\}`\s*,?\s*\)/u.test(
        runtimeController,
      );
    const durableIdentity = [
      /(?:existing|event)\.aggregateId\s*!==\s*RUNTIME_AGGREGATE_ID/u,
      /(?:existing|event)\.type\s*!==\s*RUNTIME_BOUNDARY_EVENT_TYPE/u,
      /(?:existing|event)\.idempotencyKey\s*!==\s*`runtime-boundary-v1:\$\{requested\.authorizationId\}`/u,
      /RuntimeBoundaryEventPayloadSchema/u,
      /payload\.actionId\s*!==\s*requested\.actionId/u,
      /payload\.authorizationId\s*!==\s*requested\.authorizationId/u,
      /payload\.boundary\s*!==\s*(?:requested\.boundary|"research_collection")/u,
      /payload\.checkedMode\s*!==\s*requested\.requestedMode/u,
      /payload\.checkedProcessInstanceId\s*!==\s*requested\.requestedProcessInstanceId/u,
      /payload\.checkedRevision\s*!==\s*requested\.requestedRevision/u,
      /payload\.decision\s*!==\s*"allowed"/u,
      /payload\.expiresAt\s*!==\s*requested\.expiresAt/u,
      /payload\.reason\s*!==\s*"ALLOWED"/u,
      /payload\.requestedAt\s*!==\s*requested\.requestedAt/u,
      /payload\.requestedMode\s*!==\s*requested\.requestedMode/u,
      /payload\.requestedProcessInstanceId\s*!==\s*requested\.requestedProcessInstanceId/u,
      /payload\.requestedRevision\s*!==\s*requested\.requestedRevision/u,
    ];
    const currentState = [
      /(?:(?:replay\.state|state)\.mode\s*===\s*requested\.requestedMode|requested\.requestedMode\s*!==\s*state\.mode)/u,
      /(?:(?:replay\.state|state)\.processInstanceId\s*===\s*requested\.requestedProcessInstanceId|requested\.requestedProcessInstanceId\s*!==\s*state\.processInstanceId)/u,
      /(?:(?:replay\.state|state)\.revision\s*===\s*requested\.requestedRevision|requested\.requestedRevision\s*!==\s*state\.revision)/u,
      /modeAllowsBoundary\s*\(\s*(?:replay\.state|state)\.mode\s*,\s*requested\.boundary\s*\)/u,
      /requested\.boundary\s*!==\s*"research_collection"|payload\.boundary\s*!==\s*"research_collection"/u,
    ];
    if (!durableLookup || durableIdentity.some((pattern) => !pattern.test(runtimeController))) {
      violations.push(
        `${RUNTIME_CONTROLLER_FILE} must bind completion to the exact durable allowed collection authorization`,
      );
    }
    if (
      currentState.some((pattern) => !pattern.test(runtimeController)) ||
      allowedCallbackMatch === null ||
      completionGuardStart < 0 ||
      completionTransactionStart < completionGuardStart ||
      durableGuardCall === undefined ||
      completionCallback < completionTransactionStart ||
      completionTransactionEnd < completionCallback
    ) {
      violations.push(
        `${RUNTIME_CONTROLLER_FILE} must hold the SQLite write lock through an allowed-current-state completion callback`,
      );
    }
  }
}

function verifyKeychainBoundary(root, graph, violations) {
  const source = requireSource(root, KEYCHAIN_FILE, graph.files, violations);
  const index = requireSource(root, KEYCHAIN_INDEX_FILE, graph.files, violations);
  if (index !== undefined) {
    const productionExports = [
      "CredentialHostError",
      "DarwinXReadCanaryKeychain",
      "XReadCanaryCredentialStatus",
      "XReadCanarySecretMaterial",
      "XReadCanaryStorageSecretMaterial",
      "isDarwinXReadCanaryKeychain",
    ];
    if (!hasExactNames(staticExportNames(index), productionExports)) {
      violations.push(`${KEYCHAIN_INDEX_FILE} may export only the reviewed production surface`);
    }
    if (
      /\bimport\b/u.test(index) ||
      /\bexport\s*\*/u.test(index) ||
      countMatches(index, /from\s+"\.\/x-read-canary-keychain\.js"/gu) !== 1 ||
      [...CREDENTIAL_TEST_ONLY_IDENTIFIERS].some((name) => index.includes(name))
    ) {
      violations.push(
        `${KEYCHAIN_INDEX_FILE} must be the closed static re-export of the production Keychain surface`,
      );
    }
  }
  if (source === undefined) return;
  const requirements = [
    [/import\s*\{\s*execFile\s*\}\s*from\s*"node:child_process"/u, "exact execFile import"],
    [
      /const\s+SECURITY\s*=\s*"\/usr\/bin\/security"\s+as\s+const/u,
      "fixed /usr/bin/security executable",
    ],
    [/execFile\s*\(\s*request\.file/u, "fixed request executable dispatch"],
    [/"find-generic-password"/u, "read-only generic-password command"],
    [/file:\s*SECURITY/u, "fixed security command binding"],
    [
      /"find-generic-password"\s*,\s*"-a"\s*,\s*KEYCHAIN_ACCOUNT\s*,\s*"-s"\s*,\s*service/u,
      "fixed generic-password argument shape",
    ],
    [/shell:\s*false/u, "shell disabled"],
  ];
  for (const [pattern, label] of requirements) {
    if (!pattern.test(source)) violations.push(`${KEYCHAIN_FILE} lacks ${label}`);
  }
  if (countMatches(source, /\bexecFile\s*\(/gu) !== 1) {
    violations.push(`${KEYCHAIN_FILE} must contain exactly one execFile call`);
  }
  const absoluteExecutables = [
    ...source.matchAll(/["'](\/(?:usr|bin|sbin|opt)\/[^"']+)["']/gu),
  ].map((match) => match[1]);
  if (
    absoluteExecutables.some(
      (path) => path !== "/usr/bin/security" && path !== "/usr/bin:/bin:/usr/sbin:/sbin",
    )
  ) {
    violations.push(`${KEYCHAIN_FILE} contains an unreviewed executable path`);
  }
  for (const command of [
    "add-generic-password",
    "delete-generic-password",
    "set-keychain-settings",
  ]) {
    if (source.includes(`"${command}"`) || source.includes(`'${command}'`)) {
      violations.push(`${KEYCHAIN_FILE} contains mutating Keychain command ${command}`);
    }
  }
}

function verifyOneShotClaimBoundary(root, graph, violations) {
  const entry = requireSource(root, ONE_SHOT_CLAIM_ENTRY_FILE, graph.files, violations);
  const source = requireSource(root, ONE_SHOT_CLAIM_FILE, graph.files, violations);
  if (entry !== undefined) {
    const productionExports = [
      "DarwinOneShotClaimHost",
      "OneShotClaimHostError",
      "OneShotClaimStatus",
      "createDarwinBaseRpcOneShotClaimHost",
      "createDarwinOpenSeaOneShotClaimHost",
      "createDarwinXOneShotClaimHost",
      "isDarwinOneShotClaimHost",
    ];
    if (
      !hasExactNames(staticExportNames(entry), productionExports) ||
      /ForTesting|TestingOptions|CommandExecutor|CommandRequest|CommandResult/u.test(entry) ||
      countMatches(entry, /from\s+"\.\/one-shot-claim-keychain\.js"/gu) !== 1
    ) {
      violations.push(
        `${ONE_SHOT_CLAIM_ENTRY_FILE} must keep claim-host injection behind its testing subpath`,
      );
    }
  }
  if (source === undefined) return;
  const requirements = [
    [/import\s*\{\s*execFile\s*\}\s*from\s*"node:child_process"/u, "exact execFile import"],
    [/SECURITY\s*=\s*"\/usr\/bin\/security"\s+as\s+const/u, "fixed security executable"],
    [/KEYCHAIN_ACCOUNT\s*=\s*"rsi-stage1-one-shot-claims"\s+as\s+const/u, "fixed account"],
    [/MARKER_VALUE\s*=\s*"rsi-claimed-v1"\s+as\s+const/u, "fixed marker value"],
    [/x:\s*"dev\.rsi\.canary\.one-shot\.x-nft-market-pulse-v1"/u, "fixed X marker service"],
    [
      /openSea:\s*"dev\.rsi\.canary\.one-shot\.opensea-base-trending-collections-v1"/u,
      "fixed OpenSea marker service",
    ],
    [
      /baseRpc:\s*"dev\.rsi\.canary\.one-shot\.base-mainnet-finalized-anchor-v1"/u,
      "fixed Base RPC marker service",
    ],
    [/"add-generic-password"/u, "atomic create-only claim command"],
    [/"find-generic-password"/u, "presence-only status command"],
    [/DUPLICATE_ITEM_EXIT_CODE\s*=\s*45/u, "duplicate-item classification"],
    [/ITEM_NOT_FOUND_EXIT_CODE\s*=\s*44/u, "missing-item classification"],
    [/shell:\s*false/u, "shell-free execution"],
  ];
  for (const [pattern, label] of requirements) {
    if (!pattern.test(source)) violations.push(`${ONE_SHOT_CLAIM_FILE} lacks ${label}`);
  }
  const claimCommand = namedFunctionSource(source, "command");
  const statusCommand = namedFunctionSource(source, "statusCommand");
  if (
    claimCommand.length === 0 ||
    !/"add-generic-password"[\s\S]{0,220}?"-a"[\s\S]{0,120}?KEYCHAIN_ACCOUNT[\s\S]{0,120}?"-s"[\s\S]{0,120}?SERVICES\[target\][\s\S]{0,120}?"-w"[\s\S]{0,120}?MARKER_VALUE/u.test(
      claimCommand,
    ) ||
    statusCommand.length === 0 ||
    !/"find-generic-password"[\s\S]{0,220}?"-a"[\s\S]{0,120}?KEYCHAIN_ACCOUNT[\s\S]{0,120}?"-s"[\s\S]{0,120}?SERVICES\[target\]/u.test(
      statusCommand,
    ) ||
    /["']-w["']/u.test(statusCommand) ||
    countMatches(source, /\bexecFile\s*\(/gu) !== 1 ||
    countMatches(source, /["']add-generic-password["']/gu) !== 1 ||
    countMatches(source, /["']find-generic-password["']/gu) !== 1 ||
    /["'](?:-U|delete-generic-password|set-generic-password|reset-generic-password)["']/u.test(
      source,
    )
  ) {
    violations.push(
      `${ONE_SHOT_CLAIM_FILE} must expose only create-once claims and value-free presence checks`,
    );
  }
  for (const [factory, target] of [
    ["createDarwinXOneShotClaimHost", "x"],
    ["createDarwinOpenSeaOneShotClaimHost", "openSea"],
    ["createDarwinBaseRpcOneShotClaimHost", "baseRpc"],
  ]) {
    const factorySource = namedFunctionSource(source, factory);
    if (
      factorySource.length === 0 ||
      !/arguments\.length\s*!==\s*0/u.test(factorySource) ||
      !new RegExp(`return\\s+productionHost\\("${target}"\\)`, "u").test(factorySource)
    ) {
      violations.push(`${ONE_SHOT_CLAIM_FILE} must keep ${factory} option-free and target-fixed`);
    }
  }
}

function verifyReadCanaryCompletionBoundary(root, graph, violations) {
  const controller = requireSource(root, READ_CANARY_CONTROLLER_FILE, graph.files, violations);
  const schemas = requireSource(root, READ_CANARY_SCHEMAS_FILE, graph.files, violations);
  if (controller === undefined || schemas === undefined) return;
  const schemaStart = schemas.indexOf("export const XReadCanaryResultEventPayloadSchema");
  const schemaEnd = schemas.indexOf(".superRefine", schemaStart);
  const resultSchema =
    schemaStart < 0 ? "" : schemas.slice(schemaStart, schemaEnd < 0 ? schemas.length : schemaEnd);
  const resultFields = [...resultSchema.matchAll(/^\s{4}([A-Za-z_$][\w$]*)\s*:/gmu)]
    .map((match) => match[1])
    .sort();
  if (
    !/XReadCanaryResultEventPayloadSchema\s*=\s*z\s*\.strictObject\s*\(\s*\{/u.test(resultSchema) ||
    !hasExactNames(resultFields, [
      "acquiredAt",
      "attemptId",
      "byteLength",
      "capture",
      "completedAt",
      "failureCode",
      "hasNextPage",
      "outcome",
      "postCount",
      "rateLimit",
      "requestFingerprint",
      "requestId",
      "runtime",
      "schemaVersion",
    ])
  ) {
    violations.push(
      `${READ_CANARY_SCHEMAS_FILE} must keep the result checkpoint strict and content-free`,
    );
  }
  const append = namedFunctionSource(controller, "appendResult");
  const candidate = namedFunctionSource(controller, "resultCandidate");
  const recovery = namedFunctionSource(controller, "persistRecoveryResult");
  const live = namedFunctionSource(controller, "persistLiveResult");
  if (
    append.length === 0 ||
    !/const\s+result\s*=\s*XReadCanaryResultEventPayloadSchema\.parse\s*\(\s*resultValue\s*\)/u.test(
      append,
    ) ||
    !/payload:\s*jsonValue\s*\(\s*result\s*\)/u.test(append) ||
    /\b(?:body|content|posts|rawResponse)\s*:/u.test(append)
  ) {
    violations.push(
      `${READ_CANARY_CONTROLLER_FILE} must append only the closed content-free result payload`,
    );
  }
  if (
    candidate.length === 0 ||
    !/const\s+outcome\s*=\s*runtimeDenied\s*\?\s*\("rejected"\s+as\s+const\)/u.test(candidate) ||
    !/failureCode:\s*runtimeDenied\s*\?\s*"RUNTIME_DENIED"/u.test(candidate) ||
    countMatches(candidate, /!runtimeDenied\s*&&/gu) < 2
  ) {
    violations.push(
      `${READ_CANARY_CONTROLLER_FILE} must force denied recovery results to RUNTIME_DENIED with no accepted-result fields`,
    );
  }
  const guardedLiveAppend =
    /runtimeAuthorization\.guardCompletion\s*\(\s*\(\)\s*=>\s*\{\s*persisted\s*=\s*appendResult\s*\(\s*dependencies\.eventStore\s*,\s*candidate\s*\)\s*;?\s*\}\s*\)/u.test(
      live,
    );
  if (
    countMatches(controller, /runtimeAuthorization\.guardCompletion\s*\(/gu) !== 1 ||
    countMatches(live, /\bappendResult\s*\(/gu) !== 1 ||
    !/resultCandidate\s*\(\s*dependencies\s*,\s*prepared\s*,\s*ingestion\s*,\s*false\s*\)/u.test(
      live,
    ) ||
    !guardedLiveAppend ||
    !/completion\.decision\s*!==\s*"allowed"\s*\|\|\s*persisted\s*===\s*undefined/u.test(live) ||
    !/return\s+persistRecoveryResult\s*\(\s*dependencies\s*,\s*prepared\s*,\s*ingestion\s*\)/u.test(
      live,
    )
  ) {
    violations.push(
      `${READ_CANARY_CONTROLLER_FILE} must append the live result inside exactly one allowed completion guard`,
    );
  }
  if (
    countMatches(controller, /\bappendResult\s*\(/gu) !== 3 ||
    countMatches(recovery, /\bappendResult\s*\(/gu) !== 1 ||
    !/resultCandidate\s*\(\s*dependencies\s*,\s*prepared\s*,\s*ingestion\s*,\s*true\s*\)/u.test(
      recovery,
    ) ||
    !/appendResult\s*\(\s*dependencies\.eventStore\s*,\s*candidate\s*\)/u.test(recovery)
  ) {
    violations.push(
      `${READ_CANARY_CONTROLLER_FILE} must forbid unguarded accepted-result appends and force recovery denial`,
    );
  }
}

function verifyOperationsAttemptBoundary(root, graph, violations) {
  const controller = requireSource(root, READ_CANARY_CONTROLLER_FILE, graph.files, violations);
  const operationsStore = requireSource(root, OPERATIONS_STORE_FILE, graph.files, violations);
  if (controller !== undefined) {
    const binding = namedFunctionSource(controller, "assertOperationsAttemptBinding");
    const exactBinding = [
      /binding\.attemptId\s*!==\s*prepared\.attemptId/u,
      /binding\.authorizationExpiresAt\s*!==\s*prepared\.expiresAt/u,
      /binding\.budgetId\s*!==\s*prepared\.budgetId/u,
      /binding\.createdAt\s*!==\s*prepared\.preparedAt/u,
      /binding\.idempotencyKey\s*!==\s*`x-read-canary:\$\{prepared\.requestId\}`/u,
      /binding\.lane\s*!==\s*"discovery"/u,
      /binding\.operation\s*!==\s*X_READ_CANARY_OPERATION/u,
      /binding\.profile\s*!==\s*"canary"/u,
      /binding\.reservedAtomic\s*!==\s*X_RECENT_SEARCH_RESERVED_USD_MICRO/u,
      /binding\.sessionId\s*!==\s*prepared\.requestId/u,
      /binding\.sourcePlane\s*!==\s*"social"/u,
    ];
    if (binding.length === 0 || exactBinding.some((pattern) => !pattern.test(binding))) {
      violations.push(
        `${READ_CANARY_CONTROLLER_FILE} must pin every durable operations-attempt binding field`,
      );
    }

    const allReadbacks = countMatches(controller, /\.readNetworkAttemptBinding\s*\(/gu);
    const exactReadbacks = countMatches(
      controller,
      /\.readNetworkAttemptBinding\s*\(\s*(?:prepared|result)\.attemptId\s*\)/gu,
    );
    const resultBinding = namedFunctionSource(controller, "assertResultBinding");
    const failureClosure = namedFunctionSource(controller, "closeAttemptAfterFailure");
    const resultClosure = namedFunctionSource(controller, "closeAttemptForResult");
    if (
      allReadbacks === 0 ||
      allReadbacks !== exactReadbacks ||
      !/operationsStore\.readNetworkAttemptBinding\s*\(\s*prepared\.attemptId\s*\)[\s\S]{0,300}?prepared/u.test(
        resultBinding,
      ) ||
      !/binding\s*=\s*operationsStore\.readNetworkAttemptBinding\s*\(\s*prepared\.attemptId\s*\)[\s\S]{0,500}?assertOperationsAttemptBinding\s*\(\s*binding\s*,\s*prepared\s*\)/u.test(
        failureClosure,
      ) ||
      !/binding\s*=\s*operationsStore\.readNetworkAttemptBinding\s*\(\s*result\.attemptId\s*\)[\s\S]{0,500}?assertOperationsAttemptBinding\s*\(\s*binding\s*,\s*prepared\s*\)/u.test(
        resultClosure,
      )
    ) {
      violations.push(
        `${READ_CANARY_CONTROLLER_FILE} must authenticate exact operations-attempt readback on result and failure paths`,
      );
    }

    const reservationStart = controller.indexOf("this.#operationsStore.reserveAttempt({");
    const reservationEnd = controller.indexOf("\n      });", reservationStart);
    const reservation =
      reservationStart < 0 || reservationEnd < 0
        ? ""
        : controller.slice(reservationStart, reservationEnd);
    const reservationFields = [
      /attemptId:\s*permit\.attemptId/u,
      /authorizationExpiresAt:\s*runtimeAuthorization\.expiresAt/u,
      /budgetId\s*,/u,
      /createdAt:\s*runtimeAuthorization\.requestedAt/u,
      /idempotencyKey:\s*`x-read-canary:\$\{command\.requestId\}`/u,
      /lane:\s*"discovery"/u,
      /operation:\s*"x\.recent-search\.v1"/u,
      /permitToken:\s*permit\.token/u,
      /reservedAtomic:\s*X_RECENT_SEARCH_RESERVED_USD_MICRO/u,
      /sessionId:\s*command\.requestId/u,
      /sourcePlane:\s*"social"/u,
    ];
    const reservationPropertyNames = [
      ...reservation.matchAll(/^\s+([A-Za-z_$][\w$]*)\s*(?=:|,)/gmu),
    ].map((match) => match[1]);
    if (
      countMatches(controller, /\.reserveAttempt\s*\(/gu) !== 1 ||
      reservationFields.some((pattern) => !pattern.test(reservation)) ||
      reservationPropertyNames.length !== 11 ||
      countMatches(controller, /\.createNetworkAttemptAuthorization\s*\(\s*permit\s*\)/gu) !== 1 ||
      !/createXRecentSearchCollector\s*\(\s*\{[\s\S]{0,1000}?attemptAuthorization:\s*networkAuthorization[\s\S]{0,1000}?runtimeAuthorization[\s\S]{0,1000}?\}\s*\)/u.test(
        controller,
      )
    ) {
      violations.push(
        `${READ_CANARY_CONTROLLER_FILE} must reserve and hand off one exact X canary operations attempt`,
      );
    }
  }

  if (operationsStore !== undefined) {
    const readback = namedClassMethodSource(operationsStore, "readNetworkAttemptBinding");
    const authenticatedReadback = [
      /parseWithSchema\s*\(\s*UuidSchema\s*,\s*attemptIdInput\s*,\s*"attemptId"\s*\)/u,
      /return\s+this\.transaction\s*\(\s*\(\)\s*=>\s*\{/u,
      /this\.getAttemptRow\s*\(\s*attemptId\s*\)/u,
      /this\.assertAttemptRow\s*\(\s*attempt\s*\)/u,
      /this\.getBudgetRow\s*\(\s*attempt\.budget_id\s*\)/u,
      /this\.assertBudgetRow\s*\(\s*budget\s*\)/u,
      /this\.networkAttemptBinding\s*\(\s*attempt\s*,\s*budget\s*\)/u,
      /this\.attemptFromRow\s*\(\s*attempt\s*\)/u,
      /return\s+Object\.freeze\s*\(\s*\{[\s\S]{0,1000}?\.\.\.binding/u,
      /budgetId:\s*facts\.budgetId/u,
      /closedAt:\s*facts\.closedAt/u,
      /createdAt:\s*facts\.createdAt/u,
      /dispatchedAt:\s*facts\.dispatchedAt/u,
      /idempotencyKey:\s*facts\.idempotencyKey/u,
      /outcome:\s*facts\.outcome/u,
      /state:\s*facts\.state/u,
    ];
    if (
      readback.length === 0 ||
      authenticatedReadback.some((pattern) => !pattern.test(readback)) ||
      /\b(?:permit|token)\b/u.test(readback)
    ) {
      violations.push(
        `${OPERATIONS_STORE_FILE} must return only MAC-authenticated durable attempt binding facts`,
      );
    }
  }
}

function verifyProductionLaunchBoundary(root, graph, violations) {
  const config = requireSource(root, PRODUCTION_CONFIG_FILE, graph.files, violations);
  const runtime = requireSource(root, PRODUCTION_RUNTIME_FILE, graph.files, violations);
  const options = requireSource(root, OPERATOR_OPTIONS_FILE, graph.files, violations);
  const entry = requireSource(root, ENTRY, graph.files, violations);
  const host = requireSource(root, OPERATOR_HOST_FILE, graph.files, violations);

  if (config !== undefined) {
    const requirements = [
      [/import\s+\{\s*resolve\s*\}\s+from\s+"node:path"/u, "reviewed path resolver"],
      [
        /CLI_PACKAGE_DIRECTORY\s*=\s*resolve\(import\.meta\.dirname,\s*"\.\."\)/u,
        "module-anchored CLI directory",
      ],
      [
        /PRODUCTION_DATA_DIRECTORY\s*=\s*resolve\(CLI_PACKAGE_DIRECTORY,\s*"\.local"\)/u,
        "module-anchored data directory",
      ],
      [/PRODUCTION_CANARY_PORT\s*=\s*8_787\s+as\s+const/u, "fixed port 8787"],
      [
        /databasePath:\s*resolve\(PRODUCTION_DATA_DIRECTORY,\s*"rsi-runtime\.sqlite"\)/u,
        "fixed X runtime database",
      ],
      [
        /researchDatabasePath:\s*resolve\(PRODUCTION_DATA_DIRECTORY,\s*"rsi-research\.sqlite"\)/u,
        "fixed X research database",
      ],
      [
        /databasePath:\s*resolve\(PRODUCTION_DATA_DIRECTORY,\s*"rsi-opensea-canary-runtime\.sqlite"\)/u,
        "fixed OpenSea runtime database",
      ],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(config)) {
        violations.push(`${PRODUCTION_CONFIG_FILE} lacks ${label}`);
      }
    }
    if (/\b(?:cwd|env|homedir)\s*\(/u.test(config) || /\bprocess\b/u.test(config)) {
      violations.push(
        `${PRODUCTION_CONFIG_FILE} must derive production paths only from its module location`,
      );
    }
  }

  if (runtime !== undefined) {
    const exactStart = runtime.indexOf("export function assertExactProductionRuntime(");
    const activeStart = runtime.indexOf("export function assertActiveProductionRuntime(");
    const exact =
      exactStart < 0 || activeStart < 0 || activeStart <= exactStart
        ? ""
        : runtime.slice(exactStart, activeStart);
    const active = activeStart < 0 ? "" : runtime.slice(activeStart);
    const exactCode = exact.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/gu, "");
    const requirements = [
      [/PRODUCTION_NODE_VERSION\s*=\s*"24\.19\.0"\s+as\s+const/u, "exact Node pin"],
      [/PRODUCTION_PNPM_VERSION\s*=\s*"11\.20\.0"\s+as\s+const/u, "exact pnpm pin"],
      [/value\.nodeVersion\s*!==\s*PRODUCTION_NODE_VERSION/u, "pure Node identity comparison"],
      [
        /pnpmVersionFromUserAgent\(value\.packageManagerUserAgent\)\s*!==\s*PRODUCTION_PNPM_VERSION/u,
        "pure pnpm identity comparison",
      ],
      [
        /throw\s+new\s+Error\(PRODUCTION_RUNTIME_FAILURE_MESSAGE\.trim\(\)\)/u,
        "sanitized fail-closed assertion",
      ],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(runtime)) {
        violations.push(`${PRODUCTION_RUNTIME_FILE} lacks ${label}`);
      }
    }
    if (
      exact.length === 0 ||
      /\bprocess\b/u.test(exactCode) ||
      active.length === 0 ||
      !/nodeVersion:\s*process\.versions\.node/u.test(active) ||
      !/packageManagerUserAgent:\s*process\.env\.npm_config_user_agent\s*\?\?\s*""/u.test(active) ||
      !/assertExactProductionRuntime\s*\(\s*\{/u.test(active) ||
      countMatches(runtime, /\bprocess\.versions\.node\b/gu) !== 1 ||
      countMatches(runtime, /\bprocess\.env\.npm_config_user_agent\b/gu) !== 1
    ) {
      violations.push(
        `${PRODUCTION_RUNTIME_FILE} must keep one exact ambient bridge into the pure runtime assertion`,
      );
    }
  }

  if (options !== undefined) {
    if (
      !/return\s+productionXCanaryHostOptions\(\)/u.test(options) ||
      !/argument\s*===\s*"--help"\s*\|\|\s*argument\s*===\s*"-h"/u.test(options) ||
      !/throw\s+new\s+Error\("X canary production options are fixed"\)/u.test(options) ||
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
    const parseOptions = entry.indexOf("parseXCanaryOperatorOptions(process.argv.slice(2))");
    const runtimeCheck = entry.indexOf("assertActiveProductionRuntime();");
    const hostStart = entry.indexOf("await startXCanaryOperator(options)");
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
      !/STARTUP_FAILURE_MESSAGE\s*=\s*"RSI X canary startup was refused\.\\n"\s+as\s+const/u.test(
        entry,
      ) ||
      countMatches(entry, /process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)/gu) !== 2 ||
      !/try\s*\{[\s\S]{0,300}?options\s*=\s*parseXCanaryOperatorOptions\(process\.argv\.slice\(2\)\)[\s\S]{0,180}?catch\s*\{[\s\S]{0,100}?process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      !/try\s*\{[\s\S]{0,180}?const\s+operator\s*=\s*await\s+startXCanaryOperator\(options\)[\s\S]{0,2400}?catch\s*\{[\s\S]{0,100}?process\.stderr\.write\(STARTUP_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      !/catch\s*\{[\s\S]{0,180}?process\.stderr\.write\(PRODUCTION_RUNTIME_FAILURE_MESSAGE\)[\s\S]{0,120}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      /\bpaths\s*:/u.test(entry)
    ) {
      violations.push(
        `${ENTRY} must sanitize option, runtime, and host startup failures and keep startup output path-free`,
      );
    }
  }

  if (host !== undefined) {
    const runtimeCheck = host.indexOf("assertActiveProductionRuntime();");
    const canonicalOptions = host.indexOf("productionXCanaryHostOptions();");
    const keychain = host.indexOf("new DarwinXReadCanaryKeychain()");
    const claimHost = host.indexOf("createDarwinXOneShotClaimHost()");
    const dispatch = host.indexOf("return startXCanaryOperatorWithHost(");
    if (
      runtimeCheck < 0 ||
      canonicalOptions < runtimeCheck ||
      keychain < canonicalOptions ||
      claimHost < canonicalOptions ||
      dispatch < canonicalOptions ||
      countMatches(host, /assertActiveProductionRuntime\s*\(\s*\)/gu) !== 1 ||
      !/options\.databasePath\s*!==\s*productionOptions\.databasePath/u.test(host) ||
      !/options\.researchDatabasePath\s*!==\s*productionOptions\.researchDatabasePath/u.test(
        host,
      ) ||
      !/options\.port\s*!==\s*productionOptions\.port/u.test(host)
    ) {
      violations.push(
        `${OPERATOR_HOST_FILE} must reject injected production paths and ports before Keychain access`,
      );
    }
  }
}

function verifyXClaimBackfillBoundary(root, violations) {
  const source = (relativeFile) => {
    const path = resolveSourceFile(join(root, relativeFile));
    if (path === undefined) {
      violations.push(`required reviewed source ${relativeFile} is missing`);
      return undefined;
    }
    return readFileSync(path, "utf8");
  };
  const entry = source(CLAIM_BACKFILL_ENTRY_FILE);
  const host = source(CLAIM_BACKFILL_HOST_FILE);
  const core = source(CLAIM_BACKFILL_CORE_FILE);
  const options = source(CLAIM_BACKFILL_OPTIONS_FILE);
  const config = source(PRODUCTION_CONFIG_FILE);

  if (config !== undefined) {
    if (
      !/function\s+productionXCanaryEventStorePath\s*\(\s*\)[\s\S]{0,180}?return\s+resolve\(PRODUCTION_DATA_DIRECTORY,\s*"rsi-x-canary-events\.sqlite"\)/u.test(
        config,
      )
    ) {
      violations.push(
        `${PRODUCTION_CONFIG_FILE} must own the canonical X receipt-store path for marker backfill`,
      );
    }
  }
  if (options !== undefined) {
    if (
      !/ACKNOWLEDGEMENT_FLAG\s*=\s*"--typed-plan-id-acknowledgement"\s+as\s+const/u.test(options) ||
      !/normalized\[1\]\s*!==\s*X_READ_CANARY_PLAN_ID/u.test(options) ||
      !/return\s+X_READ_CANARY_PLAN_ID/u.test(options) ||
      /["']--(?:db|research-db|port)["']/u.test(options) ||
      /\b(?:cwd|env|homedir)\s*\(/u.test(options)
    ) {
      violations.push(
        `${CLAIM_BACKFILL_OPTIONS_FILE} must require only the exact published X plan acknowledgement`,
      );
    }
  }
  if (core !== undefined) {
    const projection = core.indexOf('readXReadCanaryProjection(eventStore, "unknown")');
    const claim = core.indexOf("await claimHost.claim();");
    if (
      projection < 0 ||
      claim < projection ||
      countMatches(core, /claimHost\.claim\s*\(\s*\)/gu) !== 1 ||
      !/projection\.status\s*!==\s*"completed"/u.test(core) ||
      !/projection\.lastReceipt\s*===\s*null/u.test(core) ||
      !/projection\.lastReceipt\.planId\s*!==\s*X_READ_CANARY_PLAN_ID/u.test(core) ||
      !/typedPlanIdAcknowledgement\s*!==\s*X_READ_CANARY_PLAN_ID/u.test(core) ||
      /\b(?:fetch|withSecrets|bearerToken|apiKey|XReadCanaryController)\b/u.test(core)
    ) {
      violations.push(
        `${CLAIM_BACKFILL_CORE_FILE} must validate the canonical completed receipt before its only marker claim`,
      );
    }
  }
  if (host !== undefined) {
    const runtime = host.indexOf("assertActiveProductionRuntime();");
    const path = host.indexOf("productionXCanaryEventStorePath();");
    const inspect = host.indexOf("lstat(dirname(eventStorePath)");
    const open = host.indexOf("new SqliteEventStore(eventStorePath)");
    const invoke = host.indexOf("backfillXCanaryClaimWithHost(");
    if (
      runtime < 0 ||
      path < runtime ||
      inspect < path ||
      open < inspect ||
      invoke < open ||
      countMatches(host, /createDarwinXOneShotClaimHost\s*\(\s*\)/gu) !== 1 ||
      !/OWNER_ONLY_DIRECTORY_MODE\s*=\s*0o700n/u.test(host) ||
      !/directoryEntry\.uid\s*!==\s*EFFECTIVE_USER_ID/u.test(host) ||
      !/eventStoreEntry\.uid\s*!==\s*EFFECTIVE_USER_ID/u.test(host) ||
      !/eventStore\.close\(\)/u.test(host) ||
      /\b(?:fetch|withSecrets|bearerToken|apiKey|DarwinXReadCanaryKeychain)\b/u.test(host)
    ) {
      violations.push(
        `${CLAIM_BACKFILL_HOST_FILE} must use only the canonical owner-controlled receipt store and fixed X marker host`,
      );
    }
  }
  if (entry !== undefined) {
    const parse = entry.indexOf("parseXCanaryClaimBackfillAcknowledgement(process.argv.slice(2))");
    const runtime = entry.indexOf("assertActiveProductionRuntime();");
    const invoke = entry.indexOf("backfillXCanaryClaim(acknowledgement)");
    if (
      parse < 0 ||
      runtime < 0 ||
      runtime < parse ||
      invoke < runtime ||
      countMatches(entry, /assertActiveProductionRuntime\s*\(\s*\)/gu) !== 1 ||
      !/process\.stderr\.write\(PRODUCTION_RUNTIME_FAILURE_MESSAGE\)/u.test(entry) ||
      !/BACKFILL_FAILURE_MESSAGE\s*=\s*"RSI X one-shot marker backfill was refused\.\\n"\s+as\s+const/u.test(
        entry,
      ) ||
      countMatches(entry, /process\.stderr\.write\(BACKFILL_FAILURE_MESSAGE\)/gu) !== 2 ||
      !/try\s*\{[\s\S]{0,300}?acknowledgement\s*=\s*parseXCanaryClaimBackfillAcknowledgement\(process\.argv\.slice\(2\)\)[\s\S]{0,180}?catch\s*\{[\s\S]{0,100}?process\.stderr\.write\(BACKFILL_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      !/try\s*\{[\s\S]{0,180}?await\s+backfillXCanaryClaim\(acknowledgement\)[\s\S]{0,500}?catch\s*\{[\s\S]{0,100}?process\.stderr\.write\(BACKFILL_FAILURE_MESSAGE\)[\s\S]{0,100}?process\.exitCode\s*=\s*1/u.test(
        entry,
      ) ||
      /\b(?:fetch|withSecrets|bearerToken|apiKey)\b/u.test(entry)
    ) {
      violations.push(
        `${CLAIM_BACKFILL_ENTRY_FILE} must fail closed before marker backfill and emit only sanitized status`,
      );
    }
  }

  try {
    const rootPackage = readJson(join(root, "package.json"), "package.json");
    const cliPackage = readJson(join(root, "apps/cli/package.json"), "apps/cli/package.json");
    if (
      rootPackage.scripts?.["operator:x-canary-backfill-claim"] !==
        "pnpm --filter @rsi/cli run operator:x-canary-backfill-claim --" ||
      cliPackage.scripts?.["operator:x-canary-backfill-claim"] !==
        "node ../../scripts/ci/assert-runtime.mjs && tsx src/x-canary-claim-backfill.ts"
    ) {
      violations.push("X marker backfill scripts must retain the exact runtime preflight");
    }
  } catch (error) {
    violations.push(error instanceof Error ? error.message : String(error));
  }
}

function verifyOperatorHostBoundary(root, graph, violations) {
  const host = requireSource(root, OPERATOR_HOST_FILE, graph.files, violations);
  const core = requireSource(root, OPERATOR_HOST_CORE_FILE, graph.files, violations);
  const publicTypes = [
    "RunningXCanaryOperator",
    "StartXCanaryOperatorOptions",
    "XCanaryOperatorPaths",
  ];
  if (core !== undefined) {
    if (!hasExactNames(staticExportNames(core), [...publicTypes, "startXCanaryOperatorWithHost"])) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} may export only the reviewed host function and three public types`,
      );
    }
    if (
      !/export\s+async\s+function\s+startXCanaryOperatorWithHost\s*\([\s\S]{0,500}?options\s*:\s*StartXCanaryOperatorOptions\s*,[\s\S]{0,500}?credentialHost\s*:\s*DarwinXReadCanaryKeychain\s*,[\s\S]{0,300}?claimHost\s*:\s*DarwinOneShotClaimHost/u.test(
        core,
      )
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must keep credential and claim injection in its private three-argument host function`,
      );
    }
    const optionsStart = core.search(
      /export\s+(?:interface\s+StartXCanaryOperatorOptions|type\s+StartXCanaryOperatorOptions\b)/u,
    );
    const optionsEnd =
      optionsStart < 0 ? -1 : core.indexOf("\nexport ", optionsStart + "\nexport ".length);
    const optionsSource =
      optionsStart < 0 ? "" : core.slice(optionsStart, optionsEnd < 0 ? core.length : optionsEnd);
    if (
      optionsSource.length === 0 ||
      /\b(?:bearerToken|credentialHost|executor|fetch|now|platform|secret)\b/u.test(optionsSource)
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must keep credential and transport injection out of public options`,
      );
    }

    const privateDirectoryRequirements = [
      /const\s+PRIVATE_DIRECTORY_MODE\s*=\s*0o700n/u,
      /typeof\s+process\.geteuid\s*===\s*"function"\s*\?\s*BigInt\(process\.geteuid\(\)\)\s*:\s*null/u,
      /mkdir\(dirname\(path\),\s*\{\s*mode:\s*Number\(PRIVATE_DIRECTORY_MODE\),\s*recursive:\s*true\s*\}\)/u,
      /lstat\(parent,\s*\{\s*bigint:\s*true\s*\}\)/u,
      /\(parentEntry\.mode\s*&\s*0o777n\)\s*!==\s*PRIVATE_DIRECTORY_MODE/u,
      /EFFECTIVE_USER_ID\s*===\s*null\s*\|\|\s*parentEntry\.uid\s*!==\s*EFFECTIVE_USER_ID/u,
    ];
    if (privateDirectoryRequirements.some((pattern) => !pattern.test(core))) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must enforce an owner-owned mode-0700 data directory before credential access`,
      );
    }

    const live = namedClassMethodSource(core, "runWithKeychain");
    const recovery = namedClassMethodSource(core, "recoverWithStorageSecrets");
    const operationsConstruction =
      /new\s+SqliteOperationsStore\s*\(\s*\{\s*path:\s*this\.paths\.operations\s*,\s*stateKey:\s*secrets\.operationsStateKey\s*,?\s*\}\s*\)/u;
    const registryConstruction =
      /SqliteCaptureRegistry\.open\s*\(\s*\{\s*expectedProfile:\s*"canary"\s*,\s*path:\s*this\.paths\.captureRegistry\s*,\s*registryKey:\s*secrets\.captureRegistryKey\s*,?\s*\}\s*\)/u;
    const vaultConstruction =
      /SnapshotVault\.open\s*\(\s*\{\s*directory:\s*this\.paths\.vault\s*,\s*maxCaptureBytes:\s*1_048_576\s*,\s*wrappingKey:\s*secrets\.vaultWrappingKey\s*,?\s*\}\s*\)/u;
    const liveControllerConstruction =
      /new\s+XReadCanaryController\s*\(\s*\{\s*bearerToken:\s*secrets\.bearerToken\s*,\s*captureRegistry\s*,\s*eventStore:\s*this\.eventStore\s*,\s*operationsStore\s*,\s*runtime:\s*this\.runtime\s*,\s*vault\s*,?\s*\}\s*\)/u;
    if (
      live.length === 0 ||
      recovery.length === 0 ||
      countMatches(core, /\.withSecrets\s*\(/gu) !== 1 ||
      countMatches(core, /\.withStorageSecrets\s*\(/gu) !== 1 ||
      !/return\s+this\.credentialHost\.withSecrets\s*\(\s*async\s*\(\s*secrets\s*\)\s*=>\s*\{/u.test(
        live,
      ) ||
      !/await\s+this\.claimHost\.claim\(\)\s*;[\s\S]{0,120}?return\s+this\.credentialHost\.withSecrets/u.test(
        live,
      ) ||
      !/await\s+this\.credentialHost\.withStorageSecrets\s*\(\s*async\s*\(\s*secrets\s*\)\s*=>\s*\{/u.test(
        recovery,
      ) ||
      !operationsConstruction.test(live) ||
      !operationsConstruction.test(recovery) ||
      !registryConstruction.test(live) ||
      !registryConstruction.test(recovery) ||
      !vaultConstruction.test(live) ||
      !vaultConstruction.test(recovery) ||
      !liveControllerConstruction.test(live) ||
      countMatches(core, /new\s+SqliteOperationsStore\s*\(/gu) !== 2 ||
      countMatches(core, /SqliteCaptureRegistry\.open\s*\(/gu) !== 2 ||
      countMatches(core, /SnapshotVault\.open\s*\(/gu) !== 2 ||
      countMatches(core, /new\s+XReadCanaryController\s*\(/gu) !== 1 ||
      countMatches(core, /secrets\.bearerToken\b/gu) !== 1 ||
      countMatches(core, /secrets\.operationsStateKey\b/gu) !== 2 ||
      countMatches(core, /secrets\.captureRegistryKey\b/gu) !== 2 ||
      countMatches(core, /secrets\.vaultWrappingKey\b/gu) !== 2
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must bind the live and recovery paths only to their exact Keychain secrets`,
      );
    }
    if (
      countMatches(core, /this\.claimHost\.claim\(\)/gu) !== 1 ||
      countMatches(core, /this\.claimHost\.status\(\)/gu) !== 1 ||
      /claimHost/u.test(recovery) ||
      !/projection\.lastReceipt\s*!==\s*null\s*&&\s*\(await\s+this\.claimHost\.status\(\)\)\s*!==\s*"present"/u.test(
        core,
      )
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must claim before live credentials and require a presence-only marker for completed receipts`,
      );
    }

    if (
      countMatches(core, /SqliteRuntimeController\.open\s*\(/gu) !== 1 ||
      countMatches(core, /SqliteRuntimeController\.open\s*\(\s*\{[^{}]*\}\s*\)/gu) !== 1 ||
      countMatches(core, /new\s+SqliteOperationsStore\s*\(\s*\{[^{}]*\}\s*\)/gu) !== 2 ||
      /\b(?:clock|monotonicClock)\s*:/u.test(core)
    ) {
      violations.push(
        `${OPERATOR_HOST_CORE_FILE} must keep runtime and operations clocks production-owned`,
      );
    }
  }
  if (host !== undefined) {
    if (!hasExactNames(staticExportNames(host), [...publicTypes, "startXCanaryOperator"])) {
      violations.push(
        `${OPERATOR_HOST_FILE} may export only the production starter and three public types`,
      );
    }
    const requirements = [
      [/from\s+"\.\/x-canary-operator-host-core\.js"/u, "private host-core import"],
      [/from\s+"@rsi\/credential-host"/u, "production credential-host import"],
      [/\bDarwinXReadCanaryKeychain\b/u, "production Darwin Keychain binding"],
      [/new\s+DarwinXReadCanaryKeychain\s*\(\s*\)/u, "option-free production Keychain"],
      [
        /createDarwinXOneShotClaimHost\s*\(\s*\)/u,
        "option-free target-fixed production claim host",
      ],
      [
        /export\s+async\s+function\s+startXCanaryOperator\s*\(\s*options\s*:\s*StartXCanaryOperatorOptions\s*,?\s*\)\s*:\s*Promise<RunningXCanaryOperator>/u,
        "one-argument production starter",
      ],
      [
        /startXCanaryOperatorWithHost\s*\(\s*(?:options|productionOptions)\s*,\s*(?:credentialHost|keychain|new\s+DarwinXReadCanaryKeychain\s*\(\s*\))\s*,\s*(?:claimHost|createDarwinXOneShotClaimHost\s*\(\s*\))\s*,?\s*\)/u,
        "private host dispatch",
      ],
    ];
    for (const [pattern, label] of requirements) {
      if (!pattern.test(host)) violations.push(`${OPERATOR_HOST_FILE} lacks ${label}`);
    }
    if (
      /\b(?:ForTesting|TestingOptions|credentialHost\s*[:?]|executor\s*[:?]|fetch\s*[:?])\b/u.test(
        host,
      ) ||
      /(?:\/testing|\.testing(?:\.|"|'))/u.test(host)
    ) {
      violations.push(
        `${OPERATOR_HOST_FILE} must not expose or import a credential-injecting testing surface`,
      );
    }
  }
}

function verifyOriginAndBrowserBoundary(root, graph, violations) {
  const allowedLiteralOrigins = new Set([
    "http://operator.invalid",
    "https://api.x.com",
    EXACT_X_ENDPOINT,
  ]);
  for (const path of graph.files) {
    const relativeFile = canonicalRelative(root, path);
    const analysis = graph.analyses.get(path);
    if (analysis === undefined) continue;
    const origins = [];
    for (const literal of analysis.literals) {
      origins.push(
        ...[...literal.matchAll(/\b(?:https?|wss?):\/\/[A-Za-z0-9][^"'`\s)<]*/gu)].map(
          (match) => match[0],
        ),
      );
    }
    for (const origin of origins) {
      if (!allowedLiteralOrigins.has(origin)) {
        violations.push(`${relativeFile} declares unreviewed network origin ${origin}`);
      }
    }
  }
  const server = requireSource(root, OPERATOR_SERVER_FILE, graph.files, violations);
  if (server === undefined) return;
  if (
    countMatches(server, /connect-src/gu) !== 1 ||
    !server.includes(
      `"default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; " +`,
    ) ||
    !server.includes(`"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"`)
  ) {
    violations.push(
      `${OPERATOR_SERVER_FILE} must keep dashboard connections, scripts, styles, and forms same-origin`,
    );
  }
}

function verifyRequiredPackages(graph, violations) {
  for (const name of REQUIRED_PACKAGES) {
    if (!graph.reachedPackages.has(name)) {
      violations.push(`production graph does not reach required reviewed package ${name}`);
    }
  }
}

export function verifyStage1ReadCanaryBoundary(options = {}) {
  const root = realpathSync(options.root ?? DEFAULT_ROOT);
  const violations = [];
  let packages;
  try {
    packages = discoverWorkspacePackages(root);
  } catch (error) {
    violations.push(error instanceof Error ? error.message : String(error));
    packages = new Map();
  }
  const graph = inspectGraph(root, packages);
  violations.push(...graph.violations);
  verifyRequiredPackages(graph, violations);
  verifyFetchBoundary(root, graph, violations);
  verifyXContract(root, graph, violations);
  verifyKeychainBoundary(root, graph, violations);
  verifyOneShotClaimBoundary(root, graph, violations);
  verifyReadCanaryCompletionBoundary(root, graph, violations);
  verifyOperationsAttemptBoundary(root, graph, violations);
  verifyProductionLaunchBoundary(root, graph, violations);
  verifyXClaimBackfillBoundary(root, violations);
  verifyOperatorHostBoundary(root, graph, violations);
  verifyOriginAndBrowserBoundary(root, graph, violations);

  const uniqueViolations = [...new Set(violations)].sort();
  if (uniqueViolations.length > 0) throw new Stage1VerificationFailure(uniqueViolations);
  return Object.freeze({
    endpoint: EXACT_X_ENDPOINT,
    files: graph.files.size,
    maximumRequests: 1,
    maximumResults: 10,
    packages: Object.freeze([...graph.reachedPackages].sort()),
    status: "pass",
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(THIS_FILE);
}

if (isMainModule()) {
  try {
    const report = verifyStage1ReadCanaryBoundary();
    console.log(
      `Stage 1 X read-canary authority isolation passed: ${report.files} production graph files, ` +
        `${report.packages.length} reviewed workspace packages, exactly ${report.maximumRequests} ` +
        `GET request with at most ${report.maximumResults} results.`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

export { Stage1VerificationFailure };
