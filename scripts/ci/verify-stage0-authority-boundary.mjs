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
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:http",
  "node:net",
  "node:path",
  "node:perf_hooks",
  "node:sqlite",
  "node:util",
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
const FORBIDDEN_MODULE_LOADER_IDENTIFIERS = new Set(["createRequire", "getBuiltinModule"]);
const FORBIDDEN_MODULE_LOADER_LITERALS = new Set(["createRequire", "getBuiltinModule"]);
const FORBIDDEN_DYNAMIC_CODE_IDENTIFIERS = new Set([
  "AsyncFunction",
  "eval",
  "Function",
  "GeneratorFunction",
]);

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

function conditionTarget(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    for (const item of value) {
      const target = conditionTarget(item);
      if (target !== undefined) return target;
    }
    return undefined;
  }
  if (value !== null && typeof value === "object") {
    for (const condition of ["types", "import", "node", "default"]) {
      const target = conditionTarget(value[condition]);
      if (target !== undefined) return target;
    }
  }
  return undefined;
}

function packageTarget(workspacePackage, subpath) {
  const { manifest } = workspacePackage;
  const exportKey = subpath === "" ? "." : `./${subpath}`;
  if (manifest.exports !== undefined) {
    const exportValue =
      typeof manifest.exports === "string" || Array.isArray(manifest.exports)
        ? subpath === ""
          ? manifest.exports
          : undefined
        : manifest.exports?.[exportKey];
    const target = conditionTarget(exportValue);
    if (target !== undefined) return target;
  }
  if (subpath !== "") return `./src/${subpath}`;
  for (const field of ["types", "module", "main"]) {
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
  const forbiddenIdentifiers = [];
  const forbiddenLiterals = [];
  const forbiddenDynamicCode = [];
  const forbiddenModuleLoaders = [];
  const allLiterals = new Set();

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
    if (token.kind === ts.SyntaxKind.Identifier && FORBIDDEN_CODE_IDENTIFIERS.has(token.value)) {
      forbiddenIdentifiers.push(token.value);
    }
    if (
      token.kind === ts.SyntaxKind.Identifier &&
      FORBIDDEN_MODULE_LOADER_IDENTIFIERS.has(token.value)
    ) {
      forbiddenModuleLoaders.push(token.value);
    }
    if (
      token.kind === ts.SyntaxKind.Identifier &&
      FORBIDDEN_DYNAMIC_CODE_IDENTIFIERS.has(token.value)
    ) {
      forbiddenDynamicCode.push(token.value);
    }
    if (isLiteral(token)) {
      allLiterals.add(token.value);
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

    if (token.kind === ts.SyntaxKind.ImportKeyword) {
      const next = source.tokens[index + 1];
      if (next?.kind === ts.SyntaxKind.DotToken) continue;
      if (next?.kind === ts.SyntaxKind.OpenParenToken) {
        const specifier = moduleLiteral(source.tokens[index + 2]);
        const closed = source.tokens[index + 3]?.kind === ts.SyntaxKind.CloseParenToken;
        imports.push(
          specifier !== undefined && closed
            ? { dynamic: false, specifier }
            : { dynamic: true, specifier: null },
        );
        continue;
      }

      const end = statementEnd(index + 1);
      const sideEffectSpecifier = moduleLiteral(next);
      if (sideEffectSpecifier !== undefined) {
        imports.push({ dynamic: false, specifier: sideEffectSpecifier });
        continue;
      }
      let found;
      let containsRequire = false;
      for (let cursor = index + 1; cursor < end; cursor += 1) {
        if (
          source.tokens[cursor].kind === ts.SyntaxKind.Identifier &&
          source.tokens[cursor].value === "require"
        ) {
          containsRequire = true;
        }
        if (source.tokens[cursor].kind !== ts.SyntaxKind.FromKeyword) continue;
        found = moduleLiteral(source.tokens[cursor + 1]);
        break;
      }
      if (found !== undefined) imports.push({ dynamic: false, specifier: found });
      else if (!containsRequire) imports.push({ dynamic: true, specifier: null });
      continue;
    }

    if (token.kind === ts.SyntaxKind.ExportKeyword) {
      let declarationStart = index + 1;
      if (source.tokens[declarationStart]?.kind === ts.SyntaxKind.TypeKeyword) {
        declarationStart += 1;
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
            ? { dynamic: true, specifier: null }
            : { dynamic: false, specifier },
        );
        break;
      }
      continue;
    }

    if (
      token.kind === ts.SyntaxKind.Identifier &&
      token.value === "require" &&
      source.tokens[index + 1]?.kind === ts.SyntaxKind.OpenParenToken
    ) {
      const specifier = moduleLiteral(source.tokens[index + 2]);
      const closed = source.tokens[index + 3]?.kind === ts.SyntaxKind.CloseParenToken;
      imports.push(
        specifier !== undefined && closed
          ? { dynamic: false, specifier }
          : { dynamic: true, specifier: null },
      );
    }
  }
  return {
    imports,
    forbiddenDynamicCode: [...new Set(forbiddenDynamicCode)].sort(),
    forbiddenIdentifiers: [...new Set(forbiddenIdentifiers)].sort(),
    forbiddenLiterals: [...new Set(forbiddenLiterals)].sort(),
    forbiddenModuleLoaders: [...new Set(forbiddenModuleLoaders)].sort(),
    literals: allLiterals,
  };
}

function classifyModuleSpecifier(specifier) {
  if (FORBIDDEN_PLATFORM_MODULES.has(specifier)) {
    return `platform module ${specifier} (${FORBIDDEN_PLATFORM_MODULES.get(specifier)})`;
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

    for (const dependency of analysis.imports) {
      if (dependency.dynamic) {
        violations.push(`${label}: ${relativeFile} contains a non-literal import/require`);
        continue;
      }
      const specifier = dependency.specifier;
      const classification = classifyModuleSpecifier(specifier);
      if (classification !== undefined) {
        violations.push(`${label}: ${relativeFile} imports ${classification}`);
        continue;
      }

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
          const target = packageTarget(workspace.workspacePackage, workspace.subpath);
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
  const exportTarget = conditionTarget(
    typeof manifest.exports === "object" && manifest.exports !== null
      ? manifest.exports["."]
      : manifest.exports,
  );
  if (exportTarget !== "./src/index.ts") {
    violations.push(`@rsi/runtime must export only ./src/index.ts from its root entrypoint`);
  }
  if (
    typeof manifest.exports === "object" &&
    manifest.exports !== null &&
    !Array.isArray(manifest.exports) &&
    Object.keys(manifest.exports).some((key) => key !== ".")
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
