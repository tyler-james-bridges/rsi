import assert from "node:assert/strict";
import {
  appendFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  Stage1VerificationFailure,
  verifyStage1ReadCanaryBoundary,
} from "./verify-stage1-read-canary-boundary.mjs";

const REQUIRED_PACKAGES = [
  "capture-registry",
  "credential-host",
  "ingestion",
  "operations",
  "operator",
  "read-canary",
  "research-ledger",
  "runtime",
  "store",
  "vault",
  "x-collector",
];

function write(root, path, contents) {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function manifest(name, exports = { ".": "./src/index.ts" }) {
  return `${JSON.stringify({ name, type: "module", exports }, null, 2)}\n`;
}

function makeFixture() {
  const root = mkdtempSync(join(tmpdir(), "rsi-stage1-read-canary-gate-"));
  for (const packageName of REQUIRED_PACKAGES) {
    const directory = packageName === "operator" ? "apps/operator" : `packages/${packageName}`;
    write(root, `${directory}/package.json`, manifest(`@rsi/${packageName}`));
    write(
      root,
      `${directory}/src/index.ts`,
      `export const ${packageName.replaceAll("-", "_")} = true;\n`,
    );
  }

  write(
    root,
    "packages/operations/src/index.ts",
    `export * from "./sqlite-operations-store.js";\n`,
  );
  write(
    root,
    "packages/operations/src/sqlite-operations-store.ts",
    `declare const UuidSchema: unknown;
declare function parseWithSchema(...values: unknown[]): any;
export class SqliteOperationsStore {
  private transaction<T>(operation: () => T): T { return operation(); }
  private getAttemptRow(attemptId: string): any { return { attemptId }; }
  private assertAttemptRow(attempt: unknown): void { void attempt; }
  private getBudgetRow(budgetId: string): any { return { budgetId }; }
  private assertBudgetRow(budget: unknown): void { void budget; }
  private networkAttemptBinding(attempt: unknown, budget: unknown): any {
    void attempt;
    void budget;
    return {};
  }
  private attemptFromRow(attempt: unknown): any { void attempt; return {}; }
  readNetworkAttemptBinding(attemptIdInput: unknown): any {
    const attemptId = parseWithSchema(UuidSchema, attemptIdInput, "attemptId");
    return this.transaction(() => {
      const attempt = this.getAttemptRow(attemptId);
      if (attempt === undefined) throw new Error("missing attempt");
      this.assertAttemptRow(attempt);
      const budget = this.getBudgetRow(attempt.budget_id);
      if (budget === undefined) throw new Error("missing budget");
      this.assertBudgetRow(budget);
      const binding = this.networkAttemptBinding(attempt, budget);
      const facts = this.attemptFromRow(attempt);
      return Object.freeze({
        ...binding,
        budgetId: facts.budgetId,
        closedAt: facts.closedAt,
        createdAt: facts.createdAt,
        dispatchedAt: facts.dispatchedAt,
        idempotencyKey: facts.idempotencyKey,
        outcome: facts.outcome,
        state: facts.state,
      });
    });
  }
}
`,
  );

  write(
    root,
    "apps/cli/src/x-canary-operator.ts",
    `${REQUIRED_PACKAGES.map((name) => `import "@rsi/${name}";`).join("\n")}
import { startXCanaryOperator } from "./x-canary-operator-host.js";
void startXCanaryOperator;
`,
  );
  write(
    root,
    "apps/cli/src/x-canary-operator-host-core.ts",
    `import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import { dirname } from "node:path";
import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import type { DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import { SqliteOperationsStore } from "@rsi/operations";
import { XReadCanaryController } from "@rsi/read-canary";
import { SqliteRuntimeController } from "@rsi/runtime";
import { SnapshotVault } from "@rsi/vault";
const PRIVATE_DIRECTORY_MODE = 0o700n;
const EFFECTIVE_USER_ID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : null;
async function resolveDatabaseIdentity(path: string) {
  await mkdir(dirname(path), { mode: Number(PRIVATE_DIRECTORY_MODE), recursive: true });
  const parent = await realpath(dirname(path));
  const parentEntry = await lstat(parent, { bigint: true });
  if (
    !parentEntry.isDirectory() ||
    parentEntry.isSymbolicLink() ||
    (parentEntry.mode & 0o777n) !== PRIVATE_DIRECTORY_MODE ||
    (EFFECTIVE_USER_ID === null || parentEntry.uid !== EFFECTIVE_USER_ID)
  ) throw new Error("unsafe fixture directory");
  void stat;
  return path;
}
export interface StartXCanaryOperatorOptions {
  readonly databasePath: string;
  readonly port: number;
  readonly researchDatabasePath: string;
}
export interface XCanaryOperatorPaths {
  readonly runtime: string;
}
export interface RunningXCanaryOperator {
  readonly paths: XCanaryOperatorPaths;
}
class FixtureCredentialProvider {
  constructor(
    private readonly credentialHost: DarwinXReadCanaryKeychain,
    private readonly eventStore: unknown,
    private readonly paths: any,
    private readonly runtime: unknown,
  ) {}
  async #runWithKeychain(): Promise<unknown> {
    return this.credentialHost.withSecrets(async (secrets) => {
      const operationsStore = new SqliteOperationsStore({
        path: this.paths.operations,
        stateKey: secrets.operationsStateKey,
      });
      const captureRegistry = SqliteCaptureRegistry.open({
        expectedProfile: "canary",
        path: this.paths.captureRegistry,
        registryKey: secrets.captureRegistryKey,
      });
      const vault = await SnapshotVault.open({
        directory: this.paths.vault,
        maxCaptureBytes: 1_048_576,
        wrappingKey: secrets.vaultWrappingKey,
      });
      return new XReadCanaryController({
        bearerToken: secrets.bearerToken,
        captureRegistry,
        eventStore: this.eventStore,
        operationsStore,
        runtime: this.runtime,
        vault,
      });
    });
  }
  async #recoverWithStorageSecrets(): Promise<void> {
    await this.credentialHost.withStorageSecrets(async (secrets) => {
      const operationsStore = new SqliteOperationsStore({
        path: this.paths.operations,
        stateKey: secrets.operationsStateKey,
      });
      const captureRegistry = SqliteCaptureRegistry.open({
        expectedProfile: "canary",
        path: this.paths.captureRegistry,
        registryKey: secrets.captureRegistryKey,
      });
      const vault = await SnapshotVault.open({
        directory: this.paths.vault,
        maxCaptureBytes: 1_048_576,
        wrappingKey: secrets.vaultWrappingKey,
      });
      void operationsStore;
      void captureRegistry;
      void vault;
    });
  }
}
export async function startXCanaryOperatorWithHost(
  options: StartXCanaryOperatorOptions,
  credentialHost: DarwinXReadCanaryKeychain,
): Promise<RunningXCanaryOperator> {
  await resolveDatabaseIdentity(options.databasePath);
  const runtime = SqliteRuntimeController.open({
    openedAt: "2026-01-01T00:00:00.000Z",
    path: options.databasePath,
    processInstanceId: "00000000-0000-4000-8000-000000000000",
  });
  void new FixtureCredentialProvider(credentialHost, {}, {}, runtime);
  return { paths: { runtime: options.databasePath } };
}
`,
  );
  write(
    root,
    "apps/cli/src/x-canary-operator-host.ts",
    `import { DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import {
  startXCanaryOperatorWithHost,
  type RunningXCanaryOperator,
  type StartXCanaryOperatorOptions,
} from "./x-canary-operator-host-core.js";
export type {
  RunningXCanaryOperator,
  StartXCanaryOperatorOptions,
  XCanaryOperatorPaths,
} from "./x-canary-operator-host-core.js";
export async function startXCanaryOperator(
  options: StartXCanaryOperatorOptions,
): Promise<RunningXCanaryOperator> {
  const credentialHost = new DarwinXReadCanaryKeychain();
  return startXCanaryOperatorWithHost(options, credentialHost);
}
`,
  );
  write(
    root,
    "apps/cli/src/x-canary-operator-host.testing.ts",
    `import type { DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import {
  startXCanaryOperatorWithHost,
  type StartXCanaryOperatorOptions,
} from "./x-canary-operator-host-core.js";
export interface StartXCanaryOperatorTestingOptions extends StartXCanaryOperatorOptions {
  readonly credentialHost: DarwinXReadCanaryKeychain;
}
export function startXCanaryOperatorForTesting(options: StartXCanaryOperatorTestingOptions) {
  return startXCanaryOperatorWithHost(options, options.credentialHost);
}
`,
  );

  write(
    root,
    "packages/x-collector/src/index.ts",
    `export {
  createXRecentSearchCollector,
  isXRecentSearchCollector,
  xRecentSearchRuntimeActionId,
  type XRecentSearchCollectOptions,
  type XRecentSearchCollector,
  type XRecentSearchCollectorOptions,
  type XRecentSearchLiveOptions,
  type XRecentSearchReplayOptions,
} from "./collector.js";
export * from "./constants.js";
export * from "./query.js";
`,
  );
  write(
    root,
    "packages/runtime/src/index.ts",
    `export * from "./boundary-authorization.js";
export * from "./sqlite-runtime-controller.js";
`,
  );
  write(
    root,
    "packages/runtime/src/boundary-authorization.ts",
    `import { types as utilTypes } from "node:util";
const AUTHENTIC_AUTHORIZATIONS = new WeakSet<object>();
const CONSUMED_AUTHORIZATIONS = new WeakSet<object>();
const DISPATCHED_AUTHORIZATIONS = new WeakSet<object>();
const COMPLETED_AUTHORIZATIONS = new WeakSet<object>();
export function isRuntimeBoundaryAuthorization() { return true; }
export function createAuthorization(parts: { boundary: string }) {
  const authorization = Object.create(null);
  const properties: Record<string, unknown> = {};
  const consume = () => {
    CONSUMED_AUTHORIZATIONS.add(authorization);
  };
  const guardCompletion = (...arguments_: unknown[]) => {
    if (!AUTHENTIC_AUTHORIZATIONS.has(authorization)) throw new Error("not authentic");
    if (!DISPATCHED_AUTHORIZATIONS.has(authorization)) throw new Error("not dispatched");
    if (COMPLETED_AUTHORIZATIONS.has(authorization)) throw new Error("already completed");
    COMPLETED_AUTHORIZATIONS.add(authorization);
    const callback = arguments_[0];
    if (
      arguments_.length !== 1 ||
      typeof callback !== "function" ||
      utilTypes.isProxy(callback) ||
      utilTypes.isAsyncFunction(callback) ||
      utilTypes.isGeneratorFunction(callback) ||
      Object.prototype.toString.call(callback) !== "[object Function]"
    ) throw new Error("completion callback must be synchronous");
    return guardBoundaryCompletion(callback);
  };
  if (parts.boundary === "research_collection") {
    properties.consumeAndDispatch = { value: consumeAndDispatch };
    properties.guardCompletion = { value: guardCompletion };
  } else {
    properties.consume = { value: consume };
  }
  AUTHENTIC_AUTHORIZATIONS.add(authorization);
  return authorization;
}
declare const consumeAndDispatch: unknown;
declare function guardBoundaryCompletion(callback: unknown): unknown;
void CONSUMED_AUTHORIZATIONS;
void DISPATCHED_AUTHORIZATIONS;
`,
  );
  write(
    root,
    "packages/runtime/src/sqlite-runtime-controller.ts",
    `declare const RUNTIME_AGGREGATE_ID: string;
declare const RUNTIME_BOUNDARY_EVENT_TYPE: string;
declare const RuntimeBoundaryEventPayloadSchema: { parse(value: unknown): Record<string, unknown> };
declare function appendBoundaryCheck(...values: unknown[]): { decision: string };
declare function replayRuntimeStore(...values: unknown[]): {
  state: { mode: string; processInstanceId: string; revision: number };
};
declare function modeAllowsBoundary(mode: string, boundary: string): boolean;
export class SqliteRuntimeController {
  #store: {
    withExclusiveTransaction<T>(callback: () => T): T;
    getByIdempotencyKey(key: string):
      | { aggregateId: string; idempotencyKey: string; payload: unknown; type: string }
      | undefined;
  } = undefined as never;
  #consumeBoundaryAuthorizationAndDispatch(requested: unknown, dispatch: (value: unknown) => void) {
    const receipt = this.#store.withExclusiveTransaction(() => {
      const checked = appendBoundaryCheck(this.#store, requested);
      if (checked.decision === "allowed") dispatch(checked);
      return checked;
    });
    return receipt;
  }
  #guardBoundaryCompletion(
    requested: {
      actionId: string;
      authorizationId: string;
      boundary: string;
      expiresAt: string;
      requestedAt: string;
      requestedMode: string;
      requestedProcessInstanceId: string;
      requestedRevision: number;
    },
    callback: (value: unknown) => void,
  ) {
    return this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      const existing = this.#store.getByIdempotencyKey(
        \`runtime-boundary-v1:\${requested.authorizationId}\`,
      );
      if (
        existing === undefined ||
        existing.aggregateId !== RUNTIME_AGGREGATE_ID ||
        existing.type !== RUNTIME_BOUNDARY_EVENT_TYPE ||
        existing.idempotencyKey !== \`runtime-boundary-v1:\${requested.authorizationId}\`
      ) throw new Error("missing prior authorization");
      const payload = RuntimeBoundaryEventPayloadSchema.parse(existing.payload);
      if (
        payload.actionId !== requested.actionId ||
        payload.authorizationId !== requested.authorizationId ||
        payload.boundary !== "research_collection" ||
        payload.checkedMode !== requested.requestedMode ||
        payload.checkedProcessInstanceId !== requested.requestedProcessInstanceId ||
        payload.checkedRevision !== requested.requestedRevision ||
        payload.decision !== "allowed" ||
        payload.expiresAt !== requested.expiresAt ||
        payload.reason !== "ALLOWED" ||
        payload.requestedAt !== requested.requestedAt ||
        payload.requestedMode !== requested.requestedMode ||
        payload.requestedProcessInstanceId !== requested.requestedProcessInstanceId ||
        payload.requestedRevision !== requested.requestedRevision
      ) throw new Error("authorization binding mismatch");
      const allowed =
        replay.state.mode === requested.requestedMode &&
        replay.state.processInstanceId === requested.requestedProcessInstanceId &&
        replay.state.revision === requested.requestedRevision &&
        modeAllowsBoundary(replay.state.mode, requested.boundary);
      const completion = { decision: allowed ? "allowed" : "denied" };
      if (completion.decision === "allowed") callback(completion);
      return completion;
    });
  }
}
`,
  );
  write(
    root,
    "packages/x-collector/src/constants.ts",
    `export const X_API_ORIGIN = "https://api.x.com" as const;
export const X_RECENT_SEARCH_PATH = "/2/tweets/search/recent" as const;
export const X_RECENT_SEARCH_ENDPOINT = \`${"${X_API_ORIGIN}"}${"${X_RECENT_SEARCH_PATH}"}\` as const;
export const X_RECENT_SEARCH_METHOD = "GET" as const;
export const X_RECENT_SEARCH_SORT_ORDER = "recency" as const;
export const X_RECENT_SEARCH_MIN_RESULTS = 10 as const;
export const X_RECENT_SEARCH_MAX_RESULTS = 10 as const;
export const X_RECENT_SEARCH_DEFAULT_RESULTS = 10 as const;
`,
  );
  write(
    root,
    "packages/x-collector/src/query.ts",
    `import {
  X_API_ORIGIN,
  X_RECENT_SEARCH_DEFAULT_RESULTS,
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_METHOD,
  X_RECENT_SEARCH_PATH,
  X_RECENT_SEARCH_SORT_ORDER,
} from "./constants.js";
const QUERY_KEYS = new Set(["query"]);
const canonicalizeQuery = (parameters: URLSearchParams) => parameters.toString();
export function prepareRecentSearchRequest(input: { query: string }) {
  void QUERY_KEYS;
  const query = { query: input.query, maxResults: X_RECENT_SEARCH_DEFAULT_RESULTS };
  const url = new URL(X_RECENT_SEARCH_PATH, X_API_ORIGIN);
  url.searchParams.set("query", query.query);
  url.searchParams.set("max_results", String(query.maxResults));
  url.searchParams.set("sort_order", X_RECENT_SEARCH_SORT_ORDER);
  const canonicalRequest = \`${"${X_RECENT_SEARCH_METHOD}"}\\n${"${X_RECENT_SEARCH_ENDPOINT}"}\\n${"${canonicalizeQuery(url.searchParams)}"}\`;
  return {
    method: X_RECENT_SEARCH_METHOD,
    endpoint: X_RECENT_SEARCH_ENDPOINT,
    url: url.href,
    canonicalRequest,
    query,
  };
}
`,
  );
  write(
    root,
    "packages/x-collector/src/collector.ts",
    `import { isNetworkAttemptAuthorization } from "@rsi/operations";
import { isRuntimeBoundaryAuthorization } from "@rsi/runtime";

declare const attemptAuthorization: { consume(): unknown };
declare const runtimeAuthorization: unknown;
declare const runtimeCollectionAuthorization: {
  consumeAndDispatch(dispatch: (receipt: unknown) => void): unknown;
};
declare const prepared: { url: string };
declare function executeNetworkRequest(): Promise<unknown>;
declare function assertRuntimeReceipt(receipt: unknown): void;

void isNetworkAttemptAuthorization(attemptAuthorization);
void isRuntimeBoundaryAuthorization(runtimeAuthorization);
const fetchImplementation = globalThis.fetch.bind(globalThis);
const request = new Request(prepared.url, {
  method: "GET",
  body: null,
  credentials: "omit",
  redirect: "error",
});
async function collect() {
  let responsePromise: Promise<unknown> | undefined;
  try {
    runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {
      assertRuntimeReceipt(receipt);
      attemptAuthorization.consume();
      void fetchImplementation(request);
      responsePromise = executeNetworkRequest();
    });
  } catch (error) {
    if (responsePromise !== undefined) {
      try {
        await responsePromise;
      } catch {
        // The launched transport is still drained before the dispatch failure wins.
      }
    }
    throw error;
  }
  return await responsePromise;
}
void collect;
void request;
`,
  );

  write(
    root,
    "packages/credential-host/src/index.ts",
    `export {
  CredentialHostError,
  DarwinXReadCanaryKeychain,
  isDarwinXReadCanaryKeychain,
  type XReadCanaryCredentialStatus,
  type XReadCanarySecretMaterial,
  type XReadCanaryStorageSecretMaterial,
} from "./x-read-canary-keychain.js";
`,
  );
  write(
    root,
    "packages/credential-host/src/x-read-canary-keychain.ts",
    `import { execFile } from "node:child_process";
const SECURITY = "/usr/bin/security" as const;
const KEYCHAIN_ACCOUNT = "rsi-stage1-x-read-canary" as const;
export class DarwinXReadCanaryKeychain {}
function command(service: string) {
  return {
    file: SECURITY,
    args: ["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", service, "-w"],
  };
}
export function readCredential() {
  const request = command("dev.rsi.canary.x-read");
  execFile(
    request.file,
    request.args,
    { shell: false },
    () => undefined,
  );
}
`,
  );
  write(
    root,
    "packages/read-canary/src/index.ts",
    `export * from "./constants.js";
export * from "./x-read-canary-controller.js";
`,
  );
  write(
    root,
    "packages/read-canary/src/constants.ts",
    `export const X_READ_CANARY_MAXIMUM_REQUESTS = 1 as const;
export const X_READ_CANARY_MAXIMUM_RESULTS = 10 as const;
export const X_READ_CANARY_QUERY =
  '(NFT OR OpenSea OR "Robinhood Chain" OR "Base chain") lang:en -is:retweet' as const;
`,
  );
  write(
    root,
    "packages/read-canary/src/x-read-canary-controller.ts",
    `import { XReadCanaryResultEventPayloadSchema } from "./schemas.js";
declare const RESULT_EVENT_TYPE: string;
declare const AGGREGATE_ID: string;
declare const X_READ_CANARY_OPERATION: string;
declare const X_RECENT_SEARCH_RESERVED_USD_MICRO: number;
declare function createXRecentSearchCollector(options: unknown): unknown;
declare function jsonValue(value: unknown): unknown;
function assertOperationsAttemptBinding(binding: any, prepared: any): void {
  if (
    binding.attemptId !== prepared.attemptId ||
    binding.authorizationExpiresAt !== prepared.expiresAt ||
    binding.budgetId !== prepared.budgetId ||
    binding.createdAt !== prepared.preparedAt ||
    binding.idempotencyKey !== \`x-read-canary:${"${prepared.requestId}"}\` ||
    binding.lane !== "discovery" ||
    binding.operation !== X_READ_CANARY_OPERATION ||
    binding.profile !== "canary" ||
    binding.reservedAtomic !== X_RECENT_SEARCH_RESERVED_USD_MICRO ||
    binding.sessionId !== prepared.requestId ||
    binding.sourcePlane !== "social"
  ) throw new Error("operations attempt binding mismatch");
}
function assertResultBinding(operationsStore: any, prepared: any): void {
  assertOperationsAttemptBinding(
    operationsStore.readNetworkAttemptBinding(prepared.attemptId),
    prepared,
  );
}
function closeAttemptAfterFailure(operationsStore: any, prepared: any): any {
  const binding = operationsStore.readNetworkAttemptBinding(prepared.attemptId);
  assertOperationsAttemptBinding(binding, prepared);
  return binding;
}
function closeAttemptForResult(operationsStore: any, prepared: any, result: any): any {
  const binding = operationsStore.readNetworkAttemptBinding(result.attemptId);
  assertOperationsAttemptBinding(binding, prepared);
  return binding;
}
class FixtureCanaryController {
  #operationsStore: any = undefined as never;
  reserve(command: any, permit: any, runtimeAuthorization: any, budgetId: any, bearerToken: any) {
    try {
      this.#operationsStore.reserveAttempt({
        attemptId: permit.attemptId,
        authorizationExpiresAt: runtimeAuthorization.expiresAt,
        budgetId,
        createdAt: runtimeAuthorization.requestedAt,
        idempotencyKey: \`x-read-canary:${"${command.requestId}"}\`,
        lane: "discovery",
        operation: "x.recent-search.v1",
        permitToken: permit.token,
        reservedAtomic: X_RECENT_SEARCH_RESERVED_USD_MICRO,
        sessionId: command.requestId,
        sourcePlane: "social",
      });
      const networkAuthorization =
        this.#operationsStore.createNetworkAttemptAuthorization(permit);
      return createXRecentSearchCollector({
        attemptAuthorization: networkAuthorization,
        bearerToken,
        runtimeAuthorization,
      });
    } catch (error) {
      throw error;
    }
  }
}
function appendResult(store: any, resultValue: any): any {
  const result = XReadCanaryResultEventPayloadSchema.parse(resultValue);
  const event = store.append({
    aggregateId: AGGREGATE_ID,
    idempotencyKey: result.requestId,
    occurredAt: result.completedAt,
    payload: jsonValue(result),
    type: RESULT_EVENT_TYPE,
  });
  return event.payload;
}
function resultCandidate(
  dependencies: any,
  prepared: any,
  ingestion: any,
  runtimeDenied: boolean,
): any {
  void dependencies;
  void prepared;
  const outcome = runtimeDenied
    ? ("rejected" as const)
    : ingestion.status === "accepted"
      ? ("accepted" as const)
      : ("rejected" as const);
  return {
    outcome,
    failureCode: runtimeDenied ? "RUNTIME_DENIED" : ingestion.failureCode,
    postCount: !runtimeDenied && ingestion.status === "accepted" ? ingestion.postCount : null,
    hasNextPage: !runtimeDenied && ingestion.status === "accepted" ? false : null,
  };
}
function persistRecoveryResult(dependencies: any, prepared: any, ingestion: any): any {
  const candidate = resultCandidate(dependencies, prepared, ingestion, true);
  const persisted = appendResult(dependencies.eventStore, candidate);
  return persisted;
}
function persistLiveResult(
  dependencies: any,
  prepared: any,
  ingestion: any,
  runtimeAuthorization: any,
): any {
  const candidate = resultCandidate(dependencies, prepared, ingestion, false);
  let persisted: any;
  const completion = runtimeAuthorization.guardCompletion(() => {
    persisted = appendResult(dependencies.eventStore, candidate);
  });
  if (completion.decision !== "allowed" || persisted === undefined) {
    return persistRecoveryResult(dependencies, prepared, ingestion);
  }
  return persisted;
}
export const xReadCanaryController = true;
`,
  );
  write(
    root,
    "packages/read-canary/src/schemas.ts",
    `import { z } from "zod";
export const XReadCanaryResultEventPayloadSchema = z.strictObject({
    schemaVersion: z.literal(1),
    requestId: z.string(),
    attemptId: z.string(),
    requestFingerprint: z.string(),
    outcome: z.enum(["accepted", "empty", "rejected"]),
    failureCode: z.string().nullable(),
    acquiredAt: z.string(),
    completedAt: z.string(),
    postCount: z.number().nullable(),
    byteLength: z.number(),
    hasNextPage: z.boolean().nullable(),
    rateLimit: z.unknown(),
    runtime: z.unknown(),
    capture: z.unknown(),
});
`,
  );
  write(root, "apps/operator/src/index.ts", `export * from "./server.js";\n`);
  write(
    root,
    "apps/operator/src/server.ts",
    `export const DASHBOARD_HEADERS = {
  "content-security-policy":
    "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};
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
    () => verifyStage1ReadCanaryBoundary({ root }),
    (error) => error instanceof Stage1VerificationFailure && pattern.test(error.message),
  );
}

function replace(root, path, from, to) {
  const target = join(root, path);
  const before = readFileSync(target, "utf8");
  assert.ok(before.includes(from), `fixture replacement source is present in ${path}`);
  writeFileSync(target, before.replace(from, to));
}

test("accepts only the bounded Stage 1 X read-canary graph", () => {
  withFixture((root) => {
    const report = verifyStage1ReadCanaryBoundary({ root });
    assert.equal(report.status, "pass");
    assert.equal(report.endpoint, "https://api.x.com/2/tweets/search/recent");
    assert.equal(report.maximumRequests, 1);
    assert.equal(report.maximumResults, 10);
    assert.deepEqual(report.packages, REQUIRED_PACKAGES.map((name) => `@rsi/${name}`).sort());
  });
});

test("fails clearly until the dedicated production entry exists", () => {
  withFixture((root) => {
    unlinkSync(join(root, "apps/cli/src/x-canary-operator.ts"));
    expectFailure(root, /production entrypoint apps\/cli\/src\/x-canary-operator\.ts is missing/u);
  });
});

test("rejects policy, executable domain, adapters, wallet, payment, and test transport imports", () => {
  const imports = [
    ["@rsi/policy", /policy authority import @rsi\/policy/u],
    ["@rsi/domain", /executable domain import @rsi\/domain/u],
    ["@rsi/adapters", /execution-adapter import @rsi\/adapters/u],
    ["viem", /financial\/network package viem/u],
    ["@coinbase/x402", /financial\/network package @coinbase\/x402/u],
    ["@rsi/x-collector/testing", /test-only transport import @rsi\/x-collector\/testing/u],
  ];
  for (const [specifier, pattern] of imports) {
    withFixture((root) => {
      appendFileSync(join(root, "apps/cli/src/x-canary-operator.ts"), `import "${specifier}";\n`);
      expectFailure(root, pattern);
    });
  }
});

test("rejects reuse of other CLI production, demo, or offline entrypoints", () => {
  withFixture((root) => {
    write(root, "apps/cli/src/operator.ts", `export const legacy = true;\n`);
    appendFileSync(join(root, "apps/cli/src/x-canary-operator.ts"), `import "./operator.js";\n`);
    expectFailure(root, /unreviewed local source apps\/cli\/src\/operator\.ts/u);
  });
});

test("rejects exposure of the collector's test-only transport injection surface", () => {
  withFixture((root) => {
    write(
      root,
      "packages/x-collector/src/testing.ts",
      `export const createXRecentSearchCollectorForTesting = true;\n`,
    );
    appendFileSync(
      join(root, "packages/x-collector/src/index.ts"),
      `export * from "./testing.js";\n`,
    );
    expectFailure(root, /test-only transport injection source/u);
    expectFailure(root, /closed static re-export of the production collector surface/u);
  });
});

test("resolves workspace exports through every selectable production condition", () => {
  for (const exports of [
    {
      ".": {
        types: "./src/index.ts",
        import: "./src/unsafe-runtime.ts",
      },
    },
    {
      types: "./src/index.ts",
      import: "./src/unsafe-runtime.ts",
    },
  ]) {
    withFixture((root) => {
      write(root, "packages/read-canary/package.json", manifest("@rsi/read-canary", exports));
      write(
        root,
        "packages/read-canary/src/unsafe-runtime.ts",
        `import "@rsi/policy";\nexport * from "./index.js";\n`,
      );
      expectFailure(root, /workspace export has divergent runtime targets/u);
    });
  }

  withFixture((root) => {
    write(
      root,
      "packages/read-canary/package.json",
      manifest("@rsi/read-canary", {
        ".": {
          types: "./src/index.ts",
          node: "./src/index.ts",
          import: "./src/unsafe-runtime.ts",
        },
      }),
    );
    write(
      root,
      "packages/read-canary/src/unsafe-runtime.ts",
      `import "@rsi/policy";\nexport * from "./index.js";\n`,
    );
    expectFailure(root, /workspace export has divergent runtime targets/u);
  });

  withFixture((root) => {
    write(
      root,
      "packages/read-canary/package.json",
      manifest("@rsi/read-canary", {
        types: "./src/index.ts",
        "module-sync": "./src/unsafe-runtime.ts",
        import: "./src/index.ts",
      }),
    );
    write(
      root,
      "packages/read-canary/src/unsafe-runtime.ts",
      `import { request } from "node:https";\nvoid request;\n`,
    );
    expectFailure(root, /workspace export has divergent runtime targets/u);
  });

  withFixture((root) => {
    write(
      root,
      "packages/domain/package.json",
      manifest("@rsi/domain", {
        "./proposals": {
          types: "./src/proposals.ts",
          "module-sync": "./src/unsafe-runtime.ts",
          import: "./src/proposals.ts",
        },
      }),
    );
    write(root, "packages/domain/src/proposals.ts", `export const proposals = true;\n`);
    write(
      root,
      "packages/domain/src/unsafe-runtime.ts",
      `import { request } from "node:https";\nvoid request;\n`,
    );
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator.ts"),
      `import "@rsi/domain/proposals";\n`,
    );
    expectFailure(root, /workspace export has divergent runtime targets/u);
  });

  withFixture((root) => {
    write(
      root,
      "packages/domain/package.json",
      manifest("@rsi/domain", {
        "./*": "./src/runtime/*.ts",
      }),
    );
    write(root, "packages/domain/src/proposals.ts", `export const proposals = true;\n`);
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator.ts"),
      `import "@rsi/domain/proposals";\n`,
    );
    expectFailure(root, /unsupported subpath pattern/u);
  });

  withFixture((root) => {
    write(
      root,
      "packages/read-canary/package.json",
      manifest("@rsi/read-canary", {
        types: "./src/index.ts",
        development: "./src/unsafe-runtime.ts",
        import: "./src/index.ts",
      }),
    );
    write(root, "packages/read-canary/src/unsafe-runtime.ts", `import "@rsi/policy";\n`);
    expectFailure(root, /unreviewed export condition development/u);
  });

  withFixture((root) => {
    write(
      root,
      "packages/read-canary/package.json",
      manifest("@rsi/read-canary", { ".": [null, "./src/index.ts"] }),
    );
    expectFailure(root, /unsupported export fallback array/u);
  });

  withFixture((root) => {
    write(
      root,
      "packages/read-canary/package.json",
      manifest("@rsi/read-canary", "./src/index.cjs"),
    );
    write(root, "packages/read-canary/src/index.cjs", `module.exports = {};\n`);
    expectFailure(root, /CommonJS runtime source packages\/read-canary\/src\/index\.cjs/u);
  });
});

test("rejects alternate HTTP clients, sockets, network globals, and extra fetch sites", () => {
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `import { request } from "node:https";\nvoid request;\n`,
    );
    expectFailure(root, /unapproved network platform module node:https/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const socket = new WebSocket("wss:\/\/example.invalid");\nvoid socket;\n`,
    );
    expectFailure(root, /unapproved network global: WebSocket/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const extraFetch = globalThis.fetch.bind(globalThis);\nvoid extraFetch;\n`,
    );
    expectFailure(root, /expected exactly one audited global fetch site/u);
  });
  withFixture((root) => {
    appendFileSync(join(root, "packages/read-canary/src/index.ts"), `void fetch("/hidden");\n`);
    expectFailure(root, /unaudited bare fetch call/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const hiddenFetch = Reflect.get(globalThis, "fetch");\nvoid hiddenFetch;\n`,
    );
    expectFailure(root, /unapproved network global: Reflect\.get\(globalThis, fetch\)/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const hiddenFetch = globalThis["fetch"];\nvoid hiddenFetch;\n`,
    );
    expectFailure(root, /unapproved network global: globalThis\[fetch\]/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const hiddenSocket = globalThis["WebSocket"];\nvoid hiddenSocket;\n`,
    );
    expectFailure(root, /unapproved network global: (?:WebSocket|globalThis\[WebSocket\])/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "apps/operator/src/server.ts"),
      `export const remote = "https:\/\/example.invalid/upload";\n`,
    );
    expectFailure(root, /declares unreviewed network origin https:\/\/example\.invalid\/upload/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/operator/src/server.ts",
      "connect-src 'self'",
      "connect-src https://example.invalid",
    );
    expectFailure(root, /must keep dashboard connections, scripts, styles, and forms same-origin/u);
  });
});

test("rejects method, endpoint-shape, result-limit, field, and pagination drift", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/constants.ts",
      "X_RECENT_SEARCH_MAX_RESULTS = 10",
      "X_RECENT_SEARCH_MAX_RESULTS = 100",
    );
    expectFailure(root, /does not enforce maximum results of 10/u);
  });
  withFixture((root) => {
    replace(root, "packages/x-collector/src/collector.ts", 'method: "GET"', 'method: "POST"');
    expectFailure(root, /lacks GET request method/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/x-collector/src/query.ts"),
      `new URL("https:\/\/api.x.com").searchParams.set("next_token", "hidden");\n`,
    );
    expectFailure(root, /exactly query, max_results, and sort_order/u);
    expectFailure(root, /forbidden pagination\/field parameter next_token/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/x-collector/src/query.ts"),
      `new URL("https:\/\/api.x.com").searchParams.set("expansions", "author_id");\n`,
    );
    expectFailure(root, /forbidden pagination\/field parameter expansions/u);
  });
});

test("requires genuine runtime and operations validation and one-shot consumption order", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/collector.ts",
      "runtimeCollectionAuthorization.consumeAndDispatch((receipt) => {",
      "runtimeCollectionAuthorization.consume((receipt) => {",
    );
    expectFailure(root, /lacks write-locked runtime dispatch consumption/u);
    expectFailure(root, /unprotected runtime consume path/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/collector.ts",
      "responsePromise = executeNetworkRequest();",
      "void runtimeCollectionAuthorization;",
    );
    expectFailure(root, /invoke transport inside consumeAndDispatch/u);
    expectFailure(root, /does not keep receipt validation, attempt consumption, and transport/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/collector.ts",
      "void isNetworkAttemptAuthorization(attemptAuthorization);",
      "void attemptAuthorization;",
    );
    expectFailure(root, /lacks operations authorization authenticity check/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/collector.ts",
      "void fetchImplementation(request);",
      "void fetchImplementation(request);\nvoid fetchImplementation(request);",
    );
    expectFailure(root, /exactly one protected runtime dispatch, attempt consume, and transport/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/sqlite-runtime-controller.ts",
      'if (checked.decision === "allowed") dispatch(checked);',
      "void checked;",
    );
    expectFailure(
      root,
      /hold the SQLite write lock from revalidation through synchronous dispatch/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/boundary-authorization.ts",
      "CONSUMED_AUTHORIZATIONS.add(authorization);",
      "void authorization;",
    );
    expectFailure(root, /dispatch and completion guards only for network collection authority/u);
  });
});

test("pins durable operations-attempt reservation and authenticated readback", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      'binding.sourcePlane !== "social"',
      "false",
    );
    expectFailure(root, /pin every durable operations-attempt binding field/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      `operationsStore.readNetworkAttemptBinding(prepared.attemptId),\n    prepared,`,
      `operationsStore.readNetworkAttemptBinding(prepared.requestId),\n    prepared,`,
    );
    expectFailure(root, /authenticate exact operations-attempt readback/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      '        sourcePlane: "social",',
      '        sourcePlane: "canonical_chain",',
    );
    expectFailure(root, /reserve and hand off one exact X canary operations attempt/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/operations/src/sqlite-operations-store.ts",
      "      this.assertAttemptRow(attempt);",
      "      void attempt;",
    );
    expectFailure(root, /MAC-authenticated durable attempt binding facts/u);
  });
});

test("rejects completion-guard and launched-request cleanup bypasses", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/boundary-authorization.ts",
      "    properties.guardCompletion = { value: guardCompletion };\n  } else {\n    properties.consume = { value: consume };",
      "  } else {\n    properties.consume = { value: consume };\n    properties.guardCompletion = { value: guardCompletion };",
    );
    expectFailure(root, /dispatch and completion guards only for network collection authority/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/boundary-authorization.ts",
      "COMPLETED_AUTHORIZATIONS.add(authorization);",
      "void authorization;",
    );
    expectFailure(
      root,
      /completion guarding authentic, terminal, synchronous, and proxy-resistant/u,
    );
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/boundary-authorization.ts",
      'if (!AUTHENTIC_AUTHORIZATIONS.has(authorization)) throw new Error("not authentic");',
      "void authorization;",
    );
    expectFailure(
      root,
      /completion guarding authentic, terminal, synchronous, and proxy-resistant/u,
    );
  });
  for (const validation of [
    "      utilTypes.isProxy(callback) ||\n",
    "      utilTypes.isAsyncFunction(callback) ||\n",
  ]) {
    withFixture((root) => {
      replace(root, "packages/runtime/src/boundary-authorization.ts", validation, "");
      expectFailure(
        root,
        /completion guarding authentic, terminal, synchronous, and proxy-resistant/u,
      );
    });
  }
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/sqlite-runtime-controller.ts",
      "payload.actionId !== requested.actionId ||",
      "false ||",
    );
    expectFailure(root, /bind completion to the exact durable allowed collection authorization/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/sqlite-runtime-controller.ts",
      'payload.decision !== "allowed" ||',
      "false ||",
    );
    expectFailure(root, /bind completion to the exact durable allowed collection authorization/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/sqlite-runtime-controller.ts",
      "replay.state.revision === requested.requestedRevision &&",
      "true &&",
    );
    expectFailure(root, /allowed-current-state completion callback/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/runtime/src/sqlite-runtime-controller.ts",
      'if (completion.decision === "allowed") callback(completion);',
      "callback(completion);",
    );
    expectFailure(root, /allowed-current-state completion callback/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/collector.ts",
      `    if (responsePromise !== undefined) {
      try {
        await responsePromise;
      } catch {
        // The launched transport is still drained before the dispatch failure wins.
      }
    }
`,
      "",
    );
    expectFailure(root, /await the launched response before reporting a post-dispatch/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/x-collector/src/collector.ts",
      "  } catch (error) {\n    if (responsePromise !== undefined) {",
      "  } catch (error) {\n    if (error) throw error;\n    if (responsePromise !== undefined) {",
    );
    expectFailure(root, /await the launched response before reporting a post-dispatch/u);
  });
});

test("rejects unguarded or content-bearing read-canary result checkpoints", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      "resultCandidate(dependencies, prepared, ingestion, true)",
      "resultCandidate(dependencies, prepared, ingestion, false)",
    );
    expectFailure(root, /forbid unguarded accepted-result appends and force recovery denial/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      `  const completion = runtimeAuthorization.guardCompletion(() => {
    persisted = appendResult(dependencies.eventStore, candidate);
  });`,
      `  const completion = { decision: "allowed" };
  persisted = appendResult(dependencies.eventStore, candidate);`,
    );
    expectFailure(root, /append the live result inside exactly one allowed completion guard/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      "runtimeAuthorization.guardCompletion(() => {",
      "runtimeAuthorization.guardCompletion(async () => {",
    );
    expectFailure(root, /append the live result inside exactly one allowed completion guard/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      "    payload: jsonValue(result),",
      "    payload: { ...jsonValue(result), content: result.content },",
    );
    expectFailure(root, /append only the closed content-free result payload/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/schemas.ts",
      "    capture: z.unknown(),",
      "    capture: z.unknown(),\n    content: z.string(),",
    );
    expectFailure(root, /keep the result checkpoint strict and content-free/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      'failureCode: runtimeDenied ? "RUNTIME_DENIED" : ingestion.failureCode',
      "failureCode: ingestion.failureCode",
    );
    expectFailure(root, /force denied recovery results to RUNTIME_DENIED/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/read-canary/src/x-read-canary-controller.ts",
      '  if (completion.decision !== "allowed" || persisted === undefined) {',
      '  persisted = appendResult(dependencies.eventStore, candidate);\n  if (completion.decision !== "allowed" || persisted === undefined) {',
    );
    expectFailure(root, /forbid unguarded accepted-result appends/u);
  });
});

test("keeps credential injection behind the private host core", () => {
  withFixture((root) => {
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator.ts"),
      `import "./x-canary-operator-host-core.js";\n`,
    );
    expectFailure(root, /imports the credential-injecting host core outside/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator.ts"),
      `import "./x-canary-operator-host.testing.js";\n`,
    );
    expectFailure(root, /test-only wrapper source/u);
  });
  withFixture((root) => {
    write(root, "packages/read-canary/src/hidden.testing.ts", `export const hidden = true;\n`);
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `export * from "./hidden.testing.js";\n`,
    );
    expectFailure(
      root,
      /test-only wrapper source packages\/read-canary\/src\/hidden\.testing\.ts/u,
    );
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator.ts"),
      `import "@rsi/credential-host/testing";\n`,
    );
    expectFailure(root, /test-only credential injection import/u);
  });
  withFixture((root) => {
    write(root, "packages/credential-host/src/testing.ts", `export const inject = true;\n`);
    appendFileSync(
      join(root, "packages/credential-host/src/index.ts"),
      `export * from "./testing.js";\n`,
    );
    expectFailure(root, /test-only credential injection source/u);
  });
  withFixture((root) => {
    write(
      root,
      "packages/credential-host/src/injected.ts",
      `import { createDarwinXReadCanaryKeychainForTesting } from "./x-read-canary-keychain.js";
export const injectedHost = createDarwinXReadCanaryKeychainForTesting({
  executor: async () => ({ exitCode: 0, stdout: new Uint8Array(), stderr: new Uint8Array(), timedOut: false }),
  platform: "darwin",
});
`,
    );
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator-host.ts"),
      `import "../../../packages/credential-host/src/injected.js";\n`,
    );
    expectFailure(root, /cross-package relative import|test-only credential injection/u);
    expectFailure(root, /imports the credential implementation outside/u);
  });
  withFixture((root) => {
    write(
      root,
      "packages/x-collector/src/injected.ts",
      `import { createXRecentSearchCollectorForTesting } from "./collector.js";
export const injectedCollectorFactory = createXRecentSearchCollectorForTesting;
`,
    );
    appendFileSync(
      join(root, "packages/x-collector/src/index.ts"),
      `export { injectedCollectorFactory } from "./injected.js";\n`,
    );
    expectFailure(root, /closed static re-export|reviewed production surface/u);
    expectFailure(
      root,
      /test-only collector injection|imports the collector implementation outside/u,
    );
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/credential-host/src/index.ts"),
      `export { createDarwinXReadCanaryKeychainForTesting } from "./x-read-canary-keychain.js";\n`,
    );
    expectFailure(root, /may export only the reviewed production surface/u);
    expectFailure(root, /closed static re-export/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator-host.ts"),
      `export { startXCanaryOperatorWithHost };\n`,
    );
    expectFailure(root, /may export only the production starter and three public types/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host.ts",
      "export async function startXCanaryOperator(",
      "async function startXCanaryOperator(",
    );
    appendFileSync(
      join(root, "apps/cli/src/x-canary-operator-host.ts"),
      `export { startXCanaryOperatorWithHost as startXCanaryOperator };\n`,
    );
    expectFailure(root, /lacks one-argument production starter/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "  readonly databasePath: string;",
      "  readonly databasePath: string;\n  readonly credentialHost?: DarwinXReadCanaryKeychain;",
    );
    expectFailure(root, /keep credential and transport injection out of public options/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "    (EFFECTIVE_USER_ID === null || parentEntry.uid !== EFFECTIVE_USER_ID)\n",
      "    false\n",
    );
    expectFailure(root, /owner-owned mode-0700 data directory/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "bearerToken: secrets.bearerToken",
      "bearerToken: process.env.X_BEARER_TOKEN",
    );
    expectFailure(root, /ambient credential source: process\.env/u);
    expectFailure(root, /exact Keychain secrets/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "stateKey: secrets.operationsStateKey",
      'stateKey: process["env"].OPERATIONS_STATE_KEY',
    );
    expectFailure(root, /ambient credential source: process\.env/u);
    expectFailure(root, /exact Keychain secrets/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "bearerToken: secrets.bearerToken",
      "bearerToken: ambientProcess.env.X_BEARER_TOKEN",
    );
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "export async function startXCanaryOperatorWithHost",
      "const ambientProcess = process;\nexport async function startXCanaryOperatorWithHost",
    );
    expectFailure(root, /unapproved process capability: <aliased-or-computed>/u);
    expectFailure(root, /exact Keychain secrets/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "bearerToken: secrets.bearerToken",
      "bearerToken: ambientProcess.env.X_BEARER_TOKEN",
    );
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      "export async function startXCanaryOperatorWithHost",
      'const ambientProcess = globalThis["process"];\nexport async function startXCanaryOperatorWithHost',
    );
    expectFailure(root, /unapproved process capability: <aliased-or-computed>/u);
    expectFailure(root, /exact Keychain secrets/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      `  const runtime = SqliteRuntimeController.open({\n    openedAt: "2026-01-01T00:00:00.000Z",\n    path: options.databasePath,\n    processInstanceId: "00000000-0000-4000-8000-000000000000",\n  });`,
      `  const runtime = SqliteRuntimeController.open({\n    openedAt: "2026-01-01T00:00:00.000Z",\n    path: options.databasePath,\n    processInstanceId: "00000000-0000-4000-8000-000000000000",\n  }, { clock: () => "2026-01-01T00:00:00.000Z" });`,
    );
    expectFailure(root, /runtime and operations clocks production-owned/u);
  });
  withFixture((root) => {
    replace(
      root,
      "apps/cli/src/x-canary-operator-host-core.ts",
      `        stateKey: secrets.operationsStateKey,\n      });`,
      `        stateKey: secrets.operationsStateKey,\n      }, { monotonicClock: () => 0 });`,
    );
    expectFailure(root, /runtime and operations clocks production-owned/u);
  });
});

test("allows only fixed, shell-free Keychain reads in the credential host", () => {
  withFixture((root) => {
    replace(
      root,
      "packages/credential-host/src/x-read-canary-keychain.ts",
      "shell: false",
      "shell: true",
    );
    expectFailure(root, /lacks shell disabled/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/credential-host/src/x-read-canary-keychain.ts",
      '"find-generic-password"',
      '"add-generic-password"',
    );
    expectFailure(root, /mutating Keychain command add-generic-password/u);
  });
  withFixture((root) => {
    replace(
      root,
      "packages/credential-host/src/x-read-canary-keychain.ts",
      'import { execFile } from "node:child_process";',
      'import { execFile, spawn } from "node:child_process";',
    );
    expectFailure(root, /node:child_process imports must be exactly execFile/u);
    expectFailure(root, /unapproved child-process API: spawn/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `import { execFile } from "node:child_process";\nvoid execFile;\n`,
    );
    expectFailure(root, /node:child_process is allowed only in packages\/credential-host/u);
  });
});

test("pins filesystem and crypto capabilities to reviewed per-file imports", () => {
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/ingestion/src/index.ts"),
      `import { writeFile } from "node:fs/promises";\nvoid writeFile;\n`,
    );
    expectFailure(root, /node:fs\/promises is not approved in packages\/ingestion/u);
  });
  for (const capability of ["generateKeyPairSync", "sign"]) {
    withFixture((root) => {
      write(
        root,
        "packages/x-collector/src/hash.ts",
        `import { createHash, ${capability} } from "node:crypto";\nvoid createHash;\nvoid ${capability};\n`,
      );
      appendFileSync(
        join(root, "packages/x-collector/src/index.ts"),
        `export * from "./hash.js";\n`,
      );
      expectFailure(root, /unapproved asymmetric\/signing crypto capability/u);
      expectFailure(root, /node:crypto imports must be exactly createHash/u);
    });
  }
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `void globalThis.crypto.subtle.sign;\n`,
    );
    expectFailure(root, /unapproved asymmetric\/signing crypto capability: sign, subtle/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `void globalThis.crypto["subtle"]["importKey"];\n`,
    );
    expectFailure(root, /unapproved asymmetric\/signing crypto capability: importKey, subtle/u);
  });
});

test("rejects dynamic code and alternate module loaders", () => {
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const load = Function("return import('@rsi/policy')");\nvoid load;\n`,
    );
    expectFailure(root, /references dynamic code: Function/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `globalThis["eval"]("void 0");\n`,
    );
    expectFailure(root, /references dynamic code: eval/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `void ({}).constructor.constructor("return process['getBuiltin' + 'Module']('node:https')")();\n`,
    );
    expectFailure(root, /references dynamic code: constructor/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `void import("./constants.js");\n`,
    );
    expectFailure(root, /references dynamic code: import\(\)/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const name = "@rsi/policy";\nvoid import(name);\n`,
    );
    expectFailure(root, /non-literal import\/require/u);
  });
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/read-canary/src/index.ts"),
      `const native = process.binding("tcp_wrap");\nvoid native;\n`,
    );
    expectFailure(root, /alternate module loader: process\.binding/u);
  });
  for (const source of [
    `process.dlopen({}, "/tmp/unreviewed.dylib");\n`,
    `process._linkedBinding("unreviewed");\n`,
    `process["binding"]("tcp_wrap");\n`,
    `module["require"]("node:https");\n`,
    `module.constructor["_load"]("node:https");\n`,
    `process.mainModule.require("node:https");\n`,
  ]) {
    withFixture((root) => {
      appendFileSync(join(root, "packages/read-canary/src/index.ts"), source);
      expectFailure(root, /alternate module loader/u);
    });
  }
  withFixture((root) => {
    appendFileSync(
      join(root, "packages/store/src/index.ts"),
      `import { DatabaseSync } from "node:sqlite";
const extensionDatabase = new DatabaseSync(":memory:", { allowExtension: true });
extensionDatabase.enableLoadExtension(true);
extensionDatabase.loadExtension("/tmp/unreviewed-extension.dylib");
`,
    );
    expectFailure(
      root,
      /alternate module loader: allowExtension, enableLoadExtension, loadExtension/u,
    );
  });
});
