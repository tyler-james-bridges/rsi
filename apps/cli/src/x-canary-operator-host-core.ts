import { randomUUID } from "node:crypto";
import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import {
  CredentialHostError,
  isDarwinXReadCanaryKeychain,
  type DarwinXReadCanaryKeychain,
  type XReadCanaryCredentialStatus,
} from "@rsi/credential-host";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";
import { recoverCaptureStorage } from "@rsi/ingestion";
import {
  createRuntimeOperatorControls,
  startOperatorServer,
  type OperatorEventPage,
  type OperatorEventQuery,
  type OperatorReadCanaryProvider,
  type OperatorResearchProvider,
  type OperatorRuntimeProvider,
  type OperatorSnapshotProvider,
  type RuntimeOperatorControlCommand,
  type RunningOperatorServer,
} from "@rsi/operator";
import { SqliteOperationsStore } from "@rsi/operations";
import {
  XReadCanaryConflictError,
  XReadCanaryController,
  readXReadCanaryProjection,
  recoverXReadCanary,
  type XReadCanaryProjectionV1,
  type XReadCanaryReceiptV1,
  type XReadCanaryRunCommand,
} from "@rsi/read-canary";
import { SqliteResearchLedger } from "@rsi/research-ledger";
import {
  RuntimeConflictError,
  SqliteRuntimeController,
  type RuntimeAuditEvent,
} from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { SnapshotVault } from "@rsi/vault";

import {
  IncompleteCanaryCleanupError,
  acquireCanaryResource,
  acquireCanaryResourceAsync,
  closeCanaryResourceSet,
  rethrowCanaryStartupFailureAfterCleanup,
} from "./canary-operator-startup-cleanup.js";
import {
  assertCanaryProfileLockForDatabasePath,
  type CanaryProfileLockLease,
} from "./profile-service-lock-core.js";

interface DatabaseIdentity {
  readonly path: string;
  readonly device?: bigint;
  readonly inode?: bigint;
}

const PRIVATE_DIRECTORY_MODE = 0o700n;
const EFFECTIVE_USER_ID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : null;

export interface XCanaryOperatorPaths {
  readonly captureRegistry: string;
  readonly eventStore: string;
  readonly operations: string;
  readonly research: string;
  readonly runtime: string;
  readonly vault: string;
}

export interface StartXCanaryOperatorOptions {
  readonly databasePath: string;
  readonly port: number;
  readonly researchDatabasePath: string;
}

export interface RunningXCanaryOperator {
  readonly origin: string;
  readonly paths: Readonly<XCanaryOperatorPaths>;
  readonly runtime: SqliteRuntimeController;
  close(): Promise<void>;
}

function isMissingPath(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

async function resolveDatabaseIdentity(path: string): Promise<DatabaseIdentity> {
  if (path === ":memory:") {
    throw new TypeError("The Stage 1 canary requires durable, separate storage files");
  }
  await mkdir(dirname(path), { mode: Number(PRIVATE_DIRECTORY_MODE), recursive: true });
  const parent = await realpath(dirname(path));
  const parentEntry = await lstat(parent, { bigint: true });
  if (
    !parentEntry.isDirectory() ||
    parentEntry.isSymbolicLink() ||
    (parentEntry.mode & 0o777n) !== PRIVATE_DIRECTORY_MODE ||
    EFFECTIVE_USER_ID === null ||
    parentEntry.uid !== EFFECTIVE_USER_ID
  ) {
    throw new TypeError("Stage 1 data directories must be owner-only (mode 0700)");
  }
  const canonicalPath = resolve(parent, basename(path));
  try {
    const entry = await lstat(canonicalPath, { bigint: true });
    if (
      entry.isSymbolicLink() ||
      !entry.isFile() ||
      entry.nlink !== 1n ||
      EFFECTIVE_USER_ID === null ||
      entry.uid !== EFFECTIVE_USER_ID
    ) {
      throw new TypeError("Stage 1 SQLite paths must be regular files");
    }
    const identity = await stat(canonicalPath, { bigint: true });
    if (
      !identity.isFile() ||
      identity.nlink !== 1n ||
      identity.uid !== EFFECTIVE_USER_ID ||
      identity.dev !== entry.dev ||
      identity.ino !== entry.ino
    ) {
      throw new TypeError("Stage 1 SQLite paths must be regular files");
    }
    return { path: canonicalPath, device: identity.dev, inode: identity.ino };
  } catch (error) {
    if (isMissingPath(error)) return { path: canonicalPath };
    throw error;
  }
}

function assertSeparateDatabases(identities: readonly DatabaseIdentity[]): void {
  for (let left = 0; left < identities.length; left += 1) {
    for (let right = left + 1; right < identities.length; right += 1) {
      const first = identities[left]!;
      const second = identities[right]!;
      if (
        first.path === second.path ||
        (first.device !== undefined &&
          second.device !== undefined &&
          first.device === second.device &&
          first.inode === second.inode)
      ) {
        throw new TypeError("Every Stage 1 SQLite role requires a separate file");
      }
    }
  }
}

function cursorSequence(cursor: string | undefined): number | undefined {
  if (cursor === undefined) return undefined;
  const sequence = Number(cursor.slice("seq:".length));
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new TypeError("invalid event cursor");
  return sequence;
}

function projectRuntimeAuditEvent(event: RuntimeAuditEvent): unknown {
  return Object.freeze({
    sequence: event.sequence,
    eventId: event.eventId,
    type: event.type,
    occurredAt: event.occurredAt,
    previousHash: event.previousHash,
    eventHash: event.eventHash,
    payload: event.payload,
  });
}

class RuntimeOperatorSnapshotProvider
  implements OperatorSnapshotProvider, OperatorResearchProvider
{
  constructor(
    private readonly runtime: SqliteRuntimeController,
    private readonly research: SqliteResearchLedger,
  ) {}

  getSummary(): unknown {
    const snapshot = this.runtime.getSnapshot();
    return {
      schemaVersion: 1,
      status: "ok",
      runtimeMode: snapshot.mode,
      runtimeRevision: snapshot.revision,
      auditHead: snapshot.auditHead,
      financialAuthority: false,
    };
  }

  listEvents(query: Readonly<OperatorEventQuery>): OperatorEventPage {
    if (query.decisionId !== undefined) return { items: [], nextCursor: null };
    const beforeSequence = cursorSequence(query.cursor);
    let events = [...this.runtime.listAudit()].reverse();
    if (beforeSequence !== undefined) {
      events = events.filter((event) => event.sequence < beforeSequence);
    }
    if (query.type !== undefined) events = events.filter((event) => event.type === query.type);
    if (query.since !== undefined) {
      events = events.filter((event) => event.occurredAt >= query.since!);
    }
    if (query.until !== undefined) {
      events = events.filter((event) => event.occurredAt <= query.until!);
    }
    const items = events.slice(0, query.limit);
    return {
      items: items.map(projectRuntimeAuditEvent),
      nextCursor:
        events.length > query.limit && items.length > 0
          ? `seq:${items[items.length - 1]!.sequence}`
          : null,
    };
  }

  getDecision(): null {
    return null;
  }

  getResearchProjection(): unknown {
    return this.research.getProjection();
  }
}

function publicCredentialStatus(
  status: XReadCanaryCredentialStatus,
): XReadCanaryProjectionV1["credentialStatus"] {
  return status === "configured" ? "configured" : status === "missing" ? "missing" : "unknown";
}

function createHostClosingRuntimeControls(
  controller: SqliteRuntimeController,
  isHostClosing: () => boolean,
): OperatorRuntimeProvider {
  const controls = createRuntimeOperatorControls({ controller });
  const assertHostOpen = (): void => {
    if (isHostClosing()) {
      throw new RuntimeConflictError(
        "STALE_STATE",
        "Runtime controls are unavailable while the canary host is closing",
      );
    }
  };
  return Object.freeze({
    supportedActions: controls.supportedActions,
    executeRuntimeControl(command: RuntimeOperatorControlCommand): unknown {
      assertHostOpen();
      return controls.executeRuntimeControl(command);
    },
    getRuntimeSnapshot(): unknown {
      assertHostOpen();
      return controls.getRuntimeSnapshot();
    },
  });
}

class KeychainReadCanaryProvider implements OperatorReadCanaryProvider {
  #activeController: XReadCanaryController | null = null;
  #activeRun: Promise<Readonly<XReadCanaryReceiptV1>> | null = null;
  #activeRecovery: Promise<void> | null = null;
  #activeStatus: Promise<Readonly<XReadCanaryProjectionV1>> | null = null;
  #admissionAbortFailure: unknown;
  #abortEpoch = 0;
  #closing = false;
  #closingBegan = false;
  #incompleteCleanupError: IncompleteCanaryCleanupError | null = null;
  #ownedCanaryClaim = false;
  #startupRecoveryReconciled = false;

  constructor(
    private readonly credentialHost: DarwinXReadCanaryKeychain,
    private readonly claimHost: DarwinOneShotClaimHost,
    private readonly eventStore: SqliteEventStore,
    private readonly paths: Readonly<XCanaryOperatorPaths>,
    private readonly runtime: SqliteRuntimeController,
  ) {
    if (!isDarwinXReadCanaryKeychain(credentialHost)) {
      throw new TypeError("An authentic macOS Keychain boundary is required");
    }
    if (!isDarwinOneShotClaimHost(claimHost)) {
      throw new TypeError("An authentic X one-shot claim boundary is required");
    }
  }

  getReadCanaryProjection(): Promise<Readonly<XReadCanaryProjectionV1>> {
    if (this.#closing) {
      throw new XReadCanaryConflictError("The X read canary provider is closing");
    }
    if (this.#activeStatus !== null) return this.#activeStatus;
    const status = this.#readCanaryProjection();
    this.#activeStatus = status;
    const clear = (): void => {
      if (this.#activeStatus === status) this.#activeStatus = null;
    };
    void status.then(clear, (error: unknown) => {
      this.#latchIncompleteCleanupError(error);
      clear();
    });
    return status;
  }

  async #readCanaryProjection(): Promise<Readonly<XReadCanaryProjectionV1>> {
    if (this.#activeController !== null) return this.#activeController.getProjection();
    await this.#recoverInterruptedIfPossible();
    return readXReadCanaryProjection(
      this.eventStore,
      publicCredentialStatus(await this.credentialHost.status()),
    );
  }

  executeReadCanary(
    command: Readonly<XReadCanaryRunCommand>,
  ): Promise<Readonly<XReadCanaryReceiptV1>> {
    if (this.#closing) {
      throw new XReadCanaryConflictError("The X read canary provider is closing");
    }
    if (this.#activeRun !== null) {
      throw new XReadCanaryConflictError("An X read canary is already running");
    }
    const runtime = this.runtime.getSnapshot();
    if (runtime.mode !== "RESEARCH" || runtime.revision !== command.expectedRuntimeRevision) {
      throw new XReadCanaryConflictError(
        "Runtime state changed before the X canary entered its provider boundary",
      );
    }
    const existing = this.#existingReceipt(command);
    if (existing !== null) return Promise.resolve(existing);
    if (this.#ownedCanaryClaim) {
      throw new XReadCanaryConflictError("The one-shot X read canary was already claimed");
    }
    const run = this.#executeAfterRecovery(command, this.#abortEpoch);
    this.#activeRun = run;
    const clear = (): void => {
      if (this.#activeRun === run) this.#activeRun = null;
    };
    void run.then(clear, (error: unknown) => {
      this.#latchIncompleteCleanupError(error);
      clear();
    });
    return run;
  }

  abortActive(): void {
    this.#abortEpoch += 1;
    this.#activeController?.abortActive();
  }

  beginClosing(): void {
    if (this.#closingBegan) return;
    this.#closingBegan = true;
    this.#closing = true;
    try {
      this.abortActive();
    } catch (error) {
      this.#latchIncompleteCleanupError(error);
      this.#admissionAbortFailure ??= error;
    }
  }

  async close(): Promise<void> {
    this.beginClosing();
    const activeRun = this.#activeRun;
    const activeRecovery = this.#activeRecovery;
    const activeStatus = this.#activeStatus;
    await Promise.all([
      this.#awaitActiveWork(activeRun),
      this.#awaitActiveWork(activeRecovery),
      this.#awaitActiveWork(activeStatus),
    ]);
    if (this.#incompleteCleanupError !== null) throw this.#incompleteCleanupError;
    if (this.#admissionAbortFailure !== undefined) {
      const abortFailure = this.#admissionAbortFailure;
      await closeCanaryResourceSet([
        () => {
          throw abortFailure;
        },
      ]);
    }
  }

  async #awaitActiveWork(work: Promise<unknown> | null): Promise<void> {
    try {
      await work;
    } catch (error) {
      this.#latchIncompleteCleanupError(error);
    }
  }

  #latchIncompleteCleanupError(error: unknown): void {
    if (error instanceof IncompleteCanaryCleanupError) {
      this.#closing = true;
      this.#incompleteCleanupError ??= error;
    }
  }

  async initialize(): Promise<void> {
    await this.#recoverInterruptedIfPossible();
    const projection = readXReadCanaryProjection(this.eventStore, "unknown");
    const claimStatus = await this.claimHost.status();
    if (projection.lastReceipt === null && claimStatus === "present") {
      throw new XReadCanaryConflictError("The permanent X canary marker has no durable receipt");
    }
    if (projection.lastReceipt !== null && claimStatus !== "present") {
      throw new XReadCanaryConflictError(
        "The completed X canary requires its permanent one-shot marker",
      );
    }
  }

  async #executeAfterRecovery(
    command: Readonly<XReadCanaryRunCommand>,
    abortEpoch: number,
  ): Promise<Readonly<XReadCanaryReceiptV1>> {
    await this.#recoverInterruptedIfPossible(false);
    if (this.#closing || this.#abortEpoch !== abortEpoch) {
      throw new XReadCanaryConflictError("The X read canary provider is closing");
    }
    const existing = this.#existingReceipt(command);
    if (existing !== null) return existing;
    return this.#runWithKeychain(command, abortEpoch);
  }

  #existingReceipt(
    command: Readonly<XReadCanaryRunCommand>,
  ): Readonly<XReadCanaryReceiptV1> | null {
    const existing = readXReadCanaryProjection(this.eventStore, "unknown").lastReceipt;
    if (existing === null) return null;
    if (existing.requestId === command.requestId) return existing;
    throw new XReadCanaryConflictError("The one-shot X read canary is already complete");
  }

  async #runWithKeychain(
    command: Readonly<XReadCanaryRunCommand>,
    abortEpoch: number,
  ): Promise<Readonly<XReadCanaryReceiptV1>> {
    const runtimeBeforeClaim = this.runtime.getSnapshot();
    if (
      runtimeBeforeClaim.mode !== "RESEARCH" ||
      runtimeBeforeClaim.revision !== command.expectedRuntimeRevision
    ) {
      throw new XReadCanaryConflictError("Runtime state changed before the permanent X claim");
    }
    await this.claimHost.claim();
    this.#ownedCanaryClaim = true;
    const runtimeAfterClaim = this.runtime.getSnapshot();
    if (
      this.#closing ||
      this.#abortEpoch !== abortEpoch ||
      runtimeAfterClaim.mode !== "RESEARCH" ||
      runtimeAfterClaim.revision !== command.expectedRuntimeRevision
    ) {
      throw new XReadCanaryConflictError("The X read canary run was stopped");
    }
    return this.credentialHost.withSecrets(async (secrets) => {
      if (this.#closing || this.#abortEpoch !== abortEpoch) {
        throw new XReadCanaryConflictError("The X read canary provider is closing");
      }
      let operationsStoreToClose: SqliteOperationsStore | undefined;
      let captureRegistryToClose: SqliteCaptureRegistry | undefined;
      let vaultToClose: SnapshotVault | undefined;
      let controllerToClose: XReadCanaryController | undefined;
      try {
        const operationsStore = acquireCanaryResource(
          () =>
            new SqliteOperationsStore({
              path: this.paths.operations,
              stateKey: secrets.operationsStateKey,
            }),
        );
        operationsStoreToClose = operationsStore;
        const captureRegistry = acquireCanaryResource(() =>
          SqliteCaptureRegistry.open({
            expectedProfile: "canary",
            path: this.paths.captureRegistry,
            registryKey: secrets.captureRegistryKey,
          }),
        );
        captureRegistryToClose = captureRegistry;
        const vault = await acquireCanaryResourceAsync(() =>
          SnapshotVault.open({
            directory: this.paths.vault,
            maxCaptureBytes: 1_048_576,
            wrappingKey: secrets.vaultWrappingKey,
          }),
        );
        vaultToClose = vault;
        await recoverCaptureStorage({
          captureRegistry,
          recoveredAt: new Date().toISOString(),
          vault,
        });
        const recovered = await recoverXReadCanary({
          captureRegistry,
          eventStore: this.eventStore,
          operationsStore,
          runtime: this.runtime,
          vault,
        });
        if (recovered !== null) {
          if (recovered.requestId === command.requestId) return recovered;
          throw new XReadCanaryConflictError("The one-shot X read canary is already complete");
        }
        const controller = acquireCanaryResource(
          () =>
            new XReadCanaryController({
              bearerToken: secrets.bearerToken,
              captureRegistry,
              eventStore: this.eventStore,
              operationsStore,
              runtime: this.runtime,
              vault,
            }),
        );
        controllerToClose = controller;
        this.#activeController = controller;
        return await controller.execute(command);
      } finally {
        if (this.#activeController === controllerToClose) this.#activeController = null;
        await closeCanaryResourceSet([
          () => controllerToClose?.close(),
          () => vaultToClose?.close(),
          () => captureRegistryToClose?.close(),
          () => operationsStoreToClose?.close(),
        ]);
      }
    });
  }

  async #recoverInterruptedIfPossible(suppressCredentialError = true): Promise<void> {
    if (this.#activeController !== null || this.#ownedCanaryClaim) return;
    if (this.#activeRecovery !== null) {
      try {
        await this.#activeRecovery;
      } catch (error) {
        this.#latchIncompleteCleanupError(error);
        if (!(error instanceof CredentialHostError) || !suppressCredentialError) throw error;
      }
      return;
    }
    if (this.#activeRun !== null || this.#startupRecoveryReconciled) return;
    const projection = readXReadCanaryProjection(this.eventStore, "unknown");
    if (projection.status !== "interrupted" && projection.lastReceipt === null) {
      this.#startupRecoveryReconciled = true;
      return;
    }
    const recovery = this.#recoverWithStorageSecrets();
    this.#activeRecovery = recovery;
    try {
      await recovery;
      this.#startupRecoveryReconciled = true;
    } catch (error) {
      this.#latchIncompleteCleanupError(error);
      if (!(error instanceof CredentialHostError) || !suppressCredentialError) throw error;
    } finally {
      if (this.#activeRecovery === recovery) this.#activeRecovery = null;
    }
  }

  async #recoverWithStorageSecrets(): Promise<void> {
    await this.credentialHost.withStorageSecrets(async (secrets) => {
      let operationsStore: SqliteOperationsStore | undefined;
      let captureRegistry: SqliteCaptureRegistry | undefined;
      let vault: SnapshotVault | undefined;
      try {
        operationsStore = acquireCanaryResource(
          () =>
            new SqliteOperationsStore({
              path: this.paths.operations,
              stateKey: secrets.operationsStateKey,
            }),
        );
        captureRegistry = acquireCanaryResource(() =>
          SqliteCaptureRegistry.open({
            expectedProfile: "canary",
            path: this.paths.captureRegistry,
            registryKey: secrets.captureRegistryKey,
          }),
        );
        vault = await acquireCanaryResourceAsync(() =>
          SnapshotVault.open({
            directory: this.paths.vault,
            maxCaptureBytes: 1_048_576,
            wrappingKey: secrets.vaultWrappingKey,
          }),
        );
        await recoverCaptureStorage({
          captureRegistry,
          recoveredAt: new Date().toISOString(),
          vault,
        });
        await recoverXReadCanary({
          captureRegistry,
          eventStore: this.eventStore,
          operationsStore,
          runtime: this.runtime,
          vault,
        });
      } finally {
        await closeCanaryResourceSet([
          () => vault?.close(),
          () => captureRegistry?.close(),
          () => operationsStore?.close(),
        ]);
      }
    });
  }
}

function requestedPaths(options: StartXCanaryOperatorOptions): XCanaryOperatorPaths {
  if (options.databasePath === ":memory:" || options.researchDatabasePath === ":memory:") {
    throw new TypeError("The Stage 1 canary requires durable, separate storage files");
  }
  const runtime = resolve(options.databasePath);
  const research = resolve(options.researchDatabasePath);
  const directory = dirname(runtime);
  return {
    runtime,
    research,
    operations: join(directory, "rsi-x-canary-operations.sqlite"),
    captureRegistry: join(directory, "rsi-x-canary-captures.sqlite"),
    eventStore: join(directory, "rsi-x-canary-events.sqlite"),
    vault: join(directory, "rsi-x-canary-vault"),
  };
}

export async function startXCanaryOperatorWithHost(
  options: StartXCanaryOperatorOptions,
  credentialHost: DarwinXReadCanaryKeychain,
  claimHost: DarwinOneShotClaimHost,
  profileLock: CanaryProfileLockLease,
): Promise<RunningXCanaryOperator> {
  await assertCanaryProfileLockForDatabasePath(profileLock, options.databasePath);
  const requested = requestedPaths(options);
  const identities = await Promise.all([
    resolveDatabaseIdentity(requested.runtime),
    resolveDatabaseIdentity(requested.research),
    resolveDatabaseIdentity(requested.operations),
    resolveDatabaseIdentity(requested.captureRegistry),
    resolveDatabaseIdentity(requested.eventStore),
  ]);
  assertSeparateDatabases(identities);
  const paths: XCanaryOperatorPaths = Object.freeze({
    runtime: identities[0]!.path,
    research: identities[1]!.path,
    operations: identities[2]!.path,
    captureRegistry: identities[3]!.path,
    eventStore: identities[4]!.path,
    vault: join(dirname(identities[0]!.path), "rsi-x-canary-vault"),
  });
  if (!isDarwinXReadCanaryKeychain(credentialHost)) {
    throw new TypeError("An authentic macOS Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(claimHost)) {
    throw new TypeError("An authentic X one-shot claim boundary is required");
  }

  let runtime: SqliteRuntimeController | undefined;
  let research: SqliteResearchLedger | undefined;
  let eventStore: SqliteEventStore | undefined;
  let canary: KeychainReadCanaryProvider | undefined;
  let operator: RunningOperatorServer | undefined;
  let closePromise: Promise<void> | null = null;
  let hostClosing = false;

  const close = (): Promise<void> => {
    if (closePromise === null) {
      hostClosing = true;
      canary?.beginClosing();
      closePromise = closeCanaryResourceSet([
        () => {
          runtime?.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
        },
        () => operator?.close(),
        () => canary?.close(),
        () => eventStore?.close(),
        () => research?.close(),
        () => {
          const failures: unknown[] = [];
          try {
            runtime?.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
          } catch (error) {
            failures.push(error);
          }
          try {
            runtime?.close();
          } catch (error) {
            failures.push(error);
          }
          if (failures.length > 0) {
            throw new AggregateError(failures, "X canary runtime shutdown did not complete");
          }
        },
      ]);
    }
    return closePromise;
  };

  try {
    runtime = acquireCanaryResource(() =>
      SqliteRuntimeController.open({
        openedAt: new Date().toISOString(),
        path: paths.runtime,
        processInstanceId: randomUUID(),
      }),
    );
    research = acquireCanaryResource(() => SqliteResearchLedger.open(paths.research));
    eventStore = acquireCanaryResource(() => new SqliteEventStore(paths.eventStore));
    canary = acquireCanaryResource(
      () => new KeychainReadCanaryProvider(credentialHost, claimHost, eventStore!, paths, runtime!),
    );
    await canary.initialize();
    const provider = new RuntimeOperatorSnapshotProvider(runtime, research);
    const runtimeControls = createHostClosingRuntimeControls(runtime, () => hostClosing);
    operator = await acquireCanaryResourceAsync(() =>
      startOperatorServer(provider, {
        port: options.port,
        readCanary: canary!,
        research: provider,
        runtime: runtimeControls,
      }),
    );
    return Object.freeze({ origin: operator.origin, paths, runtime, close });
  } catch (error) {
    return rethrowCanaryStartupFailureAfterCleanup(error, close);
  }
}
