import { randomUUID } from "node:crypto";
import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import {
  OpenSeaTrendingCredentialHostError,
  isDarwinOpenSeaTrendingKeychain,
  type DarwinOpenSeaTrendingKeychain,
  type OpenSeaTrendingCredentialStatus,
} from "@rsi/credential-host/opensea-trending";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";
import { recoverCaptureStorage } from "@rsi/ingestion/capture-storage-recovery";
import {
  createRuntimeOperatorControls,
  startOpenSeaOperatorServer,
  type OpenSeaOperatorEventPage,
  type OpenSeaOperatorEventQuery,
  type OpenSeaOperatorSnapshotProvider,
  type OperatorOpenSeaReadCanaryProvider,
  type OperatorRuntimeProvider,
  type RuntimeOperatorControlCommand,
  type RunningOpenSeaOperatorServer,
} from "@rsi/operator/opensea";
import { SqliteOperationsStore } from "@rsi/operations";
import {
  OpenSeaReadCanaryConflictError,
  OpenSeaReadCanaryController,
  readOpenSeaReadCanaryProjection,
  recoverOpenSeaReadCanary,
  type OpenSeaReadCanaryProjectionV1,
  type OpenSeaReadCanaryReceiptV1,
  type OpenSeaReadCanaryRunCommand,
} from "@rsi/read-canary/opensea";
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

export interface OpenSeaCanaryOperatorPaths {
  readonly captureRegistry: string;
  readonly eventStore: string;
  readonly operations: string;
  readonly runtime: string;
  readonly vault: string;
}

export interface StartOpenSeaCanaryOperatorOptions {
  readonly databasePath: string;
  readonly port: number;
}

export interface RunningOpenSeaCanaryOperator {
  readonly origin: string;
  readonly paths: Readonly<OpenSeaCanaryOperatorPaths>;
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
    throw new TypeError("The OpenSea canary requires durable, separate storage files");
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
    throw new TypeError("OpenSea canary data directories must be owner-only (mode 0700)");
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
      throw new TypeError("OpenSea canary SQLite paths must be regular files");
    }
    const identity = await stat(canonicalPath, { bigint: true });
    if (
      !identity.isFile() ||
      identity.nlink !== 1n ||
      identity.uid !== EFFECTIVE_USER_ID ||
      identity.dev !== entry.dev ||
      identity.ino !== entry.ino
    ) {
      throw new TypeError("OpenSea canary SQLite paths must be regular files");
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
        throw new TypeError("Every OpenSea canary SQLite role requires a separate file");
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

function projectRuntimeEvent(event: RuntimeAuditEvent): unknown {
  return Object.freeze({
    sequence: event.sequence,
    type: event.type,
    occurredAt: event.occurredAt,
  });
}

class OpenSeaRuntimeEventProvider implements OpenSeaOperatorSnapshotProvider {
  constructor(private readonly runtime: SqliteRuntimeController) {}

  listEvents(query: Readonly<OpenSeaOperatorEventQuery>): OpenSeaOperatorEventPage {
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
    return Object.freeze({
      items: Object.freeze(items.map(projectRuntimeEvent)),
      nextCursor:
        events.length > query.limit && items.length > 0
          ? `seq:${items[items.length - 1]!.sequence}`
          : null,
    });
  }
}

function publicCredentialStatus(
  status: OpenSeaTrendingCredentialStatus,
): OpenSeaReadCanaryProjectionV1["credentialStatus"] {
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

class KeychainOpenSeaReadCanaryProvider implements OperatorOpenSeaReadCanaryProvider {
  #activeController: OpenSeaReadCanaryController | null = null;
  #activeRun: Promise<Readonly<OpenSeaReadCanaryReceiptV1>> | null = null;
  #activeRecovery: Promise<void> | null = null;
  #activeStatus: Promise<Readonly<OpenSeaReadCanaryProjectionV1>> | null = null;
  #admissionAbortFailure: unknown;
  #abortEpoch = 0;
  #closing = false;
  #closingBegan = false;
  #credentialStatus: OpenSeaReadCanaryProjectionV1["credentialStatus"] = "unknown";
  #incompleteCleanupError: IncompleteCanaryCleanupError | null = null;
  #ownedCanaryClaim = false;
  #startupRecoveryReconciled = false;

  constructor(
    private readonly credentialHost: DarwinOpenSeaTrendingKeychain,
    private readonly claimHost: DarwinOneShotClaimHost,
    private readonly eventStore: SqliteEventStore,
    private readonly paths: Readonly<OpenSeaCanaryOperatorPaths>,
    private readonly runtime: SqliteRuntimeController,
  ) {
    if (!isDarwinOpenSeaTrendingKeychain(credentialHost)) {
      throw new TypeError("An authentic OpenSea macOS Keychain boundary is required");
    }
    if (!isDarwinOneShotClaimHost(claimHost)) {
      throw new TypeError("An authentic OpenSea one-shot claim boundary is required");
    }
  }

  getOpenSeaReadCanaryProjection(): Readonly<OpenSeaReadCanaryProjectionV1> {
    if (this.#activeController !== null) return this.#activeController.getProjection();
    return readOpenSeaReadCanaryProjection(this.eventStore, this.#credentialStatus);
  }

  refreshOpenSeaCredentialStatus(): Promise<Readonly<OpenSeaReadCanaryProjectionV1>> {
    if (this.#closing) {
      throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
    }
    if (this.#activeStatus !== null) return this.#activeStatus;
    const status = this.#refreshCredentialStatus();
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

  async #refreshCredentialStatus(): Promise<Readonly<OpenSeaReadCanaryProjectionV1>> {
    this.#credentialStatus = publicCredentialStatus(await this.credentialHost.status());
    return this.getOpenSeaReadCanaryProjection();
  }

  executeOpenSeaReadCanary(
    command: Readonly<OpenSeaReadCanaryRunCommand>,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    if (this.#closing) {
      throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
    }
    if (this.#activeRun !== null) {
      throw new OpenSeaReadCanaryConflictError("An OpenSea read canary is already running");
    }
    const runtime = this.runtime.getSnapshot();
    if (runtime.mode !== "RESEARCH" || runtime.revision !== command.expectedRuntimeRevision) {
      throw new OpenSeaReadCanaryConflictError(
        "Runtime state changed before the OpenSea canary entered its provider boundary",
      );
    }
    const existing = this.#existingReceipt(command);
    if (existing !== null) return Promise.resolve(existing);
    if (this.#ownedCanaryClaim) {
      throw new OpenSeaReadCanaryConflictError("The one-shot OpenSea canary was already claimed");
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
    const projection = readOpenSeaReadCanaryProjection(this.eventStore, "unknown");
    const claimStatus = await this.claimHost.status();
    if (projection.lastReceipt === null && claimStatus === "present") {
      throw new OpenSeaReadCanaryConflictError(
        "The permanent OpenSea canary marker has no durable receipt",
      );
    }
    if (projection.lastReceipt !== null && claimStatus !== "present") {
      throw new OpenSeaReadCanaryConflictError(
        "The completed OpenSea canary requires its permanent one-shot marker",
      );
    }
  }

  async #executeAfterRecovery(
    command: Readonly<OpenSeaReadCanaryRunCommand>,
    abortEpoch: number,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    await this.#recoverInterruptedIfPossible(false);
    if (this.#closing || this.#abortEpoch !== abortEpoch) {
      throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
    }
    const existing = this.#existingReceipt(command);
    if (existing !== null) return existing;
    return this.#runWithKeychain(command, abortEpoch);
  }

  #existingReceipt(
    command: Readonly<OpenSeaReadCanaryRunCommand>,
  ): Readonly<OpenSeaReadCanaryReceiptV1> | null {
    const existing = readOpenSeaReadCanaryProjection(this.eventStore, "unknown").lastReceipt;
    if (existing === null) return null;
    if (existing.requestId === command.requestId) return existing;
    throw new OpenSeaReadCanaryConflictError("The one-shot OpenSea canary is already complete");
  }

  async #runWithKeychain(
    command: Readonly<OpenSeaReadCanaryRunCommand>,
    abortEpoch: number,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    const runtimeBeforeClaim = this.runtime.getSnapshot();
    if (
      runtimeBeforeClaim.mode !== "RESEARCH" ||
      runtimeBeforeClaim.revision !== command.expectedRuntimeRevision
    ) {
      throw new OpenSeaReadCanaryConflictError(
        "Runtime state changed before the permanent OpenSea claim",
      );
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
      throw new OpenSeaReadCanaryConflictError("The OpenSea read canary run was stopped");
    }
    return this.credentialHost.withSecrets(async (secrets) => {
      if (this.#closing || this.#abortEpoch !== abortEpoch) {
        throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
      }
      let operationsStoreToClose: SqliteOperationsStore | undefined;
      let captureRegistryToClose: SqliteCaptureRegistry | undefined;
      let vaultToClose: SnapshotVault | undefined;
      let controllerToClose: OpenSeaReadCanaryController | undefined;
      try {
        this.#credentialStatus = "configured";
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
            maxCaptureBytes: 2_097_152,
            wrappingKey: secrets.vaultWrappingKey,
          }),
        );
        vaultToClose = vault;
        await recoverCaptureStorage({
          captureRegistry,
          recoveredAt: new Date().toISOString(),
          vault,
        });
        const recovered = await recoverOpenSeaReadCanary({
          captureRegistry,
          eventStore: this.eventStore,
          operationsStore,
          runtime: this.runtime,
          vault,
        });
        if (recovered !== null) {
          if (recovered.requestId === command.requestId) return recovered;
          throw new OpenSeaReadCanaryConflictError("The one-shot OpenSea canary is complete");
        }
        const controller = acquireCanaryResource(
          () =>
            new OpenSeaReadCanaryController({
              apiKey: secrets.apiKey,
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
        if (!(error instanceof OpenSeaTrendingCredentialHostError) || !suppressCredentialError) {
          throw error;
        }
      }
      return;
    }
    if (this.#activeRun !== null || this.#startupRecoveryReconciled) return;
    const recovery = this.#recoverWithStorageSecrets();
    this.#activeRecovery = recovery;
    try {
      await recovery;
      this.#startupRecoveryReconciled = true;
    } catch (error) {
      this.#latchIncompleteCleanupError(error);
      if (!(error instanceof OpenSeaTrendingCredentialHostError) || !suppressCredentialError) {
        throw error;
      }
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
            maxCaptureBytes: 2_097_152,
            wrappingKey: secrets.vaultWrappingKey,
          }),
        );
        await recoverCaptureStorage({
          captureRegistry,
          recoveredAt: new Date().toISOString(),
          vault,
        });
        await recoverOpenSeaReadCanary({
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

function requestedPaths(options: StartOpenSeaCanaryOperatorOptions): OpenSeaCanaryOperatorPaths {
  if (options.databasePath === ":memory:") {
    throw new TypeError("The OpenSea canary requires durable storage");
  }
  const runtime = resolve(options.databasePath);
  const directory = dirname(runtime);
  return {
    runtime,
    operations: join(directory, "rsi-opensea-canary-operations.sqlite"),
    captureRegistry: join(directory, "rsi-opensea-canary-captures.sqlite"),
    eventStore: join(directory, "rsi-opensea-canary-events.sqlite"),
    vault: join(directory, "rsi-opensea-canary-vault"),
  };
}

export async function startOpenSeaCanaryOperatorWithHost(
  options: StartOpenSeaCanaryOperatorOptions,
  credentialHost: DarwinOpenSeaTrendingKeychain,
  claimHost: DarwinOneShotClaimHost,
  profileLock: CanaryProfileLockLease,
): Promise<RunningOpenSeaCanaryOperator> {
  await assertCanaryProfileLockForDatabasePath(profileLock, options.databasePath);
  const requested = requestedPaths(options);
  const identities = await Promise.all([
    resolveDatabaseIdentity(requested.runtime),
    resolveDatabaseIdentity(requested.operations),
    resolveDatabaseIdentity(requested.captureRegistry),
    resolveDatabaseIdentity(requested.eventStore),
  ]);
  assertSeparateDatabases(identities);
  const paths: OpenSeaCanaryOperatorPaths = Object.freeze({
    runtime: identities[0]!.path,
    operations: identities[1]!.path,
    captureRegistry: identities[2]!.path,
    eventStore: identities[3]!.path,
    vault: join(dirname(identities[0]!.path), "rsi-opensea-canary-vault"),
  });
  if (!isDarwinOpenSeaTrendingKeychain(credentialHost)) {
    throw new TypeError("An authentic OpenSea macOS Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(claimHost)) {
    throw new TypeError("An authentic OpenSea one-shot claim boundary is required");
  }

  let runtime: SqliteRuntimeController | undefined;
  let eventStore: SqliteEventStore | undefined;
  let canary: KeychainOpenSeaReadCanaryProvider | undefined;
  let operator: RunningOpenSeaOperatorServer | undefined;
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
            throw new AggregateError(failures, "OpenSea canary runtime shutdown did not complete");
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
    eventStore = acquireCanaryResource(() => new SqliteEventStore(paths.eventStore));
    canary = acquireCanaryResource(
      () =>
        new KeychainOpenSeaReadCanaryProvider(
          credentialHost,
          claimHost,
          eventStore!,
          paths,
          runtime!,
        ),
    );
    await canary.initialize();
    const runtimeControls = createHostClosingRuntimeControls(runtime, () => hostClosing);
    operator = await acquireCanaryResourceAsync(() =>
      startOpenSeaOperatorServer(new OpenSeaRuntimeEventProvider(runtime!), {
        port: options.port,
        readCanary: canary!,
        runtime: runtimeControls,
      }),
    );
    return Object.freeze({ origin: operator.origin, paths, runtime, close });
  } catch (error) {
    return rethrowCanaryStartupFailureAfterCleanup(error, close);
  }
}
