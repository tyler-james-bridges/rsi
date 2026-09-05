import { randomUUID } from "node:crypto";
import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { SqliteCaptureRegistry } from "@rsi/capture-registry";
import {
  BaseRpcCredentialHostError,
  isDarwinBaseRpcKeychain,
  type BaseRpcCredentialStatus,
  type DarwinBaseRpcKeychain,
} from "@rsi/credential-host/base-rpc";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";
import { recoverCaptureStorage } from "@rsi/ingestion/capture-storage-recovery";
import {
  createRuntimeOperatorControls,
  startBaseRpcOperatorServer,
  type OperatorBaseRpcReadCanaryProvider,
  type OperatorRuntimeProvider,
  type RuntimeOperatorControlCommand,
  type RunningBaseRpcOperatorServer,
} from "@rsi/operator/base-rpc";
import { SqliteOperationsStore } from "@rsi/operations";
import {
  BaseRpcReadCanaryConflictError,
  BaseRpcReadCanaryController,
  readBaseRpcReadCanaryProjection,
  type BaseRpcReadCanaryProjectionV1,
  type BaseRpcReadCanaryReceiptV1,
  type BaseRpcReadCanaryRunCommand,
} from "@rsi/read-canary/base-rpc";
import { recoverBaseRpcReadCanary } from "@rsi/read-canary/base-rpc-recovery";
import { RuntimeConflictError, SqliteRuntimeController } from "@rsi/runtime";
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

export interface BaseRpcCanaryOperatorPaths {
  readonly captureRegistry: string;
  readonly eventStore: string;
  readonly operations: string;
  readonly runtime: string;
  readonly vault: string;
}

export interface StartBaseRpcCanaryOperatorOptions {
  readonly databasePath: string;
  readonly port: number;
}

export interface RunningBaseRpcCanaryOperator {
  readonly origin: string;
  readonly paths: Readonly<BaseRpcCanaryOperatorPaths>;
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
    throw new TypeError("The Base RPC canary requires durable, separate storage files");
  }
  const requestedParent = resolve(dirname(path));
  await mkdir(requestedParent, { mode: Number(PRIVATE_DIRECTORY_MODE), recursive: true });
  const requestedParentEntry = await lstat(requestedParent, { bigint: true });
  if (requestedParentEntry.isSymbolicLink()) {
    throw new TypeError("Base RPC canary data directories cannot be symbolic links");
  }
  const parent = await realpath(requestedParent);
  const parentEntry = await lstat(parent, { bigint: true });
  if (
    !parentEntry.isDirectory() ||
    parentEntry.isSymbolicLink() ||
    (parentEntry.mode & 0o777n) !== PRIVATE_DIRECTORY_MODE ||
    EFFECTIVE_USER_ID === null ||
    parentEntry.uid !== EFFECTIVE_USER_ID
  ) {
    throw new TypeError("Base RPC canary data directories must be owner-only (mode 0700)");
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
      throw new TypeError("Base RPC canary SQLite paths must be regular files");
    }
    const identity = await stat(canonicalPath, { bigint: true });
    if (
      !identity.isFile() ||
      identity.nlink !== 1n ||
      identity.uid !== EFFECTIVE_USER_ID ||
      identity.dev !== entry.dev ||
      identity.ino !== entry.ino
    ) {
      throw new TypeError("Base RPC canary SQLite paths must be regular files");
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
        throw new TypeError("Every Base RPC canary SQLite role requires a separate file");
      }
    }
  }
}

function publicCredentialStatus(
  status: BaseRpcCredentialStatus,
): BaseRpcReadCanaryProjectionV1["credentialStatus"] {
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

class KeychainBaseRpcReadCanaryProvider implements OperatorBaseRpcReadCanaryProvider {
  #activeController: BaseRpcReadCanaryController | null = null;
  #activeRun: Promise<Readonly<BaseRpcReadCanaryReceiptV1>> | null = null;
  #activeRecovery: Promise<void> | null = null;
  #activeStatus: Promise<Readonly<BaseRpcReadCanaryProjectionV1>> | null = null;
  #admissionAbortFailure: unknown;
  #abortEpoch = 0;
  #closing = false;
  #closingBegan = false;
  #credentialStatus: BaseRpcReadCanaryProjectionV1["credentialStatus"] = "unknown";
  #incompleteCleanupError: IncompleteCanaryCleanupError | null = null;
  #ownedCanaryClaim = false;
  #startupRecoveryReconciled = false;

  constructor(
    private readonly credentialHost: DarwinBaseRpcKeychain,
    private readonly claimHost: DarwinOneShotClaimHost,
    private readonly eventStore: SqliteEventStore,
    private readonly paths: Readonly<BaseRpcCanaryOperatorPaths>,
    private readonly runtime: SqliteRuntimeController,
  ) {
    if (!isDarwinBaseRpcKeychain(credentialHost)) {
      throw new TypeError("An authentic Base RPC macOS Keychain boundary is required");
    }
    if (!isDarwinOneShotClaimHost(claimHost)) {
      throw new TypeError("An authentic Base RPC one-shot claim boundary is required");
    }
  }

  getBaseRpcReadCanaryProjection(): Readonly<BaseRpcReadCanaryProjectionV1> {
    if (this.#activeController !== null) return this.#activeController.getProjection();
    return readBaseRpcReadCanaryProjection(this.eventStore, this.#credentialStatus);
  }

  refreshBaseRpcCredentialStatus(): Promise<Readonly<BaseRpcReadCanaryProjectionV1>> {
    if (this.#closing) {
      throw new BaseRpcReadCanaryConflictError("The Base RPC canary provider is closing");
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

  async #refreshCredentialStatus(): Promise<Readonly<BaseRpcReadCanaryProjectionV1>> {
    this.#credentialStatus = publicCredentialStatus(await this.credentialHost.status());
    return this.getBaseRpcReadCanaryProjection();
  }

  executeBaseRpcReadCanary(
    command: Readonly<BaseRpcReadCanaryRunCommand>,
  ): Promise<Readonly<BaseRpcReadCanaryReceiptV1>> {
    if (this.#closing) {
      throw new BaseRpcReadCanaryConflictError("The Base RPC canary provider is closing");
    }
    if (this.#activeRun !== null) {
      throw new BaseRpcReadCanaryConflictError("A Base RPC read canary is already running");
    }
    const runtime = this.runtime.getSnapshot();
    if (runtime.mode !== "RESEARCH" || runtime.revision !== command.expectedRuntimeRevision) {
      throw new BaseRpcReadCanaryConflictError(
        "Runtime state changed before the Base RPC canary entered its provider boundary",
      );
    }
    const existing = this.#existingReceipt();
    if (existing !== null) {
      throw new BaseRpcReadCanaryConflictError("The one-shot Base RPC canary is already complete");
    }
    if (this.#ownedCanaryClaim) {
      throw new BaseRpcReadCanaryConflictError("The one-shot Base RPC canary was already claimed");
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
    const projection = readBaseRpcReadCanaryProjection(this.eventStore, "unknown");
    const claimStatus = await this.claimHost.status();
    if (projection.lastReceipt === null && claimStatus === "present") {
      throw new BaseRpcReadCanaryConflictError(
        "The permanent Base RPC canary marker has no durable receipt",
      );
    }
    if (projection.lastReceipt !== null && claimStatus !== "present") {
      throw new BaseRpcReadCanaryConflictError(
        "The completed Base RPC canary requires its permanent one-shot marker",
      );
    }
  }

  async #executeAfterRecovery(
    command: Readonly<BaseRpcReadCanaryRunCommand>,
    abortEpoch: number,
  ): Promise<Readonly<BaseRpcReadCanaryReceiptV1>> {
    await this.#recoverInterruptedIfPossible(false);
    if (this.#closing || this.#abortEpoch !== abortEpoch) {
      throw new BaseRpcReadCanaryConflictError("The Base RPC canary provider is closing");
    }
    const existing = this.#existingReceipt();
    if (existing !== null) {
      throw new BaseRpcReadCanaryConflictError("The one-shot Base RPC canary is already complete");
    }
    return this.#runWithKeychain(command, abortEpoch);
  }

  #existingReceipt(): Readonly<BaseRpcReadCanaryReceiptV1> | null {
    return readBaseRpcReadCanaryProjection(this.eventStore, "unknown").lastReceipt;
  }

  async #runWithKeychain(
    command: Readonly<BaseRpcReadCanaryRunCommand>,
    abortEpoch: number,
  ): Promise<Readonly<BaseRpcReadCanaryReceiptV1>> {
    const runtimeBeforeClaim = this.runtime.getSnapshot();
    if (
      runtimeBeforeClaim.mode !== "RESEARCH" ||
      runtimeBeforeClaim.revision !== command.expectedRuntimeRevision
    ) {
      throw new BaseRpcReadCanaryConflictError(
        "Runtime state changed before the permanent Base RPC canary claim",
      );
    }
    await this.claimHost.claim();
    // The permanent marker owns this process before the API credential can be revealed.
    this.#ownedCanaryClaim = true;
    const runtimeAfterClaim = this.runtime.getSnapshot();
    if (
      this.#closing ||
      this.#abortEpoch !== abortEpoch ||
      runtimeAfterClaim.mode !== "RESEARCH" ||
      runtimeAfterClaim.revision !== command.expectedRuntimeRevision
    ) {
      throw new BaseRpcReadCanaryConflictError("The Base RPC canary run was stopped");
    }
    return this.credentialHost.withSecrets(async (secrets) => {
      if (this.#closing || this.#abortEpoch !== abortEpoch) {
        throw new BaseRpcReadCanaryConflictError("The Base RPC canary run was stopped");
      }
      let operationsStoreToClose: SqliteOperationsStore | undefined;
      let captureRegistryToClose: SqliteCaptureRegistry | undefined;
      let vaultToClose: SnapshotVault | undefined;
      let controllerToClose: BaseRpcReadCanaryController | undefined;
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
        const recovered = await recoverBaseRpcReadCanary({
          captureRegistry,
          eventStore: this.eventStore,
          operationsStore,
          runtime: this.runtime,
          vault,
        });
        if (recovered !== null) {
          throw new BaseRpcReadCanaryConflictError(
            "Recovered Base RPC receipt cannot authenticate this command",
          );
        }
        const controller = acquireCanaryResource(
          () =>
            new BaseRpcReadCanaryController({
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
        if (!(error instanceof BaseRpcCredentialHostError) || !suppressCredentialError) {
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
      if (!(error instanceof BaseRpcCredentialHostError) || !suppressCredentialError) {
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
        await recoverBaseRpcReadCanary({
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

function requestedPaths(options: StartBaseRpcCanaryOperatorOptions): BaseRpcCanaryOperatorPaths {
  if (options.databasePath === ":memory:") {
    throw new TypeError("The Base RPC canary requires durable storage");
  }
  const runtime = resolve(options.databasePath);
  const directory = dirname(runtime);
  return {
    runtime,
    operations: join(directory, "rsi-base-rpc-canary-operations.sqlite"),
    captureRegistry: join(directory, "rsi-base-rpc-canary-captures.sqlite"),
    eventStore: join(directory, "rsi-base-rpc-canary-events.sqlite"),
    vault: join(directory, "rsi-base-rpc-canary-vault"),
  };
}

export async function startBaseRpcCanaryOperatorWithHost(
  options: StartBaseRpcCanaryOperatorOptions,
  credentialHost: DarwinBaseRpcKeychain,
  claimHost: DarwinOneShotClaimHost,
  profileLock: CanaryProfileLockLease,
): Promise<RunningBaseRpcCanaryOperator> {
  await assertCanaryProfileLockForDatabasePath(profileLock, options.databasePath);
  const requested = requestedPaths(options);
  const identities = await Promise.all([
    resolveDatabaseIdentity(requested.runtime),
    resolveDatabaseIdentity(requested.operations),
    resolveDatabaseIdentity(requested.captureRegistry),
    resolveDatabaseIdentity(requested.eventStore),
  ]);
  assertSeparateDatabases(identities);
  const paths: BaseRpcCanaryOperatorPaths = Object.freeze({
    runtime: identities[0]!.path,
    operations: identities[1]!.path,
    captureRegistry: identities[2]!.path,
    eventStore: identities[3]!.path,
    vault: join(dirname(identities[0]!.path), "rsi-base-rpc-canary-vault"),
  });
  if (!isDarwinBaseRpcKeychain(credentialHost)) {
    throw new TypeError("An authentic Base RPC macOS Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(claimHost)) {
    throw new TypeError("An authentic Base RPC one-shot claim boundary is required");
  }

  let runtime: SqliteRuntimeController | undefined;
  let eventStore: SqliteEventStore | undefined;
  let canary: KeychainBaseRpcReadCanaryProvider | undefined;
  let operator: RunningBaseRpcOperatorServer | undefined;
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
            throw new AggregateError(failures, "Base RPC canary runtime shutdown did not complete");
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
        new KeychainBaseRpcReadCanaryProvider(
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
      startBaseRpcOperatorServer({
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
