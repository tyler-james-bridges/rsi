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
import { recoverCaptureStorage } from "@rsi/ingestion/capture-storage-recovery";
import {
  createRuntimeOperatorControls,
  startOpenSeaOperatorServer,
  type OpenSeaOperatorEventPage,
  type OpenSeaOperatorEventQuery,
  type OpenSeaOperatorSnapshotProvider,
  type OperatorOpenSeaReadCanaryProvider,
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
import { SqliteRuntimeController, type RuntimeAuditEvent } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
import { SnapshotVault } from "@rsi/vault";

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
    if (entry.isSymbolicLink() || !entry.isFile()) {
      throw new TypeError("OpenSea canary SQLite paths must be regular files");
    }
    const identity = await stat(canonicalPath, { bigint: true });
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

class KeychainOpenSeaReadCanaryProvider implements OperatorOpenSeaReadCanaryProvider {
  #activeController: OpenSeaReadCanaryController | null = null;
  #activeRun: Promise<Readonly<OpenSeaReadCanaryReceiptV1>> | null = null;
  #activeRecovery: Promise<void> | null = null;
  #closing = false;
  #credentialStatus: OpenSeaReadCanaryProjectionV1["credentialStatus"] = "unknown";
  #ownedCanaryClaim = false;
  #startupRecoveryReconciled = false;

  constructor(
    private readonly credentialHost: DarwinOpenSeaTrendingKeychain,
    private readonly eventStore: SqliteEventStore,
    private readonly paths: Readonly<OpenSeaCanaryOperatorPaths>,
    private readonly runtime: SqliteRuntimeController,
  ) {
    if (!isDarwinOpenSeaTrendingKeychain(credentialHost)) {
      throw new TypeError("An authentic OpenSea macOS Keychain boundary is required");
    }
  }

  getOpenSeaReadCanaryProjection(): Readonly<OpenSeaReadCanaryProjectionV1> {
    if (this.#activeController !== null) return this.#activeController.getProjection();
    return readOpenSeaReadCanaryProjection(this.eventStore, this.#credentialStatus);
  }

  async refreshOpenSeaCredentialStatus(): Promise<Readonly<OpenSeaReadCanaryProjectionV1>> {
    if (this.#closing) {
      throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
    }
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
    const existing = this.#existingReceipt(command);
    if (existing !== null) return Promise.resolve(existing);
    if (this.#ownedCanaryClaim) {
      throw new OpenSeaReadCanaryConflictError("The one-shot OpenSea canary was already claimed");
    }
    const run = this.#executeAfterRecovery(command);
    this.#activeRun = run;
    const clear = (): void => {
      if (this.#activeRun === run) this.#activeRun = null;
    };
    void run.then(clear, clear);
    return run;
  }

  abortActive(): void {
    this.#activeController?.abortActive();
  }

  async close(): Promise<void> {
    this.#closing = true;
    this.abortActive();
    await this.#activeRun?.catch(() => undefined);
    await this.#activeRecovery?.catch(() => undefined);
  }

  async initialize(): Promise<void> {
    await this.#recoverInterruptedIfPossible();
  }

  async #executeAfterRecovery(
    command: Readonly<OpenSeaReadCanaryRunCommand>,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    await this.#recoverInterruptedIfPossible(false);
    if (this.#closing) {
      throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
    }
    const existing = this.#existingReceipt(command);
    if (existing !== null) return existing;
    return this.#runWithKeychain(command);
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
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> {
    return this.credentialHost.withSecrets(async (secrets) => {
      if (this.#closing) {
        throw new OpenSeaReadCanaryConflictError("The OpenSea canary provider is closing");
      }
      let operationsStore: SqliteOperationsStore | undefined;
      let captureRegistry: SqliteCaptureRegistry | undefined;
      let vault: SnapshotVault | undefined;
      let controller: OpenSeaReadCanaryController | undefined;
      try {
        this.#credentialStatus = "configured";
        operationsStore = new SqliteOperationsStore({
          path: this.paths.operations,
          stateKey: secrets.operationsStateKey,
        });
        captureRegistry = SqliteCaptureRegistry.open({
          expectedProfile: "canary",
          path: this.paths.captureRegistry,
          registryKey: secrets.captureRegistryKey,
        });
        vault = await SnapshotVault.open({
          directory: this.paths.vault,
          maxCaptureBytes: 2_097_152,
          wrappingKey: secrets.vaultWrappingKey,
        });
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
        controller = new OpenSeaReadCanaryController({
          apiKey: secrets.apiKey,
          captureRegistry,
          eventStore: this.eventStore,
          operationsStore,
          runtime: this.runtime,
          vault,
        });
        this.#activeController = controller;
        this.#ownedCanaryClaim = true;
        return await controller.execute(command);
      } finally {
        if (this.#activeController === controller) this.#activeController = null;
        controller?.close();
        await vault?.close().catch(() => undefined);
        captureRegistry?.close();
        operationsStore?.close();
      }
    });
  }

  async #recoverInterruptedIfPossible(suppressCredentialError = true): Promise<void> {
    if (this.#activeController !== null || this.#ownedCanaryClaim) return;
    if (this.#activeRecovery !== null) {
      try {
        await this.#activeRecovery;
      } catch (error) {
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
        operationsStore = new SqliteOperationsStore({
          path: this.paths.operations,
          stateKey: secrets.operationsStateKey,
        });
        captureRegistry = SqliteCaptureRegistry.open({
          expectedProfile: "canary",
          path: this.paths.captureRegistry,
          registryKey: secrets.captureRegistryKey,
        });
        vault = await SnapshotVault.open({
          directory: this.paths.vault,
          maxCaptureBytes: 2_097_152,
          wrappingKey: secrets.vaultWrappingKey,
        });
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
        await vault?.close().catch(() => undefined);
        captureRegistry?.close();
        operationsStore?.close();
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
): Promise<RunningOpenSeaCanaryOperator> {
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

  const runtime = SqliteRuntimeController.open({
    openedAt: new Date().toISOString(),
    path: paths.runtime,
    processInstanceId: randomUUID(),
  });
  let eventStore: SqliteEventStore | undefined;
  let canary: KeychainOpenSeaReadCanaryProvider | undefined;
  let operator: RunningOpenSeaOperatorServer | undefined;
  let closing = false;

  const close = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    canary?.abortActive();
    try {
      runtime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
    } finally {
      try {
        await canary?.close();
      } finally {
        try {
          await operator?.close();
        } finally {
          try {
            eventStore?.close();
          } finally {
            runtime.close();
          }
        }
      }
    }
  };

  try {
    eventStore = new SqliteEventStore(paths.eventStore);
    canary = new KeychainOpenSeaReadCanaryProvider(credentialHost, eventStore, paths, runtime);
    await canary.initialize();
    operator = await startOpenSeaOperatorServer(new OpenSeaRuntimeEventProvider(runtime), {
      port: options.port,
      readCanary: canary,
      runtime: createRuntimeOperatorControls({ controller: runtime }),
    });
    return Object.freeze({ origin: operator.origin, paths, runtime, close });
  } catch (error) {
    await close();
    throw error;
  }
}
