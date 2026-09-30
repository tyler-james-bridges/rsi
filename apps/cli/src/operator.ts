import { randomUUID } from "node:crypto";
import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

import {
  createRuntimeOperatorControls,
  startOperatorServer,
  type OperatorEventPage,
  type OperatorEventQuery,
  type OperatorResearchProvider,
  type OperatorRuntimeProvider,
  type OperatorSnapshotProvider,
  type RuntimeOperatorControlCommand,
} from "@rsi/operator";
import { SqliteResearchLedger } from "@rsi/research-ledger";
import {
  RuntimeConflictError,
  SqliteRuntimeController,
  type RuntimeAuditEvent,
} from "@rsi/runtime";

import {
  assertStage0StorageIsolation,
  operatorUsage,
  parseOperatorOptions,
  resolveProspectiveStoragePath,
} from "./operator-options.js";
import { productionXCanaryHostOptions } from "./production-canary-config.js";
import { createRecordedResearchReplayProvider } from "./research-replay-provider.js";

interface DatabaseIdentity {
  readonly path: string;
  readonly device?: bigint;
  readonly inode?: bigint;
}

function isMissingPath(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

async function resolveDatabaseIdentity(path: string): Promise<DatabaseIdentity> {
  if (path === ":memory:") return { path };
  await mkdir(dirname(path), { mode: 0o700, recursive: true });
  const parent = await realpath(dirname(path));
  const canonicalPath = resolve(parent, basename(path));
  try {
    const entry = await lstat(canonicalPath, { bigint: true });
    if (entry.isSymbolicLink() || !entry.isFile() || entry.nlink !== 1n) {
      throw new TypeError("SQLite paths must be single-link regular files");
    }
    const identity = await stat(canonicalPath, { bigint: true });
    return { path: canonicalPath, device: identity.dev, inode: identity.ino };
  } catch (error) {
    if (isMissingPath(error)) return { path: canonicalPath };
    throw error;
  }
}

function assertSeparateDatabases(runtime: DatabaseIdentity, research: DatabaseIdentity): void {
  if (
    runtime.path === research.path ||
    (runtime.device !== undefined &&
      research.device !== undefined &&
      runtime.device === research.device &&
      runtime.inode === research.inode)
  ) {
    throw new TypeError("Runtime and research ledgers must use separate SQLite files");
  }
}

function cursorSequence(cursor: string | undefined): number | undefined {
  if (cursor === undefined) return undefined;
  const sequence = Number(cursor.slice("seq:".length));
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new TypeError("invalid event cursor");
  return sequence;
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
    if (query.type !== undefined) {
      events = events.filter((event) => event.type === query.type);
    }
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

function createClosingAwareRuntimeControls(
  controller: SqliteRuntimeController,
  isClosing: () => boolean,
): OperatorRuntimeProvider {
  const controls = createRuntimeOperatorControls({ controller });
  const assertHostOpen = (): void => {
    if (isClosing()) {
      throw new RuntimeConflictError(
        "STALE_STATE",
        "Runtime controls are unavailable while the Stage 0 host is closing",
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

type Stage0OperatorOptions = Exclude<ReturnType<typeof parseOperatorOptions>, null>;

async function runStage0Operator(options: Stage0OperatorOptions): Promise<void> {
  const requestedDatabasePath =
    options.databasePath === ":memory:" ? options.databasePath : resolve(options.databasePath);
  const requestedResearchDatabasePath =
    options.researchDatabasePath === ":memory:"
      ? options.researchDatabasePath
      : resolve(options.researchDatabasePath);
  const requestedProductionDataDirectory = dirname(productionXCanaryHostOptions().databasePath);
  assertStage0StorageIsolation(
    requestedDatabasePath,
    requestedResearchDatabasePath,
    requestedProductionDataDirectory,
  );
  const [prospectiveRuntimePath, prospectiveResearchPath, productionDataDirectory] =
    await Promise.all([
      resolveProspectiveStoragePath(requestedDatabasePath),
      resolveProspectiveStoragePath(requestedResearchDatabasePath),
      resolveProspectiveStoragePath(requestedProductionDataDirectory),
    ]);
  assertStage0StorageIsolation(
    prospectiveRuntimePath,
    prospectiveResearchPath,
    productionDataDirectory,
  );

  let runtime: SqliteRuntimeController | undefined;
  let research: SqliteResearchLedger | undefined;
  let operator: Awaited<ReturnType<typeof startOperatorServer>> | undefined;
  let hostClosing = false;
  let closePromise: Promise<void> | null = null;
  let shutdownRequested = false;

  const close = (): Promise<void> => {
    if (closePromise !== null) return closePromise;
    hostClosing = true;
    closePromise = (async (): Promise<void> => {
      const failures: unknown[] = [];
      const activeRuntime = runtime;
      if (activeRuntime !== undefined) {
        try {
          activeRuntime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
        } catch (error) {
          failures.push(error);
        }
      }
      try {
        await operator?.close();
      } catch (error) {
        failures.push(error);
      }
      try {
        research?.close();
      } catch (error) {
        failures.push(error);
      }

      if (activeRuntime !== undefined) {
        // Keep the final STOP and database close in one synchronous section so no
        // already-admitted task can create a post-STOP transition between them.
        try {
          activeRuntime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
        } catch (error) {
          failures.push(error);
        }
        try {
          activeRuntime.close();
        } catch (error) {
          failures.push(error);
        }
      }
      if (failures.length > 0) {
        throw new AggregateError(failures, "Stage 0 operator shutdown did not complete");
      }
    })();
    return closePromise;
  };
  const removeSignalHandlers = (): void => {
    process.off("SIGINT", handleSignal);
    process.off("SIGTERM", handleSignal);
  };
  const handleSignal = (): void => {
    shutdownRequested = true;
    hostClosing = true;
    // Startup may still be inside a factory that has not returned its cleanup handle.
    // In that case the latched request is handled immediately after the factory returns.
    if (operator === undefined) return;
    void close()
      .catch(() => {
        process.stderr.write("RSI failed to persist STOP cleanly during shutdown.\n");
        process.exitCode = 1;
      })
      .finally(removeSignalHandlers);
  };
  process.once("SIGINT", handleSignal);
  process.once("SIGTERM", handleSignal);

  try {
    const [runtimeIdentity, researchIdentity] = await Promise.all([
      resolveDatabaseIdentity(prospectiveRuntimePath),
      resolveDatabaseIdentity(prospectiveResearchPath),
    ]);
    if (shutdownRequested) {
      removeSignalHandlers();
      return;
    }
    assertStage0StorageIsolation(
      runtimeIdentity.path,
      researchIdentity.path,
      productionDataDirectory,
    );
    assertSeparateDatabases(runtimeIdentity, researchIdentity);
    const databasePath = runtimeIdentity.path;
    const researchDatabasePath = researchIdentity.path;

    runtime = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: databasePath,
      processInstanceId: randomUUID(),
    });
    research = SqliteResearchLedger.open(researchDatabasePath);
    if (shutdownRequested) {
      await close();
      removeSignalHandlers();
      return;
    }
    const runtimeControls = createClosingAwareRuntimeControls(runtime, () => hostClosing);
    const provider = new RuntimeOperatorSnapshotProvider(runtime, research);
    const researchReplay = createRecordedResearchReplayProvider({
      runtime,
      research,
      isClosing: () => hostClosing,
    });
    operator = await startOperatorServer(provider, {
      port: options.port,
      research: provider,
      researchReplay,
      runtime: runtimeControls,
    });
    if (shutdownRequested) {
      await close();
      removeSignalHandlers();
      return;
    }
    const snapshot = runtime.getSnapshot();
    const startupLine = JSON.stringify({
      mode: "stage0-local-runtime",
      runtimeMode: snapshot.mode,
      executionEnabled: false,
      financialAuthority: false,
      databasePath,
      researchDatabasePath,
      origin: operator.origin,
    });
    if (shutdownRequested) {
      await close();
      removeSignalHandlers();
    } else {
      console.log(startupLine);
    }
  } catch (error) {
    try {
      await close();
    } finally {
      removeSignalHandlers();
    }
    throw error;
  }
}

const options = parseOperatorOptions(process.argv.slice(2));
if (options === null) {
  console.log(operatorUsage());
  process.exitCode = 0;
} else {
  try {
    await runStage0Operator(options);
  } catch {
    process.stderr.write("RSI Stage 0 operator startup was refused.\n");
    process.exitCode = 1;
  }
}
