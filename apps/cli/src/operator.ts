import { randomUUID } from "node:crypto";
import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

import {
  createRuntimeOperatorControls,
  startOperatorServer,
  type OperatorEventPage,
  type OperatorEventQuery,
  type OperatorResearchProvider,
  type OperatorSnapshotProvider,
} from "@rsi/operator";
import { SqliteResearchLedger } from "@rsi/research-ledger";
import { SqliteRuntimeController, type RuntimeAuditEvent } from "@rsi/runtime";

import { operatorUsage, parseOperatorOptions } from "./operator-options.js";

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
  await mkdir(dirname(path), { recursive: true });
  const parent = await realpath(dirname(path));
  const canonicalPath = resolve(parent, basename(path));
  try {
    const entry = await lstat(canonicalPath, { bigint: true });
    if (entry.isSymbolicLink() || !entry.isFile()) {
      throw new TypeError("SQLite paths must be regular files, not links or special files");
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

const options = parseOperatorOptions(process.argv.slice(2));
if (options === null) {
  console.log(operatorUsage());
  process.exitCode = 0;
} else {
  const requestedDatabasePath =
    options.databasePath === ":memory:" ? options.databasePath : resolve(options.databasePath);
  const requestedResearchDatabasePath =
    options.researchDatabasePath === ":memory:"
      ? options.researchDatabasePath
      : resolve(options.researchDatabasePath);
  const [runtimeIdentity, researchIdentity] = await Promise.all([
    resolveDatabaseIdentity(requestedDatabasePath),
    resolveDatabaseIdentity(requestedResearchDatabasePath),
  ]);
  assertSeparateDatabases(runtimeIdentity, researchIdentity);
  const databasePath = runtimeIdentity.path;
  const researchDatabasePath = researchIdentity.path;

  const runtime = SqliteRuntimeController.open({
    openedAt: new Date().toISOString(),
    path: databasePath,
    processInstanceId: randomUUID(),
  });
  let research: SqliteResearchLedger;
  try {
    research = SqliteResearchLedger.open(researchDatabasePath);
  } catch (error) {
    try {
      runtime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
    } finally {
      runtime.close();
    }
    throw error;
  }
  const runtimeControls = createRuntimeOperatorControls({ controller: runtime });
  let operator: Awaited<ReturnType<typeof startOperatorServer>> | undefined;
  let closing = false;

  const close = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    try {
      runtime.stop({ occurredAt: new Date().toISOString(), requestId: randomUUID() });
    } finally {
      try {
        await operator?.close();
      } finally {
        try {
          research.close();
        } finally {
          runtime.close();
        }
      }
    }
  };

  try {
    const provider = new RuntimeOperatorSnapshotProvider(runtime, research);
    operator = await startOperatorServer(provider, {
      port: options.port,
      research: provider,
      runtime: runtimeControls,
    });
    const snapshot = runtime.getSnapshot();
    console.log(
      JSON.stringify({
        mode: "stage0-local-runtime",
        runtimeMode: snapshot.mode,
        executionEnabled: false,
        financialAuthority: false,
        databasePath,
        researchDatabasePath,
        origin: operator.origin,
      }),
    );

    const handleSignal = (): void => {
      void close().catch(() => {
        process.stderr.write("RSI failed to persist STOP cleanly during shutdown.\n");
        process.exitCode = 1;
      });
    };
    process.once("SIGINT", handleSignal);
    process.once("SIGTERM", handleSignal);
  } catch (error) {
    await close();
    throw error;
  }
}
