import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface OperatorOptions {
  readonly attentionDatabasePath: string;
  readonly databasePath: string;
  readonly port: number;
  readonly researchDatabasePath: string;
  readonly watchlistDatabasePath: string;
}

function isMissingPath(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function storageContainmentIdentity(path: string): string {
  return resolve(path).normalize("NFC").toLowerCase();
}

function isAtOrBelow(root: string, candidate: string): boolean {
  const offset = relative(storageContainmentIdentity(root), storageContainmentIdentity(candidate));
  return (
    offset === "" || (offset !== ".." && !offset.startsWith(`..${sep}`) && !isAbsolute(offset))
  );
}

/** Resolves the nearest existing ancestor without creating any part of the requested path. */
export async function resolveProspectiveStoragePath(path: string): Promise<string> {
  if (path === ":memory:") return path;
  let existingAncestor = resolve(path);
  const unresolvedSegments: string[] = [];
  for (;;) {
    try {
      return resolve(await realpath(existingAncestor), ...unresolvedSegments);
    } catch (error) {
      if (!isMissingPath(error)) throw error;
      const parent = dirname(existingAncestor);
      if (parent === existingAncestor) throw error;
      unresolvedSegments.unshift(basename(existingAncestor));
      existingAncestor = parent;
    }
  }
}

export function assertStage0StorageIsolation(
  databasePath: string,
  researchDatabasePath: string,
  productionDataDirectory: string,
  watchlistDatabasePath?: string,
  attentionDatabasePath?: string,
): void {
  const productionRoot = resolve(productionDataDirectory);
  const permittedStage0Root = join(productionRoot, "stage0");
  for (const path of [
    databasePath,
    researchDatabasePath,
    ...(watchlistDatabasePath === undefined ? [] : [watchlistDatabasePath]),
    ...(attentionDatabasePath === undefined ? [] : [attentionDatabasePath]),
  ]) {
    if (path === ":memory:") continue;
    const candidate = resolve(path);
    if (isAtOrBelow(productionRoot, candidate) && !isAtOrBelow(permittedStage0Root, candidate)) {
      throw new TypeError("The Stage 0 operator cannot open Stage 1 production storage");
    }
  }
}

export function assertDistinctStage0DatabasePaths(paths: readonly string[]): void {
  const identities = paths.map((path) =>
    path === ":memory:" ? path : resolve(path).normalize("NFC"),
  );
  if (new Set(identities).size !== identities.length) {
    throw new TypeError("Stage 0 databases must use separate SQLite files");
  }
}

const DEFAULT_DATABASE_PATH = ".local/stage0/rsi-runtime.sqlite";
const DEFAULT_RESEARCH_DATABASE_PATH = ".local/stage0/rsi-research.sqlite";
const DEFAULT_ATTENTION_DATABASE_PATH = ".local/stage0/rsi-attention.sqlite";

export function operatorUsage(): string {
  return [
    "Usage: pnpm operator [--db PATH] [--research-db PATH] [--watchlist-db PATH] [--attention-db PATH] [--port PORT]",
    "",
    "Starts RSI's signer-blind Stage 0 runtime and operator API on IPv4 loopback.",
    "Every process boot begins in STOPPED; this command cannot pay, sign, or execute.",
  ].join("\n");
}

export function parseOperatorOptions(args: readonly string[]): OperatorOptions | null {
  let databasePath = DEFAULT_DATABASE_PATH;
  let researchDatabasePath = DEFAULT_RESEARCH_DATABASE_PATH;
  let attentionDatabasePath: string | undefined;
  let watchlistDatabasePath: string | undefined;
  let port = 8_787;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    // pnpm may forward one or more option separators to the child command.
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return null;
    if (argument === "--db") {
      const value = args[index + 1];
      if (value === undefined || value.length === 0) throw new Error("--db requires a path");
      databasePath = value;
      index += 1;
      continue;
    }
    if (argument === "--research-db") {
      const value = args[index + 1];
      if (value === undefined || value.length === 0) {
        throw new Error("--research-db requires a path");
      }
      researchDatabasePath = value;
      index += 1;
      continue;
    }
    if (argument === "--attention-db") {
      const value = args[index + 1];
      if (value === undefined || value.length === 0) {
        throw new Error("--attention-db requires a path");
      }
      attentionDatabasePath = value;
      index += 1;
      continue;
    }
    if (argument === "--port") {
      const value = args[index + 1];
      if (value === undefined || !/^\d{1,5}$/.test(value)) {
        throw new Error("--port requires an integer from 0 through 65535");
      }
      port = Number(value);
      if (port > 65_535) throw new Error("--port requires an integer from 0 through 65535");
      index += 1;
      continue;
    }
    if (argument === "--watchlist-db") {
      const value = args[index + 1];
      if (value === undefined || value.length === 0)
        throw new Error("--watchlist-db requires a path");
      watchlistDatabasePath = value;
      index += 1;
      continue;
    }
    throw new Error(`unknown argument: ${argument}`);
  }
  watchlistDatabasePath ??= join(dirname(researchDatabasePath), "rsi-watchlist.sqlite");
  attentionDatabasePath ??=
    researchDatabasePath === DEFAULT_RESEARCH_DATABASE_PATH
      ? DEFAULT_ATTENTION_DATABASE_PATH
      : join(dirname(researchDatabasePath), "rsi-attention.sqlite");
  assertDistinctStage0DatabasePaths([
    databasePath,
    researchDatabasePath,
    watchlistDatabasePath,
    attentionDatabasePath,
  ]);
  return {
    attentionDatabasePath,
    databasePath,
    port,
    researchDatabasePath,
    watchlistDatabasePath,
  };
}
