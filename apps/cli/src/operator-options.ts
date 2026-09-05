import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface OperatorOptions {
  readonly databasePath: string;
  readonly port: number;
  readonly researchDatabasePath: string;
}

function isMissingPath(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function isAtOrBelow(root: string, candidate: string): boolean {
  const offset = relative(root, candidate);
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
): void {
  const productionRoot = resolve(productionDataDirectory);
  const permittedStage0Root = join(productionRoot, "stage0");
  for (const path of [databasePath, researchDatabasePath]) {
    if (path === ":memory:") continue;
    const candidate = resolve(path);
    if (isAtOrBelow(productionRoot, candidate) && !isAtOrBelow(permittedStage0Root, candidate)) {
      throw new TypeError("The Stage 0 operator cannot open Stage 1 production storage");
    }
  }
}

const DEFAULT_DATABASE_PATH = ".local/stage0/rsi-runtime.sqlite";
const DEFAULT_RESEARCH_DATABASE_PATH = ".local/stage0/rsi-research.sqlite";

export function operatorUsage(): string {
  return [
    "Usage: pnpm operator [--db PATH] [--research-db PATH] [--port PORT]",
    "",
    "Starts RSI's signer-blind Stage 0 runtime and operator API on IPv4 loopback.",
    "Every process boot begins in STOPPED; this command cannot pay, sign, or execute.",
  ].join("\n");
}

export function parseOperatorOptions(args: readonly string[]): OperatorOptions | null {
  let databasePath = DEFAULT_DATABASE_PATH;
  let researchDatabasePath = DEFAULT_RESEARCH_DATABASE_PATH;
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
    throw new Error(`unknown argument: ${argument}`);
  }

  if (databasePath !== ":memory:" && researchDatabasePath !== ":memory:") {
    const normalizedRuntime = databasePath.replaceAll("\\", "/");
    const normalizedResearch = researchDatabasePath.replaceAll("\\", "/");
    if (normalizedRuntime === normalizedResearch) {
      throw new Error("--db and --research-db must use separate SQLite files");
    }
  }
  if (databasePath === ":memory:" && researchDatabasePath === ":memory:") {
    throw new Error("--db and --research-db must use separate SQLite files");
  }
  return { databasePath, port, researchDatabasePath };
}
