export interface OperatorOptions {
  readonly databasePath: string;
  readonly port: number;
  readonly researchDatabasePath: string;
}

const DEFAULT_DATABASE_PATH = ".local/rsi-runtime.sqlite";
const DEFAULT_RESEARCH_DATABASE_PATH = ".local/rsi-research.sqlite";

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
