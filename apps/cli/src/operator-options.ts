export interface OperatorOptions {
  readonly databasePath: string;
  readonly port: number;
  readonly seed: boolean;
}

const DEFAULT_DATABASE_PATH = ".local/rsi.sqlite";

export function operatorUsage(): string {
  return [
    "Usage: pnpm operator [--db PATH] [--port PORT] [--seed]",
    "",
    "Starts RSI's read-only operator API on IPv4 loopback.",
    "--seed evaluates the recorded adversarial fixture corpus first.",
  ].join("\n");
}

export function parseOperatorOptions(args: readonly string[]): OperatorOptions | null {
  let databasePath = DEFAULT_DATABASE_PATH;
  let port = 8_787;
  let seed = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    // pnpm may forward one or more option separators to the child command.
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return null;
    if (argument === "--seed") {
      seed = true;
      continue;
    }
    if (argument === "--db") {
      const value = args[index + 1];
      if (value === undefined || value.length === 0) throw new Error("--db requires a path");
      databasePath = value;
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

  return { databasePath, port, seed };
}
