export interface OpenSeaCanaryOperatorOptions {
  readonly databasePath: string;
  readonly port: number;
}

const DEFAULT_DATABASE_PATH = ".local/rsi-opensea-canary-runtime.sqlite";

export function openSeaCanaryOperatorUsage(): string {
  return [
    "Usage: pnpm operator:opensea-canary [--db PATH] [--port PORT]",
    "",
    "Starts RSI's loopback-only OpenSea Base trending read canary.",
    "Every process boot begins STOPPED; this command cannot pay, sign, order, or transact.",
  ].join("\n");
}

export function parseOpenSeaCanaryOperatorOptions(
  args: readonly string[],
): OpenSeaCanaryOperatorOptions | null {
  let databasePath = DEFAULT_DATABASE_PATH;
  let port = 8_787;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return null;
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
  if (databasePath === ":memory:") {
    throw new Error("The OpenSea canary requires durable storage");
  }
  return Object.freeze({ databasePath, port });
}
