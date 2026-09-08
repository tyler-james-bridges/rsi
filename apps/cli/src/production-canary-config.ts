import { resolve } from "node:path";

const CLI_PACKAGE_DIRECTORY = resolve(import.meta.dirname, "..");
const PRODUCTION_DATA_DIRECTORY = resolve(CLI_PACKAGE_DIRECTORY, ".local");

export const PRODUCTION_CANARY_PORT = 8_787 as const;

export interface ProductionOpenSeaCanaryHostOptions {
  readonly databasePath: string;
  readonly port: typeof PRODUCTION_CANARY_PORT;
}

export interface ProductionBaseRpcCanaryHostOptions {
  readonly databasePath: string;
  readonly port: typeof PRODUCTION_CANARY_PORT;
}

export interface ProductionXCanaryHostOptions {
  readonly databasePath: string;
  readonly port: typeof PRODUCTION_CANARY_PORT;
  readonly researchDatabasePath: string;
}

export function productionOpenSeaCanaryHostOptions(): Readonly<ProductionOpenSeaCanaryHostOptions> {
  return Object.freeze({
    databasePath: resolve(PRODUCTION_DATA_DIRECTORY, "rsi-opensea-canary-runtime.sqlite"),
    port: PRODUCTION_CANARY_PORT,
  });
}

export function productionBaseRpcCanaryHostOptions(): Readonly<ProductionBaseRpcCanaryHostOptions> {
  return Object.freeze({
    databasePath: resolve(PRODUCTION_DATA_DIRECTORY, "rsi-base-rpc-canary-runtime.sqlite"),
    port: PRODUCTION_CANARY_PORT,
  });
}

export function productionXCanaryHostOptions(): Readonly<ProductionXCanaryHostOptions> {
  return Object.freeze({
    databasePath: resolve(PRODUCTION_DATA_DIRECTORY, "rsi-runtime.sqlite"),
    port: PRODUCTION_CANARY_PORT,
    researchDatabasePath: resolve(PRODUCTION_DATA_DIRECTORY, "rsi-research.sqlite"),
  });
}

export function productionXCanaryEventStorePath(): string {
  return resolve(PRODUCTION_DATA_DIRECTORY, "rsi-x-canary-events.sqlite");
}
