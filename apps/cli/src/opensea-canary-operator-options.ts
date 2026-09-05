import {
  productionOpenSeaCanaryHostOptions,
  type ProductionOpenSeaCanaryHostOptions,
} from "./production-canary-config.js";

export function openSeaCanaryOperatorUsage(): string {
  return [
    "Usage: pnpm operator:opensea-canary",
    "",
    "Starts RSI's loopback-only OpenSea Base trending read canary on its fixed port.",
    "Runtime paths and port are code-owned; this command cannot pay, sign, order, or transact.",
  ].join("\n");
}

export function parseOpenSeaCanaryOperatorOptions(
  args: readonly string[],
): Readonly<ProductionOpenSeaCanaryHostOptions> | null {
  for (const argument of args) {
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return null;
    throw new Error("OpenSea canary production options are fixed");
  }
  return productionOpenSeaCanaryHostOptions();
}
