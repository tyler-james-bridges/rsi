import {
  productionXCanaryHostOptions,
  type ProductionXCanaryHostOptions,
} from "./production-canary-config.js";

export function xCanaryOperatorUsage(): string {
  return [
    "Usage: pnpm operator:x-canary",
    "",
    "Starts RSI's signer-blind Stage 1 X read-canary runtime on its fixed loopback port.",
    "Runtime paths and port are code-owned; this command cannot pay, sign, or execute.",
  ].join("\n");
}

export function parseXCanaryOperatorOptions(
  args: readonly string[],
): Readonly<ProductionXCanaryHostOptions> | null {
  for (const argument of args) {
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return null;
    throw new Error("X canary production options are fixed");
  }
  return productionXCanaryHostOptions();
}
