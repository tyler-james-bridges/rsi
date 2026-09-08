export function baseRpcCanaryOperatorUsage(): string {
  return [
    "Usage: pnpm operator:base-rpc-canary",
    "",
    "Starts RSI's loopback-only Base mainnet finalized-anchor read canary on its fixed port.",
    "Runtime paths and port are code-owned; this command cannot pay, sign, or transact.",
  ].join("\n");
}

export function parseBaseRpcCanaryOperatorOptions(args: readonly string[]): true | null {
  for (const argument of args) {
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return null;
    throw new Error("Base RPC canary production options are fixed");
  }
  return true;
}
