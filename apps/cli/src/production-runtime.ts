export const PRODUCTION_NODE_VERSION = "24.19.0" as const;
export const PRODUCTION_PNPM_VERSION = "11.20.0" as const;
export const PRODUCTION_RUNTIME_FAILURE_MESSAGE =
  "RSI live canary startup refused because the exact production runtime is unavailable.\n" as const;

export interface ProductionRuntimeIdentity {
  readonly nodeVersion: string;
  readonly packageManagerUserAgent: string;
}

function pnpmVersionFromUserAgent(value: string): string | null {
  const matches = [...value.matchAll(/(?:^|\s)pnpm\/([^\s]+)/gu)];
  return matches.length === 1 ? (matches[0]?.[1] ?? null) : null;
}

/** Pure fail-closed assertion over an explicitly supplied runtime identity. */
export function assertExactProductionRuntime(value: ProductionRuntimeIdentity): void {
  if (
    value.nodeVersion !== PRODUCTION_NODE_VERSION ||
    pnpmVersionFromUserAgent(value.packageManagerUserAgent) !== PRODUCTION_PNPM_VERSION
  ) {
    throw new Error(PRODUCTION_RUNTIME_FAILURE_MESSAGE.trim());
  }
}

/** The only production bridge from ambient process metadata into the pure assertion. */
export function assertActiveProductionRuntime(): void {
  assertExactProductionRuntime({
    nodeVersion: process.versions.node,
    packageManagerUserAgent: process.env.npm_config_user_agent ?? "",
  });
}
