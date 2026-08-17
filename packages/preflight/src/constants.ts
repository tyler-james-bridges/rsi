import type { CredentialAlias, PreflightProfile, SharingService } from "./types.js";

// Volatile pins are reviewed before every release. Node 24.19.0 was the current
// Node 24 LTS release when this Stage A block was prepared on 2026-08-14.
export const EXPECTED_NODE_VERSION = "24.19.0" as const;
export const EXPECTED_PNPM_VERSION = "11.20.0" as const;
export const MINIMUM_MACOS_VERSION = "26.6.1" as const;

export const MINIMUM_DISK_AVAILABLE_BYTES = 25 * 1024 * 1024 * 1024;
export const MINIMUM_DISK_AVAILABLE_PERCENT = 15;
export const CLOCK_WARN_SKEW_SECONDS = 2;
export const CLOCK_FAIL_SKEW_SECONDS = 5;
export const MAXIMUM_SUPERVISED_SESSION_MINUTES = 120;

export const EXPECTED_PROFILE_USER: Readonly<Record<Exclude<PreflightProfile, "dev">, string>> =
  Object.freeze({
    canary: "rsi-canary",
    "production-observer": "rsi-observer",
  });

export const SHARING_SERVICES: readonly SharingService[] = Object.freeze([
  "remote_login",
  "screen_sharing",
  "file_sharing",
  "remote_management",
]);

const REQUIRED_PROFILE_CREDENTIALS = Object.freeze([
  "x_read",
  "opensea_read",
  "alchemy_read",
  "b2_writer",
  "b2_outbox_writer",
  "resend_send",
  "healthchecks_ping",
  "checkpoint_signing",
  "capture_registry",
  "operations_state",
  "external_anchor_state",
  "alert_state",
  "session_state",
  "vault_wrapping",
] as const satisfies readonly CredentialAlias[]);

export const REQUIRED_CREDENTIALS: Readonly<
  Record<Exclude<PreflightProfile, "dev">, readonly CredentialAlias[]>
> = Object.freeze({
  canary: REQUIRED_PROFILE_CREDENTIALS,
  "production-observer": REQUIRED_PROFILE_CREDENTIALS,
});
