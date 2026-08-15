export const PREFLIGHT_SCHEMA_VERSION = "rsi.preflight.v1" as const;

export const PREFLIGHT_PROFILES = ["dev", "canary", "production-observer"] as const;
export type PreflightProfile = (typeof PREFLIGHT_PROFILES)[number];

export type PreflightStatus = "pass" | "warn" | "fail" | "unknown";

export type PreflightCheckId =
  | "platform"
  | "account"
  | "macos_version"
  | "filevault"
  | "firewall"
  | "sharing"
  | "sleep"
  | "disk"
  | "clock"
  | "runtime"
  | "credentials";

export type SanitizedFactValue = string | number | boolean | null | readonly string[];

export interface PreflightObservation {
  readonly checkId: PreflightCheckId;
  readonly status: PreflightStatus;
  readonly summary: string;
  readonly facts: Readonly<Record<string, SanitizedFactValue>>;
}

export interface PreflightReport {
  readonly schemaVersion: typeof PREFLIGHT_SCHEMA_VERSION;
  readonly profile: PreflightProfile;
  readonly observedAt: string;
  readonly ready: boolean;
  readonly counts: Readonly<Record<PreflightStatus, number>>;
  readonly observations: readonly PreflightObservation[];
}

export type SharingService =
  "remote_login" | "screen_sharing" | "file_sharing" | "remote_management";

export type CredentialAlias =
  | "x_read"
  | "opensea_read"
  | "alchemy_read"
  | "b2_writer"
  | "b2_outbox_writer"
  | "resend_send"
  | "healthchecks_ping"
  | "checkpoint_signing"
  | "capture_registry"
  | "operations_state"
  | "external_anchor_state"
  | "alert_state"
  | "session_state"
  | "vault_wrapping";

export type ReadOnlyProbeRequest =
  | Readonly<{ kind: "os_version" }>
  | Readonly<{ kind: "account_user" }>
  | Readonly<{ kind: "account_uid" }>
  | Readonly<{ kind: "account_groups" }>
  | Readonly<{ kind: "filevault" }>
  | Readonly<{ kind: "firewall_global" }>
  | Readonly<{ kind: "firewall_block_all" }>
  | Readonly<{ kind: "firewall_stealth" }>
  | Readonly<{ kind: "sharing_disabled" }>
  | Readonly<{ kind: "sharing_loaded"; service: SharingService }>
  | Readonly<{ kind: "airplay_receiver" }>
  | Readonly<{ kind: "sleep" }>
  | Readonly<{ kind: "disk" }>
  | Readonly<{ kind: "clock_sync_service" }>
  | Readonly<{
      kind: "credential_presence";
      profile: "canary" | "production-observer";
      alias: CredentialAlias;
    }>;

export type ProbeResult =
  | Readonly<{ status: "ok"; stdout: string }>
  | Readonly<{ status: "not_found" | "permission_denied" | "timed_out" | "unavailable" | "error" }>;

export interface ReadOnlyProbeHost {
  readonly platform: NodeJS.Platform;
  probe(request: ReadOnlyProbeRequest): Promise<ProbeResult>;
}

export interface RuntimeFacts {
  readonly nodeVersion: string;
  readonly pnpmVersion: string | null;
  readonly architecture: string;
}

export interface ClockReference {
  readonly sourceId: string;
  readonly epochMilliseconds: number;
}

export interface SupervisedSessionWakeAssertion {
  readonly scope: "supervised-session";
  readonly active: boolean;
  readonly acquiredAt: string;
  readonly expiresAt: string;
}

export interface RunPreflightInput {
  readonly profile: PreflightProfile;
  readonly host: ReadOnlyProbeHost;
  readonly observedAt: Date;
  readonly runtime: RuntimeFacts;
  readonly clockReferences?: readonly ClockReference[];
  readonly wakeAssertion?: SupervisedSessionWakeAssertion;
}
