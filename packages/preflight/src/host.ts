import { execFile } from "node:child_process";
import { isAbsolute } from "node:path";

import type {
  CredentialAlias,
  PreflightProfile,
  ProbeResult,
  ReadOnlyProbeHost,
  ReadOnlyProbeRequest,
  SharingService,
} from "./types.js";

const COMMAND_TIMEOUT_MILLISECONDS = 3_000;
const COMMAND_MAX_BUFFER_BYTES = 64 * 1024;

const SHARING_LABELS: Readonly<Record<SharingService, string>> = Object.freeze({
  remote_login: "com.openssh.sshd",
  screen_sharing: "com.apple.screensharing",
  file_sharing: "com.apple.smbd",
  remote_management: "com.apple.RemoteDesktop.PrivilegeProxy",
});

const KEYCHAIN_SERVICES: Readonly<
  Record<Exclude<PreflightProfile, "dev">, Readonly<Record<CredentialAlias, string>>>
> = Object.freeze({
  canary: Object.freeze({
    x_read: "dev.rsi.canary.x-read",
    opensea_read: "dev.rsi.canary.opensea-read",
    alchemy_read: "dev.rsi.canary.alchemy-read",
    b2_writer: "dev.rsi.canary.b2-writer",
    b2_outbox_writer: "dev.rsi.canary.b2-outbox-writer",
    resend_send: "dev.rsi.canary.resend-send",
    healthchecks_ping: "dev.rsi.canary.healthchecks-ping",
    checkpoint_signing: "dev.rsi.canary.checkpoint-signing",
    capture_registry: "dev.rsi.canary.capture-registry",
    operations_state: "dev.rsi.canary.operations-state",
    external_anchor_state: "dev.rsi.canary.external-anchor-state",
    alert_state: "dev.rsi.canary.alert-state",
    session_state: "dev.rsi.canary.session-state",
    vault_wrapping: "dev.rsi.canary.vault-wrapping",
  }),
  "production-observer": Object.freeze({
    x_read: "dev.rsi.observer.x-read",
    opensea_read: "dev.rsi.observer.opensea-read",
    alchemy_read: "dev.rsi.observer.alchemy-read",
    b2_writer: "dev.rsi.observer.b2-writer",
    b2_outbox_writer: "dev.rsi.observer.b2-outbox-writer",
    resend_send: "dev.rsi.observer.resend-send",
    healthchecks_ping: "dev.rsi.observer.healthchecks-ping",
    checkpoint_signing: "dev.rsi.observer.checkpoint-signing",
    capture_registry: "dev.rsi.observer.capture-registry",
    operations_state: "dev.rsi.observer.operations-state",
    external_anchor_state: "dev.rsi.observer.external-anchor-state",
    alert_state: "dev.rsi.observer.alert-state",
    session_state: "dev.rsi.observer.session-state",
    vault_wrapping: "dev.rsi.observer.vault-wrapping",
  }),
});

export interface ExecFileRequest {
  readonly file: string;
  readonly args: readonly string[];
  readonly timeoutMilliseconds: number;
  readonly maxBufferBytes: number;
}

export interface ExecFileResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
}

export type SafeExecFile = (request: ExecFileRequest) => Promise<ExecFileResult>;

function defaultExecFile(request: ExecFileRequest): Promise<ExecFileResult> {
  return new Promise((resolve) => {
    execFile(
      request.file,
      [...request.args],
      {
        encoding: "utf8",
        env: {
          LANG: "C",
          LC_ALL: "C",
          PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        },
        maxBuffer: request.maxBufferBytes,
        shell: false,
        timeout: request.timeoutMilliseconds,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const errorCode = error === null ? 0 : typeof error.code === "number" ? error.code : null;
        resolve(
          Object.freeze({
            exitCode: errorCode,
            stdout,
            stderr,
            timedOut: error?.killed === true,
          }),
        );
      },
    );
  });
}

function invocationFor(
  request: ReadOnlyProbeRequest,
  workingDirectory: string,
): Readonly<{
  file: string;
  args: readonly string[];
  missingIsExpected: boolean;
}> | null {
  switch (request.kind) {
    case "os_version":
      return { file: "/usr/bin/sw_vers", args: ["-productVersion"], missingIsExpected: false };
    case "account_user":
      return { file: "/usr/bin/id", args: ["-un"], missingIsExpected: false };
    case "account_uid":
      return { file: "/usr/bin/id", args: ["-u"], missingIsExpected: false };
    case "account_groups":
      return { file: "/usr/bin/id", args: ["-Gn"], missingIsExpected: false };
    case "filevault":
      return { file: "/usr/bin/fdesetup", args: ["status"], missingIsExpected: false };
    case "firewall_global":
      return {
        file: "/usr/libexec/ApplicationFirewall/socketfilterfw",
        args: ["--getglobalstate"],
        missingIsExpected: false,
      };
    case "firewall_block_all":
      return {
        file: "/usr/libexec/ApplicationFirewall/socketfilterfw",
        args: ["--getblockall"],
        missingIsExpected: false,
      };
    case "firewall_stealth":
      return {
        file: "/usr/libexec/ApplicationFirewall/socketfilterfw",
        args: ["--getstealthmode"],
        missingIsExpected: false,
      };
    case "sharing_disabled":
      return {
        file: "/bin/launchctl",
        args: ["print-disabled", "system"],
        missingIsExpected: false,
      };
    case "sharing_loaded": {
      const label = SHARING_LABELS[request.service];
      if (label === undefined) return null;
      return {
        file: "/bin/launchctl",
        args: ["print", `system/${label}`],
        missingIsExpected: true,
      };
    }
    case "sleep":
      return { file: "/usr/bin/pmset", args: ["-g", "custom"], missingIsExpected: false };
    case "disk":
      return { file: "/bin/df", args: ["-Pk", workingDirectory], missingIsExpected: false };
    case "clock_sync_service":
      return {
        file: "/bin/launchctl",
        args: ["print", "system/com.apple.timed"],
        missingIsExpected: true,
      };
    case "credential_presence": {
      if (request.profile !== "canary" && request.profile !== "production-observer") return null;
      const keychainService = KEYCHAIN_SERVICES[request.profile][request.alias];
      if (keychainService === undefined) return null;
      return {
        file: "/usr/bin/security",
        // Deliberately omit -w and -g: only the exit status is consumed.
        args: ["find-generic-password", "-s", keychainService],
        missingIsExpected: true,
      };
    }
    default:
      return null;
  }
}

function classifyFailure(result: ExecFileResult, missingIsExpected: boolean): ProbeResult {
  if (result.timedOut) return Object.freeze({ status: "timed_out" });
  if (/not permitted|permission denied|authorization denied/iu.test(result.stderr)) {
    return Object.freeze({ status: "permission_denied" });
  }
  if (result.exitCode === null) return Object.freeze({ status: "unavailable" });
  if (missingIsExpected) return Object.freeze({ status: "not_found" });
  return Object.freeze({ status: "error" });
}

export interface DarwinReadOnlyProbeHostOptions {
  readonly workingDirectory: string;
  readonly platform?: NodeJS.Platform;
  readonly executor?: SafeExecFile;
}

export class DarwinReadOnlyProbeHost implements ReadOnlyProbeHost {
  readonly platform: NodeJS.Platform;
  readonly #workingDirectory: string;
  readonly #executor: SafeExecFile;

  constructor(options: DarwinReadOnlyProbeHostOptions) {
    if (!isAbsolute(options.workingDirectory) || options.workingDirectory.includes("\0")) {
      throw new TypeError("workingDirectory must be an absolute path");
    }
    this.platform = options.platform ?? process.platform;
    this.#workingDirectory = options.workingDirectory;
    this.#executor = options.executor ?? defaultExecFile;
  }

  async probe(request: ReadOnlyProbeRequest): Promise<ProbeResult> {
    if (this.platform !== "darwin") return Object.freeze({ status: "unavailable" });
    if (request.kind === "airplay_receiver") {
      // Apple exposes a UI and managed restriction, but no supported CLI status
      // source. Do not infer state from an undocumented preference key.
      return Object.freeze({ status: "unavailable" });
    }

    const invocation = invocationFor(request, this.#workingDirectory);
    if (invocation === null) return Object.freeze({ status: "error" });
    const result = await this.#executor({
      file: invocation.file,
      args: invocation.args,
      timeoutMilliseconds: COMMAND_TIMEOUT_MILLISECONDS,
      maxBufferBytes: COMMAND_MAX_BUFFER_BYTES,
    });
    if (result.exitCode !== 0) return classifyFailure(result, invocation.missingIsExpected);
    if (request.kind === "credential_presence") {
      // Treat even unexpected metadata output as secret-adjacent and discard it at
      // the host boundary. Callers receive presence only.
      return Object.freeze({ status: "ok", stdout: "" });
    }
    return Object.freeze({ status: "ok", stdout: result.stdout });
  }
}
