import {
  DarwinReadOnlyProbeHost,
  type ExecFileRequest,
  type ExecFileResult,
  type ReadOnlyProbeRequest,
} from "../src/index.js";
import { describe, expect, it } from "vitest";

function successfulResult(stdout = "fixture"): ExecFileResult {
  return Object.freeze({ exitCode: 0, stdout, stderr: "", timedOut: false });
}

const ALL_REQUESTS: readonly ReadOnlyProbeRequest[] = Object.freeze([
  { kind: "os_version" },
  { kind: "account_user" },
  { kind: "account_uid" },
  { kind: "account_groups" },
  { kind: "filevault" },
  { kind: "firewall_global" },
  { kind: "firewall_block_all" },
  { kind: "firewall_stealth" },
  { kind: "sharing_disabled" },
  { kind: "sharing_loaded", service: "remote_login" },
  { kind: "sharing_loaded", service: "screen_sharing" },
  { kind: "sharing_loaded", service: "file_sharing" },
  { kind: "sharing_loaded", service: "remote_management" },
  { kind: "sleep" },
  { kind: "disk" },
  { kind: "clock_sync_service" },
  { kind: "credential_presence", profile: "canary", alias: "x_read" },
  { kind: "credential_presence", profile: "production-observer", alias: "vault_wrapping" },
]);

describe("DarwinReadOnlyProbeHost", () => {
  it("maps every probe to bounded fixed-path read-only execFile calls", async () => {
    const invocations: ExecFileRequest[] = [];
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async (request) => {
        invocations.push(request);
        return successfulResult();
      },
    });

    for (const request of ALL_REQUESTS) await host.probe(request);

    expect(invocations).toHaveLength(ALL_REQUESTS.length);
    expect(invocations.every(({ file }) => file.startsWith("/"))).toBe(true);
    expect(invocations.every(({ timeoutMilliseconds }) => timeoutMilliseconds === 3_000)).toBe(
      true,
    );
    expect(invocations.every(({ maxBufferBytes }) => maxBufferBytes === 64 * 1024)).toBe(true);
    const allArgs = invocations.flatMap(({ args }) => args);
    expect(allArgs).not.toContain("-w");
    expect(allArgs).not.toContain("write");
    expect(allArgs).not.toContain("delete");
    expect(allArgs).not.toContain("set");
    expect(allArgs.some((arg) => arg.startsWith("--set"))).toBe(false);
    const securityArgs = invocations.find(({ file }) => file === "/usr/bin/security")?.args;
    expect(securityArgs).not.toContain("-g");
    expect(securityArgs).toEqual(["find-generic-password", "-s", "dev.rsi.canary.x-read"]);
  });

  it("does not invoke commands on a non-macOS platform", async () => {
    let called = false;
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/tmp/rsi",
      platform: "linux",
      executor: async () => {
        called = true;
        return successfulResult();
      },
    });

    await expect(host.probe({ kind: "os_version" })).resolves.toEqual({ status: "unavailable" });
    expect(called).toBe(false);
  });

  it("returns unavailable for AirPlay instead of trusting an undocumented preference", async () => {
    let called = false;
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/tmp/rsi",
      platform: "darwin",
      executor: async () => {
        called = true;
        return successfulResult();
      },
    });

    await expect(host.probe({ kind: "airplay_receiver" })).resolves.toEqual({
      status: "unavailable",
    });
    expect(called).toBe(false);
  });

  it("keeps canary and production-observer Keychain namespaces separate", async () => {
    const invocations: ExecFileRequest[] = [];
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async (request) => {
        invocations.push(request);
        return successfulResult();
      },
    });

    await host.probe({ kind: "credential_presence", profile: "canary", alias: "x_read" });
    await host.probe({
      kind: "credential_presence",
      profile: "production-observer",
      alias: "x_read",
    });

    expect(invocations.map(({ args }) => args)).toEqual([
      ["find-generic-password", "-s", "dev.rsi.canary.x-read"],
      ["find-generic-password", "-s", "dev.rsi.observer.x-read"],
    ]);
  });

  it("maps the operations state key to a dedicated per-profile service", async () => {
    const invocations: ExecFileRequest[] = [];
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async (request) => {
        invocations.push(request);
        return successfulResult();
      },
    });

    await host.probe({
      kind: "credential_presence",
      profile: "canary",
      alias: "operations_state",
    });
    await host.probe({
      kind: "credential_presence",
      profile: "production-observer",
      alias: "operations_state",
    });

    expect(invocations.map(({ args }) => args)).toEqual([
      ["find-generic-password", "-s", "dev.rsi.canary.operations-state"],
      ["find-generic-password", "-s", "dev.rsi.observer.operations-state"],
    ]);
  });

  it("keeps every durable control-plane state key in a dedicated service", async () => {
    const invocations: ExecFileRequest[] = [];
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async (request) => {
        invocations.push(request);
        return successfulResult();
      },
    });

    for (const alias of ["external_anchor_state", "alert_state", "session_state"] as const) {
      await host.probe({ kind: "credential_presence", profile: "canary", alias });
      await host.probe({
        kind: "credential_presence",
        profile: "production-observer",
        alias,
      });
    }

    expect(invocations.map(({ args }) => args)).toEqual([
      ["find-generic-password", "-s", "dev.rsi.canary.external-anchor-state"],
      ["find-generic-password", "-s", "dev.rsi.observer.external-anchor-state"],
      ["find-generic-password", "-s", "dev.rsi.canary.alert-state"],
      ["find-generic-password", "-s", "dev.rsi.observer.alert-state"],
      ["find-generic-password", "-s", "dev.rsi.canary.session-state"],
      ["find-generic-password", "-s", "dev.rsi.observer.session-state"],
    ]);
  });

  it("maps the capture registry key to a dedicated per-profile service", async () => {
    const invocations: ExecFileRequest[] = [];
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async (request) => {
        invocations.push(request);
        return successfulResult();
      },
    });

    await host.probe({
      kind: "credential_presence",
      profile: "canary",
      alias: "capture_registry",
    });
    await host.probe({
      kind: "credential_presence",
      profile: "production-observer",
      alias: "capture_registry",
    });

    expect(invocations.map(({ args }) => args)).toEqual([
      ["find-generic-password", "-s", "dev.rsi.canary.capture-registry"],
      ["find-generic-password", "-s", "dev.rsi.observer.capture-registry"],
    ]);
  });

  it("maps the review-outbox writer separately from the checkpoint writer", async () => {
    const invocations: ExecFileRequest[] = [];
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async (request) => {
        invocations.push(request);
        return successfulResult();
      },
    });

    await host.probe({
      kind: "credential_presence",
      profile: "canary",
      alias: "b2_writer",
    });
    await host.probe({
      kind: "credential_presence",
      profile: "canary",
      alias: "b2_outbox_writer",
    });

    expect(invocations.map(({ args }) => args)).toEqual([
      ["find-generic-password", "-s", "dev.rsi.canary.b2-writer"],
      ["find-generic-password", "-s", "dev.rsi.canary.b2-outbox-writer"],
    ]);
  });

  it("cannot resolve live credentials for the dev profile", async () => {
    let called = false;
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async () => {
        called = true;
        return successfulResult();
      },
    });
    const invalidRequest = {
      kind: "credential_presence",
      profile: "dev",
      alias: "x_read",
    } as unknown as ReadOnlyProbeRequest;

    await expect(host.probe(invalidRequest)).resolves.toEqual({ status: "error" });
    expect(called).toBe(false);
  });

  it("rejects unknown credential aliases before invoking Keychain", async () => {
    let called = false;
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async () => {
        called = true;
        return successfulResult();
      },
    });
    const invalidRequest = {
      kind: "credential_presence",
      profile: "canary",
      alias: "unknown_alias",
    } as unknown as ReadOnlyProbeRequest;

    await expect(host.probe(invalidRequest)).resolves.toEqual({ status: "error" });
    expect(called).toBe(false);
  });

  it("discards all successful Keychain command output at the host boundary", async () => {
    const host = new DarwinReadOnlyProbeHost({
      workingDirectory: "/private/var/rsi",
      platform: "darwin",
      executor: async () => successfulResult("SECRET-ADJACENT KEYCHAIN METADATA"),
    });

    await expect(
      host.probe({ kind: "credential_presence", profile: "canary", alias: "x_read" }),
    ).resolves.toEqual({ status: "ok", stdout: "" });
  });

  it("maps timeouts and permission failures to content-free statuses", async () => {
    const timeoutHost = new DarwinReadOnlyProbeHost({
      workingDirectory: "/tmp/rsi",
      platform: "darwin",
      executor: async () => ({
        exitCode: null,
        stdout: "sensitive output",
        stderr: "sensitive error",
        timedOut: true,
      }),
    });
    await expect(timeoutHost.probe({ kind: "filevault" })).resolves.toEqual({
      status: "timed_out",
    });

    const permissionHost = new DarwinReadOnlyProbeHost({
      workingDirectory: "/tmp/rsi",
      platform: "darwin",
      executor: async () => ({
        exitCode: 1,
        stdout: "",
        stderr: "Operation not permitted: sensitive path",
        timedOut: false,
      }),
    });
    await expect(permissionHost.probe({ kind: "filevault" })).resolves.toEqual({
      status: "permission_denied",
    });
  });

  it("rejects relative and nul-containing working directories", () => {
    expect(() => new DarwinReadOnlyProbeHost({ workingDirectory: "relative" })).toThrow(TypeError);
    expect(() => new DarwinReadOnlyProbeHost({ workingDirectory: "/tmp/rsi\0bad" })).toThrow(
      TypeError,
    );
  });
});
