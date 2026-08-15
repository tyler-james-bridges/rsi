import {
  EXPECTED_NODE_VERSION,
  EXPECTED_PNPM_VERSION,
  type PreflightObservation,
  type ProbeResult,
  type ReadOnlyProbeHost,
  type ReadOnlyProbeRequest,
  runPreflight,
} from "../src/index.js";
import { describe, expect, it } from "vitest";

const NOW = new Date("2026-08-14T12:00:00.000Z");
const SECRET_SENTINEL = "NEVER_PRINT_THIS_SECRET_VALUE";

function key(request: ReadOnlyProbeRequest): string {
  return JSON.stringify(request);
}

class FakeHost implements ReadOnlyProbeHost {
  readonly platform: NodeJS.Platform;
  readonly requests: ReadOnlyProbeRequest[] = [];
  readonly #results: Map<string, ProbeResult>;

  constructor(results: ReadonlyMap<string, ProbeResult>, platform: NodeJS.Platform = "darwin") {
    this.#results = new Map(results);
    this.platform = platform;
  }

  async probe(request: ReadOnlyProbeRequest): Promise<ProbeResult> {
    this.requests.push(request);
    const result = this.#results.get(key(request));
    if (result === undefined) throw new Error(`${SECRET_SENTINEL}: missing fixture`);
    return result;
  }
}

function ok(stdout: string): ProbeResult {
  return Object.freeze({ status: "ok", stdout });
}

function fixtureResults(): Map<string, ProbeResult> {
  const results = new Map<string, ProbeResult>();
  const add = (request: ReadOnlyProbeRequest, result: ProbeResult): void => {
    results.set(key(request), result);
  };
  add({ kind: "account_user" }, ok("rsi-observer\n"));
  add({ kind: "account_uid" }, ok("502\n"));
  add({ kind: "account_groups" }, ok("staff everyone localaccounts\n"));
  add({ kind: "os_version" }, ok("26.6.1\n"));
  add({ kind: "filevault" }, ok("FileVault is On.\n"));
  add({ kind: "firewall_global" }, ok("Firewall is enabled. (State = 1)\n"));
  add({ kind: "firewall_block_all" }, ok("Firewall block all is enabled. (State = 1)\n"));
  add({ kind: "firewall_stealth" }, ok("Firewall stealth mode is on\n"));
  add(
    { kind: "sharing_disabled" },
    ok(`disabled services = {
      "com.openssh.sshd" => true
      "com.apple.screensharing" => true
      "com.apple.smbd" => true
      "com.apple.RemoteDesktop.PrivilegeProxy" => true
    }`),
  );
  for (const service of [
    "remote_login",
    "screen_sharing",
    "file_sharing",
    "remote_management",
  ] as const) {
    add({ kind: "sharing_loaded", service }, Object.freeze({ status: "not_found" }));
  }
  add({ kind: "airplay_receiver" }, ok("0\n"));
  add({ kind: "sleep" }, ok("AC Power:\n sleep              30\n displaysleep       10\n"));
  add(
    { kind: "disk" },
    ok(
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3 900000000 1 104857600 10% /\n",
    ),
  );
  add({ kind: "clock_sync_service" }, ok("system/com.apple.timed = { state = running }\n"));
  for (const alias of [
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
  ] as const) {
    add(
      { kind: "credential_presence", profile: "production-observer", alias },
      ok(SECRET_SENTINEL),
    );
  }
  return results;
}

function healthyInput(host: ReadOnlyProbeHost) {
  return {
    profile: "production-observer" as const,
    host,
    observedAt: NOW,
    runtime: {
      nodeVersion: EXPECTED_NODE_VERSION,
      pnpmVersion: EXPECTED_PNPM_VERSION,
      architecture: "arm64",
    },
    clockReferences: [
      { sourceId: "reference-a", epochMilliseconds: NOW.getTime() + 1_000 },
      { sourceId: "reference-b", epochMilliseconds: NOW.getTime() - 1_000 },
    ],
    wakeAssertion: {
      scope: "supervised-session" as const,
      active: true,
      acquiredAt: "2026-08-14T11:59:00.000Z",
      expiresAt: "2026-08-14T13:59:00.000Z",
    },
  };
}

function find(report: { observations: readonly PreflightObservation[] }, checkId: string) {
  const item = report.observations.find((candidate) => candidate.checkId === checkId);
  if (item === undefined) throw new Error(`missing ${checkId}`);
  return item;
}

describe("runPreflight", () => {
  it("accepts a hardened observer fixture and never serializes probe output", async () => {
    const report = await runPreflight(healthyInput(new FakeHost(fixtureResults())));

    expect(report.ready).toBe(true);
    expect(report.profile).toBe("production-observer");
    expect(report.counts).toEqual({ pass: 11, warn: 0, fail: 0, unknown: 0 });
    expect(JSON.stringify(report)).not.toContain(SECRET_SENTINEL);
    expect(find(report, "credentials").facts.valuesRead).toBe(false);
  });

  it("fails the observer boundary for an admin account and Node 25", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "account_user" }), ok("tjb\n"));
    results.set(key({ kind: "account_groups" }), ok("staff admin everyone\n"));
    const input = healthyInput(new FakeHost(results));
    const report = await runPreflight({
      ...input,
      runtime: { ...input.runtime, nodeVersion: "25.8.1" },
    });

    expect(report.ready).toBe(false);
    expect(find(report, "account").status).toBe("fail");
    expect(find(report, "runtime").status).toBe("fail");
    expect(JSON.stringify(report)).not.toContain("tjb");
  });

  it("keeps a known root-account violation failed when another account fact is unavailable", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "account_uid" }), ok("0\n"));
    results.set(key({ kind: "account_groups" }), Object.freeze({ status: "unavailable" }));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "account").status).toBe("fail");
  });

  it("fails a known Node mismatch even when pnpm cannot be observed", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));
    const report = await runPreflight({
      ...input,
      runtime: { ...input.runtime, nodeVersion: "25.6.0", pnpmVersion: null },
    });

    expect(find(report, "runtime").status).toBe("fail");
    expect(report.ready).toBe(false);
  });

  it("rejects legacy or unknown profile identifiers", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));

    await expect(runPreflight({ ...input, profile: "observer" as never })).rejects.toThrow(
      TypeError,
    );
  });

  it("warns above two seconds of skew without making the report non-ready", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));
    const report = await runPreflight({
      ...input,
      clockReferences: [
        { sourceId: "reference-a", epochMilliseconds: NOW.getTime() + 2_500 },
        { sourceId: "reference-b", epochMilliseconds: NOW.getTime() - 1_000 },
      ],
    });

    expect(find(report, "clock").status).toBe("warn");
    expect(report.ready).toBe(true);
  });

  it("fails above five seconds of clock skew", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));
    const report = await runPreflight({
      ...input,
      clockReferences: [
        { sourceId: "reference-a", epochMilliseconds: NOW.getTime() + 5_001 },
        { sourceId: "reference-b", epochMilliseconds: NOW.getTime() },
      ],
    });

    expect(find(report, "clock").status).toBe("fail");
    expect(report.ready).toBe(false);
  });

  it("requires two distinct clock sources", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));
    const report = await runPreflight({
      ...input,
      clockReferences: [
        { sourceId: "same-source", epochMilliseconds: NOW.getTime() },
        { sourceId: "same-source", epochMilliseconds: NOW.getTime() },
      ],
    });

    expect(find(report, "clock").status).toBe("unknown");
    expect(report.ready).toBe(false);
  });

  it("fails when the automatic time-synchronization service is absent", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "clock_sync_service" }), Object.freeze({ status: "not_found" }));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "clock").status).toBe("fail");
    expect(report.ready).toBe(false);
  });

  it("returns unknown when time-synchronization service state cannot be verified", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "clock_sync_service" }), Object.freeze({ status: "unavailable" }));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "clock").status).toBe("unknown");
    expect(report.ready).toBe(false);
  });

  it("requires both disk thresholds", async () => {
    const results = fixtureResults();
    results.set(
      key({ kind: "disk" }),
      ok(
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3 100000000 1 31457280 86% /\n",
      ),
    );
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "disk").status).toBe("fail");
    expect(find(report, "disk").facts.availableGiB).toBe(30);
    expect(find(report, "disk").facts.availablePercent).toBe(14);
  });

  it("keeps a known firewall violation failed when another flag is unavailable", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "firewall_global" }), ok("Firewall is disabled. (State = 0)\n"));
    results.set(key({ kind: "firewall_stealth" }), Object.freeze({ status: "unavailable" }));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "firewall").status).toBe("fail");
  });

  it("treats an unloaded service without a disabled override as unknown", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "sharing_disabled" }), ok("disabled services = {}\n"));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "sharing").status).toBe("unknown");
    expect(report.ready).toBe(false);
  });

  it("fails when AirPlay Receiver is enabled", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "airplay_receiver" }), ok("1\n"));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "sharing").status).toBe("fail");
    expect(find(report, "sharing").facts.airplayReceiverEnabled).toBe(true);
    expect(report.ready).toBe(false);
  });

  it("fails when AC sleep is globally disabled", async () => {
    const results = fixtureResults();
    results.set(key({ kind: "sleep" }), ok("AC Power:\n sleep              0\n"));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "sleep").status).toBe("fail");
    expect(find(report, "sleep").facts.normalSleepPolicyEnabled).toBe(false);
  });

  it("requires an injected wake assertion for a live profile", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));
    const { wakeAssertion: _wakeAssertion, ...withoutWakeAssertion } = input;
    const report = await runPreflight(withoutWakeAssertion);

    expect(find(report, "sleep").status).toBe("unknown");
    expect(report.ready).toBe(false);
  });

  it("rejects an overlong supervised-session wake assertion", async () => {
    const input = healthyInput(new FakeHost(fixtureResults()));
    const report = await runPreflight({
      ...input,
      wakeAssertion: {
        ...input.wakeAssertion,
        acquiredAt: "2026-08-14T12:00:00.000Z",
        expiresAt: "2026-08-14T14:00:00.001Z",
      },
    });

    expect(find(report, "sleep").status).toBe("fail");
    expect(find(report, "sleep").facts.wakeAssertionBounded).toBe(false);
  });

  it("reports missing credential aliases without reading values", async () => {
    const results = fixtureResults();
    results.set(
      key({ kind: "credential_presence", profile: "production-observer", alias: "x_read" }),
      Object.freeze({ status: "not_found" }),
    );
    const report = await runPreflight(healthyInput(new FakeHost(results)));
    const credentials = find(report, "credentials");

    expect(credentials.status).toBe("fail");
    expect(credentials.facts.missingAliases).toEqual(["x_read"]);
    expect(credentials.facts.valuesRead).toBe(false);
  });

  it("keeps a known missing credential failed when another alias is unverifiable", async () => {
    const results = fixtureResults();
    results.set(
      key({ kind: "credential_presence", profile: "production-observer", alias: "x_read" }),
      Object.freeze({ status: "not_found" }),
    );
    results.set(
      key({
        kind: "credential_presence",
        profile: "production-observer",
        alias: "opensea_read",
      }),
      Object.freeze({ status: "unavailable" }),
    );
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "credentials").status).toBe("fail");
  });

  it("collapses thrown probe details to content-free unknown status", async () => {
    const results = fixtureResults();
    results.delete(key({ kind: "filevault" }));
    const report = await runPreflight(healthyInput(new FakeHost(results)));

    expect(find(report, "filevault").status).toBe("unknown");
    expect(JSON.stringify(report)).not.toContain(SECRET_SENTINEL);
  });
});
