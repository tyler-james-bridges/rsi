import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  getBaseRpcReadCanaryPlan,
} from "@rsi/read-canary/base-rpc";
import { SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  PRODUCTION_STARTUP_SIGNALS,
  captureProductionSignalListeners,
  deferred,
  invokeAddedProductionSignalListener,
  productionSignalListenersMatch,
  removeAddedProductionSignalListeners,
} from "./production-entry-lifecycle-helpers.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const TSX_CLI = fileURLToPath(new URL("../../../node_modules/tsx/dist/cli.mjs", import.meta.url));
const FIXTURE_ENTRY = fileURLToPath(
  new URL("./fixtures/base-rpc-canary-operator-process-fixture.ts", import.meta.url),
);
const PRODUCTION_ENTRY = fileURLToPath(
  new URL("../src/base-rpc-canary-operator.ts", import.meta.url),
);

function waitForLine(
  child: ChildProcessWithoutNullStreams,
  predicate: (value: unknown) => boolean,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timeout = setTimeout(
      () => reject(new Error("Base RPC operator output timed out")),
      10_000,
    );
    const onData = (chunk: Buffer): void => {
      buffer += chunk.toString("utf8");
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) return;
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        try {
          const value: unknown = JSON.parse(line);
          if (!predicate(value)) continue;
          clearTimeout(timeout);
          child.stdout.off("data", onData);
          resolve(value);
          return;
        } catch {
          // Ignore non-JSON diagnostics.
        }
      }
    };
    child.stdout.on("data", onData);
    child.once("error", reject);
  });
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Base RPC shutdown timed out")), 10_000);
    child.once("error", reject);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve(code);
    });
  });
}

function headers(origin: string): Record<string, string> {
  return {
    "content-type": "application/json",
    origin,
    "sec-fetch-site": "same-origin",
    "x-rsi-operator-request": "1",
  };
}

describe("Base RPC canary CLI process", () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let directory: string | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.resetModules();
    if (child !== undefined && child.exitCode === null && child.signalCode === null) {
      const exited = waitForExit(child);
      child.kill("SIGTERM");
      await exited.catch(() => child?.kill("SIGKILL"));
    }
    child = undefined;
    if (directory !== undefined) await rm(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it("boots without API credential or egress, runs exactly once, and persists STOP", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-base-rpc-process-"));
    const runtimePath = join(directory, "runtime.sqlite");
    let stderr = "";
    let stdout = "";
    child = spawn(process.execPath, [TSX_CLI, FIXTURE_ENTRY, runtimePath], {
      cwd: ROOT,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });

    const startup = (await waitForLine(
      child,
      (value) =>
        typeof value === "object" &&
        value !== null &&
        (value as { mode?: unknown }).mode === "stage1-base-rpc-read-canary-test-fixture",
    )) as {
      apiKeyValueReads: number;
      baseRpcRequests: number;
      claimCommands: number;
      claimStatusCommands: number;
      credentialCommands: number;
      credentialValueReads: number;
      origin: string;
      runtimeMode: string;
    };
    expect(startup).toMatchObject({
      apiKeyValueReads: 0,
      baseRpcRequests: 0,
      claimCommands: 0,
      claimStatusCommands: 1,
      credentialCommands: 3,
      credentialValueReads: 3,
      runtimeMode: "STOPPED",
    });

    const runtimeResponse = await fetch(`${startup.origin}/api/runtime`);
    const runtime = (await runtimeResponse.json()) as {
      runtime: { mode: "STOPPED"; revision: number };
    };
    const transition = await fetch(`${startup.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: runtime.runtime.revision,
        requestId: randomUUID(),
      }),
      headers: headers(startup.origin),
      method: "POST",
    });
    const transitioned = (await transition.json()) as { result: { revision: number } };
    expect(transition.status).toBe(200);

    const plan = getBaseRpcReadCanaryPlan();
    const runResponse = await fetch(`${startup.origin}/api/base-rpc-read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: plan.planId,
        expectedRuntimeRevision: transitioned.result.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: plan.planId,
        oneRequestAcknowledgement: true,
        nonPaymentReadAcknowledgement: true,
        noTransactionAuthorityAcknowledgement: true,
        finalizedAnchorAcknowledgement: true,
        methodSetAcknowledgement: BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
        ledgerReserveUsdMicrosAcknowledgement: plan.ledgerReserveUsdMicros,
      }),
      headers: headers(startup.origin),
      method: "POST",
    });
    const run = await runResponse.json();
    expect(runResponse.status).toBe(200);
    expect(run).toEqual({
      result: {
        schemaVersion: 1,
        planId: "base-mainnet-finalized-anchor-v1",
        outcome: "accepted",
        providerReportedFinalized: true,
        freshnessVerdict: "fresh",
      },
    });
    const serialized = JSON.stringify(run);
    for (const forbidden of [
      "offline-process-alchemy-api-key",
      "1234abcd",
      "111111",
      "222222",
      "capture",
      "eventHash",
      "authorizationId",
      "requestId",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }

    const closedLine = waitForLine(
      child,
      (value) =>
        typeof value === "object" &&
        value !== null &&
        (value as { closed?: unknown }).closed === true,
    );
    const exited = waitForExit(child);
    child.kill("SIGINT");
    await expect(closedLine).resolves.toEqual({
      apiKeyValueReads: 1,
      baseRpcRequests: 1,
      claimCommands: 1,
      claimStatusCommands: 1,
      closed: true,
      credentialCommands: 7,
      credentialValueReads: 7,
    });
    expect(await exited).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).not.toContain("offline-process-alchemy-api-key");
    expect(stdout).not.toContain("1234abcd");
    await expect(lstat(join(directory, ".rsi-stage1-canary.lock"))).rejects.toMatchObject({
      code: "ENOENT",
    });

    const reopened = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    expect(reopened.getSnapshot().mode).toBe("STOPPED");
    expect(reopened.listAudit().at(-2)).toMatchObject({
      payload: { to: "STOPPED" },
      type: "runtime.stop.enforced.v1",
    });
    reopened.close();
  });

  it("refuses the wrong runtime before production host startup", async () => {
    let stderr = "";
    let stdout = "";
    child = spawn(process.execPath, [TSX_CLI, PRODUCTION_ENTRY], {
      cwd: ROOT,
      env: { ...process.env, npm_config_user_agent: "pnpm/0.0.0" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });

    expect(await waitForExit(child)).toBe(1);
    expect(stdout).toBe("");
    expect(stderr).toBe(
      "RSI live canary startup refused because the exact production runtime is unavailable.\n",
    );
  });

  it("redacts a production host initialization failure without an uncaught diagnostic", async () => {
    const originalArgv = process.argv;
    const originalExitCode = process.exitCode;
    const sensitive = "Keychain failed at /Users/private/secret.sqlite with api-key-material";
    const start = vi.fn(async () => {
      throw new Error(sensitive);
    });
    vi.doMock("../src/production-runtime.js", () => ({
      PRODUCTION_RUNTIME_FAILURE_MESSAGE: "unused runtime refusal\n",
      assertActiveProductionRuntime: vi.fn(),
    }));
    vi.doMock("../src/base-rpc-canary-operator-host.js", () => ({
      startBaseRpcCanaryOperator: start,
    }));
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    process.argv = [process.execPath, PRODUCTION_ENTRY];
    process.exitCode = undefined;

    try {
      await import("../src/base-rpc-canary-operator.js");
      expect(start).toHaveBeenCalledOnce();
      expect(process.exitCode).toBe(1);
      expect(stdout).not.toHaveBeenCalled();
      expect(stderr).toHaveBeenCalledTimes(1);
      expect(String(stderr.mock.calls[0]![0])).toBe(
        "RSI Base RPC read canary startup was refused.\n",
      );
      expect(JSON.stringify(stderr.mock.calls)).not.toContain(sensitive);
    } finally {
      process.argv = originalArgv;
      process.exitCode = originalExitCode;
      vi.doUnmock("../src/production-runtime.js");
      vi.doUnmock("../src/base-rpc-canary-operator-host.js");
    }
  });

  it.each(["snapshot", "serialization"] as const)(
    "closes once and redacts a post-start %s failure",
    async (failure) => {
      vi.resetModules();
      const originalArgv = process.argv;
      const originalExitCode = process.exitCode;
      const signalListeners = captureProductionSignalListeners();
      const sensitive = `private Base RPC ${failure} failure at /Users/private/base.sqlite`;
      const close = vi.fn(async () => undefined);
      const getSnapshot = vi.fn(() => {
        if (failure === "snapshot") throw new Error(sensitive);
        return { mode: "STOPPED" };
      });
      const poisonedOrigin =
        failure === "serialization"
          ? {
              toJSON(): never {
                throw new Error(sensitive);
              },
            }
          : "http://127.0.0.1:8787";
      const start = vi.fn(async () => ({
        close,
        origin: poisonedOrigin,
        runtime: { getSnapshot },
      }));
      vi.doMock("../src/production-runtime.js", () => ({
        PRODUCTION_RUNTIME_FAILURE_MESSAGE: "unused runtime refusal\n",
        assertActiveProductionRuntime: vi.fn(),
      }));
      vi.doMock("../src/base-rpc-canary-operator-host.js", () => ({
        startBaseRpcCanaryOperator: start,
      }));
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
      process.argv = [process.execPath, PRODUCTION_ENTRY];
      process.exitCode = undefined;

      try {
        await import("../src/base-rpc-canary-operator.js");
        expect(start).toHaveBeenCalledOnce();
        expect(close).toHaveBeenCalledOnce();
        expect(process.exitCode).toBe(1);
        expect(consoleLog).not.toHaveBeenCalled();
        expect(stdout).not.toHaveBeenCalled();
        expect(stderr).toHaveBeenCalledTimes(1);
        expect(String(stderr.mock.calls[0]![0])).toBe(
          "RSI Base RPC read canary startup was refused.\n",
        );
        expect(JSON.stringify(stderr.mock.calls)).not.toContain(sensitive);
        expect(productionSignalListenersMatch(signalListeners)).toBe(true);
      } finally {
        removeAddedProductionSignalListeners(signalListeners);
        process.argv = originalArgv;
        process.exitCode = originalExitCode;
        vi.doUnmock("../src/production-runtime.js");
        vi.doUnmock("../src/base-rpc-canary-operator-host.js");
      }
    },
  );

  it.each(PRODUCTION_STARTUP_SIGNALS)(
    "latches %s during async startup, closes once, emits no startup line, and removes handlers",
    async (signal) => {
      vi.resetModules();
      const originalArgv = process.argv;
      const originalExitCode = process.exitCode;
      const signalListeners = captureProductionSignalListeners();
      const startup = deferred<{
        close(): Promise<void>;
        readonly origin: string;
        readonly runtime: { getSnapshot(): { readonly mode: "STOPPED" } };
      }>();
      const close = vi.fn(async () => undefined);
      const getSnapshot = vi.fn(() => ({ mode: "STOPPED" as const }));
      const start = vi.fn(() => startup.promise);
      vi.doMock("../src/production-runtime.js", () => ({
        PRODUCTION_RUNTIME_FAILURE_MESSAGE: "unused runtime refusal\n",
        assertActiveProductionRuntime: vi.fn(),
      }));
      vi.doMock("../src/base-rpc-canary-operator-host.js", () => ({
        startBaseRpcCanaryOperator: start,
      }));
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
      process.argv = [process.execPath, PRODUCTION_ENTRY];
      process.exitCode = undefined;

      try {
        const importing = import("../src/base-rpc-canary-operator.js");
        await vi.waitFor(() => expect(start).toHaveBeenCalledOnce());
        invokeAddedProductionSignalListener(signalListeners, signal);
        startup.resolve({
          close,
          origin: "http://127.0.0.1:8787",
          runtime: { getSnapshot },
        });
        await importing;

        expect(close).toHaveBeenCalledOnce();
        expect(getSnapshot).not.toHaveBeenCalled();
        expect(consoleLog).not.toHaveBeenCalled();
        expect(stdout).not.toHaveBeenCalled();
        expect(stderr).not.toHaveBeenCalled();
        expect(process.exitCode).toBeUndefined();
        expect(productionSignalListenersMatch(signalListeners)).toBe(true);
      } finally {
        removeAddedProductionSignalListeners(signalListeners);
        process.argv = originalArgv;
        process.exitCode = originalExitCode;
        vi.doUnmock("../src/production-runtime.js");
        vi.doUnmock("../src/base-rpc-canary-operator-host.js");
      }
    },
  );
});
