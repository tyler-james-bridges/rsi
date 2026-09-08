import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { link, mkdtemp, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

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
const OPERATOR_ENTRY = fileURLToPath(new URL("../src/operator.ts", import.meta.url));

interface StartupReceipt {
  readonly mode: "stage0-local-runtime";
  readonly runtimeMode: "STOPPED";
  readonly executionEnabled: false;
  readonly financialAuthority: false;
  readonly databasePath: string;
  readonly researchDatabasePath: string;
  readonly origin: string;
}

function waitForStartup(child: ChildProcessWithoutNullStreams): Promise<StartupReceipt> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => reject(new Error("operator startup timed out")), 10_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      reject(
        new Error(
          `operator exited before startup (code=${String(code)}, signal=${String(signal)}): ${stderr}`,
        ),
      );
    });
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      const newline = stdout.indexOf("\n");
      if (newline < 0) return;
      clearTimeout(timeout);
      try {
        resolve(JSON.parse(stdout.slice(0, newline)) as StartupReceipt);
      } catch {
        reject(new Error("operator startup receipt was invalid"));
      }
    });
  });
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("operator shutdown timed out")), 10_000);
    child.once("error", reject);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve(code);
    });
  });
}

describe("Stage 0 operator process", () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let directory: string | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.resetModules();
    if (child !== undefined && child.exitCode === null && child.signalCode === null) {
      const exited = waitForExit(child);
      child.kill("SIGTERM");
      await exited.catch(() => {
        child?.kill("SIGKILL");
      });
    }
    if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  });

  it("boots STOPPED, serves strict projections, accepts research, and persists STOP on SIGINT", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-process-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    child = spawn(
      process.execPath,
      [TSX_CLI, OPERATOR_ENTRY, "--db", runtimePath, "--research-db", researchPath, "--port", "0"],
      {
        cwd: ROOT,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );

    const startup = await waitForStartup(child);
    const canonicalDirectory = await realpath(directory);
    expect(startup).toMatchObject({
      mode: "stage0-local-runtime",
      runtimeMode: "STOPPED",
      executionEnabled: false,
      financialAuthority: false,
      databasePath: join(canonicalDirectory, "runtime.sqlite"),
      researchDatabasePath: join(canonicalDirectory, "research.sqlite"),
    });
    expect(new URL(startup.origin).hostname).toBe("127.0.0.1");

    const runtimeResponse = await fetch(`${startup.origin}/api/runtime`);
    const runtimeBody = (await runtimeResponse.json()) as {
      financialAuthority: boolean;
      runtime: { mode: string; revision: number };
    };
    expect(runtimeResponse.status).toBe(200);
    expect(runtimeBody).toMatchObject({
      financialAuthority: false,
      runtime: { mode: "STOPPED" },
    });
    const researchResponse = await fetch(`${startup.origin}/api/research`);
    expect(await researchResponse.json()).toEqual({
      research: {
        schemaVersion: 1,
        candidateCount: 0,
        abstentionCount: 0,
        proposals: [],
      },
    });

    const transition = await fetch(`${startup.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: runtimeBody.runtime.revision,
        requestId: randomUUID(),
      }),
      headers: {
        "content-type": "application/json",
        origin: startup.origin,
        "sec-fetch-site": "same-origin",
        "x-rsi-operator-request": "1",
      },
      method: "POST",
    });
    expect(transition.status).toBe(200);
    expect(await transition.json()).toMatchObject({
      result: {
        mode: "RESEARCH",
        capabilities: {
          researchCollection: true,
          proposalPersistence: false,
          paidRead: false,
          walletSign: false,
          executionAdapter: false,
          transactionBroadcast: false,
        },
      },
    });

    const exited = waitForExit(child);
    child.kill("SIGINT");
    expect(await exited).toBe(0);

    const reopened = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    const audit = reopened.listAudit();
    expect(audit.at(-2)).toMatchObject({
      type: "runtime.stop.enforced.v1",
      payload: { cause: "operator", to: "STOPPED" },
    });
    expect(reopened.getSnapshot().mode).toBe("STOPPED");
    reopened.close();
  });

  it("creates fresh default Stage 0 directories owner-only without poisoning Stage 1", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-default-modes-"));
    child = spawn(process.execPath, [TSX_CLI, OPERATOR_ENTRY, "--port", "0"], {
      cwd: directory,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const startup = await waitForStartup(child);
    const canonicalDirectory = await realpath(directory);
    expect(startup.databasePath).toBe(join(canonicalDirectory, ".local/stage0/rsi-runtime.sqlite"));
    expect(startup.researchDatabasePath).toBe(
      join(canonicalDirectory, ".local/stage0/rsi-research.sqlite"),
    );
    expect((await stat(join(directory, ".local"))).mode & 0o777).toBe(0o700);
    expect((await stat(join(directory, ".local/stage0"))).mode & 0o777).toBe(0o700);

    const exited = waitForExit(child);
    child.kill("SIGINT");
    expect(await exited).toBe(0);
  });

  it("refuses aliased runtime and research database files", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-alias-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    await writeFile(runtimePath, "");
    await link(runtimePath, researchPath);

    child = spawn(
      process.execPath,
      [TSX_CLI, OPERATOR_ENTRY, "--db", runtimePath, "--research-db", researchPath, "--port", "0"],
      {
        cwd: ROOT,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    expect(await waitForExit(child)).toBe(1);
  });

  it.each(PRODUCTION_STARTUP_SIGNALS)(
    "latches %s during server startup, closes every opened resource, and emits no startup line",
    async (signal) => {
      directory = await mkdtemp(join(tmpdir(), "rsi-stage0-early-signal-"));
      const runtimePath = join(directory, "runtime.sqlite");
      const researchPath = join(directory, "research.sqlite");
      const originalArgv = process.argv;
      const originalExitCode = process.exitCode;
      const signalListeners = captureProductionSignalListeners();
      const startup = deferred<{
        close(): Promise<void>;
        readonly origin: string;
      }>();
      const serverShutdown = deferred<void>();
      const serverClose = vi.fn(() => serverShutdown.promise);
      const runtimeStop = vi.fn(() => ({ mode: "STOPPED" }));
      const runtimeClose = vi.fn(() => undefined);
      const runtimeSnapshot = vi.fn(() => ({ mode: "STOPPED" as const }));
      const researchClose = vi.fn(() => undefined);
      const runtime = {
        close: runtimeClose,
        getSnapshot: runtimeSnapshot,
        listAudit: vi.fn(() => []),
        stop: runtimeStop,
      };
      const research = {
        close: researchClose,
        getProjection: vi.fn(() => ({ schemaVersion: 1 })),
      };
      let admittedRuntime:
        | {
            executeRuntimeControl(command: unknown): unknown;
            getRuntimeSnapshot(): unknown;
          }
        | undefined;
      const start = vi.fn(
        (
          _provider: unknown,
          serverOptions: {
            runtime: {
              executeRuntimeControl(command: unknown): unknown;
              getRuntimeSnapshot(): unknown;
            };
          },
        ) => {
          admittedRuntime = serverOptions.runtime;
          return startup.promise;
        },
      );
      vi.doMock("@rsi/runtime", () => ({
        RuntimeConflictError: class RuntimeConflictError extends Error {
          constructor(_code: string, message: string) {
            super(message);
          }
        },
        SqliteRuntimeController: { open: vi.fn(() => runtime) },
      }));
      vi.doMock("@rsi/research-ledger", () => ({
        SqliteResearchLedger: { open: vi.fn(() => research) },
      }));
      vi.doMock("@rsi/operator", () => ({
        createRuntimeOperatorControls: vi.fn(() => ({
          executeRuntimeControl: vi.fn(),
          getRuntimeSnapshot: runtimeSnapshot,
          supportedActions: [],
        })),
        startOperatorServer: start,
      }));
      vi.doMock("../src/operator-options.js", () => ({
        assertStage0StorageIsolation: vi.fn(),
        operatorUsage: vi.fn(() => "unused"),
        parseOperatorOptions: vi.fn(() => ({
          databasePath: runtimePath,
          port: 0,
          researchDatabasePath: researchPath,
        })),
        resolveProspectiveStoragePath: vi.fn(async (path: string) => path),
      }));
      vi.doMock("../src/production-canary-config.js", () => ({
        productionXCanaryHostOptions: vi.fn(() => ({
          databasePath: join(directory!, "production", "runtime.sqlite"),
        })),
      }));
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
      process.argv = [process.execPath, OPERATOR_ENTRY];
      process.exitCode = undefined;

      try {
        const importing = import("../src/operator.js");
        await vi.waitFor(() => expect(start).toHaveBeenCalledOnce());
        invokeAddedProductionSignalListener(signalListeners, signal);
        expect(() => admittedRuntime?.getRuntimeSnapshot()).toThrow(
          "Runtime controls are unavailable while the Stage 0 host is closing",
        );
        expect(() =>
          admittedRuntime?.executeRuntimeControl({
            action: "runtime-stop",
            requestId: randomUUID(),
          }),
        ).toThrow("Runtime controls are unavailable while the Stage 0 host is closing");
        startup.resolve({ close: serverClose, origin: "http://127.0.0.1:8787" });
        await vi.waitFor(() => expect(serverClose).toHaveBeenCalledOnce());
        expect(runtimeStop).toHaveBeenCalledOnce();
        serverShutdown.resolve();
        await importing;

        expect(serverClose).toHaveBeenCalledOnce();
        expect(researchClose).toHaveBeenCalledOnce();
        expect(runtimeStop).toHaveBeenCalledTimes(2);
        expect(runtimeClose).toHaveBeenCalledOnce();
        expect(runtimeSnapshot).not.toHaveBeenCalled();
        expect(consoleLog).not.toHaveBeenCalled();
        expect(stderr).not.toHaveBeenCalled();
        expect(process.exitCode).toBeUndefined();
        expect(productionSignalListenersMatch(signalListeners)).toBe(true);
      } finally {
        removeAddedProductionSignalListeners(signalListeners);
        process.argv = originalArgv;
        process.exitCode = originalExitCode;
        vi.doUnmock("@rsi/runtime");
        vi.doUnmock("@rsi/research-ledger");
        vi.doUnmock("@rsi/operator");
        vi.doUnmock("../src/operator-options.js");
        vi.doUnmock("../src/production-canary-config.js");
      }
    },
  );
});
