import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { link, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it } from "vitest";

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
});
