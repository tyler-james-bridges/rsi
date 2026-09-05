import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const TSX_CLI = fileURLToPath(new URL("../../../node_modules/tsx/dist/cli.mjs", import.meta.url));
const FIXTURE_ENTRY = fileURLToPath(
  new URL("./fixtures/x-canary-operator-process-fixture.ts", import.meta.url),
);
const PRODUCTION_ENTRY = fileURLToPath(new URL("../src/x-canary-operator.ts", import.meta.url));
const CLAIM_BACKFILL_ENTRY = fileURLToPath(
  new URL("../src/x-canary-claim-backfill.ts", import.meta.url),
);

interface StartupReceipt {
  readonly executionEnabled: false;
  readonly financialAuthority: false;
  readonly mode: "stage1-x-read-canary-test-fixture";
  readonly origin: string;
  readonly runtimeMode: "STOPPED";
}

function waitForLine(
  child: ChildProcessWithoutNullStreams,
  predicate: (value: unknown) => boolean,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timeout = setTimeout(() => reject(new Error("operator output timed out")), 10_000);
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
          // Ignore non-JSON fixture diagnostics; production output has none.
        }
      }
    };
    child.stdout.on("data", onData);
    child.once("error", reject);
  });
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve(child.exitCode);
  }
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("operator shutdown timed out")), 10_000);
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

describe("Stage 1 CLI/operator process", () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let directory: string | undefined;

  afterEach(async () => {
    if (child !== undefined && child.exitCode === null && child.signalCode === null) {
      const exited = waitForExit(child);
      child.kill("SIGTERM");
      await exited.catch(() => child?.kill("SIGKILL"));
    }
    if (directory !== undefined) await rm(directory, { recursive: true, force: true });
  });

  it("boots fail-closed, executes one explicit canary, and persists STOP on shutdown", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-process-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    let stderr = "";
    child = spawn(process.execPath, [TSX_CLI, FIXTURE_ENTRY, runtimePath, researchPath], {
      cwd: ROOT,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });

    const startup = (await waitForLine(
      child,
      (value) =>
        typeof value === "object" &&
        value !== null &&
        (value as { mode?: unknown }).mode === "stage1-x-read-canary-test-fixture",
    )) as StartupReceipt;
    expect(startup).toMatchObject({
      executionEnabled: false,
      financialAuthority: false,
      runtimeMode: "STOPPED",
    });

    const runtimeResponse = await fetch(`${startup.origin}/api/runtime`);
    const runtime = (await runtimeResponse.json()) as {
      runtime: { mode: string; revision: number };
    };
    const transition = await fetch(`${startup.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: runtime.runtime.mode,
        expectedRevision: runtime.runtime.revision,
        requestId: randomUUID(),
      }),
      headers: headers(startup.origin),
      method: "POST",
    });
    const transitioned = (await transition.json()) as { result: { revision: number } };
    expect(transition.status).toBe(200);

    const runResponse = await fetch(`${startup.origin}/api/read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: "x-nft-market-pulse-v1",
        expectedRuntimeRevision: transitioned.result.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: "x-nft-market-pulse-v1",
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      }),
      headers: headers(startup.origin),
      method: "POST",
    });
    const run = await runResponse.json();
    expect(runResponse.status).toBe(200);
    expect(run).toMatchObject({ result: { outcome: "accepted", postCount: 1 } });
    expect(JSON.stringify(run)).not.toContain("offline-process-canary-token");
    expect(JSON.stringify(run)).not.toContain("UNTRUSTED PROCESS FIXTURE TEXT");

    const closedLine = waitForLine(
      child,
      (value) =>
        typeof value === "object" &&
        value !== null &&
        (value as { closed?: unknown }).closed === true,
    );
    const exited = waitForExit(child);
    child.kill("SIGINT");
    await expect(closedLine).resolves.toEqual({ closed: true, xRequests: 1 });
    expect(await exited).toBe(0);
    expect(stderr).toBe("");

    const reopened = SqliteRuntimeController.open({
      openedAt: new Date().toISOString(),
      path: runtimePath,
      processInstanceId: randomUUID(),
    });
    expect(reopened.listAudit().at(-2)).toMatchObject({
      payload: { to: "STOPPED" },
      type: "runtime.stop.enforced.v1",
    });
    expect(reopened.getSnapshot().mode).toBe("STOPPED");
    reopened.close();
  });

  it("refuses an unreviewed production runtime before host startup", async () => {
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

  it("redacts rejected production options before runtime or host startup", async () => {
    let stderr = "";
    let stdout = "";
    const sensitiveOverride = "/Users/example/private/canary.sqlite";
    child = spawn(process.execPath, [TSX_CLI, PRODUCTION_ENTRY, "--db", sensitiveOverride], {
      cwd: ROOT,
      env: process.env,
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
    expect(stderr).toBe("RSI X canary startup was refused.\n");
    expect(stderr).not.toContain(sensitiveOverride);
    expect(stderr).not.toContain(" at ");
  });

  it("refuses marker backfill on an unreviewed runtime without touching Keychain", async () => {
    let stderr = "";
    let stdout = "";
    child = spawn(
      process.execPath,
      [TSX_CLI, CLAIM_BACKFILL_ENTRY, "--typed-plan-id-acknowledgement", "x-nft-market-pulse-v1"],
      {
        cwd: ROOT,
        env: { ...process.env, npm_config_user_agent: "pnpm/0.0.0" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
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

  it("redacts rejected marker-backfill options before runtime or Keychain", async () => {
    let stderr = "";
    let stdout = "";
    const sensitiveOverride = "/Users/example/private/receipt.sqlite";
    child = spawn(process.execPath, [TSX_CLI, CLAIM_BACKFILL_ENTRY, "--db", sensitiveOverride], {
      cwd: ROOT,
      env: process.env,
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
    expect(stderr).toBe("RSI X one-shot marker backfill was refused.\n");
    expect(stderr).not.toContain(sensitiveOverride);
    expect(stderr).not.toContain(" at ");
  });
});
