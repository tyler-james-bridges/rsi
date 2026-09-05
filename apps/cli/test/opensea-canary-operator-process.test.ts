import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { getOpenSeaReadCanaryPlan } from "@rsi/read-canary/opensea";
import { SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const TSX_CLI = fileURLToPath(new URL("../../../node_modules/tsx/dist/cli.mjs", import.meta.url));
const FIXTURE_ENTRY = fileURLToPath(
  new URL("./fixtures/opensea-canary-operator-process-fixture.ts", import.meta.url),
);
const PRODUCTION_ENTRY = fileURLToPath(
  new URL("../src/opensea-canary-operator.ts", import.meta.url),
);

function waitForLine(
  child: ChildProcessWithoutNullStreams,
  predicate: (value: unknown) => boolean,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timeout = setTimeout(
      () => reject(new Error("OpenSea operator output timed out")),
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
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve(child.exitCode);
  }
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("OpenSea shutdown timed out")), 10_000);
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

describe("OpenSea canary CLI process", () => {
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

  it("proves idle boot has no API-key read or egress, runs once, and persists STOP", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-opensea-process-"));
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
        (value as { mode?: unknown }).mode === "stage1-opensea-read-canary-test-fixture",
    )) as {
      apiKeyValueReads: number;
      credentialCommands: number;
      credentialValueReads: number;
      openSeaRequests: number;
      origin: string;
      runtimeMode: string;
    };
    expect(startup).toMatchObject({
      apiKeyValueReads: 0,
      credentialCommands: 3,
      credentialValueReads: 3,
      openSeaRequests: 0,
      runtimeMode: "STOPPED",
    });

    const health = await fetch(`${startup.origin}/health`);
    const runtimeResponse = await fetch(`${startup.origin}/api/runtime`);
    const runtime = (await runtimeResponse.json()) as {
      runtime: { mode: "STOPPED"; revision: number };
    };
    expect(await health.json()).toEqual({ status: "ok", runtime: "persisted" });
    expect(runtime.runtime.mode).toBe("STOPPED");

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

    const plan = getOpenSeaReadCanaryPlan();
    const runResponse = await fetch(`${startup.origin}/api/opensea-read-canary/run`, {
      body: JSON.stringify({
        schemaVersion: 1,
        planId: plan.planId,
        expectedRuntimeRevision: transitioned.result.revision,
        requestId: randomUUID(),
        typedPlanIdAcknowledgement: plan.planId,
        oneRequestAcknowledgement: true,
        nonPaymentReadAcknowledgement: true,
        ledgerReserveUsdMicrosAcknowledgement: plan.ledgerReserveUsdMicros,
      }),
      headers: headers(startup.origin),
      method: "POST",
    });
    const run = await runResponse.json();
    expect(runResponse.status).toBe(200);
    expect(run).toMatchObject({ result: { collectionCount: 1, outcome: "accepted" } });
    const serialized = JSON.stringify(run);
    for (const forbidden of [
      "offline-process-opensea-api-key",
      "untrusted-process-collection",
      "UNTRUSTED PROCESS OPENSEA CONTENT",
      `0x${"d".repeat(40)}`,
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
      closed: true,
      credentialCommands: 7,
      credentialValueReads: 7,
      openSeaRequests: 1,
    });
    expect(await exited).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).not.toContain("offline-process-opensea-api-key");
    expect(stdout).not.toContain("UNTRUSTED PROCESS OPENSEA CONTENT");

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
    const sensitiveOverride = "/Users/example/private/opensea.sqlite";
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
    expect(stderr).toBe("RSI OpenSea canary startup was refused.\n");
    expect(stderr).not.toContain(sensitiveOverride);
    expect(stderr).not.toContain(" at ");
  });
});
