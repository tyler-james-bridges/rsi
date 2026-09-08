import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const TSX_CLI = fileURLToPath(new URL("../../../node_modules/tsx/dist/cli.mjs", import.meta.url));
const LOCK_FIXTURE = fileURLToPath(
  new URL("./fixtures/profile-service-lock-process-fixture.ts", import.meta.url),
);
const CANARY_FIXTURES = Object.freeze({
  x: fileURLToPath(new URL("./fixtures/x-canary-operator-process-fixture.ts", import.meta.url)),
  opensea: fileURLToPath(
    new URL("./fixtures/opensea-canary-operator-process-fixture.ts", import.meta.url),
  ),
  "base-rpc": fileURLToPath(
    new URL("./fixtures/base-rpc-canary-operator-process-fixture.ts", import.meta.url),
  ),
});

let directory: string | undefined;
let holder: ChildProcessWithoutNullStreams | undefined;

function waitForText(
  child: ChildProcessWithoutNullStreams,
  stream: "stdout" | "stderr",
  expected: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error("child output timed out")), 10_000);
    child[stream].setEncoding("utf8");
    child[stream].on("data", (chunk: string) => {
      output += chunk;
      if (!output.includes(expected)) return;
      clearTimeout(timeout);
      resolve(output);
    });
    child.once("error", reject);
  });
}

function waitForExit(
  child: ChildProcessWithoutNullStreams,
): Promise<Readonly<{ code: number | null; stderr: string; stdout: string }>> {
  return new Promise((resolve, reject) => {
    let stderr = "";
    let stdout = "";
    const timeout = setTimeout(() => reject(new Error("child exit timed out")), 10_000);
    child.stderr.setEncoding("utf8");
    child.stdout.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve({ code, stderr, stdout });
    });
  });
}

afterEach(async () => {
  if (holder !== undefined && holder.exitCode === null && holder.signalCode === null) {
    holder.kill("SIGKILL");
    await waitForExit(holder).catch(() => undefined);
  }
  holder = undefined;
  if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  directory = undefined;
});

describe("Stage 1 profile lock across real canary processes", () => {
  it("rejects X, OpenSea, and Base contenders before any state file is created", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-canary-process-lock-"));
    await chmod(directory, 0o700);
    holder = spawn(process.execPath, [TSX_CLI, LOCK_FIXTURE, "hold", directory, "stage1-canary"], {
      cwd: ROOT,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    await waitForText(holder, "stdout", "acquired\n");

    for (const kind of ["x", "opensea", "base-rpc"] as const) {
      const runtimePath = join(directory, `${kind}-runtime.sqlite`);
      const args = [TSX_CLI, CANARY_FIXTURES[kind], runtimePath];
      if (kind === "x") args.push(join(directory, "x-research.sqlite"));
      const contender = spawn(process.execPath, args, {
        cwd: ROOT,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
      const result = await waitForExit(contender);
      expect(result.code).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("another process holds the selected service lock");
      expect(result.stderr).not.toMatch(
        /offline-process-(?:canary-token|opensea-api-key|alchemy-api-key)/u,
      );
      expect(await readdir(directory)).toEqual([".rsi-stage1-canary.lock"]);
    }

    const released = waitForText(holder, "stdout", "released\n");
    const holderExit = waitForExit(holder);
    holder.stdin.end("release\n");
    await released;
    expect((await holderExit).code).toBe(0);
    holder = undefined;
    expect(await readdir(directory)).toEqual([]);

    const successor = spawn(
      process.execPath,
      [TSX_CLI, LOCK_FIXTURE, "once", directory, "stage1-canary"],
      { cwd: ROOT, env: process.env, stdio: ["pipe", "pipe", "pipe"] },
    );
    await expect(waitForExit(successor)).resolves.toEqual({
      code: 0,
      stderr: "",
      stdout: "acquired\nreleased\n",
    });
  });

  it("keeps every canary fail-closed after the lock owner is killed", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-canary-process-stale-lock-"));
    await chmod(directory, 0o700);
    holder = spawn(process.execPath, [TSX_CLI, LOCK_FIXTURE, "hold", directory, "stage1-canary"], {
      cwd: ROOT,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    await waitForText(holder, "stdout", "acquired\n");
    const killed = waitForExit(holder);
    holder.kill("SIGKILL");
    expect((await killed).code).toBeNull();
    holder = undefined;

    for (const kind of ["x", "opensea", "base-rpc"] as const) {
      const runtimePath = join(directory, `${kind}-runtime.sqlite`);
      const args = [TSX_CLI, CANARY_FIXTURES[kind], runtimePath];
      if (kind === "x") args.push(join(directory, "x-research.sqlite"));
      const contender = spawn(process.execPath, args, {
        cwd: ROOT,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
      const result = await waitForExit(contender);
      expect(result.code).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("another process holds the selected service lock");
      expect(result.stderr).not.toMatch(
        /offline-process-(?:canary-token|opensea-api-key|alchemy-api-key)/u,
      );
      expect(await readdir(directory)).toEqual([".rsi-stage1-canary.lock"]);
    }
  });
});
