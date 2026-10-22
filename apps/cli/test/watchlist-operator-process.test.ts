import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { link, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";

import { afterEach, describe, expect, it } from "vitest";
import {
  OfflineBaseWatchlist,
  parseWatchlistPreview,
  parseWatchlistResult,
  parseWatchlistView,
} from "@rsi/watchlist";
import { parseOperatorRuntimeSnapshot } from "@rsi/operator";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const entry = fileURLToPath(new URL("../src/operator.ts", import.meta.url));
const tsxImport = fileURLToPath(
  new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url),
);
const operatorArguments = ["--import", tsxImport, entry] as const;
let directory: string;
let child: ChildProcessWithoutNullStreams | undefined;

async function terminate(active: ChildProcessWithoutNullStreams): Promise<void> {
  if (active.exitCode !== null || active.signalCode !== null) return;
  const exited = once(active, "exit");
  active.kill("SIGTERM");
  const force = setTimeout(() => active.kill("SIGKILL"), 1_000);
  try {
    await exited;
  } finally {
    clearTimeout(force);
  }
}

afterEach(async () => {
  if (child !== undefined) await terminate(child);
  child = undefined;
  if (directory) await rm(directory, { recursive: true, force: true });
});
async function launch(extra: string[] = []) {
  child = spawn(
    process.execPath,
    [
      ...operatorArguments,
      "--db",
      join(directory, "runtime.sqlite"),
      "--research-db",
      join(directory, "research.sqlite"),
      "--watchlist-db",
      join(directory, "watchlist.sqlite"),
      "--port",
      "0",
      ...extra,
    ],
    { cwd: root, stdio: "pipe" },
  );
  const active = child;
  return new Promise<{ origin: string; runtimeMode: string }>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    active.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    active.once("exit", () => reject(new Error(stderr)));
    active.once("error", reject);
    active.stdout.on("data", (chunk) => {
      stdout += String(chunk);
      if (stdout.includes("\n")) resolve(JSON.parse(stdout.slice(0, stdout.indexOf("\n"))));
    });
  });
}
function input(at = "2026-10-20T00:00:00.000Z") {
  return {
    schemaVersion: 1,
    kind: "offline_opensea_trending",
    sourceContractVersion: "opensea-api-v2-collections-trending.2026-09-05.one-day-base-ten-v1",
    acquiredAt: at,
    validUntil: new Date(Date.parse(at) + 120000).toISOString(),
    hasNextPage: true,
    collections: [{ rank: 1, slug: "alpha", baseAddresses: ["0x" + "ab".repeat(20)] }],
  };
}
const post = (origin: string, path: string, body: unknown, sameOrigin = origin) =>
  fetch(origin + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: sameOrigin,
      "x-rsi-operator-request": "1",
      "sec-fetch-site": "same-origin",
    },
    body: JSON.stringify(body),
  });
async function research(origin: string) {
  const runtime = await body(
    await fetch(origin + "/api/runtime"),
    "runtime",
    parseOperatorRuntimeSnapshot,
  );
  expect(
    (
      await post(origin, "/api/control", {
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: runtime.revision,
        requestId: randomUUID(),
      })
    ).status,
  ).toBe(200);
}
async function body<T>(response: Response, key: string, parse: (value: unknown) => T): Promise<T> {
  const value: unknown = await response.json();
  if (value === null || typeof value !== "object" || !Object.hasOwn(value, key))
    throw new Error("Missing response field");
  return parse(Reflect.get(value, key));
}

describe("fresh-process offline watchlist", () => {
  it("previews, confirms, retries, rejects stale previews and reopens STOPPED after a crash", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-watchlist-process-"));
    const started = await launch();
    const origin = started.origin;
    expect(started.runtimeMode).toBe("STOPPED");
    expect((await post(origin, "/api/watchlist/preview", { input: input() })).status).toBe(409);
    await research(origin);
    expect(
      (await post(origin, "/api/watchlist/preview", { input: input() }, "http://evil.invalid"))
        .status,
    ).toBe(403);
    expect((await post(origin, "/api/watchlist/preview", { path: "/tmp/anything" })).status).toBe(
      400,
    );
    expect(
      (
        await post(origin, "/api/watchlist/preview", {
          input: input("9999-12-30T00:00:00.000Z"),
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await post(origin, "/api/watchlist/preview", {
          input: { ...input(), url: "https://evil.invalid" },
        })
      ).status,
    ).toBe(400);
    expect(
      (await post(origin, "/api/watchlist/preview", { input: input(), padding: "x".repeat(33000) }))
        .status,
    ).toBe(413);
    const previewResponse = await post(origin, "/api/watchlist/preview", { input: input() });
    expect(previewResponse.status).toBe(200);
    const preview = await body(previewResponse, "preview", parseWatchlistPreview);
    expect(preview.binding.predecessorId).toBeNull();
    const before = await body(
      await fetch(origin + "/api/watchlist"),
      "watchlist",
      parseWatchlistView,
    );
    expect(before.history).toEqual([]);
    const command = { input: input(), expected: preview.binding };
    const confirmed = await post(origin, "/api/watchlist/confirm", command);
    expect(confirmed.status).toBe(200);
    expect((await body(confirmed, "result", parseWatchlistResult)).duplicate).toBe(false);
    expect(
      (
        await body(
          await post(origin, "/api/watchlist/confirm", command),
          "result",
          parseWatchlistResult,
        )
      ).duplicate,
    ).toBe(true);
    const nextInput = input("2026-10-20T00:01:00.000Z");
    const next = await body(
      await post(origin, "/api/watchlist/preview", { input: nextInput }),
      "preview",
      parseWatchlistPreview,
    );
    expect(
      (
        await post(origin, "/api/watchlist/confirm", {
          input: { ...nextInput, hasNextPage: false },
          expected: next.binding,
        })
      ).status,
    ).toBe(409);
    expect(
      (await post(origin, "/api/control", { action: "runtime-stop", requestId: randomUUID() }))
        .status,
    ).toBe(200);
    expect(
      (
        await post(origin, "/api/watchlist/confirm", {
          input: nextInput,
          expected: next.binding,
        })
      ).status,
    ).toBe(409);
    const exited = once(child!, "exit");
    child!.kill("SIGKILL");
    await exited;
    const restarted = await launch();
    expect(restarted.runtimeMode).toBe("STOPPED");
    const view = await body(
      await fetch(restarted.origin + "/api/watchlist"),
      "watchlist",
      parseWatchlistView,
    );
    expect(view).toMatchObject({
      provenance: "operator_supplied_unverified",
      partial: true,
      head: preview.binding.snapshotId,
    });
    expect(view.history).toHaveLength(1);
    await research(restarted.origin);
    expect((await post(restarted.origin, "/api/watchlist/confirm", command)).status).toBe(409);
    const closed = once(child!, "exit");
    child!.kill("SIGTERM");
    await closed;
    const history = OfflineBaseWatchlist.open(join(directory, "watchlist.sqlite"));
    try {
      expect(history.read("2026-10-20T00:02:00.000Z").stale).toBe(true);
    } finally {
      history.close();
    }
  });

  it.each(["path", "symlink", "hardlink"])(
    "refuses watchlist %s aliases before boot",
    async (kind) => {
      directory = await mkdtemp(join(tmpdir(), "rsi-watchlist-alias-"));
      const runtime = join(directory, "runtime.sqlite");
      const watchlist = join(directory, "watchlist.sqlite");
      await writeFile(runtime, "sentinel");
      if (kind === "symlink") await symlink(runtime, watchlist);
      if (kind === "hardlink") await link(runtime, watchlist);
      await expect(launch(kind === "path" ? ["--watchlist-db", runtime] : [])).rejects.toThrow();
    },
  );

  it("separates new case-fold aliases before opening SQLite", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-watchlist-casefold-"));
    const probe = join(directory, "CaseProbe");
    await writeFile(probe, "probe");
    let caseInsensitive = false;
    try {
      const original = await stat(probe);
      const folded = await stat(join(directory, "caseprobe"));
      caseInsensitive = original.dev === folded.dev && original.ino === folded.ino;
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
    }

    const runtimePath = join(directory, "Research.sqlite");
    const researchPath = join(directory, "research.sqlite");
    const startup = launch(["--db", runtimePath, "--research-db", researchPath]);
    if (caseInsensitive) {
      await expect(startup).rejects.toThrow("RSI Stage 0 operator startup was refused.");
      const placeholder = await stat(runtimePath);
      expect(placeholder.size).toBe(0);
      if (process.platform !== "win32") expect(placeholder.mode & 0o077).toBe(0);
    } else {
      await expect(startup).resolves.toMatchObject({ runtimeMode: "STOPPED" });
    }
  });
});
