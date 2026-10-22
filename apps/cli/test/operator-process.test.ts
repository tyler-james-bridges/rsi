import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { link, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AttentionOperatorPreviewSchema,
  AttentionOperatorResultSchema,
  AttentionOperatorViewSchema,
} from "@rsi/attention";
import { SqliteResearchLedger } from "@rsi/research-ledger";
import { SqliteRuntimeController } from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";
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
const OPERATOR_ENTRY = fileURLToPath(new URL("../src/operator.ts", import.meta.url));
const TSX_IMPORT = fileURLToPath(
  new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url),
);
const OPERATOR_ARGUMENTS = ["--import", TSX_IMPORT, OPERATOR_ENTRY] as const;

interface StartupReceipt {
  readonly attentionDatabasePath: string;
  readonly mode: "stage0-local-runtime";
  readonly runtimeMode: "STOPPED";
  readonly executionEnabled: false;
  readonly financialAuthority: false;
  readonly databasePath: string;
  readonly researchDatabasePath: string;
  readonly origin: string;
}

const ATTENTION_FIXTURE = fileURLToPath(
  new URL("../../../packages/attention/fixtures/recorded-mixed.json", import.meta.url),
);

async function currentAttentionFixture(): Promise<Record<string, unknown>> {
  const original = JSON.parse(await readFile(ATTENTION_FIXTURE, "utf8")) as {
    marketplace: Record<string, unknown>;
    x: Record<string, unknown>;
    base: Record<string, unknown>;
  } & Record<string, unknown>;
  const evaluatedAt = Date.now();
  const acquiredAt = new Date(evaluatedAt - 30_000).toISOString();
  return {
    ...original,
    marketplace: {
      ...original.marketplace,
      acquiredAt,
      validUntil: new Date(Date.parse(acquiredAt) + 120_000).toISOString(),
    },
    x: {
      ...original.x,
      acquiredAt: new Date(Date.parse(acquiredAt) + 10_000).toISOString(),
    },
    base: {
      ...original.base,
      acquiredAt: new Date(Date.parse(acquiredAt) + 20_000).toISOString(),
      blockTimestamp: new Date(Date.parse(acquiredAt) + 15_000).toISOString(),
    },
  };
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

async function terminate(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = waitForExit(child);
  child.kill("SIGTERM");
  const force = setTimeout(() => child.kill("SIGKILL"), 1_000);
  try {
    await exited;
  } finally {
    clearTimeout(force);
  }
}

describe("Stage 0 operator process", () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let directory: string | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.resetModules();
    if (child !== undefined) await terminate(child);
    if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  });

  it("boots STOPPED, serves strict projections, accepts research, and persists STOP on SIGINT", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-process-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    const attentionPath = join(directory, "attention.sqlite");
    child = spawn(
      process.execPath,
      [
        ...OPERATOR_ARGUMENTS,
        "--db",
        runtimePath,
        "--research-db",
        researchPath,
        "--attention-db",
        attentionPath,
        "--port",
        "0",
      ],
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
      attentionDatabasePath: join(canonicalDirectory, "attention.sqlite"),
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
    const emptyAttentionResponse = await fetch(`${startup.origin}/api/attention`);
    const emptyAttentionBody = (await emptyAttentionResponse.json()) as { attention: unknown };
    const emptyAttention = AttentionOperatorViewSchema.parse(emptyAttentionBody.attention);
    expect(emptyAttention).toMatchObject({
      schemaVersion: 1,
      kind: "available",
      provenance: "operator_supplied_unverified",
      auditHead: null,
      latest: null,
      rows: [],
      history: [],
    });
    const startupAttention = new SqliteEventStore(attentionPath);
    expect(startupAttention.list()).toMatchObject([
      { sequence: 1, type: "attention.history.initialized.v1" },
    ]);
    startupAttention.close();

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
    const researchMode = (await transition.json()) as {
      result: { mode: string; revision: number };
    };
    expect(researchMode).toMatchObject({
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

    const attentionInput = await currentAttentionFixture();
    const attentionHeaders = {
      "content-type": "application/json",
      origin: startup.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };
    const attentionPreviewResponse = await fetch(`${startup.origin}/api/attention/preview`, {
      body: JSON.stringify({ input: attentionInput }),
      headers: attentionHeaders,
      method: "POST",
    });
    const attentionPreviewBody = (await attentionPreviewResponse.json()) as { preview: unknown };
    const attentionPreview = AttentionOperatorPreviewSchema.parse(attentionPreviewBody.preview);
    expect(attentionPreviewResponse.status).toBe(200);
    if (attentionPreview.kind !== "preview") throw new Error("expected a new attention preview");
    const attentionRecordResponse = await fetch(`${startup.origin}/api/attention/record`, {
      body: JSON.stringify({
        input: attentionInput,
        expected: attentionPreview.binding,
      }),
      headers: attentionHeaders,
      method: "POST",
    });
    const attentionRecordJson = (await attentionRecordResponse.json()) as { result: unknown };
    const attentionResult = AttentionOperatorResultSchema.parse(attentionRecordJson.result);
    const attentionRecordBody = { result: attentionResult };
    expect(attentionRecordResponse.status).toBe(200);
    expect(attentionResult.assessment.rows.map((row) => row.outcome.kind).sort()).toEqual([
      "rejected",
      "review",
      "watch",
    ]);
    expect(JSON.stringify(attentionRecordBody)).not.toContain("authorization");
    const populatedAttentionBody = (await (
      await fetch(`${startup.origin}/api/attention`)
    ).json()) as { attention: unknown };
    const populatedAttention = AttentionOperatorViewSchema.parse(populatedAttentionBody.attention);
    expect(populatedAttention).toMatchObject({ kind: "available", latest: attentionResult });
    const publicBoundaryResponse = await fetch(
      `${startup.origin}/api/events?limit=100&type=runtime.boundary.checked.v1`,
    );
    const publicBoundaryBody = (await publicBoundaryResponse.json()) as {
      events: { payload: unknown; type: string }[];
    };
    expect(publicBoundaryResponse.status).toBe(200);
    expect(publicBoundaryBody.events).toEqual([
      expect.objectContaining({
        schemaVersion: 1,
        kind: "runtime_audit_projection",
        type: "runtime.boundary.checked.v1",
        ledgerAnchor: {
          kind: "opaque_runtime_ledger_anchor",
          previousHash: expect.stringMatching(/^[0-9a-f]{64}$/),
          eventHash: expect.stringMatching(/^[0-9a-f]{64}$/),
        },
        payload: {
          schemaVersion: 1,
          kind: "runtime_boundary_public_summary",
          boundary: "attention_refresh",
          decision: "allowed",
          reason: "ALLOWED",
        },
      }),
    ]);
    const publicBoundaryJson = JSON.stringify(publicBoundaryBody);
    for (const receiptField of [
      "actionId",
      "authorizationId",
      "checkedMode",
      "checkedProcessInstanceId",
      "checkedRevision",
      "expiresAt",
      "requestedAt",
      "requestedMode",
      "requestedProcessInstanceId",
      "requestedRevision",
    ]) {
      expect(publicBoundaryJson).not.toContain(`"${receiptField}"`);
    }
    for (const path of [
      "/api/attention",
      "/api/control/capabilities",
      "/api/events?limit=100",
      "/api/research",
      "/api/runtime",
      "/api/summary",
      "/api/watchlist",
    ]) {
      const response = await fetch(`${startup.origin}${path}`);
      const body = JSON.stringify(await response.json());
      expect(response.status, path).toBe(200);
      for (const privateReceiptField of [
        "actionId",
        "authorizationId",
        "checkedMode",
        "checkedProcessInstanceId",
        "checkedRevision",
        "requestedAt",
        "requestedMode",
        "requestedProcessInstanceId",
        "requestedRevision",
      ]) {
        expect(body, `${path} exposed ${privateReceiptField}`).not.toContain(
          `"${privateReceiptField}"`,
        );
      }
    }

    const proposeOnly = await fetch(`${startup.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-propose-only",
        expectedMode: "RESEARCH",
        expectedRevision: researchMode.result.revision,
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
    expect(proposeOnly.status).toBe(200);
    expect(await proposeOnly.json()).toMatchObject({
      result: {
        mode: "PROPOSE_ONLY",
        capabilities: {
          researchCollection: true,
          proposalPersistence: true,
          policyApproval: false,
          paidRead: false,
          walletSign: false,
          transactionBroadcast: false,
        },
      },
    });

    const replayRequestId = randomUUID();
    const replayHeaders = {
      "content-type": "application/json",
      origin: startup.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };
    const runReplay = (scenario: string, requestId: string) =>
      fetch(`${startup.origin}/api/research/replay`, {
        body: JSON.stringify({ action: "run-recorded-replay", requestId, scenario }),
        headers: replayHeaders,
        method: "POST",
      });
    const replay = await runReplay("safe", replayRequestId);
    const replayBody = (await replay.json()) as { result: Record<string, unknown> };
    expect(replay.status).toBe(200);
    expect(replayBody).toMatchObject({
      result: {
        kind: "recorded_fixture_replay",
        scenario: "safe",
        disposition: { kind: "abstain", reason: "market_uncertainty" },
        replayEvaluatedAt: "2026-08-11T12:00:00.000Z",
        duplicate: false,
      },
    });
    const duplicate = await runReplay("safe", replayRequestId);
    expect(await duplicate.json()).toEqual({
      result: { ...replayBody.result, duplicate: true },
    });

    const hostile = await runReplay("prompt-injection", randomUUID());
    const hostileBody = await hostile.json();
    expect(hostile.status).toBe(200);
    expect(hostileBody).toMatchObject({
      result: {
        scenario: "prompt-injection",
        disposition: { kind: "abstain", reason: "integrity_risk" },
      },
    });
    expect(JSON.stringify(hostileBody)).not.toContain("Ignore all previous");
    expect(JSON.stringify(hostileBody)).not.toContain("private key");

    const populatedResearch = await fetch(`${startup.origin}/api/research`);
    expect(await populatedResearch.json()).toMatchObject({
      research: { schemaVersion: 1, candidateCount: 0, abstentionCount: 2 },
    });

    const exited = waitForExit(child);
    child.kill("SIGINT");
    expect(await exited).toBe(0);

    child = spawn(
      process.execPath,
      [
        ...OPERATOR_ARGUMENTS,
        "--db",
        runtimePath,
        "--research-db",
        researchPath,
        "--attention-db",
        attentionPath,
        "--port",
        "0",
      ],
      {
        cwd: ROOT,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const restarted = await waitForStartup(child);
    const restartedHeaders = {
      "content-type": "application/json",
      origin: restarted.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };
    const attentionAuditBeforeResponse = await fetch(
      `${restarted.origin}/api/events?limit=100&type=runtime.boundary.checked.v1`,
    );
    const attentionAuditBefore = (await attentionAuditBeforeResponse.json()) as {
      events: unknown[];
    };
    const restartedAttentionRecord = await fetch(`${restarted.origin}/api/attention/record`, {
      body: JSON.stringify({
        input: attentionInput,
        expected: attentionResult.binding,
      }),
      headers: restartedHeaders,
      method: "POST",
    });
    expect(restartedAttentionRecord.status).toBe(200);
    const restartedAttentionRecordBody = (await restartedAttentionRecord.json()) as {
      result: unknown;
    };
    expect(AttentionOperatorResultSchema.parse(restartedAttentionRecordBody.result)).toEqual(
      attentionResult,
    );
    const restartedAttentionPreview = await fetch(`${restarted.origin}/api/attention/preview`, {
      body: JSON.stringify({ input: attentionInput }),
      headers: restartedHeaders,
      method: "POST",
    });
    expect(restartedAttentionPreview.status).toBe(200);
    const restartedAttentionPreviewBody = (await restartedAttentionPreview.json()) as {
      preview: unknown;
    };
    expect(AttentionOperatorPreviewSchema.parse(restartedAttentionPreviewBody.preview)).toEqual({
      schemaVersion: 2,
      kind: "already_recorded",
      result: attentionResult,
    });
    const attentionAuditAfter = (await (
      await fetch(`${restarted.origin}/api/events?limit=100&type=runtime.boundary.checked.v1`)
    ).json()) as { events: unknown[] };
    expect(attentionAuditAfter.events).toEqual(attentionAuditBefore.events);
    const stoppedDuplicate = await fetch(`${restarted.origin}/api/research/replay`, {
      body: JSON.stringify({
        action: "run-recorded-replay",
        requestId: replayRequestId,
        scenario: "safe",
      }),
      headers: restartedHeaders,
      method: "POST",
    });
    expect(stoppedDuplicate.status).toBe(409);
    expect(await stoppedDuplicate.json()).toEqual({
      error: {
        code: "runtime_conflict",
        message: "Runtime mode changed; refresh and try again.",
      },
    });

    const restartedRuntimeResponse = await fetch(`${restarted.origin}/api/runtime`);
    const restartedRuntimeBody = (await restartedRuntimeResponse.json()) as {
      runtime: { mode: string; revision: number };
    };
    expect(restartedRuntimeBody.runtime.mode).toBe("STOPPED");
    const restartedResearchMode = await fetch(`${restarted.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: restartedRuntimeBody.runtime.revision,
        requestId: randomUUID(),
      }),
      headers: restartedHeaders,
      method: "POST",
    });
    const restartedResearchModeBody = (await restartedResearchMode.json()) as {
      result: { revision: number };
    };
    expect(restartedResearchMode.status).toBe(200);
    const researchModeDuplicate = await fetch(`${restarted.origin}/api/research/replay`, {
      body: JSON.stringify({
        action: "run-recorded-replay",
        requestId: replayRequestId,
        scenario: "safe",
      }),
      headers: restartedHeaders,
      method: "POST",
    });
    expect(researchModeDuplicate.status).toBe(409);
    const restartedProposeOnly = await fetch(`${restarted.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-propose-only",
        expectedMode: "RESEARCH",
        expectedRevision: restartedResearchModeBody.result.revision,
        requestId: randomUUID(),
      }),
      headers: restartedHeaders,
      method: "POST",
    });
    expect(restartedProposeOnly.status).toBe(200);
    const restartedDuplicate = await fetch(`${restarted.origin}/api/research/replay`, {
      body: JSON.stringify({
        action: "run-recorded-replay",
        requestId: replayRequestId,
        scenario: "safe",
      }),
      headers: restartedHeaders,
      method: "POST",
    });
    expect(restartedDuplicate.status).toBe(200);
    expect(await restartedDuplicate.json()).toEqual({
      result: { ...replayBody.result, duplicate: true },
    });
    const restartedProjection = await fetch(`${restarted.origin}/api/research`);
    expect(await restartedProjection.json()).toMatchObject({
      research: { schemaVersion: 1, candidateCount: 0, abstentionCount: 2 },
    });

    const restartedExit = waitForExit(child);
    child.kill("SIGINT");
    expect(await restartedExit).toBe(0);

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

    const reopenedResearch = SqliteResearchLedger.open(researchPath);
    expect(reopenedResearch.getProjection()).toMatchObject({
      schemaVersion: 1,
      candidateCount: 0,
      abstentionCount: 2,
    });
    reopenedResearch.close();
    const researchBytes = await readFile(researchPath);
    expect(researchBytes.includes(Buffer.from("Ignore all previous"))).toBe(false);
    expect(researchBytes.includes(Buffer.from("private key"))).toBe(false);
    const reopenedAttention = new SqliteEventStore(attentionPath);
    expect(reopenedAttention.list()).toMatchObject([
      { sequence: 1, type: "attention.history.initialized.v1" },
      { sequence: 2, type: "attention.batch.recorded.v2" },
    ]);
    reopenedAttention.close();
    const attentionBytes = await readFile(attentionPath);
    expect(attentionBytes.includes(Buffer.from("Ignore previous safety instructions"))).toBe(false);
    expect(attentionBytes.includes(Buffer.from("100000000000000002"))).toBe(false);
  });

  it("creates fresh default Stage 0 directories owner-only without poisoning Stage 1", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-default-modes-"));
    child = spawn(process.execPath, [...OPERATOR_ARGUMENTS, "--port", "0"], {
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
    expect(startup.attentionDatabasePath).toBe(
      join(canonicalDirectory, ".local/stage0/rsi-attention.sqlite"),
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
      [...OPERATOR_ARGUMENTS, "--db", runtimePath, "--research-db", researchPath, "--port", "0"],
      {
        cwd: ROOT,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    expect(await waitForExit(child)).toBe(1);
  });

  it("refuses hard-linked attention and watchlist database files", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-attention-hardlink-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    const watchlistPath = join(directory, "watchlist.sqlite");
    const attentionPath = join(directory, "attention.sqlite");
    await writeFile(watchlistPath, "");
    await link(watchlistPath, attentionPath);

    child = spawn(
      process.execPath,
      [
        ...OPERATOR_ARGUMENTS,
        "--db",
        runtimePath,
        "--research-db",
        researchPath,
        "--watchlist-db",
        watchlistPath,
        "--attention-db",
        attentionPath,
        "--port",
        "0",
      ],
      { cwd: ROOT, env: process.env, stdio: ["pipe", "pipe", "pipe"] },
    );
    expect(await waitForExit(child)).toBe(1);
  });

  it("refuses a symlinked attention database alias", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-attention-symlink-"));
    const runtimePath = join(directory, "runtime.sqlite");
    const researchPath = join(directory, "research.sqlite");
    const attentionPath = join(directory, "attention.sqlite");
    await writeFile(runtimePath, "");
    await symlink(runtimePath, attentionPath);

    child = spawn(
      process.execPath,
      [
        ...OPERATOR_ARGUMENTS,
        "--db",
        runtimePath,
        "--research-db",
        researchPath,
        "--attention-db",
        attentionPath,
        "--port",
        "0",
      ],
      { cwd: ROOT, env: process.env, stdio: ["pipe", "pipe", "pipe"] },
    );
    expect(await waitForExit(child)).toBe(1);
  });

  it("refuses case-folded runtime and attention path aliases at startup", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-operator-attention-casefold-"));
    const runtimePath = join(directory, "Collection.sqlite");
    const researchPath = join(directory, "research.sqlite");
    const attentionPath = join(directory, "collection.SQLITE");

    await writeFile(runtimePath, "");
    const runtimeFile = await stat(runtimePath);
    const pathsAlias = await stat(attentionPath).then(
      (attentionFile) =>
        runtimeFile.dev === attentionFile.dev && runtimeFile.ino === attentionFile.ino,
      (error: unknown) => {
        if (
          error instanceof Error &&
          "code" in error &&
          (error as NodeJS.ErrnoException).code === "ENOENT"
        ) {
          return false;
        }
        throw error;
      },
    );
    if (!pathsAlias) return;

    child = spawn(
      process.execPath,
      [
        ...OPERATOR_ARGUMENTS,
        "--db",
        runtimePath,
        "--research-db",
        researchPath,
        "--attention-db",
        attentionPath,
        "--port",
        "0",
      ],
      { cwd: ROOT, env: process.env, stdio: ["pipe", "pipe", "pipe"] },
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
      const watchlistClose = vi.fn(() => undefined);
      const attentionClose = vi.fn(() => undefined);
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
      vi.doMock("@rsi/watchlist", async (importOriginal) => ({
        ...(await importOriginal<typeof import("@rsi/watchlist")>()),
        OfflineBaseWatchlist: { open: vi.fn(() => ({ close: watchlistClose })) },
      }));
      vi.doMock("@rsi/attention", () => ({
        createRuntimeAttentionReceiptVerifier: vi.fn(() => ({})),
        RecordedAttentionHistory: { open: vi.fn(() => ({ close: attentionClose })) },
      }));
      vi.doMock("../src/attention-provider.js", () => ({
        createAttentionProvider: vi.fn(() => ({})),
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
        assertDistinctStage0DatabasePaths: vi.fn(),
        assertStage0StorageIsolation: vi.fn(),
        operatorUsage: vi.fn(() => "unused"),
        parseOperatorOptions: vi.fn(() => ({
          attentionDatabasePath: join(directory!, "attention.sqlite"),
          databasePath: runtimePath,
          port: 0,
          researchDatabasePath: researchPath,
          watchlistDatabasePath: join(directory!, "watchlist.sqlite"),
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
        expect(attentionClose).toHaveBeenCalledOnce();
        expect(researchClose).toHaveBeenCalledOnce();
        expect(watchlistClose).toHaveBeenCalledOnce();
        expect(runtimeStop).toHaveBeenCalledTimes(2);
        expect(runtimeClose).toHaveBeenCalledOnce();
        expect(serverClose.mock.invocationCallOrder[0]).toBeLessThan(
          attentionClose.mock.invocationCallOrder[0]!,
        );
        expect(attentionClose.mock.invocationCallOrder[0]).toBeLessThan(
          runtimeClose.mock.invocationCallOrder[0]!,
        );
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
        vi.doUnmock("@rsi/watchlist");
        vi.doUnmock("@rsi/attention");
        vi.doUnmock("../src/attention-provider.js");
        vi.doUnmock("@rsi/operator");
        vi.doUnmock("../src/operator-options.js");
        vi.doUnmock("../src/production-canary-config.js");
      }
    },
  );
});
