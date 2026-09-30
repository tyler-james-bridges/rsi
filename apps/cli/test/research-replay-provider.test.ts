import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteResearchLedger } from "@rsi/research-ledger";
import { RuntimeBoundaryDeniedError, SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it } from "vitest";

import { createRecordedResearchReplayProvider } from "../src/research-replay-provider.js";

const OPENED_AT = "2026-09-30T03:40:00.000Z";
const RESEARCH_AT = "2026-09-30T03:40:01.000Z";
const PROPOSE_AT = "2026-09-30T03:40:02.000Z";
const AUTHORIZED_AT = "2026-09-30T03:40:03.000Z";
const REQUEST_ID = "11111111-1111-4111-8111-111111111111";

describe("recorded research replay provider", () => {
  const temporaryDirectories: string[] = [];

  afterEach(async () => {
    await Promise.all(
      temporaryDirectories
        .splice(0)
        .map((directory) => rm(directory, { recursive: true, force: true })),
    );
  });

  async function open() {
    const directory = await mkdtemp(join(tmpdir(), "rsi-recorded-replay-"));
    temporaryDirectories.push(directory);
    let now = OPENED_AT;
    let monotonic = 1_000;
    const runtime = SqliteRuntimeController.open(
      {
        openedAt: OPENED_AT,
        path: join(directory, "runtime.sqlite"),
        processInstanceId: randomUUID(),
      },
      { clock: () => now, monotonicClock: () => monotonic },
    );
    const research = SqliteResearchLedger.open(join(directory, "research.sqlite"));
    return {
      directory,
      research,
      runtime,
      authorize() {
        const stopped = runtime.getSnapshot();
        const researching = runtime.transition({
          expectedMode: "STOPPED",
          expectedRevision: stopped.revision,
          occurredAt: RESEARCH_AT,
          requestId: randomUUID(),
          targetMode: "RESEARCH",
        });
        runtime.transition({
          expectedMode: "RESEARCH",
          expectedRevision: researching.revision,
          occurredAt: PROPOSE_AT,
          requestId: randomUUID(),
          targetMode: "PROPOSE_ONLY",
        });
        now = AUTHORIZED_AT;
        monotonic += 1;
      },
    };
  }

  it("denies persistence outside PROPOSE_ONLY and persists an exact idempotent abstention", async () => {
    const context = await open();
    const provider = createRecordedResearchReplayProvider(context);
    const command = {
      action: "run-recorded-replay" as const,
      requestId: REQUEST_ID,
      scenario: "safe" as const,
    };

    expect(() => provider.executeResearchReplay(command)).toThrow(RuntimeBoundaryDeniedError);
    expect(context.research.getProjection().proposals).toHaveLength(0);
    context.authorize();

    const first = provider.executeResearchReplay(command);
    expect(first).toMatchObject({
      schemaVersion: 1,
      kind: "recorded_fixture_replay",
      scenario: "safe",
      proposalId: `rsi-proposal:safe-${REQUEST_ID}`,
      disposition: { kind: "abstain", reason: "market_uncertainty" },
      replayEvaluatedAt: "2026-08-11T12:00:00.000Z",
      duplicate: false,
    });
    const repeated = provider.executeResearchReplay(command);
    expect(repeated).toEqual({ ...first, duplicate: true });
    expect(context.research.getProjection()).toMatchObject({
      schemaVersion: 1,
      candidateCount: 0,
      abstentionCount: 1,
      proposals: [
        {
          eventSequence: 1,
          proposal: {
            strategyVersion: "rsi-recorded-replay-v1",
            scorecard: { opportunity: 0 },
          },
        },
      ],
    });
    context.research.close();
    context.runtime.close();

    let restartedNow = "2026-09-30T03:41:00.000Z";
    const restartedRuntime = SqliteRuntimeController.open(
      {
        openedAt: restartedNow,
        path: join(context.directory, "runtime.sqlite"),
        processInstanceId: randomUUID(),
      },
      { clock: () => restartedNow, monotonicClock: () => 2_000 },
    );
    const restartedResearch = SqliteResearchLedger.open(join(context.directory, "research.sqlite"));
    const restartedProvider = createRecordedResearchReplayProvider({
      runtime: restartedRuntime,
      research: restartedResearch,
    });
    expect(restartedRuntime.getSnapshot().mode).toBe("STOPPED");
    expect(() => restartedProvider.executeResearchReplay(command)).toThrow(
      RuntimeBoundaryDeniedError,
    );

    const researching = restartedRuntime.transition({
      expectedMode: "STOPPED",
      expectedRevision: restartedRuntime.getSnapshot().revision,
      occurredAt: "2026-09-30T03:41:01.000Z",
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    expect(() => restartedProvider.executeResearchReplay(command)).toThrow(
      RuntimeBoundaryDeniedError,
    );
    restartedRuntime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: researching.revision,
      occurredAt: "2026-09-30T03:41:02.000Z",
      requestId: randomUUID(),
      targetMode: "PROPOSE_ONLY",
    });
    restartedNow = "2026-09-30T03:41:03.000Z";
    expect(restartedProvider.executeResearchReplay(command)).toEqual({
      ...first,
      duplicate: true,
    });
    expect(restartedResearch.getProjection().proposals).toHaveLength(1);
    restartedResearch.close();
    restartedRuntime.close();
  });

  it("persists hostile flags without persisting hostile source material", async () => {
    const context = await open();
    context.authorize();
    const provider = createRecordedResearchReplayProvider(context);
    const result = provider.executeResearchReplay({
      action: "run-recorded-replay",
      requestId: REQUEST_ID,
      scenario: "prompt-injection",
    });
    expect(result.disposition).toEqual({ kind: "abstain", reason: "integrity_risk" });
    const projection = context.research.getProjection();
    expect(projection.proposals[0]?.proposal.flags.injection.length).toBeGreaterThan(0);
    expect(JSON.stringify(projection)).not.toContain("Ignore all previous");
    expect(JSON.stringify(projection)).not.toContain("private key");
    context.research.close();
    context.runtime.close();

    const bytes = await readFile(join(context.directory, "research.sqlite"));
    expect(bytes.includes(Buffer.from("Ignore all previous"))).toBe(false);
    expect(bytes.includes(Buffer.from("private key"))).toBe(false);
  });

  it("refuses new work after STOP and while the host is closing", async () => {
    const context = await open();
    context.authorize();
    let closing = false;
    const provider = createRecordedResearchReplayProvider({
      ...context,
      isClosing: () => closing,
    });
    const stopped = context.runtime.stop({
      occurredAt: "2026-09-30T03:40:04.000Z",
      requestId: randomUUID(),
    });
    expect(stopped.mode).toBe("STOPPED");
    expect(() =>
      provider.executeResearchReplay({
        action: "run-recorded-replay",
        requestId: REQUEST_ID,
        scenario: "safe",
      }),
    ).toThrow(RuntimeBoundaryDeniedError);
    closing = true;
    expect(() =>
      provider.executeResearchReplay({
        action: "run-recorded-replay",
        requestId: randomUUID(),
        scenario: "safe",
      }),
    ).toThrow(/host is closing/);
    context.research.close();
    context.runtime.close();
  });
});
