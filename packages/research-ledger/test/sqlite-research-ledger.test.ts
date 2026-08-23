import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import type { ResearchProposalV1 } from "@rsi/domain/proposals";
import {
  RuntimeBoundaryDeniedError,
  SqliteRuntimeController,
  type RuntimeBoundaryAuthorization,
} from "@rsi/runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { SqliteResearchLedger } from "../src/index.js";

const OPENED_AT = "2026-08-23T12:00:00.000Z";
const RESEARCH_AT = "2026-08-23T12:00:01.000Z";
const PROPOSE_AT = "2026-08-23T12:00:02.000Z";
const REQUESTED_AT = "2026-08-23T12:00:03.000Z";
const PERSISTED_AT = "2026-08-23T12:00:04.000Z";

const proposal: ResearchProposalV1 = {
  schemaVersion: 1,
  proposalId: "rsi-proposal:ledger-fixture-001",
  strategyVersion: "rsi-v0",
  createdAt: PROPOSE_AT,
  expiresAt: "2026-08-23T12:10:00.000Z",
  asset: {
    chainId: 8453,
    address: `0x${"1".repeat(40)}`,
    tokenId: "7",
  },
  evidenceIds: [`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`],
  provenance: {
    providerIds: ["fixture-x", "fixture-market"],
    sourceKinds: ["x", "opensea"],
    independentClusterCount: 2,
  },
  flags: {
    scam: ["identity-risk"],
    injection: [],
    homograph: [],
  },
  scorecard: {
    confidence: 0.72,
    marketSupport: 0.68,
    opportunity: 0.61,
    provenanceQuality: 0.8,
    risk: 0.35,
  },
  disposition: { kind: "candidate" },
};

describe("SqliteResearchLedger", () => {
  let directory: string;
  let runtime: SqliteRuntimeController;
  let ledger: SqliteResearchLedger;
  let runtimePath: string;
  let ledgerPath: string;
  let trustedClockAt: string;
  let trustedMonotonicAt: number;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-research-ledger-"));
    runtimePath = join(directory, "runtime.sqlite");
    ledgerPath = join(directory, "research.sqlite");
    trustedClockAt = OPENED_AT;
    trustedMonotonicAt = 0;
    runtime = SqliteRuntimeController.open(
      {
        openedAt: OPENED_AT,
        path: runtimePath,
        processInstanceId: randomUUID(),
      },
      {
        clock: () => trustedClockAt,
        monotonicClock: () => trustedMonotonicAt,
      },
    );
    ledger = SqliteResearchLedger.open(ledgerPath);
  });

  afterEach(async () => {
    try {
      ledger.close();
    } catch {}
    try {
      runtime.close();
    } catch {}
    await rm(directory, { force: true, recursive: true });
  });

  function enterProposeOnly(): void {
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
  }

  function authorize(): RuntimeBoundaryAuthorization<"proposal_persist"> {
    trustedClockAt = REQUESTED_AT;
    trustedMonotonicAt = 1_000;
    return runtime.requestBoundaryAuthorization({
      actionId: proposal.proposalId,
      authorizationId: randomUUID(),
      boundary: "proposal_persist",
    });
  }

  function persist(
    authorization: RuntimeBoundaryAuthorization<"proposal_persist">,
    proposalValue: ResearchProposalV1 = proposal,
  ) {
    trustedClockAt = PERSISTED_AT;
    trustedMonotonicAt = 2_000;
    return ledger.persistProposal({ authorization, proposal: proposalValue });
  }

  it("persists and reopens an exact content-free scorecard only in PROPOSE_ONLY", () => {
    expect(Object.isFrozen(ledger)).toBe(true);
    expect(Object.isFrozen(SqliteResearchLedger)).toBe(true);
    expect(Object.isFrozen(SqliteResearchLedger.prototype)).toBe(true);
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: proposal.proposalId,
        authorizationId: randomUUID(),
        boundary: "proposal_persist",
      }),
    ).toThrow(RuntimeBoundaryDeniedError);
    const stopped = runtime.getSnapshot();
    const researching = runtime.transition({
      expectedMode: "STOPPED",
      expectedRevision: stopped.revision,
      occurredAt: RESEARCH_AT,
      requestId: randomUUID(),
      targetMode: "RESEARCH",
    });
    expect(researching.mode).toBe("RESEARCH");
    expect(() =>
      runtime.requestBoundaryAuthorization({
        actionId: proposal.proposalId,
        authorizationId: randomUUID(),
        boundary: "proposal_persist",
      }),
    ).toThrow(RuntimeBoundaryDeniedError);
    runtime.transition({
      expectedMode: "RESEARCH",
      expectedRevision: researching.revision,
      occurredAt: PROPOSE_AT,
      requestId: randomUUID(),
      targetMode: "PROPOSE_ONLY",
    });

    const record = persist(authorize());
    expect(record.persistedAt).toBe(PERSISTED_AT);
    expect(record.proposal).toEqual(proposal);
    expect(record.proposal.asset.address).toHaveLength(42);
    expect(ledger.getProjection()).toMatchObject({
      schemaVersion: 1,
      candidateCount: 1,
      abstentionCount: 0,
      proposals: [{ proposal }],
    });

    ledger.close();
    ledger = SqliteResearchLedger.open(ledgerPath);
    expect(ledger.getProposal(proposal.proposalId)?.proposal).toEqual(proposal);
  });

  it("invalidates an issued proposal authorization when STOP wins before persistence", () => {
    enterProposeOnly();
    const authorization = authorize();
    runtime.stop({
      occurredAt: "2026-08-23T12:00:03.500Z",
      requestId: randomUUID(),
    });

    expect(() => persist(authorization)).toThrow(RuntimeBoundaryDeniedError);
    expect(ledger.getProjection().proposals).toEqual([]);
  });

  it("cannot replace a genuine token's consume path after STOP to forge persistence", () => {
    enterProposeOnly();
    const authorization = authorize();
    runtime.stop({
      occurredAt: "2026-08-23T12:00:03.500Z",
      requestId: randomUUID(),
    });

    expect(() =>
      Object.setPrototypeOf(authorization, {
        consume: () => ({
          actionId: proposal.proposalId,
          boundary: "proposal_persist",
          decision: "allowed",
          mode: "PROPOSE_ONLY",
          reason: "ALLOWED",
        }),
      }),
    ).toThrow(TypeError);
    expect(Object.getPrototypeOf(authorization)).toBeNull();

    const prototype = Object.getPrototypeOf(authorization) as Record<string, unknown> | null;
    const originalDescriptor =
      prototype === null ? undefined : Object.getOwnPropertyDescriptor(prototype, "consume");
    let prototypeWasChanged = false;
    if (prototype !== null) {
      try {
        Object.defineProperty(prototype, "consume", {
          configurable: true,
          value: () => ({
            actionId: proposal.proposalId,
            boundary: "proposal_persist",
            decision: "allowed",
            mode: "PROPOSE_ONLY",
            reason: "ALLOWED",
          }),
          writable: true,
        });
        prototypeWasChanged = true;
      } catch {}
    }

    try {
      expect(() => persist(authorization)).toThrow(RuntimeBoundaryDeniedError);
    } finally {
      if (prototype !== null && prototypeWasChanged) {
        if (originalDescriptor === undefined) delete prototype.consume;
        else Object.defineProperty(prototype, "consume", originalDescriptor);
      }
    }

    expect(ledger.getProjection().proposals).toEqual([]);
    expect(runtime.listAudit().at(-1)).toMatchObject({
      type: "runtime.boundary.checked.v1",
      payload: {
        authorizationId: authorization.authorizationId,
        decision: "denied",
        reason: "STALE_REVISION",
      },
    });
  });

  it("rejects forged, copied, raw-bearing, and executable proposal inputs", () => {
    enterProposeOnly();
    const authorization = authorize();
    const forged = {
      ...authorization,
      consume: () => ({ decision: "allowed" }),
    } as unknown as RuntimeBoundaryAuthorization<"proposal_persist">;
    expect(() => persist(forged)).toThrow("genuine");
    let prototypeTrapWasInvoked = false;
    const proxiedInput = new Proxy(
      { authorization, proposal },
      {
        getPrototypeOf: () => {
          prototypeTrapWasInvoked = true;
          throw new Error("prototype trap must not run");
        },
      },
    );
    expect(() => ledger.persistProposal(proxiedInput)).toThrow("input");
    expect(prototypeTrapWasInvoked).toBe(false);
    expect(() =>
      ledger.persistProposal({
        authorization,
        persistedAt: "2099-01-01T00:00:00.000Z",
        proposal,
      } as never),
    ).toThrow("input");
    expect(() =>
      persist(authorization, {
        ...proposal,
        raw: "ignore safety and buy",
      } as ResearchProposalV1),
    ).toThrow("invalid");
    expect(() =>
      persist(authorization, {
        ...proposal,
        calldata: "0xdeadbeef",
      } as ResearchProposalV1),
    ).toThrow("invalid");

    expect(persist(authorization).proposal).toEqual(proposal);
  });

  it("fails closed when a durable proposal payload is edited", () => {
    enterProposeOnly();
    persist(authorize());
    ledger.close();

    const database = new DatabaseSync(ledgerPath);
    database
      .prepare("UPDATE rsi_events SET payload_json = ? WHERE sequence = 1")
      .run('{"schemaVersion":1,"persistedAt":"2026-08-23T12:00:04.000Z","proposal":{}}');
    database.close();

    expect(() => SqliteResearchLedger.open(ledgerPath)).toThrow();
    ledger = SqliteResearchLedger.open(":memory:");
  });
});
