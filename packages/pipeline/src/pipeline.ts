import { createHash } from "node:crypto";

import {
  Bytes32Schema,
  ExecutionIntentSchema,
  PositiveAtomicAmountSchema,
  assetKey,
  type ExecutionIntent,
  type PolicyConfig,
} from "@rsi/domain";
import {
  PolicyKernel,
  canonicalHash,
  executionIntentHash,
  type PolicyDecision,
  type PolicyKernelState,
} from "@rsi/policy";
import {
  extractResearchBatch,
  loadRecordedFixtures,
  summarizeCorrelation,
  type CorrelationSummary,
  type FixtureAnalysis,
} from "@rsi/research";
import {
  EventStoreIntegrityError,
  SqliteEventStore,
  type JsonValue,
  type StoredEvent,
} from "@rsi/store";

import {
  FIXTURE_CHAIN_ID,
  FIXTURE_COLLECTION,
  FIXTURE_MARKETPLACE_TARGET,
  FIXTURE_ORDER_HASH,
  FIXTURE_PAYMENT_ASSET,
  FIXTURE_RECIPIENT,
} from "./constants.js";
import {
  FIXTURE_SCENARIOS,
  FixtureScenarioNameSchema,
  type FixtureScenarioName,
} from "./scenarios.js";

const RUN_ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$/;

export interface RunScenarioOptions {
  readonly runId: string;
  readonly now?: Date;
  readonly maxTotalSpend?: string;
}

export interface ScenarioRunReport {
  readonly runId: string;
  readonly scenario: FixtureScenarioName;
  readonly maxTotalSpend: string;
  readonly evaluatedAt: string;
  readonly fixtureCount: number;
  readonly observationCount: number;
  readonly correlation: CorrelationSummary;
  readonly decision: PolicyDecision;
  readonly eventRange: {
    readonly firstSequence: number;
    readonly lastSequence: number;
  };
  readonly rawContentPersisted: false;
}

export class ScenarioRunConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScenarioRunConflictError";
  }
}

const RSI_FIXTURE_PIPELINE_CONSTRUCTION_TOKEN = Object.freeze({});
const AUTHENTIC_RSI_FIXTURE_PIPELINES = new WeakSet<object>();

function jsonValue(value: unknown): JsonValue {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("event payload is not JSON serializable");
  return JSON.parse(encoded) as JsonValue;
}

function eventSafeAnalysis(analysis: FixtureAnalysis): JsonValue {
  return jsonValue({
    observationId: analysis.observationId,
    fixtureType: analysis.fixtureType,
    contentHash: analysis.contentHash,
    instructionFlags: analysis.instructionFlags,
    identityFlags: analysis.identityFlags,
    accountSignals: analysis.accountSignals,
    coordinationSignals: analysis.coordinationSignals,
    urls: analysis.urls.map((trace) => ({
      traceHash: `sha256:${createHash("sha256").update(JSON.stringify(trace)).digest("hex")}`,
      redirectCount: trace.redirects.length,
      flags: trace.flags,
    })),
  });
}

function payloadObject(event: StoredEvent): Record<string, JsonValue> {
  if (event.payload === null || Array.isArray(event.payload) || typeof event.payload !== "object") {
    throw new Error(`event ${event.eventId} payload is not an object`);
  }
  return event.payload as Record<string, JsonValue>;
}

function persistedDecision(event: StoredEvent): PolicyDecision {
  const decision = payloadObject(event).decision;
  if (decision === null || Array.isArray(decision) || typeof decision !== "object") {
    throw new Error(`event ${event.eventId} does not contain a policy decision`);
  }
  const candidate = decision as Record<string, JsonValue>;
  if (typeof candidate.approved !== "boolean") {
    throw new Error(`event ${event.eventId} has an invalid approval flag`);
  }
  if (
    typeof candidate.decisionId !== "string" ||
    !Bytes32Schema.safeParse(candidate.decisionId).success ||
    typeof candidate.evaluatedAt !== "string" ||
    !Number.isFinite(Date.parse(candidate.evaluatedAt)) ||
    typeof candidate.policyHash !== "string" ||
    !Bytes32Schema.safeParse(candidate.policyHash).success ||
    !Array.isArray(candidate.reasons) ||
    candidate.reasons.some((reason) => typeof reason !== "string")
  ) {
    throw new Error(`event ${event.eventId} has an invalid decision envelope`);
  }

  if (candidate.approved) {
    if (
      typeof candidate.intentHash !== "string" ||
      !Bytes32Schema.safeParse(candidate.intentHash).success ||
      candidate.reasons.length !== 0
    ) {
      throw new Error(`event ${event.eventId} has no approved intent hash`);
    }
    const intent = ExecutionIntentSchema.parse(candidate.intent);
    const intentHash = executionIntentHash(intent);
    if (
      candidate.intentHash.toLowerCase() !== intentHash.toLowerCase() ||
      candidate.policyHash.toLowerCase() !== intent.policyHash.toLowerCase() ||
      candidate.decisionId.toLowerCase() !==
        canonicalHash({
          approved: true,
          evaluatedAt: candidate.evaluatedAt,
          intentHash,
          policyHash: candidate.policyHash,
        }).toLowerCase()
    ) {
      throw new Error(`event ${event.eventId} has an inconsistent approved decision`);
    }
    return {
      approved: true,
      decisionId: candidate.decisionId,
      evaluatedAt: candidate.evaluatedAt,
      policyHash: candidate.policyHash,
      intentHash,
      reasons: [],
      intent,
    };
  }

  return candidate as unknown as PolicyDecision;
}

function restoreKernelState(
  store: SqliteEventStore,
  policyHash: string,
): PolicyKernelState | undefined {
  const decisions = store.list({ type: "policy.decided", order: "asc" });
  if (decisions.length === 0) return undefined;

  const processedIntentIds = new Set<string>();
  const processedNonces = new Set<`0x${string}`>();
  const dailySpend = new Map<string, bigint>();
  for (const event of decisions) {
    const decision = persistedDecision(event);
    if (decision.policyHash.toLowerCase() !== policyHash.toLowerCase()) {
      throw new Error("persisted decision belongs to a different policy hash");
    }
    if (!decision.approved) continue;

    if (processedIntentIds.has(decision.intent.intentId)) {
      throw new Error("persisted approvals reuse an intent ID");
    }
    const normalizedNonce = decision.intent.action.nonce.toLowerCase() as `0x${string}`;
    if (processedNonces.has(normalizedNonce)) {
      throw new Error("persisted approvals reuse an action nonce");
    }
    processedIntentIds.add(decision.intent.intentId);
    processedNonces.add(normalizedNonce);
    const day = decision.evaluatedAt.slice(0, 10);
    const key = `${day}:${assetKey(
      decision.intent.action.chainId,
      decision.intent.action.paymentAsset,
    )}`;
    dailySpend.set(key, (dailySpend.get(key) ?? 0n) + BigInt(decision.intent.action.maxTotalSpend));
  }

  return {
    schemaVersion: 1,
    policyHash,
    processedIntentIds: [...processedIntentIds].sort(),
    processedNonces: [...processedNonces].sort(),
    dailySpendByKey: Object.fromEntries(
      [...dailySpend.entries()].map(([key, value]) => [key, value.toString()]),
    ),
  };
}

function nonceFor(runId: string): `0x${string}` {
  return `0x${createHash("sha256").update(`rsi-fixture-nonce:${runId}`).digest("hex")}`;
}

function intentFor(
  runId: string,
  observations: readonly { observationId: string }[],
  policyVersion: string,
  policyHash: string,
  now: Date,
  maxTotalSpend: string,
): ExecutionIntent {
  return ExecutionIntentSchema.parse({
    intentId: `rsi-intent:${runId}`,
    strategyVersion: "rsi-fixture-v1",
    policyVersion,
    policyHash,
    evidenceIds: observations.map(({ observationId }) => observationId),
    createdAt: new Date(now.getTime() - 5_000).toISOString(),
    expiresAt: new Date(now.getTime() + 30_000).toISOString(),
    action: {
      kind: "nft.purchase",
      adapterId: "opensea.seaport",
      chainId: FIXTURE_CHAIN_ID,
      marketplace: "opensea",
      targetContract: FIXTURE_MARKETPLACE_TARGET,
      collectionContract: FIXTURE_COLLECTION,
      tokenId: "7",
      paymentAsset: FIXTURE_PAYMENT_ASSET,
      maxTotalSpend,
      recipient: FIXTURE_RECIPIENT,
      orderHash: FIXTURE_ORDER_HASH,
      nonce: nonceFor(runId),
    },
  });
}

function existingRunTime(store: SqliteEventStore, aggregateId: string): Date | undefined {
  const event = store.list({ aggregateId, type: "run.started", limit: 1 })[0];
  if (event === undefined) return undefined;
  const value = payloadObject(event).evaluatedAt;
  if (typeof value !== "string") throw new Error("run.started has no evaluatedAt timestamp");
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("run.started timestamp is invalid");
  return date;
}

function existingReport(
  store: SqliteEventStore,
  aggregateId: string,
): ScenarioRunReport | undefined {
  const event = store.list({ aggregateId, type: "run.completed", limit: 1 })[0];
  if (event === undefined) return undefined;
  const report = payloadObject(event).report;
  if (report === null || Array.isArray(report) || typeof report !== "object") {
    throw new Error("run.completed has no report object");
  }
  const candidate = report as unknown as ScenarioRunReport;
  FixtureScenarioNameSchema.parse(candidate.scenario);
  if (
    !RUN_ID.test(candidate.runId) ||
    !PositiveAtomicAmountSchema.safeParse(candidate.maxTotalSpend).success ||
    candidate.rawContentPersisted !== false
  ) {
    throw new Error("run.completed has an invalid report envelope");
  }
  persistedDecision({ ...event, payload: { decision: jsonValue(candidate.decision) } });
  return candidate;
}

function assertMatchingRun(
  report: ScenarioRunReport,
  request: { runId: string; scenario: FixtureScenarioName; maxTotalSpend: string },
): void {
  if (
    report.runId !== request.runId ||
    report.scenario !== request.scenario ||
    report.maxTotalSpend !== request.maxTotalSpend
  ) {
    throw new ScenarioRunConflictError(
      "runId is already associated with a different scenario request",
    );
  }
}

export class RsiFixturePipeline {
  readonly store: SqliteEventStore;
  readonly policy: Readonly<PolicyConfig>;
  readonly policyHash: `0x${string}`;

  static open(path: string, policy: PolicyConfig): RsiFixturePipeline {
    const store = new SqliteEventStore(path);
    try {
      const pipeline = new RsiFixturePipeline(
        store,
        policy,
        RSI_FIXTURE_PIPELINE_CONSTRUCTION_TOKEN,
      );
      AUTHENTIC_RSI_FIXTURE_PIPELINES.add(pipeline);
      return pipeline;
    } catch (error) {
      store.close();
      throw error;
    }
  }

  private constructor(store: SqliteEventStore, policy: PolicyConfig, constructionToken: unknown) {
    if (constructionToken !== RSI_FIXTURE_PIPELINE_CONSTRUCTION_TOKEN) {
      throw new Error("RsiFixturePipeline must be created through RsiFixturePipeline.open");
    }
    const probe = new PolicyKernel(policy);
    const state = restoreKernelState(store, probe.policyHash);
    // Parse and validate any reconstructed state before exposing the pipeline.
    new PolicyKernel(policy, state);
    this.store = store;
    this.policy = probe.policy;
    this.policyHash = probe.policyHash;
  }

  async runScenario(
    rawScenario: FixtureScenarioName,
    options: RunScenarioOptions,
  ): Promise<ScenarioRunReport> {
    this.assertAuthentic();
    const integrity = this.store.verifyIntegrity();
    if (!integrity.valid) throw new EventStoreIntegrityError(integrity);
    const scenario = FixtureScenarioNameSchema.parse(rawScenario);
    if (!RUN_ID.test(options.runId)) {
      throw new Error("runId must contain 1-96 safe identifier characters");
    }
    const maxTotalSpend = options.maxTotalSpend ?? "5000000";
    PositiveAtomicAmountSchema.parse(maxTotalSpend);

    const aggregateId = `run:${options.runId}`;
    const completed = existingReport(this.store, aggregateId);
    if (completed !== undefined) {
      assertMatchingRun(completed, { runId: options.runId, scenario, maxTotalSpend });
      return completed;
    }

    const now = existingRunTime(this.store, aggregateId) ?? options.now ?? new Date();
    if (!Number.isFinite(now.getTime())) throw new Error("scenario time must be valid");
    const evaluatedAt = now.toISOString();
    const append = (stage: string, payload: unknown, identity = stage): StoredEvent =>
      this.store.append({
        aggregateId,
        idempotencyKey: `${aggregateId}:${identity}`,
        occurredAt: evaluatedAt,
        type: stage,
        payload: jsonValue(payload),
      });

    append("run.started", {
      evaluatedAt,
      fixtureNames: FIXTURE_SCENARIOS[scenario],
      maxTotalSpend,
      runId: options.runId,
      scenario,
    });

    const captures = await loadRecordedFixtures(FIXTURE_SCENARIOS[scenario]);
    captures.forEach((capture, index) => {
      append(
        "fixture.quarantined",
        {
          capture: capture.metadata,
          fixtureName: FIXTURE_SCENARIOS[scenario][index],
          index,
        },
        `fixture.quarantined:${index}`,
      );
    });

    const batch = extractResearchBatch(captures);
    batch.observations.forEach((observation, index) => {
      append("observation.extracted", { index, observation }, `observation.extracted:${index}`);
    });
    batch.analyses.forEach((analysis, index) => {
      append(
        "observation.analyzed",
        { analysis: eventSafeAnalysis(analysis), index },
        `observation.analyzed:${index}`,
      );
    });

    const correlation = summarizeCorrelation(
      batch.observations,
      { chainId: FIXTURE_CHAIN_ID, address: FIXTURE_COLLECTION, tokenId: "7" },
      now,
    );
    append("evidence.correlated", { correlation });

    const intent = intentFor(
      options.runId,
      batch.observations,
      this.policy.policyVersion,
      this.policyHash,
      now,
      maxTotalSpend,
    );
    append("intent.proposed", { intent });

    return this.store.withExclusiveTransaction(() => {
      const racedCompletion = existingReport(this.store, aggregateId);
      if (racedCompletion !== undefined) {
        assertMatchingRun(racedCompletion, { runId: options.runId, scenario, maxTotalSpend });
        return racedCompletion;
      }

      const state = restoreKernelState(this.store, this.policyHash);
      const kernel = new PolicyKernel(this.policy, state);
      const priorDecisionEvent = this.store.list({
        aggregateId,
        type: "policy.decided",
        limit: 1,
      })[0];
      const decision =
        priorDecisionEvent === undefined
          ? kernel.authorize(intent, batch.observations, now)
          : persistedDecision(priorDecisionEvent);
      append("policy.decided", { decision, runId: options.runId, scenario });
      append("policy.state", { state: kernel.exportState() });

      const runEvents = this.store.list({ aggregateId, order: "asc" });
      const firstSequence = runEvents[0]?.sequence;
      if (firstSequence === undefined) throw new Error("run has no persisted start event");
      const lastSequence = this.store.verifyIntegrity().headSequence + 1;
      const report: ScenarioRunReport = {
        runId: options.runId,
        scenario,
        maxTotalSpend,
        evaluatedAt,
        fixtureCount: captures.length,
        observationCount: batch.observations.length,
        correlation,
        decision,
        eventRange: { firstSequence, lastSequence },
        rawContentPersisted: false,
      };
      const completedEvent = append("run.completed", { report });
      if (completedEvent.sequence !== lastSequence) {
        throw new Error("run completion sequence did not match the report");
      }
      return report;
    });
  }

  close(): void {
    this.assertAuthentic();
    this.store.close();
  }

  private assertAuthentic(): void {
    if (
      Object.getPrototypeOf(this) !== RsiFixturePipeline.prototype ||
      !AUTHENTIC_RSI_FIXTURE_PIPELINES.has(this)
    ) {
      throw new Error("RsiFixturePipeline was not created through its authenticated factory");
    }
  }
}

export function isRsiFixturePipeline(value: unknown): value is RsiFixturePipeline {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === RsiFixturePipeline.prototype &&
    AUTHENTIC_RSI_FIXTURE_PIPELINES.has(value)
  );
}
