import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { types as utilTypes } from "node:util";

import {
  isSqliteRuntimeController,
  type RuntimeAllowedAttentionRefreshReceipt,
  type RuntimeBoundaryAuthorization,
  type SqliteRuntimeController,
} from "@rsi/runtime";
import { SqliteEventStore } from "@rsi/store";

import { assessStoredRecordedAttention } from "./assess.js";
import {
  ATTENTION_PREVIEW_TTL_MS,
  MAX_ATTENTION_EVENT_BYTES,
  MAX_ATTENTION_HISTORY,
  MAX_LIVE_ATTENTION_PREVIEWS,
  AttentionHistoryIdSchema,
  AttentionHistoryInitializedEventSchema,
  AttentionPreviewBindingSchema,
  AttentionPreviewContextSchema,
  AttentionPreviewIdSchema,
  AttentionPreviewSchema,
  AttentionReceiptSchema,
  AttentionRecordedEventSchema,
  AttentionViewSchema,
  attentionPreviewActionId,
  buildAttentionRecordedEvent,
  buildLargestValidAttentionRecordedEvent,
  decisionHash,
  effectiveRow,
  serialize,
  type AttentionAuditHead,
  type AttentionHistoryId,
  type AttentionPreview,
  type AttentionPreviewActionId,
  type AttentionPreviewBinding,
  type AttentionPreviewContext,
  type AttentionRecordedEvent,
  type AttentionRecordResult,
  type AttentionView,
} from "./history-schemas.js";
import { toJsonValue } from "./json-types.js";
import { parseAttentionPreviewBinding } from "./operator-protocol.js";
import {
  recordedBundleId,
  recordedRefreshId,
  sanitizeRecordedAttentionBundle,
} from "./sanitize.js";
import {
  ATTENTION_POLICY_VERSION,
  MAX_CANONICAL_TIME_MILLISECONDS,
  assertPlainAttentionData,
  deepFreeze,
  emptyRecordedAttentionFacts,
  parseCanonicalTime,
  type RecordedAttentionFactsV1,
  type SanitizedRecordedBundleV1,
} from "./schemas.js";

const GENESIS_EVENT_TYPE = "attention.history.initialized.v1";
const BATCH_EVENT_TYPE = "attention.batch.recorded.v2";
const LEGACY_BATCH_EVENT_TYPE = "attention.batch.recorded.v1";
const AGGREGATE_ID = "attention:recorded-base";
const GENESIS_HASH = "0".repeat(64);
const VERIFIERS = new WeakMap<object, string>();
const HISTORIES = new WeakSet<object>();
const SYSTEM_MONOTONIC_CLOCK = () => performance.now();

export interface RuntimeAttentionReceiptVerifier {
  ownsAttentionRefreshAuthorization(
    input: unknown,
  ): input is RuntimeBoundaryAuthorization<"attention_refresh">;
  verifyPersistedAttentionRefreshReceipts(
    input: unknown,
  ): readonly Readonly<RuntimeAllowedAttentionRefreshReceipt>[];
}

export function createRuntimeAttentionReceiptVerifier(
  runtime: SqliteRuntimeController,
): RuntimeAttentionReceiptVerifier {
  if (!isSqliteRuntimeController(runtime))
    throw new AttentionHistoryError("runtime_verifier_invalid");
  const verifier: RuntimeAttentionReceiptVerifier = Object.freeze({
    ownsAttentionRefreshAuthorization: (
      input: unknown,
    ): input is RuntimeBoundaryAuthorization<"attention_refresh"> =>
      runtime.ownsAttentionRefreshAuthorization(input),
    verifyPersistedAttentionRefreshReceipts: (input: unknown) =>
      runtime.verifyPersistedAttentionRefreshReceipts(input),
  });
  VERIFIERS.set(verifier, runtime.processInstanceId);
  return verifier;
}

export class AttentionHistoryError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "AttentionHistoryError";
  }
}

export interface AttentionRecordCommand {
  readonly input: unknown;
  readonly expected: AttentionPreviewBinding;
  readonly authorization: RuntimeBoundaryAuthorization<"attention_refresh">;
}

interface RecordEntry {
  readonly head: AttentionAuditHead;
  readonly payload: AttentionRecordedEvent;
}

interface RawHistoryHead {
  readonly eventHash: string;
  readonly sequence: number;
}

interface ReplayResult {
  readonly genesisHash: string;
  readonly historyId: AttentionHistoryId;
  readonly rawHead: RawHistoryHead;
  readonly records: readonly RecordEntry[];
}

interface PreviewLease {
  readonly actionId: AttentionPreviewActionId;
  readonly binding: string;
  readonly expiresAt: number;
}

function headOf(records: readonly RecordEntry[]): AttentionAuditHead | null {
  return records.at(-1)?.head ?? null;
}

function factsOf(records: readonly RecordEntry[]): RecordedAttentionFactsV1 {
  return records.at(-1)?.payload.nextFacts ?? emptyRecordedAttentionFacts();
}

function assertEventBound(payload: unknown): void {
  if (Buffer.byteLength(serialize(payload), "utf8") > MAX_ATTENTION_EVENT_BYTES) {
    throw new AttentionHistoryError("attention_event_too_large");
  }
}

function replay(store: SqliteEventStore): ReplayResult {
  const events = store.list({ limit: MAX_ATTENTION_HISTORY + 2 });
  if (events.length > MAX_ATTENTION_HISTORY + 1)
    throw new AttentionHistoryError("attention_history_full");
  const genesis = events[0];
  const identity = parseGenesis(genesis);
  const records: RecordEntry[] = [];
  const ids = new Set<string>();
  const authorizations = new Set<string>();
  const receiptHashes = new Set<string>();
  for (const event of events.slice(1)) {
    if (event.type === LEGACY_BATCH_EVENT_TYPE)
      throw new AttentionHistoryError("attention_history_unsupported");
    if (event.type === GENESIS_EVENT_TYPE)
      throw new AttentionHistoryError("attention_history_inconsistent");
    assertEventBound(event.payload);
    const payload = parseStoredEvent(AttentionRecordedEventSchema, event.payload);
    const { result, sourceFacts, nextFacts } = payload;
    const { binding, assessment, authorization, checkpointAt } = result;
    const prior = records.at(-1);
    const recomputed = assessStoredRecordedAttention({
      sourceFacts,
      evaluatedAt: binding.evaluatedAt,
      priorFacts: factsOf(records),
    });
    const checkpointAssessment = assessStoredRecordedAttention({
      sourceFacts,
      evaluatedAt: checkpointAt,
      priorFacts: factsOf(records),
    });
    if (
      event.type !== BATCH_EVENT_TYPE ||
      event.aggregateId !== AGGREGATE_ID ||
      event.eventId !== `attention-batch-v2:${binding.refreshId}` ||
      event.idempotencyKey !== `attention-batch-v2:${binding.refreshId}` ||
      event.occurredAt !== checkpointAt ||
      event.sequence !== records.length + 2 ||
      binding.historyId !== identity.historyId ||
      serialize(binding.auditHead) !== serialize(headOf(records)) ||
      authorization.actionId !== attentionPreviewActionId(binding) ||
      serialize(recomputed) !== serialize({ assessment, nextFacts }) ||
      decisionHash(recomputed) !== binding.decisionHash ||
      decisionHash(checkpointAssessment) !== binding.decisionHash ||
      (prior !== undefined &&
        (Date.parse(binding.evaluatedAt) < Date.parse(prior.payload.result.checkpointAt) ||
          authorization.eventSequence <= prior.payload.result.authorization.eventSequence)) ||
      ids.has(binding.refreshId) ||
      authorizations.has(authorization.authorizationId) ||
      receiptHashes.has(authorization.eventHash)
    )
      throw new AttentionHistoryError("attention_history_inconsistent");
    ids.add(binding.refreshId);
    authorizations.add(authorization.authorizationId);
    receiptHashes.add(authorization.eventHash);
    records.push(
      deepFreeze({
        head: {
          refreshId: binding.refreshId,
          eventHash: event.eventHash,
          sequence: event.sequence,
        },
        payload,
      }),
    );
  }
  const rawHeadEvent = events.at(-1);
  if (rawHeadEvent === undefined) throw new AttentionHistoryError("attention_history_inconsistent");
  return deepFreeze({
    genesisHash: identity.genesisHash,
    historyId: identity.historyId,
    rawHead: { eventHash: rawHeadEvent.eventHash, sequence: rawHeadEvent.sequence },
    records,
  });
}

function parseGenesis(genesis: ReturnType<SqliteEventStore["list"]>[number] | undefined) {
  if (genesis === undefined) throw new AttentionHistoryError("attention_history_inconsistent");
  if (genesis.type === LEGACY_BATCH_EVENT_TYPE)
    throw new AttentionHistoryError("attention_history_unsupported");
  if (genesis.type !== GENESIS_EVENT_TYPE)
    throw new AttentionHistoryError("attention_history_inconsistent");
  assertEventBound(genesis.payload);
  const initialized = parseStoredEvent(AttentionHistoryInitializedEventSchema, genesis.payload);
  if (
    genesis.aggregateId !== AGGREGATE_ID ||
    genesis.sequence !== 1 ||
    genesis.previousHash !== GENESIS_HASH ||
    genesis.eventId !== `attention-history-v1:${initialized.historyId}` ||
    genesis.idempotencyKey !== `attention-history-v1:${initialized.historyId}` ||
    genesis.occurredAt !== initialized.initializedAt
  ) {
    throw new AttentionHistoryError("attention_history_inconsistent");
  }
  return deepFreeze({
    genesisHash: genesis.eventHash,
    historyId: initialized.historyId,
  });
}

function readIdentityAndRawHead(store: SqliteEventStore): Readonly<{
  genesisHash: string;
  historyId: AttentionHistoryId;
  rawHead: RawHistoryHead;
}> {
  const identity = parseGenesis(store.list({ limit: 1 })[0]);
  const rawHead = store.list({ order: "desc", limit: 1 })[0];
  if (rawHead === undefined) throw new AttentionHistoryError("attention_history_inconsistent");
  return deepFreeze({
    genesisHash: identity.genesisHash,
    historyId: identity.historyId,
    rawHead: { eventHash: rawHead.eventHash, sequence: rawHead.sequence },
  });
}

function parseStoredEvent<T>(schema: { parse(value: unknown): T }, payload: unknown): T {
  try {
    return schema.parse(payload);
  } catch {
    throw new AttentionHistoryError("attention_history_inconsistent");
  }
}

function existingResult(
  records: readonly RecordEntry[],
  sourceFacts: SanitizedRecordedBundleV1,
): AttentionRecordResult | null {
  const refreshId = recordedRefreshId(recordedBundleId(sourceFacts));
  const existing = records.find((record) => record.head.refreshId === refreshId);
  if (existing === undefined) return null;
  if (serialize(existing.payload.sourceFacts) !== serialize(sourceFacts))
    throw new AttentionHistoryError("attention_identity_reused");
  return existing.payload.result;
}

function buildPreview(
  sourceFacts: SanitizedRecordedBundleV1,
  context: AttentionPreviewContext,
  state: ReplayResult,
  previewId: string,
): Extract<AttentionPreview, { kind: "preview" }> {
  const records = state.records;
  if (records.length >= MAX_ATTENTION_HISTORY)
    throw new AttentionHistoryError("attention_history_full");
  const latest = records.at(-1);
  if (
    latest !== undefined &&
    Date.parse(context.evaluatedAt) < Date.parse(latest.payload.result.checkpointAt)
  ) {
    throw new AttentionHistoryError("clock_regressed");
  }
  const deadlineMs = Date.parse(context.evaluatedAt) + ATTENTION_PREVIEW_TTL_MS;
  if (deadlineMs > MAX_CANONICAL_TIME_MILLISECONDS)
    throw new AttentionHistoryError("attention_time_invalid");
  const result = assessStoredRecordedAttention({
    sourceFacts,
    evaluatedAt: context.evaluatedAt,
    priorFacts: factsOf(records),
  });
  const binding = AttentionPreviewBindingSchema.parse({
    schemaVersion: 2,
    kind: "attention_preview_binding",
    policyVersion: ATTENTION_POLICY_VERSION,
    historyId: state.historyId,
    previewId,
    bundleId: result.assessment.bundleId,
    refreshId: result.assessment.refreshId,
    auditHead: headOf(records),
    processInstanceId: context.processInstanceId,
    modeRevision: context.modeRevision,
    evaluatedAt: context.evaluatedAt,
    deadline: new Date(deadlineMs).toISOString(),
    decisionHash: decisionHash(result),
  });
  assertEventBound(
    buildLargestValidAttentionRecordedEvent({ sourceFacts, binding, assessed: result }),
  );
  const preview = AttentionPreviewSchema.parse({
    schemaVersion: 2,
    kind: "preview",
    binding,
    assessment: result.assessment,
  });
  if (preview.kind !== "preview") throw new AttentionHistoryError("attention_preview_mismatch");
  return deepFreeze(preview);
}

function initializeEmptyHistory(store: SqliteEventStore): void {
  store.withExclusiveTransaction(() => {
    if (store.list({ limit: 1 }).length !== 0) return;
    const historyId = AttentionHistoryIdSchema.parse(randomUUID());
    const initializedAt = new Date().toISOString();
    const payload = AttentionHistoryInitializedEventSchema.parse({
      schemaVersion: 1,
      kind: "attention_history_initialized",
      historyId,
      initializedAt,
    });
    store.append({
      type: GENESIS_EVENT_TYPE,
      aggregateId: AGGREGATE_ID,
      eventId: `attention-history-v1:${historyId}`,
      idempotencyKey: `attention-history-v1:${historyId}`,
      occurredAt: initializedAt,
      payload: toJsonValue(payload),
    });
  });
}

interface AttentionHistoryOpenOptions {
  readonly path: string;
  readonly receiptVerifier: RuntimeAttentionReceiptVerifier;
  readonly monotonicClock?: () => number;
}

function isRuntimeAttentionReceiptVerifier(
  value: unknown,
): value is RuntimeAttentionReceiptVerifier {
  return typeof value === "object" && value !== null && VERIFIERS.has(value);
}

function parseOpenOptions(input: unknown): Readonly<{
  path: string;
  receiptVerifier: RuntimeAttentionReceiptVerifier;
  monotonicClock: () => number;
}> {
  if (
    input === null ||
    typeof input !== "object" ||
    utilTypes.isProxy(input) ||
    Object.getPrototypeOf(input) !== Object.prototype
  ) {
    throw new AttentionHistoryError("attention_open_options_invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(input);
  if (
    keys.some((key) => key !== "path" && key !== "receiptVerifier" && key !== "monotonicClock") ||
    !["path", "receiptVerifier"].every((key) => {
      const descriptor = descriptors[key];
      return descriptor !== undefined && descriptor.enumerable && "value" in descriptor;
    })
  ) {
    throw new AttentionHistoryError("attention_open_options_invalid");
  }
  const path = descriptors.path?.value as unknown;
  const receiptVerifier = descriptors.receiptVerifier?.value as unknown;
  const monotonicDescriptor = descriptors.monotonicClock;
  const monotonicClock =
    monotonicDescriptor === undefined
      ? SYSTEM_MONOTONIC_CLOCK
      : "value" in monotonicDescriptor &&
          monotonicDescriptor.enumerable &&
          typeof monotonicDescriptor.value === "function" &&
          !utilTypes.isProxy(monotonicDescriptor.value)
        ? (monotonicDescriptor.value as () => number)
        : null;
  if (
    typeof path !== "string" ||
    !isRuntimeAttentionReceiptVerifier(receiptVerifier) ||
    monotonicClock === null
  ) {
    throw new AttentionHistoryError(
      !isRuntimeAttentionReceiptVerifier(receiptVerifier)
        ? "runtime_verifier_invalid"
        : "attention_open_options_invalid",
    );
  }
  return Object.freeze({
    path,
    receiptVerifier,
    monotonicClock,
  });
}

export class RecordedAttentionHistory {
  #cachedReplay: ReplayResult | null = null;
  #closed = false;
  #genesisHash: string | null = null;
  #historyId: AttentionHistoryId | null = null;
  #lastMonotonic: number | null = null;
  readonly #leases = new Map<string, PreviewLease>();
  readonly #monotonicClock: () => number;
  readonly #store: SqliteEventStore;
  readonly #verifier: RuntimeAttentionReceiptVerifier;

  static open(options: AttentionHistoryOpenOptions): RecordedAttentionHistory;
  static open(optionsValue: unknown): RecordedAttentionHistory {
    const options = parseOpenOptions(optionsValue);
    const store = new SqliteEventStore(options.path);
    const history = new RecordedAttentionHistory(
      store,
      options.receiptVerifier,
      options.monotonicClock,
    );
    HISTORIES.add(history);
    try {
      initializeEmptyHistory(store);
      history.#verifiedReplay();
      Object.freeze(history);
      return history;
    } catch (error) {
      store.close();
      throw error;
    }
  }

  private constructor(
    store: SqliteEventStore,
    verifier: RuntimeAttentionReceiptVerifier,
    monotonicClock: () => number,
  ) {
    this.#store = store;
    this.#verifier = verifier;
    this.#monotonicClock = monotonicClock;
  }

  findRecorded(input: unknown): AttentionRecordResult | null {
    this.#assertAuthentic();
    const sourceFacts = sanitizeRecordedAttentionBundle(input);
    return existingResult(this.#verifiedReplay().records, sourceFacts);
  }

  preview(input: unknown, context: AttentionPreviewContext): AttentionPreview {
    this.#assertAuthentic();
    const sourceFacts = sanitizeRecordedAttentionBundle(input);
    assertPlainAttentionData(context);
    const parsedContext = AttentionPreviewContextSchema.parse(context);
    const state = this.#verifiedReplay();
    const result = existingResult(state.records, sourceFacts);
    if (result === null && parsedContext.processInstanceId !== VERIFIERS.get(this.#verifier)) {
      throw new AttentionHistoryError("attention_authority_mismatch");
    }
    if (result !== null) {
      return deepFreeze(
        AttentionPreviewSchema.parse({ schemaVersion: 2, kind: "already_recorded", result }),
      );
    }
    const preview = buildPreview(
      sourceFacts,
      parsedContext,
      state,
      AttentionPreviewIdSchema.parse(randomUUID()),
    );
    const leaseWindow = this.#reserveLeaseWindow();
    const actionId = attentionPreviewActionId(preview.binding);
    if (this.#leases.has(preview.binding.previewId))
      throw new AttentionHistoryError("attention_preview_id_collision");
    this.#leases.set(preview.binding.previewId, {
      actionId,
      binding: serialize(preview.binding),
      expiresAt: leaseWindow.expiresAt,
    });
    return preview;
  }

  record(command: AttentionRecordCommand): AttentionRecordResult {
    this.#assertAuthentic();
    assertRecordCommand(command);
    const sourceFacts = sanitizeRecordedAttentionBundle(command.input);
    const expected = parseAttentionPreviewBinding(command.expected);
    const verified = this.#verifiedReplay();
    const existing = existingResult(verified.records, sourceFacts);
    if (existing !== null) {
      if (serialize(expected) !== serialize(existing.binding))
        throw new AttentionHistoryError("attention_preview_mismatch");
      return existing;
    }
    const preview = this.#recomputePreview(sourceFacts, expected, verified);
    if (serialize(preview.binding) !== serialize(expected))
      throw new AttentionHistoryError("attention_preview_mismatch");
    const authorization = command.authorization;
    const actionId = attentionPreviewActionId(expected);
    if (
      !this.#verifier.ownsAttentionRefreshAuthorization(authorization) ||
      authorization.actionId !== actionId ||
      authorization.processInstanceId !== VERIFIERS.get(this.#verifier) ||
      authorization.processInstanceId !== expected.processInstanceId ||
      authorization.requestedRevision !== expected.modeRevision ||
      authorization.requestedMode !== "RESEARCH"
    ) {
      throw new AttentionHistoryError("attention_authority_mismatch");
    }
    this.#assertLiveLease(expected);
    let result: AttentionRecordResult | undefined;
    authorization.consumeAndCommit((receipt, checkpoint) => {
      result = this.#store.withExclusiveTransaction(() => {
        const current = this.#replayUnderLock();
        if (
          current.genesisHash !== verified.genesisHash ||
          current.historyId !== verified.historyId ||
          serialize(current.rawHead) !== serialize(verified.rawHead)
        )
          throw new AttentionHistoryError("attention_preview_stale");
        this.#assertLiveLease(expected);
        const currentPreview = this.#recomputePreview(sourceFacts, expected, current);
        if (serialize(currentPreview) !== serialize(preview))
          throw new AttentionHistoryError("attention_preview_mismatch");
        const assessed = assessStoredRecordedAttention({
          sourceFacts,
          evaluatedAt: expected.evaluatedAt,
          priorFacts: factsOf(current.records),
        });
        if (
          current.records.some(
            (record) =>
              record.payload.result.authorization.authorizationId === receipt.authorizationId ||
              record.payload.result.authorization.eventHash === receipt.eventHash,
          ) ||
          receipt.eventSequence <=
            (current.records.at(-1)?.payload.result.authorization.eventSequence ?? 0)
        ) {
          throw new AttentionHistoryError("attention_authorization_reused");
        }
        const checkpointAt = checkpoint().checkedAt;
        if (Date.parse(checkpointAt) >= Date.parse(expected.deadline))
          throw new AttentionHistoryError("attention_preview_expired");
        const finalAssessment = assessStoredRecordedAttention({
          sourceFacts,
          evaluatedAt: checkpointAt,
          priorFacts: factsOf(current.records),
        });
        if (decisionHash(finalAssessment) !== expected.decisionHash)
          throw new AttentionHistoryError("attention_classification_changed");
        const payload = buildAttentionRecordedEvent({
          sourceFacts,
          binding: expected,
          assessed,
          authorization: AttentionReceiptSchema.parse(receipt),
          checkpointAt,
        });
        assertEventBound(payload);
        this.#assertLiveLease(expected);
        this.#store.append({
          type: BATCH_EVENT_TYPE,
          aggregateId: AGGREGATE_ID,
          eventId: `attention-batch-v2:${expected.refreshId}`,
          idempotencyKey: `attention-batch-v2:${expected.refreshId}`,
          occurredAt: checkpointAt,
          payload: toJsonValue(payload),
        });
        return deepFreeze(payload.result);
      });
    });
    if (result === undefined) throw new AttentionHistoryError("attention_commit_missing");
    this.#leases.delete(expected.previewId);
    const committed = this.#verifiedReplay().records.at(-1)?.payload.result;
    if (committed === undefined || serialize(committed) !== serialize(result))
      throw new AttentionHistoryError("attention_history_changed");
    return result;
  }

  read(evaluatedAt: string): AttentionView {
    this.#assertAuthentic();
    parseCanonicalTime(evaluatedAt);
    const records = this.#verifiedReplay().records;
    const latest = records.at(-1)?.payload.result ?? null;
    if (latest !== null && Date.parse(evaluatedAt) < Date.parse(latest.checkpointAt)) {
      return deepFreeze(
        AttentionViewSchema.parse({
          schemaVersion: 1,
          kind: "unavailable",
          reason: "clock_regressed",
          evaluatedAt,
          latestCheckpointAt: latest.checkpointAt,
        }),
      );
    }
    return deepFreeze(
      AttentionViewSchema.parse({
        schemaVersion: 1,
        kind: "available",
        provenance: "operator_supplied_unverified",
        evaluatedAt,
        auditHead: headOf(records),
        latest,
        rows: latest?.assessment.rows.map((row) => effectiveRow(row, evaluatedAt)) ?? [],
        history: records
          .slice(-20)
          .reverse()
          .map(({ head, payload: { result } }) => ({
            head,
            bundleId: result.assessment.bundleId,
            predecessorId: result.assessment.predecessorId,
            acquiredAt: result.assessment.sourceSummary.marketplace.acquiredAt,
            validUntil: result.assessment.sourceSummary.marketplace.validUntil,
            evaluatedAt: result.assessment.evaluatedAt,
            checkpointAt: result.checkpointAt,
            usableRankWindow: result.assessment.sourceSummary.marketplace.usable,
          })),
      }),
    );
  }

  close(): void {
    if (this.#closed) return;
    this.#assertAuthentic();
    this.#leases.clear();
    this.#cachedReplay = null;
    this.#store.close();
    this.#closed = true;
  }
  [Symbol.dispose](): void {
    this.close();
  }

  #recomputePreview(
    sourceFacts: SanitizedRecordedBundleV1,
    expected: AttentionPreviewBinding,
    state: ReplayResult,
  ): Extract<AttentionPreview, { kind: "preview" }> {
    if (expected.historyId !== state.historyId)
      throw new AttentionHistoryError("attention_history_mismatch");
    if (serialize(expected.auditHead) !== serialize(headOf(state.records)))
      throw new AttentionHistoryError("attention_preview_stale");
    return buildPreview(
      sourceFacts,
      {
        processInstanceId: expected.processInstanceId,
        modeRevision: expected.modeRevision,
        evaluatedAt: expected.evaluatedAt,
      },
      state,
      expected.previewId,
    );
  }

  #reserveLeaseWindow(): Readonly<{ expiresAt: number }> {
    const now = this.#readMonotonicClock();
    for (const [previewId, lease] of this.#leases) {
      if (now >= lease.expiresAt) this.#leases.delete(previewId);
    }
    if (this.#leases.size >= MAX_LIVE_ATTENTION_PREVIEWS)
      throw new AttentionHistoryError("attention_preview_capacity_reached");
    const expiresAt = now + ATTENTION_PREVIEW_TTL_MS;
    if (!Number.isFinite(expiresAt) || expiresAt > Number.MAX_SAFE_INTEGER)
      throw new AttentionHistoryError("attention_monotonic_clock_invalid");
    return Object.freeze({ expiresAt });
  }

  #assertLiveLease(expected: AttentionPreviewBinding): void {
    const lease = this.#leases.get(expected.previewId);
    if (lease === undefined) throw new AttentionHistoryError("attention_preview_lease_missing");
    if (
      lease.binding !== serialize(expected) ||
      lease.actionId !== attentionPreviewActionId(expected)
    ) {
      throw new AttentionHistoryError("attention_preview_lease_mismatch");
    }
    const now = this.#readMonotonicClock();
    if (now >= lease.expiresAt) {
      this.#leases.delete(expected.previewId);
      throw new AttentionHistoryError("attention_preview_expired");
    }
  }

  #readMonotonicClock(): number {
    let value: unknown;
    try {
      value = this.#monotonicClock();
    } catch {
      throw new AttentionHistoryError("attention_monotonic_clock_failed");
    }
    if (
      typeof value !== "number" ||
      !Number.isFinite(value) ||
      value < 0 ||
      value > Number.MAX_SAFE_INTEGER
    ) {
      throw new AttentionHistoryError("attention_monotonic_clock_invalid");
    }
    if (this.#lastMonotonic !== null && value < this.#lastMonotonic)
      throw new AttentionHistoryError("attention_monotonic_clock_regressed");
    this.#lastMonotonic = value;
    return value;
  }

  #verifiedReplay(): ReplayResult {
    const state = this.#store.withExclusiveTransaction(() => this.#replayUnderLock());
    if (
      (this.#historyId !== null && state.historyId !== this.#historyId) ||
      (this.#genesisHash !== null && state.genesisHash !== this.#genesisHash)
    )
      throw new AttentionHistoryError("attention_history_changed");
    this.#verifyPersistedRuntimeReceipts(state);
    this.#assertReplayStillCurrent(state);
    if (this.#historyId === null || this.#genesisHash === null) {
      this.#historyId = state.historyId;
      this.#genesisHash = state.genesisHash;
    }
    this.#cachedReplay = state;
    return state;
  }

  #verifyPersistedRuntimeReceipts(state: ReplayResult): void {
    if (state.records.length === 0) return;
    this.#verifier.verifyPersistedAttentionRefreshReceipts(
      state.records.map((record) => record.payload.result.authorization),
    );
  }

  #assertReplayStillCurrent(state: ReplayResult): void {
    this.#store.withExclusiveTransaction(() => {
      const current = readIdentityAndRawHead(this.#store);
      if (
        current.genesisHash !== state.genesisHash ||
        current.historyId !== state.historyId ||
        (this.#genesisHash !== null && current.genesisHash !== this.#genesisHash) ||
        (this.#historyId !== null && current.historyId !== this.#historyId) ||
        current.rawHead.eventHash !== state.rawHead.eventHash ||
        current.rawHead.sequence !== state.rawHead.sequence
      ) {
        throw new AttentionHistoryError("attention_history_changed");
      }
    });
  }

  #replayUnderLock(): ReplayResult {
    const cached = this.#cachedReplay;
    if (cached === null) return replay(this.#store);
    const current = readIdentityAndRawHead(this.#store);
    if (
      current.genesisHash === cached.genesisHash &&
      current.historyId === cached.historyId &&
      current.rawHead.eventHash === cached.rawHead.eventHash &&
      current.rawHead.sequence === cached.rawHead.sequence
    ) {
      return cached;
    }
    return replay(this.#store);
  }

  #assertAuthentic(): void {
    if (
      !HISTORIES.has(this) ||
      this.#closed ||
      Object.getPrototypeOf(this) !== RecordedAttentionHistory.prototype
    ) {
      throw new AttentionHistoryError("attention_history_unavailable");
    }
  }
}

function assertRecordCommand(command: AttentionRecordCommand): void {
  if (
    command === null ||
    typeof command !== "object" ||
    utilTypes.isProxy(command) ||
    Object.getPrototypeOf(command) !== Object.prototype
  ) {
    throw new AttentionHistoryError("attention_command_invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(command);
  if (
    Reflect.ownKeys(command).length !== 3 ||
    !["input", "expected", "authorization"].every((key) => {
      const descriptor = descriptors[key];
      return descriptor !== undefined && descriptor.enumerable && "value" in descriptor;
    })
  )
    throw new AttentionHistoryError("attention_command_invalid");
}

Object.freeze(RecordedAttentionHistory.prototype);
Object.freeze(RecordedAttentionHistory);
