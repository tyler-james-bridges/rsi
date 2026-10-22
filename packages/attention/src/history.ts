import { types as utilTypes } from "node:util";

import {
  isRuntimeBoundaryAuthorization,
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
  AttentionPreviewBindingSchema,
  AttentionPreviewContextSchema,
  AttentionPreviewSchema,
  AttentionRecordedEventSchema,
  AttentionViewSchema,
  decisionHash,
  effectiveRow,
  serialize,
  type AttentionAuditHead,
  type AttentionPreview,
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

const EVENT_TYPE = "attention.batch.recorded.v1";
const AGGREGATE_ID = "attention:recorded-base";
const VERIFIERS = new WeakMap<object, string>();
const HISTORIES = new WeakSet<object>();

export interface RuntimeAttentionReceiptVerifier {
  verifyPersistedAttentionRefreshReceipt(
    input: unknown,
  ): Readonly<RuntimeAllowedAttentionRefreshReceipt>;
}

export function createRuntimeAttentionReceiptVerifier(
  runtime: SqliteRuntimeController,
): RuntimeAttentionReceiptVerifier {
  if (!isSqliteRuntimeController(runtime))
    throw new AttentionHistoryError("runtime_verifier_invalid");
  const verifier: RuntimeAttentionReceiptVerifier = Object.freeze({
    verifyPersistedAttentionRefreshReceipt: (input: unknown) =>
      runtime.verifyPersistedAttentionRefreshReceipt(input),
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

function replay(store: SqliteEventStore): readonly RecordEntry[] {
  const events = store.list({ limit: MAX_ATTENTION_HISTORY + 1 });
  if (events.length > MAX_ATTENTION_HISTORY)
    throw new AttentionHistoryError("attention_history_full");
  const records: RecordEntry[] = [];
  const ids = new Set<string>();
  const authorizations = new Set<string>();
  const receiptHashes = new Set<string>();
  for (const event of events) {
    assertEventBound(event.payload);
    const payload = AttentionRecordedEventSchema.parse(event.payload);
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
      event.type !== EVENT_TYPE ||
      event.aggregateId !== AGGREGATE_ID ||
      event.eventId !== `attention-refresh-v1:${binding.refreshId}` ||
      event.idempotencyKey !== `attention-refresh-v1:${binding.refreshId}` ||
      event.occurredAt !== checkpointAt ||
      event.sequence !== records.length + 1 ||
      serialize(binding.auditHead) !== serialize(headOf(records)) ||
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
  return records;
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
  records: readonly RecordEntry[],
): Extract<AttentionPreview, { kind: "preview" }> {
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
    policyVersion: ATTENTION_POLICY_VERSION,
    bundleId: result.assessment.bundleId,
    refreshId: result.assessment.refreshId,
    auditHead: headOf(records),
    processInstanceId: context.processInstanceId,
    modeRevision: context.modeRevision,
    evaluatedAt: context.evaluatedAt,
    deadline: new Date(deadlineMs).toISOString(),
    decisionHash: decisionHash(result),
  });
  // The receipt adds fewer than 1 KiB. Reserve it before admitting a preview.
  if (
    Buffer.byteLength(serialize({ sourceFacts, binding, ...result }), "utf8") >
    MAX_ATTENTION_EVENT_BYTES - 1_024
  ) {
    throw new AttentionHistoryError("attention_event_too_large");
  }
  return deepFreeze({ kind: "preview", binding, assessment: result.assessment });
}

export class RecordedAttentionHistory {
  readonly #store: SqliteEventStore;
  readonly #verifier: RuntimeAttentionReceiptVerifier;

  static open(options: {
    readonly path: string;
    readonly receiptVerifier: RuntimeAttentionReceiptVerifier;
  }): RecordedAttentionHistory {
    if (!VERIFIERS.has(options.receiptVerifier))
      throw new AttentionHistoryError("runtime_verifier_invalid");
    const store = new SqliteEventStore(options.path);
    const history = new RecordedAttentionHistory(store, options.receiptVerifier);
    HISTORIES.add(history);
    try {
      history.#verifiedRecords();
      Object.freeze(history);
      return history;
    } catch (error) {
      store.close();
      throw error;
    }
  }

  private constructor(store: SqliteEventStore, verifier: RuntimeAttentionReceiptVerifier) {
    this.#store = store;
    this.#verifier = verifier;
  }

  findRecorded(input: unknown): AttentionRecordResult | null {
    this.#assertAuthentic();
    const sourceFacts = sanitizeRecordedAttentionBundle(input);
    return existingResult(this.#verifiedRecords(), sourceFacts);
  }

  preview(input: unknown, context: AttentionPreviewContext): AttentionPreview {
    this.#assertAuthentic();
    const sourceFacts = sanitizeRecordedAttentionBundle(input);
    assertPlainAttentionData(context);
    const parsedContext = AttentionPreviewContextSchema.parse(context);
    const records = this.#verifiedRecords();
    const result = existingResult(records, sourceFacts);
    if (result === null && parsedContext.processInstanceId !== VERIFIERS.get(this.#verifier)) {
      throw new AttentionHistoryError("attention_authority_mismatch");
    }
    return result === null
      ? buildPreview(sourceFacts, parsedContext, records)
      : deepFreeze(AttentionPreviewSchema.parse({ kind: "already_recorded", result }));
  }

  record(command: AttentionRecordCommand): AttentionRecordResult {
    this.#assertAuthentic();
    assertRecordCommand(command);
    const sourceFacts = sanitizeRecordedAttentionBundle(command.input);
    const expected = parseAttentionPreviewBinding(command.expected);
    const authorization = command.authorization;
    if (
      !isRuntimeBoundaryAuthorization(authorization) ||
      authorization.boundary !== "attention_refresh" ||
      authorization.actionId !== recordedRefreshId(recordedBundleId(sourceFacts)) ||
      authorization.actionId !== expected.refreshId ||
      authorization.processInstanceId !== VERIFIERS.get(this.#verifier) ||
      authorization.processInstanceId !== expected.processInstanceId ||
      authorization.requestedRevision !== expected.modeRevision ||
      authorization.requestedMode !== "RESEARCH"
    ) {
      throw new AttentionHistoryError("attention_authority_mismatch");
    }
    const verified = this.#verifiedRecords();
    const existing = existingResult(verified, sourceFacts);
    if (existing !== null) {
      if (serialize(expected) !== serialize(existing.binding))
        throw new AttentionHistoryError("attention_preview_mismatch");
      return existing;
    }
    const preview = buildPreview(sourceFacts, expected, verified);
    if (serialize(preview.binding) !== serialize(expected))
      throw new AttentionHistoryError("attention_preview_mismatch");
    let result: AttentionRecordResult | undefined;
    authorization.consumeAndCommit((receipt, checkpoint) => {
      result = this.#store.withExclusiveTransaction(() => {
        const records = replay(this.#store);
        if (serialize(headOf(records)) !== serialize(headOf(verified)))
          throw new AttentionHistoryError("attention_preview_stale");
        const currentPreview = buildPreview(sourceFacts, expected, records);
        if (serialize(currentPreview) !== serialize(preview))
          throw new AttentionHistoryError("attention_preview_mismatch");
        const assessed = assessStoredRecordedAttention({
          sourceFacts,
          evaluatedAt: expected.evaluatedAt,
          priorFacts: factsOf(records),
        });
        if (
          records.some(
            (record) =>
              record.payload.result.authorization.authorizationId === receipt.authorizationId ||
              record.payload.result.authorization.eventHash === receipt.eventHash,
          ) ||
          receipt.eventSequence <= (records.at(-1)?.payload.result.authorization.eventSequence ?? 0)
        ) {
          throw new AttentionHistoryError("attention_authorization_reused");
        }
        const checkpointAt = checkpoint().checkedAt;
        if (Date.parse(checkpointAt) >= Date.parse(expected.deadline))
          throw new AttentionHistoryError("attention_preview_expired");
        const finalAssessment = assessStoredRecordedAttention({
          sourceFacts,
          evaluatedAt: checkpointAt,
          priorFacts: factsOf(records),
        });
        if (decisionHash(finalAssessment) !== expected.decisionHash)
          throw new AttentionHistoryError("attention_classification_changed");
        const payload = AttentionRecordedEventSchema.parse({
          result: {
            schemaVersion: 1,
            kind: "recorded_attention_result",
            binding: expected,
            assessment: assessed.assessment,
            authorization: receipt,
            checkpointAt,
          },
          sourceFacts,
          nextFacts: assessed.nextFacts,
        });
        assertEventBound(payload);
        this.#store.append({
          type: EVENT_TYPE,
          aggregateId: AGGREGATE_ID,
          eventId: `attention-refresh-v1:${expected.refreshId}`,
          idempotencyKey: `attention-refresh-v1:${expected.refreshId}`,
          occurredAt: checkpointAt,
          payload: toJsonValue(payload),
        });
        return deepFreeze(payload.result);
      });
    });
    if (result === undefined) throw new AttentionHistoryError("attention_commit_missing");
    return result;
  }

  read(evaluatedAt: string): AttentionView {
    this.#assertAuthentic();
    parseCanonicalTime(evaluatedAt);
    const records = this.#verifiedRecords();
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
    this.#assertAuthentic();
    this.#store.close();
  }
  [Symbol.dispose](): void {
    this.close();
  }

  #verifiedRecords(): readonly RecordEntry[] {
    const records = this.#store.withExclusiveTransaction(() => replay(this.#store));
    // Never acquire runtime while holding attention. The reverse order is used by record.
    for (const record of records)
      this.#verifier.verifyPersistedAttentionRefreshReceipt(record.payload.result.authorization);
    this.#store.withExclusiveTransaction(() => {
      const current = this.#store.list({ order: "desc", limit: 1 })[0];
      if ((current?.eventHash ?? null) !== (headOf(records)?.eventHash ?? null)) {
        throw new AttentionHistoryError("attention_history_changed");
      }
    });
    return records;
  }

  #assertAuthentic(): void {
    if (
      !HISTORIES.has(this) ||
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
