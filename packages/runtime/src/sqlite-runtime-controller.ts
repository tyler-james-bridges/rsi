import { performance } from "node:perf_hooks";
import { types as utilTypes } from "node:util";

import type { JsonValue, StoredEvent } from "@rsi/store";
import { SqliteEventStore } from "@rsi/store";

import {
  createRuntimeBoundaryAuthorization,
  isRuntimeBoundaryAuthorization,
} from "./boundary-authorization.js";
import {
  RuntimeBoundaryDeniedError,
  RuntimeConflictError,
  RuntimeIntegrityError,
  RuntimeValidationError,
} from "./errors.js";
import {
  OpenRuntimeInputSchema,
  RuntimeBoundaryAuthorizationInputSchema,
  RuntimeCanonicalTimestampSchema,
  RuntimeBoundaryEventPayloadSchema,
  RuntimeStopEventPayloadSchema,
  RuntimeStopInputSchema,
  RuntimeTransitionEventPayloadSchema,
  RuntimeTransitionInputSchema,
  RuntimeUuidSchema,
  parseRuntimeInput,
  type RuntimeBoundaryEventPayload,
  type RuntimeStopEventPayload,
  type RuntimeTransitionEventPayload,
} from "./schemas.js";
import type {
  OpenRuntimeInput,
  RuntimeAuditEvent,
  RuntimeBoundary,
  RuntimeBoundaryAuthorization,
  RuntimeBoundaryAuthorizationInput,
  RuntimeBoundaryCompletion,
  RuntimeBoundaryCompletionFacts,
  RuntimeBoundaryDispatch,
  RuntimeBoundaryDecisionReason,
  RuntimeBoundaryReceipt,
  RuntimeMode,
  RuntimeOpenOptions,
  RuntimeSnapshotV1,
  RuntimeStopInput,
  RuntimeTransitionInput,
} from "./types.js";

export { isRuntimeBoundaryAuthorization };

export const RUNTIME_AGGREGATE_ID = "runtime:authority" as const;
export const RUNTIME_STOP_EVENT_TYPE = "runtime.stop.enforced.v1" as const;
export const RUNTIME_TRANSITION_EVENT_TYPE = "runtime.mode.transitioned.v1" as const;
export const RUNTIME_BOUNDARY_EVENT_TYPE = "runtime.boundary.checked.v1" as const;
export const RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS = 30_000 as const;

export const PERMANENTLY_DENIED_RUNTIME_BOUNDARIES = Object.freeze([
  "policy_approval",
  "paid_read",
  "wallet_sign",
  "execution_adapter",
  "transaction_broadcast",
  "external_publish",
] as const satisfies readonly RuntimeBoundary[]);

const AUTHENTIC_CONTROLLERS = new WeakSet<object>();

interface RuntimeState {
  readonly mode: RuntimeMode;
  readonly modeChangedAt: string;
  readonly modeEventHash: string;
  readonly modeEventSequence: number;
  readonly processInstanceId: string;
  readonly revision: number;
}

interface ReplayResult {
  readonly events: readonly RuntimeAuditEvent[];
  readonly lastAuditAt: string | null;
  readonly requestIds: ReadonlySet<string>;
  readonly state: RuntimeState | null;
}

interface RequestedBoundary {
  readonly actionId: string;
  readonly authorizationId: string;
  readonly boundary: RuntimeBoundary;
  readonly expiresAt: string;
  readonly requestedAt: string;
  readonly requestedMode: RuntimeMode;
  readonly requestedProcessInstanceId: string;
  readonly requestedRevision: number;
}

interface IssuedBoundary extends RequestedBoundary {
  readonly monotonicIssuedAt: number;
  readonly monotonicExpiresAt: number;
}

function toJson(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

const SYSTEM_RUNTIME_CLOCK = (): string => new Date().toISOString();
const SYSTEM_MONOTONIC_CLOCK = (): number => performance.now();

interface RuntimeClocks {
  readonly clock: () => string;
  readonly monotonicClock: () => number;
}

function parseRuntimeOpenOptions(value: unknown): RuntimeClocks {
  if (value === undefined) {
    return Object.freeze({ clock: SYSTEM_RUNTIME_CLOCK, monotonicClock: SYSTEM_MONOTONIC_CLOCK });
  }
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new RuntimeValidationError("Runtime open options are invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => key !== "clock" && key !== "monotonicClock")) {
    throw new RuntimeValidationError("Runtime open options are invalid");
  }
  const functions: Array<readonly ["clock" | "monotonicClock", () => number | string]> = [
    ["clock", SYSTEM_RUNTIME_CLOCK],
    ["monotonicClock", SYSTEM_MONOTONIC_CLOCK],
  ];
  const parsed: Record<"clock" | "monotonicClock", () => number | string> = {
    clock: SYSTEM_RUNTIME_CLOCK,
    monotonicClock: SYSTEM_MONOTONIC_CLOCK,
  };
  for (const [key, fallback] of functions) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      parsed[key] = fallback;
      continue;
    }
    if (
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      typeof descriptor.value !== "function" ||
      utilTypes.isProxy(descriptor.value)
    ) {
      throw new RuntimeValidationError(`Runtime open ${key} is invalid`);
    }
    parsed[key] = descriptor.value as () => number | string;
  }
  return Object.freeze({
    clock: parsed.clock as () => string,
    monotonicClock: parsed.monotonicClock as () => number,
  });
}

function readRuntimeClock(clock: () => string): string {
  let value: unknown;
  try {
    value = clock();
  } catch {
    throw new RuntimeValidationError("Runtime clock failed");
  }
  return parseRuntimeInput(RuntimeCanonicalTimestampSchema, value, "Runtime clock");
}

function readMonotonicClock(clock: () => number): number {
  let value: unknown;
  try {
    value = clock();
  } catch {
    throw new RuntimeValidationError("Runtime monotonic clock failed");
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new RuntimeValidationError("Runtime monotonic clock is invalid");
  }
  return value;
}

function authorizationExpiry(requestedAt: string): string {
  const expiresAt = new Date(Date.parse(requestedAt) + RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS);
  if (!Number.isFinite(expiresAt.getTime())) {
    throw new RuntimeValidationError("Runtime clock is out of range");
  }
  return expiresAt.toISOString();
}

function authorizationMonotonicExpiry(requestedAt: number): number {
  const expiresAt = requestedAt + RUNTIME_BOUNDARY_AUTHORIZATION_TTL_MS;
  if (!Number.isFinite(expiresAt)) {
    throw new RuntimeValidationError("Runtime monotonic clock is out of range");
  }
  return expiresAt;
}

function parsedEventPayload<T>(
  event: StoredEvent,
  parser: { parse(value: unknown): T },
  label: string,
): T {
  try {
    return parser.parse(event.payload);
  } catch {
    throw new RuntimeIntegrityError(`${label} at sequence ${event.sequence} is invalid`);
  }
}

function assertEventIdentity(event: StoredEvent, expectedKey: string): void {
  if (event.idempotencyKey !== expectedKey) {
    throw new RuntimeIntegrityError(
      `Runtime event at sequence ${event.sequence} has the wrong idempotency binding`,
    );
  }
}

function isModeTransitionAllowed(from: RuntimeMode, to: RuntimeMode): boolean {
  return (
    (from === "STOPPED" && to === "RESEARCH") ||
    (from === "RESEARCH" && to === "PROPOSE_ONLY") ||
    (from === "PROPOSE_ONLY" && to === "RESEARCH")
  );
}

function isPermanentlyDeniedBoundary(boundary: RuntimeBoundary): boolean {
  return (PERMANENTLY_DENIED_RUNTIME_BOUNDARIES as readonly RuntimeBoundary[]).includes(boundary);
}

function modeAllowsBoundary(mode: RuntimeMode, boundary: RuntimeBoundary): boolean {
  if (boundary === "research_collection") return mode !== "STOPPED";
  if (boundary === "proposal_persist") return mode === "PROPOSE_ONLY";
  return false;
}

function boundaryReason(
  requested: RequestedBoundary,
  state: RuntimeState,
  checkedAt: string,
): RuntimeBoundaryDecisionReason {
  if (isPermanentlyDeniedBoundary(requested.boundary)) return "PERMANENTLY_FORBIDDEN";
  if (requested.requestedProcessInstanceId !== state.processInstanceId) {
    return "PROCESS_SUPERSEDED";
  }
  if (requested.requestedMode !== state.mode || requested.requestedRevision !== state.revision) {
    return "STALE_REVISION";
  }
  if (Date.parse(checkedAt) >= Date.parse(requested.expiresAt)) return "EXPIRED";
  if (!modeAllowsBoundary(state.mode, requested.boundary)) return "MODE_NOT_ALLOWED";
  return "ALLOWED";
}

function boundaryCompletionReason(
  requested: RequestedBoundary,
  state: RuntimeState,
): RuntimeBoundaryDecisionReason {
  if (requested.boundary !== "research_collection") return "PERMANENTLY_FORBIDDEN";
  if (requested.requestedProcessInstanceId !== state.processInstanceId) {
    return "PROCESS_SUPERSEDED";
  }
  if (requested.requestedMode !== state.mode || requested.requestedRevision !== state.revision) {
    return "STALE_REVISION";
  }
  if (!modeAllowsBoundary(state.mode, requested.boundary)) return "MODE_NOT_ALLOWED";
  return "ALLOWED";
}

function stateFromModeEvent(
  event: StoredEvent,
  payload: RuntimeStopEventPayload | RuntimeTransitionEventPayload,
): RuntimeState {
  return Object.freeze({
    mode: payload.to,
    modeChangedAt: event.occurredAt,
    modeEventHash: event.eventHash,
    modeEventSequence: event.sequence,
    processInstanceId: payload.processInstanceId,
    revision: payload.revision,
  });
}

function stopAuditEvent(
  event: StoredEvent,
  payload: RuntimeStopEventPayload,
): Extract<RuntimeAuditEvent, { readonly type: typeof RUNTIME_STOP_EVENT_TYPE }> {
  return Object.freeze({
    aggregateId: RUNTIME_AGGREGATE_ID,
    eventHash: event.eventHash,
    eventId: event.eventId,
    idempotencyKey: `runtime-stop-v1:${payload.requestId}`,
    occurredAt: event.occurredAt,
    payload: Object.freeze(payload),
    previousHash: event.previousHash,
    sequence: event.sequence,
    type: RUNTIME_STOP_EVENT_TYPE,
  });
}

function transitionAuditEvent(
  event: StoredEvent,
  payload: RuntimeTransitionEventPayload,
): Extract<RuntimeAuditEvent, { readonly type: typeof RUNTIME_TRANSITION_EVENT_TYPE }> {
  return Object.freeze({
    aggregateId: RUNTIME_AGGREGATE_ID,
    eventHash: event.eventHash,
    eventId: event.eventId,
    idempotencyKey: `runtime-transition-v1:${payload.requestId}`,
    occurredAt: event.occurredAt,
    payload: Object.freeze(payload),
    previousHash: event.previousHash,
    sequence: event.sequence,
    type: RUNTIME_TRANSITION_EVENT_TYPE,
  });
}

function boundaryAuditEvent(
  event: StoredEvent,
  payload: RuntimeBoundaryEventPayload,
): Extract<RuntimeAuditEvent, { readonly type: typeof RUNTIME_BOUNDARY_EVENT_TYPE }> {
  return Object.freeze({
    aggregateId: RUNTIME_AGGREGATE_ID,
    eventHash: event.eventHash,
    eventId: event.eventId,
    idempotencyKey: `runtime-boundary-v1:${payload.authorizationId}`,
    occurredAt: event.occurredAt,
    payload: Object.freeze(payload),
    previousHash: event.previousHash,
    sequence: event.sequence,
    type: RUNTIME_BOUNDARY_EVENT_TYPE,
  });
}

function replayRuntimeStore(store: SqliteEventStore): ReplayResult {
  const storedEvents = store.list({ order: "asc" });
  const events: RuntimeAuditEvent[] = [];
  let state: RuntimeState | null = null;
  let lastAuditAt: string | null = null;
  const requestIds = new Set<string>();
  const authorizationIds = new Set<string>();

  for (const event of storedEvents) {
    let auditEvent: RuntimeAuditEvent;
    if (event.aggregateId !== RUNTIME_AGGREGATE_ID) {
      throw new RuntimeIntegrityError(
        `The isolated runtime store contains a foreign aggregate at sequence ${event.sequence}`,
      );
    }
    if (!RuntimeUuidSchema.safeParse(event.eventId).success) {
      throw new RuntimeIntegrityError(
        `Runtime event at sequence ${event.sequence} has an invalid event ID`,
      );
    }
    if (lastAuditAt !== null && Date.parse(event.occurredAt) < Date.parse(lastAuditAt)) {
      throw new RuntimeIntegrityError(`Runtime audit time regressed at sequence ${event.sequence}`);
    }

    if (event.type === RUNTIME_STOP_EVENT_TYPE) {
      const payload = parsedEventPayload(
        event,
        RuntimeStopEventPayloadSchema,
        "Runtime STOP event",
      );
      assertEventIdentity(event, `runtime-stop-v1:${payload.requestId}`);
      if (requestIds.has(payload.requestId)) {
        throw new RuntimeIntegrityError(
          `Runtime request ID was reused at sequence ${event.sequence}`,
        );
      }
      requestIds.add(payload.requestId);

      if (state === null) {
        if (
          payload.cause !== "startup" ||
          payload.from !== null ||
          payload.previousRevision !== 0 ||
          payload.revision !== 1 ||
          payload.requestId !== payload.processInstanceId
        ) {
          throw new RuntimeIntegrityError("The runtime audit does not begin with a valid STOP");
        }
      } else {
        if (
          payload.from !== state.mode ||
          payload.previousRevision !== state.revision ||
          payload.revision !== state.revision + 1
        ) {
          throw new RuntimeIntegrityError(
            `Runtime STOP revision is inconsistent at sequence ${event.sequence}`,
          );
        }
        if (
          (payload.cause === "operator" && payload.processInstanceId !== state.processInstanceId) ||
          (payload.cause === "startup" && payload.requestId !== payload.processInstanceId)
        ) {
          throw new RuntimeIntegrityError(
            `Runtime STOP process binding is invalid at sequence ${event.sequence}`,
          );
        }
      }
      state = stateFromModeEvent(event, payload);
      auditEvent = stopAuditEvent(event, payload);
    } else if (event.type === RUNTIME_TRANSITION_EVENT_TYPE) {
      const payload = parsedEventPayload(
        event,
        RuntimeTransitionEventPayloadSchema,
        "Runtime transition event",
      );
      assertEventIdentity(event, `runtime-transition-v1:${payload.requestId}`);
      if (requestIds.has(payload.requestId)) {
        throw new RuntimeIntegrityError(
          `Runtime request ID was reused at sequence ${event.sequence}`,
        );
      }
      requestIds.add(payload.requestId);
      if (
        state === null ||
        payload.processInstanceId !== state.processInstanceId ||
        payload.from !== state.mode ||
        payload.expectedMode !== state.mode ||
        payload.previousRevision !== state.revision ||
        payload.expectedRevision !== state.revision ||
        payload.revision !== state.revision + 1 ||
        !isModeTransitionAllowed(state.mode, payload.to)
      ) {
        throw new RuntimeIntegrityError(
          `Runtime transition is inconsistent at sequence ${event.sequence}`,
        );
      }
      state = stateFromModeEvent(event, payload);
      auditEvent = transitionAuditEvent(event, payload);
    } else if (event.type === RUNTIME_BOUNDARY_EVENT_TYPE) {
      const payload = parsedEventPayload(
        event,
        RuntimeBoundaryEventPayloadSchema,
        "Runtime boundary event",
      );
      assertEventIdentity(event, `runtime-boundary-v1:${payload.authorizationId}`);
      if (authorizationIds.has(payload.authorizationId)) {
        throw new RuntimeIntegrityError(
          `Runtime authorization ID was reused at sequence ${event.sequence}`,
        );
      }
      authorizationIds.add(payload.authorizationId);
      if (
        state === null ||
        payload.checkedMode !== state.mode ||
        payload.checkedRevision !== state.revision ||
        payload.checkedProcessInstanceId !== state.processInstanceId ||
        payload.expiresAt !== authorizationExpiry(payload.requestedAt) ||
        Date.parse(payload.requestedAt) > Date.parse(event.occurredAt)
      ) {
        throw new RuntimeIntegrityError(
          `Runtime boundary state is inconsistent at sequence ${event.sequence}`,
        );
      }
      const expectedReason = boundaryReason(
        {
          actionId: payload.actionId,
          authorizationId: payload.authorizationId,
          boundary: payload.boundary,
          expiresAt: payload.expiresAt,
          requestedAt: payload.requestedAt,
          requestedMode: payload.requestedMode,
          requestedProcessInstanceId: payload.requestedProcessInstanceId,
          requestedRevision: payload.requestedRevision,
        },
        state,
        event.occurredAt,
      );
      if (
        payload.reason !== expectedReason ||
        (payload.decision === "allowed") !== (expectedReason === "ALLOWED")
      ) {
        throw new RuntimeIntegrityError(
          `Runtime boundary decision is inconsistent at sequence ${event.sequence}`,
        );
      }
      auditEvent = boundaryAuditEvent(event, payload);
    } else {
      throw new RuntimeIntegrityError(
        `The runtime store contains an unknown event type at sequence ${event.sequence}`,
      );
    }
    events.push(auditEvent);
    lastAuditAt = event.occurredAt;
  }

  return Object.freeze({ events: Object.freeze(events), lastAuditAt, requestIds, state });
}

function assertUnusedRequestId(replay: ReplayResult, requestId: string): void {
  if (replay.requestIds.has(requestId)) {
    throw new RuntimeConflictError("REQUEST_CONFLICT", "Runtime request ID was reused");
  }
}

function capabilitiesFor(mode: RuntimeMode): RuntimeSnapshotV1["capabilities"] {
  return Object.freeze({
    executionAdapter: false,
    externalPublish: false,
    paidRead: false,
    policyApproval: false,
    proposalPersistence: mode === "PROPOSE_ONLY",
    researchCollection: mode !== "STOPPED",
    transactionBroadcast: false,
    walletSign: false,
  });
}

function snapshotFromState(
  state: RuntimeState,
  auditHead: Readonly<{ hash: string; sequence: number }>,
): Readonly<RuntimeSnapshotV1> {
  return Object.freeze({
    schemaVersion: 1 as const,
    auditHead: Object.freeze({ ...auditHead }),
    capabilities: capabilitiesFor(state.mode),
    mode: state.mode,
    modeChangedAt: state.modeChangedAt,
    processInstanceId: state.processInstanceId,
    revision: state.revision,
  });
}

function currentSnapshot(replay: ReplayResult): Readonly<RuntimeSnapshotV1> {
  const state = replay.state;
  const head = replay.events.at(-1);
  if (state === null || head === undefined) {
    throw new RuntimeIntegrityError("The runtime store has no startup STOP event");
  }
  return snapshotFromState(state, { hash: head.eventHash, sequence: head.sequence });
}

function snapshotFromModeEvent(
  event: StoredEvent,
  payload: RuntimeStopEventPayload | RuntimeTransitionEventPayload,
): Readonly<RuntimeSnapshotV1> {
  return snapshotFromState(stateFromModeEvent(event, payload), {
    hash: event.eventHash,
    sequence: event.sequence,
  });
}

function assertNonRegressingTime(value: string, replay: ReplayResult): void {
  if (replay.lastAuditAt !== null && Date.parse(value) < Date.parse(replay.lastAuditAt)) {
    throw new RuntimeConflictError("STALE_STATE", "Runtime audit time cannot move backward");
  }
}

function nonRegressingStopTime(value: string, replay: ReplayResult): string {
  if (replay.lastAuditAt === null) return value;
  return Date.parse(value) < Date.parse(replay.lastAuditAt) ? replay.lastAuditAt : value;
}

function nonRegressingBoundaryTime(value: string, replay: ReplayResult, minimum?: string): string {
  let effective = nonRegressingStopTime(value, replay);
  if (minimum !== undefined && Date.parse(effective) < Date.parse(minimum)) effective = minimum;
  return effective;
}

function boundaryReceipt(
  event: StoredEvent,
  payload: RuntimeBoundaryEventPayload,
): Readonly<RuntimeBoundaryReceipt> {
  return Object.freeze({
    schemaVersion: 1 as const,
    actionId: payload.actionId,
    authorizationId: payload.authorizationId,
    boundary: payload.boundary,
    checkedAt: event.occurredAt,
    decision: payload.decision,
    eventHash: event.eventHash,
    eventSequence: event.sequence,
    mode: payload.checkedMode,
    modeRevision: payload.checkedRevision,
    processInstanceId: payload.checkedProcessInstanceId,
    reason: payload.reason,
  });
}

function appendBoundaryCheck(
  store: SqliteEventStore,
  replay: ReplayResult,
  requested: RequestedBoundary,
  checkedAt: string,
): Readonly<RuntimeBoundaryReceipt> {
  const state = replay.state;
  if (state === null) throw new RuntimeIntegrityError("Runtime state is unavailable");
  if (store.getByIdempotencyKey(`runtime-boundary-v1:${requested.authorizationId}`) !== undefined) {
    throw new RuntimeConflictError(
      "AUTHORIZATION_ALREADY_USED",
      "Runtime authorization ID was already checked",
    );
  }
  assertNonRegressingTime(checkedAt, replay);
  if (Date.parse(checkedAt) < Date.parse(requested.requestedAt)) {
    throw new RuntimeConflictError(
      "STALE_STATE",
      "Runtime authorization cannot be consumed before it was requested",
    );
  }
  const reason = boundaryReason(requested, state, checkedAt);
  const payload: RuntimeBoundaryEventPayload = {
    schemaVersion: 1,
    actionId: requested.actionId,
    authorizationId: requested.authorizationId,
    boundary: requested.boundary,
    checkedMode: state.mode,
    checkedProcessInstanceId: state.processInstanceId,
    checkedRevision: state.revision,
    decision: reason === "ALLOWED" ? "allowed" : "denied",
    expiresAt: requested.expiresAt,
    reason,
    requestedAt: requested.requestedAt,
    requestedMode: requested.requestedMode,
    requestedProcessInstanceId: requested.requestedProcessInstanceId,
    requestedRevision: requested.requestedRevision,
  };
  const event = store.append({
    aggregateId: RUNTIME_AGGREGATE_ID,
    idempotencyKey: `runtime-boundary-v1:${requested.authorizationId}`,
    occurredAt: checkedAt,
    payload: toJson(payload),
    type: RUNTIME_BOUNDARY_EVENT_TYPE,
  });
  return boundaryReceipt(event, payload);
}

function assertDurableAllowedBoundary(store: SqliteEventStore, requested: IssuedBoundary): void {
  const event = store.getByIdempotencyKey(`runtime-boundary-v1:${requested.authorizationId}`);
  if (
    event === undefined ||
    event.aggregateId !== RUNTIME_AGGREGATE_ID ||
    event.type !== RUNTIME_BOUNDARY_EVENT_TYPE ||
    event.idempotencyKey !== `runtime-boundary-v1:${requested.authorizationId}`
  ) {
    throw new RuntimeIntegrityError(
      "Runtime completion has no exact durable boundary authorization",
    );
  }
  const payload = parsedEventPayload(
    event,
    RuntimeBoundaryEventPayloadSchema,
    "Runtime completion boundary event",
  );
  if (
    payload.actionId !== requested.actionId ||
    payload.authorizationId !== requested.authorizationId ||
    payload.boundary !== "research_collection" ||
    payload.decision !== "allowed" ||
    payload.reason !== "ALLOWED" ||
    payload.expiresAt !== requested.expiresAt ||
    payload.requestedAt !== requested.requestedAt ||
    payload.requestedMode !== requested.requestedMode ||
    payload.requestedProcessInstanceId !== requested.requestedProcessInstanceId ||
    payload.requestedRevision !== requested.requestedRevision ||
    payload.checkedMode !== requested.requestedMode ||
    payload.checkedProcessInstanceId !== requested.requestedProcessInstanceId ||
    payload.checkedRevision !== requested.requestedRevision
  ) {
    throw new RuntimeIntegrityError(
      "Runtime completion boundary authorization does not match its protected dispatch",
    );
  }
}

function boundaryCompletionFacts(
  requested: IssuedBoundary,
  state: RuntimeState,
  checkedAt: string,
): Readonly<RuntimeBoundaryCompletionFacts> {
  const reason = boundaryCompletionReason(requested, state);
  return Object.freeze({
    schemaVersion: 1 as const,
    actionId: requested.actionId,
    authorizationId: requested.authorizationId,
    boundary: "research_collection" as const,
    checkedAt,
    decision: reason === "ALLOWED" ? ("allowed" as const) : ("denied" as const),
    mode: state.mode,
    modeRevision: state.revision,
    processInstanceId: state.processInstanceId,
    reason,
  });
}

export class SqliteRuntimeController {
  readonly path: string;
  readonly processInstanceId: string;
  readonly #clock: () => string;
  readonly #monotonicClock: () => number;
  readonly #store: SqliteEventStore;

  static open(inputValue: OpenRuntimeInput, options?: RuntimeOpenOptions): SqliteRuntimeController;
  static open(inputValue: unknown, optionsValue?: unknown): SqliteRuntimeController {
    const input = parseRuntimeInput(OpenRuntimeInputSchema, inputValue, "Runtime open input");
    const clocks = parseRuntimeOpenOptions(optionsValue);
    const store = new SqliteEventStore(input.path);
    try {
      store.withExclusiveTransaction(() => {
        const replay = replayRuntimeStore(store);
        if (store.getByIdempotencyKey(`runtime-stop-v1:${input.processInstanceId}`) !== undefined) {
          throw new RuntimeConflictError(
            "REQUEST_CONFLICT",
            "Runtime processInstanceId must be unique for every open",
          );
        }
        assertUnusedRequestId(replay, input.processInstanceId);
        const stoppedAt = nonRegressingStopTime(input.openedAt, replay);
        const previousRevision = replay.state?.revision ?? 0;
        const payload: RuntimeStopEventPayload = {
          schemaVersion: 1,
          cause: "startup",
          from: replay.state?.mode ?? null,
          previousRevision,
          processInstanceId: input.processInstanceId,
          requestId: input.processInstanceId,
          revision: previousRevision + 1,
          to: "STOPPED",
        };
        store.append({
          aggregateId: RUNTIME_AGGREGATE_ID,
          idempotencyKey: `runtime-stop-v1:${input.processInstanceId}`,
          occurredAt: stoppedAt,
          payload: toJson(payload),
          type: RUNTIME_STOP_EVENT_TYPE,
        });
      });
      const controller = new SqliteRuntimeController(
        store,
        input.processInstanceId,
        clocks.clock,
        clocks.monotonicClock,
      );
      AUTHENTIC_CONTROLLERS.add(controller);
      Object.freeze(controller);
      return controller;
    } catch (error) {
      store.close();
      throw error;
    }
  }

  private constructor(
    store: SqliteEventStore,
    processInstanceId: string,
    clock: () => string,
    monotonicClock: () => number,
  ) {
    this.#clock = clock;
    this.#monotonicClock = monotonicClock;
    this.#store = store;
    this.path = store.path;
    this.processInstanceId = processInstanceId;
  }

  getSnapshot(): Readonly<RuntimeSnapshotV1> {
    this.#assertAuthentic();
    return this.#store.withExclusiveTransaction(() =>
      currentSnapshot(replayRuntimeStore(this.#store)),
    );
  }

  transition(inputValue: RuntimeTransitionInput): Readonly<RuntimeSnapshotV1>;
  transition(inputValue: unknown): Readonly<RuntimeSnapshotV1> {
    this.#assertAuthentic();
    const input = parseRuntimeInput(
      RuntimeTransitionInputSchema,
      inputValue,
      "Runtime transition input",
    );
    return this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      const existing = this.#store.getByIdempotencyKey(`runtime-transition-v1:${input.requestId}`);
      if (existing !== undefined) {
        if (existing.type !== RUNTIME_TRANSITION_EVENT_TYPE) {
          throw new RuntimeConflictError("REQUEST_CONFLICT", "Runtime request ID was reused");
        }
        const payload = parsedEventPayload(
          existing,
          RuntimeTransitionEventPayloadSchema,
          "Runtime transition event",
        );
        if (
          payload.processInstanceId !== this.processInstanceId ||
          payload.expectedMode !== input.expectedMode ||
          payload.expectedRevision !== input.expectedRevision ||
          payload.to !== input.targetMode
        ) {
          throw new RuntimeConflictError(
            "REQUEST_CONFLICT",
            "Runtime transition request ID has different content",
          );
        }
        if (
          replay.state?.processInstanceId !== payload.processInstanceId ||
          replay.state.mode !== payload.to ||
          replay.state.revision !== payload.revision
        ) {
          throw new RuntimeConflictError(
            "REQUEST_CONFLICT",
            "Runtime transition retry no longer names the current mode revision",
          );
        }
        return currentSnapshot(replay);
      }
      assertUnusedRequestId(replay, input.requestId);

      const state = replay.state;
      if (state === null) throw new RuntimeIntegrityError("Runtime state is unavailable");
      if (state.processInstanceId !== this.processInstanceId) {
        throw new RuntimeConflictError(
          "PROCESS_SUPERSEDED",
          "A newer runtime process superseded this controller",
        );
      }
      assertNonRegressingTime(input.occurredAt, replay);
      if (state.mode !== input.expectedMode || state.revision !== input.expectedRevision) {
        throw new RuntimeConflictError(
          "STALE_STATE",
          "Runtime transition expected mode or revision is stale",
        );
      }
      if (!isModeTransitionAllowed(state.mode, input.targetMode)) {
        throw new RuntimeConflictError(
          "INVALID_TRANSITION",
          `Runtime cannot transition from ${state.mode} to ${input.targetMode}`,
        );
      }
      const payload: RuntimeTransitionEventPayload = {
        schemaVersion: 1,
        expectedMode: input.expectedMode,
        expectedRevision: input.expectedRevision,
        from: state.mode,
        previousRevision: state.revision,
        processInstanceId: state.processInstanceId,
        requestId: input.requestId,
        revision: state.revision + 1,
        to: input.targetMode,
      };
      const event = this.#store.append({
        aggregateId: RUNTIME_AGGREGATE_ID,
        idempotencyKey: `runtime-transition-v1:${input.requestId}`,
        occurredAt: input.occurredAt,
        payload: toJson(payload),
        type: RUNTIME_TRANSITION_EVENT_TYPE,
      });
      return snapshotFromModeEvent(event, payload);
    });
  }

  stop(inputValue: RuntimeStopInput): Readonly<RuntimeSnapshotV1>;
  stop(inputValue: unknown): Readonly<RuntimeSnapshotV1> {
    this.#assertAuthentic();
    const input = parseRuntimeInput(RuntimeStopInputSchema, inputValue, "Runtime STOP input");
    return this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      const existing = this.#store.getByIdempotencyKey(`runtime-stop-v1:${input.requestId}`);
      if (existing !== undefined) {
        if (existing.type !== RUNTIME_STOP_EVENT_TYPE) {
          throw new RuntimeConflictError("REQUEST_CONFLICT", "Runtime request ID was reused");
        }
        const payload = parsedEventPayload(
          existing,
          RuntimeStopEventPayloadSchema,
          "Runtime STOP event",
        );
        if (
          payload.cause !== "operator" ||
          replay.state?.mode !== "STOPPED" ||
          replay.state.processInstanceId !== payload.processInstanceId ||
          replay.state.revision !== payload.revision
        ) {
          throw new RuntimeConflictError(
            "REQUEST_CONFLICT",
            "Runtime STOP request ID has different or no-longer-current content",
          );
        }
        return currentSnapshot(replay);
      }
      assertUnusedRequestId(replay, input.requestId);

      const state = replay.state;
      if (state === null) throw new RuntimeIntegrityError("Runtime state is unavailable");
      const stoppedAt = nonRegressingStopTime(input.occurredAt, replay);
      const payload: RuntimeStopEventPayload = {
        schemaVersion: 1,
        cause: "operator",
        from: state.mode,
        previousRevision: state.revision,
        processInstanceId: state.processInstanceId,
        requestId: input.requestId,
        revision: state.revision + 1,
        to: "STOPPED",
      };
      const event = this.#store.append({
        aggregateId: RUNTIME_AGGREGATE_ID,
        idempotencyKey: `runtime-stop-v1:${input.requestId}`,
        occurredAt: stoppedAt,
        payload: toJson(payload),
        type: RUNTIME_STOP_EVENT_TYPE,
      });
      return snapshotFromModeEvent(event, payload);
    });
  }

  requestBoundaryAuthorization<TBoundary extends RuntimeBoundary>(
    inputValue: RuntimeBoundaryAuthorizationInput & Readonly<{ boundary: TBoundary }>,
  ): RuntimeBoundaryAuthorization<TBoundary>;
  requestBoundaryAuthorization(inputValue: unknown): RuntimeBoundaryAuthorization {
    this.#assertAuthentic();
    const input = parseRuntimeInput(
      RuntimeBoundaryAuthorizationInputSchema,
      inputValue,
      "Runtime boundary authorization input",
    );
    const result = this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      const state = replay.state;
      if (state === null) throw new RuntimeIntegrityError("Runtime state is unavailable");
      if (
        this.#store.getByIdempotencyKey(`runtime-boundary-v1:${input.authorizationId}`) !==
        undefined
      ) {
        throw new RuntimeConflictError(
          "AUTHORIZATION_ALREADY_USED",
          "Runtime authorization ID was already checked",
        );
      }
      // Sample trusted time only after the write lock is held. A competing
      // writer can otherwise keep this call waiting past the fixed deadline
      // while a pre-lock clock reading remains artificially fresh.
      const clockAt = readRuntimeClock(this.#clock);
      const monotonicAt = readMonotonicClock(this.#monotonicClock);
      const requestedAt = nonRegressingBoundaryTime(clockAt, replay);
      const requested: IssuedBoundary = {
        actionId: input.actionId,
        authorizationId: input.authorizationId,
        boundary: input.boundary,
        expiresAt: authorizationExpiry(requestedAt),
        monotonicIssuedAt: monotonicAt,
        monotonicExpiresAt: authorizationMonotonicExpiry(monotonicAt),
        requestedAt,
        requestedMode: state.mode,
        requestedProcessInstanceId: this.processInstanceId,
        requestedRevision: state.revision,
      };
      const reason = boundaryReason(requested, state, requestedAt);
      if (reason === "ALLOWED") return { requested, receipt: null } as const;
      const receipt = appendBoundaryCheck(this.#store, replay, requested, requestedAt);
      return { requested, receipt } as const;
    });
    if (result.receipt !== null) throw new RuntimeBoundaryDeniedError(result.receipt);

    const requested = result.requested;
    return createRuntimeBoundaryAuthorization({
      actionId: requested.actionId,
      authorizationId: requested.authorizationId,
      boundary: requested.boundary,
      expiresAt: requested.expiresAt,
      processInstanceId: requested.requestedProcessInstanceId,
      requestedAt: requested.requestedAt,
      requestedMode: requested.requestedMode,
      requestedRevision: requested.requestedRevision,
      consume: () => this.#consumeBoundaryAuthorization(requested),
      consumeAndDispatch: (dispatch) =>
        this.#consumeBoundaryAuthorizationAndDispatch(requested, dispatch),
      guardCompletion: (completion) => this.#guardBoundaryCompletion(requested, completion),
    });
  }

  listAudit(): readonly RuntimeAuditEvent[] {
    this.#assertAuthentic();
    return this.#store.withExclusiveTransaction(() => replayRuntimeStore(this.#store).events);
  }

  close(): void {
    this.#assertAuthentic();
    this.#store.close();
  }

  [Symbol.dispose](): void {
    this.close();
  }

  #consumeBoundaryAuthorization(requested: IssuedBoundary): Readonly<RuntimeBoundaryReceipt> {
    this.#assertAuthentic();
    const receipt = this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      // Re-sample behind the write lock so lock contention counts against the
      // fixed authorization lifetime.
      const clockAt = readRuntimeClock(this.#clock);
      const monotonicAt = readMonotonicClock(this.#monotonicClock);
      let checkedAt = nonRegressingBoundaryTime(clockAt, replay, requested.requestedAt);
      if (
        (monotonicAt < requested.monotonicIssuedAt ||
          monotonicAt >= requested.monotonicExpiresAt) &&
        Date.parse(checkedAt) < Date.parse(requested.expiresAt)
      ) {
        checkedAt = requested.expiresAt;
      }
      return appendBoundaryCheck(this.#store, replay, requested, checkedAt);
    });
    if (receipt.decision === "denied") throw new RuntimeBoundaryDeniedError(receipt);
    return receipt;
  }

  #consumeBoundaryAuthorizationAndDispatch(
    requested: IssuedBoundary,
    dispatch: RuntimeBoundaryDispatch,
  ): Readonly<RuntimeBoundaryReceipt> {
    this.#assertAuthentic();
    const receipt = this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      // The current mode, process, revision, and lifetime are checked only
      // after the cross-process SQLite write lock is held. The synchronous
      // transport invocation then occurs before that lock can be released, so
      // a competing STOP writer cannot persist in the validation/dispatch gap.
      const clockAt = readRuntimeClock(this.#clock);
      const monotonicAt = readMonotonicClock(this.#monotonicClock);
      let checkedAt = nonRegressingBoundaryTime(clockAt, replay, requested.requestedAt);
      if (
        (monotonicAt < requested.monotonicIssuedAt ||
          monotonicAt >= requested.monotonicExpiresAt) &&
        Date.parse(checkedAt) < Date.parse(requested.expiresAt)
      ) {
        checkedAt = requested.expiresAt;
      }
      const checked = appendBoundaryCheck(this.#store, replay, requested, checkedAt);
      if (checked.decision === "allowed") dispatch(checked);
      return checked;
    });
    if (receipt.decision === "denied") throw new RuntimeBoundaryDeniedError(receipt);
    return receipt;
  }

  #guardBoundaryCompletion(
    requested: IssuedBoundary,
    completion: RuntimeBoundaryCompletion,
  ): Readonly<RuntimeBoundaryCompletionFacts> {
    this.#assertAuthentic();
    return this.#store.withExclusiveTransaction(() => {
      const replay = replayRuntimeStore(this.#store);
      // Completion authority is derived only from the exact durable ALLOWED
      // check that protected this authorization's dispatch. A structural
      // lookalike or a dispatch whose transaction did not commit cannot pass.
      assertDurableAllowedBoundary(this.#store, requested);
      const state = replay.state;
      if (state === null) throw new RuntimeIntegrityError("Runtime state is unavailable");
      const checkedAt = nonRegressingBoundaryTime(
        readRuntimeClock(this.#clock),
        replay,
        requested.requestedAt,
      );
      const facts = boundaryCompletionFacts(requested, state, checkedAt);
      // The content-free result checkpoint is invoked while this SQLite write
      // lock remains held. Therefore either completion wins and STOP follows,
      // or STOP wins and this callback is never invoked.
      if (facts.decision === "allowed") completion(facts);
      return facts;
    });
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_CONTROLLERS.has(this) ||
      Object.getPrototypeOf(this) !== SqliteRuntimeController.prototype
    ) {
      throw new RuntimeConflictError("PROCESS_SUPERSEDED", "Runtime controller is not authentic");
    }
  }
}

Object.freeze(SqliteRuntimeController.prototype);
Object.freeze(SqliteRuntimeController);

export function isSqliteRuntimeController(value: unknown): value is SqliteRuntimeController {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_CONTROLLERS.has(value) &&
    Object.getPrototypeOf(value) === SqliteRuntimeController.prototype
  );
}
