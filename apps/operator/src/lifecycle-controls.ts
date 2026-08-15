import { types as utilTypes } from "node:util";

import {
  isSqliteSessionCoordinator,
  type SessionRecordV1,
  type SqliteSessionCoordinator,
} from "@rsi/session-lifecycle";

import type { OperatorControlCommand, OperatorControlProvider } from "./server.js";

const SUPERVISED_SESSION_MILLISECONDS = 120 * 60 * 1_000;
const LIFECYCLE_ACTIONS = Object.freeze([
  "plan",
  "start",
  "acknowledge",
  "abort",
  "close",
] as const);
const AUTHENTIC_LIFECYCLE_CONTROLS = new WeakSet<object>();

export interface SessionLifecycleOperatorControlsOptions {
  readonly coordinator: SqliteSessionCoordinator;
  /** Defaults to the current wall clock. Inject a supervised clock in production. */
  readonly now?: () => string;
}

export interface SessionLifecycleOperatorControls extends OperatorControlProvider {
  readonly supportedActions: typeof LIFECYCLE_ACTIONS;
}

export function createSessionLifecycleOperatorControls(
  optionsValue: SessionLifecycleOperatorControlsOptions,
): SessionLifecycleOperatorControls {
  const options = exactOptions(optionsValue);
  const coordinator = options.coordinator;
  const now = options.now ?? (() => new Date().toISOString());

  const controls: SessionLifecycleOperatorControls = Object.freeze({
    supportedActions: LIFECYCLE_ACTIONS,
    executeControl(command: OperatorControlCommand): Readonly<SessionRecordV1> {
      if (!AUTHENTIC_LIFECYCLE_CONTROLS.has(controls)) {
        throw new TypeError("Operator controls are unavailable");
      }
      switch (command.action) {
        case "plan": {
          const existing = coordinator.getSession(command.sessionId);
          if (existing !== undefined) return existing;
          const plannedAt = now();
          const plannedMilliseconds = canonicalMilliseconds(plannedAt);
          return coordinator.planSession({
            plannedAt,
            qualificationDate: qualificationDateInPhoenix(plannedMilliseconds),
            sessionId: command.sessionId,
            supervisedUntil: new Date(
              plannedMilliseconds + SUPERVISED_SESSION_MILLISECONDS,
            ).toISOString(),
          });
        }
        case "start": {
          const existing = requireSession(coordinator, command.sessionId);
          if (existing.startedAt !== null) return existing;
          return coordinator.startSession({
            observerOnlyAcknowledgement: command.observerOnlyAcknowledgement,
            sessionId: command.sessionId,
            startedAt: now(),
            typedSessionIdAcknowledgement: command.typedSessionIdAcknowledgement,
          });
        }
        case "acknowledge": {
          const existing = requireSession(coordinator, command.sessionId);
          const prior =
            command.checkpoint === "minute-45"
              ? existing.minute45AcknowledgedAt
              : existing.minute90AcknowledgedAt;
          if (prior !== null) return existing;
          return coordinator.recordSupervisionAcknowledgement({
            acknowledgedAt: now(),
            checkpoint: command.checkpoint,
            sessionId: command.sessionId,
          });
        }
        case "close": {
          const existing = requireSession(coordinator, command.sessionId);
          if (existing.stoppedAt !== null) return existing;
          return coordinator.stopSession({ sessionId: command.sessionId, stoppedAt: now() });
        }
        case "abort": {
          const existing = requireSession(coordinator, command.sessionId);
          if (existing.state === "invalid" && existing.invalidationReason === "operator-abort") {
            return existing;
          }
          return coordinator.invalidateSession({
            invalidatedAt: now(),
            reason: "operator-abort",
            sessionId: command.sessionId,
          });
        }
        case "label":
        case "prepare-candidate":
          throw new TypeError("Operator control is not configured");
      }
    },
  });
  AUTHENTIC_LIFECYCLE_CONTROLS.add(controls);
  return controls;
}

export function isSessionLifecycleOperatorControls(
  value: unknown,
): value is SessionLifecycleOperatorControls {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === Object.prototype &&
    AUTHENTIC_LIFECYCLE_CONTROLS.has(value)
  );
}

function exactOptions(
  value: SessionLifecycleOperatorControlsOptions,
): Readonly<SessionLifecycleOperatorControlsOptions> {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    utilTypes.isProxy(value)
  ) {
    throw new TypeError("Lifecycle control options are invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || (key !== "coordinator" && key !== "now")) ||
    !Object.hasOwn(value, "coordinator")
  ) {
    throw new TypeError("Lifecycle control options are invalid");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Lifecycle control options are invalid");
    }
  }
  if (!isSqliteSessionCoordinator(value.coordinator)) {
    throw new TypeError("A genuine session coordinator is required");
  }
  if (value.now !== undefined && typeof value.now !== "function") {
    throw new TypeError("Lifecycle clock is invalid");
  }
  if (value.now !== undefined && utilTypes.isProxy(value.now)) {
    throw new TypeError("Lifecycle clock is invalid");
  }
  return Object.freeze({
    coordinator: value.coordinator,
    ...(value.now === undefined ? {} : { now: value.now }),
  });
}

function requireSession(
  coordinator: SqliteSessionCoordinator,
  sessionId: string,
): Readonly<SessionRecordV1> {
  const record = coordinator.getSession(sessionId);
  if (record === undefined) throw new TypeError("Session is unavailable");
  return record;
}

function canonicalMilliseconds(value: string): number {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError("Lifecycle clock did not return a canonical timestamp");
  }
  return milliseconds;
}

function qualificationDateInPhoenix(milliseconds: number): string {
  const parts = new Intl.DateTimeFormat("en-US", {
    day: "2-digit",
    month: "2-digit",
    timeZone: "America/Phoenix",
    year: "numeric",
  }).formatToParts(new Date(milliseconds));
  const values = new Map(parts.map((part) => [part.type, part.value]));
  const year = values.get("year");
  const month = values.get("month");
  const day = values.get("day");
  if (year === undefined || month === undefined || day === undefined) {
    throw new TypeError("Qualification date is unavailable");
  }
  return `${year}-${month}-${day}`;
}
