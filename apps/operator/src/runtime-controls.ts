import { types as utilTypes } from "node:util";

import { isSqliteRuntimeController, type SqliteRuntimeController } from "@rsi/runtime";

import type {
  OperatorRuntimeProvider,
  RuntimeOperatorAction,
  RuntimeOperatorControlCommand,
} from "./runtime-types.js";

const RUNTIME_ACTIONS = Object.freeze([
  "runtime-enter-research",
  "runtime-enter-propose-only",
  "runtime-stop",
] as const satisfies readonly RuntimeOperatorAction[]);
const AUTHENTIC_RUNTIME_CONTROLS = new WeakSet<object>();

export interface RuntimeOperatorControlsOptions {
  readonly controller: SqliteRuntimeController;
  /** Provider-owned wall clock. Request bodies never supply transition time. */
  readonly now?: () => string;
}

export interface RuntimeOperatorControls extends OperatorRuntimeProvider {
  readonly supportedActions: typeof RUNTIME_ACTIONS;
}

export function createRuntimeOperatorControls(
  optionsValue: RuntimeOperatorControlsOptions,
): RuntimeOperatorControls {
  const options = exactOptions(optionsValue);
  const controller = options.controller;
  const now = options.now ?? (() => new Date().toISOString());

  const controls: RuntimeOperatorControls = Object.freeze({
    supportedActions: RUNTIME_ACTIONS,
    executeRuntimeControl(command: RuntimeOperatorControlCommand): unknown {
      assertAuthentic(controls);
      const occurredAt = now();
      switch (command.action) {
        case "runtime-stop":
          return controller.stop({ occurredAt, requestId: command.requestId });
        case "runtime-enter-research":
          return controller.transition({
            occurredAt,
            requestId: command.requestId,
            expectedMode: command.expectedMode,
            expectedRevision: command.expectedRevision,
            targetMode: "RESEARCH",
          });
        case "runtime-enter-propose-only":
          return controller.transition({
            occurredAt,
            requestId: command.requestId,
            expectedMode: command.expectedMode,
            expectedRevision: command.expectedRevision,
            targetMode: "PROPOSE_ONLY",
          });
      }
    },
    getRuntimeSnapshot(): unknown {
      assertAuthentic(controls);
      return controller.getSnapshot();
    },
  });
  AUTHENTIC_RUNTIME_CONTROLS.add(controls);
  return controls;
}

export function isRuntimeOperatorControls(value: unknown): value is RuntimeOperatorControls {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHENTIC_RUNTIME_CONTROLS.has(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function assertAuthentic(controls: RuntimeOperatorControls): void {
  if (!AUTHENTIC_RUNTIME_CONTROLS.has(controls)) {
    throw new TypeError("Runtime operator controls are unavailable");
  }
}

function exactOptions(
  value: RuntimeOperatorControlsOptions,
): Readonly<RuntimeOperatorControlsOptions> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Runtime control options are invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || (key !== "controller" && key !== "now")) ||
    !Object.hasOwn(value, "controller")
  ) {
    throw new TypeError("Runtime control options are invalid");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Runtime control options are invalid");
    }
  }
  if (!isSqliteRuntimeController(value.controller)) {
    throw new TypeError("A genuine runtime controller is required");
  }
  if (
    value.now !== undefined &&
    (typeof value.now !== "function" || utilTypes.isProxy(value.now))
  ) {
    throw new TypeError("Runtime control clock is invalid");
  }
  return Object.freeze({
    controller: value.controller,
    ...(value.now === undefined ? {} : { now: value.now }),
  });
}
