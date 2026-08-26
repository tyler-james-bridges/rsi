import { types as utilTypes } from "node:util";

import { RuntimeConflictError, RuntimeValidationError } from "./errors.js";
import type {
  RuntimeBoundary,
  RuntimeBoundaryAuthorization,
  RuntimeBoundaryCompletion,
  RuntimeBoundaryCompletionFacts,
  RuntimeBoundaryDispatch,
  RuntimeBoundaryReceipt,
  RuntimeMode,
} from "./types.js";

const AUTHENTIC_AUTHORIZATIONS = new WeakSet<object>();
const CONSUMED_AUTHORIZATIONS = new WeakSet<object>();
const DISPATCHED_AUTHORIZATIONS = new WeakSet<object>();
const COMPLETION_GUARDED_AUTHORIZATIONS = new WeakSet<object>();

interface RuntimeBoundaryAuthorizationParts<TBoundary extends RuntimeBoundary> {
  readonly actionId: string;
  readonly authorizationId: string;
  readonly boundary: TBoundary;
  readonly expiresAt: string;
  readonly processInstanceId: string;
  readonly requestedAt: string;
  readonly requestedMode: RuntimeMode;
  readonly requestedRevision: number;
  readonly consume: () => Readonly<RuntimeBoundaryReceipt>;
  readonly consumeAndDispatch: (
    dispatch: RuntimeBoundaryDispatch,
  ) => Readonly<RuntimeBoundaryReceipt>;
  readonly guardCompletion: (
    completion: RuntimeBoundaryCompletion,
  ) => Readonly<RuntimeBoundaryCompletionFacts>;
}

function isSynchronousCallback(value: unknown): value is (...arguments_: unknown[]) => unknown {
  return (
    typeof value === "function" &&
    !utilTypes.isProxy(value) &&
    !utilTypes.isAsyncFunction(value) &&
    !utilTypes.isGeneratorFunction(value) &&
    Object.prototype.toString.call(value) === "[object Function]"
  );
}

export function createRuntimeBoundaryAuthorization<TBoundary extends RuntimeBoundary>(
  parts: RuntimeBoundaryAuthorizationParts<TBoundary>,
): RuntimeBoundaryAuthorization<TBoundary> {
  const authorization = Object.create(null) as RuntimeBoundaryAuthorization<TBoundary>;
  const consumeBoundary = parts.consume;
  const consumeBoundaryAndDispatch = parts.consumeAndDispatch;
  const guardBoundaryCompletion = parts.guardCompletion;
  const claim = (): void => {
    if (!AUTHENTIC_AUTHORIZATIONS.has(authorization)) {
      throw new RuntimeConflictError(
        "AUTHORIZATION_ALREADY_USED",
        "Runtime boundary authorization is not authentic",
      );
    }
    if (CONSUMED_AUTHORIZATIONS.has(authorization)) {
      throw new RuntimeConflictError(
        "AUTHORIZATION_ALREADY_USED",
        "Runtime boundary authorization was already consumed",
      );
    }
    // An attempted consumption is terminal even if validation, durable
    // persistence, or the protected dispatch invocation fails.
    CONSUMED_AUTHORIZATIONS.add(authorization);
  };
  const consume = (...arguments_: unknown[]): Readonly<RuntimeBoundaryReceipt> => {
    claim();
    if (arguments_.length !== 0) {
      throw new RuntimeValidationError("Runtime boundary consumption accepts no arguments");
    }
    return consumeBoundary();
  };
  const consumeAndDispatch = (...arguments_: unknown[]): Readonly<RuntimeBoundaryReceipt> => {
    claim();
    const dispatch = arguments_[0];
    if (arguments_.length !== 1 || !isSynchronousCallback(dispatch)) {
      throw new RuntimeValidationError(
        "Runtime network boundary consumption requires one synchronous dispatch callback",
      );
    }
    let dispatchWasInvoked = false;
    try {
      return consumeBoundaryAndDispatch((receipt) => {
        dispatchWasInvoked = true;
        dispatch(receipt);
      });
    } finally {
      // Dispatch is an irreversible boundary even if the surrounding SQLite
      // COMMIT or the protected callback subsequently throws. Remember it so
      // completion can only attempt a durable revalidation, never redispatch.
      if (dispatchWasInvoked) DISPATCHED_AUTHORIZATIONS.add(authorization);
    }
  };
  const guardCompletion = (...arguments_: unknown[]): Readonly<RuntimeBoundaryCompletionFacts> => {
    if (!AUTHENTIC_AUTHORIZATIONS.has(authorization)) {
      throw new RuntimeConflictError(
        "AUTHORIZATION_ALREADY_USED",
        "Runtime boundary authorization is not authentic",
      );
    }
    if (COMPLETION_GUARDED_AUTHORIZATIONS.has(authorization)) {
      throw new RuntimeConflictError(
        "AUTHORIZATION_ALREADY_USED",
        "Runtime boundary completion was already guarded",
      );
    }
    // Like consumption, every attempted completion is terminal. Invalid or
    // premature callbacks cannot be retried with a more permissive shape.
    COMPLETION_GUARDED_AUTHORIZATIONS.add(authorization);
    if (!DISPATCHED_AUTHORIZATIONS.has(authorization)) {
      throw new RuntimeConflictError(
        "STALE_STATE",
        "Runtime boundary completion cannot precede protected dispatch",
      );
    }
    const completion = arguments_[0];
    if (arguments_.length !== 1 || !isSynchronousCallback(completion)) {
      throw new RuntimeValidationError(
        "Runtime network completion requires one synchronous completion callback",
      );
    }
    return guardBoundaryCompletion(completion as RuntimeBoundaryCompletion);
  };

  const properties: PropertyDescriptorMap = {
    kind: { enumerable: true, value: "rsi.runtime-boundary.v1" },
    actionId: { enumerable: true, value: parts.actionId },
    authorizationId: { enumerable: true, value: parts.authorizationId },
    boundary: { enumerable: true, value: parts.boundary },
    expiresAt: { enumerable: true, value: parts.expiresAt },
    processInstanceId: { enumerable: true, value: parts.processInstanceId },
    requestedAt: { enumerable: true, value: parts.requestedAt },
    requestedMode: { enumerable: true, value: parts.requestedMode },
    requestedRevision: { enumerable: true, value: parts.requestedRevision },
  };
  if (parts.boundary === "research_collection") {
    properties.consumeAndDispatch = { enumerable: true, value: consumeAndDispatch };
    properties.guardCompletion = { enumerable: true, value: guardCompletion };
  } else {
    properties.consume = { enumerable: true, value: consume };
  }
  Object.defineProperties(authorization, properties);
  AUTHENTIC_AUTHORIZATIONS.add(authorization);
  Object.freeze(authorization);
  return authorization;
}

export function isRuntimeBoundaryAuthorization(
  value: unknown,
): value is RuntimeBoundaryAuthorization {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHENTIC_AUTHORIZATIONS.has(value) &&
    Object.getPrototypeOf(value) === null &&
    Object.isFrozen(value) &&
    (value as Partial<RuntimeBoundaryAuthorization>).kind === "rsi.runtime-boundary.v1"
  );
}
