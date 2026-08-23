import { RuntimeConflictError, RuntimeValidationError } from "./errors.js";
import type {
  RuntimeBoundary,
  RuntimeBoundaryAuthorization,
  RuntimeBoundaryReceipt,
  RuntimeMode,
} from "./types.js";

const AUTHENTIC_AUTHORIZATIONS = new WeakSet<object>();
const CONSUMED_AUTHORIZATIONS = new WeakSet<object>();

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
}

export function createRuntimeBoundaryAuthorization<TBoundary extends RuntimeBoundary>(
  parts: RuntimeBoundaryAuthorizationParts<TBoundary>,
): RuntimeBoundaryAuthorization<TBoundary> {
  const authorization = Object.create(null) as RuntimeBoundaryAuthorization<TBoundary>;
  const consumeBoundary = parts.consume;
  const consume = (...arguments_: unknown[]): Readonly<RuntimeBoundaryReceipt> => {
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
    // An attempted consumption is terminal even if validation or durable
    // persistence fails. A caller must request a fresh authorization.
    CONSUMED_AUTHORIZATIONS.add(authorization);
    if (arguments_.length !== 0) {
      throw new RuntimeValidationError("Runtime boundary consumption accepts no arguments");
    }
    return consumeBoundary();
  };

  Object.defineProperties(authorization, {
    kind: { enumerable: true, value: "rsi.runtime-boundary.v1" },
    actionId: { enumerable: true, value: parts.actionId },
    authorizationId: { enumerable: true, value: parts.authorizationId },
    boundary: { enumerable: true, value: parts.boundary },
    expiresAt: { enumerable: true, value: parts.expiresAt },
    processInstanceId: { enumerable: true, value: parts.processInstanceId },
    requestedAt: { enumerable: true, value: parts.requestedAt },
    requestedMode: { enumerable: true, value: parts.requestedMode },
    requestedRevision: { enumerable: true, value: parts.requestedRevision },
    consume: { enumerable: true, value: consume },
  });
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
