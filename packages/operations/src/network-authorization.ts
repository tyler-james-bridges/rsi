import { InvalidAttemptPermitError, OperationsValidationError } from "./errors.js";
import type { NetworkAttemptBinding } from "./types.js";

const authorizations = new WeakSet<object>();
const consumedAuthorizations = new WeakSet<object>();
const dispatchReceipts = new WeakSet<object>();

export interface NetworkAttemptDispatchReceipt {
  readonly kind: "rsi.network-attempt-dispatch.v1";
  readonly binding: NetworkAttemptBinding;
  readonly dispatchedAt: string;
}

export interface NetworkAttemptAuthorization {
  readonly kind: "rsi.network-attempt.v1";
  readonly binding: NetworkAttemptBinding;
  consume(): Readonly<NetworkAttemptDispatchReceipt>;
}

function frozenBinding(binding: NetworkAttemptBinding): NetworkAttemptBinding {
  const copy = Object.create(null) as NetworkAttemptBinding;
  Object.defineProperties(copy, {
    attemptId: { enumerable: true, value: binding.attemptId },
    authorizationExpiresAt: { enumerable: true, value: binding.authorizationExpiresAt },
    lane: { enumerable: true, value: binding.lane },
    operation: { enumerable: true, value: binding.operation },
    profile: { enumerable: true, value: binding.profile },
    reservedAtomic: { enumerable: true, value: binding.reservedAtomic },
    sessionId: { enumerable: true, value: binding.sessionId },
    sourcePlane: { enumerable: true, value: binding.sourcePlane },
  });
  return Object.freeze(copy);
}

export function createNetworkAttemptDispatchReceipt(
  binding: NetworkAttemptBinding,
  dispatchedAt: string,
): Readonly<NetworkAttemptDispatchReceipt> {
  const receipt = Object.create(null) as NetworkAttemptDispatchReceipt;
  Object.defineProperties(receipt, {
    kind: { enumerable: true, value: "rsi.network-attempt-dispatch.v1" },
    binding: { enumerable: true, value: frozenBinding(binding) },
    dispatchedAt: { enumerable: true, value: dispatchedAt },
  });
  dispatchReceipts.add(receipt);
  return Object.freeze(receipt);
}

export function isNetworkAttemptDispatchReceipt(
  value: unknown,
): value is NetworkAttemptDispatchReceipt {
  return (
    typeof value === "object" &&
    value !== null &&
    dispatchReceipts.has(value) &&
    Object.getPrototypeOf(value) === null &&
    Object.isFrozen(value) &&
    (value as Partial<NetworkAttemptDispatchReceipt>).kind === "rsi.network-attempt-dispatch.v1"
  );
}

export function isNetworkAttemptAuthorization(
  value: unknown,
): value is NetworkAttemptAuthorization {
  return (
    typeof value === "object" &&
    value !== null &&
    authorizations.has(value) &&
    Object.getPrototypeOf(value) === null &&
    Object.isFrozen(value) &&
    (value as Partial<NetworkAttemptAuthorization>).kind === "rsi.network-attempt.v1"
  );
}

export function createNetworkAttemptAuthorization(
  bindingValue: NetworkAttemptBinding,
  authorize: () => Readonly<NetworkAttemptDispatchReceipt>,
): NetworkAttemptAuthorization {
  const authorization = Object.create(null) as NetworkAttemptAuthorization;
  const binding = frozenBinding(bindingValue);
  const consume = (...arguments_: unknown[]): Readonly<NetworkAttemptDispatchReceipt> => {
    if (!authorizations.has(authorization) || consumedAuthorizations.has(authorization)) {
      throw new InvalidAttemptPermitError("Network attempt authorization was already consumed");
    }
    // Every attempted consumption is terminal, including malformed calls and
    // durable dispatch failures. Retrying requires a fresh authorization.
    consumedAuthorizations.add(authorization);
    if (arguments_.length !== 0) {
      throw new OperationsValidationError(
        "Network attempt authorization consumption accepts no arguments",
      );
    }
    const receipt = authorize();
    if (
      !isNetworkAttemptDispatchReceipt(receipt) ||
      receipt.binding.attemptId !== binding.attemptId ||
      receipt.binding.authorizationExpiresAt !== binding.authorizationExpiresAt ||
      receipt.binding.lane !== binding.lane ||
      receipt.binding.operation !== binding.operation ||
      receipt.binding.profile !== binding.profile ||
      receipt.binding.reservedAtomic !== binding.reservedAtomic ||
      receipt.binding.sessionId !== binding.sessionId ||
      receipt.binding.sourcePlane !== binding.sourcePlane
    ) {
      throw new InvalidAttemptPermitError("Network dispatch receipt binding is invalid");
    }
    return receipt;
  };

  Object.defineProperties(authorization, {
    kind: { enumerable: true, value: "rsi.network-attempt.v1" },
    binding: { enumerable: true, value: binding },
    consume: { enumerable: true, value: consume },
  });
  authorizations.add(authorization);
  return Object.freeze(authorization);
}
