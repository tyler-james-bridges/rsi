const authorizations = new WeakSet<object>();
const consumedAuthorizations = new WeakSet<object>();

export interface NetworkAttemptAuthorization {
  readonly kind: "rsi.network-attempt.v1";
  readonly binding: NetworkAttemptBinding;
  consume(dispatchedAt: string): void;
}

class NetworkAttemptAuthorizationImpl implements NetworkAttemptAuthorization {
  readonly kind = "rsi.network-attempt.v1" as const;
  readonly binding: NetworkAttemptBinding;
  private readonly authorize: (dispatchedAt: string) => void;

  constructor(binding: NetworkAttemptBinding, authorize: (dispatchedAt: string) => void) {
    this.binding = Object.freeze({ ...binding });
    this.authorize = authorize;
    authorizations.add(this);
    Object.freeze(this);
  }

  consume(dispatchedAt: string): void {
    if (consumedAuthorizations.has(this)) {
      throw new Error("Network attempt authorization was already consumed");
    }
    this.authorize(dispatchedAt);
    consumedAuthorizations.add(this);
  }
}

export function isNetworkAttemptAuthorization(
  value: unknown,
): value is NetworkAttemptAuthorization {
  return (
    typeof value === "object" &&
    value !== null &&
    authorizations.has(value) &&
    (value as Partial<NetworkAttemptAuthorization>).kind === "rsi.network-attempt.v1"
  );
}

export function createNetworkAttemptAuthorization(
  binding: NetworkAttemptBinding,
  authorize: (dispatchedAt: string) => void,
): NetworkAttemptAuthorization {
  return new NetworkAttemptAuthorizationImpl(binding, authorize);
}
import type { NetworkAttemptBinding } from "./types.js";
