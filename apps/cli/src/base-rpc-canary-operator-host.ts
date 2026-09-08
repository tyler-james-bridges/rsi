import { DarwinBaseRpcKeychain } from "@rsi/credential-host/base-rpc";
import { createDarwinBaseRpcOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";

import {
  IncompleteCanaryOperatorStartupCleanupError,
  rethrowCanaryStartupFailureAfterProfileLockDecision,
} from "./canary-operator-startup-cleanup.js";
import { productionBaseRpcCanaryHostOptions } from "./production-canary-config.js";
import {
  acquireProductionCanaryProfileLock,
  bindProfileServiceLock,
} from "./profile-service-lock.js";
import {
  createProductionCanaryOperatorFacade,
  type RunningProductionCanaryOperator,
} from "./production-canary-operator-facade.js";
import { assertActiveProductionRuntime } from "./production-runtime.js";
import {
  startBaseRpcCanaryOperatorWithHost,
  type BaseRpcCanaryOperatorPaths,
  type RunningBaseRpcCanaryOperator as InternalRunningBaseRpcCanaryOperator,
} from "./base-rpc-canary-operator-host-core.js";

export type { BaseRpcCanaryOperatorPaths } from "./base-rpc-canary-operator-host-core.js";

export type RunningBaseRpcCanaryOperator =
  RunningProductionCanaryOperator<BaseRpcCanaryOperatorPaths>;

/** Starts only the code-owned production topology; it accepts no path or port overrides. */
export async function startBaseRpcCanaryOperator(): Promise<RunningBaseRpcCanaryOperator> {
  assertActiveProductionRuntime();
  if (arguments.length !== 0) {
    throw new TypeError("Base RPC canary production options are fixed");
  }
  const profileLock = await acquireProductionCanaryProfileLock();
  let operator: InternalRunningBaseRpcCanaryOperator | undefined;
  try {
    operator = await startBaseRpcCanaryOperatorWithHost(
      productionBaseRpcCanaryHostOptions(),
      new DarwinBaseRpcKeychain(),
      createDarwinBaseRpcOneShotClaimHost(),
      profileLock,
    );
    return createProductionCanaryOperatorFacade(bindProfileServiceLock(operator, profileLock));
  } catch (error) {
    if (operator !== undefined) {
      try {
        await operator.close();
      } catch (cleanupError) {
        return rethrowCanaryStartupFailureAfterProfileLockDecision(
          new IncompleteCanaryOperatorStartupCleanupError(error, cleanupError),
          profileLock,
          "RSI Base RPC canary startup and lock release both failed",
        );
      }
    }
    return rethrowCanaryStartupFailureAfterProfileLockDecision(
      error,
      profileLock,
      "RSI Base RPC canary startup and lock release both failed",
    );
  }
}
