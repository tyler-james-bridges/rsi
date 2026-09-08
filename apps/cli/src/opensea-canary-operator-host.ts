import { DarwinOpenSeaTrendingKeychain } from "@rsi/credential-host/opensea-trending";
import { createDarwinOpenSeaOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";

import {
  IncompleteCanaryOperatorStartupCleanupError,
  rethrowCanaryStartupFailureAfterProfileLockDecision,
} from "./canary-operator-startup-cleanup.js";
import { productionOpenSeaCanaryHostOptions } from "./production-canary-config.js";
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
  startOpenSeaCanaryOperatorWithHost,
  type OpenSeaCanaryOperatorPaths,
  type RunningOpenSeaCanaryOperator as InternalRunningOpenSeaCanaryOperator,
  type StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";

export type {
  OpenSeaCanaryOperatorPaths,
  StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";

export type RunningOpenSeaCanaryOperator =
  RunningProductionCanaryOperator<OpenSeaCanaryOperatorPaths>;

export async function startOpenSeaCanaryOperator(
  options: StartOpenSeaCanaryOperatorOptions,
): Promise<RunningOpenSeaCanaryOperator> {
  assertActiveProductionRuntime();
  const productionOptions = productionOpenSeaCanaryHostOptions();
  if (
    options.databasePath !== productionOptions.databasePath ||
    options.port !== productionOptions.port
  ) {
    throw new TypeError("OpenSea canary production options are fixed");
  }
  const profileLock = await acquireProductionCanaryProfileLock();
  let operator: InternalRunningOpenSeaCanaryOperator | undefined;
  try {
    operator = await startOpenSeaCanaryOperatorWithHost(
      productionOptions,
      new DarwinOpenSeaTrendingKeychain(),
      createDarwinOpenSeaOneShotClaimHost(),
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
          "RSI OpenSea canary startup and lock release both failed",
        );
      }
    }
    return rethrowCanaryStartupFailureAfterProfileLockDecision(
      error,
      profileLock,
      "RSI OpenSea canary startup and lock release both failed",
    );
  }
}
