import { DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import { createDarwinXOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";

import {
  IncompleteCanaryOperatorStartupCleanupError,
  rethrowCanaryStartupFailureAfterProfileLockDecision,
} from "./canary-operator-startup-cleanup.js";
import { productionXCanaryHostOptions } from "./production-canary-config.js";
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
  startXCanaryOperatorWithHost,
  type RunningXCanaryOperator as InternalRunningXCanaryOperator,
  type StartXCanaryOperatorOptions,
  type XCanaryOperatorPaths,
} from "./x-canary-operator-host-core.js";

export type {
  StartXCanaryOperatorOptions,
  XCanaryOperatorPaths,
} from "./x-canary-operator-host-core.js";

export type RunningXCanaryOperator = RunningProductionCanaryOperator<XCanaryOperatorPaths>;

export async function startXCanaryOperator(
  options: StartXCanaryOperatorOptions,
): Promise<RunningXCanaryOperator> {
  assertActiveProductionRuntime();
  const productionOptions = productionXCanaryHostOptions();
  if (
    options.databasePath !== productionOptions.databasePath ||
    options.researchDatabasePath !== productionOptions.researchDatabasePath ||
    options.port !== productionOptions.port
  ) {
    throw new TypeError("X canary production options are fixed");
  }
  const profileLock = await acquireProductionCanaryProfileLock();
  let operator: InternalRunningXCanaryOperator | undefined;
  try {
    operator = await startXCanaryOperatorWithHost(
      productionOptions,
      new DarwinXReadCanaryKeychain(),
      createDarwinXOneShotClaimHost(),
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
          "RSI X canary startup and lock release both failed",
        );
      }
    }
    return rethrowCanaryStartupFailureAfterProfileLockDecision(
      error,
      profileLock,
      "RSI X canary startup and lock release both failed",
    );
  }
}
