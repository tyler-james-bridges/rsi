import {
  isDarwinOpenSeaTrendingKeychain,
  type DarwinOpenSeaTrendingKeychain,
} from "@rsi/credential-host/opensea-trending";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";

import { rethrowCanaryStartupFailureAfterProfileLockDecision } from "./canary-operator-startup-cleanup.js";
import {
  startOpenSeaCanaryOperatorWithHost,
  type RunningOpenSeaCanaryOperator as RunningOpenSeaCanaryOperatorForTesting,
  type StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";
import {
  acquireCanaryProfileLockForDatabasePathForTesting,
  bindProfileServiceLock,
} from "./profile-service-lock.testing.js";

export interface StartOpenSeaCanaryOperatorTestingOptions extends StartOpenSeaCanaryOperatorOptions {
  readonly claimHost: DarwinOneShotClaimHost;
  readonly credentialHost: DarwinOpenSeaTrendingKeychain;
}

export type { RunningOpenSeaCanaryOperatorForTesting };

export async function startOpenSeaCanaryOperatorForTesting(
  options: StartOpenSeaCanaryOperatorTestingOptions,
): Promise<RunningOpenSeaCanaryOperatorForTesting> {
  if (!isDarwinOpenSeaTrendingKeychain(options.credentialHost)) {
    throw new TypeError("An authentic OpenSea test Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(options.claimHost)) {
    throw new TypeError("An authentic OpenSea test one-shot claim boundary is required");
  }
  const profileLock = await acquireCanaryProfileLockForDatabasePathForTesting(options.databasePath);
  try {
    const operator = await startOpenSeaCanaryOperatorWithHost(
      { databasePath: options.databasePath, port: options.port },
      options.credentialHost,
      options.claimHost,
      profileLock,
    );
    return bindProfileServiceLock(operator, profileLock);
  } catch (error) {
    return rethrowCanaryStartupFailureAfterProfileLockDecision(
      error,
      profileLock,
      "RSI OpenSea test canary startup and lock release both failed",
    );
  }
}
