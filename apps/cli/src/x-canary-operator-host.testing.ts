import { isDarwinXReadCanaryKeychain, type DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";

import { rethrowCanaryStartupFailureAfterProfileLockDecision } from "./canary-operator-startup-cleanup.js";
import {
  startXCanaryOperatorWithHost,
  type RunningXCanaryOperator as RunningXCanaryOperatorForTesting,
  type StartXCanaryOperatorOptions,
} from "./x-canary-operator-host-core.js";
import {
  acquireCanaryProfileLockForDatabasePathForTesting,
  bindProfileServiceLock,
} from "./profile-service-lock.testing.js";

export interface StartXCanaryOperatorTestingOptions extends StartXCanaryOperatorOptions {
  readonly claimHost: DarwinOneShotClaimHost;
  readonly credentialHost: DarwinXReadCanaryKeychain;
}

export type { RunningXCanaryOperatorForTesting };

export async function startXCanaryOperatorForTesting(
  options: StartXCanaryOperatorTestingOptions,
): Promise<RunningXCanaryOperatorForTesting> {
  if (!isDarwinXReadCanaryKeychain(options.credentialHost)) {
    throw new TypeError("An authentic test Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(options.claimHost)) {
    throw new TypeError("An authentic test one-shot claim boundary is required");
  }
  const profileLock = await acquireCanaryProfileLockForDatabasePathForTesting(options.databasePath);
  try {
    const operator = await startXCanaryOperatorWithHost(
      {
        databasePath: options.databasePath,
        port: options.port,
        researchDatabasePath: options.researchDatabasePath,
      },
      options.credentialHost,
      options.claimHost,
      profileLock,
    );
    return bindProfileServiceLock(operator, profileLock);
  } catch (error) {
    return rethrowCanaryStartupFailureAfterProfileLockDecision(
      error,
      profileLock,
      "RSI X test canary startup and lock release both failed",
    );
  }
}
