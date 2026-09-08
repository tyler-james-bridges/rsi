import { isDarwinBaseRpcKeychain, type DarwinBaseRpcKeychain } from "@rsi/credential-host/base-rpc";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";

import { rethrowCanaryStartupFailureAfterProfileLockDecision } from "./canary-operator-startup-cleanup.js";
import {
  startBaseRpcCanaryOperatorWithHost,
  type RunningBaseRpcCanaryOperator as RunningBaseRpcCanaryOperatorForTesting,
  type StartBaseRpcCanaryOperatorOptions,
} from "./base-rpc-canary-operator-host-core.js";
import {
  acquireCanaryProfileLockForDatabasePathForTesting,
  bindProfileServiceLock,
} from "./profile-service-lock.testing.js";

export interface StartBaseRpcCanaryOperatorTestingOptions extends StartBaseRpcCanaryOperatorOptions {
  readonly claimHost: DarwinOneShotClaimHost;
  readonly credentialHost: DarwinBaseRpcKeychain;
}

export type { RunningBaseRpcCanaryOperatorForTesting };

export async function startBaseRpcCanaryOperatorForTesting(
  options: StartBaseRpcCanaryOperatorTestingOptions,
): Promise<RunningBaseRpcCanaryOperatorForTesting> {
  if (!isDarwinBaseRpcKeychain(options.credentialHost)) {
    throw new TypeError("An authentic Base RPC test Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(options.claimHost)) {
    throw new TypeError("An authentic Base RPC test one-shot claim boundary is required");
  }
  const profileLock = await acquireCanaryProfileLockForDatabasePathForTesting(options.databasePath);
  try {
    const operator = await startBaseRpcCanaryOperatorWithHost(
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
      "RSI Base RPC test canary startup and lock release both failed",
    );
  }
}
