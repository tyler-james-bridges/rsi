import {
  isDarwinOpenSeaTrendingKeychain,
  type DarwinOpenSeaTrendingKeychain,
} from "@rsi/credential-host/opensea-trending";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";

import {
  startOpenSeaCanaryOperatorWithHost,
  type RunningOpenSeaCanaryOperator,
  type StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";

export interface StartOpenSeaCanaryOperatorTestingOptions extends StartOpenSeaCanaryOperatorOptions {
  readonly claimHost: DarwinOneShotClaimHost;
  readonly credentialHost: DarwinOpenSeaTrendingKeychain;
}

export async function startOpenSeaCanaryOperatorForTesting(
  options: StartOpenSeaCanaryOperatorTestingOptions,
): Promise<RunningOpenSeaCanaryOperator> {
  if (!isDarwinOpenSeaTrendingKeychain(options.credentialHost)) {
    throw new TypeError("An authentic OpenSea test Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(options.claimHost)) {
    throw new TypeError("An authentic OpenSea test one-shot claim boundary is required");
  }
  return startOpenSeaCanaryOperatorWithHost(
    { databasePath: options.databasePath, port: options.port },
    options.credentialHost,
    options.claimHost,
  );
}
