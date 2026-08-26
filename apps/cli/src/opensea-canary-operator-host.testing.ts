import {
  isDarwinOpenSeaTrendingKeychain,
  type DarwinOpenSeaTrendingKeychain,
} from "@rsi/credential-host/opensea-trending";

import {
  startOpenSeaCanaryOperatorWithHost,
  type RunningOpenSeaCanaryOperator,
  type StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";

export interface StartOpenSeaCanaryOperatorTestingOptions extends StartOpenSeaCanaryOperatorOptions {
  readonly credentialHost: DarwinOpenSeaTrendingKeychain;
}

export async function startOpenSeaCanaryOperatorForTesting(
  options: StartOpenSeaCanaryOperatorTestingOptions,
): Promise<RunningOpenSeaCanaryOperator> {
  if (!isDarwinOpenSeaTrendingKeychain(options.credentialHost)) {
    throw new TypeError("An authentic OpenSea test Keychain boundary is required");
  }
  return startOpenSeaCanaryOperatorWithHost(
    { databasePath: options.databasePath, port: options.port },
    options.credentialHost,
  );
}
