import { isDarwinBaseRpcKeychain, type DarwinBaseRpcKeychain } from "@rsi/credential-host/base-rpc";
import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";

import {
  startBaseRpcCanaryOperatorWithHost,
  type RunningBaseRpcCanaryOperator,
  type StartBaseRpcCanaryOperatorOptions,
} from "./base-rpc-canary-operator-host-core.js";

export interface StartBaseRpcCanaryOperatorTestingOptions extends StartBaseRpcCanaryOperatorOptions {
  readonly claimHost: DarwinOneShotClaimHost;
  readonly credentialHost: DarwinBaseRpcKeychain;
}

export async function startBaseRpcCanaryOperatorForTesting(
  options: StartBaseRpcCanaryOperatorTestingOptions,
): Promise<RunningBaseRpcCanaryOperator> {
  if (!isDarwinBaseRpcKeychain(options.credentialHost)) {
    throw new TypeError("An authentic Base RPC test Keychain boundary is required");
  }
  if (!isDarwinOneShotClaimHost(options.claimHost)) {
    throw new TypeError("An authentic Base RPC test one-shot claim boundary is required");
  }
  return startBaseRpcCanaryOperatorWithHost(
    { databasePath: options.databasePath, port: options.port },
    options.credentialHost,
    options.claimHost,
  );
}
