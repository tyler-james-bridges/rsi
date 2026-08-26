import { isDarwinXReadCanaryKeychain, type DarwinXReadCanaryKeychain } from "@rsi/credential-host";

import {
  startXCanaryOperatorWithHost,
  type RunningXCanaryOperator,
  type StartXCanaryOperatorOptions,
} from "./x-canary-operator-host-core.js";

export interface StartXCanaryOperatorTestingOptions extends StartXCanaryOperatorOptions {
  readonly credentialHost: DarwinXReadCanaryKeychain;
}

export async function startXCanaryOperatorForTesting(
  options: StartXCanaryOperatorTestingOptions,
): Promise<RunningXCanaryOperator> {
  if (!isDarwinXReadCanaryKeychain(options.credentialHost)) {
    throw new TypeError("An authentic test Keychain boundary is required");
  }
  return startXCanaryOperatorWithHost(
    {
      databasePath: options.databasePath,
      port: options.port,
      researchDatabasePath: options.researchDatabasePath,
    },
    options.credentialHost,
  );
}
