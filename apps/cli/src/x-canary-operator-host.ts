import { DarwinXReadCanaryKeychain } from "@rsi/credential-host";
import { createDarwinXOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";

import { productionXCanaryHostOptions } from "./production-canary-config.js";
import { assertActiveProductionRuntime } from "./production-runtime.js";
import {
  startXCanaryOperatorWithHost,
  type RunningXCanaryOperator,
  type StartXCanaryOperatorOptions,
} from "./x-canary-operator-host-core.js";

export type {
  RunningXCanaryOperator,
  StartXCanaryOperatorOptions,
  XCanaryOperatorPaths,
} from "./x-canary-operator-host-core.js";

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
  return startXCanaryOperatorWithHost(
    productionOptions,
    new DarwinXReadCanaryKeychain(),
    createDarwinXOneShotClaimHost(),
  );
}
