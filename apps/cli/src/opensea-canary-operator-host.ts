import { DarwinOpenSeaTrendingKeychain } from "@rsi/credential-host/opensea-trending";
import { createDarwinOpenSeaOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";

import { productionOpenSeaCanaryHostOptions } from "./production-canary-config.js";
import { assertActiveProductionRuntime } from "./production-runtime.js";
import {
  startOpenSeaCanaryOperatorWithHost,
  type RunningOpenSeaCanaryOperator,
  type StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";

export type {
  OpenSeaCanaryOperatorPaths,
  RunningOpenSeaCanaryOperator,
  StartOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-host-core.js";

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
  return startOpenSeaCanaryOperatorWithHost(
    productionOptions,
    new DarwinOpenSeaTrendingKeychain(),
    createDarwinOpenSeaOneShotClaimHost(),
  );
}
