import { DarwinOpenSeaTrendingKeychain } from "@rsi/credential-host/opensea-trending";

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
  return startOpenSeaCanaryOperatorWithHost(options, new DarwinOpenSeaTrendingKeychain());
}
