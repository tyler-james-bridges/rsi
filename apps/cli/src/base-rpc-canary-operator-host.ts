import { DarwinBaseRpcKeychain } from "@rsi/credential-host/base-rpc";
import { createDarwinBaseRpcOneShotClaimHost } from "@rsi/credential-host/one-shot-claim";

import { productionBaseRpcCanaryHostOptions } from "./production-canary-config.js";
import { assertActiveProductionRuntime } from "./production-runtime.js";
import {
  startBaseRpcCanaryOperatorWithHost,
  type RunningBaseRpcCanaryOperator,
} from "./base-rpc-canary-operator-host-core.js";

export type {
  BaseRpcCanaryOperatorPaths,
  RunningBaseRpcCanaryOperator,
} from "./base-rpc-canary-operator-host-core.js";

/** Starts only the code-owned production topology; it accepts no path or port overrides. */
export async function startBaseRpcCanaryOperator(): Promise<RunningBaseRpcCanaryOperator> {
  assertActiveProductionRuntime();
  if (arguments.length !== 0) {
    throw new TypeError("Base RPC canary production options are fixed");
  }
  return startBaseRpcCanaryOperatorWithHost(
    productionBaseRpcCanaryHostOptions(),
    new DarwinBaseRpcKeychain(),
    createDarwinBaseRpcOneShotClaimHost(),
  );
}
