import { DarwinXReadCanaryKeychain } from "@rsi/credential-host";

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
  return startXCanaryOperatorWithHost(options, new DarwinXReadCanaryKeychain());
}
