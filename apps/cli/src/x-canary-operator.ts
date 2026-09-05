import {
  PRODUCTION_RUNTIME_FAILURE_MESSAGE,
  assertActiveProductionRuntime,
} from "./production-runtime.js";
import { parseXCanaryOperatorOptions, xCanaryOperatorUsage } from "./x-canary-operator-options.js";
import { startXCanaryOperator } from "./x-canary-operator-host.js";

const STARTUP_FAILURE_MESSAGE = "RSI X canary startup was refused.\n" as const;

let options: ReturnType<typeof parseXCanaryOperatorOptions> | undefined;
try {
  options = parseXCanaryOperatorOptions(process.argv.slice(2));
} catch {
  process.stderr.write(STARTUP_FAILURE_MESSAGE);
  process.exitCode = 1;
}
if (options === null) {
  console.log(xCanaryOperatorUsage());
  process.exitCode = 0;
} else if (options !== undefined) {
  let runtimeVerified = false;
  try {
    assertActiveProductionRuntime();
    runtimeVerified = true;
  } catch {
    process.stderr.write(PRODUCTION_RUNTIME_FAILURE_MESSAGE);
    process.exitCode = 1;
  }

  if (runtimeVerified) {
    try {
      const operator = await startXCanaryOperator(options);
      const snapshot = operator.runtime.getSnapshot();
      console.log(
        JSON.stringify({
          mode: "stage1-x-read-canary",
          runtimeMode: snapshot.mode,
          executionEnabled: false,
          financialAuthority: false,
          credentialBoundary: "macos-keychain",
          origin: operator.origin,
        }),
      );

      let closing = false;
      const handleSignal = (): void => {
        if (closing) return;
        closing = true;
        void operator.close().catch(() => {
          process.stderr.write("RSI failed to persist STOP cleanly during shutdown.\n");
          process.exitCode = 1;
        });
      };
      process.once("SIGINT", handleSignal);
      process.once("SIGTERM", handleSignal);
    } catch {
      process.stderr.write(STARTUP_FAILURE_MESSAGE);
      process.exitCode = 1;
    }
  }
}
