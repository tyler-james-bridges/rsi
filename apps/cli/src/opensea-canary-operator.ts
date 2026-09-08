import {
  openSeaCanaryOperatorUsage,
  parseOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-options.js";
import {
  PRODUCTION_RUNTIME_FAILURE_MESSAGE,
  assertActiveProductionRuntime,
} from "./production-runtime.js";
import { startOpenSeaCanaryOperator } from "./opensea-canary-operator-host.js";

const STARTUP_FAILURE_MESSAGE = "RSI OpenSea canary startup was refused.\n" as const;

let options: ReturnType<typeof parseOpenSeaCanaryOperatorOptions> | undefined;
try {
  options = parseOpenSeaCanaryOperatorOptions(process.argv.slice(2));
} catch {
  process.stderr.write(STARTUP_FAILURE_MESSAGE);
  process.exitCode = 1;
}
if (options === null) {
  console.log(openSeaCanaryOperatorUsage());
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
    let operator: Awaited<ReturnType<typeof startOpenSeaCanaryOperator>> | undefined;
    let closePromise: Promise<void> | null = null;
    let shutdownRequested = false;
    const closeOperator = (): Promise<void> => {
      if (operator === undefined) return Promise.resolve();
      closePromise ??= operator.close();
      return closePromise;
    };
    const removeSignalHandlers = (): void => {
      process.off("SIGINT", handleSignal);
      process.off("SIGTERM", handleSignal);
    };
    const handleSignal = (): void => {
      shutdownRequested = true;
      if (operator === undefined) return;
      void closeOperator()
        .catch(() => {
          process.stderr.write("RSI failed to persist STOP cleanly during OpenSea shutdown.\n");
          process.exitCode = 1;
        })
        .finally(removeSignalHandlers);
    };
    process.once("SIGINT", handleSignal);
    process.once("SIGTERM", handleSignal);
    try {
      operator = await startOpenSeaCanaryOperator(options);
      if (shutdownRequested) {
        await closeOperator();
        removeSignalHandlers();
      } else {
        const snapshot = operator.runtime.getSnapshot();
        const startupLine = JSON.stringify({
          mode: "stage1-opensea-read-canary",
          runtimeMode: snapshot.mode,
          executionEnabled: false,
          financialAuthority: false,
          paymentCapability: false,
          credentialBoundary: "macos-keychain",
          provider: "opensea-api-v2",
          chain: "base",
          origin: operator.origin,
        });
        if (shutdownRequested) {
          await closeOperator();
          removeSignalHandlers();
        } else {
          console.log(startupLine);
        }
      }
    } catch {
      await closeOperator().catch(() => undefined);
      removeSignalHandlers();
      process.stderr.write(STARTUP_FAILURE_MESSAGE);
      process.exitCode = 1;
    }
  }
}
