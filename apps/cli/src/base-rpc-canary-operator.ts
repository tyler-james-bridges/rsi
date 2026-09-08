import {
  baseRpcCanaryOperatorUsage,
  parseBaseRpcCanaryOperatorOptions,
} from "./base-rpc-canary-operator-options.js";
import { startBaseRpcCanaryOperator } from "./base-rpc-canary-operator-host.js";
import {
  PRODUCTION_RUNTIME_FAILURE_MESSAGE,
  assertActiveProductionRuntime,
} from "./production-runtime.js";

const STARTUP_FAILURE_MESSAGE = "RSI Base RPC read canary startup was refused.\n";

let requested = false;
try {
  const parsed = parseBaseRpcCanaryOperatorOptions(process.argv.slice(2));
  if (parsed === null) {
    process.stdout.write(`${baseRpcCanaryOperatorUsage()}\n`);
    process.exitCode = 0;
  } else {
    requested = true;
  }
} catch {
  process.stderr.write(STARTUP_FAILURE_MESSAGE);
  process.exitCode = 1;
}

if (requested) {
  let runtimeVerified = false;
  try {
    assertActiveProductionRuntime();
    runtimeVerified = true;
  } catch {
    process.stderr.write(PRODUCTION_RUNTIME_FAILURE_MESSAGE);
    process.exitCode = 1;
  }

  if (runtimeVerified) {
    let operator: Awaited<ReturnType<typeof startBaseRpcCanaryOperator>> | undefined;
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
          process.stderr.write("RSI failed to persist STOP cleanly during Base RPC shutdown.\n");
          process.exitCode = 1;
        })
        .finally(removeSignalHandlers);
    };
    process.once("SIGINT", handleSignal);
    process.once("SIGTERM", handleSignal);
    try {
      operator = await startBaseRpcCanaryOperator();
      const running = operator;
      if (shutdownRequested) {
        await closeOperator();
        removeSignalHandlers();
      } else {
        const snapshot = running.runtime.getSnapshot();
        const startupLine = `${JSON.stringify({
          mode: "stage1-base-rpc-read-canary",
          runtimeMode: snapshot.mode,
          executionEnabled: false,
          financialAuthority: false,
          paymentCapability: false,
          credentialBoundary: "macos-keychain",
          provider: "alchemy-base-mainnet",
          chain: "base-mainnet",
          origin: running.origin,
        })}\n`;
        if (shutdownRequested) {
          await closeOperator();
          removeSignalHandlers();
        } else {
          process.stdout.write(startupLine);
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
