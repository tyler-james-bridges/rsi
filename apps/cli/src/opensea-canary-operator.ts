import {
  openSeaCanaryOperatorUsage,
  parseOpenSeaCanaryOperatorOptions,
} from "./opensea-canary-operator-options.js";
import { startOpenSeaCanaryOperator } from "./opensea-canary-operator-host.js";

const options = parseOpenSeaCanaryOperatorOptions(process.argv.slice(2));
if (options === null) {
  console.log(openSeaCanaryOperatorUsage());
  process.exitCode = 0;
} else {
  const operator = await startOpenSeaCanaryOperator(options);
  const snapshot = operator.runtime.getSnapshot();
  console.log(
    JSON.stringify({
      mode: "stage1-opensea-read-canary",
      runtimeMode: snapshot.mode,
      executionEnabled: false,
      financialAuthority: false,
      paymentCapability: false,
      credentialBoundary: "macos-keychain",
      provider: "opensea-api-v2",
      chain: "base",
      origin: operator.origin,
    }),
  );

  let closing = false;
  const handleSignal = (): void => {
    if (closing) return;
    closing = true;
    void operator.close().catch(() => {
      process.stderr.write("RSI failed to persist STOP cleanly during OpenSea shutdown.\n");
      process.exitCode = 1;
    });
  };
  process.once("SIGINT", handleSignal);
  process.once("SIGTERM", handleSignal);
}
