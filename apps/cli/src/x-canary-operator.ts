import { parseOperatorOptions, operatorUsage } from "./operator-options.js";
import { startXCanaryOperator } from "./x-canary-operator-host.js";

const options = parseOperatorOptions(process.argv.slice(2));
if (options === null) {
  console.log(
    operatorUsage()
      .replace("pnpm operator", "pnpm operator:x-canary")
      .replace("Stage 0 runtime", "Stage 1 X read-canary runtime"),
  );
  process.exitCode = 0;
} else {
  const operator = await startXCanaryOperator(options);
  const snapshot = operator.runtime.getSnapshot();
  console.log(
    JSON.stringify({
      mode: "stage1-x-read-canary",
      runtimeMode: snapshot.mode,
      executionEnabled: false,
      financialAuthority: false,
      credentialBoundary: "macos-keychain",
      paths: operator.paths,
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
}
