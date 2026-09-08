import {
  PRODUCTION_RUNTIME_FAILURE_MESSAGE,
  assertActiveProductionRuntime,
} from "./production-runtime.js";
import { backfillXCanaryClaim } from "./x-canary-claim-backfill-host.js";
import {
  parseXCanaryClaimBackfillAcknowledgement,
  xCanaryClaimBackfillUsage,
} from "./x-canary-claim-backfill-options.js";

const BACKFILL_FAILURE_MESSAGE = "RSI X one-shot marker backfill was refused.\n" as const;

let acknowledgement: ReturnType<typeof parseXCanaryClaimBackfillAcknowledgement> | undefined;
try {
  acknowledgement = parseXCanaryClaimBackfillAcknowledgement(process.argv.slice(2));
} catch {
  process.stderr.write(BACKFILL_FAILURE_MESSAGE);
  process.exitCode = 1;
}
if (acknowledgement === null) {
  console.log(xCanaryClaimBackfillUsage());
  process.exitCode = 0;
} else if (acknowledgement !== undefined) {
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
      const result = await backfillXCanaryClaim(acknowledgement);
      console.log(JSON.stringify({ mode: "x-one-shot-marker-backfill", ...result }));
    } catch {
      process.stderr.write(BACKFILL_FAILURE_MESSAGE);
      process.exitCode = 1;
    }
  }
}
