import {
  isDarwinOneShotClaimHost,
  type DarwinOneShotClaimHost,
} from "@rsi/credential-host/one-shot-claim";
import { X_READ_CANARY_PLAN_ID, readXReadCanaryProjection } from "@rsi/read-canary";
import { type SqliteEventStore } from "@rsi/store";

export interface XCanaryClaimBackfillReceipt {
  readonly markerCreated: true;
  readonly planId: typeof X_READ_CANARY_PLAN_ID;
  readonly receiptVerified: true;
}

export async function backfillXCanaryClaimWithHost(
  eventStore: SqliteEventStore,
  claimHost: DarwinOneShotClaimHost,
  typedPlanIdAcknowledgement: string,
): Promise<Readonly<XCanaryClaimBackfillReceipt>> {
  if (typedPlanIdAcknowledgement !== X_READ_CANARY_PLAN_ID) {
    throw new TypeError("The exact published X plan acknowledgement is required");
  }
  if (!isDarwinOneShotClaimHost(claimHost)) {
    throw new TypeError("An authentic X one-shot claim boundary is required");
  }
  const projection = readXReadCanaryProjection(eventStore, "unknown");
  if (
    projection.status !== "completed" ||
    projection.lastReceipt === null ||
    projection.lastReceipt.planId !== X_READ_CANARY_PLAN_ID
  ) {
    throw new TypeError("The canonical completed X receipt is unavailable");
  }
  await claimHost.claim();
  return Object.freeze({
    markerCreated: true,
    planId: X_READ_CANARY_PLAN_ID,
    receiptVerified: true,
  });
}
