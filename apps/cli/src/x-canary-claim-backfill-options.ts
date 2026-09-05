import { X_READ_CANARY_PLAN_ID } from "@rsi/read-canary";

const ACKNOWLEDGEMENT_FLAG = "--typed-plan-id-acknowledgement" as const;

export function xCanaryClaimBackfillUsage(): string {
  return [
    `Usage: pnpm operator:x-canary-backfill-claim ${ACKNOWLEDGEMENT_FLAG} ${X_READ_CANARY_PLAN_ID}`,
    "",
    "Verifies the canonical completed X receipt, then creates its permanent one-shot marker.",
    "This command cannot read provider credentials, issue a request, or accept a path override.",
  ].join("\n");
}

export function parseXCanaryClaimBackfillAcknowledgement(
  args: readonly string[],
): typeof X_READ_CANARY_PLAN_ID | null {
  const normalized = args.filter((argument) => argument !== "--");
  if (normalized.length === 1 && (normalized[0] === "--help" || normalized[0] === "-h")) {
    return null;
  }
  if (
    normalized.length !== 2 ||
    normalized[0] !== ACKNOWLEDGEMENT_FLAG ||
    normalized[1] !== X_READ_CANARY_PLAN_ID
  ) {
    throw new Error("The exact published X plan acknowledgement is required");
  }
  return X_READ_CANARY_PLAN_ID;
}
