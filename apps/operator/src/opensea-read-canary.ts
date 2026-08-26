import {
  OPENSEA_READ_CANARY_ENDPOINT,
  OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  OPENSEA_READ_CANARY_MAXIMUM_REQUESTS,
  OPENSEA_READ_CANARY_MAXIMUM_RESULTS,
  OPENSEA_READ_CANARY_OPERATION,
  OPENSEA_READ_CANARY_PLAN_ID,
  OPENSEA_READ_CANARY_PROFILE,
  OPENSEA_READ_CANARY_PROVIDER_ID,
  OpenSeaReadCanaryProjectionSchema,
  OpenSeaReadCanaryReceiptSchema,
  OpenSeaReadCanaryRunCommandSchema,
  parseOpenSeaReadCanaryInput,
  type OpenSeaReadCanaryPlanV1,
  type OpenSeaReadCanaryProjectionV1,
  type OpenSeaReadCanaryReceiptV1,
  type OpenSeaReadCanaryRunCommand,
} from "@rsi/read-canary/opensea";

export {
  OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO as OPERATOR_OPENSEA_LEDGER_RESERVE_USD_MICROS,
  OPENSEA_READ_CANARY_MAXIMUM_REQUESTS as OPERATOR_OPENSEA_MAXIMUM_REQUESTS,
  OPENSEA_READ_CANARY_MAXIMUM_RESULTS as OPERATOR_OPENSEA_MAXIMUM_RESULTS,
  OPENSEA_READ_CANARY_PLAN_ID as OPERATOR_OPENSEA_PLAN_ID,
};

export interface OperatorOpenSeaReadCanaryReceiptV1 {
  readonly schemaVersion: 1;
  readonly planId: typeof OPENSEA_READ_CANARY_PLAN_ID;
  readonly providerId: typeof OPENSEA_READ_CANARY_PROVIDER_ID;
  readonly outcome: OpenSeaReadCanaryReceiptV1["outcome"];
  readonly failureCode: OpenSeaReadCanaryReceiptV1["failureCode"];
  readonly acquiredAt: string | null;
  readonly completedAt: string;
  readonly collectionCount: number | null;
  readonly byteLength: number | null;
  readonly hasNextPage: boolean | null;
  readonly rateLimit: OpenSeaReadCanaryReceiptV1["rateLimit"];
  readonly maximumRequests: typeof OPENSEA_READ_CANARY_MAXIMUM_REQUESTS;
  readonly maximumResults: typeof OPENSEA_READ_CANARY_MAXIMUM_RESULTS;
  readonly ledgerReserveUsdMicros: typeof OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO;
  readonly actualChargeUsdMicros: null;
}

export interface OperatorOpenSeaReadCanaryProjectionV1 {
  readonly schemaVersion: 1;
  readonly status: OpenSeaReadCanaryProjectionV1["status"];
  readonly credentialStatus: OpenSeaReadCanaryProjectionV1["credentialStatus"];
  readonly plan: Readonly<OpenSeaReadCanaryPlanV1>;
  readonly lastReceipt: Readonly<OperatorOpenSeaReadCanaryReceiptV1> | null;
}

export interface OperatorOpenSeaReadCanaryProvider {
  /** Returns the controller projection. The HTTP boundary removes private provenance. */
  getOpenSeaReadCanaryProjection():
    Promise<Readonly<OpenSeaReadCanaryProjectionV1>> | Readonly<OpenSeaReadCanaryProjectionV1>;
  /** Explicit same-origin metadata refresh; it must never reveal credential values. */
  refreshOpenSeaCredentialStatus():
    Promise<Readonly<OpenSeaReadCanaryProjectionV1>> | Readonly<OpenSeaReadCanaryProjectionV1>;
  /** Executes only the fixed, one-shot, non-payment command. */
  executeOpenSeaReadCanary(
    command: Readonly<OpenSeaReadCanaryRunCommand>,
  ): Promise<Readonly<OpenSeaReadCanaryReceiptV1>> | Readonly<OpenSeaReadCanaryReceiptV1>;
  /** Best-effort synchronous interruption performed before durable STOP. */
  abortActive(): void;
}

function freezePlan(plan: OpenSeaReadCanaryPlanV1): Readonly<OpenSeaReadCanaryPlanV1> {
  if (
    plan.planId !== OPENSEA_READ_CANARY_PLAN_ID ||
    plan.providerId !== OPENSEA_READ_CANARY_PROVIDER_ID ||
    plan.operation !== OPENSEA_READ_CANARY_OPERATION ||
    plan.profile !== OPENSEA_READ_CANARY_PROFILE ||
    plan.endpoint !== OPENSEA_READ_CANARY_ENDPOINT ||
    plan.method !== "GET" ||
    plan.chain !== "base" ||
    plan.timeframe !== "one_day" ||
    plan.maximumRequests !== OPENSEA_READ_CANARY_MAXIMUM_REQUESTS ||
    plan.maximumResults !== OPENSEA_READ_CANARY_MAXIMUM_RESULTS ||
    plan.ledgerReserveUsdMicros !== OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO ||
    plan.actualChargeUsdMicros !== null ||
    plan.automaticRetries !== 0 ||
    plan.automaticPagination !== false ||
    plan.rawContentDisposition !== "encrypted_ephemeral"
  ) {
    throw new TypeError("OpenSea read canary plan is invalid");
  }
  return Object.freeze({ ...plan });
}

/**
 * Converts a valid controller receipt into the deliberately smaller public shape.
 * Runtime authorization, capture event hashes/sequences, request identifiers, and
 * other private provenance never cross the loopback HTTP boundary.
 */
export function parseOperatorOpenSeaReadCanaryReceipt(
  value: unknown,
): Readonly<OperatorOpenSeaReadCanaryReceiptV1> {
  const receipt = parseOpenSeaReadCanaryInput(
    OpenSeaReadCanaryReceiptSchema,
    value,
    "OpenSea read canary receipt",
  );
  const rateLimit = receipt.rateLimit === null ? null : Object.freeze({ ...receipt.rateLimit });
  return Object.freeze({
    schemaVersion: 1,
    planId: OPENSEA_READ_CANARY_PLAN_ID,
    providerId: OPENSEA_READ_CANARY_PROVIDER_ID,
    outcome: receipt.outcome,
    failureCode: receipt.failureCode,
    acquiredAt: receipt.acquiredAt,
    completedAt: receipt.completedAt,
    collectionCount: receipt.collectionCount,
    byteLength: receipt.byteLength,
    hasNextPage: receipt.hasNextPage,
    rateLimit,
    maximumRequests: OPENSEA_READ_CANARY_MAXIMUM_REQUESTS,
    maximumResults: OPENSEA_READ_CANARY_MAXIMUM_RESULTS,
    ledgerReserveUsdMicros: OPENSEA_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
  });
}

export function parseOperatorOpenSeaReadCanaryProjection(
  value: unknown,
): Readonly<OperatorOpenSeaReadCanaryProjectionV1> {
  const projection = parseOpenSeaReadCanaryInput(
    OpenSeaReadCanaryProjectionSchema,
    value,
    "OpenSea read canary projection",
  );
  return Object.freeze({
    schemaVersion: 1,
    status: projection.status,
    credentialStatus: projection.credentialStatus,
    plan: freezePlan(projection.plan),
    lastReceipt:
      projection.lastReceipt === null
        ? null
        : parseOperatorOpenSeaReadCanaryReceipt(projection.lastReceipt),
  });
}

export function parseOperatorOpenSeaReadCanaryCommand(
  value: unknown,
): Readonly<OpenSeaReadCanaryRunCommand> {
  return Object.freeze(
    parseOpenSeaReadCanaryInput(
      OpenSeaReadCanaryRunCommandSchema,
      value,
      "OpenSea read canary command",
    ),
  );
}
