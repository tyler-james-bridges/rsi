import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS,
  BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_PROFILE,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  BASE_RPC_READ_CANARY_RPC_METHODS,
  BaseRpcReadCanaryPlanSchema,
  BaseRpcReadCanaryProjectionSchema,
  BaseRpcReadCanaryReceiptSchema,
  BaseRpcReadCanaryRunCommandSchema,
  parseBaseRpcReadCanaryInput,
  type BaseRpcReadCanaryPlanV1,
  type BaseRpcReadCanaryProjectionV1,
  type BaseRpcReadCanaryReceiptV1,
  type BaseRpcReadCanaryRunCommand,
} from "@rsi/read-canary/base-rpc";

export {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO as OPERATOR_BASE_RPC_LEDGER_RESERVE_USD_MICROS,
  BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS as OPERATOR_BASE_RPC_MAXIMUM_ANCHORS,
  BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS as OPERATOR_BASE_RPC_MAXIMUM_REQUESTS,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT as OPERATOR_BASE_RPC_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID as OPERATOR_BASE_RPC_PLAN_ID,
};

export interface OperatorBaseRpcReadCanaryPlanV1 {
  readonly schemaVersion: 1;
  readonly planId: typeof BASE_RPC_READ_CANARY_PLAN_ID;
  readonly profile: typeof BASE_RPC_READ_CANARY_PROFILE;
  readonly method: "POST";
  readonly chain: "base-mainnet";
  readonly blockTag: "finalized";
  readonly rpcMethods: readonly ["eth_chainId", "eth_getBlockByNumber"];
  readonly maximumRequests: typeof BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS;
  readonly maximumAnchors: typeof BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS;
  readonly ledgerReserveUsdMicros: typeof BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO;
  readonly actualChargeUsdMicros: null;
  readonly rawContentDisposition: "encrypted_ephemeral";
  readonly automaticRetries: 0;
  readonly automaticFallback: false;
  readonly paymentAuthority: "none";
  readonly transactionAuthority: "none";
}

/** No timestamps, hashes, block identifiers, or operational identifiers cross this boundary. */
export interface OperatorBaseRpcReadCanaryReceiptV1 {
  readonly schemaVersion: 1;
  readonly planId: typeof BASE_RPC_READ_CANARY_PLAN_ID;
  readonly outcome: BaseRpcReadCanaryReceiptV1["outcome"];
  /** A provider response to the `finalized` tag, never an independent finality proof. */
  readonly providerReportedFinalized: true | null;
  readonly freshnessVerdict: "fresh" | null;
}

export interface OperatorBaseRpcReadCanaryProjectionV1 {
  readonly schemaVersion: 1;
  readonly status: BaseRpcReadCanaryProjectionV1["status"];
  readonly credentialStatus: BaseRpcReadCanaryProjectionV1["credentialStatus"];
  readonly plan: Readonly<OperatorBaseRpcReadCanaryPlanV1>;
  readonly lastReceipt: Readonly<OperatorBaseRpcReadCanaryReceiptV1> | null;
}

export interface OperatorBaseRpcReadCanaryProvider {
  /** Returns a controller projection; this boundary removes private provenance. */
  getBaseRpcReadCanaryProjection():
    Promise<Readonly<BaseRpcReadCanaryProjectionV1>> | Readonly<BaseRpcReadCanaryProjectionV1>;
  /** Explicit presence-only credential refresh; credential values must never be returned. */
  refreshBaseRpcCredentialStatus():
    Promise<Readonly<BaseRpcReadCanaryProjectionV1>> | Readonly<BaseRpcReadCanaryProjectionV1>;
  /** Executes the exact one-request, two-read-method, non-payment command only. */
  executeBaseRpcReadCanary(
    command: Readonly<BaseRpcReadCanaryRunCommand>,
  ): Promise<Readonly<BaseRpcReadCanaryReceiptV1>> | Readonly<BaseRpcReadCanaryReceiptV1>;
  /** Best-effort synchronous interruption performed before durable STOP. */
  abortActive(): void;
}

function projectPlan(value: BaseRpcReadCanaryPlanV1): Readonly<OperatorBaseRpcReadCanaryPlanV1> {
  if (
    value.planId !== BASE_RPC_READ_CANARY_PLAN_ID ||
    value.profile !== BASE_RPC_READ_CANARY_PROFILE ||
    value.method !== "POST" ||
    value.chain !== "base-mainnet" ||
    value.blockTag !== "finalized" ||
    value.rpcMethods.length !== BASE_RPC_READ_CANARY_RPC_METHODS.length ||
    value.rpcMethods.some((method, index) => method !== BASE_RPC_READ_CANARY_RPC_METHODS[index]) ||
    value.maximumRequests !== BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS ||
    value.maximumAnchors !== BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS ||
    value.ledgerReserveUsdMicros !== BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO ||
    value.actualChargeUsdMicros !== null ||
    value.requestFingerprint !== BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT ||
    value.rawContentDisposition !== "encrypted_ephemeral" ||
    value.automaticRetries !== 0 ||
    value.automaticFallback !== false ||
    value.paymentAuthority !== "none" ||
    value.transactionAuthority !== "none"
  ) {
    throw new TypeError("Base RPC read canary plan is invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    profile: BASE_RPC_READ_CANARY_PROFILE,
    method: "POST",
    chain: "base-mainnet",
    blockTag: "finalized",
    rpcMethods: Object.freeze([
      BASE_RPC_READ_CANARY_RPC_METHODS[0],
      BASE_RPC_READ_CANARY_RPC_METHODS[1],
    ] as const),
    maximumRequests: BASE_RPC_READ_CANARY_MAXIMUM_REQUESTS,
    maximumAnchors: BASE_RPC_READ_CANARY_MAXIMUM_ANCHORS,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    rawContentDisposition: "encrypted_ephemeral",
    automaticRetries: 0,
    automaticFallback: false,
    paymentAuthority: "none",
    transactionAuthority: "none",
  });
}

export function parseOperatorBaseRpcReadCanaryReceipt(
  value: unknown,
): Readonly<OperatorBaseRpcReadCanaryReceiptV1> {
  const receipt = parseBaseRpcReadCanaryInput(
    BaseRpcReadCanaryReceiptSchema,
    value,
    "Base RPC read canary receipt",
  );
  return Object.freeze({
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    outcome: receipt.outcome,
    providerReportedFinalized: receipt.providerReportedFinalized,
    freshnessVerdict: receipt.freshnessVerdict,
  });
}

export function parseOperatorBaseRpcReadCanaryProjection(
  value: unknown,
): Readonly<OperatorBaseRpcReadCanaryProjectionV1> {
  const projection = parseBaseRpcReadCanaryInput(
    BaseRpcReadCanaryProjectionSchema,
    value,
    "Base RPC read canary projection",
  );
  return Object.freeze({
    schemaVersion: 1,
    status: projection.status,
    credentialStatus: projection.credentialStatus,
    plan: projectPlan(projection.plan),
    lastReceipt:
      projection.lastReceipt === null
        ? null
        : parseOperatorBaseRpcReadCanaryReceipt(projection.lastReceipt),
  });
}

export function parseOperatorBaseRpcReadCanaryCommand(
  value: unknown,
): Readonly<BaseRpcReadCanaryRunCommand> {
  return Object.freeze(
    parseBaseRpcReadCanaryInput(
      BaseRpcReadCanaryRunCommandSchema,
      value,
      "Base RPC read canary command",
    ),
  );
}
