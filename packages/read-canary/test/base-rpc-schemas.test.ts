import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  BaseRpcReadCanaryReceiptSchema,
  BaseRpcReadCanaryRunCommandSchema,
} from "../src/base-rpc.js";
import {
  BaseRpcReadCanaryDurableReceiptSchema,
  parseBaseRpcReadCanaryInput,
} from "../src/base-rpc-schemas.js";

function publicReceipt() {
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
    rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
    outcome: "accepted",
    failureCode: null,
    completedAt: "2026-09-05T12:00:00.000Z",
    providerReportedFinalized: true,
    freshnessVerdict: "fresh",
    maximumRequests: 1,
    ledgerReserveUsdMicros: "1",
    actualChargeUsdMicros: null,
  };
}

describe("Base RPC read-canary schemas", () => {
  it("accepts only the full typed acknowledgement for the fixed method set", () => {
    const value = {
      schemaVersion: 1,
      planId: BASE_RPC_READ_CANARY_PLAN_ID,
      expectedRuntimeRevision: 2,
      requestId: randomUUID(),
      typedPlanIdAcknowledgement: BASE_RPC_READ_CANARY_PLAN_ID,
      oneRequestAcknowledgement: true,
      nonPaymentReadAcknowledgement: true,
      noTransactionAuthorityAcknowledgement: true,
      finalizedAnchorAcknowledgement: true,
      methodSetAcknowledgement: BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
      ledgerReserveUsdMicrosAcknowledgement: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    };
    expect(BaseRpcReadCanaryRunCommandSchema.parse(value)).toEqual(value);
    expect(() => BaseRpcReadCanaryRunCommandSchema.parse({ ...value, retry: true })).toThrow();
    expect(() =>
      BaseRpcReadCanaryRunCommandSchema.parse({
        ...value,
        methodSetAcknowledgement: "eth_call",
      }),
    ).toThrow();
  });

  it("keeps public receipts content-free and rejects contradictory verdicts", () => {
    const valid = publicReceipt();
    expect(BaseRpcReadCanaryReceiptSchema.parse(valid)).toEqual(valid);
    expect(() =>
      BaseRpcReadCanaryReceiptSchema.parse({ ...valid, requestId: randomUUID() }),
    ).toThrow();
    expect(() =>
      BaseRpcReadCanaryReceiptSchema.parse({
        ...valid,
        outcome: "rejected",
        failureCode: "RUNTIME_DENIED",
      }),
    ).toThrow();
  });

  it("authenticates the internal binding while excluding it from the public schema", () => {
    const requestId = randomUUID();
    const durable = {
      schemaVersion: 1,
      receiptId: `base-rpc-read-canary:${requestId}`,
      planId: BASE_RPC_READ_CANARY_PLAN_ID,
      providerId: "alchemy-base-mainnet",
      requestId,
      requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
      outcome: "accepted",
      failureCode: null,
      acquiredAt: "2026-09-05T11:59:59.000Z",
      completedAt: "2026-09-05T12:00:00.000Z",
      anchorCount: 1,
      byteLength: 512,
      providerReportedFinalized: true,
      freshnessVerdict: "fresh",
      maximumRequests: 1,
      maximumAnchors: 1,
      ledgerReserveUsdMicros: "1",
      actualChargeUsdMicros: null,
      runtime: {
        authorizationId: randomUUID(),
        eventHash: "11".repeat(32),
        eventSequence: 2,
        modeRevision: 2,
      },
      capture: { eventHash: "22".repeat(32), eventSequence: 3 },
    };
    expect(BaseRpcReadCanaryDurableReceiptSchema.parse(durable)).toEqual(durable);
    expect(() => BaseRpcReadCanaryReceiptSchema.parse(durable)).toThrow();
    expect(() =>
      BaseRpcReadCanaryDurableReceiptSchema.parse({ ...durable, requestId: randomUUID() }),
    ).toThrow();
  });

  it("rejects accessors, proxies, and cyclic input before schema traversal", () => {
    const accessor = Object.defineProperty({}, "schemaVersion", {
      enumerable: true,
      get: () => 1,
    });
    expect(() =>
      parseBaseRpcReadCanaryInput(BaseRpcReadCanaryReceiptSchema, accessor, "receipt"),
    ).toThrow(TypeError);
    expect(() =>
      parseBaseRpcReadCanaryInput(
        BaseRpcReadCanaryReceiptSchema,
        new Proxy(publicReceipt(), {}),
        "receipt",
      ),
    ).toThrow(TypeError);
    const cyclic: Record<string, unknown> = publicReceipt();
    cyclic.self = cyclic;
    expect(() =>
      parseBaseRpcReadCanaryInput(BaseRpcReadCanaryReceiptSchema, cyclic, "receipt"),
    ).toThrow(TypeError);
  });
});
