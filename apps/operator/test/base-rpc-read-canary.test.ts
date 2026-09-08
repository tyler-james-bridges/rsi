import { randomUUID } from "node:crypto";

import {
  BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
  BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT,
  BASE_RPC_READ_CANARY_PLAN_ID,
  BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
  type BaseRpcReadCanaryPlanV1,
  type BaseRpcReadCanaryProjectionV1,
  type BaseRpcReadCanaryReceiptV1,
  type BaseRpcReadCanaryRunCommand,
} from "@rsi/read-canary/base-rpc";
import { describe, expect, it, vi } from "vitest";

import * as baseEntry from "../src/base-rpc.js";
import {
  parseOperatorBaseRpcReadCanaryCommand,
  parseOperatorBaseRpcReadCanaryProjection,
  parseOperatorBaseRpcReadCanaryReceipt,
} from "../src/base-rpc.js";
import * as rootEntry from "../src/index.js";

function plan(): BaseRpcReadCanaryPlanV1 {
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    profile: "canary",
    method: "POST",
    chain: "base-mainnet",
    blockTag: "finalized",
    rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
    maximumRequests: 1,
    maximumAnchors: 1,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
    requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
    rawContentDisposition: "encrypted_ephemeral",
    automaticRetries: 0,
    automaticFallback: false,
    paymentAuthority: "none",
    transactionAuthority: "none",
  };
}

function receipt(
  outcome: "accepted" | "failed" | "rejected" = "accepted",
): BaseRpcReadCanaryReceiptV1 {
  const accepted = outcome === "accepted";
  return {
    schemaVersion: 1,
    planId: BASE_RPC_READ_CANARY_PLAN_ID,
    requestFingerprint: BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
    rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
    outcome,
    failureCode: accepted ? null : "INVALID_RESPONSE_SCHEMA",
    completedAt: "2026-09-05T12:00:02.000Z",
    providerReportedFinalized: accepted ? true : null,
    freshnessVerdict: accepted ? "fresh" : null,
    maximumRequests: 1,
    ledgerReserveUsdMicros: BASE_RPC_READ_CANARY_LEDGER_RESERVE_USD_MICRO,
    actualChargeUsdMicros: null,
  };
}

function projection(
  status: BaseRpcReadCanaryProjectionV1["status"] = "completed",
): BaseRpcReadCanaryProjectionV1 {
  return {
    schemaVersion: 1,
    status,
    credentialStatus: "configured",
    plan: plan(),
    lastReceipt: status === "completed" ? receipt() : null,
  };
}

function command(): BaseRpcReadCanaryRunCommand {
  return {
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
}

describe("Base RPC operator projections", () => {
  it("is available only from the dedicated package subpath", () => {
    expect(baseEntry).toHaveProperty(
      "parseOperatorBaseRpcReadCanaryProjection",
      parseOperatorBaseRpcReadCanaryProjection,
    );
    expect(rootEntry).not.toHaveProperty("parseOperatorBaseRpcReadCanaryProjection");
    expect(rootEntry).not.toHaveProperty("startBaseRpcOperatorServer");
  });

  it("projects only fixed plan facts and the three public verdict fields", () => {
    const value = parseOperatorBaseRpcReadCanaryProjection(projection());

    expect(value).toEqual({
      schemaVersion: 1,
      status: "completed",
      credentialStatus: "configured",
      plan: {
        schemaVersion: 1,
        planId: BASE_RPC_READ_CANARY_PLAN_ID,
        profile: "canary",
        method: "POST",
        chain: "base-mainnet",
        blockTag: "finalized",
        rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
        maximumRequests: 1,
        maximumAnchors: 1,
        ledgerReserveUsdMicros: "1",
        actualChargeUsdMicros: null,
        rawContentDisposition: "encrypted_ephemeral",
        automaticRetries: 0,
        automaticFallback: false,
        paymentAuthority: "none",
        transactionAuthority: "none",
      },
      lastReceipt: {
        schemaVersion: 1,
        planId: BASE_RPC_READ_CANARY_PLAN_ID,
        outcome: "accepted",
        providerReportedFinalized: true,
        freshnessVerdict: "fresh",
      },
    });
    expect(Object.isFrozen(value)).toBe(true);
    expect(Object.isFrozen(value.plan)).toBe(true);
    expect(Object.isFrozen(value.plan.rpcMethods)).toBe(true);

    const serialized = JSON.stringify(value);
    for (const forbidden of [
      "requestFingerprint",
      BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT,
      "providerId",
      "alchemy",
      "requestId",
      "attemptId",
      "captureId",
      "eventHash",
      "blockNumber",
      "blockHash",
      "parentHash",
      "byteLength",
      "completedAt",
      "failureCode",
      "rateLimit",
      "headers",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("returns the same minimal receipt shape for accepted and closed failure outcomes", () => {
    expect(parseOperatorBaseRpcReadCanaryReceipt(receipt())).toEqual({
      schemaVersion: 1,
      planId: BASE_RPC_READ_CANARY_PLAN_ID,
      outcome: "accepted",
      providerReportedFinalized: true,
      freshnessVerdict: "fresh",
    });
    expect(parseOperatorBaseRpcReadCanaryReceipt(receipt("failed"))).toEqual({
      schemaVersion: 1,
      planId: BASE_RPC_READ_CANARY_PLAN_ID,
      outcome: "failed",
      providerReportedFinalized: null,
      freshnessVerdict: null,
    });
  });

  it("requires the exact acknowledgements and rejects extra or accessor data", () => {
    const exact = command();
    expect(parseOperatorBaseRpcReadCanaryCommand(exact)).toEqual(exact);

    for (const mutation of [
      { typedPlanIdAcknowledgement: "wrong-plan" },
      { oneRequestAcknowledgement: false },
      { nonPaymentReadAcknowledgement: false },
      { noTransactionAuthorityAcknowledgement: false },
      { finalizedAnchorAcknowledgement: false },
      { methodSetAcknowledgement: "eth_sendRawTransaction" },
      { ledgerReserveUsdMicrosAcknowledgement: "0" },
      { extra: true },
    ]) {
      expect(() => parseOperatorBaseRpcReadCanaryCommand({ ...exact, ...mutation })).toThrow(
        "invalid",
      );
    }

    const getter = vi.fn(() => "secret");
    const accessor = { ...projection("ready") } as Record<string, unknown>;
    Object.defineProperty(accessor, "apiKey", { enumerable: true, get: getter });
    expect(() => parseOperatorBaseRpcReadCanaryProjection(accessor)).toThrow(TypeError);
    expect(getter).not.toHaveBeenCalled();
  });

  it("rejects injected provider, JSON-RPC, block, quota, header, or secret fields", () => {
    for (const [key, value] of [
      ["providerId", "alchemy-base-mainnet"],
      ["jsonRpcId", "rsi-base-finalized-block-v1"],
      ["blockNumber", "123"],
      ["blockHash", `0x${"1".repeat(64)}`],
      ["rateLimit", { remaining: 1 }],
      ["headers", { authorization: "secret" }],
      ["apiKey", "secret"],
    ] as const) {
      expect(() =>
        parseOperatorBaseRpcReadCanaryProjection({ ...projection("ready"), [key]: value }),
      ).toThrow("invalid");
    }
  });
});
