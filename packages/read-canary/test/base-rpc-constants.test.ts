import { describe, expect, it } from "vitest";

import * as production from "../src/base-rpc.js";

describe("Base RPC read-canary production surface", () => {
  it("publishes only code-owned request review constants", () => {
    expect(production.BASE_RPC_READ_CANARY_PLAN_ID).toBe("base-mainnet-finalized-anchor-v1");
    expect(production.BASE_RPC_READ_CANARY_RPC_METHODS).toEqual([
      "eth_chainId",
      "eth_getBlockByNumber",
    ]);
    expect(production.BASE_RPC_READ_CANARY_METHOD_SET_ACKNOWLEDGEMENT).toBe(
      "eth_chainId[]+eth_getBlockByNumber[finalized,false]",
    );
    expect(production.BASE_RPC_READ_CANARY_REQUEST_FINGERPRINT).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("does not export provider or authenticated durable-state internals", () => {
    const keys = Object.keys(production);
    for (const forbidden of [
      "recoverBaseRpcReadCanary",
      "BASE_RPC_READ_CANARY_PROVIDER_ID",
      "BASE_RPC_READ_CANARY_ENDPOINT",
      "BaseRpcReadCanaryPreparedEventPayloadSchema",
      "BaseRpcReadCanaryDurableReceiptSchema",
      "BaseRpcReadCanaryResultEventPayloadSchema",
      "BaseRpcReadCanaryFailureEventPayloadSchema",
    ]) {
      expect(keys).not.toContain(forbidden);
    }
  });
});
