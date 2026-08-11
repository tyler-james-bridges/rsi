import { describe, expect, it } from "vitest";

import {
  AtomicAmountSchema,
  PositiveAtomicAmountSchema,
  evidenceRoot,
  hashExecutionIntent,
  type ExecutionIntent,
} from "../src/index.js";

const intent: ExecutionIntent = {
  intentId: "rsi-intent:typed-data-001",
  strategyVersion: "rsi-v0",
  policyVersion: "kernel-v0",
  policyHash: `0x${"a".repeat(64)}`,
  evidenceIds: [`sha256:${"b".repeat(64)}`, `sha256:${"c".repeat(64)}`],
  createdAt: "2026-08-11T12:00:00.000Z",
  expiresAt: "2026-08-11T12:01:00.000Z",
  action: {
    kind: "nft.purchase",
    adapterId: "opensea.seaport",
    chainId: 4663,
    marketplace: "opensea",
    targetContract: `0x${"1".repeat(40)}`,
    collectionContract: `0x${"2".repeat(40)}`,
    tokenId: "7",
    paymentAsset: `0x${"3".repeat(40)}`,
    maxTotalSpend: "5000000",
    recipient: `0x${"4".repeat(40)}`,
    orderHash: `0x${"5".repeat(64)}`,
    nonce: `0x${"6".repeat(64)}`,
  },
};

describe("EIP-712 execution intent", () => {
  it("produces a stable digest", () => {
    const verifier = `0x${"7".repeat(40)}`;

    expect(hashExecutionIntent(intent, verifier)).toBe(
      hashExecutionIntent(structuredClone(intent), verifier),
    );
  });

  it("domain-separates the digest by verifying contract", () => {
    const first = hashExecutionIntent(intent, `0x${"7".repeat(40)}`);
    const second = hashExecutionIntent(intent, `0x${"8".repeat(40)}`);

    expect(first).not.toBe(second);
  });

  it("commits to nonce and evidence while making evidence order irrelevant", () => {
    const verifier = `0x${"7".repeat(40)}`;
    const changedNonce = {
      ...intent,
      action: { ...intent.action, nonce: `0x${"9".repeat(64)}` },
    };

    expect(hashExecutionIntent(intent, verifier)).not.toBe(
      hashExecutionIntent(changedNonce, verifier),
    );
    expect(evidenceRoot(intent.evidenceIds)).toBe(evidenceRoot([...intent.evidenceIds].reverse()));
  });

  it("rejects decimal values above the EVM uint256 boundary", () => {
    const maxUint256 = ((1n << 256n) - 1n).toString();
    expect(AtomicAmountSchema.parse(maxUint256)).toBe(maxUint256);
    expect(() => AtomicAmountSchema.parse((1n << 256n).toString())).toThrow(/uint256/);
    expect(() => AtomicAmountSchema.parse("9".repeat(10_000))).toThrow(/uint256/);
    expect(PositiveAtomicAmountSchema.safeParse("not-a-number").success).toBe(false);
    expect(PositiveAtomicAmountSchema.safeParse("0").success).toBe(false);
  });
});
