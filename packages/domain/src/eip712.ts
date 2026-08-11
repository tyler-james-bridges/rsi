import { concatHex, hashTypedData, keccak256, stringToHex, type Address, type Hex } from "viem";

import { EvmAddressSchema, ExecutionIntentSchema, type ExecutionIntent } from "./schemas.js";

const EXECUTION_INTENT_TYPES = {
  ExecutionIntent: [
    { name: "intentId", type: "bytes32" },
    { name: "strategyVersion", type: "bytes32" },
    { name: "policyVersion", type: "bytes32" },
    { name: "policyHash", type: "bytes32" },
    { name: "target", type: "address" },
    { name: "collection", type: "address" },
    { name: "tokenId", type: "string" },
    { name: "paymentAsset", type: "address" },
    { name: "maxTotalSpend", type: "uint256" },
    { name: "recipient", type: "address" },
    { name: "orderHash", type: "bytes32" },
    { name: "evidenceRoot", type: "bytes32" },
    { name: "nonce", type: "bytes32" },
    { name: "expiresAt", type: "uint64" },
  ],
} as const;

function textHash(value: string): Hex {
  return keccak256(stringToHex(value));
}

export function evidenceRoot(evidenceIds: readonly string[]): Hex {
  const leaves = [...evidenceIds].sort().map(textHash);
  return keccak256(concatHex(leaves));
}

export function executionIntentTypedData(rawIntent: ExecutionIntent, rawVerifyingContract: string) {
  const intent = ExecutionIntentSchema.parse(rawIntent);
  const verifyingContract = EvmAddressSchema.parse(rawVerifyingContract) as Address;

  return {
    domain: {
      name: "RSI Policy Gateway",
      version: "1",
      chainId: intent.action.chainId,
      verifyingContract,
    },
    types: EXECUTION_INTENT_TYPES,
    primaryType: "ExecutionIntent" as const,
    message: {
      intentId: textHash(intent.intentId),
      strategyVersion: textHash(intent.strategyVersion),
      policyVersion: textHash(intent.policyVersion),
      policyHash: intent.policyHash as Hex,
      target: intent.action.targetContract as Address,
      collection: intent.action.collectionContract as Address,
      tokenId: intent.action.tokenId,
      paymentAsset: intent.action.paymentAsset as Address,
      maxTotalSpend: BigInt(intent.action.maxTotalSpend),
      recipient: intent.action.recipient as Address,
      orderHash: intent.action.orderHash as Hex,
      evidenceRoot: evidenceRoot(intent.evidenceIds),
      nonce: intent.action.nonce as Hex,
      expiresAt: BigInt(Math.floor(Date.parse(intent.expiresAt) / 1_000)),
    },
  };
}

export function hashExecutionIntent(intent: ExecutionIntent, verifyingContract: string): Hex {
  return hashTypedData(executionIntentTypedData(intent, verifyingContract));
}
