import { generateKeyPairSync, sign } from "node:crypto";

import {
  CHECKPOINT_JOURNAL_GENESIS_HASH,
  CHECKPOINT_PAYLOAD_VERSION,
  CHECKPOINT_TYPE,
  computeCheckpointHash,
  encodeCheckpointPayload,
  type SignedCheckpoint,
} from "@rsi/checkpoints";

import {
  signExternalAnchorAuthorization,
  type AnchorProfile,
  type AnchorRetentionMode,
} from "../src/index.js";

export const T0 = "2026-08-14T12:00:00.000Z";
export const T1 = "2026-08-14T12:01:00.000Z";
export const T2 = "2026-08-14T12:02:00.000Z";
export const T3 = "2026-08-14T12:03:00.000Z";
export const BEFORE_GOVERNANCE_EXPIRY = "2026-09-01T12:00:00.000Z";
export const AFTER_GOVERNANCE_EXPIRY = "2026-09-14T12:00:00.000Z";

export function checkpointIdentity() {
  const keys = generateKeyPairSync("ed25519");
  return {
    expectedKeyId: "checkpoint-key-canary-v1",
    expectedPublicKey: keys.publicKey,
    expectedStoreId: "observer-store-canary-v1",
    privateKey: keys.privateKey,
  } as const;
}

export function checkpointVerifierIdentity(identity: ReturnType<typeof checkpointIdentity>) {
  return Object.freeze({
    expectedKeyId: identity.expectedKeyId,
    expectedPublicKey: identity.expectedPublicKey,
    expectedStoreId: identity.expectedStoreId,
  });
}

export function signedCheckpoint(
  identity: ReturnType<typeof checkpointIdentity>,
  input: Readonly<{
    createdAt: string;
    journalSequence: number;
    previousCheckpointHash?: string;
    storeHeadHash?: string;
    storeHeadSequence: number;
  }>,
): SignedCheckpoint {
  const payload = Object.freeze({
    checkpointType: CHECKPOINT_TYPE,
    createdAt: input.createdAt,
    journalSequence: input.journalSequence,
    keyId: identity.expectedKeyId,
    previousCheckpointHash: input.previousCheckpointHash ?? CHECKPOINT_JOURNAL_GENESIS_HASH,
    storeHeadHash: input.storeHeadHash ?? String(input.storeHeadSequence).padStart(64, "a"),
    storeHeadSequence: input.storeHeadSequence,
    storeId: identity.expectedStoreId,
    version: CHECKPOINT_PAYLOAD_VERSION,
  });
  const signature = sign(null, encodeCheckpointPayload(payload), identity.privateKey).toString(
    "base64url",
  );
  return Object.freeze({
    checkpointHash: computeCheckpointHash(payload, signature),
    payload,
    signature,
  });
}

export function checkpointChain(
  identity: ReturnType<typeof checkpointIdentity>,
  length: number,
): readonly SignedCheckpoint[] {
  const result: SignedCheckpoint[] = [];
  for (let index = 0; index < length; index += 1) {
    result.push(
      signedCheckpoint(identity, {
        createdAt: [T0, T1, T2, T3][index]!,
        journalSequence: index + 1,
        ...(index === 0 ? {} : { previousCheckpointHash: result[index - 1]!.checkpointHash }),
        storeHeadSequence: (index + 1) * 10,
      }),
    );
  }
  return Object.freeze(result);
}

export function anchorAuthorization(
  identity: ReturnType<typeof checkpointIdentity>,
  checkpoint: SignedCheckpoint,
  retentionMode: AnchorRetentionMode,
  profile: AnchorProfile = "canary",
) {
  return signExternalAnchorAuthorization({
    checkpoint,
    privateKey: identity.privateKey,
    profile,
    retentionMode,
  });
}

export function sequenceClock(...timestamps: readonly string[]): () => string {
  let index = 0;
  return () => timestamps[Math.min(index++, timestamps.length - 1)]!;
}
