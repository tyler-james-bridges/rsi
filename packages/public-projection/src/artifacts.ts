import { createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  base64url,
  canonicalBytes,
  canonicalJson,
  copyOrdinaryBytes,
  sha256Hex,
} from "./canonical.js";
import { PublicProjectionError } from "./errors.js";
import {
  PublicArtifactPayloadSchema,
  PublicReceiptCandidateSchema,
  SignedPublicArtifactSchema,
  parseSchema,
} from "./schemas.js";
import { artifactSigningMessage, publicArtifactHashPreimage } from "./protocol.js";
import type {
  PublicArtifactPayloadV1,
  PublicArtifactSigner,
  PublicCorrectionPayloadV1,
  PublicProfile,
  PublicReceiptCandidateV1,
  PublicReceiptPayloadV1,
  PublicTombstonePayloadV1,
  SignedPublicArtifactV1,
} from "./types.js";

const MAX_CANDIDATE_BYTES = 16 * 1_024;
const MINIMUM_PUBLICATION_DELAY_MS = 24 * 60 * 60 * 1_000;

export function preparePublicReceiptCandidate(value: unknown): Readonly<PublicReceiptCandidateV1> {
  const candidate = parseSchema(PublicReceiptCandidateSchema, value);
  if (
    Date.parse(candidate.createdAt) < Date.parse(candidate.acceptedAt) ||
    Date.parse(candidate.eligibleAt) < Date.parse(candidate.createdAt) ||
    Date.parse(candidate.eligibleAt) - Date.parse(candidate.acceptedAt) <
      MINIMUM_PUBLICATION_DELAY_MS ||
    BigInt(candidate.costs.reconciledAtomic) > BigInt(candidate.costs.reservedAtomic) ||
    canonicalBytes(candidate).byteLength > MAX_CANDIDATE_BYTES
  ) {
    throw new PublicProjectionError("INPUT_INVALID");
  }
  return deepFreeze(candidate);
}

export async function createSignedPublicReceipt(
  optionsValue: Readonly<{
    candidate: PublicReceiptCandidateV1;
    predecessorSha256: string | null;
    publishApproved: true;
    publishedAt: string;
    reviewedAt: string;
    sequence: number;
    signer: PublicArtifactSigner;
  }>,
): Promise<Readonly<SignedPublicArtifactV1>> {
  const options = exactOptions(optionsValue, [
    "candidate",
    "predecessorSha256",
    "publishApproved",
    "publishedAt",
    "reviewedAt",
    "sequence",
    "signer",
  ]);
  if (options.publishApproved !== true) throw new PublicProjectionError("INPUT_INVALID");
  const candidate = preparePublicReceiptCandidate(options.candidate);
  const payload = parseSchema(PublicArtifactPayloadSchema, {
    ...candidate,
    artifactType: "rsi.public-receipt",
    predecessorSha256: options.predecessorSha256,
    publishedAt: options.publishedAt,
    receiptId: randomUUID(),
    reviewedAt: options.reviewedAt,
    sequence: options.sequence,
  }) as PublicReceiptPayloadV1;
  if (
    Date.parse(payload.reviewedAt) < Date.parse(payload.eligibleAt) ||
    Date.parse(payload.publishedAt) < Date.parse(payload.reviewedAt) ||
    (payload.sequence === 1) !== (payload.predecessorSha256 === null)
  ) {
    throw new PublicProjectionError("DELAY_NOT_MET");
  }
  return signPayload(payload, options.signer as PublicArtifactSigner);
}

export async function createSignedPublicCorrection(
  optionsValue: Readonly<{
    effectiveAt: string;
    predecessorSha256: string;
    profile: PublicProfile;
    reason: PublicCorrectionPayloadV1["reason"];
    replacementArtifactSha256: string | null;
    sequence: number;
    signer: PublicArtifactSigner;
    targetArtifactSha256: string;
  }>,
): Promise<Readonly<SignedPublicArtifactV1>> {
  const options = exactOptions(optionsValue, [
    "effectiveAt",
    "predecessorSha256",
    "profile",
    "reason",
    "replacementArtifactSha256",
    "sequence",
    "signer",
    "targetArtifactSha256",
  ]);
  const payload = parseSchema(PublicArtifactPayloadSchema, {
    artifactType: "rsi.public-correction",
    correctionId: randomUUID(),
    effectiveAt: options.effectiveAt,
    predecessorSha256: options.predecessorSha256,
    profile: options.profile,
    reason: options.reason,
    replacementArtifactSha256: options.replacementArtifactSha256,
    sequence: options.sequence,
    targetArtifactSha256: options.targetArtifactSha256,
    version: 1,
  }) as PublicCorrectionPayloadV1;
  return signPayload(payload, options.signer as PublicArtifactSigner);
}

export async function createSignedPublicTombstone(
  optionsValue: Readonly<{
    predecessorSha256: string;
    profile: PublicProfile;
    reason: PublicTombstonePayloadV1["reason"];
    removedAt: string;
    sequence: number;
    signer: PublicArtifactSigner;
    targetArtifactSha256: string;
  }>,
): Promise<Readonly<SignedPublicArtifactV1>> {
  const options = exactOptions(optionsValue, [
    "predecessorSha256",
    "profile",
    "reason",
    "removedAt",
    "sequence",
    "signer",
    "targetArtifactSha256",
  ]);
  const payload = parseSchema(PublicArtifactPayloadSchema, {
    artifactType: "rsi.public-tombstone",
    predecessorSha256: options.predecessorSha256,
    profile: options.profile,
    reason: options.reason,
    removedAt: options.removedAt,
    sequence: options.sequence,
    targetArtifactSha256: options.targetArtifactSha256,
    tombstoneId: randomUUID(),
    version: 1,
  }) as PublicTombstonePayloadV1;
  return signPayload(payload, options.signer as PublicArtifactSigner);
}

export function computePublicArtifactHash(
  envelope: Omit<SignedPublicArtifactV1, "artifactSha256">,
): string {
  return sha256Hex(publicArtifactHashPreimage(envelope));
}

async function signPayload(
  payloadValue: PublicArtifactPayloadV1,
  signerValue: PublicArtifactSigner,
): Promise<Readonly<SignedPublicArtifactV1>> {
  const payload = deepFreeze(parseSchema(PublicArtifactPayloadSchema, payloadValue));
  const signer = parseSigner(signerValue);
  const message = artifactSigningMessage(payload, signer.keyId, signer.fingerprint);
  const signerMessage = Uint8Array.from(message);
  let signature: Uint8Array;
  try {
    signature = copyOrdinaryBytes(await signer.sign(signerMessage));
  } catch {
    throw new PublicProjectionError("SIGNATURE_INVALID");
  } finally {
    signerMessage.fill(0);
  }
  if (signature.byteLength !== 64 || !verifySignature(null, message, signer.publicKey, signature)) {
    signature.fill(0);
    throw new PublicProjectionError("SIGNATURE_INVALID");
  }
  const unsigned = {
    payload,
    schemaVersion: 1 as const,
    signature: base64url(signature),
    signerFingerprintSha256: signer.fingerprint,
    signerKeyId: signer.keyId,
  };
  signature.fill(0);
  return deepFreeze(
    parseSchema(SignedPublicArtifactSchema, {
      ...unsigned,
      artifactSha256: computePublicArtifactHash(unsigned),
    }),
  );
}

function parseSigner(value: PublicArtifactSigner) {
  const record = exactOptions(value, ["keyId", "publicKeySpkiDer", "sign"]);
  if (
    typeof record.keyId !== "string" ||
    !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(record.keyId) ||
    typeof record.sign !== "function" ||
    utilTypes.isProxy(record.sign)
  ) {
    throw new PublicProjectionError("INPUT_INVALID");
  }
  const der = copyOrdinaryBytes(record.publicKeySpkiDer);
  let publicKey;
  const derBuffer = Buffer.from(der);
  try {
    publicKey = createPublicKey({ format: "der", key: derBuffer, type: "spki" });
  } catch {
    throw new PublicProjectionError("INPUT_INVALID");
  } finally {
    der.fill(0);
    derBuffer.fill(0);
  }
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new PublicProjectionError("INPUT_INVALID");
  }
  const canonicalDer = publicKey.export({ format: "der", type: "spki" });
  return Object.freeze({
    fingerprint: sha256Hex(canonicalDer),
    keyId: record.keyId,
    publicKey,
    sign: record.sign as PublicArtifactSigner["sign"],
  });
}

function exactOptions(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    utilTypes.isProxy(value)
  ) {
    throw new PublicProjectionError("INPUT_INVALID");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new PublicProjectionError("INPUT_INVALID");
  }
  const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new PublicProjectionError("INPUT_INVALID");
    }
    record[key] = descriptor.value;
  }
  return record;
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

export function canonicalPublicArtifactJson(value: SignedPublicArtifactV1): string {
  return canonicalJson(parseSchema(SignedPublicArtifactSchema, value));
}
