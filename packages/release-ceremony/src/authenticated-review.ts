import {
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { types as utilTypes } from "node:util";

import {
  canonicalJson,
  exactObject,
  sha256,
  validateHash,
  validateIdentifier,
} from "./canonical.js";
import { fail } from "./errors.js";
import {
  parseFoundationIndependentReviewEvidence,
  type FoundationIndependentReviewEvidenceV1,
} from "./review-evidence.js";
import {
  foundationIndependentReviewerIdentitySha256,
  foundationIndependentReviewerPublicKeySpkiDer,
  parseFoundationIndependentReviewerIdentity,
  type FoundationIndependentReviewerIdentityV1,
} from "./reviewer-identity.js";

export const FOUNDATION_AUTHENTICATED_REVIEW_TYPE =
  "rsi.foundation-authenticated-independent-review" as const;
export const FOUNDATION_AUTHENTICATED_REVIEW_VERSION = 1 as const;
export const FOUNDATION_AUTHENTICATED_REVIEW_SIGNATURE_DOMAIN =
  "rsi.foundation-authenticated-independent-review.v1\0" as const;

const MAX_AUTHENTICATED_REVIEW_BYTES = 64 * 1024;
const ED25519_SIGNATURE_BYTES = 64;

export interface FoundationAuthenticatedIndependentReviewV1 {
  readonly envelopeType: typeof FOUNDATION_AUTHENTICATED_REVIEW_TYPE;
  readonly evidence: FoundationIndependentReviewEvidenceV1;
  readonly reviewerFingerprintSha256: string;
  readonly reviewerId: string;
  readonly reviewerIdentitySha256: string;
  readonly reviewerKeyId: string;
  readonly signatureAlgorithm: "Ed25519";
  readonly signatureBase64url: string;
  readonly version: typeof FOUNDATION_AUTHENTICATED_REVIEW_VERSION;
}

export interface FoundationIndependentReviewSignerV1 {
  readonly keyId: string;
  /** Canonical DER-encoded Ed25519 SubjectPublicKeyInfo. */
  readonly publicKeySpkiDer: Uint8Array;
  /** Receives one copy of the complete domain-separated canonical unsigned envelope. */
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

interface FoundationUnsignedAuthenticatedIndependentReviewV1 {
  readonly envelopeType: typeof FOUNDATION_AUTHENTICATED_REVIEW_TYPE;
  readonly evidence: FoundationIndependentReviewEvidenceV1;
  readonly reviewerFingerprintSha256: string;
  readonly reviewerId: string;
  readonly reviewerIdentitySha256: string;
  readonly reviewerKeyId: string;
  readonly signatureAlgorithm: "Ed25519";
  readonly version: typeof FOUNDATION_AUTHENTICATED_REVIEW_VERSION;
}

export async function createFoundationAuthenticatedIndependentReview(
  evidenceValue: FoundationIndependentReviewEvidenceV1,
  identityValue: FoundationIndependentReviewerIdentityV1,
  signerValue: FoundationIndependentReviewSignerV1,
): Promise<FoundationAuthenticatedIndependentReviewV1> {
  const evidence = parseFoundationIndependentReviewEvidence(evidenceValue);
  const identity = parseFoundationIndependentReviewerIdentity(identityValue);
  assertEvidenceIdentityBinding(evidence, identity);
  const signer = exactObject(
    signerValue,
    ["keyId", "publicKeySpkiDer", "sign"],
    "Foundation independent-review signer",
  );
  if (
    validateIdentifier(signer.keyId, "Foundation independent-review signer key ID") !==
      identity.keyId ||
    typeof signer.sign !== "function"
  ) {
    fail("INPUT_INVALID", "Foundation independent-review signer does not match its identity");
  }
  const signerPublicKey = importEd25519PublicKey(
    signer.publicKeySpkiDer,
    "Foundation independent-review signer public key",
  );
  const identityPublicKey = Buffer.from(foundationIndependentReviewerPublicKeySpkiDer(identity));
  if (!equalBytes(signerPublicKey.spkiDer, identityPublicKey)) {
    signerPublicKey.spkiDer.fill(0);
    identityPublicKey.fill(0);
    fail("INPUT_INVALID", "Foundation independent-review signer public key is not pinned");
  }
  const unsigned = createUnsignedEnvelope(evidence, identity);
  const message = encodeSignatureMessage(unsigned);
  let signature: Buffer | undefined;
  try {
    let returned: Uint8Array;
    try {
      returned = await (signer.sign as (message: Uint8Array) => Promise<Uint8Array> | Uint8Array)(
        Uint8Array.from(message),
      );
    } catch {
      fail("VERIFICATION_FAILED", "Foundation independent-review signer failed");
    }
    signature = copySignature(returned);
    if (!verifyEd25519(null, message, signerPublicKey.key, signature)) {
      fail("VERIFICATION_FAILED", "Foundation independent-review signer returned a bad signature");
    }
    return Object.freeze({
      ...unsigned,
      signatureBase64url: signature.toString("base64url"),
    });
  } finally {
    identityPublicKey.fill(0);
    message.fill(0);
    signature?.fill(0);
    signerPublicKey.spkiDer.fill(0);
  }
}

export function parseFoundationAuthenticatedIndependentReview(
  value: unknown,
): FoundationAuthenticatedIndependentReviewV1 {
  const record = exactObject(
    value,
    [
      "envelopeType",
      "evidence",
      "reviewerFingerprintSha256",
      "reviewerId",
      "reviewerIdentitySha256",
      "reviewerKeyId",
      "signatureAlgorithm",
      "signatureBase64url",
      "version",
    ],
    "Foundation authenticated independent-review envelope",
  );
  if (
    record.envelopeType !== FOUNDATION_AUTHENTICATED_REVIEW_TYPE ||
    record.signatureAlgorithm !== "Ed25519" ||
    record.version !== FOUNDATION_AUTHENTICATED_REVIEW_VERSION
  ) {
    fail("VERIFICATION_FAILED", "Foundation authenticated independent-review policy is invalid");
  }
  const signature = decodeCanonicalBase64url(
    record.signatureBase64url,
    ED25519_SIGNATURE_BYTES,
    "Foundation independent-review signature",
  );
  try {
    return Object.freeze({
      envelopeType: FOUNDATION_AUTHENTICATED_REVIEW_TYPE,
      evidence: parseFoundationIndependentReviewEvidence(record.evidence),
      reviewerFingerprintSha256: validateHash(
        record.reviewerFingerprintSha256,
        "Foundation independent-review fingerprint",
      ),
      reviewerId: validateIdentifier(record.reviewerId, "Foundation independent reviewer ID"),
      reviewerIdentitySha256: validateHash(
        record.reviewerIdentitySha256,
        "Foundation independent-reviewer identity hash",
      ),
      reviewerKeyId: validateIdentifier(
        record.reviewerKeyId,
        "Foundation independent-review key ID",
      ),
      signatureAlgorithm: "Ed25519",
      signatureBase64url: signature.toString("base64url"),
      version: FOUNDATION_AUTHENTICATED_REVIEW_VERSION,
    });
  } finally {
    signature.fill(0);
  }
}

export function decodeFoundationAuthenticatedIndependentReview(
  value: Uint8Array,
): FoundationAuthenticatedIndependentReviewV1 {
  if (
    !(value instanceof Uint8Array) ||
    utilTypes.isProxy(value) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_AUTHENTICATED_REVIEW_BYTES
  ) {
    fail("INPUT_INVALID", "Foundation authenticated independent-review bytes are invalid");
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail("INPUT_INVALID", "Foundation authenticated independent-review is not valid JSON");
  }
  const envelope = parseFoundationAuthenticatedIndependentReview(parsed);
  if (canonicalJson(envelope) !== text) {
    fail("INPUT_INVALID", "Foundation authenticated independent-review is not canonical JSON");
  }
  return envelope;
}

export function verifyFoundationAuthenticatedIndependentReview(
  envelopeValue: FoundationAuthenticatedIndependentReviewV1,
  identityValue: FoundationIndependentReviewerIdentityV1,
): FoundationIndependentReviewEvidenceV1 {
  const envelope = parseFoundationAuthenticatedIndependentReview(envelopeValue);
  const identity = parseFoundationIndependentReviewerIdentity(identityValue);
  assertEvidenceIdentityBinding(envelope.evidence, identity);
  if (
    envelope.reviewerId !== identity.reviewerId ||
    envelope.reviewerKeyId !== identity.keyId ||
    envelope.reviewerFingerprintSha256 !== identity.reviewerFingerprintSha256 ||
    envelope.reviewerIdentitySha256 !== foundationIndependentReviewerIdentitySha256(identity)
  ) {
    fail(
      "VERIFICATION_FAILED",
      "Foundation independent-review envelope does not bind the pinned reviewer identity",
    );
  }
  const publicKeyBytes = Buffer.from(foundationIndependentReviewerPublicKeySpkiDer(identity));
  const publicKey = importEd25519PublicKey(
    publicKeyBytes,
    "Foundation independent-reviewer public key",
  );
  const signature = decodeCanonicalBase64url(
    envelope.signatureBase64url,
    ED25519_SIGNATURE_BYTES,
    "Foundation independent-review signature",
  );
  const message = encodeSignatureMessage(envelope);
  try {
    if (!verifyEd25519(null, message, publicKey.key, signature)) {
      fail("VERIFICATION_FAILED", "Foundation independent-review signature did not verify");
    }
    return envelope.evidence;
  } finally {
    publicKeyBytes.fill(0);
    publicKey.spkiDer.fill(0);
    signature.fill(0);
    message.fill(0);
  }
}

export function encodeFoundationAuthenticatedIndependentReview(
  value: FoundationAuthenticatedIndependentReviewV1,
): Uint8Array {
  return new TextEncoder().encode(
    canonicalJson(parseFoundationAuthenticatedIndependentReview(value)),
  );
}

export function foundationAuthenticatedIndependentReviewSha256(
  value: FoundationAuthenticatedIndependentReviewV1,
): string {
  return sha256(canonicalJson(parseFoundationAuthenticatedIndependentReview(value)));
}

export function foundationAuthenticatedIndependentReviewSignatureMessage(
  evidenceValue: FoundationIndependentReviewEvidenceV1,
  identityValue: FoundationIndependentReviewerIdentityV1,
): Uint8Array {
  const evidence = parseFoundationIndependentReviewEvidence(evidenceValue);
  const identity = parseFoundationIndependentReviewerIdentity(identityValue);
  assertEvidenceIdentityBinding(evidence, identity);
  return Uint8Array.from(encodeSignatureMessage(createUnsignedEnvelope(evidence, identity)));
}

function createUnsignedEnvelope(
  evidence: FoundationIndependentReviewEvidenceV1,
  identity: FoundationIndependentReviewerIdentityV1,
): FoundationUnsignedAuthenticatedIndependentReviewV1 {
  return Object.freeze({
    envelopeType: FOUNDATION_AUTHENTICATED_REVIEW_TYPE,
    evidence,
    reviewerFingerprintSha256: identity.reviewerFingerprintSha256,
    reviewerId: identity.reviewerId,
    reviewerIdentitySha256: foundationIndependentReviewerIdentitySha256(identity),
    reviewerKeyId: identity.keyId,
    signatureAlgorithm: "Ed25519",
    version: FOUNDATION_AUTHENTICATED_REVIEW_VERSION,
  });
}

function encodeSignatureMessage(
  envelope:
    FoundationAuthenticatedIndependentReviewV1 | FoundationUnsignedAuthenticatedIndependentReviewV1,
): Buffer {
  const unsigned = Object.freeze({
    envelopeType: envelope.envelopeType,
    evidence: envelope.evidence,
    reviewerFingerprintSha256: envelope.reviewerFingerprintSha256,
    reviewerId: envelope.reviewerId,
    reviewerIdentitySha256: envelope.reviewerIdentitySha256,
    reviewerKeyId: envelope.reviewerKeyId,
    signatureAlgorithm: envelope.signatureAlgorithm,
    version: envelope.version,
  });
  return Buffer.concat([
    Buffer.from(FOUNDATION_AUTHENTICATED_REVIEW_SIGNATURE_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(unsigned), "utf8"),
  ]);
}

function assertEvidenceIdentityBinding(
  evidence: FoundationIndependentReviewEvidenceV1,
  identity: FoundationIndependentReviewerIdentityV1,
): void {
  if (
    evidence.reviewerId !== identity.reviewerId ||
    evidence.reviewerRole !== identity.reviewerRole
  ) {
    fail(
      "VERIFICATION_FAILED",
      "Foundation independent-review body does not bind the pinned reviewer identity",
    );
  }
}

function importEd25519PublicKey(
  value: unknown,
  label: string,
): {
  readonly key: KeyObject;
  readonly spkiDer: Buffer;
} {
  if (!(value instanceof Uint8Array) || utilTypes.isProxy(value) || value.byteLength > 512) {
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  const spkiDer = Buffer.from(value);
  let key: KeyObject;
  try {
    key = createPublicKey({ format: "der", key: spkiDer, type: "spki" });
  } catch {
    spkiDer.fill(0);
    fail("INPUT_INVALID", `${label} is invalid`);
  }
  const canonical = key.export({ format: "der", type: "spki" });
  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ed25519" ||
    !equalBytes(spkiDer, canonical)
  ) {
    spkiDer.fill(0);
    canonical.fill(0);
    fail("INPUT_INVALID", `${label} is not canonical Ed25519`);
  }
  spkiDer.fill(0);
  return Object.freeze({ key, spkiDer: canonical });
}

function copySignature(value: unknown): Buffer {
  if (!(value instanceof Uint8Array) || utilTypes.isProxy(value) || value.byteLength !== 64) {
    fail("VERIFICATION_FAILED", "Foundation independent-review signature is invalid");
  }
  return Buffer.from(value);
}

function decodeCanonicalBase64url(value: unknown, size: number, label: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    fail("INPUT_INVALID", `${label} encoding is invalid`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== size || bytes.toString("base64url") !== value) {
    bytes.fill(0);
    fail("INPUT_INVALID", `${label} encoding is invalid`);
  }
  return bytes;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}
