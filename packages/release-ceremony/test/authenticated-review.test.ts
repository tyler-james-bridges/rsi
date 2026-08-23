import { createHash, generateKeyPairSync, sign as signEd25519, type KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createFoundationAuthenticatedIndependentReview,
  decodeFoundationAuthenticatedIndependentReview,
  encodeFoundationAuthenticatedIndependentReview,
  foundationAuthenticatedIndependentReviewSha256,
  parseFoundationAuthenticatedIndependentReview,
  verifyFoundationAuthenticatedIndependentReview,
  type FoundationAuthenticatedIndependentReviewV1,
} from "../src/authenticated-review.js";
import { canonicalJson } from "../src/canonical.js";
import type { FoundationIndependentReviewEvidenceV1 } from "../src/review-evidence.js";
import type { FoundationIndependentReviewerIdentityV1 } from "../src/reviewer-identity.js";
import { makeReviewEvidence } from "./helpers.js";

function makeReviewer(reviewerId = "rsi-independent-review-agent"): {
  readonly identity: FoundationIndependentReviewerIdentityV1;
  readonly privateKey: KeyObject;
  readonly publicKeySpkiDer: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = publicKey.export({ format: "der", type: "spki" });
  const reviewerFingerprintSha256 = createHash("sha256").update(publicKeySpkiDer).digest("hex");
  return {
    identity: {
      algorithm: "Ed25519",
      identityType: "rsi.foundation-independent-reviewer-identity",
      keyId: `rsi-reviewer-${reviewerFingerprintSha256.slice(0, 16)}`,
      publicKeySpkiDerBase64url: publicKeySpkiDer.toString("base64url"),
      reviewerFingerprintSha256,
      reviewerId,
      reviewerRole: "independent-non-authoring-agent",
      version: 1,
    },
    privateKey,
    publicKeySpkiDer,
  };
}

async function createEnvelope(
  reviewer = makeReviewer(),
  evidence: FoundationIndependentReviewEvidenceV1 = makeReviewEvidence({
    reviewerId: reviewer.identity.reviewerId,
  }),
): Promise<FoundationAuthenticatedIndependentReviewV1> {
  return createFoundationAuthenticatedIndependentReview(evidence, reviewer.identity, {
    keyId: reviewer.identity.keyId,
    publicKeySpkiDer: reviewer.publicKeySpkiDer,
    sign: (message) => Uint8Array.from(signEd25519(null, message, reviewer.privateKey)),
  });
}

describe("foundation authenticated independent review", () => {
  it("creates, canonically decodes, hashes, and verifies an ephemeral-key envelope", async () => {
    const reviewer = makeReviewer();
    const envelope = await createEnvelope(reviewer);
    const bytes = encodeFoundationAuthenticatedIndependentReview(envelope);

    expect(decodeFoundationAuthenticatedIndependentReview(bytes)).toEqual(envelope);
    expect(verifyFoundationAuthenticatedIndependentReview(envelope, reviewer.identity)).toEqual(
      envelope.evidence,
    );
    expect(foundationAuthenticatedIndependentReviewSha256(envelope)).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  it("rejects a wrong key, wrong signature, changed body, or changed identity binding", async () => {
    const reviewer = makeReviewer();
    const other = makeReviewer(reviewer.identity.reviewerId);
    await expect(
      createFoundationAuthenticatedIndependentReview(
        makeReviewEvidence({ reviewerId: reviewer.identity.reviewerId }),
        reviewer.identity,
        {
          keyId: reviewer.identity.keyId,
          publicKeySpkiDer: other.publicKeySpkiDer,
          sign: (message) => Uint8Array.from(signEd25519(null, message, other.privateKey)),
        },
      ),
    ).rejects.toThrow(/not pinned/u);

    const envelope = await createEnvelope(reviewer);
    const badSignature = Buffer.from(envelope.signatureBase64url, "base64url");
    badSignature[0] = badSignature[0]! ^ 1;
    expect(() =>
      verifyFoundationAuthenticatedIndependentReview(
        { ...envelope, signatureBase64url: badSignature.toString("base64url") },
        reviewer.identity,
      ),
    ).toThrow(/signature did not verify/u);
    expect(() =>
      verifyFoundationAuthenticatedIndependentReview(
        {
          ...envelope,
          evidence: { ...envelope.evidence, reviewedAt: "2026-08-23T08:00:01.000Z" },
        },
        reviewer.identity,
      ),
    ).toThrow(/signature did not verify/u);
    expect(() =>
      verifyFoundationAuthenticatedIndependentReview(
        { ...envelope, reviewerIdentitySha256: "a".repeat(64) },
        reviewer.identity,
      ),
    ).toThrow(/does not bind/u);
  });

  it("rejects noncanonical and extra-field envelopes", async () => {
    const envelope = await createEnvelope();
    expect(() =>
      decodeFoundationAuthenticatedIndependentReview(
        Buffer.from(`${canonicalJson(envelope)}\n`, "utf8"),
      ),
    ).toThrow(/canonical/u);
    expect(() =>
      parseFoundationAuthenticatedIndependentReview({ ...envelope, unsupported: true }),
    ).toThrow(/unsupported fields/u);
  });
});
