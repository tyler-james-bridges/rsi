import { createHash, generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import {
  assertFoundationIndependentReviewerSeparation,
  decodeFoundationIndependentReviewerIdentity,
  foundationIndependentReviewerIdentitySha256,
  parseFoundationIndependentReviewerIdentity,
  type FoundationIndependentReviewerIdentityV1,
} from "../src/reviewer-identity.js";

function makeIdentity(): FoundationIndependentReviewerIdentityV1 {
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = publicKey.export({ format: "der", type: "spki" });
  const reviewerFingerprintSha256 = createHash("sha256").update(publicKeySpkiDer).digest("hex");
  return {
    algorithm: "Ed25519",
    identityType: "rsi.foundation-independent-reviewer-identity",
    keyId: `rsi-reviewer-${reviewerFingerprintSha256.slice(0, 16)}`,
    publicKeySpkiDerBase64url: publicKeySpkiDer.toString("base64url"),
    reviewerFingerprintSha256,
    reviewerId: "independent-review-agent-1",
    reviewerRole: "independent-non-authoring-agent",
    version: 1,
  };
}

describe("foundation independent-reviewer identity", () => {
  it("accepts only a canonical Ed25519 identity with fingerprint and key-ID binding", () => {
    const identity = makeIdentity();
    const bytes = Buffer.from(canonicalJson(identity), "utf8");

    expect(decodeFoundationIndependentReviewerIdentity(bytes)).toEqual(identity);
    expect(foundationIndependentReviewerIdentitySha256(identity)).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  it("rejects noncanonical, extra-field, wrong-fingerprint, and wrong-key-ID identities", () => {
    const identity = makeIdentity();
    expect(() =>
      decodeFoundationIndependentReviewerIdentity(
        Buffer.from(`${canonicalJson(identity)}\n`, "utf8"),
      ),
    ).toThrow(/canonical/u);
    expect(() =>
      parseFoundationIndependentReviewerIdentity({ ...identity, unsupported: true }),
    ).toThrow(/unsupported fields/u);
    expect(() =>
      parseFoundationIndependentReviewerIdentity({
        ...identity,
        reviewerFingerprintSha256: "a".repeat(64),
      }),
    ).toThrow(/cryptographic binding/u);
    expect(() =>
      parseFoundationIndependentReviewerIdentity({ ...identity, keyId: "rsi-reviewer-wrong" }),
    ).toThrow(/cryptographic binding/u);
  });

  it("refuses reviewer identity reuse by a release signer or release operator", () => {
    const identity = makeIdentity();
    const empty = {
      operatorIds: [],
      releaseSignerFingerprintsSha256: [],
      releaseSignerKeyIds: [],
      releaseSignerPublicKeysSpkiDerBase64url: [],
    };
    expect(() => assertFoundationIndependentReviewerSeparation(identity, empty)).not.toThrow();
    expect(() =>
      assertFoundationIndependentReviewerSeparation(identity, {
        ...empty,
        operatorIds: [identity.reviewerId],
      }),
    ).toThrow(/not independent/u);
    expect(() =>
      assertFoundationIndependentReviewerSeparation(identity, {
        ...empty,
        releaseSignerFingerprintsSha256: [identity.reviewerFingerprintSha256],
      }),
    ).toThrow(/not independent/u);
    expect(() =>
      assertFoundationIndependentReviewerSeparation(identity, {
        ...empty,
        releaseSignerKeyIds: [identity.keyId],
      }),
    ).toThrow(/not independent/u);
    expect(() =>
      assertFoundationIndependentReviewerSeparation(identity, {
        ...empty,
        releaseSignerPublicKeysSpkiDerBase64url: [identity.publicKeySpkiDerBase64url],
      }),
    ).toThrow(/not independent/u);
  });
});
