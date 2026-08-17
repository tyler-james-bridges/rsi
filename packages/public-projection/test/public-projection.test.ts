import { createHash, generateKeyPairSync, sign as nodeSign, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  PublicProjectionError,
  artifactSigningMessage,
  computePublicArtifactHash,
  createSignedPublicCorrection,
  createSignedPublicReceipt,
  createSignedPublicTombstone,
  preparePublicReceiptCandidate,
  verifyPublicArtifactChain,
  webCryptoAdapter,
  type PublicArtifactPayloadV1,
  type PublicArtifactSigner,
  type PublicReceiptCandidateV1,
  type SignedPublicArtifactV1,
} from "../src/index.js";

const HASH_A = "a".repeat(64);

describe("public receipt preparation and signing", () => {
  it("requires the 24-hour review delay and explicit approval", async () => {
    const signer = makeSigner();
    const candidate = makeCandidate();
    const prepared = preparePublicReceiptCandidate(candidate);
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.counts)).toBe(true);

    await expect(
      createSignedPublicReceipt({
        candidate,
        predecessorSha256: null,
        publishApproved: true,
        publishedAt: "2026-08-02T11:59:59.999Z",
        reviewedAt: "2026-08-02T11:59:59.999Z",
        sequence: 1,
        signer,
      }),
    ).rejects.toMatchObject({ code: "DELAY_NOT_MET" });

    await expect(
      createSignedPublicReceipt({
        candidate,
        predecessorSha256: null,
        publishApproved: false,
        publishedAt: "2026-08-02T12:00:00.000Z",
        reviewedAt: "2026-08-02T12:00:00.000Z",
        sequence: 1,
        signer,
      } as never),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });

    const receipt = await createReceipt(candidate, signer, null, 1, "2026-08-02T12:00:00.000Z");
    expect(receipt.payload.artifactType).toBe("rsi.public-receipt");
    expect(receipt.payload.sequence).toBe(1);
    expect(Object.isFrozen(receipt)).toBe(true);
  });

  it("rejects extra, sensitive-shaped, hostile, and non-plain inputs", async () => {
    const candidate = makeCandidate();
    expect(() => preparePublicReceiptCandidate({ ...candidate, asset: "nft" })).toThrowError(
      PublicProjectionError,
    );
    expect(() =>
      preparePublicReceiptCandidate({ ...candidate, url: "https://example.invalid" }),
    ).toThrowError(PublicProjectionError);
    expect(() => preparePublicReceiptCandidate(new Proxy(candidate, {}))).toThrowError(
      PublicProjectionError,
    );

    let getterCalled = false;
    const accessor = { ...candidate } as Record<string, unknown>;
    Object.defineProperty(accessor, "createdAt", {
      enumerable: true,
      get() {
        getterCalled = true;
        return candidate.createdAt;
      },
    });
    expect(() => preparePublicReceiptCandidate(accessor)).toThrowError(PublicProjectionError);
    expect(getterCalled).toBe(false);

    const signer = makeSigner();
    await expect(
      createReceipt(
        candidate,
        { ...signer, privateKey: new Uint8Array(32) } as never,
        null,
        1,
        "2026-08-02T12:00:00.000Z",
      ),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    await expect(
      createReceipt(
        candidate,
        { ...signer, publicKeySpkiDer: Buffer.from(signer.publicKeySpkiDer) } as never,
        null,
        1,
        "2026-08-02T12:00:00.000Z",
      ),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });
});

describe("browser verification", () => {
  it("verifies a pinned receipt/correction/tombstone chain and applies visibility", async () => {
    const signer = makeSigner();
    const receiptOne = await createReceipt(
      makeCandidate(),
      signer,
      null,
      1,
      "2026-08-02T12:00:00.000Z",
    );
    const receiptTwo = await createReceipt(
      makeCandidate({
        acceptedAt: "2026-08-02T12:00:00.000Z",
        candidateId: "22222222-2222-4222-8222-222222222222",
        createdAt: "2026-08-02T12:00:00.000Z",
        eligibleAt: "2026-08-03T12:00:00.000Z",
      }),
      signer,
      receiptOne.artifactSha256,
      2,
      "2026-08-03T12:00:00.000Z",
    );
    const correction = await createSignedPublicCorrection({
      effectiveAt: "2026-08-04T12:00:00.000Z",
      predecessorSha256: receiptTwo.artifactSha256,
      profile: "canary",
      reason: "integrity",
      replacementArtifactSha256: receiptTwo.artifactSha256,
      sequence: 3,
      signer,
      targetArtifactSha256: receiptOne.artifactSha256,
    });
    const verified = await verify([receiptOne, receiptTwo, correction], signer, {
      artifactSha256: receiptOne.artifactSha256,
      sequence: 1,
    });
    expect(verified).toMatchObject({
      artifactCount: 3,
      head: { artifactSha256: correction.artifactSha256, sequence: 3 },
      schemaVersion: 1,
      status: "VERIFIED",
    });
    if (receiptTwo.payload.artifactType !== "rsi.public-receipt") throw new Error("fixture");
    expect(verified.latestReceipt?.receiptId).toBe(receiptTwo.payload.receiptId);

    const tombstone = await createSignedPublicTombstone({
      predecessorSha256: correction.artifactSha256,
      profile: "canary",
      reason: "privacy",
      removedAt: "2026-08-05T12:00:00.000Z",
      sequence: 4,
      signer,
      targetArtifactSha256: receiptTwo.artifactSha256,
    });
    const removed = await verify([receiptOne, receiptTwo, correction, tombstone], signer);
    expect(removed.status).toBe("VERIFIED");
    expect(removed.latestReceipt).toBeNull();
  });

  it("returns exactly the closed UNVERIFIED report for every mismatch", async () => {
    const signer = makeSigner();
    const receipt = await createReceipt(
      makeCandidate(),
      signer,
      null,
      1,
      "2026-08-02T12:00:00.000Z",
    );
    const expected = {
      artifactCount: 0,
      head: null,
      latestReceipt: null,
      schemaVersion: 1,
      status: "UNVERIFIED",
    };
    const tampered = clone(receipt);
    if (tampered.payload.artifactType !== "rsi.public-receipt") throw new Error("fixture");
    (tampered.payload.counts as { requestCount: number }).requestCount += 1;
    expect(await verify([tampered], signer)).toEqual(expected);
    expect(
      await verify([receipt], signer, { artifactSha256: "b".repeat(64), sequence: 1 }),
    ).toEqual(expected);
    const otherSigner = makeSigner("public-key-2");
    expect(await verify([receipt], otherSigner)).toEqual(expected);
    expect(
      await verifyPublicArtifactChain({
        artifacts: [receipt],
        crypto: browserCrypto(),
        expectedKeyId: signer.keyId,
        publicKeySpkiDer: Buffer.from(signer.publicKeySpkiDer) as never,
      }),
    ).toEqual(expected);
  });

  it("rejects a valid signature over semantically invalid timing and mixed profiles", async () => {
    const signer = makeSigner();
    const receipt = await createReceipt(
      makeCandidate(),
      signer,
      null,
      1,
      "2026-08-02T12:00:00.000Z",
    );
    if (receipt.payload.artifactType !== "rsi.public-receipt") throw new Error("fixture");
    const invalidPayload = {
      ...receipt.payload,
      reviewedAt: "2026-08-01T12:00:00.000Z",
    } satisfies PublicArtifactPayloadV1;
    const resigned = signRaw(invalidPayload, signer);
    expect((await verify([resigned], signer)).status).toBe("UNVERIFIED");

    const receiptTwo = await createReceipt(
      makeCandidate({
        acceptedAt: "2026-08-02T12:00:00.000Z",
        candidateId: "33333333-3333-4333-8333-333333333333",
        createdAt: "2026-08-02T12:00:00.000Z",
        eligibleAt: "2026-08-03T12:00:00.000Z",
        profile: "production-observer",
      }),
      signer,
      receipt.artifactSha256,
      2,
      "2026-08-03T12:00:00.000Z",
    );
    expect((await verify([receipt, receiptTwo], signer)).status).toBe("UNVERIFIED");
  });

  it("keeps the browser verification dependency path free of Node-only imports", () => {
    for (const name of ["browser-verifier.ts", "portable.ts", "protocol.ts", "schemas.ts"]) {
      const source = readFileSync(
        fileURLToPath(new URL(`../src/${name}`, import.meta.url)),
        "utf8",
      );
      expect(source).not.toContain('from "node:');
      expect(source).not.toMatch(/\bBuffer\b/);
    }
  });
});

function makeCandidate(
  overrides: Partial<PublicReceiptCandidateV1> = {},
): PublicReceiptCandidateV1 {
  return {
    candidateType: "rsi.public-receipt-candidate",
    version: 1,
    candidateId: "11111111-1111-4111-8111-111111111111",
    profile: "canary",
    acceptedAt: "2026-08-01T12:00:00.000Z",
    createdAt: "2026-08-01T12:00:00.000Z",
    eligibleAt: "2026-08-02T12:00:00.000Z",
    releaseManifestSha256: HASH_A,
    counts: {
      requestCount: 15,
      laneCount: 7,
      findingCount: 4,
      abstentionCount: 2,
    },
    costs: {
      currency: "USD_MICRO",
      reservedAtomic: "2250000",
      reconciledAtomic: "2100000",
    },
    status: {
      alert: "healthy",
      anchor: "verified",
      backup: "verified",
      deletion: "verified",
      digest: "verified",
      eventIntegrity: "verified",
    },
    qualification: {
      acceptedSessions: 1,
      requiredSessions: 10,
    },
    ...overrides,
  };
}

function makeSigner(keyId = "public-key-1"): PublicArtifactSigner {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = Uint8Array.from(publicKey.export({ format: "der", type: "spki" }));
  return Object.freeze({
    keyId,
    publicKeySpkiDer,
    sign(message: Uint8Array) {
      return Uint8Array.from(nodeSign(null, message, privateKey));
    },
  });
}

async function createReceipt(
  candidate: PublicReceiptCandidateV1,
  signer: PublicArtifactSigner,
  predecessorSha256: string | null,
  sequence: number,
  at: string,
): Promise<Readonly<SignedPublicArtifactV1>> {
  return createSignedPublicReceipt({
    candidate,
    predecessorSha256,
    publishApproved: true,
    publishedAt: at,
    reviewedAt: at,
    sequence,
    signer,
  });
}

function browserCrypto() {
  return webCryptoAdapter(webcrypto.subtle as never);
}

async function verify(
  artifacts: readonly unknown[],
  signer: PublicArtifactSigner,
  expectedHead?: Readonly<{ artifactSha256: string; sequence: number }>,
) {
  return verifyPublicArtifactChain({
    artifacts,
    crypto: browserCrypto(),
    ...(expectedHead === undefined ? {} : { expectedHead }),
    expectedKeyId: signer.keyId,
    publicKeySpkiDer: signer.publicKeySpkiDer,
  });
}

function signRaw(
  payload: PublicArtifactPayloadV1,
  signer: PublicArtifactSigner,
): SignedPublicArtifactV1 {
  const fingerprint = createHash("sha256").update(signer.publicKeySpkiDer).digest("hex");
  const signature = signer.sign(
    artifactSigningMessage(payload, signer.keyId, fingerprint),
  ) as Uint8Array;
  const unsigned = {
    schemaVersion: 1 as const,
    payload,
    signature: Buffer.from(signature).toString("base64url"),
    signerFingerprintSha256: fingerprint,
    signerKeyId: signer.keyId,
  };
  return {
    ...unsigned,
    artifactSha256: computePublicArtifactHash(unsigned),
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
