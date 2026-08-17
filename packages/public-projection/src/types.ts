export type PublicProfile = "canary" | "production-observer";

export interface PublicReceiptCandidateV1 {
  readonly candidateType: "rsi.public-receipt-candidate";
  readonly version: 1;
  readonly candidateId: string;
  readonly profile: PublicProfile;
  readonly acceptedAt: string;
  readonly createdAt: string;
  readonly eligibleAt: string;
  readonly releaseManifestSha256: string;
  readonly counts: Readonly<{
    requestCount: number;
    laneCount: number;
    findingCount: number;
    abstentionCount: number;
  }>;
  readonly costs: Readonly<{
    currency: "USD_MICRO";
    reservedAtomic: string;
    reconciledAtomic: string;
  }>;
  readonly status: Readonly<{
    alert: "healthy";
    anchor: "verified";
    backup: "verified";
    deletion: "verified";
    digest: "verified";
    eventIntegrity: "verified";
  }>;
  readonly qualification: Readonly<{
    acceptedSessions: number;
    requiredSessions: 10;
  }>;
}

export interface PublicReceiptPayloadV1 extends PublicReceiptCandidateV1 {
  readonly artifactType: "rsi.public-receipt";
  readonly receiptId: string;
  readonly reviewedAt: string;
  readonly publishedAt: string;
  readonly sequence: number;
  readonly predecessorSha256: string | null;
}

export interface PublicCorrectionPayloadV1 {
  readonly artifactType: "rsi.public-correction";
  readonly version: 1;
  readonly correctionId: string;
  readonly effectiveAt: string;
  readonly predecessorSha256: string;
  readonly profile: PublicProfile;
  readonly reason: "integrity" | "legal" | "provider-terms" | "privacy";
  readonly replacementArtifactSha256: string | null;
  readonly sequence: number;
  readonly targetArtifactSha256: string;
}

export interface PublicTombstonePayloadV1 {
  readonly artifactType: "rsi.public-tombstone";
  readonly version: 1;
  readonly predecessorSha256: string;
  readonly profile: PublicProfile;
  readonly reason: "integrity" | "legal" | "provider-terms" | "privacy";
  readonly removedAt: string;
  readonly sequence: number;
  readonly targetArtifactSha256: string;
  readonly tombstoneId: string;
}

export type PublicArtifactPayloadV1 =
  PublicReceiptPayloadV1 | PublicCorrectionPayloadV1 | PublicTombstonePayloadV1;

export interface SignedPublicArtifactV1 {
  readonly schemaVersion: 1;
  readonly artifactSha256: string;
  readonly payload: Readonly<PublicArtifactPayloadV1>;
  readonly signature: string;
  readonly signerFingerprintSha256: string;
  readonly signerKeyId: string;
}

export interface PublicArtifactSigner {
  readonly keyId: string;
  readonly publicKeySpkiDer: Uint8Array;
  readonly sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface PublicArtifactHeadV1 {
  readonly artifactSha256: string;
  readonly sequence: number;
}

export interface PublicVerificationCrypto {
  digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer>;
  importEd25519PublicKey(spkiDer: Uint8Array): Promise<unknown>;
  verifyEd25519(key: unknown, signature: Uint8Array, message: Uint8Array): Promise<boolean>;
}

export interface PublicArtifactVerificationReportV1 {
  readonly schemaVersion: 1;
  readonly status: "UNVERIFIED" | "VERIFIED";
  readonly artifactCount: number;
  readonly head: Readonly<PublicArtifactHeadV1> | null;
  readonly latestReceipt: Readonly<PublicReceiptPayloadV1> | null;
}
