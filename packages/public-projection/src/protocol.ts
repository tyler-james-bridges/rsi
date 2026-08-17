import { canonicalBytes, concatBytes } from "./portable.js";
import type { PublicArtifactPayloadV1, SignedPublicArtifactV1 } from "./types.js";

const SIGNATURE_DOMAIN = new TextEncoder().encode("rsi-public-artifact-v1\0");

export function artifactSigningMessage(
  payload: PublicArtifactPayloadV1,
  signerKeyId: string,
  signerFingerprintSha256: string,
): Uint8Array {
  return concatBytes(
    SIGNATURE_DOMAIN,
    canonicalBytes({ payload, signerFingerprintSha256, signerKeyId }),
  );
}

export function publicArtifactHashPreimage(
  envelope: Omit<SignedPublicArtifactV1, "artifactSha256">,
): Uint8Array {
  return canonicalBytes(envelope);
}
