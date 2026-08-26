import { parseOpenSeaTrendingResponse } from "@rsi/source-contracts/opensea-trending";
import type { NetworkAttemptDispatchReceipt } from "@rsi/operations";

import { OpenSeaCollectorError } from "./errors.js";
import {
  isQuarantinedOpenSeaTrendingResponse,
  type QuarantinedOpenSeaTrendingResponse,
} from "./quarantine.js";
import { copyOpenSeaRateLimitReceipt, type OpenSeaRateLimitReceipt } from "./rate-limit.js";
import type { Sha256 } from "./hash.js";

export type OpenSeaTrendingCollectionResult = Readonly<{
  evidence: ReturnType<typeof parseOpenSeaTrendingResponse>;
  networkAttempt: Readonly<NetworkAttemptDispatchReceipt>;
  requestFingerprint: Sha256;
  responseHash: Sha256;
  rateLimit: OpenSeaRateLimitReceipt | undefined;
}>;

/**
 * Crosses from destroyable raw bytes into the reviewed, immutable source
 * projection. The raw copy is wiped regardless of parse outcome.
 */
export function parseOpenSeaTrendingQuarantine(
  quarantine: QuarantinedOpenSeaTrendingResponse,
): OpenSeaTrendingCollectionResult {
  if (!isQuarantinedOpenSeaTrendingResponse(quarantine)) {
    throw new OpenSeaCollectorError(
      "INVALID_RESPONSE_SCHEMA",
      "An authentic quarantined OpenSea response is required.",
    );
  }
  const bytes = quarantine.copyBytes();
  try {
    let evidence: ReturnType<typeof parseOpenSeaTrendingResponse>;
    try {
      evidence = parseOpenSeaTrendingResponse(bytes, quarantine.metadata.acquiredAt);
    } catch {
      throw new OpenSeaCollectorError(
        "INVALID_RESPONSE_SCHEMA",
        "The quarantined OpenSea response failed the reviewed source contract.",
      );
    }
    return Object.freeze({
      evidence,
      networkAttempt: quarantine.metadata.networkAttempt,
      requestFingerprint: quarantine.metadata.requestFingerprint,
      responseHash: quarantine.metadata.responseHash,
      rateLimit: copyOpenSeaRateLimitReceipt(quarantine.metadata.rateLimit),
    });
  } finally {
    bytes.fill(0);
  }
}
