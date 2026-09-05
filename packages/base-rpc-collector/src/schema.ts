import { parseBaseRpcFinalizedAnchor } from "@rsi/source-contracts/base-rpc-anchor";
import type { NetworkAttemptDispatchReceipt } from "@rsi/operations";

import { BaseRpcCollectorError } from "./errors.js";
import type { Sha256 } from "./hash.js";
import {
  isQuarantinedBaseRpcAnchorResponse,
  type QuarantinedBaseRpcAnchorResponse,
} from "./quarantine.js";

export type BaseRpcAnchorResult = Readonly<{
  anchor: ReturnType<typeof parseBaseRpcFinalizedAnchor>;
  networkAttempt: Readonly<NetworkAttemptDispatchReceipt>;
  requestFingerprint: Sha256;
  responseHash: Sha256;
}>;

/**
 * Crosses from destroyable raw bytes into the reviewed, immutable source
 * projection. The raw working copy is wiped regardless of parse outcome.
 */
export function parseBaseRpcAnchorQuarantine(
  quarantine: QuarantinedBaseRpcAnchorResponse,
): BaseRpcAnchorResult {
  if (!isQuarantinedBaseRpcAnchorResponse(quarantine)) {
    throw new BaseRpcCollectorError(
      "INVALID_RESPONSE_SCHEMA",
      "An authentic quarantined Base RPC response is required.",
    );
  }
  const bytes = quarantine.copyBytes();
  try {
    let anchor: ReturnType<typeof parseBaseRpcFinalizedAnchor>;
    try {
      anchor = parseBaseRpcFinalizedAnchor(bytes, quarantine.metadata.acquiredAt);
    } catch {
      throw new BaseRpcCollectorError(
        "INVALID_RESPONSE_SCHEMA",
        "The quarantined Base RPC response failed the reviewed source contract.",
      );
    }
    return Object.freeze({
      anchor,
      networkAttempt: quarantine.metadata.networkAttempt,
      requestFingerprint: quarantine.metadata.requestFingerprint,
      responseHash: quarantine.metadata.responseHash,
    });
  } finally {
    bytes.fill(0);
  }
}
