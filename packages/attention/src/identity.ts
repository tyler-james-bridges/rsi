import { hashCanonical } from "./hash.js";
import { toJsonValue } from "./json-types.js";
import {
  BASE_CHAIN_ID,
  BaseCollectionIdentitySchema,
  CandidateIdSchema,
  CollectionIdSchema,
  HARD_REASONS,
  type BaseCollectionIdentityV1,
  type CandidateId,
  type HardReason,
  type SanitizedRecordedBundleV1,
} from "./schemas.js";

const ZERO_ADDRESS = `0x${"0".repeat(40)}`;

export type SanitizedCandidate = SanitizedRecordedBundleV1["marketplace"]["candidates"][number];

export type CandidateIdentityResult =
  | Readonly<{
      candidateId: CandidateId;
      identity: BaseCollectionIdentityV1;
      reasons: readonly HardReason[];
    }>
  | Readonly<{
      candidateId: CandidateId;
      identity: null;
      reasons: readonly HardReason[];
    }>;

export function deriveCandidateIdentity(candidate: SanitizedCandidate): CandidateIdentityResult {
  const candidateId = CandidateIdSchema.parse(
    hashCanonical(
      "rsi-attention-candidate-v1\0",
      toJsonValue({ slug: candidate.slug, contracts: candidate.contracts }),
    ),
  );
  const reasons: HardReason[] = [];
  if (candidate.contracts.some((contract) => contract.chainId !== BASE_CHAIN_ID)) {
    reasons.push("UNSUPPORTED_CHAIN");
  }
  if (candidate.contracts.some((contract) => contract.address === ZERO_ADDRESS)) {
    reasons.push("ZERO_CONTRACT");
  }
  const addresses = candidate.contracts.map(
    (contract) => `${contract.chainId}:${contract.address}`,
  );
  if (new Set(addresses).size !== addresses.length) reasons.push("DUPLICATE_CONTRACT");

  const orderedReasons = orderReasons(reasons);
  if (orderedReasons.length > 0) {
    return Object.freeze({ candidateId, identity: null, reasons: Object.freeze(orderedReasons) });
  }

  const contracts = candidate.contracts.map((contract) => contract.address);
  const collectionId = CollectionIdSchema.parse(
    hashCanonical(
      "rsi-attention-base-collection-v1\0",
      toJsonValue({ chainId: BASE_CHAIN_ID, contracts }),
    ),
  );
  return Object.freeze({
    candidateId,
    identity: BaseCollectionIdentitySchema.parse({
      kind: "base_collection",
      chainId: BASE_CHAIN_ID,
      collectionId,
      contracts,
    }),
    reasons: Object.freeze([]),
  });
}

export function contractsOverlap(
  left: BaseCollectionIdentityV1,
  right: BaseCollectionIdentityV1,
): boolean {
  const addresses = new Set(left.contracts);
  return right.contracts.some((address) => addresses.has(address));
}

function orderReasons(reasons: readonly HardReason[]): HardReason[] {
  const unique = new Set(reasons);
  return HARD_REASONS.filter((reason) => unique.has(reason));
}
