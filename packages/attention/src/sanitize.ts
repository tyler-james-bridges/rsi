import { compareStrings, toJsonValue } from "./json-types.js";
import { hashCanonical } from "./hash.js";
import {
  BundleIdSchema,
  RefreshIdSchema,
  SanitizedRecordedBundleSchema,
  AttentionInputError,
  assertPlainAttentionData,
  deepFreeze,
  parseRecordedAttentionBundle,
  type BundleId,
  type RecordedAttentionBundleV1,
  type SanitizedRecordedBundleV1,
} from "./schemas.js";
import { sanitizeSocialPost } from "./social.js";

export function sanitizeRecordedAttentionBundle(input: unknown): SanitizedRecordedBundleV1 {
  const parsed = parseRecordedAttentionBundle(input);
  return sanitizeValidatedRecordedAttentionBundle(parsed);
}

export function sanitizeParsedRecordedAttentionBundle(
  bundle: RecordedAttentionBundleV1,
): SanitizedRecordedBundleV1 {
  return sanitizeValidatedRecordedAttentionBundle(parseRecordedAttentionBundle(bundle));
}

function sanitizeValidatedRecordedAttentionBundle(
  bundle: RecordedAttentionBundleV1,
): SanitizedRecordedBundleV1 {
  const x =
    bundle.x.kind === "absent"
      ? { kind: "absent" as const }
      : {
          kind: "recorded_posts" as const,
          acquiredAt: bundle.x.acquiredAt,
          hasNextPage: bundle.x.hasNextPage,
          posts: bundle.x.posts
            .map(sanitizeSocialPost)
            .sort((left, right) => compareStrings(left.postIdHash, right.postIdHash)),
        };
  const normalized = SanitizedRecordedBundleSchema.parse({
    schemaVersion: 1,
    kind: "sanitized_recorded_collection_attention",
    marketplace: {
      ...bundle.marketplace,
      candidates: bundle.marketplace.candidates.map((candidate) => ({
        ...candidate,
        contracts: candidate.contracts
          .map((contract) => ({
            chainId: contract.chainId,
            address: contract.address.toLowerCase(),
          }))
          .sort(compareContracts),
      })),
    },
    x,
    base: bundle.base,
  });
  return deepFreeze(normalized);
}

export function recordedBundleId(bundle: SanitizedRecordedBundleV1): BundleId {
  assertPlainAttentionData(bundle);
  const parsed = SanitizedRecordedBundleSchema.safeParse(bundle);
  if (!parsed.success) throw new AttentionInputError();
  return BundleIdSchema.parse(hashCanonical("rsi-attention-bundle-v1\0", toJsonValue(parsed.data)));
}

export function recordedRefreshId(bundleId: BundleId): ReturnType<typeof RefreshIdSchema.parse> {
  const parsedBundleId = BundleIdSchema.safeParse(bundleId);
  if (!parsedBundleId.success) throw new AttentionInputError();
  return RefreshIdSchema.parse(
    hashCanonical(
      "rsi-attention-refresh-v1\0",
      toJsonValue({
        streamId: "recorded-base-v1",
        bundleId: parsedBundleId.data,
        policyVersion: "attention-v1",
      }),
    ),
  );
}

function compareContracts(
  left: { readonly chainId: string; readonly address: string },
  right: { readonly chainId: string; readonly address: string },
): number {
  const chainDifference = Number(left.chainId) - Number(right.chainId);
  return chainDifference || compareStrings(left.address, right.address);
}
