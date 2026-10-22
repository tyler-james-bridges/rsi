import { readFileSync } from "node:fs";

import type { RecordedAttentionBundleV1 } from "../src/index.js";

const MIXED_FIXTURE_URL = new URL("../fixtures/recorded-mixed.json", import.meta.url);

export const ADDRESS_A = "0x1111111111111111111111111111111111111111";
export const ADDRESS_B = "0x2222222222222222222222222222222222222222";
export const ADDRESS_C = "0x3333333333333333333333333333333333333333";
export const ADDRESS_D = "0x4444444444444444444444444444444444444444";
export const UNKNOWN_ADDRESS = "0x9999999999999999999999999999999999999999";

export function mixedFixture(): RecordedAttentionBundleV1 {
  return JSON.parse(readFileSync(MIXED_FIXTURE_URL, "utf8"));
}

export function recordedBundle(
  options: {
    readonly acquiredAt?: string;
    readonly base?: RecordedAttentionBundleV1["base"];
    readonly candidates?: RecordedAttentionBundleV1["marketplace"]["candidates"];
    readonly hasNextPage?: boolean;
    readonly posts?: Extract<RecordedAttentionBundleV1["x"], { kind: "recorded_posts" }>["posts"];
    readonly validUntil?: string;
    readonly x?: RecordedAttentionBundleV1["x"];
  } = {},
): RecordedAttentionBundleV1 {
  const acquiredAt = options.acquiredAt ?? "2026-10-21T12:00:00.000Z";
  const validUntil = options.validUntil ?? new Date(Date.parse(acquiredAt) + 120_000).toISOString();
  return {
    schemaVersion: 1,
    kind: "recorded_collection_attention",
    marketplace: {
      kind: "recorded_rank_window",
      acquiredAt,
      validUntil,
      hasNextPage: options.hasNextPage ?? false,
      candidates: options.candidates ?? [candidate(1, "alpha", [ADDRESS_A])],
    },
    x:
      options.x ??
      ({
        kind: "recorded_posts",
        acquiredAt: new Date(Date.parse(acquiredAt) + 10_000).toISOString(),
        hasNextPage: false,
        posts: options.posts ?? [{ id: "1", text: `Research ${ADDRESS_A}` }],
      } satisfies RecordedAttentionBundleV1["x"]),
    base: options.base ?? { kind: "absent" },
  };
}

export function candidate(
  rank: number,
  slug: string,
  addresses: readonly string[],
  chainId = "8453",
): RecordedAttentionBundleV1["marketplace"]["candidates"][number] {
  return {
    rank,
    slug,
    contracts: addresses.map((address) => ({ chainId, address })),
  };
}

export function assessTime(bundle: RecordedAttentionBundleV1, offsetMilliseconds = 30_000): string {
  return new Date(Date.parse(bundle.marketplace.acquiredAt) + offsetMilliseconds).toISOString();
}
