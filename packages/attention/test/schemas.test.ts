import { describe, expect, it } from "vitest";

import {
  AttentionInputError,
  assessRecordedAttention,
  emptyRecordedAttentionFacts,
  parseRecordedAttentionBundle,
  recordedBundleId,
  sanitizeParsedRecordedAttentionBundle,
  sanitizeRecordedAttentionBundle,
  type RecordedAttentionBundleV1,
  type RecordedAttentionFactsV1,
  type SanitizedRecordedBundleV1,
} from "../src/index.js";
import { ADDRESS_A, ADDRESS_B, mixedFixture, recordedBundle } from "./fixtures.js";

describe("recorded attention input", () => {
  it("parses and freezes the bounded fictional bundle", () => {
    const parsed = parseRecordedAttentionBundle(mixedFixture());

    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.marketplace.candidates)).toBe(true);
    expect(parsed.marketplace.candidates).toHaveLength(3);
  });

  it("accepts ordered unique rank subsets without inventing missing ranks", () => {
    const bundle = recordedBundle({
      candidates: [
        {
          rank: 2,
          slug: "alpha",
          contracts: [{ chainId: "8453", address: ADDRESS_A }],
        },
        {
          rank: 6,
          slug: "beta",
          contracts: [{ chainId: "8453", address: ADDRESS_B }],
        },
      ],
    });

    expect(
      parseRecordedAttentionBundle(bundle).marketplace.candidates.map(({ rank }) => rank),
    ).toEqual([2, 6]);
  });

  it.each([
    ["top-level key", (bundle: Record<string, unknown>) => (bundle.authenticated = true)],
    [
      "caller provenance",
      (bundle: Record<string, unknown>) => (bundle.provenance = "authenticated"),
    ],
    [
      "transaction field",
      (bundle: Record<string, unknown>) => (bundle.transaction = { to: ADDRESS_A }),
    ],
    [
      "post author",
      (bundle: Record<string, unknown>) => {
        const x = bundle.x as { posts: Record<string, unknown>[] };
        x.posts[0]!.author = "claimed-author";
      },
    ],
  ])("rejects unknown %s", (_label, mutate) => {
    const bundle = structuredClone(mixedFixture()) as unknown as Record<string, unknown>;
    mutate(bundle);
    expect(() => parseRecordedAttentionBundle(bundle)).toThrowError(AttentionInputError);
  });

  it("rejects invalid duration, unordered ranks, duplicate post IDs, and noncanonical time", () => {
    const duration = structuredClone(mixedFixture());
    duration.marketplace.validUntil = "2026-10-21T12:02:00.001Z";
    const ranks = structuredClone(mixedFixture());
    ranks.marketplace.candidates[1]!.rank = 3;
    const ids = structuredClone(mixedFixture());
    if (ids.x.kind !== "recorded_posts") throw new Error("fixture invariant");
    ids.x.posts[1]!.id = ids.x.posts[0]!.id;
    const time = structuredClone(mixedFixture());
    time.marketplace.acquiredAt = "2026-10-21T12:00:00Z";

    for (const invalid of [duration, ranks, ids, time]) {
      expect(() => parseRecordedAttentionBundle(invalid)).toThrowError("attention_input_invalid");
    }
  });

  it("rejects proxies, accessors, cycles, shared references, and sparse arrays", () => {
    const proxied = new Proxy(mixedFixture(), {});
    const accessor = structuredClone(mixedFixture()) as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "score", { enumerable: true, get: () => 100 });
    const cyclic = structuredClone(mixedFixture()) as unknown as Record<string, unknown>;
    cyclic.loop = cyclic;
    const shared = structuredClone(mixedFixture()) as unknown as Record<string, unknown>;
    const value = { chainId: "8453", address: ADDRESS_A };
    shared.first = value;
    shared.second = value;
    const sparse = structuredClone(mixedFixture());
    sparse.marketplace.candidates.length = 5;

    for (const invalid of [proxied, accessor, cyclic, shared, sparse]) {
      expect(() => parseRecordedAttentionBundle(invalid)).toThrowError(AttentionInputError);
    }
  });

  it("guards every exported model boundary before schema traversal", () => {
    let accessorReads = 0;
    const rawAccessor = structuredClone(mixedFixture());
    Object.defineProperty(rawAccessor.marketplace, "candidates", {
      enumerable: true,
      get: () => {
        accessorReads += 1;
        return [];
      },
    });
    expect(() =>
      sanitizeParsedRecordedAttentionBundle(rawAccessor as unknown as RecordedAttentionBundleV1),
    ).toThrowError(AttentionInputError);

    const sanitized = sanitizeRecordedAttentionBundle(recordedBundle());
    const sourceProxy = new Proxy(sanitized, {
      get: (target, property, receiver) => {
        accessorReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    expect(() =>
      assessRecordedAttention({
        sourceFacts: sourceProxy as SanitizedRecordedBundleV1,
        evaluatedAt: "2026-10-21T12:00:30.000Z",
      }),
    ).toThrowError(AttentionInputError);
    expect(() => recordedBundleId(sourceProxy as SanitizedRecordedBundleV1)).toThrowError(
      AttentionInputError,
    );

    const priorAccessor = structuredClone(emptyRecordedAttentionFacts());
    Object.defineProperty(priorAccessor, "knownCollections", {
      enumerable: true,
      get: () => {
        accessorReads += 1;
        return [];
      },
    });
    expect(() =>
      assessRecordedAttention({
        sourceFacts: sanitized,
        evaluatedAt: "2026-10-21T12:00:30.000Z",
        priorFacts: priorAccessor as unknown as RecordedAttentionFactsV1,
      }),
    ).toThrowError(AttentionInputError);
    expect(accessorReads).toBe(0);
  });

  it("drops text, URLs, and raw post IDs before bundle identity", () => {
    const raw = recordedBundle({
      posts: [
        {
          id: "987654321",
          text: `Look at ${ADDRESS_A} via https://untrusted.example/private-path`,
        },
      ],
    });
    const sanitized = sanitizeRecordedAttentionBundle(raw);
    const serialized = JSON.stringify(sanitized);

    expect(serialized).not.toContain("987654321");
    expect(serialized).not.toContain("untrusted.example");
    expect(serialized).not.toContain("private-path");
    expect(serialized).not.toContain("Look at");
    expect(serialized).toContain(ADDRESS_A);
    expect(sanitized.x.kind === "recorded_posts" && sanitized.x.posts[0]).toMatchObject({
      detectedWatchReasons: ["LINKS_UNCHECKED"],
    });
  });

  it("canonicalizes address case and contract order into one bundle identity", () => {
    const first = recordedBundle({
      candidates: [candidateWith([ADDRESS_B.toUpperCase().replace("0X", "0x"), ADDRESS_A])],
    });
    const second = recordedBundle({
      candidates: [candidateWith([ADDRESS_A, ADDRESS_B])],
    });

    expect(recordedBundleId(sanitizeRecordedAttentionBundle(first))).toBe(
      recordedBundleId(sanitizeRecordedAttentionBundle(second)),
    );
  });
});

function candidateWith(addresses: readonly string[]) {
  return {
    rank: 1,
    slug: "alpha",
    contracts: addresses.map((address) => ({ chainId: "8453", address })),
  };
}
