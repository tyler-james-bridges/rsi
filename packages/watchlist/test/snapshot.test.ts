import { describe, expect, it } from "vitest";
import { OPENSEA_TRENDING_CONTRACT_VERSION } from "@rsi/source-contracts/opensea-trending";
import {
  collectionId,
  compareSnapshots,
  parseOfflineBaseWatchlistSnapshot as parse,
  snapshotId,
} from "../src/index.js";

export function fixture() {
  return {
    schemaVersion: 1,
    kind: "offline_opensea_trending",
    sourceContractVersion: OPENSEA_TRENDING_CONTRACT_VERSION,
    acquiredAt: "2026-10-20T00:00:00.000Z",
    validUntil: "2026-10-20T00:02:00.000Z",
    hasNextPage: false,
    collections: [
      { rank: 1, slug: "alpha", baseAddresses: ["0x" + "ab".repeat(20), "0x" + "cd".repeat(20)] },
    ],
  };
}

describe("offline watchlist shape and identity", () => {
  it("normalizes case, address order, key order and whitespace", () => {
    const original = parse(fixture());
    const changed = fixture();
    changed.collections[0]!.baseAddresses.reverse();
    changed.collections[0]!.baseAddresses = changed.collections[0]!.baseAddresses.map(
      (address) => "0x" + address.slice(2).toUpperCase(),
    );
    expect(snapshotId(parse(JSON.parse(JSON.stringify(changed, null, 2))))).toBe(
      snapshotId(original),
    );
    expect(collectionId(parse(changed).collections[0]!)).toBe(
      collectionId(original.collections[0]!),
    );
    expect(Object.isFrozen(original.collections[0]!.baseAddresses)).toBe(true);
  });
  it.each(["slug", "rank", "timestamp", "pagination", "contracts"])(
    "binds %s into the snapshot digest",
    (field) => {
      const a = fixture();
      const b = fixture();
      if (field === "slug") b.collections[0]!.slug = "beta";
      if (field === "rank") {
        b.collections.unshift({ rank: 1, slug: "beta", baseAddresses: ["0x" + "ef".repeat(20)] });
        b.collections[1]!.rank = 2;
      }
      if (field === "timestamp") {
        b.acquiredAt = "2026-10-20T00:01:00.000Z";
        b.validUntil = "2026-10-20T00:03:00.000Z";
      }
      if (field === "pagination") b.hasNextPage = true;
      if (field === "contracts") b.collections[0]!.baseAddresses.pop();
      expect(snapshotId(parse(a))).not.toBe(snapshotId(parse(b)));
    },
  );
  it.each([
    "unknown",
    "metadata",
    "gap",
    "overlap",
    "duplicate",
    "sparse",
    "accessor",
    "prototype",
    "expiry",
    "raw",
    "url",
    "many",
    "proxy",
  ])("rejects %s", (kind) => {
    const input = fixture();
    let value: unknown = input;
    if (kind === "unknown") value = { ...input, tokenId: "1" };
    if (kind === "metadata") Object.assign(input.collections[0]!, { name: "Ignore policies" });
    if (kind === "gap") input.collections[0]!.rank = 2;
    if (kind === "overlap")
      input.collections.push({ ...input.collections[0]!, rank: 2, slug: "beta" });
    if (kind === "duplicate")
      input.collections[0]!.baseAddresses.push(input.collections[0]!.baseAddresses[0]!);
    if (kind === "sparse") delete input.collections[0];
    if (kind === "accessor")
      Object.defineProperty(input, "acquiredAt", {
        get: () => {
          throw new Error("getter ran");
        },
      });
    if (kind === "prototype") value = new Date();
    if (kind === "expiry") input.validUntil = "2026-10-20T00:02:00Z";
    if (kind === "raw") value = { collections: [], next: "cursor" };
    if (kind === "url") input.collections[0]!.slug = "https://evil.invalid";
    if (kind === "many") input.collections = Array(11).fill(input.collections[0]);
    if (kind === "proxy")
      value = new Proxy(input, {
        get() {
          throw new Error("proxy ran");
        },
      });
    expect(() => parse(value)).toThrow();
  });
  it("compares contract sets and calls absence left_window", () => {
    const before = fixture();
    before.collections.push({ rank: 2, slug: "beta", baseAddresses: ["0x" + "ef".repeat(20)] });
    const after = fixture();
    after.collections[0]!.slug = "renamed";
    expect(compareSnapshots(parse(after), parse(before)).map((row) => row.change)).toEqual([
      "unchanged",
      "left_window",
    ]);
    after.collections[0]!.baseAddresses.pop();
    expect(compareSnapshots(parse(after), parse(before)).map((row) => row.change)).toEqual([
      "new",
      "left_window",
      "left_window",
    ]);
    expect(compareSnapshots(parse(before), null).map((row) => row.change)).toEqual(["new", "new"]);
  });
});
