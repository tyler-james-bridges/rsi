import { describe, expect, it, vi } from "vitest";

import {
  MemoryCassetteStore,
  createXRecentSearchCassette,
  createXRecentSearchCollector,
  isXRecentSearchCollector,
  parseXRecentSearchResponse,
  prepareRecentSearchRequest,
  quarantineNetworkResponse,
  validateXRecentSearchCassette,
} from "../src/index.js";
import {
  ACQUIRED_AT,
  TEST_BEARER_TOKEN,
  jsonResponse,
  validResponseBytes,
  validResponseObject,
} from "./helpers.js";

function syntheticCassette(query: unknown, bytes = validResponseBytes()) {
  const request = prepareRecentSearchRequest(query);
  const response = quarantineNetworkResponse(request, 200, "application/json", bytes, ACQUIRED_AT);
  try {
    return createXRecentSearchCassette(request, response);
  } finally {
    response.destroy();
  }
}

describe("deterministic synthetic fixture replay", () => {
  it("brands only collectors created through the closed factory", () => {
    const collector = createXRecentSearchCollector({
      mode: "replay",
      cassetteStore: new MemoryCassetteStore(),
    });
    expect(isXRecentSearchCollector(collector)).toBe(true);
    expect(isXRecentSearchCollector({ ...collector })).toBe(false);
    expect(
      isXRecentSearchCollector({
        attemptBinding: null,
        collectRaw: collector.collectRaw,
        mode: "replay",
      }),
    ).toBe(false);
  });

  it("replays an explicitly constructed synthetic cassette byte-identically without network", async () => {
    const query = { query: "recorded fictional evidence", maxResults: 10 };
    const cassette = syntheticCassette(query);
    const store = new MemoryCassetteStore([cassette]);
    const snapshot = store.snapshot();

    expect(snapshot).toHaveLength(1);
    expect(snapshot[0]?.acquiredAt).toBe(ACQUIRED_AT);
    const serializedCassette = JSON.stringify(snapshot);
    expect(serializedCassette).not.toContain(TEST_BEARER_TOKEN);
    expect(serializedCassette.toLowerCase()).not.toContain("authorization");

    const network = vi.fn(() => {
      throw new Error("network must not run during replay");
    });
    vi.stubGlobal("fetch", network);
    try {
      const replay = createXRecentSearchCollector({ mode: "replay", cassetteStore: store });
      const replayed = await replay.collectRaw(query);
      expect(replayed.copyBytes()).toEqual(validResponseBytes());
      expect(replayed.metadata.responseHash).toBe(cassette.response.bodySha256);
      expect(replayed.metadata.acquiredAt).toBe(cassette.acquiredAt);
      expect(replayed.metadata.provenance).toBe("cassette");
      expect(parseXRecentSearchResponse(replayed).posts).toHaveLength(
        validResponseObject().data.length,
      );
      expect(network).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("wipes replay decode and validation buffers after quarantine handoff", async () => {
    const query = { query: "synthetic wipe evidence", maxResults: 10 };
    const cassette = syntheticCassette(query);
    const store = new MemoryCassetteStore([cassette]);
    const expected = validResponseBytes();
    const allocations: Uint8Array[] = [];
    const NativeUint8Array = globalThis.Uint8Array;
    const TrackingUint8Array = new Proxy(NativeUint8Array, {
      construct(target, argumentsList, newTarget) {
        const allocation = Reflect.construct(target, argumentsList, newTarget) as Uint8Array;
        allocations.push(allocation);
        return allocation;
      },
    });
    vi.stubGlobal("Uint8Array", TrackingUint8Array);
    let replayed: Awaited<
      ReturnType<ReturnType<typeof createXRecentSearchCollector>["collectRaw"]>
    > | null = null;
    try {
      const replay = createXRecentSearchCollector({ mode: "replay", cassetteStore: store });
      replayed = await replay.collectRaw(query);
      const readableRawCopies = allocations.filter(
        (allocation) =>
          allocation.byteLength === expected.byteLength &&
          allocation.every((byte, index) => byte === expected[index]),
      );
      expect(readableRawCopies).toHaveLength(1);

      replayed.destroy();
      expect([...readableRawCopies[0]!]).toEqual(new Array(expected.byteLength).fill(0));
    } finally {
      replayed?.destroy();
      vi.unstubAllGlobals();
      expected.fill(0);
    }
  });

  it("has no live recording mode or live cassette sink", () => {
    const store = new MemoryCassetteStore();
    expect(() =>
      createXRecentSearchCollector({
        mode: "live",
        attemptAuthorization: {},
        bearerToken: TEST_BEARER_TOKEN,
        cassetteStore: store,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      createXRecentSearchCollector({
        mode: "record",
        bearerToken: TEST_BEARER_TOKEN,
        cassetteStore: store,
        fetch: async () => jsonResponse(),
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("deduplicates exact synthetic seeds and rejects conflicting fingerprint reuse", () => {
    const query = { query: "idempotent recording" };
    const exact = syntheticCassette(query);
    const store = new MemoryCassetteStore([exact, exact]);
    expect(store.snapshot()).toHaveLength(1);

    const changed = validResponseObject();
    changed.data[0]!.text = "A changed response for the same canonical request.";
    const conflicting = syntheticCassette(query, Buffer.from(JSON.stringify(changed)));
    expect(() => new MemoryCassetteStore([exact, conflicting])).toThrowError(
      expect.objectContaining({ code: "INVALID_CASSETTE" }),
    );
  });

  it("strictly validates hashes, acquisition time, envelope keys, and the pinned request", async () => {
    const baseline = syntheticCassette({ query: "tamper test" });

    for (const mutate of [
      (cassette: any) => {
        cassette.response.bodyBase64 = Buffer.from("changed").toString("base64");
      },
      (cassette: any) => {
        cassette.acquiredAt = "2026-08-11T19:20:21Z";
      },
      (cassette: any) => {
        cassette.request.authorization = `Bearer ${TEST_BEARER_TOKEN}`;
      },
      (cassette: any) => {
        cassette.request.canonicalRequest = cassette.request.canonicalRequest.replace(
          "https://api.x.com",
          "https://example.invalid",
        );
      },
    ]) {
      const tampered = structuredClone(baseline);
      mutate(tampered);
      expect(() => validateXRecentSearchCassette(tampered)).toThrowError(
        expect.objectContaining({ code: "INVALID_CASSETTE" }),
      );
    }
  });

  it("rejects a replay configuration that could reach a transport or carry credentials", () => {
    const store = new MemoryCassetteStore();
    expect(() =>
      createXRecentSearchCollector({
        mode: "replay",
        cassetteStore: store,
        fetch: async () => jsonResponse(),
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      createXRecentSearchCollector({
        mode: "replay",
        cassetteStore: store,
        bearerToken: TEST_BEARER_TOKEN,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });
});
