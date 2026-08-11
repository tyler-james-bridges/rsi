import { describe, expect, it, vi } from "vitest";

import {
  MemoryCassetteStore,
  createXRecentSearchCollector,
  parseXRecentSearchResponse,
  validateXRecentSearchCassette,
  type XRecentSearchFetch,
} from "../src/index.js";
import {
  ACQUIRED_AT,
  FIXED_CLOCK,
  TEST_BEARER_TOKEN,
  jsonResponse,
  validResponseBytes,
  validResponseObject,
} from "./helpers.js";

describe("deterministic record and replay", () => {
  it("records only in explicit record mode and replays byte-identically without network", async () => {
    const store = new MemoryCassetteStore();
    const fetch = vi.fn<XRecentSearchFetch>(async () => jsonResponse());
    const recorder = createXRecentSearchCollector({
      mode: "record",
      bearerToken: TEST_BEARER_TOKEN,
      cassetteStore: store,
      fetch,
      now: FIXED_CLOCK,
    });
    const query = { query: "recorded fictional evidence", maxResults: 10 };
    const recorded = await recorder.collectRaw(query);
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
      expect(replayed.copyBytes()).toEqual(recorded.copyBytes());
      expect(replayed.metadata.responseHash).toBe(recorded.metadata.responseHash);
      expect(replayed.metadata.acquiredAt).toBe(recorded.metadata.acquiredAt);
      expect(replayed.metadata.provenance).toBe("cassette");
      expect(parseXRecentSearchResponse(replayed)).toEqual(parseXRecentSearchResponse(recorded));
      expect(network).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("does not write cassettes in live mode", async () => {
    const store = new MemoryCassetteStore();
    const live = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => jsonResponse(),
      now: FIXED_CLOCK,
    });
    await live.collectRaw({ query: "live only" });
    expect(store.snapshot()).toEqual([]);
    expect(() =>
      createXRecentSearchCollector({
        mode: "live",
        bearerToken: TEST_BEARER_TOKEN,
        cassetteStore: store,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("makes exact recording retries idempotent and rejects conflicting fingerprint reuse", async () => {
    const store = new MemoryCassetteStore();
    const query = { query: "idempotent recording" };
    const exactRecorder = createXRecentSearchCollector({
      mode: "record",
      bearerToken: TEST_BEARER_TOKEN,
      cassetteStore: store,
      fetch: async () => jsonResponse(),
      now: FIXED_CLOCK,
    });
    await exactRecorder.collectRaw(query);
    await exactRecorder.collectRaw(query);
    expect(store.snapshot()).toHaveLength(1);

    const changed = validResponseObject();
    changed.data[0]!.text = "A changed response for the same canonical request.";
    const conflictingRecorder = createXRecentSearchCollector({
      mode: "record",
      bearerToken: TEST_BEARER_TOKEN,
      cassetteStore: store,
      fetch: async () => jsonResponse(JSON.stringify(changed)),
      now: FIXED_CLOCK,
    });
    await expect(conflictingRecorder.collectRaw(query)).rejects.toMatchObject({
      code: "CASSETTE_STORAGE_FAILURE",
    });
    expect(store.snapshot()).toHaveLength(1);
    expect(Buffer.from(store.snapshot()[0]!.response.bodyBase64, "base64")).toEqual(
      Buffer.from(validResponseBytes()),
    );
  });

  it("strictly validates hashes, acquisition time, envelope keys, and the pinned request", async () => {
    const store = new MemoryCassetteStore();
    const recorder = createXRecentSearchCollector({
      mode: "record",
      bearerToken: TEST_BEARER_TOKEN,
      cassetteStore: store,
      fetch: async () => jsonResponse(),
      now: FIXED_CLOCK,
    });
    await recorder.collectRaw({ query: "tamper test" });
    const baseline = store.snapshot()[0]!;

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
