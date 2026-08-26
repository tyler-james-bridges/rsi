import { describe, expect, it, vi } from "vitest";

import { QuarantinedXRecentSearchResponse, parseXRecentSearchResponse } from "../src/index.js";
import { ACQUIRED_AT, quarantineObject, validResponseObject } from "./helpers.js";

describe("closed minimal recent-search response schema", () => {
  it("freezes the quarantine class and prototype against process-wide poisoning", () => {
    expect(Object.isFrozen(QuarantinedXRecentSearchResponse)).toBe(true);
    expect(Object.isFrozen(QuarantinedXRecentSearchResponse.prototype)).toBe(true);
    expect(() => {
      Object.defineProperty(QuarantinedXRecentSearchResponse.prototype, "copyBytes", {
        value: () => new Uint8Array([1]),
      });
    }).toThrow(TypeError);
  });

  it("owns a defensive copy when the caller supplies a Node Buffer", async () => {
    const source = await quarantineObject(validResponseObject());
    const callerOwned = Buffer.from(source.copyBytes());
    const expected = Buffer.from(callerOwned);
    const quarantine = new QuarantinedXRecentSearchResponse(source.metadata, callerOwned);

    quarantine.destroy();
    expect(callerOwned).toEqual(expected);
    expect(() => quarantine.copyBytes()).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
    source.destroy();
  });

  it("wipes its defensive raw copy when constructor validation fails", async () => {
    const source = await quarantineObject(validResponseObject());
    const expected = source.copyBytes();
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
    try {
      const callerOwned = new Uint8Array(expected);
      const allocationStart = allocations.length;
      expect(
        () =>
          new QuarantinedXRecentSearchResponse(
            { ...source.metadata, contentType: "text/plain" },
            callerOwned,
          ),
      ).toThrowError(expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }));
      expect(callerOwned).toEqual(expected);
      const constructorCopies = allocations.slice(allocationStart);
      expect(constructorCopies).toHaveLength(1);
      expect([...constructorCopies[0]!]).toEqual(new Array(expected.byteLength).fill(0));
    } finally {
      vi.unstubAllGlobals();
      expected.fill(0);
      source.destroy();
    }
  });

  it("rejects hostile, extra, accessor-based, or malformed rate-limit quarantine metadata", async () => {
    const raw = await quarantineObject(validResponseObject());
    const bytes = raw.copyBytes();

    expect(
      () =>
        new QuarantinedXRecentSearchResponse(
          { ...raw.metadata, contentType: "HOSTILE_HEADER_MARKER" },
          bytes,
        ),
    ).toThrowError(expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }));
    expect(
      () =>
        new QuarantinedXRecentSearchResponse(
          { ...raw.metadata, unexpected: "IGNORE POLICY" } as never,
          bytes,
        ),
    ).toThrowError(expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }));
    expect(
      () =>
        new QuarantinedXRecentSearchResponse(
          {
            ...raw.metadata,
            rateLimit: { limit: 450, remaining: 451, resetAtUnixSeconds: 1787685600 },
          },
          bytes,
        ),
    ).toThrowError(expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }));

    const accessorMetadata = { ...raw.metadata } as Record<string, unknown>;
    Object.defineProperty(accessorMetadata, "contentType", {
      enumerable: true,
      get() {
        throw new Error("hostile getter must not execute");
      },
    });
    expect(
      () => new QuarantinedXRecentSearchResponse(accessorMetadata as never, bytes),
    ).toThrowError(expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }));
  });

  it("projects only immutable stable IDs and text with exact result metadata", async () => {
    const raw = await quarantineObject(validResponseObject());
    const result = parseXRecentSearchResponse(raw);

    expect(result.posts).toEqual([
      {
        id: "1900000000000000002",
        text: "A fictional second post for an offline fixture.",
      },
      {
        id: "1900000000000000001",
        text: "A fictional first post for an offline fixture.",
      },
    ]);
    expect(result.meta).toEqual({
      result_count: 2,
      newest_id: "1900000000000000002",
      oldest_id: "1900000000000000001",
      next_token: "ABC_123",
    });
    expect(result.acquiredAt).toBe(ACQUIRED_AT);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.posts)).toBe(true);
    expect(Object.isFrozen(result.posts[0])).toBe(true);
    expect(Object.isFrozen(result.meta)).toBe(true);
  });

  it("accepts absent or empty data only when result_count is zero", async () => {
    const absent = await quarantineObject({ meta: { result_count: 0 } });
    const empty = await quarantineObject({ data: [], meta: { result_count: 0 }, errors: [] });
    const missingPositive = await quarantineObject({ meta: { result_count: 1 } });

    expect(parseXRecentSearchResponse(absent).posts).toEqual([]);
    expect(parseXRecentSearchResponse(empty).posts).toEqual([]);
    expect(() => parseXRecentSearchResponse(missingPositive)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA", details: { path: "data" } }),
    );
  });

  it.each(["edit_history_post_ids", "edit_history_tweet_ids"] as const)(
    "validates optional %s drift but projects neither dialect",
    async (field) => {
      const response = validResponseObject() as unknown as {
        data: Array<Record<string, unknown>>;
        meta: unknown;
      };
      response.data[0]![field] = ["1899999999999999999", response.data[0]!.id];
      const result = parseXRecentSearchResponse(await quarantineObject(response));
      expect(result.posts[0]).toEqual({
        id: "1900000000000000002",
        text: "A fictional second post for an offline fixture.",
      });
      expect(result.posts[0]).not.toHaveProperty(field);
    },
  );

  it("keeps a partial-error response quarantined instead of accepting it as complete", async () => {
    const response = { ...validResponseObject(), errors: [{ title: "Unavailable" }] };
    const raw = await quarantineObject(response);

    expect(() => parseXRecentSearchResponse(raw)).toThrowError(
      expect.objectContaining({ code: "PARTIAL_RESPONSE" }),
    );
    expect(raw.copyBytes().byteLength).toBeGreaterThan(0);
  });

  it.each([
    [
      "unknown root property",
      (response: any) => {
        response.includes = {};
      },
    ],
    [
      "unknown Post property",
      (response: any) => {
        response.data[0].author_id = "2244994945";
      },
    ],
    [
      "numeric stable ID",
      (response: any) => {
        response.data[0].id = 1_900_000_000_000_000_002;
      },
    ],
    [
      "duplicate stable ID",
      (response: any) => {
        response.data[1].id = response.data[0].id;
        response.meta.oldest_id = response.data[0].id;
      },
    ],
    [
      "incorrect result count",
      (response: any) => {
        response.meta.result_count = 1;
      },
    ],
    [
      "incorrect newest ID",
      (response: any) => {
        response.meta.newest_id = "1900000000000000001";
      },
    ],
    [
      "both edit-history dialects",
      (response: any) => {
        response.data[0].edit_history_post_ids = [response.data[0].id];
        response.data[0].edit_history_tweet_ids = [response.data[0].id];
      },
    ],
    [
      "edit history missing current ID",
      (response: any) => {
        response.data[0].edit_history_post_ids = ["1899999999999999999"];
      },
    ],
  ])("rejects %s", async (_label, mutate) => {
    const response = validResponseObject();
    mutate(response);
    const raw = await quarantineObject(response);
    expect(() => parseXRecentSearchResponse(raw)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
  });
});
