import { describe, expect, it } from "vitest";

import { QuarantinedXRecentSearchResponse, parseXRecentSearchResponse } from "../src/index.js";
import { quarantineObject, validResponseObject } from "./helpers.js";

describe("closed endpoint-specific response schema", () => {
  it("rejects hostile, extra, or accessor-based quarantine metadata", async () => {
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

  it("parses stable IDs, edit history, timestamps, and correlated included users", async () => {
    const raw = await quarantineObject(validResponseObject());
    const result = parseXRecentSearchResponse(raw);

    expect(result.posts).toHaveLength(2);
    expect(result.posts[0]?.edit_history_post_ids).toContain(result.posts[0]?.id);
    expect(result.usersById[result.posts[0]!.author_id]?.username).toBe("fictional_dev");
    expect(result.meta).toMatchObject({
      result_count: 2,
      newest_id: "1900000000000000002",
      oldest_id: "1900000000000000001",
    });
    expect(result.acquiredAt).toBe("2026-08-11T19:20:21.123Z");
  });

  it("accepts the strictly closed zero-result shape", async () => {
    const raw = await quarantineObject({ meta: { result_count: 0 } });
    expect(parseXRecentSearchResponse(raw)).toMatchObject({ posts: [], users: [] });
  });

  it("rejects the legacy tweet-fields dialect instead of silently merging API shapes", async () => {
    const response = validResponseObject() as unknown as {
      data: Array<Record<string, unknown>>;
      includes: unknown;
      meta: unknown;
    };
    for (const post of response.data) {
      post.edit_history_tweet_ids = post.edit_history_post_ids;
      delete post.edit_history_post_ids;
    }
    const raw = await quarantineObject(response);
    expect(() => parseXRecentSearchResponse(raw)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
  });

  it.each([
    [
      "unknown root property",
      (response: any) => {
        response.errors = [];
      },
    ],
    [
      "missing author expansion",
      (response: any) => {
        response.includes.users.pop();
      },
    ],
    [
      "unrelated included user",
      (response: any) => {
        response.includes.users.push({
          id: "999",
          name: "Unrelated",
          username: "unrelated",
          created_at: "2020-01-01T00:00:00Z",
        });
      },
    ],
    [
      "noncanonical timestamp",
      (response: any) => {
        response.data[0].created_at = "2026-08-11 18:02:03 UTC";
      },
    ],
    [
      "post timestamp later than acquisition",
      (response: any) => {
        response.data[0].created_at = "2026-08-11T20:02:03.000Z";
      },
    ],
    [
      "numeric stable ID",
      (response: any) => {
        response.data[0].id = 1_900_000_000_000_000_002;
      },
    ],
    [
      "edit history missing current ID",
      (response: any) => {
        response.data[0].edit_history_post_ids = ["1899999999999999999"];
      },
    ],
    [
      "incorrect result count",
      (response: any) => {
        response.meta.result_count = 1;
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
