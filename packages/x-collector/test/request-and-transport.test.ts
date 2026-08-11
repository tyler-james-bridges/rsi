import { ReadableStream } from "node:stream/web";

import { describe, expect, it, vi } from "vitest";

import {
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_EXPANSIONS,
  X_RECENT_SEARCH_POST_FIELDS,
  X_RECENT_SEARCH_USER_FIELDS,
  createXRecentSearchCollector,
  prepareRecentSearchRequest,
  type XRecentSearchFetch,
} from "../src/index.js";
import {
  ACQUIRED_AT,
  FIXED_CLOCK,
  TEST_BEARER_TOKEN,
  jsonResponse,
  validResponseBytes,
} from "./helpers.js";

describe("closed and pinned requests", () => {
  it("pins the production endpoint, method, parameters, fields, headers, and redirect policy", async () => {
    const fetch = vi.fn<XRecentSearchFetch>(async (request) => {
      const url = new URL(request.url);
      expect(`${url.origin}${url.pathname}`).toBe(X_RECENT_SEARCH_ENDPOINT);
      expect(request.method).toBe("GET");
      expect(request.redirect).toBe("error");
      expect(request.credentials).toBe("omit");
      expect(request.body).toBeNull();
      expect([...url.searchParams.keys()].sort()).toEqual(
        ["query", "max_results", "post.fields", "expansions", "user.fields"].sort(),
      );
      expect(url.searchParams.get("query")).toBe("nft evidence -is:retweet");
      expect(url.searchParams.get("max_results")).toBe("10");
      expect(url.searchParams.get("post.fields")).toBe(X_RECENT_SEARCH_POST_FIELDS.join(","));
      expect(url.searchParams.get("expansions")).toBe(X_RECENT_SEARCH_EXPANSIONS.join(","));
      expect(url.searchParams.get("user.fields")).toBe(X_RECENT_SEARCH_USER_FIELDS.join(","));
      expect([...request.headers.keys()].sort()).toEqual(["accept", "authorization"]);
      expect(request.headers.get("accept")).toBe("application/json");
      expect(request.headers.get("authorization")).toBe(`Bearer ${TEST_BEARER_TOKEN}`);
      return jsonResponse();
    });
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
      now: FIXED_CLOCK,
    });

    const raw = await collector.collectRaw({ query: "nft evidence -is:retweet" });

    expect(fetch).toHaveBeenCalledOnce();
    expect(raw.metadata.acquiredAt).toBe(ACQUIRED_AT);
    expect(raw.metadata).not.toHaveProperty("canonicalRequest");
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain(TEST_BEARER_TOKEN);
    expect(serialized).not.toContain("nft evidence");
  });

  it("builds a credential-free deterministic fingerprint and supports one bounded page token", () => {
    const first = prepareRecentSearchRequest({
      query: "same query",
      maxResults: 100,
      nextToken: "ABC_123",
    });
    const second = prepareRecentSearchRequest({
      nextToken: "ABC_123",
      maxResults: 100,
      query: "same query",
    });

    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.canonicalRequest).toBe(second.canonicalRequest);
    expect(first.canonicalRequest).not.toContain(TEST_BEARER_TOKEN);
    expect(new URL(first.url).searchParams.get("next_token")).toBe("ABC_123");
  });

  it.each(["url", "method", "headers", "redirect", "params", "tweet.fields"])(
    "rejects caller-supplied %s before transport",
    async (property) => {
      const fetch = vi.fn<XRecentSearchFetch>();
      const collector = createXRecentSearchCollector({
        bearerToken: TEST_BEARER_TOKEN,
        fetch,
      });
      await expect(
        collector.collectRaw({ query: "closed query", [property]: "untrusted" }),
      ).rejects.toMatchObject({ code: "INVALID_QUERY" });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each([
    { query: "" },
    { query: "   " },
    { query: "x".repeat(4_097) },
    { query: "ok", maxResults: 9 },
    { query: "ok", maxResults: 101 },
    { query: "ok", maxResults: 10.5 },
    { query: "ok", nextToken: "not url safe!" },
  ])("rejects an out-of-bounds query shape", (input) => {
    expect(() => prepareRecentSearchRequest(input)).toThrowError(
      expect.objectContaining({ code: "INVALID_QUERY" }),
    );
  });

  it("rejects method/header/URL configuration channels at collector creation", () => {
    for (const property of ["url", "method", "headers", "redirect"] as const) {
      expect(() =>
        createXRecentSearchCollector({
          bearerToken: TEST_BEARER_TOKEN,
          [property]: "untrusted",
        } as never),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    }
  });
});

describe("network trust-boundary handling", () => {
  it("rejects malformed JSON only at the explicit parse boundary", async () => {
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => jsonResponse("{not-json"),
      now: FIXED_CLOCK,
    });
    const raw = await collector.collectRaw({ query: "malformed" });
    const { parseXRecentSearchResponse } = await import("../src/index.js");
    expect(() => parseXRecentSearchResponse(raw)).toThrowError(
      expect.objectContaining({ code: "MALFORMED_JSON" }),
    );
  });

  it("rejects a streamed response as soon as it exceeds the byte bound", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("12345678"));
        controller.enqueue(new TextEncoder().encode("901234567"));
        controller.close();
      },
    });
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      maxResponseBytes: 16,
      fetch: async () =>
        new Response(stream as unknown as ConstructorParameters<typeof Response>[0], {
          headers: { "content-type": "application/json" },
        }),
    });
    await expect(collector.collectRaw({ query: "oversized" })).rejects.toMatchObject({
      code: "RESPONSE_TOO_LARGE",
    });
  });

  it.each([
    ["shorter", "{}", "3"],
    ["longer", "{}", "1"],
  ])("rejects a body %s than its declared Content-Length", async (_label, body, declared) => {
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () =>
        new Response(body, {
          headers: {
            "content-type": "application/json",
            "content-length": declared,
          },
        }),
    });
    await expect(collector.collectRaw({ query: "length mismatch" })).rejects.toMatchObject({
      code: "CONTENT_LENGTH_MISMATCH",
    });
  });

  it("rejects non-allowlisted JSON-like content types", async () => {
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () =>
        new Response(validResponseBytes(), {
          headers: { "content-type": "application/problem+json" },
        }),
    });
    await expect(collector.collectRaw({ query: "wrong type" })).rejects.toMatchObject({
      code: "UNSUPPORTED_CONTENT_TYPE",
    });
  });

  it("refuses redirects and non-200 statuses without consuming their bodies", async () => {
    const redirectCollector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () =>
        new Response(null, { status: 302, headers: { location: "https://example.invalid" } }),
    });
    await expect(redirectCollector.collectRaw({ query: "redirect" })).rejects.toMatchObject({
      code: "REDIRECT_REFUSED",
    });

    const statusCollector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => new Response(TEST_BEARER_TOKEN, { status: 429 }),
    });
    await expect(statusCollector.collectRaw({ query: "rate limit" })).rejects.toMatchObject({
      code: "HTTP_STATUS",
      details: { status: 429 },
    });
  });

  it("times out a transport that does not complete and redacts its eventual error", async () => {
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      timeoutMs: 5,
      fetch: async (request) =>
        new Promise<Response>((_resolve, reject) => {
          request.signal.addEventListener(
            "abort",
            () => reject(new Error(`Bearer ${TEST_BEARER_TOKEN}`)),
            { once: true },
          );
        }),
    });
    const error = await collector
      .collectRaw({ query: "timeout" })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "TIMEOUT" });
    expect(JSON.stringify(error)).not.toContain(TEST_BEARER_TOKEN);
    expect(String(error)).not.toContain(TEST_BEARER_TOKEN);
  });

  it("supports caller abort without starting an already-aborted request", async () => {
    const fetch = vi.fn<XRecentSearchFetch>();
    const collector = createXRecentSearchCollector({ bearerToken: TEST_BEARER_TOKEN, fetch });
    const controller = new AbortController();
    controller.abort();
    await expect(
      collector.collectRaw({ query: "abort" }, { signal: controller.signal }),
    ).rejects.toMatchObject({ code: "ABORTED" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not retain a transport error that contains the credential", async () => {
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => {
        throw new Error(`request failed with Authorization: Bearer ${TEST_BEARER_TOKEN}`);
      },
    });
    const error = await collector
      .collectRaw({ query: "failure" })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "TRANSPORT_FAILURE" });
    expect(JSON.stringify(error)).not.toContain(TEST_BEARER_TOKEN);
  });

  it("rejects credential material in query fields before it can enter a URL or cassette", async () => {
    const fetch = vi.fn<XRecentSearchFetch>();
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
    });
    await expect(collector.collectRaw({ query: TEST_BEARER_TOKEN })).rejects.toMatchObject({
      code: "CREDENTIAL_IN_REQUEST",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses to quarantine or record a body that echoes the Bearer Token", async () => {
    const collector = createXRecentSearchCollector({
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => jsonResponse(JSON.stringify({ leaked: TEST_BEARER_TOKEN })),
    });
    await expect(collector.collectRaw({ query: "echo" })).rejects.toMatchObject({
      code: "CREDENTIAL_IN_RESPONSE",
    });
  });
});
