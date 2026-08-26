import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { ReadableStream } from "node:stream/web";

import { SqliteRuntimeController } from "@rsi/runtime";
import { describe, expect, it, vi } from "vitest";

import {
  X_RECENT_SEARCH_ENDPOINT,
  X_RECENT_SEARCH_RESERVED_USD_MICRO,
  X_RECENT_SEARCH_SORT_ORDER,
  createXRecentSearchCollector,
  prepareRecentSearchRequest,
  xRecentSearchRuntimeActionId,
} from "../src/index.js";
import { createXRecentSearchCollectorForTesting, type XRecentSearchFetch } from "../src/testing.js";
import {
  ACQUIRED_AT,
  FIXED_CLOCK,
  TEST_BEARER_TOKEN,
  jsonResponse,
  testAttemptAuthorization,
  testLiveAuthorizations,
  testRuntimeAuthorization,
  testRuntimeAuthorizationFixture,
  validResponseBytes,
} from "./helpers.js";

function createLiveCollector(query: string, options: Record<string, unknown>) {
  return createXRecentSearchCollectorForTesting({
    ...testLiveAuthorizations(query),
    now: FIXED_CLOCK,
    ...options,
  } as never);
}

describe("closed and pinned requests", () => {
  it("pins one minimal request to the production endpoint with no pagination or expansions", async () => {
    const fetch = vi.fn<XRecentSearchFetch>(async (request) => {
      const url = new URL(request.url);
      expect(`${url.origin}${url.pathname}`).toBe(X_RECENT_SEARCH_ENDPOINT);
      expect(request.method).toBe("GET");
      expect(request.redirect).toBe("error");
      expect(request.credentials).toBe("omit");
      expect(request.body).toBeNull();
      expect([...url.searchParams.keys()].sort()).toEqual(
        ["query", "max_results", "sort_order"].sort(),
      );
      expect(url.searchParams.get("query")).toBe("nft evidence -is:retweet");
      expect(url.searchParams.get("max_results")).toBe("10");
      expect(url.searchParams.get("sort_order")).toBe(X_RECENT_SEARCH_SORT_ORDER);
      expect(url.searchParams.has("next_token")).toBe(false);
      expect(url.searchParams.has("pagination_token")).toBe(false);
      expect(url.searchParams.has("post.fields")).toBe(false);
      expect(url.searchParams.has("tweet.fields")).toBe(false);
      expect(url.searchParams.has("expansions")).toBe(false);
      expect([...request.headers.keys()].sort()).toEqual([
        "accept",
        "accept-encoding",
        "authorization",
      ]);
      expect(request.headers.get("accept")).toBe("application/json");
      expect(request.headers.get("accept-encoding")).toBe("identity");
      expect(request.headers.get("authorization")).toBe(`Bearer ${TEST_BEARER_TOKEN}`);
      return jsonResponse();
    });
    const collector = createLiveCollector("nft evidence -is:retweet", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
      now: FIXED_CLOCK,
    });
    expect(collector.attemptBinding?.reservedAtomic).toBe(X_RECENT_SEARCH_RESERVED_USD_MICRO);

    const raw = await collector.collectRaw({ query: "nft evidence -is:retweet" });

    expect(fetch).toHaveBeenCalledOnce();
    expect(raw.metadata.acquiredAt).toBe(ACQUIRED_AT);
    expect(raw.metadata).not.toHaveProperty("canonicalRequest");
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain(TEST_BEARER_TOKEN);
    expect(serialized).not.toContain("nft evidence");
    raw.destroy();
    raw.destroy();
    expect(() => raw.copyBytes()).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
  });

  it("builds a credential-free deterministic fingerprint from the caller's bounded query only", () => {
    const first = prepareRecentSearchRequest({ query: "same query" });
    const second = prepareRecentSearchRequest(
      Object.assign(Object.create(null), { query: "same query" }),
    );

    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.canonicalRequest).toBe(second.canonicalRequest);
    expect(first.canonicalRequest).not.toContain(TEST_BEARER_TOKEN);
    expect(first.query.maxResults).toBe(10);
  });

  it.each([
    "url",
    "method",
    "headers",
    "redirect",
    "params",
    "tweet.fields",
    "post.fields",
    "expansions",
    "maxResults",
    "nextToken",
    "paginationToken",
    "startTime",
    "endTime",
  ])("rejects caller-supplied %s before transport", async (property) => {
    const fetch = vi.fn<XRecentSearchFetch>();
    const collector = createLiveCollector("closed query", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
    });
    await expect(
      collector.collectRaw({ query: "closed query", [property]: "untrusted" }),
    ).rejects.toMatchObject({ code: "INVALID_QUERY" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([{ query: "" }, { query: "   " }, { query: "x".repeat(513) }, { query: "line\nbreak" }])(
    "rejects an out-of-bounds query shape",
    (input) => {
      expect(() => prepareRecentSearchRequest(input)).toThrowError(
        expect.objectContaining({ code: "INVALID_QUERY" }),
      );
    },
  );

  it("rejects method/header/URL configuration channels at collector creation", () => {
    for (const property of ["url", "method", "headers", "redirect"] as const) {
      expect(() =>
        createLiveCollector("test query", {
          bearerToken: TEST_BEARER_TOKEN,
          [property]: "untrusted",
        } as never),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    }
  });

  it("keeps transport and clock injection behind the test-only package entry", () => {
    const authorizations = testLiveAuthorizations("production factory");
    expect(() =>
      createXRecentSearchCollector({
        ...authorizations,
        bearerToken: TEST_BEARER_TOKEN,
        fetch: async () => jsonResponse(),
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      createXRecentSearchCollector({
        ...testLiveAuthorizations("production clock"),
        bearerToken: TEST_BEARER_TOKEN,
        now: FIXED_CLOCK,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("refuses to construct a live collector without a reserved one-shot authorization", () => {
    expect(() =>
      createXRecentSearchCollector({ bearerToken: TEST_BEARER_TOKEN } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("requires an authentic runtime authorization in addition to the attempt reservation", () => {
    const attemptAuthorization = testAttemptAuthorization();
    expect(() =>
      createXRecentSearchCollector({
        attemptAuthorization,
        bearerToken: TEST_BEARER_TOKEN,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      createXRecentSearchCollector({
        attemptAuthorization,
        bearerToken: TEST_BEARER_TOKEN,
        runtimeAuthorization: {},
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("binds runtime authority to the exact attempt and prepared request fingerprint", async () => {
    const attemptAuthorization = testAttemptAuthorization();
    const runtimeAuthorization = testRuntimeAuthorization(attemptAuthorization, "authorized query");
    const fetch = vi.fn<XRecentSearchFetch>(async () => jsonResponse());
    const collector = createXRecentSearchCollectorForTesting({
      attemptAuthorization,
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
      now: FIXED_CLOCK,
      runtimeAuthorization,
    });

    await expect(collector.collectRaw({ query: "different query" })).rejects.toMatchObject({
      code: "RUNTIME_AUTHORIZATION_FAILED",
    });
    expect(fetch).not.toHaveBeenCalled();
    const raw = await collector.collectRaw({ query: "authorized query" });
    expect(fetch).toHaveBeenCalledOnce();
    raw.destroy();
  });

  it("rechecks STOP durably when consuming runtime authority", async () => {
    const attemptAuthorization = testAttemptAuthorization();
    const { authorization: runtimeAuthorization, runtime } = testRuntimeAuthorizationFixture(
      attemptAuthorization,
      "stop race",
    );
    const fetch = vi.fn<XRecentSearchFetch>();
    const collector = createXRecentSearchCollectorForTesting({
      attemptAuthorization,
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
      runtimeAuthorization,
    });
    runtime.stop({ requestId: randomUUID(), occurredAt: ACQUIRED_AT });

    await expect(collector.collectRaw({ query: "stop race" })).rejects.toMatchObject({
      code: "RUNTIME_AUTHORIZATION_FAILED",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("invokes fetch while the allowed runtime boundary event is still write-locked", async () => {
    const directory = mkdtempSync(join(tmpdir(), "rsi-x-dispatch-lock-"));
    const path = join(directory, "runtime.sqlite");
    const query = "locked dispatch";
    const attemptAuthorization = testAttemptAuthorization();
    const runtime = SqliteRuntimeController.open(
      { path, openedAt: ACQUIRED_AT, processInstanceId: randomUUID() },
      { clock: () => ACQUIRED_AT, monotonicClock: () => 1_000 },
    );
    try {
      runtime.transition({
        expectedMode: "STOPPED",
        expectedRevision: 1,
        occurredAt: ACQUIRED_AT,
        requestId: randomUUID(),
        targetMode: "RESEARCH",
      });
      const fingerprint = prepareRecentSearchRequest({ query }).fingerprint;
      const runtimeAuthorization = runtime.requestBoundaryAuthorization({
        actionId: xRecentSearchRuntimeActionId(attemptAuthorization.binding.attemptId, fingerprint),
        authorizationId: randomUUID(),
        boundary: "research_collection",
      });
      let headVisibleAtFetch: number | undefined;
      const fetch = vi.fn<XRecentSearchFetch>(async () => {
        const observer = new DatabaseSync(path, { readOnly: true });
        try {
          headVisibleAtFetch = (
            observer
              .prepare("SELECT head_sequence FROM rsi_event_store_metadata WHERE singleton = 1")
              .get() as { head_sequence: number }
          ).head_sequence;
        } finally {
          observer.close();
        }
        return jsonResponse();
      });
      const collector = createXRecentSearchCollectorForTesting({
        attemptAuthorization,
        bearerToken: TEST_BEARER_TOKEN,
        fetch,
        now: FIXED_CLOCK,
        runtimeAuthorization,
      });

      const raw = await collector.collectRaw({ query });
      raw.destroy();
      expect(fetch).toHaveBeenCalledOnce();
      // Startup STOP + RESEARCH transition are committed. The allowed boundary
      // event is appended but deliberately uncommitted when fetch is invoked.
      expect(headVisibleAtFetch).toBe(2);
      expect(runtime.getSnapshot().auditHead.sequence).toBe(3);
    } finally {
      runtime.close();
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it("drains a launched response before reporting a post-dispatch runtime COMMIT failure", async () => {
    const query = "commit failure after dispatch";
    const attemptAuthorization = testAttemptAuthorization();
    const { authorization: runtimeAuthorization, runtime } = testRuntimeAuthorizationFixture(
      attemptAuthorization,
      query,
    );
    let resolveResponse: ((response: Response) => void) | undefined;
    const fetch = vi.fn<XRecentSearchFetch>(() => {
      const response = new Promise<Response>((resolve) => {
        resolveResponse = resolve;
      });
      // Closing the active runtime connection rolls back its boundary event;
      // withExclusiveTransaction then fails COMMIT after fetch has launched.
      runtime.close();
      return response;
    });
    const collector = createXRecentSearchCollectorForTesting({
      attemptAuthorization,
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
      now: FIXED_CLOCK,
      runtimeAuthorization,
    });

    const collection = collector.collectRaw({ query });
    let collectionSettled = false;
    void collection.then(
      () => {
        collectionSettled = true;
      },
      () => {
        collectionSettled = true;
      },
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(fetch).toHaveBeenCalledOnce();
    expect(resolveResponse).toBeTypeOf("function");
    expect(collectionSettled).toBe(false);

    resolveResponse?.(jsonResponse());
    await expect(collection).rejects.toMatchObject({ code: "RUNTIME_AUTHORIZATION_FAILED" });
    expect(collectionSettled).toBe(true);
  });

  it("rejects underfunded or wrong-operation attempt authorizations", () => {
    expect(() =>
      createXRecentSearchCollector({
        attemptAuthorization: testAttemptAuthorization({ reservedAtomic: "1" }),
        bearerToken: TEST_BEARER_TOKEN,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      createXRecentSearchCollector({
        attemptAuthorization: testAttemptAuthorization({
          operation: "alchemy.json-rpc.v1",
          sourcePlane: "canonical_chain",
        }),
        bearerToken: TEST_BEARER_TOKEN,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });
});

describe("network trust-boundary handling", () => {
  it("wipes streamed and handoff copies, leaving only the destroyable quarantine copy", async () => {
    const expected = validResponseBytes();
    const sourceChunk = new Uint8Array(expected);
    const allocations: Uint8Array[] = [];
    const NativeUint8Array = globalThis.Uint8Array;
    const TrackingUint8Array = new Proxy(NativeUint8Array, {
      construct(target, argumentsList, newTarget) {
        const allocation = Reflect.construct(target, argumentsList, newTarget) as Uint8Array;
        allocations.push(allocation);
        return allocation;
      },
    });
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(sourceChunk);
        controller.close();
      },
    });
    vi.stubGlobal("Uint8Array", TrackingUint8Array);
    let raw: Awaited<ReturnType<ReturnType<typeof createLiveCollector>["collectRaw"]>> | undefined;
    try {
      const collector = createLiveCollector("wipe transient buffers", {
        bearerToken: TEST_BEARER_TOKEN,
        fetch: async () =>
          new Response(stream as unknown as ConstructorParameters<typeof Response>[0], {
            headers: { "content-type": "application/json" },
          }),
      });
      raw = await collector.collectRaw({ query: "wipe transient buffers" });
      expect([...sourceChunk]).toEqual(new Array(expected.byteLength).fill(0));
      const readableRawCopies = allocations.filter(
        (allocation) =>
          allocation.byteLength === expected.byteLength &&
          allocation.every((byte, index) => byte === expected[index]),
      );
      expect(readableRawCopies).toHaveLength(1);

      raw.destroy();
      expect([...readableRawCopies[0]!]).toEqual(new Array(expected.byteLength).fill(0));
    } finally {
      raw?.destroy();
      vi.unstubAllGlobals();
      expected.fill(0);
    }
  });

  it("rejects malformed JSON only at the explicit parse boundary", async () => {
    const collector = createLiveCollector("malformed", {
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
    const collector = createLiveCollector("oversized", {
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
    const collector = createLiveCollector("length mismatch", {
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

  it("requests identity encoding and rejects a compressed response before length comparison", async () => {
    const collector = createLiveCollector("compressed response", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async (request: Request) => {
        expect(request.headers.get("accept-encoding")).toBe("identity");
        return new Response(validResponseBytes(), {
          headers: {
            "content-encoding": "gzip",
            "content-length": "37",
            "content-type": "application/json",
          },
        });
      },
    });

    await expect(collector.collectRaw({ query: "compressed response" })).rejects.toMatchObject({
      code: "UNSUPPORTED_CONTENT_ENCODING",
    });
  });

  it("rejects non-allowlisted JSON-like content types", async () => {
    const collector = createLiveCollector("wrong type", {
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
    const redirectCollector = createLiveCollector("redirect", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () =>
        new Response(null, { status: 302, headers: { location: "https://example.invalid" } }),
    });
    await expect(redirectCollector.collectRaw({ query: "redirect" })).rejects.toMatchObject({
      code: "REDIRECT_REFUSED",
    });

    const statusFetch = vi.fn<XRecentSearchFetch>(
      async () =>
        new Response(TEST_BEARER_TOKEN, {
          status: 429,
          headers: {
            "x-rate-limit-limit": "450",
            "x-rate-limit-remaining": "0",
            "x-rate-limit-reset": "1787685600",
          },
        }),
    );
    const statusCollector = createLiveCollector("rate limit", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch: statusFetch,
    });
    await expect(statusCollector.collectRaw({ query: "rate limit" })).rejects.toMatchObject({
      code: "HTTP_STATUS",
      details: {
        status: 429,
        rateLimit: { limit: 450, remaining: 0, resetAtUnixSeconds: 1787685600 },
      },
    });
    expect(statusFetch).toHaveBeenCalledOnce();
  });

  it("captures only strictly parsed rate-limit receipt metadata", async () => {
    const collector = createLiveCollector("rate metadata", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () =>
        jsonResponse(undefined, {
          headers: {
            "x-rate-limit-limit": "450",
            "x-rate-limit-remaining": "449",
            "x-rate-limit-reset": "1787685600",
          },
        }),
    });

    const raw = await collector.collectRaw({ query: "rate metadata" });
    expect(raw.metadata.rateLimit).toEqual({
      limit: 450,
      remaining: 449,
      resetAtUnixSeconds: 1787685600,
    });
    expect(Object.isFrozen(raw.metadata.rateLimit)).toBe(true);
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain("x-rate-limit-");
  });

  it.each([
    { "x-rate-limit-limit": "450" },
    {
      "x-rate-limit-limit": "450",
      "x-rate-limit-remaining": "451",
      "x-rate-limit-reset": "1787685600",
    },
    {
      "x-rate-limit-limit": "450, 450",
      "x-rate-limit-remaining": "449",
      "x-rate-limit-reset": "1787685600",
    },
  ])("rejects incomplete or malformed rate-limit headers", async (headers) => {
    const fetch = vi.fn<XRecentSearchFetch>(async () => jsonResponse(undefined, { headers }));
    const collector = createLiveCollector("bad rate metadata", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
    });
    await expect(collector.collectRaw({ query: "bad rate metadata" })).rejects.toMatchObject({
      code: "INVALID_RATE_LIMIT_METADATA",
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("performs zero retries after a transient HTTP failure", async () => {
    const fetch = vi.fn<XRecentSearchFetch>(async () => new Response(null, { status: 503 }));
    const collector = createLiveCollector("no retries", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
    });

    await expect(collector.collectRaw({ query: "no retries" })).rejects.toMatchObject({
      code: "HTTP_STATUS",
      details: { status: 503 },
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("times out a transport that does not complete and redacts its eventual error", async () => {
    const collector = createLiveCollector("timeout", {
      bearerToken: TEST_BEARER_TOKEN,
      timeoutMs: 5,
      fetch: async (request: Request) =>
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
    const fetch = vi.fn<XRecentSearchFetch>(async () => jsonResponse());
    const collector = createLiveCollector("abort", { bearerToken: TEST_BEARER_TOKEN, fetch });
    const controller = new AbortController();
    controller.abort();
    await expect(
      collector.collectRaw({ query: "abort" }, { signal: controller.signal }),
    ).rejects.toMatchObject({ code: "ABORTED" });
    expect(fetch).not.toHaveBeenCalled();

    const raw = await collector.collectRaw({ query: "abort" });
    expect(fetch).toHaveBeenCalledOnce();
    raw.destroy();
  });

  it("permits exactly one runtime-authorized network dispatch per canary", async () => {
    const fetch = vi.fn<XRecentSearchFetch>(async () => jsonResponse());
    const collector = createLiveCollector("first authorized request", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
    });

    await collector.collectRaw({ query: "first authorized request" });
    await expect(
      collector.collectRaw({ query: "second unauthorized request" }),
    ).rejects.toMatchObject({ code: "RUNTIME_AUTHORIZATION_FAILED" });

    expect(fetch).toHaveBeenCalledOnce();
  });

  it("fails closed when the clock moves backward during a request", async () => {
    const collector = createLiveCollector("clock regression", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => jsonResponse(),
      now: () => new Date("2026-08-25T19:20:21.000Z"),
    });

    await expect(collector.collectRaw({ query: "clock regression" })).rejects.toMatchObject({
      code: "CLOCK_REGRESSION",
    });
  });

  it("does not retain a transport error that contains the credential", async () => {
    const collector = createLiveCollector("failure", {
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
    const collector = createLiveCollector("test query", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch,
    });
    await expect(collector.collectRaw({ query: TEST_BEARER_TOKEN })).rejects.toMatchObject({
      code: "CREDENTIAL_IN_REQUEST",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses to quarantine or record a body that echoes the Bearer Token", async () => {
    const collector = createLiveCollector("echo", {
      bearerToken: TEST_BEARER_TOKEN,
      fetch: async () => jsonResponse(JSON.stringify({ leaked: TEST_BEARER_TOKEN })),
    });
    await expect(collector.collectRaw({ query: "echo" })).rejects.toMatchObject({
      code: "CREDENTIAL_IN_RESPONSE",
    });
  });
});
