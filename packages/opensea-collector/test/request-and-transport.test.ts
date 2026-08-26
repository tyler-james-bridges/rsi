import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { isNetworkAttemptDispatchReceipt } from "@rsi/operations";
import { SqliteRuntimeController } from "@rsi/runtime";

import { describe, expect, it, vi } from "vitest";

import {
  OPENSEA_TRENDING_MAXIMUM_RESULTS,
  OPENSEA_TRENDING_OPERATION,
  OPENSEA_TRENDING_PATH,
  OPENSEA_TRENDING_QUERY,
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  OPENSEA_TRENDING_URL,
  createOpenSeaTrendingCollector,
  openSeaTrendingRuntimeActionId,
  parseOpenSeaTrendingQuarantine,
  prepareOpenSeaTrendingCollectorRequest,
} from "../src/index.js";
import {
  createOpenSeaTrendingCollectorForTesting,
  type OpenSeaTrendingFetch,
} from "../src/testing.js";
import {
  ACQUIRED_AT,
  FIXED_CLOCK,
  TEST_API_KEY,
  TEST_RATE_LIMIT_HEADERS,
  createLiveCollector,
  jsonResponse,
  testAttemptAuthorization,
  testLiveAuthorizations,
  testRuntimeAuthorizationFixture,
  validResponseBytes,
  validResponseObject,
} from "./helpers.js";

describe("closed OpenSea trending request", () => {
  it("pins one GET with the exact URL, headers, and no pagination input", async () => {
    const fetch = vi.fn<OpenSeaTrendingFetch>(async (request) => {
      expect(request.url).toBe(OPENSEA_TRENDING_URL);
      expect(new URL(request.url).search).toBe("?timeframe=one_day&chains=base&limit=10");
      expect(request.method).toBe("GET");
      expect(request.redirect).toBe("error");
      expect(request.credentials).toBe("omit");
      expect(request.referrerPolicy).toBe("no-referrer");
      expect(request.body).toBeNull();
      expect([...request.headers.keys()].sort()).toEqual([
        "accept",
        "accept-encoding",
        "x-api-key",
      ]);
      expect(request.headers.get("accept")).toBe("application/json");
      expect(request.headers.get("accept-encoding")).toBe("identity");
      expect(request.headers.get("x-api-key")).toBe(TEST_API_KEY);
      return jsonResponse(JSON.stringify(validResponseObject(2, { next: "DO_NOT_FOLLOW" })), {
        headers: {
          "x-ratelimit-limit": "100",
          "x-ratelimit-remaining": "99",
          "x-ratelimit-reset": "1787685600",
        },
      });
    });
    const collector = createLiveCollector({ fetch });

    const raw = await collector.collectRaw();
    const parsed = parseOpenSeaTrendingQuarantine(raw);

    expect(fetch).toHaveBeenCalledOnce();
    expect(collector.attemptBinding).toMatchObject({
      lane: "marketplace",
      operation: OPENSEA_TRENDING_OPERATION,
      reservedAtomic: OPENSEA_TRENDING_RESERVED_ATOMIC,
      sourcePlane: "marketplace",
    });
    expect(raw.metadata).toMatchObject({
      acquiredAt: ACQUIRED_AT,
      endpoint: OPENSEA_TRENDING_URL,
      maximumResults: OPENSEA_TRENDING_MAXIMUM_RESULTS,
      rateLimit: { limit: 100, remaining: 99, resetAtUnixSeconds: 1787685600 },
    });
    expect(isNetworkAttemptDispatchReceipt(raw.metadata.networkAttempt)).toBe(true);
    expect(raw.metadata.networkAttempt).toMatchObject({
      binding: collector.attemptBinding,
      dispatchedAt: ACQUIRED_AT,
    });
    expect(parsed.evidence).toMatchObject({
      collections: [
        { rank: 1, slug: "fictional-base-collection-1" },
        { rank: 2, slug: "fictional-base-collection-2" },
      ],
      hasNextPage: true,
    });
    expect(JSON.stringify(raw)).not.toContain(TEST_API_KEY);
    expect(JSON.stringify(parsed)).not.toContain("DO_NOT_FOLLOW");
    raw.destroy();
  });

  it("builds one deterministic credential-free request and rejects arguments", () => {
    const first = prepareOpenSeaTrendingCollectorRequest();
    const second = prepareOpenSeaTrendingCollectorRequest();
    expect(first).toEqual(second);
    expect(first).toMatchObject({
      origin: "https://api.opensea.io",
      path: OPENSEA_TRENDING_PATH,
      query: OPENSEA_TRENDING_QUERY,
      url: OPENSEA_TRENDING_URL,
    });
    expect(first.canonicalRequest).not.toContain(TEST_API_KEY);
    expect(first.canonicalRequest).not.toContain("DO_NOT_FOLLOW");
    expect(() =>
      (prepareOpenSeaTrendingCollectorRequest as unknown as (value: unknown) => unknown)({
        cursor: "attacker",
      }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("keeps transport and clock injection behind the testing subpath", () => {
    expect(() =>
      createOpenSeaTrendingCollector({
        ...testLiveAuthorizations(),
        apiKey: TEST_API_KEY,
        fetch: async () => jsonResponse(),
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(() =>
      createOpenSeaTrendingCollector({
        ...testLiveAuthorizations(),
        apiKey: TEST_API_KEY,
        now: FIXED_CLOCK,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it.each(["", "contains space", "line\nbreak", "x".repeat(4_097)])(
    "rejects invalid API credentials without dispatch",
    (apiKey) => {
      const fetch = vi.fn<OpenSeaTrendingFetch>();
      expect(() =>
        createOpenSeaTrendingCollectorForTesting({
          ...testLiveAuthorizations(),
          apiKey,
          fetch,
        }),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CREDENTIAL" }));
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("rejects proxied and accessor-bearing option objects", () => {
    const options = {
      ...testLiveAuthorizations(),
      apiKey: TEST_API_KEY,
    };
    expect(() => createOpenSeaTrendingCollector(new Proxy(options, {}))).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
    const accessorOptions = { ...options };
    Object.defineProperty(accessorOptions, "apiKey", {
      enumerable: true,
      get: () => TEST_API_KEY,
    });
    expect(() => createOpenSeaTrendingCollector(accessorOptions)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
  });

  it.each(["url", "method", "headers", "query", "cursor", "next", "retry", "payment"])(
    "rejects caller-supplied %s configuration",
    (property) => {
      expect(() =>
        createOpenSeaTrendingCollector({
          ...testLiveAuthorizations(),
          apiKey: TEST_API_KEY,
          [property]: "untrusted",
        } as never),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    },
  );

  it("requires exact genuine attempt and runtime authorizations", () => {
    const validAttempt = testAttemptAuthorization();
    expect(() => createOpenSeaTrendingCollector({ apiKey: TEST_API_KEY } as never)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
    expect(() =>
      createOpenSeaTrendingCollector({
        apiKey: TEST_API_KEY,
        attemptAuthorization: validAttempt,
        runtimeAuthorization: {},
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    for (const attemptAuthorization of [
      testAttemptAuthorization({
        operation: "x.recent-search.v1",
        lane: "discovery",
        reservedAtomic: "50000",
        sourcePlane: "social",
      }),
      testAttemptAuthorization({ reservedAtomic: "2" }),
      testAttemptAuthorization({ lane: "official" }),
    ]) {
      const runtimeAuthorization =
        testRuntimeAuthorizationFixture(attemptAuthorization).authorization;
      expect(() =>
        createOpenSeaTrendingCollector({
          apiKey: TEST_API_KEY,
          attemptAuthorization,
          runtimeAuthorization,
        }),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    }
  });

  it("binds runtime authority to the exact attempt and request fingerprint", async () => {
    const attemptAuthorization = testAttemptAuthorization();
    const runtimeAuthorization = testRuntimeAuthorizationFixture(
      attemptAuthorization,
      `opensea.tc:${randomUUID()}:${"0".repeat(64)}`,
    ).authorization;
    const fetch = vi.fn<OpenSeaTrendingFetch>();
    const collector = createOpenSeaTrendingCollectorForTesting({
      apiKey: TEST_API_KEY,
      attemptAuthorization,
      fetch,
      runtimeAuthorization,
    });
    await expect(collector.collectRaw()).rejects.toMatchObject({
      code: "RUNTIME_AUTHORIZATION_FAILED",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rechecks durable STOP before dispatch", async () => {
    const attemptAuthorization = testAttemptAuthorization();
    const { authorization: runtimeAuthorization, runtime } =
      testRuntimeAuthorizationFixture(attemptAuthorization);
    const fetch = vi.fn<OpenSeaTrendingFetch>();
    const collector = createOpenSeaTrendingCollectorForTesting({
      apiKey: TEST_API_KEY,
      attemptAuthorization,
      fetch,
      runtimeAuthorization,
    });
    runtime.stop({ occurredAt: ACQUIRED_AT, requestId: randomUUID() });
    await expect(collector.collectRaw()).rejects.toMatchObject({
      code: "RUNTIME_AUTHORIZATION_FAILED",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("invokes fetch while the allowed runtime event remains write-locked", async () => {
    const directory = mkdtempSync(join(tmpdir(), "rsi-opensea-dispatch-lock-"));
    const path = join(directory, "runtime.sqlite");
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
      const request = prepareOpenSeaTrendingCollectorRequest();
      const runtimeAuthorization = runtime.requestBoundaryAuthorization({
        actionId: openSeaTrendingRuntimeActionId(
          attemptAuthorization.binding.attemptId,
          request.fingerprint,
        ),
        authorizationId: randomUUID(),
        boundary: "research_collection",
      });
      let headVisibleAtFetch: number | undefined;
      const fetch = vi.fn<OpenSeaTrendingFetch>(async () => {
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
      const collector = createOpenSeaTrendingCollectorForTesting({
        apiKey: TEST_API_KEY,
        attemptAuthorization,
        fetch,
        now: FIXED_CLOCK,
        runtimeAuthorization,
      });

      const raw = await collector.collectRaw();
      raw.destroy();
      expect(fetch).toHaveBeenCalledOnce();
      expect(headVisibleAtFetch).toBe(2);
      expect(runtime.getSnapshot().auditHead.sequence).toBe(3);
    } finally {
      runtime.close();
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it("drains a launched response before reporting a runtime COMMIT failure", async () => {
    const attemptAuthorization = testAttemptAuthorization();
    const { authorization: runtimeAuthorization, runtime } =
      testRuntimeAuthorizationFixture(attemptAuthorization);
    let resolveResponse: ((response: Response) => void) | undefined;
    const fetch = vi.fn<OpenSeaTrendingFetch>(() => {
      const response = new Promise<Response>((resolve) => {
        resolveResponse = resolve;
      });
      runtime.close();
      return response;
    });
    const collector = createOpenSeaTrendingCollectorForTesting({
      apiKey: TEST_API_KEY,
      attemptAuthorization,
      fetch,
      now: FIXED_CLOCK,
      runtimeAuthorization,
    });

    const collection = collector.collectRaw();
    let settled = false;
    void collection.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(fetch).toHaveBeenCalledOnce();
    expect(resolveResponse).toBeTypeOf("function");
    expect(settled).toBe(false);

    resolveResponse?.(jsonResponse());
    await expect(collection).rejects.toMatchObject({ code: "RUNTIME_AUTHORIZATION_FAILED" });
    expect(settled).toBe(true);
  });

  it("distinguishes byte-identical responses from separate attempts and sessions", async () => {
    const first = await createLiveCollector().collectRaw();
    const second = await createLiveCollector().collectRaw();
    try {
      expect(first.metadata.requestFingerprint).toBe(second.metadata.requestFingerprint);
      expect(first.metadata.responseHash).toBe(second.metadata.responseHash);
      expect(first.metadata.networkAttempt.binding.attemptId).not.toBe(
        second.metadata.networkAttempt.binding.attemptId,
      );
      expect(first.metadata.networkAttempt.binding.sessionId).not.toBe(
        second.metadata.networkAttempt.binding.sessionId,
      );
      expect(isNetworkAttemptDispatchReceipt(first.metadata.networkAttempt)).toBe(true);
      expect(isNetworkAttemptDispatchReceipt(second.metadata.networkAttempt)).toBe(true);
    } finally {
      first.destroy();
      second.destroy();
    }
  });
});

describe("OpenSea network trust boundary", () => {
  it("refuses 402 distinctly without reading or paying", async () => {
    const fetch = vi.fn<OpenSeaTrendingFetch>(
      async () => new Response(TEST_API_KEY, { status: 402 }),
    );
    const collector = createLiveCollector({ fetch });
    await expect(collector.collectRaw()).rejects.toMatchObject({
      code: "PAYMENT_REQUIRED",
      details: { status: 402 },
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([401, 429, 500, 503])("does not retry HTTP %i", async (status) => {
    const fetch = vi.fn<OpenSeaTrendingFetch>(async () => new Response(null, { status }));
    const collector = createLiveCollector({ fetch });
    await expect(collector.collectRaw()).rejects.toMatchObject({
      code: "HTTP_STATUS",
      details: { status },
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([
    {
      code: "REDIRECT_REFUSED",
      headers: {},
      label: "redirect",
      status: 302,
    },
    {
      code: "PAYMENT_REQUIRED",
      headers: { "x-ratelimit-limit": "100" },
      label: "402 with malformed rate metadata",
      status: 402,
    },
    {
      code: "HTTP_STATUS",
      headers: {},
      label: "non-200 status",
      status: 401,
    },
    {
      code: "UNSUPPORTED_CONTENT_ENCODING",
      headers: {
        ...TEST_RATE_LIMIT_HEADERS,
        "content-encoding": "gzip",
        "content-type": "application/json",
      },
      label: "compressed response",
      status: 200,
    },
    {
      code: "UNSUPPORTED_CONTENT_TYPE",
      headers: { ...TEST_RATE_LIMIT_HEADERS, "content-type": "text/plain" },
      label: "unsupported media type",
      status: 200,
    },
    {
      code: "INVALID_RATE_LIMIT_METADATA",
      headers: { "content-type": "application/json", "x-ratelimit-limit": "100" },
      label: "malformed rate metadata",
      status: 200,
    },
    {
      code: "RESPONSE_TOO_LARGE",
      headers: {
        ...TEST_RATE_LIMIT_HEADERS,
        "content-length": "17",
        "content-type": "application/json",
      },
      label: "oversized declared body",
      maxResponseBytes: 16,
      status: 200,
    },
  ])("cancels the unread body for $label rejection", async (fixture) => {
    const cancel = vi.fn(() => undefined);
    const body = new ReadableStream<Uint8Array>({ cancel });
    const response = new Response(body as unknown as ConstructorParameters<typeof Response>[0], {
      headers: fixture.headers,
      status: fixture.status,
    });
    const fetch = vi.fn<OpenSeaTrendingFetch>(async () => response);
    const collector = createLiveCollector({
      fetch,
      ...(fixture.maxResponseBytes === undefined
        ? {}
        : { maxResponseBytes: fixture.maxResponseBytes }),
    });

    await expect(collector.collectRaw()).rejects.toMatchObject({ code: fixture.code });
    await vi.waitFor(() => expect(cancel).toHaveBeenCalledOnce());
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("refuses redirects, compression, and non-allowlisted content types", async () => {
    await expect(
      createLiveCollector({ fetch: async () => new Response(null, { status: 302 }) }).collectRaw(),
    ).rejects.toMatchObject({ code: "REDIRECT_REFUSED" });
    await expect(
      createLiveCollector({
        fetch: async () => jsonResponse(undefined, { headers: { "content-encoding": "gzip" } }),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "UNSUPPORTED_CONTENT_ENCODING" });
    await expect(
      createLiveCollector({
        fetch: async () =>
          new Response(validResponseBytes(), {
            headers: {
              ...TEST_RATE_LIMIT_HEADERS,
              "content-type": "application/problem+json",
            },
          }),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "UNSUPPORTED_CONTENT_TYPE" });
  });

  it("enforces streamed and declared body bounds", async () => {
    await expect(
      createLiveCollector({
        fetch: async () => jsonResponse("123456789"),
        maxResponseBytes: 8,
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
    await expect(
      createLiveCollector({
        fetch: async () =>
          new Response("{}", {
            headers: {
              ...TEST_RATE_LIMIT_HEADERS,
              "content-length": "3",
              "content-type": "application/json",
            },
          }),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "CONTENT_LENGTH_MISMATCH" });

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("12345678"));
        controller.enqueue(new TextEncoder().encode("901234567"));
        controller.close();
      },
    });
    await expect(
      createLiveCollector({
        fetch: async () =>
          new Response(stream as unknown as ConstructorParameters<typeof Response>[0], {
            headers: { ...TEST_RATE_LIMIT_HEADERS, "content-type": "application/json" },
          }),
        maxResponseBytes: 16,
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
  });

  it("parses only complete valid rate-limit metadata", async () => {
    const raw = await createLiveCollector({
      fetch: async () =>
        jsonResponse(undefined, {
          headers: {
            "x-ratelimit-limit": "100",
            "x-ratelimit-remaining": "99",
            "x-ratelimit-reset": "1787685600",
          },
        }),
    }).collectRaw();
    expect(raw.metadata.rateLimit).toEqual({
      limit: 100,
      remaining: 99,
      resetAtUnixSeconds: 1787685600,
    });
    raw.destroy();

    await expect(
      createLiveCollector({
        fetch: async () => jsonResponse(undefined, { headers: { "x-ratelimit-limit": "100" } }),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "INVALID_RATE_LIMIT_METADATA" });

    await expect(
      createLiveCollector({
        fetch: async () =>
          new Response(validResponseBytes(), {
            headers: { "content-type": "application/json" },
            status: 200,
          }),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "INVALID_RATE_LIMIT_METADATA" });
  });

  it("rejects an echoed API key and redacts transport failures", async () => {
    await expect(
      createLiveCollector({
        fetch: async () => jsonResponse(JSON.stringify({ key: TEST_API_KEY })),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "CREDENTIAL_IN_RESPONSE" });

    const error = await createLiveCollector({
      fetch: async () => {
        throw new Error(`failed with x-api-key: ${TEST_API_KEY}`);
      },
    })
      .collectRaw()
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "TRANSPORT_FAILURE" });
    expect(JSON.stringify(error)).not.toContain(TEST_API_KEY);
    expect(String(error)).not.toContain(TEST_API_KEY);
  });

  it("supports abort and timeout without retry", async () => {
    const preAbortedFetch = vi.fn<OpenSeaTrendingFetch>();
    const preAborted = createLiveCollector({ fetch: preAbortedFetch });
    const controller = new AbortController();
    controller.abort();
    await expect(preAborted.collectRaw({ signal: controller.signal })).rejects.toMatchObject({
      code: "ABORTED",
    });
    expect(preAbortedFetch).not.toHaveBeenCalled();

    const timeoutFetch = vi.fn<OpenSeaTrendingFetch>(
      async (request) =>
        new Promise<Response>((_resolve, reject) => {
          request.signal.addEventListener(
            "abort",
            () => reject(new Error(`x-api-key: ${TEST_API_KEY}`)),
            { once: true },
          );
        }),
    );
    const timeout = createLiveCollector({ fetch: timeoutFetch, timeoutMs: 5 });
    await expect(timeout.collectRaw()).rejects.toMatchObject({ code: "TIMEOUT" });
    expect(timeoutFetch).toHaveBeenCalledOnce();
  });

  it("aborts a request after dispatch without retry", async () => {
    const fetch = vi.fn<OpenSeaTrendingFetch>(
      async (request) =>
        new Promise<Response>((_resolve, reject) => {
          request.signal.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          });
        }),
    );
    const collector = createLiveCollector({ fetch });
    const controller = new AbortController();
    const collection = collector.collectRaw({ signal: controller.signal });
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    controller.abort();

    await expect(collection).rejects.toMatchObject({ code: "ABORTED" });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each(["timeout", "abort"] as const)(
    "cancels a Response that arrives late after %s",
    async (reason) => {
      let resolveResponse: ((response: Response) => void) | undefined;
      const fetch = vi.fn<OpenSeaTrendingFetch>(
        () =>
          new Promise<Response>((resolve) => {
            resolveResponse = resolve;
          }),
      );
      const collector = createLiveCollector({
        fetch,
        timeoutMs: reason === "timeout" ? 5 : 1_000,
      });
      const controller = new AbortController();
      const collection = collector.collectRaw({ signal: controller.signal });
      const rejection = expect(collection).rejects.toMatchObject({
        code: reason === "timeout" ? "TIMEOUT" : "ABORTED",
      });
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
      if (reason === "abort") controller.abort();
      await rejection;

      const cancel = vi.fn(() => undefined);
      const body = new ReadableStream<Uint8Array>({ cancel });
      resolveResponse?.(
        new Response(body as unknown as ConstructorParameters<typeof Response>[0], {
          headers: { "content-type": "application/json" },
        }),
      );
      await vi.waitFor(() => expect(cancel).toHaveBeenCalledOnce());
      expect(fetch).toHaveBeenCalledOnce();
    },
  );

  it("permits exactly one authorized dispatch", async () => {
    const fetch = vi.fn<OpenSeaTrendingFetch>(async () => jsonResponse());
    const collector = createLiveCollector({ fetch });
    const raw = await collector.collectRaw();
    raw.destroy();
    await expect(collector.collectRaw()).rejects.toMatchObject({
      code: "RUNTIME_AUTHORIZATION_FAILED",
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("fails closed on clock regression", async () => {
    await expect(
      createLiveCollector({
        now: () => new Date("2026-08-25T19:20:21.000Z"),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "CLOCK_REGRESSION" });
  });
});
