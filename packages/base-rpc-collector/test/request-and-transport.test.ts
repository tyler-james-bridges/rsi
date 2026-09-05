import { randomUUID } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  BASE_RPC_ANCHOR_BODY,
  BASE_RPC_ANCHOR_RESERVED_ATOMIC,
  BASE_RPC_ANCHOR_URL,
  baseRpcAnchorRuntimeActionId,
  createBaseRpcAnchorCollector,
  isBaseRpcAnchorCollector,
  parseBaseRpcAnchorQuarantine,
  prepareBaseRpcAnchorCollectorRequest,
} from "../src/index.js";
import { createBaseRpcAnchorCollectorForTesting, type BaseRpcAnchorFetch } from "../src/testing.js";
import {
  ACQUIRED_AT,
  BLOCK_HASH,
  FIXED_CLOCK,
  TEST_API_KEY,
  createLiveCollector,
  jsonResponse,
  testAttemptAuthorization,
  testLiveAuthorizations,
  testRuntimeAuthorizationFixture,
  validResponseBytes,
} from "./helpers.js";

describe("closed Base RPC anchor request", () => {
  it("pins one authorized POST with the exact URL, headers, and two-call body", async () => {
    const fetch = vi.fn<BaseRpcAnchorFetch>(async (request) => {
      expect(request.url).toBe(BASE_RPC_ANCHOR_URL);
      expect(new URL(request.url).search).toBe("");
      expect(request.url).not.toContain(TEST_API_KEY);
      expect(request.method).toBe("POST");
      expect(request.redirect).toBe("error");
      expect(request.credentials).toBe("omit");
      expect(request.referrerPolicy).toBe("no-referrer");
      expect([...request.headers.keys()].sort()).toEqual([
        "accept",
        "accept-encoding",
        "authorization",
        "content-type",
      ]);
      expect(request.headers.get("accept")).toBe("application/json");
      expect(request.headers.get("accept-encoding")).toBe("identity");
      expect(request.headers.get("authorization")).toBe(`Bearer ${TEST_API_KEY}`);
      expect(request.headers.get("content-type")).toBe("application/json");
      const body = await request.text();
      expect(body).toBe(BASE_RPC_ANCHOR_BODY);
      expect(JSON.parse(body)).toEqual([
        { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", method: "eth_chainId", params: [] },
        {
          id: "rsi-base-finalized-block-v1",
          jsonrpc: "2.0",
          method: "eth_getBlockByNumber",
          params: ["finalized", false],
        },
      ]);
      return jsonResponse();
    });
    const collector = createLiveCollector({ fetch });

    expect(isBaseRpcAnchorCollector(collector)).toBe(true);
    const raw = await collector.collectRaw();
    const result = parseBaseRpcAnchorQuarantine(raw);

    expect(fetch).toHaveBeenCalledOnce();
    expect(collector.attemptBinding).toMatchObject({
      lane: "contract",
      operation: "alchemy.json-rpc.v1",
      reservedAtomic: BASE_RPC_ANCHOR_RESERVED_ATOMIC,
      sourcePlane: "canonical_chain",
    });
    expect(raw.metadata).toMatchObject({
      acquiredAt: ACQUIRED_AT,
      endpoint: BASE_RPC_ANCHOR_URL,
      status: 200,
    });
    expect(result.anchor.blockHash).toBe(BLOCK_HASH);
    expect(result.networkAttempt).toBe(raw.metadata.networkAttempt);
    expect(JSON.stringify(raw)).not.toContain(TEST_API_KEY);
    expect(JSON.stringify(raw)).not.toContain(BLOCK_HASH);
    expect(JSON.stringify(result)).not.toContain(BLOCK_HASH);
    raw.destroy();
  });

  it("builds one deterministic credential-free request and rejects arguments", () => {
    const first = prepareBaseRpcAnchorCollectorRequest();
    const second = prepareBaseRpcAnchorCollectorRequest();
    expect(first).toBe(second);
    expect(first).toMatchObject({
      body: BASE_RPC_ANCHOR_BODY,
      method: "POST",
      origin: "https://base-mainnet.g.alchemy.com",
      path: "/v2",
      url: BASE_RPC_ANCHOR_URL,
    });
    expect(first.canonicalRequest).not.toContain(TEST_API_KEY);
    expect(first.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(() =>
      (prepareBaseRpcAnchorCollectorRequest as unknown as (value: unknown) => unknown)({
        method: "eth_call",
      }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("keeps transport, clock, timeout, and body-limit hooks behind the testing subpath", () => {
    for (const extra of [
      { fetch: async () => jsonResponse() },
      { now: FIXED_CLOCK },
      { timeoutMs: 5 },
      { maxResponseBytes: 64 },
    ]) {
      expect(() =>
        createBaseRpcAnchorCollector({
          ...testLiveAuthorizations(),
          apiKey: TEST_API_KEY,
          ...extra,
        } as never),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    }
  });

  it.each(["", "contains space", "line\nbreak", "x".repeat(4_097)])(
    "rejects invalid API credentials without dispatch",
    (apiKey) => {
      const fetch = vi.fn<BaseRpcAnchorFetch>();
      expect(() =>
        createBaseRpcAnchorCollectorForTesting({
          ...testLiveAuthorizations(),
          apiKey,
          fetch,
        }),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CREDENTIAL" }));
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("rejects proxied, accessor-bearing, and caller-configured options", () => {
    const options = { ...testLiveAuthorizations(), apiKey: TEST_API_KEY };
    expect(() => createBaseRpcAnchorCollector(new Proxy(options, {}))).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
    const accessorOptions = { ...options };
    Object.defineProperty(accessorOptions, "apiKey", {
      enumerable: true,
      get: () => TEST_API_KEY,
    });
    expect(() => createBaseRpcAnchorCollector(accessorOptions)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
    for (const property of [
      "url",
      "method",
      "headers",
      "body",
      "chain",
      "blockTag",
      "retry",
      "fallback",
      "payment",
    ]) {
      expect(() =>
        createBaseRpcAnchorCollector({ ...options, [property]: "untrusted" } as never),
      ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    }
  });

  it("requires exact authentic attempt and runtime authorizations", () => {
    expect(() => createBaseRpcAnchorCollector({ apiKey: TEST_API_KEY } as never)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
    const validAttempt = testAttemptAuthorization();
    expect(() =>
      createBaseRpcAnchorCollector({
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
        createBaseRpcAnchorCollector({
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
      `base.rpc-anchor:${randomUUID()}:${"0".repeat(64)}`,
    ).authorization;
    const fetch = vi.fn<BaseRpcAnchorFetch>();
    const collector = createBaseRpcAnchorCollectorForTesting({
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
    const fetch = vi.fn<BaseRpcAnchorFetch>();
    const collector = createBaseRpcAnchorCollectorForTesting({
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

  it("distinguishes identical bodies from separate authorized attempts", async () => {
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
    } finally {
      first.destroy();
      second.destroy();
    }
  });
});

describe("Base RPC network trust boundary", () => {
  it.each([
    [302, "REDIRECT_REFUSED"],
    [402, "PAYMENT_REQUIRED"],
    [429, "RATE_LIMITED"],
    [401, "HTTP_STATUS"],
    [403, "HTTP_STATUS"],
    [500, "HTTP_STATUS"],
    [503, "HTTP_STATUS"],
  ] as const)("rejects HTTP %i once with %s", async (status, code) => {
    const fetch = vi.fn<BaseRpcAnchorFetch>(async () => new Response(null, { status }));
    await expect(createLiveCollector({ fetch }).collectRaw()).rejects.toMatchObject({
      code,
      details: { status },
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([
    {
      code: "UNSUPPORTED_CONTENT_ENCODING",
      headers: { "content-encoding": "gzip", "content-type": "application/json" },
      label: "compressed response",
    },
    {
      code: "UNSUPPORTED_CONTENT_TYPE",
      headers: { "content-type": "application/problem+json" },
      label: "unsupported media type",
    },
    {
      code: "RESPONSE_TOO_LARGE",
      headers: { "content-length": "17", "content-type": "application/json" },
      label: "oversized declared body",
      maxResponseBytes: 16,
    },
  ])("cancels the unread body for $label", async (fixture) => {
    const cancel = vi.fn(() => undefined);
    const body = new ReadableStream<Uint8Array>({ cancel });
    const response = new Response(body as never, { headers: fixture.headers, status: 200 });
    const fetch = vi.fn<BaseRpcAnchorFetch>(async () => response);
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
            headers: { "content-length": "3", "content-type": "application/json" },
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
          new Response(stream as never, { headers: { "content-type": "application/json" } }),
        maxResponseBytes: 16,
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
  });

  it("rejects credential echoes and redacts transport failures", async () => {
    await expect(
      createLiveCollector({
        fetch: async () => jsonResponse(JSON.stringify({ key: TEST_API_KEY })),
      }).collectRaw(),
    ).rejects.toMatchObject({ code: "CREDENTIAL_IN_RESPONSE" });

    const error = await createLiveCollector({
      fetch: async () => {
        throw new Error(`Authorization: Bearer ${TEST_API_KEY}`);
      },
    })
      .collectRaw()
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "TRANSPORT_FAILURE" });
    expect(JSON.stringify(error)).not.toContain(TEST_API_KEY);
    expect(String(error)).not.toContain(TEST_API_KEY);
  });

  it("supports abort and timeout without retry", async () => {
    const preAbortedFetch = vi.fn<BaseRpcAnchorFetch>();
    const preAborted = createLiveCollector({ fetch: preAbortedFetch });
    const controller = new AbortController();
    controller.abort();
    await expect(preAborted.collectRaw({ signal: controller.signal })).rejects.toMatchObject({
      code: "ABORTED",
    });
    expect(preAbortedFetch).not.toHaveBeenCalled();

    const timeoutFetch = vi.fn<BaseRpcAnchorFetch>(
      async (request) =>
        new Promise<Response>((_resolve, reject) => {
          request.signal.addEventListener(
            "abort",
            () => reject(new Error(`Bearer ${TEST_API_KEY}`)),
            { once: true },
          );
        }),
    );
    await expect(
      createLiveCollector({ fetch: timeoutFetch, timeoutMs: 5 }).collectRaw(),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    expect(timeoutFetch).toHaveBeenCalledOnce();
  });

  it("cancels a response that arrives after timeout", async () => {
    let resolveResponse: ((response: Response) => void) | undefined;
    const fetch = vi.fn<BaseRpcAnchorFetch>(
      () =>
        new Promise<Response>((resolve) => {
          resolveResponse = resolve;
        }),
    );
    const collection = createLiveCollector({ fetch, timeoutMs: 5 }).collectRaw();
    await expect(collection).rejects.toMatchObject({ code: "TIMEOUT" });
    const cancel = vi.fn(() => undefined);
    const body = new ReadableStream<Uint8Array>({ cancel });
    resolveResponse?.(
      new Response(body as never, { headers: { "content-type": "application/json" } }),
    );
    await vi.waitFor(() => expect(cancel).toHaveBeenCalledOnce());
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("permits exactly one authorized dispatch", async () => {
    const fetch = vi.fn<BaseRpcAnchorFetch>(async () => jsonResponse());
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
      createLiveCollector({ now: () => new Date("2026-09-05T11:59:59.999Z") }).collectRaw(),
    ).rejects.toMatchObject({ code: "CLOCK_REGRESSION" });
  });

  it("rejects malformed testing bounds before dispatch", () => {
    for (const override of [
      { timeoutMs: 0 },
      { timeoutMs: 10_001 },
      { maxResponseBytes: 0 },
      { maxResponseBytes: 1_048_577 },
    ]) {
      const fetch = vi.fn<BaseRpcAnchorFetch>();
      expect(() => createLiveCollector({ fetch, ...override })).toThrowError(
        expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
      );
      expect(fetch).not.toHaveBeenCalled();
    }
  });

  it("uses an action id that binds the exact attempt and request fingerprint", () => {
    const attempt = testAttemptAuthorization();
    const request = prepareBaseRpcAnchorCollectorRequest();
    expect(baseRpcAnchorRuntimeActionId(attempt.binding.attemptId, request.fingerprint)).toBe(
      `base.rpc-anchor:${attempt.binding.attemptId}:${request.fingerprint.slice("sha256:".length)}`,
    );
  });

  it("does not expose response bytes after explicit destruction", async () => {
    const raw = await createLiveCollector({
      fetch: async () => jsonResponse(validResponseBytes()),
    }).collectRaw();
    raw.destroy();
    raw.destroy();
    expect(() => raw.copyBytes()).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE_SCHEMA" }),
    );
  });
});
