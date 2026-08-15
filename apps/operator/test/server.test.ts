import { request as httpRequest } from "node:http";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  projectPublicJson,
  startOperatorServer,
  type OperatorControlCommand,
  type OperatorControlProvider,
  type OperatorEventQuery,
  type OperatorSnapshotProvider,
  type RunningOperatorServer,
} from "../src/index.js";

const SECRETS = [
  "raw-secret",
  "byte-secret",
  "content-secret",
  "key-secret",
  "account-secret",
  "card-secret",
  "auth-secret",
  "credential-secret",
  "password-secret",
  "api-key-secret",
  "token-secret",
  "seed-secret",
  "cookie-secret",
];

function assertNoSensitiveFields(body: unknown): void {
  const serialized = JSON.stringify(body);
  for (const forbidden of [
    '"raw"',
    '"bytes"',
    '"content"',
    '"privateKey"',
    '"accountNumber"',
    '"cardNumber"',
    '"authorization"',
    '"credentials"',
    '"private_key"',
    '"password"',
    '"openaiApiKey"',
    '"access_token"',
    '"seedPhrase"',
    '"cookie"',
  ]) {
    expect(serialized).not.toContain(forbidden);
  }
  for (const secret of SECRETS) expect(serialized).not.toContain(secret);
}

describe("operator HTTP API", () => {
  let running: RunningOperatorServer;
  let lastQuery: OperatorEventQuery | undefined;
  let requestedDecisionId: string | undefined;

  const provider: OperatorSnapshotProvider = {
    getSummary: vi.fn(() => ({
      service: "rsi",
      contentHash: "sha256:safe",
      raw: "raw-secret",
      nested: {
        healthy: true,
        privateKey: "key-secret",
        account_number: "account-secret",
        password: "password-secret",
        openaiApiKey: "api-key-secret",
        access_token: "token-secret",
        seedPhrase: "seed-secret",
        cookie: "cookie-secret",
      },
    })),
    listEvents: vi.fn((query) => {
      lastQuery = query;
      return {
        items: Array.from({ length: 12 }, (_, index) => ({
          id: `event-${index}`,
          type: "observation.accepted",
          payload: {
            visible: index,
            content: "content-secret",
            deeper: { credentials: "credential-secret", authorization: "auth-secret" },
          },
        })),
        nextCursor: "seq:12",
      };
    }),
    getDecision: vi.fn((id) => {
      requestedDecisionId = id;
      return id === "missing"
        ? null
        : {
            id,
            outcome: "approved",
            audit: {
              visible: "policy-v1",
              bytes: "byte-secret",
              cardNumber: "card-secret",
            },
          };
    }),
  };

  beforeEach(async () => {
    lastQuery = undefined;
    requestedDecisionId = undefined;
    running = await startOperatorServer(provider, { port: 0 });
  });

  afterEach(async () => {
    await running.close();
    vi.clearAllMocks();
  });

  async function get(path: string): Promise<Response> {
    return fetch(`${running.origin}${path}`);
  }

  async function restartWithControls(controls: OperatorControlProvider): Promise<void> {
    await running.close();
    running = await startOperatorServer(provider, { controls, port: 0 });
  }

  it("binds to loopback by default and serves JSON health with defensive headers", async () => {
    expect(running.host).toBe("127.0.0.1");
    expect(running.port).toBeGreaterThan(0);

    const response = await get("/health");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("serves a fixed loopback dashboard and same-origin assets without embedding provider data", async () => {
    const [page, stylesheet, script, capabilities] = await Promise.all([
      get("/"),
      get("/operator.css"),
      get("/operator.js"),
      get("/api/control/capabilities"),
    ]);
    const html = await page.text();
    const css = await stylesheet.text();
    const javascript = await script.text();

    expect(page.status).toBe(200);
    expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(page.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(page.headers.get("content-security-policy")).not.toContain("unsafe-inline");
    expect(html).toContain("Observer console");
    expect(html).toContain("no financial authority");
    expect(html).not.toContain("raw-secret");
    expect(css).toContain("prefers-reduced-motion");
    expect(javascript).toContain("textContent = JSON.stringify(summary, null, 2)");
    expect(javascript).not.toContain("innerHTML");
    expect(await capabilities.json()).toEqual({ controls: { actions: [], enabled: false } });
  });

  it("accepts only the closed same-origin control vocabulary when controls are configured", async () => {
    const commands: OperatorControlCommand[] = [];
    const controls: OperatorControlProvider = {
      supportedActions: [
        "plan",
        "start",
        "acknowledge",
        "abort",
        "close",
        "label",
        "prepare-candidate",
      ],
      executeControl(command) {
        commands.push(command);
        return { sessionId: "018f102a-8f54-4a93-8cce-2461c4f28a12", privateKey: "key-secret" };
      },
    };
    await restartWithControls(controls);
    const originHeaders = {
      "content-type": "application/json",
      origin: running.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };
    const sessionId = "018f102a-8f54-4a93-8cce-2461c4f28a12";
    const payloads = [
      { action: "plan", sessionId },
      {
        action: "start",
        observerOnlyAcknowledgement: true,
        sessionId,
        typedSessionIdAcknowledgement: sessionId,
      },
      { action: "acknowledge", checkpoint: "minute-45", sessionId },
      { action: "acknowledge", checkpoint: "minute-90", sessionId },
      { action: "close", sessionId },
      { action: "abort", sessionId },
      { action: "label", findingId: "finding-1", label: "useful" },
      { action: "prepare-candidate", findingId: "finding-1" },
    ];

    for (const payload of payloads) {
      const response = await fetch(`${running.origin}/api/control`, {
        body: JSON.stringify(payload),
        headers: originHeaders,
        method: "POST",
      });
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body).toEqual({ result: { sessionId } });
      assertNoSensitiveFields(body);
    }

    expect(commands).toEqual(payloads);
    expect(commands.every(Object.isFrozen)).toBe(true);
    expect(await (await get("/api/control/capabilities")).json()).toEqual({
      controls: {
        actions: ["plan", "start", "acknowledge", "abort", "close", "label", "prepare-candidate"],
        enabled: true,
      },
    });
  });

  it("rejects cross-origin, non-JSON, malformed, oversized, and unsupported control requests", async () => {
    const controls: OperatorControlProvider = {
      supportedActions: [
        "plan",
        "start",
        "acknowledge",
        "abort",
        "close",
        "label",
        "prepare-candidate",
      ],
      executeControl: vi.fn(() => ({ ok: true })),
    };
    await restartWithControls(controls);
    const sessionId = "018f102a-8f54-4a93-8cce-2461c4f28a12";
    const validHeaders = {
      "content-type": "application/json",
      origin: running.origin,
      "x-rsi-operator-request": "1",
    };
    const cases: Array<Readonly<{ body: string; headers: Record<string, string> }>> = [
      {
        body: JSON.stringify({ action: "abort", sessionId }),
        headers: { ...validHeaders, origin: "https://example.test" },
      },
      {
        body: JSON.stringify({ action: "abort", sessionId }),
        headers: { "content-type": "application/json", origin: running.origin },
      },
      {
        body: JSON.stringify({ action: "abort", sessionId }),
        headers: { ...validHeaders, "content-type": "text/plain" },
      },
      { body: "{", headers: validHeaders },
      {
        body: JSON.stringify({
          action: "start",
          observerOnlyAcknowledgement: false,
          sessionId,
          typedSessionIdAcknowledgement: sessionId,
        }),
        headers: validHeaders,
      },
      {
        body: JSON.stringify({ action: "abort", sessionId, policy: "edit" }),
        headers: validHeaders,
      },
      { body: JSON.stringify({ action: "edit-policy", sessionId }), headers: validHeaders },
      {
        body: JSON.stringify({ action: "label", findingId: "../private", label: "useful" }),
        headers: validHeaders,
      },
      {
        body: JSON.stringify({ action: "plan", sessionId, padding: "x".repeat(4_200) }),
        headers: validHeaders,
      },
    ];

    for (const item of cases) {
      const response = await fetch(`${running.origin}/api/control`, {
        body: item.body,
        headers: item.headers,
        method: "POST",
      });
      expect([400, 403, 413, 415]).toContain(response.status);
    }
    expect(controls.executeControl).not.toHaveBeenCalled();
  });

  it("keeps the dashboard read-only when no control provider is configured", async () => {
    const response = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({
        action: "plan",
        sessionId: "018f102a-8f54-4a93-8cce-2461c4f28a12",
      }),
      headers: {
        "content-type": "application/json",
        origin: running.origin,
        "x-rsi-operator-request": "1",
      },
      method: "POST",
    });

    expect(response.status).toBe(501);
    expect(await response.json()).toMatchObject({ error: { code: "controls_unavailable" } });
  });

  it("returns a deeply projected public summary", async () => {
    const response = await get("/api/summary");
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      summary: {
        service: "rsi",
        contentHash: "sha256:safe",
        nested: { healthy: true },
      },
    });
    assertNoSensitiveFields(body);
  });

  it("validates filters, passes a bounded query, truncates results, and redacts events", async () => {
    const response = await get(
      "/api/events?limit=5&cursor=seq:7&type=observation.accepted&decisionId=decision-1" +
        "&since=2026-08-10T01%3A02%3A03Z&until=2026-08-11T01%3A02%3A03.123Z",
    );
    const body = (await response.json()) as {
      events: unknown[];
      page: { limit: number; nextCursor: string | null };
    };

    expect(response.status).toBe(200);
    expect(lastQuery).toEqual({
      limit: 5,
      cursor: "seq:7",
      type: "observation.accepted",
      decisionId: "decision-1",
      since: "2026-08-10T01:02:03.000Z",
      until: "2026-08-11T01:02:03.123Z",
    });
    expect(body.events).toHaveLength(5);
    expect(body.page).toEqual({ limit: 5, nextCursor: "seq:12" });
    assertNoSensitiveFields(body);
  });

  it("uses a conservative default event limit", async () => {
    const response = await get("/api/events");

    expect(response.status).toBe(200);
    expect(lastQuery).toEqual({ limit: 50 });
  });

  it.each([
    "/api/events?limit=0",
    "/api/events?limit=101",
    "/api/events?limit=1.5",
    "/api/events?limit=1&limit=2",
    "/api/events?cursor=not%20safe",
    "/api/events?cursor=event-7",
    "/api/events?type=%24where",
    "/api/events?decisionId=../../secret",
    "/api/events?since=yesterday",
    "/api/events?since=2026-02-31T00%3A00%3A00Z",
    "/api/events?since=2026-08-12T00%3A00%3A00Z&until=2026-08-11T00%3A00%3A00Z",
    "/api/events?unknown=value",
  ])("rejects unsafe or out-of-bounds event queries: %s", async (path) => {
    const response = await get(path);

    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(await response.json()).toMatchObject({ error: { code: "invalid_request" } });
  });

  it("returns a projected decision by validated id", async () => {
    const response = await get("/api/decisions/decision-7");
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(requestedDecisionId).toBe("decision-7");
    expect(body).toEqual({
      decision: {
        id: "decision-7",
        outcome: "approved",
        audit: { visible: "policy-v1" },
      },
    });
    assertNoSensitiveFields(body);
  });

  it("returns JSON 404 responses for missing decisions and unknown routes", async () => {
    const missingDecision = await get("/api/decisions/missing");
    const missingRoute = await get("/not-here");

    expect(missingDecision.status).toBe(404);
    expect(await missingDecision.json()).toMatchObject({ error: { code: "not_found" } });
    expect(missingRoute.status).toBe(404);
    expect(await missingRoute.json()).toMatchObject({ error: { code: "not_found" } });
  });

  it("rejects non-GET methods with JSON, 405, and an Allow header", async () => {
    const response = await fetch(`${running.origin}/api/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ authorization: "auth-secret" }),
    });

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(await response.json()).toMatchObject({ error: { code: "method_not_allowed" } });
  });

  it("rejects DNS-rebinding Host headers and non-loopback bind requests", async () => {
    const response = await new Promise<{ body: unknown; status: number | undefined }>(
      (resolve, reject) => {
        const request = httpRequest(
          {
            host: "127.0.0.1",
            port: running.port,
            path: "/api/summary",
            headers: { host: "attacker.example" },
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
            incoming.on("end", () =>
              resolve({
                status: incoming.statusCode,
                body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown,
              }),
            );
          },
        );
        request.on("error", reject);
        request.end();
      },
    );

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: { code: "invalid_host" } });
    await expect(startOperatorServer(provider, { host: "0.0.0.0", port: 0 })).rejects.toThrow(
      /loopback/,
    );
  });

  it("returns an opaque JSON error when the provider throws", async () => {
    vi.mocked(provider.getSummary).mockRejectedValueOnce(
      new Error("credentials=credential-secret privateKey=key-secret"),
    );

    const response = await get("/api/summary");
    const body = await response.json();

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: { code: "internal_error", message: "The operator snapshot could not be read." },
    });
    assertNoSensitiveFields(body);
  });
});

describe("public JSON projection", () => {
  it("drops sensitive variants, accessors, binary values, and cycles", () => {
    const cyclic: Record<string, unknown> = { safe: true };
    cyclic.self = cyclic;
    Object.defineProperty(cyclic, "content", {
      enumerable: true,
      get: () => {
        throw new Error("must not run");
      },
    });

    expect(
      projectPublicJson({
        cyclic,
        private_key: "key-secret",
        binary: Buffer.from("byte-secret"),
        valid: 7n,
      }),
    ).toEqual({ cyclic: { safe: true }, valid: "7" });
  });
});
