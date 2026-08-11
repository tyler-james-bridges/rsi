import { request as httpRequest } from "node:http";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  projectPublicJson,
  startOperatorServer,
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
