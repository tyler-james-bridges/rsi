import { request as httpRequest } from "node:http";

import { RuntimeConflictError } from "@rsi/runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createOperatorServer,
  parseOperatorResearchProjection,
  parseOperatorRuntimeSnapshot,
  projectPublicJson,
  startOperatorServer,
  type OperatorControlCommand,
  type OperatorControlProvider,
  type OperatorEventQuery,
  type OperatorReadCanaryProvider,
  type OperatorResearchProvider,
  type OperatorRuntimeProvider,
  type OperatorSnapshotProvider,
  type RunningOperatorServer,
} from "../src/index.js";

const KEY_FIXTURE = ["key", "secret"].join("-");
const PASSWORD_FIXTURE = ["password", "secret"].join("-");
const SEED_FIXTURE = ["seed", "secret"].join("-");

const SECRETS = [
  "raw-secret",
  "byte-secret",
  "content-secret",
  KEY_FIXTURE,
  "account-secret",
  "card-secret",
  "auth-secret",
  "credential-secret",
  PASSWORD_FIXTURE,
  "api-key-secret",
  "token-secret",
  SEED_FIXTURE,
  "cookie-secret",
];

function runtimeSnapshot(mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED" = "STOPPED", revision = 1) {
  return {
    schemaVersion: 1 as const,
    mode,
    revision,
    modeChangedAt: "2026-08-23T12:00:00.000Z",
    processInstanceId: "018f102a-8f54-4a93-8cce-2461c4f28a12",
    auditHead: { sequence: revision, hash: "a".repeat(64) },
    capabilities: {
      researchCollection: mode !== "STOPPED",
      proposalPersistence: mode === "PROPOSE_ONLY",
      policyApproval: false as const,
      paidRead: false as const,
      transactionBroadcast: false as const,
      walletSign: false as const,
      executionAdapter: false as const,
      externalPublish: false as const,
    },
  };
}

function researchProposal(disposition: "abstain" | "candidate" = "candidate") {
  return {
    schemaVersion: 1 as const,
    proposalId: `rsi-proposal:${disposition}-001`,
    strategyVersion: "rsi-v0",
    createdAt: "2026-08-23T12:00:00.000Z",
    expiresAt: "2026-08-23T12:10:00.000Z",
    asset: { chainId: 8453, address: `0x${"1".repeat(40)}`, tokenId: "7" },
    evidenceIds: [`sha256:${"b".repeat(64)}`],
    provenance: {
      providerIds: ["fixture-x"],
      sourceKinds: ["x"],
      independentClusterCount: 1,
    },
    flags: {
      scam: ["identity-risk"],
      injection: ["prompt:financial-action"],
      homograph: [],
    },
    scorecard: {
      confidence: 0.72,
      marketSupport: 0.68,
      opportunity: 0.61,
      provenanceQuality: 0.8,
      risk: 0.35,
    },
    disposition:
      disposition === "candidate"
        ? ({ kind: "candidate" } as const)
        : ({ kind: "abstain", reason: "integrity_risk" } as const),
  };
}

function researchProjection() {
  return {
    schemaVersion: 1 as const,
    candidateCount: 1,
    abstentionCount: 0,
    proposals: [
      {
        schemaVersion: 1 as const,
        eventHash: "c".repeat(64),
        eventSequence: 7,
        persistedAt: "2026-08-23T12:01:00.000Z",
        proposal: researchProposal(),
      },
    ],
  };
}

const CANARY_FINGERPRINT = `sha256:${"d".repeat(64)}` as const;

function readCanaryPlan() {
  return {
    schemaVersion: 1 as const,
    planId: "x-nft-market-pulse-v1" as const,
    providerId: "x-api-v2" as const,
    operation: "x.recent-search.v1" as const,
    endpoint: "https://api.x.com/2/tweets/search/recent" as const,
    method: "GET" as const,
    sortOrder: "recency" as const,
    maximumRequests: 1 as const,
    maximumResults: 10 as const,
    maximumChargeUsdMicros: "50000" as const,
    requestFingerprint: CANARY_FINGERPRINT,
    rawContentDisposition: "encrypted_ephemeral" as const,
    automaticRetries: 0 as const,
  };
}

function readCanaryReceipt() {
  const requestId = "11111111-1111-4111-8111-111111111111";
  return {
    schemaVersion: 1 as const,
    receiptId: `x-read-canary:${requestId}`,
    planId: "x-nft-market-pulse-v1" as const,
    providerId: "x-api-v2" as const,
    requestId,
    attemptId: "22222222-2222-4222-8222-222222222222",
    requestFingerprint: CANARY_FINGERPRINT,
    outcome: "accepted" as const,
    failureCode: null,
    acquiredAt: "2026-08-25T21:00:00.000Z",
    completedAt: "2026-08-25T21:00:01.000Z",
    postCount: 3,
    byteLength: 1_024,
    hasNextPage: false,
    rateLimit: { limit: 450, remaining: 449, resetAtUnixSeconds: 1_788_000_000 },
    maximumRequests: 1 as const,
    maximumResults: 10 as const,
    maximumChargeUsdMicros: "50000" as const,
    actualChargeUsdMicros: null,
    runtime: {
      authorizationId: "33333333-3333-4333-8333-333333333333",
      eventHash: "e".repeat(64),
      eventSequence: 8,
      modeRevision: 2,
    },
    capture: { eventHash: "f".repeat(64), eventSequence: 9 },
  };
}

function readCanaryProjection(status: "completed" | "ready" | "running" = "ready") {
  return {
    schemaVersion: 1 as const,
    status,
    credentialStatus: "configured" as const,
    plan: readCanaryPlan(),
    lastReceipt: status === "completed" ? readCanaryReceipt() : null,
  };
}

function readCanaryCommand() {
  return {
    schemaVersion: 1 as const,
    planId: "x-nft-market-pulse-v1" as const,
    expectedRuntimeRevision: 2,
    requestId: "11111111-1111-4111-8111-111111111111",
    typedPlanIdAcknowledgement: "x-nft-market-pulse-v1" as const,
    oneRequestAcknowledgement: true as const,
    maximumChargeUsdMicrosAcknowledgement: "50000" as const,
  };
}

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
        privateKey: KEY_FIXTURE,
        account_number: "account-secret",
        password: PASSWORD_FIXTURE,
        openaiApiKey: "api-key-secret",
        access_token: "token-secret",
        seedPhrase: SEED_FIXTURE,
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

  async function restartWithRuntime(runtime: OperatorRuntimeProvider): Promise<void> {
    await running.close();
    running = await startOperatorServer(provider, { port: 0, runtime });
  }

  async function restartWithResearch(research: OperatorResearchProvider): Promise<void> {
    await running.close();
    running = await startOperatorServer(provider, { port: 0, research });
  }

  async function restartWithReadCanary(
    readCanary: OperatorReadCanaryProvider,
    runtime?: OperatorRuntimeProvider,
  ): Promise<void> {
    await running.close();
    running = await startOperatorServer(provider, {
      port: 0,
      readCanary,
      ...(runtime === undefined ? {} : { runtime }),
    });
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
    expect(html).toContain("Runtime console");
    expect(html).toContain("no financial authority");
    expect(html).toContain('data-runtime-action="runtime-stop"');
    expect(html).not.toContain("raw-secret");
    expect(css).toContain("prefers-reduced-motion");
    expect(javascript).toContain("textContent = JSON.stringify(summary, null, 2)");
    expect(javascript).toContain("Promise.allSettled");
    expect(javascript).toContain('byId("runtime-stop").disabled = false');
    expect(javascript).toContain('" · contract " + proposal.asset.address');
    expect(javascript).not.toContain("innerHTML");
    expect(javascript).not.toContain("window.open");
    expect(await capabilities.json()).toEqual({
      controls: {
        actions: [],
        enabled: false,
        legacy: { actions: [], enabled: false },
        runtime: { actions: [], enabled: false },
      },
    });
  });

  it("serves only a strict content-free runtime snapshot", async () => {
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
      executeRuntimeControl: vi.fn(() => runtimeSnapshot()),
      getRuntimeSnapshot: vi.fn(() => runtimeSnapshot()),
    };
    await restartWithRuntime(runtime);

    const response = await get("/api/runtime");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      financialAuthority: false,
      runtime: runtimeSnapshot(),
    });
    expect(await (await get("/api/control/capabilities")).json()).toEqual({
      controls: {
        actions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
        enabled: true,
        legacy: { actions: [], enabled: false },
        runtime: {
          actions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
          enabled: true,
        },
      },
    });
  });

  it("accepts exact runtime commands and keeps emergency stop revision-free", async () => {
    const commands: unknown[] = [];
    let snapshot = runtimeSnapshot();
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
      executeRuntimeControl(command) {
        commands.push(command);
        const nextMode =
          command.action === "runtime-stop"
            ? "STOPPED"
            : command.action === "runtime-enter-research"
              ? "RESEARCH"
              : "PROPOSE_ONLY";
        snapshot = runtimeSnapshot(nextMode, snapshot.revision + 1);
        return snapshot;
      },
      getRuntimeSnapshot: () => snapshot,
    };
    await restartWithRuntime(runtime);
    const headers = {
      "content-type": "application/json",
      origin: running.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };
    const requests = [
      {
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: "11111111-1111-4111-8111-111111111111",
      },
      {
        action: "runtime-enter-propose-only",
        expectedMode: "RESEARCH",
        expectedRevision: 2,
        requestId: "22222222-2222-4222-8222-222222222222",
      },
      {
        action: "runtime-enter-research",
        expectedMode: "PROPOSE_ONLY",
        expectedRevision: 3,
        requestId: "33333333-3333-4333-8333-333333333333",
      },
      {
        action: "runtime-stop",
        requestId: "44444444-4444-4444-8444-444444444444",
      },
    ] as const;

    for (const payload of requests) {
      const response = await fetch(`${running.origin}/api/control`, {
        body: JSON.stringify(payload),
        headers,
        method: "POST",
      });
      expect(response.status).toBe(200);
      expect((await response.json()) as unknown).toHaveProperty(
        "result.capabilities.walletSign",
        false,
      );
    }
    expect(commands).toEqual(requests);
    expect(commands.every(Object.isFrozen)).toBe(true);
    expect(commands.at(-1)).toEqual({
      action: "runtime-stop",
      requestId: "44444444-4444-4444-8444-444444444444",
    });
  });

  it("rejects malformed runtime commands before the provider is called", async () => {
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
      executeRuntimeControl: vi.fn(() => runtimeSnapshot()),
      getRuntimeSnapshot: () => runtimeSnapshot(),
    };
    await restartWithRuntime(runtime);
    const headers = {
      "content-type": "application/json",
      origin: running.origin,
      "x-rsi-operator-request": "1",
    };
    const cases = [
      { action: "runtime-stop" },
      {
        action: "runtime-stop",
        expectedRevision: 1,
        requestId: "11111111-1111-4111-8111-111111111111",
      },
      {
        action: "runtime-enter-research",
        expectedMode: "RESEARCH",
        expectedRevision: 1,
        requestId: "11111111-1111-4111-8111-111111111111",
      },
      {
        action: "runtime-enter-propose-only",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: "11111111-1111-4111-8111-111111111111",
      },
      {
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1.5,
        requestId: "11111111-1111-4111-8111-111111111111",
      },
      {
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: Number.MAX_SAFE_INTEGER + 1,
        requestId: "11111111-1111-4111-8111-111111111111",
      },
      {
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: "not-a-uuid",
      },
    ];

    for (const payload of cases) {
      const response = await fetch(`${running.origin}/api/control`, {
        body: JSON.stringify(payload),
        headers,
        method: "POST",
      });
      expect(response.status).toBe(400);
    }
    expect(runtime.executeRuntimeControl).not.toHaveBeenCalled();
  });

  it("keeps runtime stop usable when every read endpoint fails", async () => {
    const failingProvider: OperatorSnapshotProvider = {
      getSummary: vi.fn(() => Promise.reject(new Error("summary failed"))),
      listEvents: vi.fn(() => Promise.reject(new Error("events failed"))),
      getDecision: vi.fn(() => null),
    };
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-stop"],
      executeRuntimeControl: vi.fn(() => runtimeSnapshot()),
      getRuntimeSnapshot: vi.fn(() => Promise.reject(new Error("runtime read failed"))),
    };
    const research: OperatorResearchProvider = {
      getResearchProjection: vi.fn(() => Promise.reject(new Error("research read failed"))),
    };
    await running.close();
    running = await startOperatorServer(failingProvider, { port: 0, research, runtime });

    expect((await get("/api/runtime")).status).toBe(500);
    expect((await get("/api/research")).status).toBe(500);
    expect((await get("/api/summary")).status).toBe(500);
    expect((await get("/api/events")).status).toBe(500);
    const response = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-stop",
        requestId: "11111111-1111-4111-8111-111111111111",
      }),
      headers: {
        "content-type": "application/json",
        origin: running.origin,
        "x-rsi-operator-request": "1",
      },
      method: "POST",
    });
    expect(response.status).toBe(200);
    expect(runtime.executeRuntimeControl).toHaveBeenCalledOnce();
  });

  it("maps runtime transition conflicts to an opaque 409", async () => {
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-enter-research"],
      executeRuntimeControl: vi.fn(() => {
        throw new RuntimeConflictError("STALE_STATE", "secret internal state");
      }),
      getRuntimeSnapshot: () => runtimeSnapshot(),
    };
    await restartWithRuntime(runtime);
    const response = await fetch(`${running.origin}/api/control`, {
      body: JSON.stringify({
        action: "runtime-enter-research",
        expectedMode: "STOPPED",
        expectedRevision: 1,
        requestId: "11111111-1111-4111-8111-111111111111",
      }),
      headers: {
        "content-type": "application/json",
        origin: running.origin,
        "x-rsi-operator-request": "1",
      },
      method: "POST",
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: {
        code: "runtime_conflict",
        message: "Runtime mode changed; refresh and try again.",
      },
    });
  });

  it("rejects runtime projections with extra content or authority", async () => {
    const invalidSnapshots = [
      { ...runtimeSnapshot(), title: "raw-secret" },
      {
        ...runtimeSnapshot(),
        capabilities: { ...runtimeSnapshot().capabilities, walletSign: true },
      },
    ];
    for (const invalid of invalidSnapshots) {
      const runtime: OperatorRuntimeProvider = {
        supportedActions: [],
        executeRuntimeControl: vi.fn(),
        getRuntimeSnapshot: () => invalid,
      };
      await restartWithRuntime(runtime);
      const response = await get("/api/runtime");
      const body = await response.json();
      expect(response.status).toBe(500);
      expect(body).toEqual({
        error: { code: "internal_error", message: "The operator snapshot could not be read." },
      });
      expect(JSON.stringify(body)).not.toContain("raw-secret");
    }
  });

  it("serves the exact bounded content-free research projection", async () => {
    const research: OperatorResearchProvider = {
      getResearchProjection: vi.fn(() => researchProjection()),
    };
    await restartWithResearch(research);

    const response = await get("/api/research");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ research: researchProjection() });
    expect((await get("/api/research?limit=100")).status).toBe(400);
  });

  it("rejects research projections containing raw, executable, malformed, or inconsistent data", async () => {
    const valid = researchProjection();
    const invalidProjections = [
      { ...valid, raw: "raw-secret" },
      {
        ...valid,
        proposals: [
          {
            ...valid.proposals[0],
            proposal: { ...valid.proposals[0]!.proposal, calldata: "0xdeadbeef" },
          },
        ],
      },
      { ...valid, candidateCount: 0 },
      {
        ...valid,
        proposals: [
          valid.proposals[0],
          { ...valid.proposals[0], eventHash: "d".repeat(64), eventSequence: 8 },
        ],
      },
      {
        ...valid,
        proposals: [
          {
            ...valid.proposals[0],
            proposal: {
              ...valid.proposals[0]!.proposal,
              scorecard: { ...valid.proposals[0]!.proposal.scorecard, risk: 1.1 },
            },
          },
        ],
      },
    ];

    for (const invalid of invalidProjections) {
      await restartWithResearch({ getResearchProjection: () => invalid });
      const response = await get("/api/research");
      const body = await response.json();
      expect(response.status).toBe(500);
      expect(body).toEqual({
        error: { code: "internal_error", message: "The operator snapshot could not be read." },
      });
      expect(JSON.stringify(body)).not.toContain("raw-secret");
      expect(JSON.stringify(body)).not.toContain("deadbeef");
    }
  });

  it("serves only the closed Stage 1 read-canary projection", async () => {
    const readCanary: OperatorReadCanaryProvider = {
      abortActive: vi.fn(),
      executeReadCanary: vi.fn(() => readCanaryReceipt()),
      getReadCanaryProjection: vi.fn(() => readCanaryProjection("completed")),
    };
    await restartWithReadCanary(readCanary);

    const response = await get("/api/read-canary");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ readCanary: readCanaryProjection("completed") });
    expect((await get("/api/read-canary?detail=full")).status).toBe(400);

    const serialized = JSON.stringify(await (await get("/api/read-canary")).json());
    expect(serialized).not.toContain('"query"');
    expect(serialized).not.toContain('"token"');
    expect(serialized).not.toContain('"text"');
  });

  it("rejects read-canary projections with extra source material or credentials", async () => {
    const unsafeValues = [
      { ...readCanaryProjection(), query: "source-material" },
      {
        ...readCanaryProjection(),
        plan: { ...readCanaryPlan(), bearerToken: "credential-material" },
      },
      {
        ...readCanaryProjection("completed"),
        lastReceipt: { ...readCanaryReceipt(), text: "captured-material" },
      },
      {
        ...readCanaryProjection("completed"),
        lastReceipt: {
          ...readCanaryReceipt(),
          rateLimit: { limit: 0, remaining: 0, resetAtUnixSeconds: 1_788_000_000 },
        },
      },
    ];
    for (const unsafe of unsafeValues) {
      await restartWithReadCanary({
        abortActive: vi.fn(),
        executeReadCanary: vi.fn(() => readCanaryReceipt()),
        getReadCanaryProjection: () => unsafe as never,
      });
      const response = await get("/api/read-canary");
      const body = await response.json();
      expect(response.status).toBe(500);
      expect(body).toEqual({
        error: { code: "internal_error", message: "The operator snapshot could not be read." },
      });
      expect(JSON.stringify(body)).not.toContain("source-material");
      expect(JSON.stringify(body)).not.toContain("credential-material");
      expect(JSON.stringify(body)).not.toContain("captured-material");
    }
  });

  it("accepts exactly the typed, same-origin one-shot canary command", async () => {
    const commands: unknown[] = [];
    const readCanary: OperatorReadCanaryProvider = {
      abortActive: vi.fn(),
      executeReadCanary: vi.fn((command) => {
        commands.push(command);
        return readCanaryReceipt();
      }),
      getReadCanaryProjection: vi.fn(() => readCanaryProjection()),
    };
    await restartWithReadCanary(readCanary);
    const response = await fetch(`${running.origin}/api/read-canary/run`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: running.origin,
        "sec-fetch-site": "same-origin",
        "x-rsi-operator-request": "1",
      },
      body: JSON.stringify(readCanaryCommand()),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ result: readCanaryReceipt() });
    expect(commands).toEqual([readCanaryCommand()]);
    expect(commands.every(Object.isFrozen)).toBe(true);
  });

  it("rejects malformed, expanded, and cross-origin canary commands before execution", async () => {
    const executeReadCanary = vi.fn(() => readCanaryReceipt());
    await restartWithReadCanary({
      abortActive: vi.fn(),
      executeReadCanary,
      getReadCanaryProjection: vi.fn(() => readCanaryProjection()),
    });
    const validHeaders = {
      "content-type": "application/json",
      origin: running.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };
    const valid = readCanaryCommand();
    const cases: Array<Readonly<{ body: unknown; headers?: Record<string, string> }>> = [
      { body: { ...valid, query: "not-accepted" } },
      { body: { ...valid, bearerToken: "not-accepted" } },
      { body: { ...valid, oneRequestAcknowledgement: false } },
      { body: { ...valid, maximumChargeUsdMicrosAcknowledgement: 50_000 } },
      { body: { ...valid, maximumChargeUsdMicrosAcknowledgement: "50001" } },
      { body: { ...valid, typedPlanIdAcknowledgement: "yes" } },
      { body: { ...valid, expectedRuntimeRevision: 0 } },
      { body: { ...valid, requestId: "not-a-uuid" } },
      { body: valid, headers: { ...validHeaders, origin: "https://attacker.invalid" } },
      {
        body: valid,
        headers: { ...validHeaders, "sec-fetch-site": "cross-site" },
      },
    ];

    for (const testCase of cases) {
      const response = await fetch(`${running.origin}/api/read-canary/run`, {
        method: "POST",
        headers: testCase.headers ?? validHeaders,
        body: JSON.stringify(testCase.body),
      });
      expect([400, 403]).toContain(response.status);
    }
    expect(executeReadCanary).not.toHaveBeenCalled();
  });

  it("serializes canary execution and persists STOP without waiting for the pending run", async () => {
    const order: string[] = [];
    let completeCanary!: (receipt: ReturnType<typeof readCanaryReceipt>) => void;
    const pendingCanary = new Promise<ReturnType<typeof readCanaryReceipt>>((resolve) => {
      completeCanary = resolve;
    });
    const executeReadCanary = vi.fn(() => {
      order.push("canary-started");
      return pendingCanary;
    });
    const readCanary: OperatorReadCanaryProvider = {
      abortActive: vi.fn(() => {
        order.push("canary-aborted");
      }),
      executeReadCanary,
      getReadCanaryProjection: vi.fn(() => readCanaryProjection("running")),
    };
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-stop"],
      executeRuntimeControl: vi.fn(() => {
        order.push("runtime-stopped");
        return runtimeSnapshot("STOPPED", 3);
      }),
      getRuntimeSnapshot: vi.fn(() => runtimeSnapshot("RESEARCH", 2)),
    };
    await restartWithReadCanary(readCanary, runtime);
    const headers = {
      "content-type": "application/json",
      origin: running.origin,
      "sec-fetch-site": "same-origin",
      "x-rsi-operator-request": "1",
    };

    const first = fetch(`${running.origin}/api/read-canary/run`, {
      method: "POST",
      headers,
      body: JSON.stringify(readCanaryCommand()),
    });
    await vi.waitFor(() => expect(executeReadCanary).toHaveBeenCalledOnce());

    const concurrent = await fetch(`${running.origin}/api/read-canary/run`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        ...readCanaryCommand(),
        requestId: "44444444-4444-4444-8444-444444444444",
      }),
    });
    expect(concurrent.status).toBe(409);
    expect(await concurrent.json()).toMatchObject({ error: { code: "read_canary_conflict" } });

    const stopped = await fetch(`${running.origin}/api/control`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        action: "runtime-stop",
        requestId: "55555555-5555-4555-8555-555555555555",
      }),
    });
    expect(stopped.status).toBe(200);
    expect(order).toEqual(["canary-started", "canary-aborted", "runtime-stopped"]);
    expect(readCanary.abortActive).toHaveBeenCalledOnce();

    completeCanary(readCanaryReceipt());
    expect((await first).status).toBe(200);
  });

  it("keeps the Stage 0 surface unchanged when the read canary is absent", async () => {
    expect((await get("/api/read-canary")).status).toBe(501);
    const response = await fetch(`${running.origin}/api/read-canary/run`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: running.origin,
        "x-rsi-operator-request": "1",
      },
      body: JSON.stringify(readCanaryCommand()),
    });
    expect(response.status).toBe(501);
    expect(await response.json()).toMatchObject({ error: { code: "read_canary_unavailable" } });
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
        return {
          sessionId: "018f102a-8f54-4a93-8cce-2461c4f28a12",
          privateKey: KEY_FIXTURE,
        };
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
        legacy: {
          actions: ["plan", "start", "acknowledge", "abort", "close", "label", "prepare-candidate"],
          enabled: true,
        },
        runtime: { actions: [], enabled: false },
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

  it("rejects raw-server control requests received on a non-loopback socket", async () => {
    const runtime: OperatorRuntimeProvider = {
      supportedActions: ["runtime-stop"],
      executeRuntimeControl: vi.fn(() => runtimeSnapshot()),
      getRuntimeSnapshot: () => runtimeSnapshot(),
    };
    const server = createOperatorServer(provider, undefined, runtime);
    let socketLocalAddress = "0.0.0.0";
    server.prependListener("request", (request) => {
      Object.defineProperty(request.socket, "localAddress", {
        configurable: true,
        value: socketLocalAddress,
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "0.0.0.0", port: 0 }, resolve);
    });
    const address = server.address();
    expect(address).not.toBeNull();
    expect(typeof address).not.toBe("string");
    if (address === null || typeof address === "string") {
      throw new Error("Raw operator server did not bind to an IP socket.");
    }
    const origin = `http://127.0.0.1:${address.port}`;
    const payload = JSON.stringify({
      action: "runtime-stop",
      requestId: "44444444-4444-4444-8444-444444444444",
    });

    try {
      const response = await new Promise<{ body: unknown; status: number | undefined }>(
        (resolve, reject) => {
          const request = httpRequest(
            {
              host: "127.0.0.1",
              port: address.port,
              path: "/api/control",
              method: "POST",
              headers: {
                "content-length": Buffer.byteLength(payload),
                "content-type": "application/json",
                host: `127.0.0.1:${address.port}`,
                origin,
                "sec-fetch-site": "same-origin",
                "x-rsi-operator-request": "1",
              },
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
          request.end(payload);
        },
      );

      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({
        error: { code: "loopback_socket_required" },
      });
      expect(runtime.executeRuntimeControl).not.toHaveBeenCalled();

      socketLocalAddress = "::ffff:127.0.0.1";
      const health = await fetch(`${origin}/health`);
      expect(health.status).toBe(200);
      expect(await health.json()).toEqual({ status: "ok" });
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
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

  it("drops proxy values without invoking reflective traps", () => {
    const getPrototypeOf = vi.fn(() => {
      throw new Error("must not run");
    });
    const ownKeys = vi.fn(() => {
      throw new Error("must not run");
    });
    const proxy = new Proxy({ safe: true }, { getPrototypeOf, ownKeys });

    expect(projectPublicJson(proxy)).toBeNull();
    expect(projectPublicJson({ nested: proxy, safe: true })).toEqual({ safe: true });
    expect(getPrototypeOf).not.toHaveBeenCalled();
    expect(ownKeys).not.toHaveBeenCalled();
  });
});

describe("runtime snapshot projection", () => {
  it("returns a deeply frozen closed snapshot", () => {
    const parsed = parseOperatorRuntimeSnapshot(runtimeSnapshot("PROPOSE_ONLY", 7));

    expect(parsed).toEqual(runtimeSnapshot("PROPOSE_ONLY", 7));
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.auditHead)).toBe(true);
    expect(Object.isFrozen(parsed.capabilities)).toBe(true);
  });

  it("rejects proxies, accessors, inconsistent modes, and noncanonical fields", () => {
    const accessor = { ...runtimeSnapshot() } as Record<string, unknown>;
    Object.defineProperty(accessor, "processInstanceId", {
      enumerable: true,
      get: () => "018f102a-8f54-4a93-8cce-2461c4f28a12",
    });
    const prototypeTrap = vi.fn(() => {
      throw new Error("must not run");
    });
    const trappedProxy = new Proxy(runtimeSnapshot(), { getPrototypeOf: prototypeTrap });
    const cases = [
      trappedProxy,
      accessor,
      { ...runtimeSnapshot(), revision: 0 },
      { ...runtimeSnapshot(), modeChangedAt: "2026-08-23T12:00:00Z" },
      { ...runtimeSnapshot(), processInstanceId: "../../runtime" },
      { ...runtimeSnapshot(), auditHead: { sequence: 1, hash: "A".repeat(64) } },
      {
        ...runtimeSnapshot(),
        capabilities: { ...runtimeSnapshot().capabilities, proposalPersistence: true },
      },
      {
        ...runtimeSnapshot(),
        capabilities: { ...runtimeSnapshot().capabilities, externalPublish: true },
      },
    ];

    for (const value of cases) {
      expect(() => parseOperatorRuntimeSnapshot(value)).toThrow(/invalid|disagree/i);
    }
    expect(prototypeTrap).not.toHaveBeenCalled();
  });
});

describe("research projection", () => {
  it("returns a deeply frozen closed proposal projection", () => {
    const parsed = parseOperatorResearchProjection(researchProjection());

    expect(parsed).toEqual(researchProjection());
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.proposals)).toBe(true);
    expect(Object.isFrozen(parsed.proposals[0])).toBe(true);
    expect(Object.isFrozen(parsed.proposals[0]?.proposal)).toBe(true);
    expect(Object.isFrozen(parsed.proposals[0]?.proposal.scorecard)).toBe(true);
  });

  it("rejects proxy and accessor-bearing proposal trees without invoking accessors", () => {
    const accessor = { ...researchProposal() } as Record<string, unknown>;
    const getter = vi.fn(() => "rsi-proposal:accessor");
    Object.defineProperty(accessor, "proposalId", { enumerable: true, get: getter });
    const base = researchProjection();

    const prototypeTrap = vi.fn(() => {
      throw new Error("must not run");
    });
    expect(() =>
      parseOperatorResearchProjection(new Proxy(base, { getPrototypeOf: prototypeTrap })),
    ).toThrow(/invalid/i);
    expect(() =>
      parseOperatorResearchProjection({
        ...base,
        proposals: [{ ...base.proposals[0], proposal: accessor }],
      }),
    ).toThrow(/invalid/i);
    expect(getter).not.toHaveBeenCalled();
    expect(prototypeTrap).not.toHaveBeenCalled();
  });
});
