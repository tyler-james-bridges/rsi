import { randomBytes, randomUUID } from "node:crypto";

import {
  SqliteOperationsStore,
  type NetworkAttemptAuthorization,
  type ResearchLane,
  type ResearchOperation,
  type SourcePlane,
} from "@rsi/operations";
import { SqliteRuntimeController, type RuntimeBoundaryAuthorization } from "@rsi/runtime";
import { afterAll } from "vitest";

import {
  OPENSEA_TRENDING_RESERVED_ATOMIC,
  openSeaTrendingRuntimeActionId,
  prepareOpenSeaTrendingCollectorRequest,
} from "../src/index.js";
import {
  createOpenSeaTrendingCollectorForTesting,
  type OpenSeaTrendingFetch,
} from "../src/testing.js";

export const TEST_API_KEY = "offline-opensea-api-key-never-persist-0123456789";
export const TEST_RATE_LIMIT_HEADERS = Object.freeze({
  "x-ratelimit-limit": "100",
  "x-ratelimit-remaining": "99",
  "x-ratelimit-reset": "1787685600",
});
export const ACQUIRED_AT = "2026-08-25T19:20:21.123Z";
export const FIXED_CLOCK = (): Date => new Date(ACQUIRED_AT);
const authorizationStores: SqliteOperationsStore[] = [];
const runtimeControllers: SqliteRuntimeController[] = [];

afterAll(() => {
  for (const store of authorizationStores.splice(0)) store.close();
  for (const runtime of runtimeControllers.splice(0)) runtime.close();
});

export function testAttemptAuthorization(
  options: Readonly<{
    lane?: ResearchLane;
    operation?: ResearchOperation;
    reservedAtomic?: string;
    sourcePlane?: SourcePlane;
  }> = {},
): NetworkAttemptAuthorization {
  const store = new SqliteOperationsStore(
    { path: ":memory:", stateKey: randomBytes(32) },
    { clock: () => ACQUIRED_AT, monotonicClock: () => 1_000 },
  );
  authorizationStores.push(store);
  const budgetId = randomUUID();
  const permit = SqliteOperationsStore.createAttemptPermit();
  const reservedAtomic = options.reservedAtomic ?? OPENSEA_TRENDING_RESERVED_ATOMIC;
  store.createBudget({
    budgetId,
    createdAt: "2026-08-25T19:00:00.000Z",
    currency: "USD_MICRO",
    endsAt: "2026-08-25T21:00:00.000Z",
    maxAtomic: reservedAtomic,
    maxAttempts: 1,
    profile: "canary",
    startsAt: "2026-08-25T19:00:00.000Z",
  });
  store.reserveAttempt({
    attemptId: permit.attemptId,
    authorizationExpiresAt: "2026-08-25T19:20:51.123Z",
    budgetId,
    createdAt: "2026-08-25T19:00:00.000Z",
    idempotencyKey: `test:${permit.attemptId}`,
    lane: options.lane ?? "marketplace",
    operation: options.operation ?? "opensea.trending-collections.v1",
    permitToken: permit.token,
    reservedAtomic,
    sessionId: randomUUID(),
    sourcePlane: options.sourcePlane ?? "marketplace",
  });
  return store.createNetworkAttemptAuthorization(permit);
}

export function testRuntimeAuthorizationFixture(
  attemptAuthorization: NetworkAttemptAuthorization,
  actionId = openSeaTrendingRuntimeActionId(
    attemptAuthorization.binding.attemptId,
    prepareOpenSeaTrendingCollectorRequest().fingerprint,
  ),
): Readonly<{
  authorization: RuntimeBoundaryAuthorization<"research_collection">;
  runtime: SqliteRuntimeController;
}> {
  const runtime = SqliteRuntimeController.open(
    { path: ":memory:", openedAt: ACQUIRED_AT, processInstanceId: randomUUID() },
    { clock: () => ACQUIRED_AT, monotonicClock: () => 1_000 },
  );
  runtimeControllers.push(runtime);
  runtime.transition({
    expectedMode: "STOPPED",
    expectedRevision: 1,
    occurredAt: ACQUIRED_AT,
    requestId: randomUUID(),
    targetMode: "RESEARCH",
  });
  return Object.freeze({
    authorization: runtime.requestBoundaryAuthorization({
      actionId,
      authorizationId: randomUUID(),
      boundary: "research_collection",
    }),
    runtime,
  });
}

export function testLiveAuthorizations(): Readonly<{
  attemptAuthorization: NetworkAttemptAuthorization;
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">;
}> {
  const attemptAuthorization = testAttemptAuthorization();
  return Object.freeze({
    attemptAuthorization,
    runtimeAuthorization: testRuntimeAuthorizationFixture(attemptAuthorization).authorization,
  });
}

export function validCollection(index = 0): Record<string, unknown> {
  const suffix = (index + 1).toString(16).padStart(40, "0");
  return {
    collection: `fictional-base-collection-${index + 1}`,
    collection_offers_enabled: true,
    contracts: [{ address: `0x${suffix}`, chain: "base" }],
    is_disabled: false,
    is_nsfw: false,
    name: `Untrusted collection name ${index + 1}`,
    opensea_url: `https://opensea.io/collection/fictional-base-collection-${index + 1}`,
    safelist_status: "verified",
    trait_offers_enabled: true,
  };
}

export function validResponseObject(
  count = 2,
  options: Readonly<{ next?: string; hostileName?: string }> = {},
): Record<string, unknown> {
  const collections = Array.from({ length: count }, (_, index) => validCollection(index));
  if (options.hostileName !== undefined && collections[0] !== undefined) {
    collections[0].name = options.hostileName;
  }
  return {
    collections,
    ...(options.next === undefined ? {} : { next: options.next }),
  };
}

export function validResponseBytes(): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(validResponseObject()));
}

export function jsonResponse(
  body: ConstructorParameters<typeof Response>[0] = validResponseBytes(),
  init: ResponseInit = {},
): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "application/json; charset=utf-8");
  if (
    !headers.has("x-ratelimit-limit") &&
    !headers.has("x-ratelimit-remaining") &&
    !headers.has("x-ratelimit-reset")
  ) {
    for (const [name, value] of Object.entries(TEST_RATE_LIMIT_HEADERS)) headers.set(name, value);
  }
  return new Response(body, { ...init, headers, status: init.status ?? 200 });
}

export function createLiveCollector(options: Record<string, unknown> = {}) {
  return createOpenSeaTrendingCollectorForTesting({
    ...testLiveAuthorizations(),
    apiKey: TEST_API_KEY,
    fetch: (async () => jsonResponse()) satisfies OpenSeaTrendingFetch,
    now: FIXED_CLOCK,
    ...options,
  } as never);
}
