import { randomBytes, randomUUID } from "node:crypto";

import {
  SqliteOperationsStore,
  type NetworkAttemptAuthorization,
  type ResearchOperation,
  type SourcePlane,
} from "@rsi/operations";
import { SqliteRuntimeController, type RuntimeBoundaryAuthorization } from "@rsi/runtime";
import { afterAll } from "vitest";

import { prepareRecentSearchRequest, xRecentSearchRuntimeActionId } from "../src/index.js";
import { createXRecentSearchCollectorForTesting, type XRecentSearchFetch } from "../src/testing.js";

export const TEST_BEARER_TOKEN = "test-bearer-token-never-persist-0123456789";
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
  store.createBudget({
    budgetId,
    createdAt: "2026-08-25T19:00:00.000Z",
    currency: "USD_MICRO",
    endsAt: "2026-08-25T21:00:00.000Z",
    maxAtomic: "50000",
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
    lane: "official",
    operation: options.operation ?? "x.recent-search.v1",
    permitToken: permit.token,
    reservedAtomic: options.reservedAtomic ?? "50000",
    sessionId: randomUUID(),
    sourcePlane: options.sourcePlane ?? "social",
  });
  return store.createNetworkAttemptAuthorization(permit);
}

export function testRuntimeAuthorization(
  attemptAuthorization: NetworkAttemptAuthorization,
  query: string,
): RuntimeBoundaryAuthorization<"research_collection"> {
  return testRuntimeAuthorizationFixture(attemptAuthorization, query).authorization;
}

export function testRuntimeAuthorizationFixture(
  attemptAuthorization: NetworkAttemptAuthorization,
  query: string,
): Readonly<{
  authorization: RuntimeBoundaryAuthorization<"research_collection">;
  runtime: SqliteRuntimeController;
}> {
  const runtime = SqliteRuntimeController.open(
    {
      path: ":memory:",
      openedAt: ACQUIRED_AT,
      processInstanceId: randomUUID(),
    },
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
  const fingerprint = prepareRecentSearchRequest({ query }).fingerprint;
  const authorization = runtime.requestBoundaryAuthorization({
    actionId: xRecentSearchRuntimeActionId(attemptAuthorization.binding.attemptId, fingerprint),
    authorizationId: randomUUID(),
    boundary: "research_collection",
  });
  return Object.freeze({ authorization, runtime });
}

export function testLiveAuthorizations(query: string): Readonly<{
  attemptAuthorization: NetworkAttemptAuthorization;
  runtimeAuthorization: RuntimeBoundaryAuthorization<"research_collection">;
}> {
  const attemptAuthorization = testAttemptAuthorization();
  return Object.freeze({
    attemptAuthorization,
    runtimeAuthorization: testRuntimeAuthorization(attemptAuthorization, query),
  });
}

export function validResponseObject(): {
  data: Array<{
    id: string;
    text: string;
  }>;
  meta: {
    result_count: number;
    newest_id: string;
    oldest_id: string;
    next_token: string;
  };
} {
  return {
    data: [
      {
        id: "1900000000000000002",
        text: "A fictional second post for an offline fixture.",
      },
      {
        id: "1900000000000000001",
        text: "A fictional first post for an offline fixture.",
      },
    ],
    meta: {
      result_count: 2,
      newest_id: "1900000000000000002",
      oldest_id: "1900000000000000001",
      next_token: "ABC_123",
    },
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
  return new Response(body, { ...init, headers, status: init.status ?? 200 });
}

export async function quarantineObject(value: unknown) {
  const fetch: XRecentSearchFetch = async () => jsonResponse(JSON.stringify(value));
  const authorizations = testLiveAuthorizations("fictional evidence");
  return createXRecentSearchCollectorForTesting({
    ...authorizations,
    bearerToken: TEST_BEARER_TOKEN,
    fetch,
    now: FIXED_CLOCK,
  }).collectRaw({ query: "fictional evidence" });
}
