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
  BASE_RPC_ANCHOR_RESERVED_ATOMIC,
  baseRpcAnchorRuntimeActionId,
  prepareBaseRpcAnchorCollectorRequest,
} from "../src/index.js";
import { createBaseRpcAnchorCollectorForTesting, type BaseRpcAnchorFetch } from "../src/testing.js";

export const TEST_API_KEY = "offline-alchemy-api-key-never-persist-0123456789";
export const ACQUIRED_AT = "2026-09-05T12:00:00.000Z";
export const FINALIZED_BLOCK_AT = "2026-09-05T11:30:00.000Z";
export const BLOCK_HASH = `0x${"11".repeat(32)}`;
export const PARENT_HASH = `0x${"22".repeat(32)}`;
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
  const reservedAtomic = options.reservedAtomic ?? BASE_RPC_ANCHOR_RESERVED_ATOMIC;
  store.createBudget({
    budgetId,
    createdAt: "2026-09-05T11:00:00.000Z",
    currency: "USD_MICRO",
    endsAt: "2026-09-05T13:00:00.000Z",
    maxAtomic: reservedAtomic,
    maxAttempts: 1,
    profile: "canary",
    startsAt: "2026-09-05T11:00:00.000Z",
  });
  store.reserveAttempt({
    attemptId: permit.attemptId,
    authorizationExpiresAt: "2026-09-05T12:00:30.000Z",
    budgetId,
    createdAt: "2026-09-05T11:00:00.000Z",
    idempotencyKey: `test:${permit.attemptId}`,
    lane: options.lane ?? "contract",
    operation: options.operation ?? "alchemy.json-rpc.v1",
    permitToken: permit.token,
    reservedAtomic,
    sessionId: randomUUID(),
    sourcePlane: options.sourcePlane ?? "canonical_chain",
  });
  return store.createNetworkAttemptAuthorization(permit);
}

export function testRuntimeAuthorizationFixture(
  attemptAuthorization: NetworkAttemptAuthorization,
  actionId = baseRpcAnchorRuntimeActionId(
    attemptAuthorization.binding.attemptId,
    prepareBaseRpcAnchorCollectorRequest().fingerprint,
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

function hexTimestamp(timestamp: string): string {
  return `0x${Math.floor(Date.parse(timestamp) / 1_000).toString(16)}`;
}

export function validResponseObject(): unknown[] {
  const root = `0x${"33".repeat(32)}`;
  return [
    { id: "rsi-base-chain-id-v1", jsonrpc: "2.0", result: "0x2105" },
    {
      id: "rsi-base-finalized-block-v1",
      jsonrpc: "2.0",
      result: {
        baseFeePerGas: "0x1",
        blobGasUsed: "0x0",
        difficulty: "0x0",
        excessBlobGas: "0x0",
        extraData: "0x",
        gasLimit: "0x1c9c380",
        gasUsed: "0x5208",
        hash: BLOCK_HASH,
        logsBloom: `0x${"00".repeat(256)}`,
        miner: `0x${"44".repeat(20)}`,
        mixHash: root,
        nonce: "0x0000000000000000",
        number: "0x1234abcd",
        parentBeaconBlockRoot: root,
        parentHash: PARENT_HASH,
        receiptsRoot: root,
        requestsHash: root,
        sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        size: "0x200",
        stateRoot: root,
        timestamp: hexTimestamp(FINALIZED_BLOCK_AT),
        totalDifficulty: "0x0",
        transactions: [],
        transactionsRoot: root,
        uncles: [],
        withdrawals: [],
        withdrawalsRoot: root,
      },
    },
  ];
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

export function createLiveCollector(options: Record<string, unknown> = {}) {
  return createBaseRpcAnchorCollectorForTesting({
    ...testLiveAuthorizations(),
    apiKey: TEST_API_KEY,
    fetch: (async () => jsonResponse()) satisfies BaseRpcAnchorFetch,
    now: FIXED_CLOCK,
    ...options,
  } as never);
}
