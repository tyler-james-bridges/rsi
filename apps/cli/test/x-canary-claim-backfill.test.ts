import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createDarwinOneShotClaimHostForTesting,
  type OneShotClaimCommandRequest,
} from "@rsi/credential-host/one-shot-claim-testing";
import {
  X_READ_CANARY_PLAN_ID,
  X_READ_CANARY_PROVIDER_ID,
  X_READ_CANARY_REQUEST_FINGERPRINT,
} from "@rsi/read-canary";
import { SqliteEventStore } from "@rsi/store";
import { afterEach, describe, expect, it, vi } from "vitest";

import { backfillXCanaryClaimWithHost } from "../src/x-canary-claim-backfill-core.js";
import {
  parseXCanaryClaimBackfillAcknowledgement,
  xCanaryClaimBackfillUsage,
} from "../src/x-canary-claim-backfill-options.js";

const REQUEST_ID = "11111111-1111-4111-8111-111111111111";
const ATTEMPT_ID = "22222222-2222-4222-8222-222222222222";
const BUDGET_ID = "33333333-3333-4333-8333-333333333333";
const AUTHORIZATION_ID = "44444444-4444-4444-8444-444444444444";
const PROCESS_ID = "55555555-5555-4555-8555-555555555555";
const PREPARED_AT = "2026-08-26T04:45:00.000Z";
const COMPLETED_AT = "2026-08-26T04:45:01.000Z";
let directory: string | undefined;
let eventStore: SqliteEventStore | undefined;

afterEach(async () => {
  eventStore?.close();
  eventStore = undefined;
  if (directory !== undefined) {
    await rm(directory, { force: true, recursive: true });
    directory = undefined;
  }
});

async function openEventStore(): Promise<SqliteEventStore> {
  directory = await mkdtemp(join(tmpdir(), "rsi-x-claim-backfill-"));
  eventStore = new SqliteEventStore(join(directory, "events.sqlite"));
  return eventStore;
}

function appendCompletedReceipt(store: SqliteEventStore): void {
  store.append({
    aggregateId: "read-canary:x",
    idempotencyKey: "x-read-canary-prepared-v1:singleton",
    occurredAt: PREPARED_AT,
    payload: {
      schemaVersion: 1,
      planId: X_READ_CANARY_PLAN_ID,
      providerId: X_READ_CANARY_PROVIDER_ID,
      requestId: REQUEST_ID,
      attemptId: ATTEMPT_ID,
      budgetId: BUDGET_ID,
      expectedRuntimeRevision: 2,
      runtimeAuthorizationId: AUTHORIZATION_ID,
      runtimeProcessInstanceId: PROCESS_ID,
      requestFingerprint: X_READ_CANARY_REQUEST_FINGERPRINT,
      preparedAt: PREPARED_AT,
      expiresAt: "2026-08-26T04:46:00.000Z",
      maximumRequests: 1,
      maximumResults: 10,
      maximumChargeUsdMicros: "50000",
    },
    type: "x.read-canary.prepared.v1",
  });
  store.append({
    aggregateId: "read-canary:x",
    idempotencyKey: `x-read-canary-receipt-v1:${REQUEST_ID}`,
    occurredAt: COMPLETED_AT,
    payload: {
      schemaVersion: 1,
      receiptId: `x-read-canary:${REQUEST_ID}`,
      planId: X_READ_CANARY_PLAN_ID,
      providerId: X_READ_CANARY_PROVIDER_ID,
      requestId: REQUEST_ID,
      attemptId: ATTEMPT_ID,
      requestFingerprint: X_READ_CANARY_REQUEST_FINGERPRINT,
      outcome: "accepted",
      failureCode: null,
      acquiredAt: PREPARED_AT,
      completedAt: COMPLETED_AT,
      postCount: 10,
      byteLength: 2_739,
      hasNextPage: true,
      rateLimit: { limit: 450, remaining: 449, resetAtUnixSeconds: 1_777_777_777 },
      maximumRequests: 1,
      maximumResults: 10,
      maximumChargeUsdMicros: "50000",
      actualChargeUsdMicros: null,
      runtime: {
        authorizationId: AUTHORIZATION_ID,
        eventHash: "a".repeat(64),
        eventSequence: 2,
        modeRevision: 2,
      },
      capture: { eventHash: "b".repeat(64), eventSequence: 3 },
    },
    type: "x.read-canary.receipt.v1",
  });
}

function claimFixture(requests: OneShotClaimCommandRequest[]) {
  return createDarwinOneShotClaimHostForTesting("x", {
    executor: vi.fn(async (request) => {
      requests.push(request);
      return {
        exitCode: 0,
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
        timedOut: false,
      };
    }),
    platform: "darwin",
  });
}

describe("X permanent-claim backfill", () => {
  it("requires the exact typed published plan acknowledgement", () => {
    expect(
      parseXCanaryClaimBackfillAcknowledgement([
        "--typed-plan-id-acknowledgement",
        X_READ_CANARY_PLAN_ID,
      ]),
    ).toBe(X_READ_CANARY_PLAN_ID);
    expect(parseXCanaryClaimBackfillAcknowledgement(["--", "--help"])).toBeNull();
    expect(() => parseXCanaryClaimBackfillAcknowledgement([])).toThrow();
    expect(() =>
      parseXCanaryClaimBackfillAcknowledgement([
        "--typed-plan-id-acknowledgement",
        "alternate-plan",
      ]),
    ).toThrow();
    expect(xCanaryClaimBackfillUsage()).not.toContain("--db");
    expect(xCanaryClaimBackfillUsage()).not.toContain("--port");
  });

  it("verifies a valid completed canonical receipt before creating the marker", async () => {
    const store = await openEventStore();
    appendCompletedReceipt(store);
    const requests: OneShotClaimCommandRequest[] = [];

    await expect(
      backfillXCanaryClaimWithHost(store, claimFixture(requests), X_READ_CANARY_PLAN_ID),
    ).resolves.toEqual({
      markerCreated: true,
      planId: X_READ_CANARY_PLAN_ID,
      receiptVerified: true,
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.args[0]).toBe("add-generic-password");
    expect(requests[0]!.args).not.toContain("-U");
  });

  it("does not touch the marker when the receipt or acknowledgement is unavailable", async () => {
    const store = await openEventStore();
    const missingReceiptRequests: OneShotClaimCommandRequest[] = [];
    await expect(
      backfillXCanaryClaimWithHost(
        store,
        claimFixture(missingReceiptRequests),
        X_READ_CANARY_PLAN_ID,
      ),
    ).rejects.toThrow("canonical completed X receipt is unavailable");
    expect(missingReceiptRequests).toEqual([]);

    appendCompletedReceipt(store);
    const wrongAcknowledgementRequests: OneShotClaimCommandRequest[] = [];
    await expect(
      backfillXCanaryClaimWithHost(
        store,
        claimFixture(wrongAcknowledgementRequests),
        "alternate-plan",
      ),
    ).rejects.toThrow("exact published X plan acknowledgement is required");
    expect(wrongAcknowledgementRequests).toEqual([]);
  });
});
