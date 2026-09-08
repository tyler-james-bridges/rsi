import { Buffer } from "node:buffer";

import { describe, expect, it, vi } from "vitest";

import {
  createDarwinBaseRpcOneShotClaimHost,
  createDarwinOpenSeaOneShotClaimHost,
  createDarwinXOneShotClaimHost,
  isDarwinOneShotClaimHost,
} from "../src/one-shot-claim.js";
import {
  createDarwinOneShotClaimHostForTesting,
  type OneShotClaimCommandExecutor,
  type OneShotClaimCommandRequest,
} from "../src/one-shot-claim-testing.js";

const SERVICES = Object.freeze({
  baseRpc: "dev.rsi.canary.one-shot.base-mainnet-finalized-anchor-v1",
  openSea: "dev.rsi.canary.one-shot.opensea-base-trending-collections-v1",
  x: "dev.rsi.canary.one-shot.x-nft-market-pulse-v1",
} as const);

function fixture(
  exitCode: number | null = 0,
  timedOut = false,
): Readonly<{
  executor: OneShotClaimCommandExecutor;
  outputs: Uint8Array[];
  requests: OneShotClaimCommandRequest[];
}> {
  const requests: OneShotClaimCommandRequest[] = [];
  const outputs: Uint8Array[] = [];
  const executor: OneShotClaimCommandExecutor = vi.fn(async (request) => {
    requests.push(request);
    const stdout = new Uint8Array(Buffer.from("untrusted-output"));
    const stderr = new Uint8Array(Buffer.from("untrusted-diagnostic"));
    outputs.push(stdout, stderr);
    return { exitCode, stderr, stdout, timedOut };
  });
  return { executor, outputs, requests };
}

describe("permanent Keychain one-shot claims", () => {
  it("checks marker presence without requesting its value", async () => {
    for (const [exitCode, expected] of [
      [0, "present"],
      [44, "missing"],
      [1, "unknown"],
    ] as const) {
      const state = fixture(exitCode);
      const host = createDarwinOneShotClaimHostForTesting("x", {
        executor: state.executor,
        platform: "darwin",
      });
      await expect(host.status()).resolves.toBe(expected);
      expect(state.requests).toEqual([
        {
          args: ["find-generic-password", "-a", "rsi-stage1-one-shot-claims", "-s", SERVICES.x],
          file: "/usr/bin/security",
          maxBufferBytes: 8_192,
          timeoutMs: 3_000,
        },
      ]);
      expect(state.requests[0]!.args).not.toContain("-w");
      expect(state.outputs.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    }
  });

  it.each(Object.entries(SERVICES))(
    "atomically claims the fixed %s service without update or delete authority",
    async (target, service) => {
      const state = fixture();
      const host = createDarwinOneShotClaimHostForTesting(target as keyof typeof SERVICES, {
        executor: state.executor,
        platform: "darwin",
      });
      await expect(host.claim()).resolves.toBeUndefined();
      expect(state.requests).toEqual([
        {
          args: [
            "add-generic-password",
            "-a",
            "rsi-stage1-one-shot-claims",
            "-s",
            service,
            "-w",
            "rsi-claimed-v1",
          ],
          file: "/usr/bin/security",
          maxBufferBytes: 8_192,
          timeoutMs: 3_000,
        },
      ]);
      expect(state.requests[0]!.args).not.toContain("-U");
      expect(state.requests[0]!.args).not.toContain("delete-generic-password");
      expect(state.outputs.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
      await expect(host.claim()).rejects.toMatchObject({ code: "ALREADY_CLAIMED" });
      expect(state.requests).toHaveLength(1);
    },
  );

  it("classifies duplicate and unavailable outcomes without exposing command output", async () => {
    const duplicate = fixture(45);
    await expect(
      createDarwinOneShotClaimHostForTesting("x", {
        executor: duplicate.executor,
        platform: "darwin",
      }).claim(),
    ).rejects.toMatchObject({
      code: "ALREADY_CLAIMED",
      message: expect.not.stringContaining("untrusted"),
    });

    for (const state of [fixture(1), fixture(null), fixture(0, true)]) {
      await expect(
        createDarwinOneShotClaimHostForTesting("x", {
          executor: state.executor,
          platform: "darwin",
        }).claim(),
      ).rejects.toMatchObject({
        code: "CLAIM_UNAVAILABLE",
        message: expect.not.stringContaining("untrusted"),
      });
      expect(state.outputs.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    }
  });

  it("rejects unsupported platforms, hostile results, arguments, and forged hosts", async () => {
    const state = fixture();
    await expect(
      createDarwinOneShotClaimHostForTesting("baseRpc", {
        executor: state.executor,
        platform: "linux",
      }).claim(),
    ).rejects.toMatchObject({ code: "CLAIM_UNAVAILABLE" });
    expect(state.requests).toHaveLength(0);

    const hostile: OneShotClaimCommandExecutor = vi.fn(async () =>
      Object.assign(
        { exitCode: 0, stderr: new Uint8Array(), stdout: new Uint8Array(), timedOut: false },
        { extra: true },
      ),
    );
    await expect(
      createDarwinOneShotClaimHostForTesting("x", {
        executor: hostile,
        platform: "darwin",
      }).claim(),
    ).rejects.toMatchObject({ code: "CLAIM_UNAVAILABLE" });

    const host = createDarwinOneShotClaimHostForTesting("x", {
      executor: state.executor,
      platform: "darwin",
    });
    await expect(
      (host.claim as unknown as (value: unknown) => Promise<void>)(true),
    ).rejects.toMatchObject({
      code: "CLAIM_UNAVAILABLE",
    });
    expect(isDarwinOneShotClaimHost(host)).toBe(true);
    expect(isDarwinOneShotClaimHost({ claim: host.claim })).toBe(false);
    expect(() =>
      (createDarwinOneShotClaimHostForTesting as (target: unknown) => unknown)("toString"),
    ).toThrow("claim target is invalid");
  });

  it("keeps production constructors option-free and independently branded", () => {
    for (const factory of [
      createDarwinXOneShotClaimHost,
      createDarwinOpenSeaOneShotClaimHost,
      createDarwinBaseRpcOneShotClaimHost,
    ]) {
      expect(isDarwinOneShotClaimHost(factory())).toBe(true);
      expect(() => (factory as unknown as (value: unknown) => unknown)({})).toThrow();
    }
  });
});
