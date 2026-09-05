import { randomUUID } from "node:crypto";

import type { RuntimeSnapshotV1 } from "@rsi/runtime";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createProductionCanaryOperatorFacade } from "../src/production-canary-operator-facade.js";

const LOCAL_MODULES = [
  "../src/profile-service-lock.js",
  "../src/production-canary-config.js",
  "../src/production-canary-operator-facade.js",
  "../src/production-runtime.js",
  "../src/x-canary-operator-host-core.js",
  "../src/opensea-canary-operator-host-core.js",
  "../src/base-rpc-canary-operator-host-core.js",
] as const;

type Flavor = "x" | "openSea" | "baseRpc";
type WrapFailure = "bind" | "facade";

interface WrappingScenario {
  readonly close: ReturnType<typeof vi.fn>;
  readonly release: ReturnType<typeof vi.fn>;
  readonly result: Promise<unknown>;
  readonly timeline: string[];
  readonly wrappingError: Error;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.resetModules();
  for (const moduleId of LOCAL_MODULES) vi.doUnmock(moduleId);
  vi.doUnmock("@rsi/credential-host");
  vi.doUnmock("@rsi/credential-host/base-rpc");
  vi.doUnmock("@rsi/credential-host/one-shot-claim");
  vi.doUnmock("@rsi/credential-host/opensea-trending");
});

function runtimeSnapshot(): Readonly<RuntimeSnapshotV1> {
  return Object.freeze({
    schemaVersion: 1,
    auditHead: Object.freeze({ hash: "0".repeat(64), sequence: 1 }),
    capabilities: Object.freeze({
      executionAdapter: false,
      externalPublish: false,
      paidRead: false,
      policyApproval: false,
      proposalPersistence: false,
      researchCollection: false,
      transactionBroadcast: false,
      walletSign: false,
    }),
    mode: "STOPPED",
    modeChangedAt: "2026-09-05T00:00:00.000Z",
    processInstanceId: randomUUID(),
    revision: 1,
  });
}

async function wrappingScenario(
  flavor: Flavor,
  failurePoint: WrapFailure,
  closeFails: boolean,
): Promise<WrappingScenario> {
  vi.resetModules();
  const timeline: string[] = [];
  const wrappingError = new Error("sensitive wrapping failure");
  const closeError = new Error("sensitive close failure");
  const close = vi.fn(async () => {
    timeline.push("close");
    if (closeFails) throw closeError;
  });
  const operator = {
    close,
    origin: "http://127.0.0.1:8787",
    paths: Object.freeze({ runtime: "/private/runtime.sqlite" }),
    runtime: Object.freeze({ getSnapshot: runtimeSnapshot }),
  };
  const release = vi.fn(async () => {
    timeline.push("release");
  });
  const start = vi.fn(async () => operator);
  const bind = vi.fn((resource: unknown) => {
    if (failurePoint === "bind") throw wrappingError;
    return resource;
  });
  const facade = vi.fn(() => {
    throw wrappingError;
  });

  vi.doMock("../src/production-runtime.js", () => ({
    assertActiveProductionRuntime: vi.fn(),
  }));
  vi.doMock("../src/production-canary-config.js", () => ({
    productionBaseRpcCanaryHostOptions: () => ({
      databasePath: "/private/runtime.sqlite",
      port: 8787,
    }),
    productionOpenSeaCanaryHostOptions: () => ({
      databasePath: "/private/runtime.sqlite",
      port: 8787,
    }),
    productionXCanaryHostOptions: () => ({
      databasePath: "/private/runtime.sqlite",
      port: 8787,
      researchDatabasePath: "/private/research.sqlite",
    }),
  }));
  vi.doMock("../src/profile-service-lock.js", () => ({
    acquireProductionCanaryProfileLock: vi.fn(async () => ({ release })),
    bindProfileServiceLock: bind,
  }));
  vi.doMock("../src/production-canary-operator-facade.js", () => ({
    createProductionCanaryOperatorFacade: facade,
  }));
  vi.doMock("@rsi/credential-host", () => ({ DarwinXReadCanaryKeychain: class {} }));
  vi.doMock("@rsi/credential-host/opensea-trending", () => ({
    DarwinOpenSeaTrendingKeychain: class {},
  }));
  vi.doMock("@rsi/credential-host/base-rpc", () => ({ DarwinBaseRpcKeychain: class {} }));
  vi.doMock("@rsi/credential-host/one-shot-claim", () => ({
    createDarwinBaseRpcOneShotClaimHost: () => Object.freeze({}),
    createDarwinOpenSeaOneShotClaimHost: () => Object.freeze({}),
    createDarwinXOneShotClaimHost: () => Object.freeze({}),
  }));

  let result: Promise<unknown>;
  if (flavor === "x") {
    vi.doMock("../src/x-canary-operator-host-core.js", () => ({
      startXCanaryOperatorWithHost: start,
    }));
    const host = await import("../src/x-canary-operator-host.js");
    result = host.startXCanaryOperator({
      databasePath: "/private/runtime.sqlite",
      port: 8787,
      researchDatabasePath: "/private/research.sqlite",
    });
  } else if (flavor === "openSea") {
    vi.doMock("../src/opensea-canary-operator-host-core.js", () => ({
      startOpenSeaCanaryOperatorWithHost: start,
    }));
    const host = await import("../src/opensea-canary-operator-host.js");
    result = host.startOpenSeaCanaryOperator({
      databasePath: "/private/runtime.sqlite",
      port: 8787,
    });
  } else {
    vi.doMock("../src/base-rpc-canary-operator-host-core.js", () => ({
      startBaseRpcCanaryOperatorWithHost: start,
    }));
    const host = await import("../src/base-rpc-canary-operator-host.js");
    result = host.startBaseRpcCanaryOperator();
  }
  return { close, release, result, timeline, wrappingError };
}

describe("production canary operator facade", () => {
  it("exposes only a frozen runtime snapshot reader", async () => {
    const close = vi.fn(async () => undefined);
    const transition = vi.fn();
    const internalRuntime = { getSnapshot: runtimeSnapshot, transition };
    const facade = createProductionCanaryOperatorFacade({
      close,
      origin: "http://127.0.0.1:8787",
      paths: Object.freeze({ runtime: "/private/runtime.sqlite" }),
      runtime: internalRuntime,
    });

    expect(Object.isFrozen(facade)).toBe(true);
    expect(Object.isFrozen(facade.runtime)).toBe(true);
    expect(Object.keys(facade.runtime)).toEqual(["getSnapshot"]);
    expect(facade.runtime).not.toHaveProperty("transition");
    expect(facade.runtime).not.toHaveProperty("stop");
    expect(facade.runtime).not.toHaveProperty("close");
    expect(facade.runtime).not.toHaveProperty("listAudit");
    expect(facade.runtime).not.toHaveProperty("requestBoundaryAuthorization");
    expect(facade.runtime.getSnapshot()).toMatchObject({ mode: "STOPPED", revision: 1 });
    await facade.close();
    expect(close).toHaveBeenCalledOnce();
    expect(transition).not.toHaveBeenCalled();
  });

  it.each(["x", "openSea", "baseRpc"] as const)(
    "%s closes a started core before releasing its lock when binding fails",
    async (flavor) => {
      const scenario = await wrappingScenario(flavor, "bind", false);
      await expect(scenario.result).rejects.toBe(scenario.wrappingError);
      expect(scenario.timeline).toEqual(["close", "release"]);
      expect(scenario.close).toHaveBeenCalledOnce();
      expect(scenario.release).toHaveBeenCalledOnce();
    },
  );

  it.each(["x", "openSea", "baseRpc"] as const)(
    "%s retains its lock when facade failure cleanup is incomplete",
    async (flavor) => {
      const scenario = await wrappingScenario(flavor, "facade", true);
      const error = await scenario.result.catch((caught: unknown) => caught);
      expect(error).toMatchObject({ name: "IncompleteCanaryOperatorStartupCleanupError" });
      expect(scenario.timeline).toEqual(["close"]);
      expect(scenario.close).toHaveBeenCalledOnce();
      expect(scenario.release).not.toHaveBeenCalled();
    },
  );
});
