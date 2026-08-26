import { Buffer } from "node:buffer";

import { afterEach, describe, expect, it, vi } from "vitest";

import * as packageRoot from "../src/index.js";
import { DarwinXReadCanaryKeychain, isDarwinXReadCanaryKeychain } from "../src/index.js";
import * as productionEntry from "../src/opensea-trending.js";
import {
  DarwinOpenSeaTrendingKeychain,
  isDarwinOpenSeaTrendingKeychain,
  type OpenSeaTrendingSecretMaterial,
  type OpenSeaTrendingStorageSecretMaterial,
} from "../src/opensea-trending.js";
import {
  createDarwinOpenSeaTrendingKeychainForTesting,
  type OpenSeaTrendingCredentialCommandExecutor,
  type OpenSeaTrendingCredentialCommandRequest,
  type OpenSeaTrendingCredentialCommandResult,
} from "../src/opensea-trending-testing.js";

const SERVICES = Object.freeze([
  "dev.rsi.canary.opensea-read",
  "dev.rsi.canary.operations-state",
  "dev.rsi.canary.capture-registry",
  "dev.rsi.canary.vault-wrapping",
] as const);
const API_KEY = "fixed-visible-opensea-api-key";
const KEYS = Object.freeze([
  Buffer.alloc(32, 0x11).toString("base64url"),
  Buffer.alloc(32, 0x22).toString("base64url"),
  Buffer.alloc(32, 0x33).toString("base64url"),
] as const);

afterEach(() => {
  vi.restoreAllMocks();
});

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function allZero(value: Uint8Array): boolean {
  return value.every((byte) => byte === 0);
}

interface ExecutorFixture {
  readonly executor: OpenSeaTrendingCredentialCommandExecutor;
  readonly outputs: Uint8Array[];
  readonly requests: OpenSeaTrendingCredentialCommandRequest[];
}

function executorFixture(
  override?: (
    request: Readonly<OpenSeaTrendingCredentialCommandRequest>,
    index: number,
    stdout: Uint8Array,
    stderr: Uint8Array,
  ) =>
    | Readonly<OpenSeaTrendingCredentialCommandResult>
    | Promise<Readonly<OpenSeaTrendingCredentialCommandResult>>,
  values: readonly string[] = [API_KEY, ...KEYS],
): ExecutorFixture {
  const outputs: Uint8Array[] = [];
  const requests: OpenSeaTrendingCredentialCommandRequest[] = [];
  const executor: OpenSeaTrendingCredentialCommandExecutor = vi.fn(async (request) => {
    const index = requests.length;
    requests.push(request);
    const stdout = bytes(`${values[index] ?? "status"}\r\n`);
    const stderr = bytes(`diagnostic-${index}`);
    outputs.push(stdout, stderr);
    return override === undefined
      ? { exitCode: 0, stdout, stderr, timedOut: false }
      : await override(request, index, stdout, stderr);
  });
  return { executor, outputs, requests };
}

function host(fixture: ExecutorFixture): DarwinOpenSeaTrendingKeychain {
  return createDarwinOpenSeaTrendingKeychainForTesting({
    executor: fixture.executor,
    platform: "darwin",
  });
}

function expectFixedRequest(
  request: Readonly<OpenSeaTrendingCredentialCommandRequest>,
  service: string,
  reveal: boolean,
): void {
  expect(request).toEqual({
    args: [
      "find-generic-password",
      "-a",
      "rsi-stage1-opensea-read-canary",
      "-s",
      service,
      ...(reveal ? ["-w"] : []),
    ],
    file: "/usr/bin/security",
    maxBufferBytes: 8_192,
    timeoutMs: 3_000,
  });
  expect(Object.isFrozen(request)).toBe(true);
  expect(Object.isFrozen(request.args)).toBe(true);
}

describe("DarwinOpenSeaTrendingKeychain status", () => {
  it("uses four fixed presence-only commands and wipes every output", async () => {
    const fixture = executorFixture();

    await expect(host(fixture).status()).resolves.toBe("configured");

    expect(fixture.requests).toHaveLength(4);
    fixture.requests.forEach((request, index) => {
      expectFixedRequest(request, SERVICES[index]!, false);
      expect(request.args).not.toContain("-w");
      expect(request.args).not.toContain("rsi-stage1-x-read-canary");
      expect(request.args).not.toContain("dev.rsi.canary.x-read");
    });
    expect(fixture.outputs.every(allZero)).toBe(true);
  });

  it.each([
    ["missing", { exitCode: 44, timedOut: false }],
    ["unavailable", { exitCode: 1, timedOut: false }],
    ["unavailable", { exitCode: null, timedOut: false }],
    ["unavailable", { exitCode: 0, timedOut: true }],
  ] as const)("reports %s without interpreting stderr", async (expected, state) => {
    const fixture = executorFixture((_request, _index, stdout, stderr) => ({
      ...state,
      stdout,
      stderr,
    }));

    await expect(host(fixture).status()).resolves.toBe(expected);
    expect(fixture.outputs.every(allZero)).toBe(true);
  });

  it("maps executor rejection and malformed results to unavailable", async () => {
    const rejected: OpenSeaTrendingCredentialCommandExecutor = vi.fn(async () => {
      throw new Error("host failure");
    });
    await expect(
      createDarwinOpenSeaTrendingKeychainForTesting({
        executor: rejected,
        platform: "darwin",
      }).status(),
    ).resolves.toBe("unavailable");

    const fixture = executorFixture((_request, _index, stdout, stderr) =>
      Object.assign({ exitCode: 0, stdout, stderr, timedOut: false }, { unexpected: true }),
    );
    await expect(host(fixture).status()).resolves.toBe("unavailable");
    expect(fixture.outputs.every(allZero)).toBe(true);
  });
});

describe("DarwinOpenSeaTrendingKeychain commissioning reads", () => {
  it("reveals only the four controlled services and presents non-enumerable material", async () => {
    const fixture = executorFixture();
    let retained: Readonly<OpenSeaTrendingSecretMaterial> | undefined;

    const result = await host(fixture).withSecrets(async (material) => {
      retained = material;
      expect(material.apiKey).toBe(API_KEY);
      expect([...material.operationsStateKey]).toEqual([...Buffer.alloc(32, 0x11)]);
      expect([...material.captureRegistryKey]).toEqual([...Buffer.alloc(32, 0x22)]);
      expect([...material.vaultWrappingKey]).toEqual([...Buffer.alloc(32, 0x33)]);
      expect(Object.getPrototypeOf(material)).toBeNull();
      expect(Object.isFrozen(material)).toBe(true);
      expect(Object.keys(material)).toEqual([]);
      expect({ ...material }).toEqual({});
      expect(JSON.stringify(material)).toBe("{}");
      for (const name of [
        "apiKey",
        "operationsStateKey",
        "captureRegistryKey",
        "vaultWrappingKey",
      ]) {
        expect(Object.getOwnPropertyDescriptor(material, name)).toMatchObject({
          configurable: false,
          enumerable: false,
          writable: false,
        });
      }
      return "consumed";
    });

    expect(result).toBe("consumed");
    expect(fixture.requests).toHaveLength(4);
    fixture.requests.forEach((request, index) =>
      expectFixedRequest(request, SERVICES[index]!, true),
    );
    expect(
      fixture.requests.every(
        (request) =>
          !request.args.includes("rsi-stage1-x-read-canary") &&
          !request.args.includes("dev.rsi.canary.x-read"),
      ),
    ).toBe(true);
    expect(fixture.outputs.every(allZero)).toBe(true);
    expect(retained).toBeDefined();
    expect(allZero(retained!.operationsStateKey)).toBe(true);
    expect(allZero(retained!.captureRegistryKey)).toBe(true);
    expect(allZero(retained!.vaultWrappingKey)).toBe(true);
  });

  it("reads only storage keys for recovery and never requests the OpenSea API key", async () => {
    const fixture = executorFixture(undefined, KEYS);
    let retained: Readonly<OpenSeaTrendingStorageSecretMaterial> | undefined;

    const result = await host(fixture).withStorageSecrets(async (material) => {
      retained = material;
      expect([...material.operationsStateKey]).toEqual([...Buffer.alloc(32, 0x11)]);
      expect([...material.captureRegistryKey]).toEqual([...Buffer.alloc(32, 0x22)]);
      expect([...material.vaultWrappingKey]).toEqual([...Buffer.alloc(32, 0x33)]);
      expect(Object.getPrototypeOf(material)).toBeNull();
      expect(Object.isFrozen(material)).toBe(true);
      expect(Object.keys(material)).toEqual([]);
      expect({ ...material }).toEqual({});
      expect(JSON.stringify(material)).toBe("{}");
      expect(material).not.toHaveProperty("apiKey");
      return "recovered";
    });

    expect(result).toBe("recovered");
    expect(fixture.requests).toHaveLength(3);
    fixture.requests.forEach((request, index) =>
      expectFixedRequest(request, SERVICES[index + 1]!, true),
    );
    expect(
      fixture.requests.some((request) => request.args.includes("dev.rsi.canary.opensea-read")),
    ).toBe(false);
    expect(fixture.outputs.every(allZero)).toBe(true);
    expect(retained).toBeDefined();
    expect(allZero(retained!.operationsStateKey)).toBe(true);
    expect(allZero(retained!.captureRegistryKey)).toBe(true);
    expect(allZero(retained!.vaultWrappingKey)).toBe(true);
  });

  it("wipes decoded key buffers and callback key views after success", async () => {
    const fixture = executorFixture();
    const from = vi.spyOn(Buffer, "from");
    const retained: Uint8Array[] = [];

    await host(fixture).withSecrets(async (material) => {
      retained.push(
        material.operationsStateKey,
        material.captureRegistryKey,
        material.vaultWrappingKey,
      );
    });

    const decoded = from.mock.calls.flatMap((call, index) => {
      const args = call as readonly unknown[];
      if (args[1] !== "base64url") return [];
      const result = from.mock.results[index];
      return result?.type === "return" && Buffer.isBuffer(result.value) ? [result.value] : [];
    });
    expect(decoded).toHaveLength(3);
    expect(decoded.every(allZero)).toBe(true);
    expect(retained.every(allZero)).toBe(true);
    expect(fixture.outputs.every(allZero)).toBe(true);
  });

  it("wipes outputs and all delivered key views when the callback fails", async () => {
    const fixture = executorFixture();
    const retained: Uint8Array[] = [];
    const consumerFailure = new Error("consumer failed");

    await expect(
      host(fixture).withSecrets(async (material) => {
        retained.push(
          material.operationsStateKey,
          material.captureRegistryKey,
          material.vaultWrappingKey,
        );
        throw consumerFailure;
      }),
    ).rejects.toBe(consumerFailure);

    expect(retained.every(allZero)).toBe(true);
    expect(fixture.outputs.every(allZero)).toBe(true);
  });

  it.each([
    ["missing", { exitCode: 44, timedOut: false }, "CREDENTIAL_MISSING"],
    ["non-item error", { exitCode: 2, timedOut: false }, "CREDENTIAL_UNAVAILABLE"],
    ["no exit", { exitCode: null, timedOut: false }, "CREDENTIAL_UNAVAILABLE"],
    ["timeout", { exitCode: 0, timedOut: true }, "CREDENTIAL_UNAVAILABLE"],
  ] as const)("fails closed for a %s controlled read", async (_label, state, code) => {
    const fixture = executorFixture((_request, index, stdout, stderr) => ({
      ...(index === 2 ? state : { exitCode: 0, timedOut: false }),
      stdout,
      stderr,
    }));
    const consumer = vi.fn();

    await expect(host(fixture).withSecrets(consumer)).rejects.toMatchObject({ code });
    expect(consumer).not.toHaveBeenCalled();
    expect(fixture.outputs.every(allZero)).toBe(true);
  });

  it("maps executor rejection to an unavailable credential error", async () => {
    const executor: OpenSeaTrendingCredentialCommandExecutor = vi.fn(async () => {
      throw new Error("spawn failed");
    });

    await expect(
      createDarwinOpenSeaTrendingKeychainForTesting({ executor, platform: "darwin" }).withSecrets(
        async () => undefined,
      ),
    ).rejects.toMatchObject({ code: "CREDENTIAL_UNAVAILABLE" });
  });

  it.each([
    ["empty", ""],
    ["leading space", " invalid"],
    ["embedded tab", "invalid\ttoken"],
    ["embedded newline", "invalid\ntoken"],
    ["delete", "invalid\u007f"],
    ["non-ASCII", "inválid"],
    ["too long", "x".repeat(4_097)],
  ])("rejects an invalid visible-ASCII API key: %s", async (_label, token) => {
    const fixture = executorFixture(undefined, [token, ...KEYS]);
    const consumer = vi.fn();

    await expect(host(fixture).withSecrets(consumer)).rejects.toMatchObject({
      code: "CREDENTIAL_INVALID",
    });
    expect(consumer).not.toHaveBeenCalled();
    expect(fixture.outputs.every(allZero)).toBe(true);
  });

  it.each([
    ["short", Buffer.alloc(31, 1).toString("base64url")],
    ["long", Buffer.alloc(33, 1).toString("base64url")],
    ["padded", `${KEYS[0]}=`],
    ["standard alphabet", `${KEYS[0]!.slice(0, 42)}/`],
    ["non-canonical tail", `${KEYS[0]!.slice(0, 42)}B`],
    ["non-ASCII", `${KEYS[0]!.slice(0, 42)}é`],
  ])("rejects a non-canonical 32-byte key: %s", async (_label, invalidKey) => {
    const fixture = executorFixture(undefined, [API_KEY, invalidKey, KEYS[1]!, KEYS[2]!]);
    const consumer = vi.fn();

    await expect(host(fixture).withSecrets(consumer)).rejects.toMatchObject({
      code: "CREDENTIAL_INVALID",
    });
    expect(consumer).not.toHaveBeenCalled();
    expect(fixture.outputs.every(allZero)).toBe(true);
  });
});

describe("boundary authenticity", () => {
  it("keeps platform and executor injection off the production entry", () => {
    const productionHost = new DarwinOpenSeaTrendingKeychain();
    const xHost = new DarwinXReadCanaryKeychain();

    expect(isDarwinOpenSeaTrendingKeychain(productionHost)).toBe(true);
    expect(isDarwinXReadCanaryKeychain(productionHost)).toBe(false);
    expect(isDarwinXReadCanaryKeychain(xHost)).toBe(true);
    expect(isDarwinOpenSeaTrendingKeychain(xHost)).toBe(false);
    expect(productionEntry).not.toHaveProperty("createDarwinOpenSeaTrendingKeychainForTesting");
    expect(packageRoot).not.toHaveProperty("DarwinOpenSeaTrendingKeychain");
    expect(packageRoot).not.toHaveProperty("OpenSeaTrendingCredentialHostError");
    expect(packageRoot).not.toHaveProperty("createDarwinOpenSeaTrendingKeychainForTesting");
    expect(() => Reflect.construct(DarwinOpenSeaTrendingKeychain, [{ platform: "linux" }])).toThrow(
      TypeError,
    );
  });

  it("denies non-Darwin platforms before invoking an executor", async () => {
    const executor: OpenSeaTrendingCredentialCommandExecutor = vi.fn();
    const keychain = createDarwinOpenSeaTrendingKeychainForTesting({ executor, platform: "linux" });

    await expect(keychain.status()).resolves.toBe("unavailable");
    await expect(keychain.withSecrets(async () => undefined)).rejects.toMatchObject({
      code: "CREDENTIAL_UNAVAILABLE",
    });
    await expect(keychain.withStorageSecrets(async () => undefined)).rejects.toMatchObject({
      code: "CREDENTIAL_UNAVAILABLE",
    });
    expect(executor).not.toHaveBeenCalled();
  });

  it("rejects proxy and lookalike options, executors, consumers, hosts, and results", async () => {
    const fixture = executorFixture();
    const options = { executor: fixture.executor, platform: "darwin" as const };
    expect(() => createDarwinOpenSeaTrendingKeychainForTesting(new Proxy(options, {}))).toThrow(
      TypeError,
    );
    expect(() =>
      createDarwinOpenSeaTrendingKeychainForTesting({
        executor: new Proxy(fixture.executor, {}),
        platform: "darwin",
      }),
    ).toThrow(TypeError);
    expect(() =>
      createDarwinOpenSeaTrendingKeychainForTesting(Object.assign(Object.create(null), options)),
    ).toThrow(TypeError);

    const authentic = host(fixture);
    const hostProxy = new Proxy(authentic, {});
    const lookalike = Object.create(
      DarwinOpenSeaTrendingKeychain.prototype,
    ) as DarwinOpenSeaTrendingKeychain;
    expect(isDarwinOpenSeaTrendingKeychain(authentic)).toBe(true);
    expect(isDarwinOpenSeaTrendingKeychain(hostProxy)).toBe(false);
    expect(isDarwinOpenSeaTrendingKeychain(lookalike)).toBe(false);
    await expect(
      DarwinOpenSeaTrendingKeychain.prototype.status.call(lookalike),
    ).rejects.toBeInstanceOf(TypeError);

    const consumer = vi.fn(async () => undefined);
    await expect(authentic.withSecrets(new Proxy(consumer, {}))).rejects.toBeInstanceOf(TypeError);
    expect(fixture.requests).toHaveLength(0);

    const output = bytes("secret");
    const malformedExecutor: OpenSeaTrendingCredentialCommandExecutor = vi.fn(
      async () =>
        new Proxy({ exitCode: 0, stdout: output, stderr: new Uint8Array(0), timedOut: false }, {}),
    );
    await expect(
      createDarwinOpenSeaTrendingKeychainForTesting({
        executor: malformedExecutor,
        platform: "darwin",
      }).withSecrets(async () => undefined),
    ).rejects.toMatchObject({ code: "CREDENTIAL_UNAVAILABLE" });
  });

  it("never invokes accessor properties on malformed command results and wipes safe fields", async () => {
    const stdout = bytes("secret-output");
    const stderr = bytes("secret-error");
    const getter = vi.fn(() => 0);
    const result = { stdout, stderr, timedOut: false } as Record<string, unknown>;
    Object.defineProperty(result, "exitCode", { enumerable: true, get: getter });
    const executor: OpenSeaTrendingCredentialCommandExecutor = vi.fn(async () => result as never);

    await expect(
      createDarwinOpenSeaTrendingKeychainForTesting({ executor, platform: "darwin" }).status(),
    ).resolves.toBe("unavailable");
    expect(getter).not.toHaveBeenCalled();
    expect(allZero(stdout)).toBe(true);
    expect(allZero(stderr)).toBe(true);
  });

  it("rejects oversized, shared, and Buffer lookalike outputs while wiping their bytes", async () => {
    const outputs: Uint8Array[] = [
      new Uint8Array(8_193).fill(0x41),
      new Uint8Array(new SharedArrayBuffer(8)).fill(0x42),
      Buffer.from("buffer-lookalike", "ascii"),
    ];

    for (const stdout of outputs) {
      const stderr = bytes("diagnostic");
      const executor: OpenSeaTrendingCredentialCommandExecutor = vi.fn(async () => ({
        exitCode: 0,
        stdout,
        stderr,
        timedOut: false,
      }));
      await expect(
        createDarwinOpenSeaTrendingKeychainForTesting({ executor, platform: "darwin" }).status(),
      ).resolves.toBe("unavailable");
      expect(allZero(stdout)).toBe(true);
      expect(allZero(stderr)).toBe(true);
    }
  });
});
