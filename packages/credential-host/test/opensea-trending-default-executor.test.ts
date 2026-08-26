import { Buffer } from "node:buffer";

import { afterEach, describe, expect, it, vi } from "vitest";

const execFile = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({ execFile }));

import { createDarwinOpenSeaTrendingKeychainForTesting } from "../src/opensea-trending-testing.js";

const SERVICES = Object.freeze([
  "dev.rsi.canary.opensea-read",
  "dev.rsi.canary.operations-state",
  "dev.rsi.canary.capture-registry",
  "dev.rsi.canary.vault-wrapping",
] as const);
const VALUES = Object.freeze([
  "production-shaped-opensea-api-key",
  Buffer.alloc(32, 0x44).toString("base64url"),
  Buffer.alloc(32, 0x55).toString("base64url"),
  Buffer.alloc(32, 0x66).toString("base64url"),
] as const);

afterEach(() => {
  execFile.mockReset();
});

describe("default /usr/bin/security executor", () => {
  it("pins the executable options and wipes the callback's original buffers", async () => {
    const callbackBuffers: Buffer[] = [];
    execFile.mockImplementation(
      (
        _file: string,
        args: readonly string[],
        _options: object,
        callback: (error: null, stdout: Buffer, stderr: Buffer) => void,
      ) => {
        const service = args[4];
        const index = SERVICES.indexOf(service as (typeof SERVICES)[number]);
        const stdout = Buffer.from(`${VALUES[index]!}\n`, "ascii");
        const stderr = Buffer.from(`diagnostic-${index}`, "ascii");
        callbackBuffers.push(stdout, stderr);
        callback(null, stdout, stderr);
        return undefined;
      },
    );
    const retainedKeys: Uint8Array[] = [];

    await createDarwinOpenSeaTrendingKeychainForTesting({ platform: "darwin" }).withSecrets(
      async (material) => {
        retainedKeys.push(
          material.operationsStateKey,
          material.captureRegistryKey,
          material.vaultWrappingKey,
        );
      },
    );

    expect(execFile).toHaveBeenCalledTimes(4);
    execFile.mock.calls.forEach((call, index) => {
      expect(call[0]).toBe("/usr/bin/security");
      expect(call[1]).toEqual([
        "find-generic-password",
        "-a",
        "rsi-stage1-opensea-read-canary",
        "-s",
        SERVICES[index],
        "-w",
      ]);
      expect(call[1]).not.toContain("rsi-stage1-x-read-canary");
      expect(call[1]).not.toContain("dev.rsi.canary.x-read");
      expect(call[2]).toEqual({
        encoding: "buffer",
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
        maxBuffer: 8_192,
        shell: false,
        timeout: 3_000,
        windowsHide: true,
      });
    });
    expect(callbackBuffers.every((value) => value.every((byte) => byte === 0))).toBe(true);
    expect(retainedKeys.every((value) => value.every((byte) => byte === 0))).toBe(true);
  });

  it("wipes callback buffers on command failure without exposing their diagnostics", async () => {
    const stdout = Buffer.from("unexpected-output", "ascii");
    const stderr = Buffer.from("sensitive-diagnostic", "ascii");
    execFile.mockImplementation(
      (
        _file: string,
        _args: readonly string[],
        _options: object,
        callback: (
          error: Error & { code: number; killed: boolean },
          stdout: Buffer,
          stderr: Buffer,
        ) => void,
      ) => {
        const error = Object.assign(new Error("not found"), { code: 44, killed: false });
        callback(error, stdout, stderr);
        return undefined;
      },
    );

    await expect(
      createDarwinOpenSeaTrendingKeychainForTesting({ platform: "darwin" }).withSecrets(
        async () => undefined,
      ),
    ).rejects.toMatchObject({ code: "CREDENTIAL_MISSING" });
    expect(stdout.every((byte) => byte === 0)).toBe(true);
    expect(stderr.every((byte) => byte === 0)).toBe(true);
  });
});
