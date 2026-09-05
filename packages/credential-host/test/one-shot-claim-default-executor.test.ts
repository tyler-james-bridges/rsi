import { Buffer } from "node:buffer";

import { afterEach, describe, expect, it, vi } from "vitest";

const execFile = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({ execFile }));

import { createDarwinOneShotClaimHostForTesting } from "../src/one-shot-claim-testing.js";

afterEach(() => {
  execFile.mockReset();
});

describe("default one-shot claim executor", () => {
  it("uses only the fixed security command and wipes callback buffers", async () => {
    const stdout = Buffer.from("untrusted-output", "ascii");
    const stderr = Buffer.from("untrusted-diagnostic", "ascii");
    execFile.mockImplementation(
      (
        _file: string,
        _args: readonly string[],
        _options: object,
        callback: (error: null, stdout: Buffer, stderr: Buffer) => void,
      ) => {
        callback(null, stdout, stderr);
        return undefined;
      },
    );

    await expect(
      createDarwinOneShotClaimHostForTesting("baseRpc", { platform: "darwin" }).claim(),
    ).resolves.toBeUndefined();

    expect(execFile).toHaveBeenCalledOnce();
    expect(execFile.mock.calls[0]![0]).toBe("/usr/bin/security");
    expect(execFile.mock.calls[0]![1]).toEqual([
      "add-generic-password",
      "-a",
      "rsi-stage1-one-shot-claims",
      "-s",
      "dev.rsi.canary.one-shot.base-mainnet-finalized-anchor-v1",
      "-w",
      "rsi-claimed-v1",
    ]);
    expect(execFile.mock.calls[0]![1]).not.toContain("-U");
    expect(execFile.mock.calls[0]![2]).toEqual({
      encoding: "buffer",
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
      maxBuffer: 8_192,
      shell: false,
      timeout: 3_000,
      windowsHide: true,
    });
    expect(stdout.every((byte) => byte === 0)).toBe(true);
    expect(stderr.every((byte) => byte === 0)).toBe(true);
  });

  it("maps the macOS duplicate-item status to an irreversible claim", async () => {
    const stdout = Buffer.from("duplicate", "ascii");
    const stderr = Buffer.from("untrusted-diagnostic", "ascii");
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
        callback(
          Object.assign(new Error("duplicate"), { code: 45, killed: false }),
          stdout,
          stderr,
        );
        return undefined;
      },
    );

    await expect(
      createDarwinOneShotClaimHostForTesting("openSea", { platform: "darwin" }).claim(),
    ).rejects.toMatchObject({ code: "ALREADY_CLAIMED" });
    expect(stdout.every((byte) => byte === 0)).toBe(true);
    expect(stderr.every((byte) => byte === 0)).toBe(true);
  });
});
