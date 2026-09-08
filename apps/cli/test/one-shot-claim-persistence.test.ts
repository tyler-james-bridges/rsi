import { mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createDarwinOneShotClaimHostForTesting,
  type OneShotClaimCommandExecutor,
  type OneShotClaimCommandRequest,
} from "@rsi/credential-host/one-shot-claim-testing";
import { afterEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_CWD = process.cwd();
let directory: string | undefined;

afterEach(async () => {
  process.chdir(ORIGINAL_CWD);
  if (directory !== undefined) {
    await rm(directory, { force: true, recursive: true });
    directory = undefined;
  }
});

function permanentMarkerExecutor(requests: OneShotClaimCommandRequest[]): {
  readonly executor: OneShotClaimCommandExecutor;
  readonly isClaimed: () => boolean;
} {
  let claimed = false;
  return {
    executor: vi.fn(async (request) => {
      requests.push(request);
      await Promise.resolve();
      if (claimed) {
        return {
          exitCode: 45,
          stdout: new Uint8Array(),
          stderr: new Uint8Array(),
          timedOut: false,
        };
      }
      claimed = true;
      return {
        exitCode: 0,
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
        timedOut: false,
      };
    }),
    isClaimed: () => claimed,
  };
}

describe("permanent canary claim boundary", () => {
  it("allows exactly one of two concurrent claim attempts", async () => {
    const requests: OneShotClaimCommandRequest[] = [];
    const marker = permanentMarkerExecutor(requests);
    const first = createDarwinOneShotClaimHostForTesting("x", {
      executor: marker.executor,
      platform: "darwin",
    });
    const second = createDarwinOneShotClaimHostForTesting("x", {
      executor: marker.executor,
      platform: "darwin",
    });

    const results = await Promise.allSettled([first.claim(), second.claim()]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(results.find((result) => result.status === "rejected")).toMatchObject({
      reason: { code: "ALREADY_CLAIMED" },
    });
    expect(requests).toHaveLength(2);
    expect(requests.every((request) => !request.args.includes("-U"))).toBe(true);
    expect(requests.every((request) => !request.args.includes("delete-generic-password"))).toBe(
      true,
    );
  });

  it("remains claimed after local database deletion", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-one-shot-db-deletion-"));
    const databasePath = join(directory, "runtime.sqlite");
    await writeFile(databasePath, "local-state");
    const requests: OneShotClaimCommandRequest[] = [];
    const marker = permanentMarkerExecutor(requests);
    const first = createDarwinOneShotClaimHostForTesting("openSea", {
      executor: marker.executor,
      platform: "darwin",
    });
    await expect(first.claim()).resolves.toBeUndefined();

    await unlink(databasePath);
    const restarted = createDarwinOneShotClaimHostForTesting("openSea", {
      executor: marker.executor,
      platform: "darwin",
    });

    await expect(restarted.claim()).rejects.toMatchObject({ code: "ALREADY_CLAIMED" });
    expect(marker.isClaimed()).toBe(true);
    expect(requests).toHaveLength(2);
  });

  it("uses the same fixed marker when launched from an alternate working directory", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-one-shot-alternate-cwd-"));
    const requests: OneShotClaimCommandRequest[] = [];
    const marker = permanentMarkerExecutor(requests);
    process.chdir(directory);

    await createDarwinOneShotClaimHostForTesting("x", {
      executor: marker.executor,
      platform: "darwin",
    }).claim();

    expect(requests).toEqual([
      {
        args: [
          "add-generic-password",
          "-a",
          "rsi-stage1-one-shot-claims",
          "-s",
          "dev.rsi.canary.one-shot.x-nft-market-pulse-v1",
          "-w",
          "rsi-claimed-v1",
        ],
        file: "/usr/bin/security",
        maxBufferBytes: 8_192,
        timeoutMs: 3_000,
      },
    ]);
  });
});
