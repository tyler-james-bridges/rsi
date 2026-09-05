import { chmod, lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createDarwinBaseRpcKeychainForTesting } from "@rsi/credential-host/base-rpc-testing";
import { createDarwinOneShotClaimHostForTesting } from "@rsi/credential-host/one-shot-claim-testing";
import { createDarwinOpenSeaTrendingKeychainForTesting } from "@rsi/credential-host/opensea-trending-testing";
import { createDarwinXReadCanaryKeychainForTesting } from "@rsi/credential-host/testing";
import { afterEach, describe, expect, it, vi } from "vitest";

import { startBaseRpcCanaryOperatorWithHost } from "../src/base-rpc-canary-operator-host-core.js";
import { startBaseRpcCanaryOperatorForTesting } from "../src/base-rpc-canary-operator-host.testing.js";
import { startOpenSeaCanaryOperatorWithHost } from "../src/opensea-canary-operator-host-core.js";
import { startOpenSeaCanaryOperatorForTesting } from "../src/opensea-canary-operator-host.testing.js";
import { acquireCanaryProfileLockForDatabasePathForTesting } from "../src/profile-service-lock.testing.js";
import { startXCanaryOperatorWithHost } from "../src/x-canary-operator-host-core.js";
import { startXCanaryOperatorForTesting } from "../src/x-canary-operator-host.testing.js";

let directory: string | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  directory = undefined;
});

async function privateDirectory(): Promise<string> {
  directory = await mkdtemp(join(tmpdir(), "rsi-canary-lock-integration-"));
  await chmod(directory, 0o700);
  return directory;
}

function forbiddenExecutor() {
  return vi.fn(async () => {
    throw new Error("the contending host reached a credential boundary");
  });
}

describe("Stage 1 canary profile-lock integration", () => {
  it.each(["x", "opensea", "base-rpc"] as const)(
    "rejects an unauthentic %s core lease before creating storage or touching credentials",
    async (kind) => {
      const root = await privateDirectory();
      const dataDirectory = join(root, "must-not-exist");
      const runtimePath = join(dataDirectory, `${kind}-runtime.sqlite`);
      const credentialExecutor = forbiddenExecutor();
      const claimExecutor = forbiddenExecutor();
      const fakeLease = { release: vi.fn(async () => undefined) };

      const started =
        kind === "x"
          ? startXCanaryOperatorWithHost(
              {
                databasePath: runtimePath,
                port: 0,
                researchDatabasePath: join(dataDirectory, "x-research.sqlite"),
              },
              createDarwinXReadCanaryKeychainForTesting({
                executor: credentialExecutor,
                platform: "darwin",
              }),
              createDarwinOneShotClaimHostForTesting("x", {
                executor: claimExecutor,
                platform: "darwin",
              }),
              fakeLease,
            )
          : kind === "opensea"
            ? startOpenSeaCanaryOperatorWithHost(
                { databasePath: runtimePath, port: 0 },
                createDarwinOpenSeaTrendingKeychainForTesting({
                  executor: credentialExecutor,
                  platform: "darwin",
                }),
                createDarwinOneShotClaimHostForTesting("openSea", {
                  executor: claimExecutor,
                  platform: "darwin",
                }),
                fakeLease,
              )
            : startBaseRpcCanaryOperatorWithHost(
                { databasePath: runtimePath, port: 0 },
                createDarwinBaseRpcKeychainForTesting({
                  executor: credentialExecutor,
                  platform: "darwin",
                }),
                createDarwinOneShotClaimHostForTesting("baseRpc", {
                  executor: claimExecutor,
                  platform: "darwin",
                }),
                fakeLease,
              );

      await expect(started).rejects.toMatchObject({ code: "unsafe" });
      expect(fakeLease.release).not.toHaveBeenCalled();
      expect(credentialExecutor).not.toHaveBeenCalled();
      expect(claimExecutor).not.toHaveBeenCalled();
      await expect(lstat(dataDirectory)).rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it.each(["x", "opensea", "base-rpc"] as const)(
    "refuses a contending %s host before storage or Keychain access",
    async (kind) => {
      const dataDirectory = await privateDirectory();
      const runtimePath = join(dataDirectory, `${kind}-runtime.sqlite`);
      const credentialExecutor = forbiddenExecutor();
      const claimExecutor = forbiddenExecutor();
      const held = await acquireCanaryProfileLockForDatabasePathForTesting(runtimePath);

      try {
        if (kind === "x") {
          await expect(
            startXCanaryOperatorForTesting({
              claimHost: createDarwinOneShotClaimHostForTesting("x", {
                executor: claimExecutor,
                platform: "darwin",
              }),
              credentialHost: createDarwinXReadCanaryKeychainForTesting({
                executor: credentialExecutor,
                platform: "darwin",
              }),
              databasePath: runtimePath,
              port: 0,
              researchDatabasePath: join(dataDirectory, "x-research.sqlite"),
            }),
          ).rejects.toMatchObject({ code: "contended" });
        } else if (kind === "opensea") {
          await expect(
            startOpenSeaCanaryOperatorForTesting({
              claimHost: createDarwinOneShotClaimHostForTesting("openSea", {
                executor: claimExecutor,
                platform: "darwin",
              }),
              credentialHost: createDarwinOpenSeaTrendingKeychainForTesting({
                executor: credentialExecutor,
                platform: "darwin",
              }),
              databasePath: runtimePath,
              port: 0,
            }),
          ).rejects.toMatchObject({ code: "contended" });
        } else {
          await expect(
            startBaseRpcCanaryOperatorForTesting({
              claimHost: createDarwinOneShotClaimHostForTesting("baseRpc", {
                executor: claimExecutor,
                platform: "darwin",
              }),
              credentialHost: createDarwinBaseRpcKeychainForTesting({
                executor: credentialExecutor,
                platform: "darwin",
              }),
              databasePath: runtimePath,
              port: 0,
            }),
          ).rejects.toMatchObject({ code: "contended" });
        }

        expect(credentialExecutor).not.toHaveBeenCalled();
        expect(claimExecutor).not.toHaveBeenCalled();
        await expect(lstat(runtimePath)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        await held.release();
      }
    },
  );
});
