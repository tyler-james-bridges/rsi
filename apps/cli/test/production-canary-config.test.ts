import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  PRODUCTION_CANARY_PORT,
  productionBaseRpcCanaryHostOptions,
  productionOpenSeaCanaryHostOptions,
  productionXCanaryEventStorePath,
  productionXCanaryHostOptions,
} from "../src/production-canary-config.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const ORIGINAL_CWD = process.cwd();
let temporaryDirectory: string | undefined;

afterEach(async () => {
  process.chdir(ORIGINAL_CWD);
  if (temporaryDirectory !== undefined) {
    await rm(temporaryDirectory, { force: true, recursive: true });
    temporaryDirectory = undefined;
  }
});

describe("production canary configuration", () => {
  it("owns one absolute repository-anchored path set and fixed loopback port", () => {
    const baseRpc = productionBaseRpcCanaryHostOptions();
    const x = productionXCanaryHostOptions();
    const openSea = productionOpenSeaCanaryHostOptions();
    const dataDirectory = resolve(REPOSITORY_ROOT, "apps/cli/.local");

    expect(x).toEqual({
      databasePath: resolve(dataDirectory, "rsi-runtime.sqlite"),
      port: PRODUCTION_CANARY_PORT,
      researchDatabasePath: resolve(dataDirectory, "rsi-research.sqlite"),
    });
    expect(openSea).toEqual({
      databasePath: resolve(dataDirectory, "rsi-opensea-canary-runtime.sqlite"),
      port: PRODUCTION_CANARY_PORT,
    });
    expect(baseRpc).toEqual({
      databasePath: resolve(dataDirectory, "rsi-base-rpc-canary-runtime.sqlite"),
      port: PRODUCTION_CANARY_PORT,
    });
    expect(isAbsolute(baseRpc.databasePath)).toBe(true);
    expect(productionXCanaryEventStorePath()).toBe(
      resolve(dataDirectory, "rsi-x-canary-events.sqlite"),
    );
    expect(isAbsolute(x.databasePath)).toBe(true);
    expect(isAbsolute(x.researchDatabasePath)).toBe(true);
    expect(isAbsolute(openSea.databasePath)).toBe(true);
    expect(Object.isFrozen(x)).toBe(true);
    expect(Object.isFrozen(openSea)).toBe(true);
    expect(Object.isFrozen(baseRpc)).toBe(true);
  });

  it("does not change paths when the caller changes its working directory", async () => {
    const before = {
      baseRpc: productionBaseRpcCanaryHostOptions(),
      openSea: productionOpenSeaCanaryHostOptions(),
      xEventStore: productionXCanaryEventStorePath(),
      x: productionXCanaryHostOptions(),
    };
    temporaryDirectory = await mkdtemp(join(tmpdir(), "rsi-production-config-cwd-"));
    process.chdir(temporaryDirectory);

    expect(productionBaseRpcCanaryHostOptions()).toEqual(before.baseRpc);
    expect(productionOpenSeaCanaryHostOptions()).toEqual(before.openSea);
    expect(productionXCanaryEventStorePath()).toBe(before.xEventStore);
    expect(productionXCanaryHostOptions()).toEqual(before.x);
  });
});
