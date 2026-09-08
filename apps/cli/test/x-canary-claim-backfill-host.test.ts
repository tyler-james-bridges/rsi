import { chmod, link, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

let directory: string | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  vi.resetModules();
  vi.doUnmock("../src/production-runtime.js");
  vi.doUnmock("../src/production-canary-config.js");
  vi.doUnmock("../src/profile-service-lock.js");
  vi.doUnmock("@rsi/credential-host/one-shot-claim");
  if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  directory = undefined;
});

describe("X marker-backfill production host", () => {
  it("rejects a multiply linked receipt database before claim-host access", async () => {
    directory = await mkdtemp(join(tmpdir(), "rsi-x-backfill-hardlink-"));
    await chmod(directory, 0o700);
    const aliasPath = join(directory, "outside-lock-alias.sqlite");
    const eventStorePath = join(directory, "rsi-x-canary-events.sqlite");
    await writeFile(aliasPath, "not a database", { mode: 0o600 });
    await link(aliasPath, eventStorePath);

    const release = vi.fn(async () => undefined);
    const createClaimHost = vi.fn(() => {
      throw new Error("claim host must remain untouched");
    });
    vi.doMock("../src/production-runtime.js", () => ({
      assertActiveProductionRuntime: vi.fn(),
    }));
    vi.doMock("../src/production-canary-config.js", () => ({
      productionXCanaryEventStorePath: () => eventStorePath,
    }));
    vi.doMock("../src/profile-service-lock.js", () => ({
      acquireProductionCanaryProfileLock: async () => ({ release }),
    }));
    vi.doMock("@rsi/credential-host/one-shot-claim", () => ({
      createDarwinXOneShotClaimHost: createClaimHost,
    }));

    const { backfillXCanaryClaim } = await import("../src/x-canary-claim-backfill-host.js");
    await expect(backfillXCanaryClaim("x-nft-market-pulse-v1")).rejects.toThrow(
      "The canonical completed X receipt is unavailable",
    );

    expect(createClaimHost).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledOnce();
    expect(await readFile(aliasPath, "utf8")).toBe("not a database");
  });
});
