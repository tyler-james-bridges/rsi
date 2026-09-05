import { chmod, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createDarwinXReadCanaryKeychainForTesting,
  type CredentialCommandRequest,
} from "@rsi/credential-host/testing";
import { createDarwinOneShotClaimHostForTesting } from "@rsi/credential-host/one-shot-claim-testing";
import { afterEach, describe, expect, it, vi } from "vitest";

let directory: string | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  vi.resetModules();
  if (directory !== undefined) await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

describe("Stage 1 X canary data-directory ownership", () => {
  it("rejects a mode-0700 directory owned by a different effective user before credentials", async () => {
    const actualEffectiveUserId = process.geteuid?.();
    expect(actualEffectiveUserId).toBeTypeOf("number");
    directory = await mkdtemp(join(tmpdir(), "rsi-x-canary-host-wrong-owner-"));
    await chmod(directory, 0o700);
    expect((await stat(directory)).mode & 0o777).toBe(0o700);

    vi.spyOn(process, "geteuid").mockReturnValue(actualEffectiveUserId! + 1);
    const { startXCanaryOperatorForTesting } =
      await import("../src/x-canary-operator-host.testing.js");
    const requests: CredentialCommandRequest[] = [];
    const credentialHost = createDarwinXReadCanaryKeychainForTesting({
      executor: vi.fn(async (request) => {
        requests.push(request);
        throw new Error("credential access must not occur");
      }),
      platform: "darwin",
    });

    await expect(
      startXCanaryOperatorForTesting({
        claimHost: createDarwinOneShotClaimHostForTesting("x", {
          executor: vi.fn(),
          platform: "darwin",
        }),
        credentialHost,
        databasePath: join(directory, "runtime.sqlite"),
        port: 0,
        researchDatabasePath: join(directory, "research.sqlite"),
      }),
    ).rejects.toThrow("Stage 1 data directories must be owner-only (mode 0700)");
    expect(requests).toEqual([]);
    expect(await readdir(directory)).toEqual([]);
  });
});
