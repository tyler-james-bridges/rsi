import { chmod, mkdtemp, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { runFoundationCeremony } from "../src/ceremony.js";
import { foundationCiEvidenceSha256 } from "../src/ci-evidence.js";
import { removeFoundationOwnedOutput, writeFoundationReceipt } from "../src/host.js";
import { FOUNDATION_RELEASE_VERSION } from "../src/types.js";
import { CEREMONY_AT, COMMIT, makeCiEvidence, makeCustody, makeInventory } from "./helpers.js";

describe("foundation ceremony", () => {
  let root: string;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), "rsi-foundation-")));
    await chmod(root, 0o700);
  });

  it("creates, verifies, and independently receipts the exact release", async () => {
    const counter = { value: 0 };
    const evidence = makeCiEvidence();
    const destinationPath = join(root, "foundation.rsi-release");
    const receiptPath = join(root, "foundation.receipt.json");
    const report = await runFoundationCeremony(
      options(destinationPath, receiptPath),
      dependencies({ counter, evidence, root }),
    );
    expect(report).toMatchObject({
      ciEvidenceSha256: foundationCiEvidenceSha256(evidence),
      ciRunId: evidence.runId,
      commitSha: COMMIT,
      releaseVersion: FOUNDATION_RELEASE_VERSION,
      status: "verified-foundation-release",
    });
    expect(counter.value).toBe(1);
    expect((await readFile(destinationPath)).length).toBeGreaterThan(1_000);
    const bundleStat = await stat(destinationPath);
    const receiptStat = await stat(receiptPath);
    expect(bundleStat.mode & 0o777).toBe(0o600);
    expect(receiptStat.mode & 0o777).toBe(0o600);
    expect({ bundleLinks: bundleStat.nlink, receiptLinks: receiptStat.nlink }).toEqual({
      bundleLinks: 1,
      receiptLinks: 1,
    });
    const receipt = JSON.parse(await readFile(receiptPath, "utf8")) as Record<string, unknown>;
    expect(receipt.archiveSha256).toBe(report.archiveSha256);
    expect(await readFile(receiptPath, "utf8")).toBe(canonicalJson(receipt));
  });

  it("refuses non-MacBook hardware before evidence, inventory, or custody access", async () => {
    const counter = { value: 0 };
    let evidenceReads = 0;
    let inventoryReads = 0;
    const deps = dependencies({ counter, evidence: makeCiEvidence(), root });
    await expect(
      runFoundationCeremony(options(join(root, "a.rsi-release"), join(root, "a.receipt.json")), {
        ...deps,
        collectInventory: async (...args) => {
          inventoryReads += 1;
          return deps.collectInventory(...args);
        },
        platformModel: async () => "Mac mini",
        readCiEvidence: async (...args) => {
          evidenceReads += 1;
          return deps.readCiEvidence(...args);
        },
      }),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });
    expect({ counter: counter.value, evidenceReads, inventoryReads }).toEqual({
      counter: 0,
      evidenceReads: 0,
      inventoryReads: 0,
    });
  });

  it("refuses mismatched, future, and stale CI evidence before custody", async () => {
    for (const evidence of [
      makeCiEvidence({ commitSha: "c".repeat(40) }),
      makeCiEvidence({ completedAt: "2026-08-18T02:00:01.000Z" }),
      makeCiEvidence({ completedAt: "2026-08-10T00:00:00.000Z" }),
    ]) {
      const counter = { value: 0 };
      await expect(
        runFoundationCeremony(
          options(
            join(root, `${evidence.commitSha}.rsi-release`),
            join(root, `${evidence.commitSha}.receipt.json`),
          ),
          dependencies({ counter, evidence, root }),
        ),
      ).rejects.toBeInstanceOf(Error);
      expect(counter.value).toBe(0);
    }
  });

  it("removes its bundle when receipt publication fails", async () => {
    const counter = { value: 0 };
    const destinationPath = join(root, "cleanup.rsi-release");
    const receiptPath = join(root, "cleanup.receipt.json");
    const deps = dependencies({ counter, evidence: makeCiEvidence(), root });
    await expect(
      runFoundationCeremony(options(destinationPath, receiptPath), {
        ...deps,
        writeReceipt: async () => {
          throw new Error("simulated receipt failure");
        },
      }),
    ).rejects.toThrow("simulated receipt failure");
    await expect(readFile(destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(counter.value).toBe(1);
  });

  it("refuses to delete a replaced bundle during failure cleanup", async () => {
    const counter = { value: 0 };
    const destinationPath = join(root, "replaced.rsi-release");
    const receiptPath = join(root, "replaced.receipt.json");
    const deps = dependencies({ counter, evidence: makeCiEvidence(), root });
    await expect(
      runFoundationCeremony(options(destinationPath, receiptPath), {
        ...deps,
        writeReceipt: async () => {
          await writeFile(destinationPath, "replacement", { mode: 0o600 });
          throw new Error("simulated replacement");
        },
      }),
    ).rejects.toMatchObject({ code: "OUTPUT_FAILED" });
    expect(await readFile(destinationPath, "utf8")).toBe("replacement");
  });

  it("does not overwrite existing bundle or receipt paths", async () => {
    const counter = { value: 0 };
    const destinationPath = join(root, "existing.rsi-release");
    const receiptPath = join(root, "existing.receipt.json");
    await writeFile(destinationPath, "existing", { mode: 0o600 });
    await expect(
      runFoundationCeremony(
        options(destinationPath, receiptPath),
        dependencies({ counter, evidence: makeCiEvidence(), root }),
      ),
    ).rejects.toBeInstanceOf(Error);
    expect(await readFile(destinationPath, "utf8")).toBe("existing");
  });

  it("rejects accessor and extra options before touching dependencies", async () => {
    const counter = { value: 0 };
    const deps = dependencies({ counter, evidence: makeCiEvidence(), root });
    const extra = { ...options("/tmp/a.rsi-release", "/tmp/a.receipt.json"), key: "secret" };
    await expect(runFoundationCeremony(extra as never, deps)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    const hostile = options("/tmp/a.rsi-release", "/tmp/a.receipt.json") as Record<string, unknown>;
    Object.defineProperty(hostile, "confirmCommit", {
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    await expect(runFoundationCeremony(hostile as never, deps)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    expect(counter.value).toBe(0);
  });
});

function options(destinationPath: string, receiptPath: string) {
  return {
    ciEvidencePath: "/outside/evidence.json",
    confirmCommit: COMMIT,
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    destinationPath,
    receiptPath,
  } as const;
}

function dependencies({
  counter,
  evidence,
  root,
}: {
  readonly counter: { value: number };
  readonly evidence: ReturnType<typeof makeCiEvidence>;
  readonly root: string;
}) {
  return {
    collectInventory: async (_evidence: unknown, createdAt: string) => makeInventory(createdAt),
    custody: makeCustody(counter),
    now: () => new Date(CEREMONY_AT),
    platformModel: async () => "MacBook",
    readCiEvidence: async (_path: string) => ({
      evidence,
      sha256: foundationCiEvidenceSha256(evidence),
    }),
    removeOwnOutput: (path: string, receipt: Parameters<typeof removeFoundationOwnedOutput>[2]) =>
      removeFoundationOwnedOutput(path, "/Users/tjb/code/rsi", receipt),
    writeReceipt: (path: string, receipt: Parameters<typeof writeFoundationReceipt>[2]) =>
      writeFoundationReceipt(path, "/Users/tjb/code/rsi", receipt),
  };
}
