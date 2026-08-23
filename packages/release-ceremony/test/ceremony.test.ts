import { chmod, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { runFoundationCeremony } from "../src/ceremony.js";
import { foundationCiEvidenceSha256 } from "../src/ci-evidence.js";
import { reserveFoundationOutput } from "../src/host.js";
import type { FoundationPinnedReleaseIdentityV1 } from "../src/release-identity.js";
import { foundationIndependentReviewEvidenceSha256 } from "../src/review-evidence.js";
import {
  FOUNDATION_CEREMONY_REPORT_TYPE,
  FOUNDATION_RELEASE_VERSION,
  FOUNDATION_TAG,
  type FoundationCeremonyDependencies,
  type FoundationCeremonyOptions,
  type FoundationCeremonySignersV1,
} from "../src/types.js";
import {
  CEREMONY_AT,
  COMMIT,
  makeCiEvidence,
  makeCustodyFixture,
  makeInventory,
  makeReviewEvidence,
  PLATFORM_IDENTITY_SHA256,
} from "./helpers.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

describe("foundation ceremony v2", () => {
  let root: string;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), "rsi-foundation-")));
    await chmod(root, 0o700);
  });

  afterEach(async () => {
    await rm(root, { force: true, recursive: true });
  });

  it("performs exactly two ordered signatures and retains all five create-only outputs", async () => {
    const counter = { signatures: 0, value: 0 };
    const evidence = makeCiEvidence();
    const paths = outputPaths(root, "complete");
    const fixture = makeCustodyFixture(counter);

    const report = await runFoundationCeremony(options(paths), dependencies({ evidence, fixture }));

    expect(report).toMatchObject({
      ciEvidenceSha256: foundationCiEvidenceSha256(evidence),
      ciRunId: evidence.runId,
      commitSha: COMMIT,
      independentReviewEvidenceSha256:
        foundationIndependentReviewEvidenceSha256(makeReviewEvidence()),
      releaseVersion: FOUNDATION_RELEASE_VERSION,
      reportType: FOUNDATION_CEREMONY_REPORT_TYPE,
      signatureCount: 2,
      signerFingerprintSha256: fixture.identity.signerFingerprintSha256,
      signerKeyId: fixture.identity.keyId,
      status: "verified-foundation-release-and-detached-tag",
      tagName: FOUNDATION_TAG,
    });
    expect(counter).toEqual({ signatures: 2, value: 1 });

    for (const path of Object.values(paths)) {
      const outputStat = await stat(path);
      expect(outputStat.mode & 0o777, path).toBe(0o600);
      expect(outputStat.nlink, path).toBe(1);
      expect(outputStat.size, path).toBeGreaterThan(0);
    }
    expect((await readFile(paths.destinationPath)).length).toBeGreaterThan(1_000);

    for (const path of [paths.receiptPath, paths.conclusionPath, paths.reportPath]) {
      const text = await readFile(path, "utf8");
      expect(text, path).toBe(canonicalJson(JSON.parse(text) as unknown));
    }
    const conclusion = JSON.parse(await readFile(paths.conclusionPath, "utf8")) as Record<
      string,
      unknown
    >;
    expect(conclusion).toMatchObject({
      independentReviewEvidenceSha256:
        foundationIndependentReviewEvidenceSha256(makeReviewEvidence()),
      objectiveEvidenceState: "FOUNDATION_BUILT",
      outcome: "passed",
      provisioningReceiptSha256: fixture.identity.provisioningReceiptSha256,
    });
    expect(await readFile(paths.tagObjectPath, "utf8")).toContain("-----BEGIN SSH SIGNATURE-----");
    expect(JSON.parse(await readFile(paths.reportPath, "utf8"))).toEqual(report);
  });

  it("reserves every success output before custody and publishes the conclusion last", async () => {
    const counter = { signatures: 0, value: 0 };
    const paths = outputPaths(root, "ordered-lifecycle");
    const fixture = makeCustodyFixture(counter);
    const events: string[] = [];
    const base = dependencies({ evidence: makeCiEvidence(), fixture });
    const orderedCustody: FoundationCeremonyDependencies["custody"] = Object.freeze({
      async withSigners<T>(
        identity: FoundationPinnedReleaseIdentityV1,
        operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
      ): Promise<T> {
        events.push("custody:start");
        const result = await fixture.custody.withSigners(identity, async (signers) => {
          events.push("custody:signers-exposed");
          return operation(signers);
        });
        events.push("custody:complete");
        return result;
      },
    });

    await runFoundationCeremony(options(paths), {
      ...base,
      custody: orderedCustody,
      reserveOutput: async (path, suffix) => {
        events.push(`reserve:${suffix}`);
        const reservation = await reserveFoundationOutput(path, repositoryRoot, suffix);
        return Object.freeze({
          preserve: () => reservation.preserve(),
          publish: async (bytes: Uint8Array) => {
            events.push(`publish:${suffix}`);
            await reservation.publish(bytes);
          },
        });
      },
    });

    expect(events).toEqual([
      "reserve:.receipt.json",
      "reserve:.readiness-conclusion.json",
      "reserve:.foundation-tag",
      "reserve:.ceremony-report.json",
      "custody:start",
      "custody:signers-exposed",
      "custody:complete",
      "publish:.foundation-tag",
      "publish:.receipt.json",
      "publish:.ceremony-report.json",
      "publish:.readiness-conclusion.json",
    ]);
    expect(counter).toEqual({ signatures: 2, value: 1 });
  });

  it("refuses an online host before CI, inventory, identity, or custody access", async () => {
    const counter = { signatures: 0, value: 0 };
    const calls = { ci: 0, inventory: 0, offline: 0, pinnedIdentity: 0, review: 0 };
    const fixture = makeCustodyFixture(counter);
    const deps = dependencies({ evidence: makeCiEvidence(), fixture });

    await expect(
      runFoundationCeremony(options(outputPaths(root, "online")), {
        ...deps,
        assertHostOffline: async () => {
          calls.offline += 1;
          throw Object.assign(new Error("network active"), { code: "HOST_REFUSED" });
        },
        collectInventory: async (...args) => {
          calls.inventory += 1;
          return deps.collectInventory(...args);
        },
        readCiEvidence: async (...args) => {
          calls.ci += 1;
          return deps.readCiEvidence(...args);
        },
        readPinnedIdentity: async (...args) => {
          calls.pinnedIdentity += 1;
          return deps.readPinnedIdentity(...args);
        },
        readReviewEvidence: async (...args) => {
          calls.review += 1;
          return deps.readReviewEvidence(...args);
        },
      }),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });

    expect(calls).toEqual({ ci: 0, inventory: 0, offline: 1, pinnedIdentity: 0, review: 0 });
    expect(counter).toEqual({ signatures: 0, value: 0 });
  });

  it("refuses a host that reconnects before signing custody begins", async () => {
    const counter = { signatures: 0, value: 0 };
    const fixture = makeCustodyFixture(counter);
    const paths = outputPaths(root, "reconnected-before-custody");
    let offlineChecks = 0;

    await expect(
      runFoundationCeremony(options(paths), {
        ...dependencies({ evidence: makeCiEvidence(), fixture }),
        assertHostOffline: async () => {
          offlineChecks += 1;
          if (offlineChecks === 2) {
            throw Object.assign(new Error("network reconnected"), { code: "HOST_REFUSED" });
          }
        },
      }),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });

    expect({ counter, offlineChecks }).toEqual({
      counter: { signatures: 0, value: 0 },
      offlineChecks: 2,
    });
    await expect(readFile(paths.destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
    for (const path of [
      paths.receiptPath,
      paths.reportPath,
      paths.conclusionPath,
      paths.tagObjectPath,
    ]) {
      expect((await stat(path)).size, path).toBe(0);
    }
  });

  it("refuses non-MacBook hardware before even checking offline state", async () => {
    const counter = { signatures: 0, value: 0 };
    const fixture = makeCustodyFixture(counter);
    const deps = dependencies({ evidence: makeCiEvidence(), fixture });
    let offlineChecks = 0;

    await expect(
      runFoundationCeremony(options(outputPaths(root, "wrong-host")), {
        ...deps,
        assertHostOffline: async () => {
          offlineChecks += 1;
        },
        platformModel: async () => "Mac mini",
      }),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });
    expect({ counter, offlineChecks }).toEqual({
      counter: { signatures: 0, value: 0 },
      offlineChecks: 0,
    });
  });

  it("refuses a MacBook whose platform identity does not match the pinned identity", async () => {
    const counter = { signatures: 0, value: 0 };
    const fixture = makeCustodyFixture(counter);
    await expect(
      runFoundationCeremony(options(outputPaths(root, "wrong-platform")), {
        ...dependencies({ evidence: makeCiEvidence(), fixture }),
        platformIdentitySha256: async () => "8".repeat(64),
      }),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });
    expect(counter).toEqual({ signatures: 0, value: 0 });
  });

  it("refuses mismatched, future, and stale CI evidence before custody", async () => {
    for (const [index, evidence] of [
      makeCiEvidence({ commitSha: "c".repeat(40) }),
      makeCiEvidence({ completedAt: "2026-08-18T02:00:01.000Z" }),
      makeCiEvidence({ completedAt: "2026-08-10T00:00:00.000Z" }),
    ].entries()) {
      const counter = { signatures: 0, value: 0 };
      const fixture = makeCustodyFixture(counter);
      await expect(
        runFoundationCeremony(
          options(outputPaths(root, `invalid-ci-${index}`)),
          dependencies({ evidence, fixture }),
        ),
      ).rejects.toBeInstanceOf(Error);
      expect(counter).toEqual({ signatures: 0, value: 0 });
    }
  });

  it("refuses stale, mismatched-commit, and mismatched-tree review evidence before custody", async () => {
    for (const [index, reviewEvidence] of [
      makeReviewEvidence({ reviewedAt: "2026-08-10T00:00:00.000Z" }),
      makeReviewEvidence({ reviewedAt: "2026-08-17T23:59:59.000Z" }),
      makeReviewEvidence({ commitSha: "c".repeat(40) }),
      makeReviewEvidence({ gitTreeSha: "d".repeat(40) }),
    ].entries()) {
      const counter = { signatures: 0, value: 0 };
      const fixture = makeCustodyFixture(counter);
      await expect(
        runFoundationCeremony(options(outputPaths(root, `invalid-review-${index}`)), {
          ...dependencies({ evidence: makeCiEvidence(), fixture }),
          readReviewEvidence: async () => ({
            evidence: reviewEvidence,
            sha256: foundationIndependentReviewEvidenceSha256(reviewEvidence),
          }),
        }),
      ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
      expect(counter).toEqual({ signatures: 0, value: 0 });
    }
  });

  it("rejects a signer that does not match the repository-pinned identity before signing", async () => {
    const counter = { signatures: 0, value: 0 };
    const fixture = makeCustodyFixture(counter);
    const mismatchedCustody: FoundationCeremonyDependencies["custody"] = Object.freeze({
      async withSigners<T>(
        identity: FoundationPinnedReleaseIdentityV1,
        operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
      ): Promise<T> {
        return fixture.custody.withSigners(identity, (signers) =>
          operation(
            Object.freeze({
              releaseSigner: Object.freeze({
                ...signers.releaseSigner,
                keyId: "rsi-release-0000000000000000",
              }),
              tagSigner: signers.tagSigner,
            }),
          ),
        );
      },
    });

    await expect(
      runFoundationCeremony(options(outputPaths(root, "identity-mismatch")), {
        ...dependencies({ evidence: makeCiEvidence(), fixture }),
        custody: mismatchedCustody,
      }),
    ).rejects.toMatchObject({ code: "CUSTODY_FAILED" });
    expect(counter).toEqual({ signatures: 0, value: 1 });
  });

  it("publishes no success marker when detached-tag retention fails", async () => {
    const counter = { signatures: 0, value: 0 };
    const paths = outputPaths(root, "partial");
    const fixture = makeCustodyFixture(counter);
    const deps = dependencies({ evidence: makeCiEvidence(), fixture });

    await expect(
      runFoundationCeremony(options(paths), {
        ...deps,
        reserveOutput: (path, suffix) =>
          reserveFoundationOutput(
            path,
            repositoryRoot,
            suffix,
            suffix === ".foundation-tag"
              ? {
                  afterWrite: () => {
                    throw new Error("simulated detached-tag retention failure");
                  },
                }
              : {},
          ),
      }),
    ).rejects.toMatchObject({ code: "OUTPUT_FAILED" });

    expect(counter).toEqual({ signatures: 2, value: 1 });
    expect((await readFile(paths.destinationPath)).length).toBeGreaterThan(0);
    expect(await readFile(paths.tagObjectPath, "utf8")).toContain("-----BEGIN SSH SIGNATURE-----");
    expect((await stat(paths.receiptPath)).size).toBe(0);
    expect((await stat(paths.reportPath)).size).toBe(0);
    expect((await stat(paths.conclusionPath)).size).toBe(0);
  });

  it("leaves every success output empty when the second signature fails", async () => {
    const counter = { signatures: 0, value: 0 };
    const paths = outputPaths(root, "second-signature-failure");
    const fixture = makeCustodyFixture(counter);
    const custody: FoundationCeremonyDependencies["custody"] = Object.freeze({
      withSigners: <T>(
        identity: FoundationPinnedReleaseIdentityV1,
        operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
      ): Promise<T> =>
        fixture.custody.withSigners(identity, (signers): Promise<T> =>
          operation(
            Object.freeze({
              releaseSigner: signers.releaseSigner,
              tagSigner: Object.freeze({
                ...signers.tagSigner,
                sign: async () => {
                  throw new Error("simulated second-signature refusal");
                },
              }),
            }),
          ),
        ),
    });

    await expect(
      runFoundationCeremony(options(paths), {
        ...dependencies({ evidence: makeCiEvidence(), fixture }),
        custody,
      }),
    ).rejects.toBeInstanceOf(Error);

    expect(counter).toEqual({ signatures: 1, value: 1 });
    expect((await stat(paths.destinationPath)).size).toBeGreaterThan(0);
    for (const path of [
      paths.receiptPath,
      paths.reportPath,
      paths.conclusionPath,
      paths.tagObjectPath,
    ]) {
      expect((await stat(path)).size, path).toBe(0);
    }
  });

  it("publishes no success output when custody cleanup fails after both signatures", async () => {
    const counter = { signatures: 0, value: 0 };
    const paths = outputPaths(root, "custody-cleanup-failure");
    const fixture = makeCustodyFixture(counter);
    const custody: FoundationCeremonyDependencies["custody"] = Object.freeze({
      async withSigners<T>(
        identity: FoundationPinnedReleaseIdentityV1,
        operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
      ): Promise<T> {
        await fixture.custody.withSigners(identity, operation);
        throw new Error("simulated custody cleanup failure");
      },
    });

    await expect(
      runFoundationCeremony(options(paths), {
        ...dependencies({ evidence: makeCiEvidence(), fixture }),
        custody,
      }),
    ).rejects.toThrow(/cleanup/u);

    expect(counter).toEqual({ signatures: 2, value: 1 });
    expect((await stat(paths.destinationPath)).size).toBeGreaterThan(0);
    for (const path of [
      paths.receiptPath,
      paths.reportPath,
      paths.conclusionPath,
      paths.tagObjectPath,
    ]) {
      expect((await stat(path)).size, path).toBe(0);
    }
  });

  it("reserves the detached-tag destination before exposing signing custody", async () => {
    const counter = { signatures: 0, value: 0 };
    const paths = outputPaths(root, "reserved-before-custody");
    const fixture = makeCustodyFixture(counter);
    await writeFile(paths.tagObjectPath, "existing", { mode: 0o600 });

    await expect(
      runFoundationCeremony(options(paths), dependencies({ evidence: makeCiEvidence(), fixture })),
    ).rejects.toMatchObject({ code: "OUTPUT_FAILED" });

    expect(counter).toEqual({ signatures: 0, value: 0 });
    expect(await readFile(paths.tagObjectPath, "utf8")).toBe("existing");
    await expect(readFile(paths.destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("reserves every retained output before consuming a signature", async () => {
    const counter = { signatures: 0, value: 0 };
    const paths = outputPaths(root, "existing");
    const fixture = makeCustodyFixture(counter);
    await writeFile(paths.receiptPath, "existing", { mode: 0o600 });

    await expect(
      runFoundationCeremony(options(paths), dependencies({ evidence: makeCiEvidence(), fixture })),
    ).rejects.toMatchObject({ code: expect.stringMatching(/^(?:EEXIST|OUTPUT_FAILED)$/u) });
    expect(await readFile(paths.receiptPath, "utf8")).toBe("existing");
    await expect(readFile(paths.destinationPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(counter).toEqual({ signatures: 0, value: 0 });
  });

  it("rejects duplicate paths, accessors, and extra options before touching dependencies", async () => {
    const counter = { signatures: 0, value: 0 };
    const fixture = makeCustodyFixture(counter);
    const deps = dependencies({ evidence: makeCiEvidence(), fixture });
    const valid = options(outputPaths(root, "closed-input"));

    await expect(
      runFoundationCeremony({ ...valid, reportPath: valid.receiptPath }, deps),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    await expect(
      runFoundationCeremony({ ...valid, key: "secret" } as never, deps),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    const hostile = { ...valid } as Record<string, unknown>;
    Object.defineProperty(hostile, "confirmCommit", {
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    await expect(runFoundationCeremony(hostile as never, deps)).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    expect(counter).toEqual({ signatures: 0, value: 0 });
  });
});

export interface CeremonyOutputPaths {
  readonly conclusionPath: string;
  readonly destinationPath: string;
  readonly receiptPath: string;
  readonly reportPath: string;
  readonly tagObjectPath: string;
}

export function outputPaths(root: string, name: string): CeremonyOutputPaths {
  return Object.freeze({
    conclusionPath: join(root, `${name}.readiness-conclusion.json`),
    destinationPath: join(root, `${name}.rsi-release`),
    receiptPath: join(root, `${name}.receipt.json`),
    reportPath: join(root, `${name}.ceremony-report.json`),
    tagObjectPath: join(root, `${name}.foundation-tag`),
  });
}

export function options(paths: CeremonyOutputPaths): FoundationCeremonyOptions {
  return Object.freeze({
    ciEvidencePath: "/outside/evidence.json",
    confirmCommit: COMMIT,
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    reviewEvidencePath: "/outside/review-evidence.json",
    ...paths,
  });
}

export function dependencies({
  evidence,
  fixture,
  repository = repositoryRoot,
}: {
  readonly evidence: ReturnType<typeof makeCiEvidence>;
  readonly fixture: ReturnType<typeof makeCustodyFixture>;
  readonly repository?: string;
}): FoundationCeremonyDependencies {
  const result: FoundationCeremonyDependencies = {
    assertHostOffline: async () => undefined,
    collectInventory: async (_evidence: unknown, createdAt: string) => makeInventory(createdAt),
    custody: fixture.custody,
    now: () => new Date(CEREMONY_AT),
    platformIdentitySha256: async () => PLATFORM_IDENTITY_SHA256,
    platformModel: async () => "MacBook",
    readCiEvidence: async (_path: string) => ({
      evidence,
      sha256: foundationCiEvidenceSha256(evidence),
    }),
    readPinnedIdentity: async (_commitSha: string) => fixture.identity,
    readReviewEvidence: async (_path: string) => {
      const reviewEvidence = makeReviewEvidence();
      return {
        evidence: reviewEvidence,
        sha256: foundationIndependentReviewEvidenceSha256(reviewEvidence),
      };
    },
    reserveOutput: (path, suffix) => reserveFoundationOutput(path, repository, suffix),
  };
  return Object.freeze(result);
}
