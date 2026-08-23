import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { runFoundationCeremony } from "../src/ceremony.js";
import { foundationCiEvidenceSha256 } from "../src/ci-evidence.js";
import { reserveFoundationOutput } from "../src/host.js";
import { collectFoundationReleaseInventory } from "../src/inventory.js";
import { foundationIndependentReviewEvidenceSha256 } from "../src/review-evidence.js";
import {
  FOUNDATION_RELEASE_VERSION,
  type FoundationCeremonyDependencies,
  type FoundationCeremonyOptions,
} from "../src/types.js";
import {
  readFoundationVerificationRepositoryTree,
  verifyFoundationCeremonyOutputs,
  type FoundationCeremonyVerificationDependencies,
  type FoundationCeremonyVerificationOptions,
} from "../src/verification.js";
import {
  CEREMONY_AT,
  COMMIT,
  makeCiEvidence,
  makeCustodyFixture,
  makeInventory,
  makeReviewEvidence,
  PLATFORM_IDENTITY_SHA256,
} from "./helpers.js";

const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("foundation ceremony publication boundary", () => {
  it("retains detached tag bytes without creating any Git object or ref", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "rsi-detached-tag-")));
    cleanup.push(root);
    await chmod(root, 0o700);
    const repository = join(root, "repository");
    const retained = join(root, "retained");
    await mkdir(repository, { mode: 0o700 });
    await mkdir(retained, { mode: 0o700 });
    git(repository, ["init", "--quiet"]);
    git(repository, ["config", "user.email", "test@rsi.local"]);
    git(repository, ["config", "user.name", "RSI Test"]);
    await writeFile(join(repository, "README.md"), "fixture\n", { mode: 0o600 });
    git(repository, ["add", "README.md"]);
    git(repository, ["commit", "--quiet", "-m", "fixture"]);

    const refsBefore = git(repository, ["for-each-ref", "--format=%(refname):%(objectname)"]);
    const objectCountBefore = git(repository, ["count-objects", "-v"]);
    const paths = Object.freeze({
      conclusionPath: join(retained, "foundation.readiness-conclusion.json"),
      destinationPath: join(retained, "foundation.rsi-release"),
      receiptPath: join(retained, "foundation.receipt.json"),
      reportPath: join(retained, "foundation.ceremony-report.json"),
      tagObjectPath: join(retained, "foundation.foundation-tag"),
    });
    const options: FoundationCeremonyOptions = Object.freeze({
      ciEvidencePath: "/outside/foundation-ci.json",
      confirmCommit: COMMIT,
      confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
      reviewEvidencePath: "/outside/foundation-review-evidence.json",
      ...paths,
    });
    const evidence = makeCiEvidence();
    const counter = { signatures: 0, value: 0 };
    const fixture = makeCustodyFixture(counter);
    const reviewEvidence = makeReviewEvidence();
    const dependencies: FoundationCeremonyDependencies = {
      assertHostOffline: async () => undefined,
      collectInventory: async (_retainedEvidence, createdAt) => makeInventory(createdAt),
      custody: fixture.custody,
      now: () => new Date(CEREMONY_AT),
      platformIdentitySha256: async () => PLATFORM_IDENTITY_SHA256,
      platformModel: async () => "MacBook",
      readCiEvidence: async () => ({
        evidence,
        sha256: foundationCiEvidenceSha256(evidence),
      }),
      readPinnedIdentity: async () => fixture.identity,
      readReviewEvidence: async () => ({
        evidence: reviewEvidence,
        sha256: foundationIndependentReviewEvidenceSha256(reviewEvidence),
      }),
      reserveOutput: (path, suffix) => reserveFoundationOutput(path, repository, suffix),
    };

    const report = await runFoundationCeremony(options, dependencies);

    expect(counter).toEqual({ signatures: 2, value: 1 });
    expect(report.tagName).toBe("foundation-v1");
    expect((await stat(paths.tagObjectPath)).size).toBeGreaterThan(0);
    expect(await readFile(paths.tagObjectPath, "utf8")).toContain("-----BEGIN SSH SIGNATURE-----");
    expect(git(repository, ["for-each-ref", "--format=%(refname):%(objectname)"])).toBe(refsBefore);
    expect(git(repository, ["count-objects", "-v"])).toBe(objectCountBefore);
    expect(
      gitStatus(repository, ["show-ref", "--verify", "--quiet", "refs/tags/foundation-v1"]),
    ).toBe(1);
  });

  it("runs real inventory ceremony and verification paths from a committed clone without mutating Git", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "rsi-committed-ceremony-")));
    cleanup.push(root);
    await chmod(root, 0o700);
    const sourceRepository = await realpath(
      git(process.cwd(), ["rev-parse", "--show-toplevel"]).trim(),
    );
    const repositoryPath = join(root, "repository");
    const retained = join(root, "retained");
    git(root, ["clone", "--quiet", "--no-hardlinks", sourceRepository, repositoryPath]);
    const repository = await realpath(repositoryPath);
    await chmod(repository, 0o700);
    await mkdir(retained, { mode: 0o700 });
    expect(Number((await stat(repository)).mode) & 0o077).toBe(0);

    git(repository, ["checkout", "--quiet", "-B", "main", "HEAD"]);
    const configRoot = join(repository, "config");
    await mkdir(configRoot, { mode: 0o700 });
    const publicConfigPins = [
      "foundation-independent-reviewer-identity.v1.json",
      "foundation-release-identity.v1.json",
      "foundation-release-key-helper-compatibility.v1.json",
      "foundation-release-key-provisioning-receipt.v1.json",
    ] as const;
    for (const name of publicConfigPins) {
      await writeFile(join(configRoot, name), "{}", { flag: "wx", mode: 0o600 });
    }
    git(repository, ["add", "--", ...publicConfigPins.map((name) => `config/${name}`)]);
    git(
      repository,
      [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=RSI Committed Clone Test",
        "-c",
        "user.email=rsi-committed-clone@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "--message",
        "add harmless public Foundation pin fixtures",
      ],
      {
        GIT_AUTHOR_DATE: "2026-08-17T23:00:00Z",
        GIT_COMMITTER_DATE: "2026-08-17T23:00:00Z",
      },
    );
    const commitSha = git(repository, ["rev-parse", "HEAD"]).trim();
    const gitTreeSha = git(repository, ["rev-parse", "HEAD^{tree}"]).trim();
    git(repository, [
      "remote",
      "set-url",
      "origin",
      "https://github.com/tyler-james-bridges/rsi.git",
    ]);
    git(repository, ["update-ref", "refs/remotes/origin/main", commitSha]);

    const evidence = makeCiEvidence({ commitSha });
    const reviewEvidence = makeReviewEvidence({ commitSha, gitTreeSha });
    const counter = { signatures: 0, value: 0 };
    const custodyFixture = makeCustodyFixture(counter);
    const identity = Object.freeze({
      ...custodyFixture.identity,
      pinningRepositoryCommitSha: commitSha,
    });
    const paths = Object.freeze({
      archivePath: join(retained, "foundation.rsi-release"),
      ciEvidencePath: join(retained, "foundation-ci.json"),
      conclusionPath: join(retained, "foundation.readiness-conclusion.json"),
      receiptPath: join(retained, "foundation.receipt.json"),
      reportPath: join(retained, "foundation.ceremony-report.json"),
      reviewEvidencePath: join(retained, "foundation.review-evidence.json"),
      tagObjectPath: join(retained, "foundation.foundation-tag"),
    });
    await writeFile(paths.ciEvidencePath, canonicalJson(evidence), { mode: 0o600 });
    await writeFile(paths.reviewEvidencePath, canonicalJson(reviewEvidence), { mode: 0o600 });

    const ceremonyOptions: FoundationCeremonyOptions = Object.freeze({
      ciEvidencePath: paths.ciEvidencePath,
      conclusionPath: paths.conclusionPath,
      confirmCommit: commitSha,
      confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
      destinationPath: paths.archivePath,
      receiptPath: paths.receiptPath,
      reportPath: paths.reportPath,
      reviewEvidencePath: paths.reviewEvidencePath,
      tagObjectPath: paths.tagObjectPath,
    });
    let offlineChecks = 0;
    const ceremonyDependencies: FoundationCeremonyDependencies = {
      assertHostOffline: async () => {
        offlineChecks += 1;
      },
      collectInventory: async (retainedEvidence, createdAt) =>
        collectFoundationReleaseInventory({
          ciEvidence: retainedEvidence,
          createdAt,
          mode: "ceremony",
          repositoryRoot: repository,
        }),
      custody: custodyFixture.custody,
      now: () => new Date(CEREMONY_AT),
      platformIdentitySha256: async () => PLATFORM_IDENTITY_SHA256,
      platformModel: async () => "MacBook",
      readCiEvidence: async () => ({
        evidence,
        sha256: foundationCiEvidenceSha256(evidence),
      }),
      readPinnedIdentity: async () => identity,
      readReviewEvidence: async () => ({
        evidence: reviewEvidence,
        sha256: foundationIndependentReviewEvidenceSha256(reviewEvidence),
      }),
      reserveOutput: (path, suffix) => reserveFoundationOutput(path, repository, suffix),
    };
    const gitBefore = snapshotGitState(repository);
    expect(gitBefore.status).toBe("");
    expect(gitBefore.foundationTagStatus).toBe(1);

    const report = await runFoundationCeremony(ceremonyOptions, ceremonyDependencies);

    expect(report).toMatchObject({
      commitSha,
      gitTreeSha,
      signatureCount: 2,
      status: "verified-foundation-release-and-detached-tag",
    });
    expect(counter).toEqual({ signatures: 2, value: 1 });
    expect(offlineChecks).toBe(2);
    expect(snapshotGitState(repository)).toEqual(gitBefore);

    const verificationOptions: FoundationCeremonyVerificationOptions = Object.freeze({
      ...paths,
      confirmCommit: commitSha,
      confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    });
    const verificationDependencies: FoundationCeremonyVerificationDependencies = {
      collectInventory: async (repositoryRoot, retainedEvidence, createdAt) =>
        collectFoundationReleaseInventory({
          ciEvidence: retainedEvidence,
          createdAt,
          mode: "ceremony",
          repositoryRoot,
        }),
      readCiEvidence: async () => ({
        evidence,
        sha256: foundationCiEvidenceSha256(evidence),
      }),
      readPinnedIdentity: async () => identity,
      readRepositoryTree: readFoundationVerificationRepositoryTree,
      readReviewEvidence: async () => ({
        evidence: reviewEvidence,
        sha256: foundationIndependentReviewEvidenceSha256(reviewEvidence),
      }),
    };

    await expect(
      verifyFoundationCeremonyOutputs(verificationOptions, repository, verificationDependencies),
    ).resolves.toEqual(report);
    expect(counter).toEqual({ signatures: 2, value: 1 });
    expect(snapshotGitState(repository)).toEqual(gitBefore);
  }, 120_000);
});

interface GitStateSnapshot {
  readonly foundationTagStatus: number | null;
  readonly objectIds: string;
  readonly refs: string;
  readonly status: string;
}

function snapshotGitState(repository: string): GitStateSnapshot {
  return Object.freeze({
    foundationTagStatus: gitStatus(repository, [
      "show-ref",
      "--verify",
      "--quiet",
      "refs/tags/foundation-v1",
    ]),
    objectIds: git(repository, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"]),
    refs: git(repository, ["for-each-ref", "--format=%(refname):%(objectname)"]),
    status: git(repository, ["status", "--porcelain=v1", "--untracked-files=all"]),
  });
}

function git(
  repository: string,
  args: readonly string[],
  environment: NodeJS.ProcessEnv = {},
): string {
  const result = spawnSync("/usr/bin/git", args, {
    cwd: repository,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      ...environment,
    },
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    throw new Error(`fixture Git command failed: ${args[0] ?? "unknown"}`);
  }
  return result.stdout;
}

function gitStatus(repository: string, args: readonly string[]): number | null {
  return spawnSync("/usr/bin/git", args, {
    cwd: repository,
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    shell: false,
    timeout: 10_000,
  }).status;
}
