import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { runFoundationCeremony } from "../src/ceremony.js";
import { foundationCiEvidenceSha256 } from "../src/ci-evidence.js";
import { reserveFoundationOutput } from "../src/host.js";
import { foundationIndependentReviewEvidenceSha256 } from "../src/review-evidence.js";
import {
  FOUNDATION_RELEASE_VERSION,
  type FoundationCeremonyDependencies,
  type FoundationCeremonyOptions,
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
});

function git(repository: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", args, {
    cwd: repository,
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    shell: false,
    timeout: 10_000,
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
