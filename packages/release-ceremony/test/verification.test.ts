import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { deriveReleaseArtifactBindings } from "@rsi/release-bundle";

import { canonicalJson } from "../src/canonical.js";
import { runFoundationCeremony } from "../src/ceremony.js";
import { foundationCiEvidenceSha256, parseFoundationCiEvidence } from "../src/ci-evidence.js";
import { reserveFoundationOutput } from "../src/host.js";
import {
  foundationIndependentReviewEvidenceSha256,
  parseFoundationIndependentReviewEvidence,
} from "../src/review-evidence.js";
import {
  FOUNDATION_RELEASE_VERSION,
  type FoundationCeremonyDependencies,
  type FoundationCeremonyOptions,
  type FoundationCiEvidenceV1,
  type FoundationReleaseInventory,
} from "../src/types.js";
import {
  decodeFoundationCeremonyReport,
  parseFoundationCeremonyReport,
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
  TREE,
} from "./helpers.js";

const cleanup: string[] = [];

interface VerificationFixture {
  readonly dependencies: FoundationCeremonyVerificationDependencies;
  readonly options: FoundationCeremonyVerificationOptions;
  readonly outputPaths: readonly string[];
  readonly report: Awaited<ReturnType<typeof runFoundationCeremony>>;
  readonly repositoryRoot: string;
}

describe("aggregate Foundation ceremony verification", () => {
  let fixture: VerificationFixture;

  beforeEach(async () => {
    fixture = await makeVerificationFixture();
  });

  afterEach(async () => {
    await Promise.all(cleanup.splice(0).map((path) => rm(path, { force: true, recursive: true })));
  });

  it("reopens and cross-binds every output and retained evidence without mutating files or Git", async () => {
    const filesBefore = await snapshotFiles(fixture.outputPaths);
    const directoryBefore = await readdir(join(fixture.repositoryRoot, "..", "retained"));
    const refsBefore = git(fixture.repositoryRoot, [
      "for-each-ref",
      "--format=%(refname):%(objectname)",
    ]);
    const objectsBefore = git(fixture.repositoryRoot, ["count-objects", "-v"]);
    const objectIdsBefore = git(fixture.repositoryRoot, [
      "cat-file",
      "--batch-all-objects",
      "--batch-check=%(objectname)",
    ]);
    const statusBefore = git(fixture.repositoryRoot, ["status", "--porcelain=v1"]);

    await expect(
      verifyFoundationCeremonyOutputs(
        fixture.options,
        fixture.repositoryRoot,
        fixture.dependencies,
      ),
    ).resolves.toEqual(fixture.report);

    expect(await snapshotFiles(fixture.outputPaths)).toEqual(filesBefore);
    expect(await readdir(join(fixture.repositoryRoot, "..", "retained"))).toEqual(directoryBefore);
    expect(git(fixture.repositoryRoot, ["for-each-ref", "--format=%(refname):%(objectname)"])).toBe(
      refsBefore,
    );
    expect(git(fixture.repositoryRoot, ["count-objects", "-v"])).toBe(objectsBefore);
    expect(
      git(fixture.repositoryRoot, [
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname)",
      ]),
    ).toBe(objectIdsBefore);
    expect(git(fixture.repositoryRoot, ["status", "--porcelain=v1"])).toBe(statusBefore);
  });

  it("reads the production-eligible repository tree without mutating Git state", () => {
    const commit = git(fixture.repositoryRoot, ["rev-parse", "HEAD"]).trim();
    const tree = git(fixture.repositoryRoot, ["rev-parse", "HEAD^{tree}"]).trim();
    const refsBefore = git(fixture.repositoryRoot, [
      "for-each-ref",
      "--format=%(refname):%(objectname)",
    ]);
    const objectsBefore = git(fixture.repositoryRoot, ["count-objects", "-v"]);
    const objectIdsBefore = git(fixture.repositoryRoot, [
      "cat-file",
      "--batch-all-objects",
      "--batch-check=%(objectname)",
    ]);
    const statusBefore = git(fixture.repositoryRoot, ["status", "--porcelain=v1"]);

    expect(readFoundationVerificationRepositoryTree(fixture.repositoryRoot, commit)).toBe(tree);

    expect(git(fixture.repositoryRoot, ["for-each-ref", "--format=%(refname):%(objectname)"])).toBe(
      refsBefore,
    );
    expect(git(fixture.repositoryRoot, ["count-objects", "-v"])).toBe(objectsBefore);
    expect(
      git(fixture.repositoryRoot, [
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname)",
      ]),
    ).toBe(objectIdsBefore);
    expect(git(fixture.repositoryRoot, ["status", "--porcelain=v1"])).toBe(statusBefore);
  });

  it.each([
    "dirty",
    "wrong-branch",
    "wrong-remote",
    "spoofed-remote",
    "replace",
    "graft",
    "shallow",
  ] as const)("production repository eligibility refuses %s state", async (state) => {
    const commit = git(fixture.repositoryRoot, ["rev-parse", "HEAD"]).trim();
    if (state === "dirty") {
      await writeFile(join(fixture.repositoryRoot, "dirty.txt"), "dirty\n", { mode: 0o600 });
    } else if (state === "wrong-branch") {
      git(fixture.repositoryRoot, ["checkout", "--quiet", "-b", "feature"]);
    } else if (state === "wrong-remote") {
      git(fixture.repositoryRoot, [
        "remote",
        "set-url",
        "origin",
        "https://example.invalid/not-rsi.git",
      ]);
    } else if (state === "spoofed-remote") {
      git(fixture.repositoryRoot, ["remote", "set-url", "origin", "https://evil.invalid/rsi.git"]);
      git(fixture.repositoryRoot, [
        "config",
        "url.https://github.com/tyler-james-bridges/.insteadOf",
        "https://evil.invalid/",
      ]);
      expect(git(fixture.repositoryRoot, ["remote", "get-url", "origin"]).trim()).toBe(
        "https://github.com/tyler-james-bridges/rsi.git",
      );
    } else if (state === "replace") {
      git(fixture.repositoryRoot, ["update-ref", `refs/replace/${commit}`, commit]);
    } else if (state === "graft") {
      const graftsPath = join(
        fixture.repositoryRoot,
        git(fixture.repositoryRoot, ["rev-parse", "--git-path", "info/grafts"]).trim(),
      );
      await mkdir(dirname(graftsPath), { recursive: true });
      await writeFile(graftsPath, `${commit}\n`, { mode: 0o600 });
    } else {
      await writeFile(join(fixture.repositoryRoot, ".git", "shallow"), `${commit}\n`, {
        mode: 0o600,
      });
    }

    expect(() =>
      readFoundationVerificationRepositoryTree(fixture.repositoryRoot, commit),
    ).toThrow();
  });

  it("disables a hostile repository-local fsmonitor during production inspection", async () => {
    const commit = git(fixture.repositoryRoot, ["rev-parse", "HEAD"]).trim();
    const tree = git(fixture.repositoryRoot, ["rev-parse", "HEAD^{tree}"]).trim();
    const hook = join(fixture.repositoryRoot, ".git", "hostile-fsmonitor.sh");
    const marker = `${hook}.called`;
    await writeFile(hook, '#!/bin/sh\n/usr/bin/touch "${0}.called"\nexit 1\n', { mode: 0o700 });
    await chmod(hook, 0o700);
    git(fixture.repositoryRoot, ["config", "core.fsmonitor", hook]);

    expect(readFoundationVerificationRepositoryTree(fixture.repositoryRoot, commit)).toBe(tree);
    await expect(stat(marker)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each([
    "bundle",
    "receipt",
    "conclusion",
    "tag",
    "report",
    "ci-evidence",
    "review-evidence",
  ] as const)("refuses a canonical or cryptographic %s tamper", async (target) => {
    await tamper(target, fixture.options);
    await expect(
      verifyFoundationCeremonyOutputs(
        fixture.options,
        fixture.repositoryRoot,
        fixture.dependencies,
      ),
    ).rejects.toBeInstanceOf(Error);
  });

  it("refuses an empty completion marker as a partial ceremony", async () => {
    await writeFile(fixture.options.conclusionPath, Buffer.alloc(0));
    await expect(
      verifyFoundationCeremonyOutputs(
        fixture.options,
        fixture.repositoryRoot,
        fixture.dependencies,
      ),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("refuses a missing retained output as a partial ceremony", async () => {
    await rm(fixture.options.reportPath);
    await expect(
      verifyFoundationCeremonyOutputs(
        fixture.options,
        fixture.repositoryRoot,
        fixture.dependencies,
      ),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  });

  it("strictly rejects noncanonical, extended, or unsuccessful v2 reports", async () => {
    const canonical = canonicalJson(fixture.report);
    expect(decodeFoundationCeremonyReport(canonical)).toEqual(fixture.report);
    expect(() => decodeFoundationCeremonyReport(`${canonical}\n`)).toThrow(/canonical/u);
    expect(() => parseFoundationCeremonyReport({ ...fixture.report, extra: true })).toThrow(
      /unsupported/u,
    );
    expect(() =>
      parseFoundationCeremonyReport({ ...fixture.report, status: "verification-pending" }),
    ).toThrow(/status/u);
  });

  it.each([
    ["commit", { commitSha: "c".repeat(40) }],
    ["tree", { gitTreeSha: "d".repeat(40) }],
    ["signer", { signerFingerprintSha256: "e".repeat(64) }],
    ["release", { releaseVersion: "0.1.0" }],
  ] as const)("refuses a report %s mismatch", async (_label, patch) => {
    await rewriteCanonical(fixture.options.reportPath, (value) => ({ ...value, ...patch }));
    await expect(
      verifyFoundationCeremonyOutputs(
        fixture.options,
        fixture.repositoryRoot,
        fixture.dependencies,
      ),
    ).rejects.toBeInstanceOf(Error);
  });

  it("refuses a repository tree that changes between identity checks", async () => {
    let calls = 0;
    const dependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
      ...fixture.dependencies,
      readRepositoryTree: () => {
        calls += 1;
        return calls === 1 ? TREE : "d".repeat(40);
      },
    });
    await expect(
      verifyFoundationCeremonyOutputs(fixture.options, fixture.repositoryRoot, dependencies),
    ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
    expect(calls).toBe(2);
  });

  it("independently refuses review evidence predating retained CI", async () => {
    const dependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
      ...fixture.dependencies,
      readReviewEvidence: async () => ({
        evidence: makeReviewEvidence({ reviewedAt: "2026-08-17T23:59:59.000Z" }),
        sha256: fixture.report.independentReviewEvidenceSha256,
      }),
    });
    await expect(
      verifyFoundationCeremonyOutputs(fixture.options, fixture.repositoryRoot, dependencies),
    ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
  });

  it("refuses authenticated review evidence stale relative to the signed bundle creation time", async () => {
    const dependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
      ...fixture.dependencies,
      readCiEvidence: async () => ({
        evidence: makeCiEvidence({ completedAt: "2026-08-10T00:00:00.000Z" }),
        sha256: fixture.report.ciEvidenceSha256,
      }),
      readReviewEvidence: async () => ({
        evidence: makeReviewEvidence({ reviewedAt: "2026-08-10T00:01:00.000Z" }),
        sha256: fixture.report.independentReviewEvidenceSha256,
      }),
    });
    await expect(
      verifyFoundationCeremonyOutputs(fixture.options, fixture.repositoryRoot, dependencies),
    ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
  });

  it("refuses authenticated review evidence more than five minutes after signed bundle creation", async () => {
    const dependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
      ...fixture.dependencies,
      readReviewEvidence: async () => ({
        evidence: makeReviewEvidence({ reviewedAt: "2026-08-18T01:05:00.001Z" }),
        sha256: fixture.report.independentReviewEvidenceSha256,
      }),
    });
    await expect(
      verifyFoundationCeremonyOutputs(fixture.options, fixture.repositoryRoot, dependencies),
    ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
  });

  it("passes the confirmed commit into the authenticated-review trust reader", async () => {
    let receivedCommit: string | undefined;
    const dependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
      ...fixture.dependencies,
      readReviewEvidence: async (path: string, repositoryRoot: string, commitSha: string) => {
        receivedCommit = commitSha;
        return fixture.dependencies.readReviewEvidence(path, repositoryRoot, commitSha);
      },
    });
    await verifyFoundationCeremonyOutputs(fixture.options, fixture.repositoryRoot, dependencies);
    expect(receivedCommit).toBe(COMMIT);
  });

  it("refuses a freshly signed, internally consistent bundle whose source inventory is wrong", async () => {
    const mismatched = await makeVerificationFixture({
      ceremonyInventory: makeSourceMismatchedInventory,
    });
    const matchingDependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
      ...mismatched.dependencies,
      collectInventory: async (
        _repositoryRoot: string,
        _evidence: FoundationCiEvidenceV1,
        createdAt: string,
      ) => makeSourceMismatchedInventory(createdAt),
    });

    await expect(
      verifyFoundationCeremonyOutputs(
        mismatched.options,
        mismatched.repositoryRoot,
        matchingDependencies,
      ),
    ).resolves.toEqual(mismatched.report);
    await expect(
      verifyFoundationCeremonyOutputs(
        mismatched.options,
        mismatched.repositoryRoot,
        mismatched.dependencies,
      ),
    ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
  });
});

async function makeVerificationFixture(
  fixtureOptions: {
    readonly ceremonyInventory?: (createdAt: string) => FoundationReleaseInventory;
  } = {},
): Promise<VerificationFixture> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "rsi-foundation-verification-")));
  cleanup.push(root);
  await chmod(root, 0o700);
  const repositoryRoot = join(root, "repository");
  const retainedRoot = join(root, "retained");
  await mkdir(repositoryRoot, { mode: 0o700 });
  await mkdir(retainedRoot, { mode: 0o700 });
  git(repositoryRoot, ["init", "--quiet", "--initial-branch=main"]);
  await writeFile(join(repositoryRoot, "README.md"), "verification fixture\n", { mode: 0o600 });
  git(repositoryRoot, ["add", "README.md"]);
  git(repositoryRoot, [
    "-c",
    "user.name=RSI Test",
    "-c",
    "user.email=rsi-test@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "--quiet",
    "--message",
    "verification fixture",
  ]);
  const fixtureCommit = git(repositoryRoot, ["rev-parse", "HEAD"]).trim();
  git(repositoryRoot, [
    "remote",
    "add",
    "origin",
    "https://github.com/tyler-james-bridges/rsi.git",
  ]);
  git(repositoryRoot, ["update-ref", "refs/remotes/origin/main", fixtureCommit]);

  const evidence = makeCiEvidence();
  const reviewEvidence = makeReviewEvidence();
  const counter = { signatures: 0, value: 0 };
  const custody = makeCustodyFixture(counter);
  const paths = Object.freeze({
    archivePath: join(retainedRoot, "foundation.rsi-release"),
    ciEvidencePath: join(retainedRoot, "foundation-ci.json"),
    conclusionPath: join(retainedRoot, "foundation.readiness-conclusion.json"),
    receiptPath: join(retainedRoot, "foundation.receipt.json"),
    reportPath: join(retainedRoot, "foundation.ceremony-report.json"),
    reviewEvidencePath: join(retainedRoot, "foundation.review-evidence.json"),
    tagObjectPath: join(retainedRoot, "foundation.foundation-tag"),
  });
  await writeFile(paths.ciEvidencePath, canonicalJson(evidence), { mode: 0o600 });
  await writeFile(paths.reviewEvidencePath, canonicalJson(reviewEvidence), { mode: 0o600 });

  const ceremonyOptions: FoundationCeremonyOptions = Object.freeze({
    ciEvidencePath: paths.ciEvidencePath,
    conclusionPath: paths.conclusionPath,
    confirmCommit: COMMIT,
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    destinationPath: paths.archivePath,
    receiptPath: paths.receiptPath,
    reportPath: paths.reportPath,
    reviewEvidencePath: paths.reviewEvidencePath,
    tagObjectPath: paths.tagObjectPath,
  });
  const ceremonyDependencies: FoundationCeremonyDependencies = {
    assertHostOffline: async () => undefined,
    collectInventory: async (_retainedEvidence, createdAt) =>
      fixtureOptions.ceremonyInventory?.(createdAt) ?? makeInventory(createdAt),
    custody: custody.custody,
    now: () => new Date(CEREMONY_AT),
    platformIdentitySha256: async () => PLATFORM_IDENTITY_SHA256,
    platformModel: async () => "MacBook",
    readCiEvidence: async () => ({ evidence, sha256: foundationCiEvidenceSha256(evidence) }),
    readPinnedIdentity: async () => custody.identity,
    readReviewEvidence: async () => ({
      evidence: reviewEvidence,
      sha256: foundationIndependentReviewEvidenceSha256(reviewEvidence),
    }),
    reserveOutput: (path, suffix) => reserveFoundationOutput(path, repositoryRoot, suffix),
  };
  const report = await runFoundationCeremony(ceremonyOptions, ceremonyDependencies);
  expect(counter).toEqual({ signatures: 2, value: 1 });

  const dependencies: FoundationCeremonyVerificationDependencies = Object.freeze({
    collectInventory: async (
      _repositoryRoot: string,
      _retainedEvidence: FoundationCiEvidenceV1,
      createdAt: string,
    ) => makeInventory(createdAt),
    readCiEvidence: async (path: string) => {
      const value = parseFoundationCiEvidence(JSON.parse(await readFile(path, "utf8")) as unknown);
      return Object.freeze({ evidence: value, sha256: foundationCiEvidenceSha256(value) });
    },
    readPinnedIdentity: async () => custody.identity,
    readRepositoryTree: () => TREE,
    readReviewEvidence: async (path: string) => {
      const value = parseFoundationIndependentReviewEvidence(
        JSON.parse(await readFile(path, "utf8")) as unknown,
      );
      return Object.freeze({
        evidence: value,
        sha256: foundationIndependentReviewEvidenceSha256(value),
      });
    },
  });
  const options: FoundationCeremonyVerificationOptions = Object.freeze({
    ...paths,
    confirmCommit: COMMIT,
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
  });
  return Object.freeze({
    dependencies,
    options,
    outputPaths: Object.freeze(Object.values(paths)),
    report,
    repositoryRoot,
  });
}

function makeSourceMismatchedInventory(createdAt: string): FoundationReleaseInventory {
  const expected = makeInventory(createdAt);
  const artifacts = Object.freeze(
    expected.artifacts.map((artifact) =>
      artifact.path === "source/packages/observer/src/index.ts"
        ? Object.freeze({
            ...artifact,
            bytes: new TextEncoder().encode("export const observer = false;\n"),
          })
        : artifact,
    ),
  );
  const bindings = deriveReleaseArtifactBindings(artifacts);
  return Object.freeze({
    artifacts,
    release: Object.freeze({ ...expected.release, ...bindings }),
    report: Object.freeze({ ...expected.report, ...bindings }),
  });
}

async function tamper(
  target:
    "bundle" | "ci-evidence" | "conclusion" | "receipt" | "report" | "review-evidence" | "tag",
  options: FoundationCeremonyVerificationOptions,
): Promise<void> {
  if (target === "bundle" || target === "tag") {
    const path = target === "bundle" ? options.archivePath : options.tagObjectPath;
    const bytes = await readFile(path);
    bytes[Math.max(0, bytes.length - 8)]! ^= 1;
    await writeFile(path, bytes);
    bytes.fill(0);
    return;
  }
  if (target === "receipt") {
    await rewriteCanonical(options.receiptPath, (value) => ({
      ...value,
      manifestSha256: "0".repeat(64),
    }));
    return;
  }
  if (target === "conclusion") {
    await rewriteCanonical(options.conclusionPath, (value) => ({
      ...value,
      sourceTreeSha256: "0".repeat(64),
    }));
    return;
  }
  if (target === "report") {
    await rewriteCanonical(options.reportPath, (value) => ({
      ...value,
      archiveSha256: "0".repeat(64),
    }));
    return;
  }
  if (target === "ci-evidence") {
    await rewriteCanonical(options.ciEvidencePath, (value) => ({
      ...value,
      runId: "32034831277",
      runUrl: "https://github.com/tyler-james-bridges/rsi/actions/runs/32034831277",
    }));
    return;
  }
  await rewriteCanonical(options.reviewEvidencePath, (value) => ({
    ...value,
    reviewerId: "different-independent-reviewer",
  }));
}

async function rewriteCanonical(
  path: string,
  update: (value: Record<string, unknown>) => Record<string, unknown>,
): Promise<void> {
  const value = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  await writeFile(path, canonicalJson(update(value)));
}

async function snapshotFiles(paths: readonly string[]) {
  return Promise.all(
    paths.map(async (path) => {
      const [bytes, metadata] = await Promise.all([readFile(path), stat(path, { bigint: true })]);
      return Object.freeze({
        bytes: bytes.toString("base64"),
        inode: metadata.ino,
        mode: Number(metadata.mode) & 0o777,
        modifiedNanoseconds: metadata.mtimeNs,
        path,
        size: metadata.size,
      });
    }),
  );
}

function git(repositoryRoot: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    throw new Error(`Verification fixture Git command failed: ${args[0] ?? "unknown"}`);
  }
  return result.stdout;
}
