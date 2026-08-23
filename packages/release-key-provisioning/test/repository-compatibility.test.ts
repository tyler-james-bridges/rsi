import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson, sha256 } from "../src/canonical.js";
import {
  RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
  RELEASE_KEY_HELPER_PATH,
  type ReleaseKeyHelperCompatibilityEvidenceV1,
} from "../src/helper-compatibility-evidence.js";
import { assertProvisioningRepositoryEligible } from "../src/host.js";
import { runReleaseKeyProvisioning } from "../src/provisioning.js";
import {
  RELEASE_KEYCHAIN_ACCOUNT,
  type KeychainHelperEvidenceV1,
  type ReleaseKeyProvisioningDependencies,
} from "../src/types.js";

const directories: string[] = [];
const originalUserAgent = process.env.npm_config_user_agent;

afterEach(async () => {
  if (originalUserAgent === undefined) delete process.env.npm_config_user_agent;
  else process.env.npm_config_user_agent = originalUserAgent;
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe.skipIf(process.platform !== "darwin")(
  "tracked release-key helper compatibility eligibility",
  () => {
    it("keeps valid v1 evidence inspection-only and refuses provisioning authorization", async () => {
      const fixture = await makeRepository();
      await expect(
        withExactPnpmRuntime(() =>
          assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
        ),
      ).rejects.toMatchObject({
        code: "REPOSITORY_STATE",
        message:
          "V1 helper compatibility evidence is inspection-only and cannot authorize release-key provisioning",
      });
    });

    it("rejects an absent tracked evidence blob", async () => {
      const fixture = await makeRepository({ omitEvidence: true });
      await expect(
        withExactPnpmRuntime(() =>
          assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
        ),
      ).rejects.toMatchObject({ code: "REPOSITORY_STATE" });
    });

    it("rejects a non-ancestor test commit or changed current helper source", async () => {
      for (const options of [
        { unrelatedTestedCommit: true },
        { evidenceSourceSha256: "8".repeat(64) },
      ] as const) {
        const fixture = await makeRepository(options);
        await expect(
          withExactPnpmRuntime(() =>
            assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
          ),
        ).rejects.toMatchObject({ code: "REPOSITORY_STATE" });
      }
    });

    it("rejects mismatched helper binary, compiler, source, macOS, Node, or pnpm bindings", async () => {
      const helperFields = ["binarySha256", "compilerIdentitySha256", "sourceSha256"] as const;
      for (const field of helperFields) {
        const fixture = await makeRepository();
        await expect(
          withExactPnpmRuntime(() =>
            assertProvisioningRepositoryEligible(fixture.root, {
              ...fixture.helper,
              [field]: "7".repeat(64),
            }),
          ),
        ).rejects.toMatchObject({ code: "REPOSITORY_STATE" });
      }

      for (const options of [
        { macosBuildVersion: "25B79" },
        { macosProductVersion: "26.1.1" },
      ] as const) {
        const fixture = await makeRepository(options);
        await expect(
          withExactPnpmRuntime(() =>
            assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
          ),
        ).rejects.toMatchObject({ code: "REPOSITORY_STATE" });
      }

      const fixture = await makeRepository();
      process.env.npm_config_user_agent = "pnpm/11.20.1 node/v24.19.0";
      await expect(
        assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
      ).rejects.toMatchObject({ code: "REPOSITORY_STATE" });
    });

    it("forces core.fsmonitor off instead of executing repository-configured code", async () => {
      const fixture = await makeRepository();
      const hookPath = join(fixture.root, ".git", "hostile-fsmonitor.sh");
      const sentinelPath = join(fixture.root, ".git", "hostile-fsmonitor-executed");
      await writeFile(
        hookPath,
        `#!/bin/sh\n/usr/bin/touch ${JSON.stringify(sentinelPath)}\nprintf '\\n'\n`,
        { mode: 0o700 },
      );
      await chmod(hookPath, 0o700);
      git(fixture.root, ["config", "--local", "core.fsmonitor", hookPath]);

      await expect(
        withExactPnpmRuntime(() =>
          assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
        ),
      ).rejects.toMatchObject({
        code: "REPOSITORY_STATE",
        message:
          "V1 helper compatibility evidence is inspection-only and cannot authorize release-key provisioning",
      });
      await expect(lstat(sentinelPath)).rejects.toMatchObject({ code: "ENOENT" });
    });

    it("rejects a raw evil origin even when url.insteadOf makes get-url look approved", async () => {
      const fixture = await makeRepository();
      const evilRemote = "https://evil.example.invalid/redirected-rsi.git";
      const approvedRemote = "https://github.com/tyler-james-bridges/rsi.git";
      git(fixture.root, ["remote", "set-url", "origin", evilRemote]);
      git(fixture.root, ["config", `url.${approvedRemote}.insteadOf`, evilRemote]);
      expect(git(fixture.root, ["remote", "get-url", "origin"]).trim()).toBe(approvedRemote);

      await expect(
        withExactPnpmRuntime(() =>
          assertProvisioningRepositoryEligible(fixture.root, fixture.helper),
        ),
      ).rejects.toMatchObject({
        code: "REPOSITORY_STATE",
        message: "Release-key provisioning repository identity is ineligible",
      });
    });

    it("wires the real V1 refusal before every media, state, secret, or mutation dependency", async () => {
      const fixture = await makeRepository();
      const entryCalls = {
        helperEvidence: 0,
        offline: 0,
        platformIdentity: 0,
        repository: 0,
      };
      let downstreamCalls = 0;
      const downstream = (): never => {
        downstreamCalls += 1;
        throw new Error("downstream provisioning dependency must remain unreachable");
      };
      const dependencies: ReleaseKeyProvisioningDependencies = {
        async assertHostOffline() {
          entryCalls.offline += 1;
        },
        async assertRepositoryEligible(helperEvidence) {
          entryCalls.repository += 1;
          return assertProvisioningRepositoryEligible(fixture.root, helperEvidence);
        },
        generateKeyMaterial: downstream,
        inspectRecoveryTarget: async () => downstream(),
        keychain: {
          addCreateOnly: async () => downstream(),
          async helperEvidence() {
            entryCalls.helperEvidence += 1;
            return fixture.helper;
          },
          inspectPresence: async () => downstream(),
          verifyAclAndMatch: async () => downstream(),
        },
        now: downstream,
        passphrase: async () => downstream(),
        async platformIdentitySha256() {
          entryCalls.platformIdentity += 1;
          return "9".repeat(64);
        },
        platformModel: async () => "MacBook",
        readEnvelope: async () => downstream(),
        readIntent: async () => downstream(),
        readPublicIdentity: async () => downstream(),
        readReceipt: async () => downstream(),
        reverifyRecoveryTargetAfterRemount: async () => downstream(),
        writeEnvelopeCreateOnly: async () => downstream(),
        writeIntentCreateOnly: async () => downstream(),
        writePublicIdentityCreateOnly: async () => downstream(),
        writeReceiptCreateOnly: async () => downstream(),
      };

      await expect(
        withExactPnpmRuntime(() =>
          runReleaseKeyProvisioning(
            {
              backupDirectories: [
                "/Volumes/RSI Recovery 1/foundation",
                "/Volumes/RSI Recovery 2/foundation",
              ],
              confirmAccount: RELEASE_KEYCHAIN_ACCOUNT,
              confirmCopyCount: 2,
              mode: "create",
              publicIdentityPath: "/private/tmp/foundation.release-public-identity.json",
              receiptPath: "/private/tmp/foundation.release-key-provisioning-receipt.json",
            },
            dependencies,
          ),
        ),
      ).rejects.toMatchObject({
        code: "REPOSITORY_STATE",
        message:
          "V1 helper compatibility evidence is inspection-only and cannot authorize release-key provisioning",
      });
      expect(entryCalls).toEqual({
        helperEvidence: 1,
        offline: 1,
        platformIdentity: 1,
        repository: 1,
      });
      expect(downstreamCalls).toBe(0);
    });
  },
);

async function makeRepository(
  options: {
    readonly evidenceSourceSha256?: string;
    readonly macosBuildVersion?: string;
    readonly macosProductVersion?: string;
    readonly omitEvidence?: boolean;
    readonly testedCommitSha?: string;
    readonly unrelatedTestedCommit?: boolean;
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "rsi-helper-compat-repo-"));
  directories.push(root);
  git(root, ["init", "-b", "main"]);
  const source = Buffer.from("import Foundation\n", "utf8");
  const helperPath = join(root, RELEASE_KEY_HELPER_PATH);
  await mkdir(dirname(helperPath), { recursive: true });
  await writeFile(helperPath, source, { mode: 0o600 });
  git(root, ["add", RELEASE_KEY_HELPER_PATH]);
  commit(root, "tested helper");
  const testedCommit = git(root, ["rev-parse", "HEAD"]).trim();
  const unrelatedTestedCommit =
    options.unrelatedTestedCommit === true
      ? git(root, [
          "-c",
          "user.name=RSI Test",
          "-c",
          "user.email=rsi-test@example.invalid",
          "commit-tree",
          git(root, ["rev-parse", "HEAD^{tree}"]).trim(),
          "-m",
          "unrelated tested helper",
        ]).trim()
      : undefined;
  const helper = Object.freeze({
    binarySha256: "b".repeat(64),
    compilerIdentitySha256: "c".repeat(64),
    sourceSha256: options.evidenceSourceSha256 ?? sha256(source),
  }) satisfies KeychainHelperEvidenceV1;

  let evidenceBytes: Buffer | undefined;
  if (options.omitEvidence !== true) {
    const evidence = compatibilityEvidence({
      helper,
      ...(options.macosBuildVersion === undefined
        ? {}
        : { macosBuildVersion: options.macosBuildVersion }),
      ...(options.macosProductVersion === undefined
        ? {}
        : { macosProductVersion: options.macosProductVersion }),
      testedCommitSha: options.testedCommitSha ?? unrelatedTestedCommit ?? testedCommit,
    });
    evidenceBytes = Buffer.from(canonicalJson(evidence), "utf8");
    const evidencePath = join(root, RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH);
    await mkdir(dirname(evidencePath), { recursive: true });
    await writeFile(evidencePath, evidenceBytes, { mode: 0o600 });
    git(root, ["add", RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH]);
    commit(root, "record compatibility evidence");
  }
  git(root, ["remote", "add", "origin", "https://github.com/tyler-james-bridges/rsi.git"]);
  git(root, ["update-ref", "refs/remotes/origin/main", "HEAD"]);
  const currentCommit = git(root, ["rev-parse", "HEAD"]).trim();
  source.fill(0);
  return { currentCommit, evidenceBytes, helper, root, testedCommit };
}

function compatibilityEvidence(options: {
  readonly helper: KeychainHelperEvidenceV1;
  readonly macosBuildVersion?: string;
  readonly macosProductVersion?: string;
  readonly testedCommitSha: string;
}): ReleaseKeyHelperCompatibilityEvidenceV1 {
  if (process.arch !== "arm64" && process.arch !== "x64") {
    throw new Error("unsupported test architecture");
  }
  return {
    cleanup: {
      evidenceSha256: "a".repeat(64),
      keychainItem: "deleted-and-absence-verified",
      outcome: "passed",
      temporaryArtifacts: "removed-and-absence-verified",
      testPrivateMaterial: "destroyed-and-absence-verified",
    },
    completedAt: "2026-08-23T09:00:00.000Z",
    drillId: "throwaway-macbook-helper-host-test",
    drillOperatorId: "drill-operator-1",
    environment: {
      architecture: process.arch,
      hardwareClass: "MacBook",
      macosBuildVersion: options.macosBuildVersion ?? swVers("-buildVersion"),
      macosProductVersion: options.macosProductVersion ?? swVers("-productVersion"),
      nodeVersion: "v24.19.0",
      pnpmVersion: "11.20.0",
    },
    evidencePath: RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
    evidenceType: "rsi.release-key-helper-compatibility-evidence",
    helper: options.helper,
    helperPath: RELEASE_KEY_HELPER_PATH,
    independentApproval: {
      approvedAt: "2026-08-23T10:00:00.000Z",
      approvalEvidenceSha256: "d".repeat(64),
      authorship: "did-not-author-tested-helper-or-evidence",
      drillParticipation: "did-not-operate-drill",
      reviewerId: "independent-reviewer-1",
      reviewerRole: "independent-non-authoring-reviewer",
      verdict: "approved",
    },
    keychainControls: {
      accessibility: "when-unlocked-this-device-only",
      dataProtectionKeychain: "verified",
      evidenceSha256: "e".repeat(64),
      persistentApproval: "not-granted",
      synchronizable: "disabled",
      unauthorizedAlternateClientAccess: "refused",
      userPresence: "required",
    },
    privateMaterialLeakScan: {
      evidenceSha256: "f".repeat(64),
      outcome: "passed",
      scopes: [
        { name: "process-arguments", outcome: "passed" },
        { name: "process-environment", outcome: "passed" },
        { name: "standard-output", outcome: "passed" },
        { name: "standard-error", outcome: "passed" },
        { name: "logs-and-diagnostics", outcome: "passed" },
        { name: "filesystem-artifacts", outcome: "passed" },
      ],
    },
    prompts: [
      {
        attempt: 1,
        evidenceSha256: "1".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "first-fresh-helper-invocation",
        signatureVerification: "passed",
      },
      {
        attempt: 2,
        evidenceSha256: "2".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "second-fresh-helper-invocation-after-first-completed",
        signatureVerification: "passed",
      },
    ],
    repository: "tyler-james-bridges/rsi",
    repositoryVisibility: "public",
    testedCommitSha: options.testedCommitSha,
    verdict: "passed",
    version: 1,
  };
}

async function withExactPnpmRuntime<T>(operation: () => Promise<T>): Promise<T> {
  const nodeVersion = process.versions.node;
  const version = process.version;
  process.env.npm_config_user_agent = "pnpm/11.20.0 node/v24.19.0 darwin arm64";
  Object.defineProperty(process.versions, "node", { configurable: true, value: "24.19.0" });
  Object.defineProperty(process, "version", { configurable: true, value: "v24.19.0" });
  try {
    return await operation();
  } finally {
    Object.defineProperty(process.versions, "node", { configurable: true, value: nodeVersion });
    Object.defineProperty(process, "version", { configurable: true, value: version });
  }
}

function commit(root: string, message: string): void {
  git(root, [
    "-c",
    "user.name=RSI Test",
    "-c",
    "user.email=rsi-test@example.invalid",
    "commit",
    "-m",
    message,
  ]);
}

function git(root: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", args, {
    cwd: root,
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 2 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    throw new Error(`git fixture command failed: ${args[0] ?? "unknown"}`);
  }
  return result.stdout;
}

function swVers(argument: "-buildVersion" | "-productVersion"): string {
  const result = spawnSync("/usr/bin/sw_vers", [argument], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 4 * 1024,
    shell: false,
    timeout: 5_000,
  });
  if (result.status !== 0 || result.signal !== null) throw new Error("sw_vers failed");
  return result.stdout.trim();
}
