import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { readPinnedFoundationReleaseIdentity } from "../src/host.js";

const HELPER_PATH = "packages/release-key-provisioning/native/keychain-helper.swift";
const COMPATIBILITY_PATH = "config/foundation-release-key-helper-compatibility.v1.json";
const IDENTITY_PATH = "config/foundation-release-identity.v1.json";
const RECEIPT_PATH = "config/foundation-release-key-provisioning-receipt.v1.json";
const REVIEWED_HELPER_SOURCE = "// reviewed native helper\n";
const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("repository-pinned foundation identity lineage", () => {
  it("inspects an exact v1 lineage but refuses it as release-key custody authorization", async () => {
    const fixture = await makeLineageFixture();

    await expect(
      readPinnedFoundationReleaseIdentity(fixture.repositoryRoot, fixture.pinningCommitSha),
    ).rejects.toMatchObject({
      code: "CUSTODY_FAILED",
      message:
        "V1 helper compatibility evidence is inspection-only and cannot authorize release-key custody",
    });
  });

  it("rejects compatibility evidence whose tested commit is outside provisioning ancestry", async () => {
    const fixture = await makeLineageFixture({ testedCommitOutsideLineage: true });

    await expect(
      readPinnedFoundationReleaseIdentity(fixture.repositoryRoot, fixture.pinningCommitSha),
    ).rejects.toMatchObject({
      code: "CUSTODY_FAILED",
      message: "Tested helper commit is not an ancestor of the provisioning source commit",
    });
  });

  it("rejects compatibility evidence changed between provisioning and pinning", async () => {
    const fixture = await makeLineageFixture({ changeCompatibilityAtPinning: true });

    await expect(
      readPinnedFoundationReleaseIdentity(fixture.repositoryRoot, fixture.pinningCommitSha),
    ).rejects.toMatchObject({
      code: "CUSTODY_FAILED",
      message:
        "Provisioning lineage does not contain the exact reviewed helper compatibility evidence",
    });
  });

  it.each([
    ["tested commit", { testedHelperSource: "// unreviewed tested helper\n" }],
    ["provisioning commit", { provisioningHelperSource: "// changed during provisioning\n" }],
    ["pinning commit", { pinningHelperSource: "// changed while pinning identity\n" }],
  ] as const)("rejects a helper changed at the %s", async (_label, options) => {
    const fixture = await makeLineageFixture(options);

    await expect(
      readPinnedFoundationReleaseIdentity(fixture.repositoryRoot, fixture.pinningCommitSha),
    ).rejects.toMatchObject({ code: "CUSTODY_FAILED" });
  });
});

interface LineageFixtureOptions {
  readonly changeCompatibilityAtPinning?: boolean;
  readonly pinningHelperSource?: string;
  readonly provisioningHelperSource?: string;
  readonly testedCommitOutsideLineage?: boolean;
  readonly testedHelperSource?: string;
}

interface LineageFixture {
  readonly compatibilityEvidenceSha256: string;
  readonly pinningCommitSha: string;
  readonly provisioningCommitSha: string;
  readonly repositoryRoot: string;
  readonly testedCommitSha: string;
}

async function makeLineageFixture(options: LineageFixtureOptions = {}): Promise<LineageFixture> {
  const repositoryRoot = await realpath(await mkdtemp(join(tmpdir(), "rsi-ceremony-lineage-")));
  cleanup.push(repositoryRoot);
  git(repositoryRoot, ["init", "--quiet", "--initial-branch=main"]);
  await writeTracked(repositoryRoot, "seed.txt", "foundation lineage seed\n");
  const seedCommitSha = commit(repositoryRoot, "seed");

  const testedHelperSource = options.testedHelperSource ?? REVIEWED_HELPER_SOURCE;
  let testedCommitSha: string;
  if (options.testedCommitOutsideLineage === true) {
    git(repositoryRoot, ["switch", "--quiet", "--create", "tested-helper-side"]);
    await writeTracked(repositoryRoot, HELPER_PATH, testedHelperSource);
    testedCommitSha = commit(repositoryRoot, "tested helper outside main lineage");
    git(repositoryRoot, ["switch", "--quiet", "main"]);
    expect(git(repositoryRoot, ["rev-parse", "HEAD"]).trim()).toBe(seedCommitSha);
  } else {
    await writeTracked(repositoryRoot, HELPER_PATH, testedHelperSource);
    testedCommitSha = commit(repositoryRoot, "tested helper");
  }

  const helperSourceSha256 = sha256(REVIEWED_HELPER_SOURCE);
  const provisioningCompatibility = makeCompatibilityEvidence(
    testedCommitSha,
    helperSourceSha256,
    "throwaway-macbook-helper-drill",
  );
  await writeTracked(
    repositoryRoot,
    HELPER_PATH,
    options.provisioningHelperSource ?? REVIEWED_HELPER_SOURCE,
  );
  await writeTracked(repositoryRoot, COMPATIBILITY_PATH, canonicalJson(provisioningCompatibility));
  await writeTracked(repositoryRoot, "provisioning-source.txt", "provisioning source A\n");
  const provisioningCommitSha = commit(repositoryRoot, "provisioning source");

  const pinningCompatibility =
    options.changeCompatibilityAtPinning === true
      ? makeCompatibilityEvidence(
          testedCommitSha,
          helperSourceSha256,
          "throwaway-macbook-helper-drill-replaced",
        )
      : provisioningCompatibility;
  if (options.changeCompatibilityAtPinning === true) {
    await writeTracked(repositoryRoot, COMPATIBILITY_PATH, canonicalJson(pinningCompatibility));
  }
  if (options.pinningHelperSource !== undefined) {
    await writeTracked(repositoryRoot, HELPER_PATH, options.pinningHelperSource);
  }
  const pinned = makePinnedRecords(pinningCompatibility, provisioningCommitSha);
  await writeTracked(repositoryRoot, IDENTITY_PATH, canonicalJson(pinned.identity));
  await writeTracked(repositoryRoot, RECEIPT_PATH, canonicalJson(pinned.receipt));
  const pinningCommitSha = commit(repositoryRoot, "pin foundation identity");

  return Object.freeze({
    compatibilityEvidenceSha256: sha256(canonicalJson(pinningCompatibility)),
    pinningCommitSha,
    provisioningCommitSha,
    repositoryRoot,
    testedCommitSha,
  });
}

function makePinnedRecords(
  compatibility: ReturnType<typeof makeCompatibilityEvidence>,
  provisioningCommitSha: string,
) {
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = publicKey.export({ format: "der", type: "spki" });
  const signerFingerprintSha256 = sha256(publicKeySpkiDer);
  const compatibilityEvidenceSha256 = sha256(canonicalJson(compatibility));
  const identity = {
    account: "release-ed25519-v1",
    algorithm: "Ed25519",
    candidateType: "rsi.release-public-identity-candidate",
    createdAt: "2026-08-23T06:00:00.000Z",
    helperBinarySha256: compatibility.helper.binarySha256,
    helperCompatibilityEvidenceSha256: compatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: compatibility.testedCommitSha,
    helperCompilerIdentitySha256: compatibility.helper.compilerIdentitySha256,
    helperSourceSha256: compatibility.helper.sourceSha256,
    keyId: `rsi-release-${signerFingerprintSha256.slice(0, 16)}`,
    keychainProtection: "data-protection-when-unlocked-this-device-only-user-presence",
    platformIdentitySha256: "4".repeat(64),
    publicKeySpkiDerBase64url: publicKeySpkiDer.toString("base64url"),
    service: "dev.rsi.macbook.release-signing",
    signerFingerprintSha256,
    version: 1,
  } as const;
  const identitySha256 = sha256(canonicalJson(identity));
  const receipt = {
    account: identity.account,
    copyCount: 2,
    createdAt: identity.createdAt,
    helperBinarySha256: identity.helperBinarySha256,
    helperCompatibilityEvidenceSha256: identity.helperCompatibilityEvidenceSha256,
    helperCompatibilityTestedCommitSha: identity.helperCompatibilityTestedCommitSha,
    helperCompilerIdentitySha256: identity.helperCompilerIdentitySha256,
    helperSourceSha256: identity.helperSourceSha256,
    keyId: identity.keyId,
    keychainProtection: identity.keychainProtection,
    keychainStatus: "identity-verified",
    platformIdentitySha256: identity.platformIdentitySha256,
    provisioningIntentSha256: "5".repeat(64),
    publicIdentitySha256: identitySha256,
    receiptType: "rsi.release-key-provisioning-receipt",
    recoveryCopies: [
      {
        copyIndex: 1,
        envelopeSha256: "6".repeat(64),
        physicalStoreIdentitySha256: "7".repeat(64),
        restoredAt: "2026-08-23T06:05:00.000Z",
        restoreStatus: "restore-verified",
        volumeIdentitySha256: "8".repeat(64),
      },
      {
        copyIndex: 2,
        envelopeSha256: "9".repeat(64),
        physicalStoreIdentitySha256: "a".repeat(64),
        restoredAt: "2026-08-23T06:10:00.000Z",
        restoreStatus: "restore-verified",
        volumeIdentitySha256: "b".repeat(64),
      },
    ],
    repositoryCommitSha: provisioningCommitSha,
    service: identity.service,
    signerFingerprintSha256,
    status: "verified-keychain-and-two-recovery-copies",
    version: 1,
  } as const;
  return Object.freeze({ identity, receipt });
}

function makeCompatibilityEvidence(
  testedCommitSha: string,
  helperSourceSha256: string,
  drillId: string,
) {
  return {
    cleanup: {
      evidenceSha256: "c".repeat(64),
      keychainItem: "deleted-and-absence-verified",
      outcome: "passed",
      temporaryArtifacts: "removed-and-absence-verified",
      testPrivateMaterial: "destroyed-and-absence-verified",
    },
    completedAt: "2026-08-22T22:00:00.000Z",
    drillId,
    drillOperatorId: "physical-drill-operator",
    environment: {
      architecture: "arm64",
      hardwareClass: "MacBook",
      macosBuildVersion: "25A354",
      macosProductVersion: "26.0",
      nodeVersion: "v24.19.0",
      pnpmVersion: "11.20.0",
    },
    evidencePath: COMPATIBILITY_PATH,
    evidenceType: "rsi.release-key-helper-compatibility-evidence",
    helper: {
      binarySha256: "1".repeat(64),
      compilerIdentitySha256: "2".repeat(64),
      sourceSha256: helperSourceSha256,
    },
    helperPath: HELPER_PATH,
    independentApproval: {
      approvedAt: "2026-08-22T23:00:00.000Z",
      approvalEvidenceSha256: "d".repeat(64),
      authorship: "did-not-author-tested-helper-or-evidence",
      drillParticipation: "did-not-operate-drill",
      reviewerId: "independent-helper-reviewer",
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
        evidenceSha256: "3".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "first-fresh-helper-invocation",
        signatureVerification: "passed",
      },
      {
        attempt: 2,
        evidenceSha256: "4".repeat(64),
        freshHelperProcess: "verified",
        outcome: "user-presence-prompt-observed-and-approved-once",
        scenario: "second-fresh-helper-invocation-after-first-completed",
        signatureVerification: "passed",
      },
    ],
    repository: "tyler-james-bridges/rsi",
    repositoryVisibility: "public",
    testedCommitSha,
    verdict: "passed",
    version: 1,
  } as const;
}

async function writeTracked(root: string, path: string, contents: string): Promise<void> {
  const destination = join(root, path);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, contents);
}

function commit(root: string, message: string): string {
  git(root, ["add", "--all"]);
  git(root, [
    "-c",
    "user.name=RSI Test",
    "-c",
    "user.email=rsi-test@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "--quiet",
    "--message",
    message,
  ]);
  return git(root, ["rev-parse", "HEAD"]).trim();
}

function git(root: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", args, {
    cwd: root,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    throw new Error(`Git test fixture failed: ${result.stderr}`);
  }
  return result.stdout;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
