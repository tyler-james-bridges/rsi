import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, timingSafeEqual, verify as verifyEd25519 } from "node:crypto";
import { constants as fsConstants, existsSync, type BigIntStats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import type { ReleaseBundleReceiptV1 } from "@rsi/release-bundle";
import {
  assertReleaseKeyHelperCompatibilityRuntimeBindings,
  RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
} from "@rsi/release-key-provisioning";
import { createNativeKeychainAdapter } from "@rsi/release-key-provisioning/native-signing";

import {
  decodeFoundationAuthenticatedIndependentReview,
  foundationAuthenticatedIndependentReviewSha256,
  verifyFoundationAuthenticatedIndependentReview,
} from "./authenticated-review.js";
import { canonicalJson, sha256, validateGitHash } from "./canonical.js";
import { foundationCiEvidenceSha256, parseFoundationCiEvidence } from "./ci-evidence.js";
import { fail, FoundationCeremonyError } from "./errors.js";
import type { FoundationIndependentReviewEvidenceV1 } from "./review-evidence.js";
import {
  assertFoundationIndependentReviewerSeparation,
  decodeFoundationIndependentReviewerIdentity,
  FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_PATH,
  type FoundationReviewerSeparationConstraintsV1,
} from "./reviewer-identity.js";
import {
  FOUNDATION_RELEASE_IDENTITY_PATH,
  FOUNDATION_RELEASE_PROVISIONING_RECEIPT_PATH,
  parseFoundationPinnedReleaseIdentity,
  type FoundationPinnedReleaseIdentityV1,
} from "./release-identity.js";
import type {
  FoundationCeremonyCustody,
  FoundationCeremonySignersV1,
  FoundationCiEvidenceV1,
  FoundationCeremonyOutputSuffix,
  FoundationOutputReservation,
  FoundationTagObjectReservation,
} from "./types.js";

const MAX_EVIDENCE_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MINIMAL_ENV = Object.freeze({ LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" });
const HARDENED_GIT_ENV = Object.freeze({
  ...MINIMAL_ENV,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
});
const HARDENED_GIT_OPTIONS = Object.freeze([
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
] as const);

interface DirectoryGuard {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: number;
  readonly path: string;
  readonly uid: bigint;
}

export async function readFoundationCiEvidenceFile(
  path: string,
  repositoryRoot: string,
  hooks: FoundationEvidenceReadHooksForTest = {},
): Promise<{ readonly evidence: FoundationCiEvidenceV1; readonly sha256: string }> {
  const validated = await validateExternalFile(path, repositoryRoot, ".json");
  const bytes = await readUniqueOwnerFile(
    validated.path,
    MAX_EVIDENCE_BYTES,
    validated.parent,
    hooks,
  );
  try {
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
    } catch {
      fail("CI_EVIDENCE_INVALID", "Foundation CI evidence file is invalid");
    }
    const evidence = parseFoundationCiEvidence(value);
    if (new TextDecoder().decode(bytes) !== canonicalJson(evidence)) {
      fail("CI_EVIDENCE_INVALID", "Foundation CI evidence file is not canonical");
    }
    return Object.freeze({ evidence, sha256: foundationCiEvidenceSha256(evidence) });
  } finally {
    bytes.fill(0);
  }
}

export interface FoundationEvidenceReadHooksForTest {
  readonly afterOpen?: () => Promise<void> | void;
}

export async function readFoundationIndependentReviewEvidenceFile(
  path: string,
  repositoryRoot: string,
  confirmedCommitValue: string,
): Promise<{
  readonly evidence: FoundationIndependentReviewEvidenceV1;
  readonly sha256: string;
}> {
  const root = resolve(repositoryRoot);
  const confirmedCommit = validateGitHash(
    confirmedCommitValue,
    "Foundation independent-review confirmed commit",
  );
  assertUnambiguousGitHistory(root);
  if (gitText(root, ["rev-parse", "HEAD"]).trim() !== confirmedCommit) {
    fail("REPOSITORY_STATE", "Foundation independent-review commit does not match repository HEAD");
  }
  const targetIdentity = readReviewTrustBlob(
    root,
    confirmedCommit,
    FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_PATH,
  );
  const identityBytes = Buffer.from(targetIdentity.bytes);
  const parents = readCommitParents(root, confirmedCommit);
  try {
    if (parents.length === 0) {
      fail(
        "VERIFICATION_FAILED",
        "Foundation independent-reviewer identity has no strict-ancestor trust pin",
      );
    }
    for (const parent of parents) {
      const parentIdentity = readReviewTrustBlob(
        root,
        parent,
        FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_PATH,
      );
      try {
        if (
          parentIdentity.objectId !== targetIdentity.objectId ||
          !gitIsAncestor(root, parent, confirmedCommit)
        ) {
          fail(
            "VERIFICATION_FAILED",
            "Foundation independent-reviewer identity was added or changed by the reviewed commit",
          );
        }
      } finally {
        parentIdentity.bytes.fill(0);
      }
    }
    const identity = decodeFoundationIndependentReviewerIdentity(identityBytes);
    assertFoundationIndependentReviewerSeparation(
      identity,
      readReviewerSeparationConstraints(root, confirmedCommit),
    );
    const validated = await validateExternalFile(path, repositoryRoot, ".review-evidence.json");
    const bytes = await readUniqueOwnerFile(validated.path, MAX_EVIDENCE_BYTES, validated.parent);
    try {
      const envelope = decodeFoundationAuthenticatedIndependentReview(bytes);
      const evidence = verifyFoundationAuthenticatedIndependentReview(envelope, identity);
      const reviewedTree = validateGitHash(
        gitText(root, ["rev-parse", `${confirmedCommit}^{tree}`]).trim(),
        "Foundation independent-review target tree",
      );
      if (evidence.commitSha !== confirmedCommit || evidence.gitTreeSha !== reviewedTree) {
        fail(
          "VERIFICATION_FAILED",
          "Foundation independent-review envelope does not match the confirmed commit and tree",
        );
      }
      assertUnambiguousGitHistory(root);
      const retainedIdentity = readReviewTrustBlob(
        root,
        confirmedCommit,
        FOUNDATION_INDEPENDENT_REVIEWER_IDENTITY_PATH,
      );
      try {
        if (
          gitText(root, ["rev-parse", "HEAD"]).trim() !== confirmedCommit ||
          retainedIdentity.objectId !== targetIdentity.objectId
        ) {
          fail(
            "REPOSITORY_STATE",
            "Foundation independent-review trust state changed during inspection",
          );
        }
      } finally {
        retainedIdentity.bytes.fill(0);
      }
      return Object.freeze({
        evidence,
        sha256: foundationAuthenticatedIndependentReviewSha256(envelope),
      });
    } finally {
      bytes.fill(0);
    }
  } finally {
    identityBytes.fill(0);
    targetIdentity.bytes.fill(0);
  }
}

interface FoundationReviewTrustBlob {
  readonly bytes: Buffer;
  readonly objectId: string;
}

function readReviewTrustBlob(
  root: string,
  commitSha: string,
  path: string,
): FoundationReviewTrustBlob;
function readReviewTrustBlob(
  root: string,
  commitSha: string,
  path: string,
  required: false,
): FoundationReviewTrustBlob | undefined;
function readReviewTrustBlob(
  root: string,
  commitSha: string,
  path: string,
  required = true,
): FoundationReviewTrustBlob | undefined {
  const tree = spawnSync(
    "/usr/bin/git",
    [...HARDENED_GIT_OPTIONS, "ls-tree", "-z", "--full-tree", commitSha, "--", path],
    {
      cwd: root,
      encoding: "buffer",
      env: HARDENED_GIT_ENV,
      maxBuffer: MAX_EVIDENCE_BYTES,
      shell: false,
      timeout: 20_000,
    },
  );
  const treeStdout = Buffer.isBuffer(tree.stdout) ? tree.stdout : Buffer.alloc(0);
  const treeStderr = Buffer.isBuffer(tree.stderr) ? tree.stderr : Buffer.alloc(0);
  treeStderr.fill(0);
  if (tree.status !== 0 || tree.signal !== null) {
    treeStdout.fill(0);
    fail("REPOSITORY_STATE", "Foundation independent-review trust tree could not be inspected");
  }
  if (treeStdout.length === 0 && !required) return undefined;
  let record: string;
  try {
    record = new TextDecoder("utf-8", { fatal: true }).decode(treeStdout);
  } catch {
    treeStdout.fill(0);
    fail("REPOSITORY_STATE", "Foundation independent-review trust tree is not canonical UTF-8");
  }
  treeStdout.fill(0);
  const match = /^(100644) blob ([0-9a-f]{40})\t([^\0]+)\0$/u.exec(record);
  if (match === null || match[3] !== path) {
    fail(
      "VERIFICATION_FAILED",
      "Foundation independent-reviewer identity trust file is unavailable or unsafe",
    );
  }
  const objectId = match[2]!;
  const blob = spawnSync("/usr/bin/git", [...HARDENED_GIT_OPTIONS, "cat-file", "blob", objectId], {
    cwd: root,
    encoding: "buffer",
    env: HARDENED_GIT_ENV,
    maxBuffer: MAX_EVIDENCE_BYTES,
    shell: false,
    timeout: 20_000,
  });
  const bytes = Buffer.isBuffer(blob.stdout) ? blob.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(blob.stderr) ? blob.stderr : Buffer.alloc(0);
  stderr.fill(0);
  if (
    blob.status !== 0 ||
    blob.signal !== null ||
    bytes.length === 0 ||
    createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex") !== objectId
  ) {
    bytes.fill(0);
    fail("REPOSITORY_STATE", "Foundation independent-review trust blob failed verification");
  }
  return Object.freeze({ bytes, objectId });
}

function readCommitParents(root: string, commitSha: string): readonly string[] {
  const fields = gitText(root, ["rev-list", "--parents", "-n", "1", commitSha]).trim().split(" ");
  if (fields.shift() !== commitSha || fields.some((field) => !/^[0-9a-f]{40}$/u.test(field))) {
    fail("REPOSITORY_STATE", "Foundation independent-review ancestry is invalid");
  }
  return Object.freeze(fields);
}

function readReviewerSeparationConstraints(
  root: string,
  commitSha: string,
): FoundationReviewerSeparationConstraintsV1 {
  const releaseIdentity = readOptionalCanonicalReviewRecord(
    root,
    commitSha,
    FOUNDATION_RELEASE_IDENTITY_PATH,
  );
  const compatibility = readOptionalCanonicalReviewRecord(
    root,
    commitSha,
    RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
  );
  return Object.freeze({
    operatorIds: Object.freeze(readStringFields(compatibility, ["drillOperatorId"])),
    releaseSignerFingerprintsSha256: Object.freeze(
      readStringFields(releaseIdentity, ["signerFingerprintSha256"]),
    ),
    releaseSignerKeyIds: Object.freeze(readStringFields(releaseIdentity, ["keyId"])),
    releaseSignerPublicKeysSpkiDerBase64url: Object.freeze(
      readStringFields(releaseIdentity, ["publicKeySpkiDerBase64url"]),
    ),
  });
}

function readOptionalCanonicalReviewRecord(
  root: string,
  commitSha: string,
  path: string,
): Readonly<Record<string, unknown>> | undefined {
  const blob = readReviewTrustBlob(root, commitSha, path, false);
  if (blob === undefined) return undefined;
  try {
    let text: string;
    let value: unknown;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(blob.bytes);
      value = JSON.parse(text) as unknown;
    } catch {
      fail("VERIFICATION_FAILED", "Foundation reviewer separation evidence is not valid JSON");
    }
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      canonicalJson(value) !== text
    ) {
      fail("VERIFICATION_FAILED", "Foundation reviewer separation evidence is not canonical");
    }
    return value as Readonly<Record<string, unknown>>;
  } finally {
    blob.bytes.fill(0);
  }
}

function readStringFields(
  record: Readonly<Record<string, unknown>> | undefined,
  names: readonly string[],
): string[] {
  if (record === undefined) return [];
  return names.flatMap((name) => (typeof record[name] === "string" ? [record[name]] : []));
}

export async function readPlatformModel(): Promise<string> {
  const result = spawnSync("/usr/sbin/system_profiler", ["SPHardwareDataType"], {
    encoding: "utf8",
    env: MINIMAL_ENV,
    maxBuffer: 64 * 1024,
    shell: false,
    timeout: 15_000,
  });
  const modelName =
    result.status === 0 && result.signal === null
      ? /^\s*Model Name:\s*(MacBook(?: Air| Pro)?)\s*$/mu.exec(result.stdout)?.[1]
      : undefined;
  if (modelName === undefined) fail("HOST_REFUSED", "Foundation ceremony host is not a MacBook");
  return "MacBook";
}

export async function assertCeremonyHostOffline(): Promise<void> {
  for (const args of [
    ["-n", "get", "default"],
    ["-n", "get", "-inet6", "default"],
  ] as const) {
    const route = spawnSync("/sbin/route", args, {
      encoding: "buffer",
      env: MINIMAL_ENV,
      maxBuffer: 16 * 1024,
      shell: false,
      timeout: 5_000,
    });
    wipeProcessOutput(route.stdout, route.stderr);
    if (route.status === 0 || route.signal !== null || route.status === null) {
      fail("HOST_REFUSED", "Foundation ceremony requires no IPv4 or IPv6 default route");
    }
  }
  const interfaces = spawnSync("/sbin/ifconfig", ["-a"], {
    encoding: "buffer",
    env: MINIMAL_ENV,
    maxBuffer: 256 * 1024,
    shell: false,
    timeout: 5_000,
  });
  const stdout = Buffer.isBuffer(interfaces.stdout) ? interfaces.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(interfaces.stderr) ? interfaces.stderr : Buffer.alloc(0);
  try {
    if (interfaces.status !== 0 || interfaces.signal !== null || stdout.length === 0) {
      fail("HOST_REFUSED", "Foundation ceremony could not inspect network interfaces");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
    if (hasActiveNonLoopbackInterface(text)) {
      fail("HOST_REFUSED", "Foundation ceremony requires every non-loopback interface down");
    }
  } catch (error) {
    if (error instanceof FoundationCeremonyError) throw error;
    fail("HOST_REFUSED", "Foundation ceremony network evidence is invalid");
  } finally {
    stdout.fill(0);
    stderr.fill(0);
  }
}

export function hasActiveNonLoopbackInterface(ifconfigText: string): boolean {
  if (typeof ifconfigText !== "string" || ifconfigText.length === 0) return true;
  const blocks = ifconfigText.split(/\n(?=[A-Za-z0-9][A-Za-z0-9._-]*: flags=)/u);
  const names = blocks.map((block) => /^([A-Za-z0-9][A-Za-z0-9._-]*): flags=/u.exec(block)?.[1]);
  if (names.some((name) => name === undefined) || !names.includes("lo0")) return true;
  return blocks.some((block) => {
    const name = /^([A-Za-z0-9][A-Za-z0-9._-]*): flags=/u.exec(block)?.[1];
    if (name === undefined || name === "lo0") return false;
    return (
      /\n\s*status:\s*active\s*$/mu.test(block) ||
      /\n\s*inet\s+(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b/mu.test(block) ||
      /\n\s*inet6\s+(?!::1(?:%\S+)?\s)[0-9a-f:]+(?:%\S+)?\s/mu.test(block)
    );
  });
}

export async function readPinnedFoundationReleaseIdentity(
  repositoryRoot: string,
  commitSha: string,
): Promise<FoundationPinnedReleaseIdentityV1> {
  const root = resolve(repositoryRoot);
  assertUnambiguousGitHistory(root);
  if (gitText(root, ["rev-parse", "HEAD"]).trim() !== commitSha) {
    fail("REPOSITORY_STATE", "Pinned release identity commit does not match repository HEAD");
  }
  const identityBytes = gitBlob(root, commitSha, FOUNDATION_RELEASE_IDENTITY_PATH);
  const receiptBytes = gitBlob(root, commitSha, FOUNDATION_RELEASE_PROVISIONING_RECEIPT_PATH);
  const compatibilityBytes = gitBlob(
    root,
    commitSha,
    RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
  );
  try {
    const identity = parseFoundationPinnedReleaseIdentity(
      identityBytes,
      receiptBytes,
      compatibilityBytes,
      commitSha,
    );
    if (!gitIsAncestor(root, identity.provisioningRepositoryCommitSha, commitSha)) {
      fail(
        "CUSTODY_FAILED",
        "Provisioning source commit is not an ancestor of the repository-pinned identity",
      );
    }
    if (
      !gitIsAncestor(
        root,
        identity.helperCompatibilityTestedCommitSha,
        identity.provisioningRepositoryCommitSha,
      )
    ) {
      fail(
        "CUSTODY_FAILED",
        "Tested helper commit is not an ancestor of the provisioning source commit",
      );
    }
    let provisioningCompatibilityBytes: Buffer | undefined;
    let provisioningHelperSource: Buffer | undefined;
    let testedHelperSource: Buffer | undefined;
    let pinningHelperSource: Buffer | undefined;
    try {
      provisioningCompatibilityBytes = gitBlob(
        root,
        identity.provisioningRepositoryCommitSha,
        RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
      );
      provisioningHelperSource = gitBlob(
        root,
        identity.provisioningRepositoryCommitSha,
        "packages/release-key-provisioning/native/keychain-helper.swift",
      );
      testedHelperSource = gitBlob(
        root,
        identity.helperCompatibilityTestedCommitSha,
        "packages/release-key-provisioning/native/keychain-helper.swift",
      );
      pinningHelperSource = gitBlob(
        root,
        commitSha,
        "packages/release-key-provisioning/native/keychain-helper.swift",
      );
      if (
        sha256(provisioningCompatibilityBytes) !== identity.helperCompatibilityEvidenceSha256 ||
        sha256(compatibilityBytes) !== identity.helperCompatibilityEvidenceSha256 ||
        sha256(provisioningHelperSource) !== identity.helperSourceSha256 ||
        sha256(testedHelperSource) !== identity.helperSourceSha256 ||
        sha256(pinningHelperSource) !== identity.helperSourceSha256
      ) {
        fail(
          "CUSTODY_FAILED",
          "Provisioning lineage does not contain the exact reviewed helper compatibility evidence",
        );
      }
      assertUnambiguousGitHistory(root);
      if (gitText(root, ["rev-parse", "HEAD"]).trim() !== commitSha) {
        fail("REPOSITORY_STATE", "Pinned release identity repository changed during inspection");
      }
    } finally {
      provisioningCompatibilityBytes?.fill(0);
      provisioningHelperSource?.fill(0);
      testedHelperSource?.fill(0);
      pinningHelperSource?.fill(0);
    }
    return fail(
      "CUSTODY_FAILED",
      "V1 helper compatibility evidence is inspection-only and cannot authorize release-key custody",
    );
  } finally {
    identityBytes.fill(0);
    receiptBytes.fill(0);
    compatibilityBytes.fill(0);
  }
}

export function createMacBookKeychainCustody(
  repositoryRoot: string,
  assertOffline: () => Promise<void> = assertCeremonyHostOffline,
): FoundationCeremonyCustody {
  return Object.freeze({
    async withSigners<T>(
      identity: FoundationPinnedReleaseIdentityV1,
      operation: (signers: FoundationCeremonySignersV1) => Promise<T>,
    ): Promise<T> {
      const native = createNativeKeychainAdapter(repositoryRoot);
      let active = true;
      let phase = 0;
      let successfulSignatures = 0;
      const releasePublicKey = Uint8Array.from(identity.publicKeySpkiDer);
      const tagPublicKey = Uint8Array.from(identity.publicKeySpkiDer);
      const publicKey = createPublicKey({
        format: "der",
        key: Buffer.from(identity.publicKeySpkiDer),
        type: "spki",
      });
      let operationFailed = false;
      const signOnce = async (expected: 0 | 1, message: Uint8Array): Promise<Uint8Array> => {
        if (!active || phase !== expected) {
          fail("CUSTODY_FAILED", "Foundation signing capability order or lifetime is invalid");
        }
        phase = expected + 1;
        let signature: Uint8Array;
        try {
          await assertOffline();
          signature =
            expected === 0
              ? await native.signReleaseManifest(message)
              : await native.signFoundationTag(message);
        } catch {
          fail("CUSTODY_FAILED", "Fixed native foundation signing operation failed");
        }
        if (!verifyEd25519(null, message, publicKey, signature)) {
          signature.fill(0);
          fail("CUSTODY_FAILED", "Fixed native foundation signature did not verify");
        }
        successfulSignatures += 1;
        return signature;
      };
      try {
        let helper: Awaited<ReturnType<typeof native.helperEvidence>>;
        try {
          helper = await native.helperEvidence();
        } catch {
          fail("CUSTODY_FAILED", "Fixed native foundation helper could not be attested");
        }
        if (
          helper.binarySha256 !== identity.helperBinarySha256 ||
          helper.compilerIdentitySha256 !== identity.helperCompilerIdentitySha256 ||
          helper.sourceSha256 !== identity.helperSourceSha256
        ) {
          fail("CUSTODY_FAILED", "Native helper does not match the repository-pinned identity");
        }
        const macos = readMacosBuildIdentifiers();
        if (process.arch !== "arm64" && process.arch !== "x64") {
          fail("CUSTODY_FAILED", "Foundation helper runtime architecture is unsupported");
        }
        try {
          assertReleaseKeyHelperCompatibilityRuntimeBindings(identity.helperCompatibilityEvidence, {
            architecture: process.arch,
            helper,
            macosBuildVersion: macos.buildVersion,
            macosProductVersion: macos.productVersion,
            nodeVersion: process.version,
            pnpmVersion: pnpmVersion(),
          });
        } catch {
          fail("CUSTODY_FAILED", "Native helper runtime does not match the reviewed drill");
        }
        const result = await operation(
          Object.freeze({
            releaseSigner: Object.freeze({
              keyId: identity.keyId,
              publicKeySpkiDer: releasePublicKey,
              sign: (message: Uint8Array) => signOnce(0, message),
            }),
            tagSigner: Object.freeze({
              keyId: identity.keyId,
              publicKeySpkiDer: tagPublicKey,
              sign: (message: Uint8Array) => signOnce(1, message),
            }),
          }),
        );
        if (phase !== 2 || successfulSignatures !== 2) {
          fail("CUSTODY_FAILED", "Foundation ceremony did not complete exactly two signatures");
        }
        return result;
      } catch (error) {
        operationFailed = true;
        if (error instanceof FoundationCeremonyError) throw error;
        fail("CUSTODY_FAILED", "Foundation signing custody operation failed");
      } finally {
        active = false;
        releasePublicKey.fill(0);
        tagPublicKey.fill(0);
        try {
          await native.dispose();
        } catch {
          if (!operationFailed) {
            fail("CUSTODY_FAILED", "Fixed native foundation helper cleanup failed");
          }
        }
      }
    },
  });
}

export async function writeFoundationReceipt(
  path: string,
  repositoryRoot: string,
  receipt: ReleaseBundleReceiptV1,
): Promise<void> {
  return writeFoundationBytesCreateOnly(
    path,
    repositoryRoot,
    ".receipt.json",
    Buffer.from(canonicalJson(receipt), "utf8"),
  );
}

export async function writeFoundationEvidence(
  path: string,
  repositoryRoot: string,
  suffix: string,
  bytes: Uint8Array,
): Promise<void> {
  return writeFoundationBytesCreateOnly(path, repositoryRoot, suffix, Buffer.from(bytes));
}

export const validateFoundationDestination = (path: string, repositoryRoot: string) =>
  validateExternalDestination(path, repositoryRoot, ".rsi-release");
export const validateFoundationReceiptDestination = (path: string, repositoryRoot: string) =>
  validateExternalDestination(path, repositoryRoot, ".receipt.json");
export const validateFoundationConclusionDestination = (path: string, repositoryRoot: string) =>
  validateExternalDestination(path, repositoryRoot, ".readiness-conclusion.json");
export const validateFoundationTagObjectDestination = (path: string, repositoryRoot: string) =>
  validateExternalDestination(path, repositoryRoot, ".foundation-tag");
export const validateFoundationReportDestination = (path: string, repositoryRoot: string) =>
  validateExternalDestination(path, repositoryRoot, ".ceremony-report.json");

export interface FoundationOutputReservationHooksForTest {
  readonly afterWrite?: () => Promise<void> | void;
}

/**
 * Reserves the detached-tag destination before either signing capability is
 * exposed. The reservation is durable and is never removed or truncated, so a
 * later failure cannot make a consumed authorization look unused.
 */
export async function reserveFoundationTagObject(
  path: string,
  repositoryRoot: string,
  hooks: FoundationOutputReservationHooksForTest = {},
): Promise<FoundationTagObjectReservation> {
  return reserveFoundationOutput(path, repositoryRoot, ".foundation-tag", hooks);
}

export async function reserveFoundationOutput(
  path: string,
  repositoryRoot: string,
  suffix: FoundationCeremonyOutputSuffix,
  hooks: FoundationOutputReservationHooksForTest = {},
): Promise<FoundationOutputReservation> {
  const absolute = await validateExternalDestination(path, repositoryRoot, suffix);
  const parent = await guardCanonicalParent(dirname(absolute), "output");
  let handle: FileHandle;
  try {
    handle = await open(
      absolute,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
  } catch {
    fail("OUTPUT_FAILED", "Foundation retained-output reservation could not be created");
  }
  let closed = false;
  let published = false;
  try {
    await handle.chmod(0o600);
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.nlink !== 1n ||
      opened.uid !== currentUserId(opened.uid) ||
      opened.size !== 0n ||
      (Number(opened.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation retained-output reservation is unsafe");
    }
    await handle.sync();
    await assertDirectoryGuard(parent);
    await syncDirectory(parent.path);

    const closePreserving = async (): Promise<void> => {
      if (closed) return;
      closed = true;
      await handle.close().catch(() => undefined);
    };

    return Object.freeze({
      async preserve(): Promise<void> {
        await closePreserving();
      },
      async publish(bytesValue: Uint8Array): Promise<void> {
        if (published || closed || !(bytesValue instanceof Uint8Array)) {
          fail("OUTPUT_FAILED", "Foundation retained-output reservation is not publishable");
        }
        published = true;
        const bytes = Buffer.from(bytesValue);
        try {
          if (bytes.length <= 0 || bytes.length > MAX_OUTPUT_BYTES) {
            fail("OUTPUT_FAILED", "Foundation retained-output size is invalid");
          }
          await handle.writeFile(bytes);
          await handle.sync();
          if (hooks.afterWrite !== undefined) await hooks.afterWrite();
          const written = await handle.stat({ bigint: true });
          const pathStat = await lstat(absolute, { bigint: true }).catch(() => undefined);
          if (
            pathStat === undefined ||
            !sameFile(opened, written) ||
            !sameFile(written, pathStat) ||
            written.nlink !== 1n ||
            written.size !== BigInt(bytes.length) ||
            (Number(written.mode) & 0o777) !== 0o600
          ) {
            fail("OUTPUT_FAILED", "Foundation retained output changed during publication");
          }
          await assertDirectoryGuard(parent);
          await syncDirectory(parent.path);
          const retained = await readUniqueOwnerFile(absolute, MAX_OUTPUT_BYTES, parent);
          try {
            if (retained.length !== bytes.length || !timingSafeEqual(retained, bytes)) {
              fail("OUTPUT_FAILED", "Foundation retained output did not verify after publication");
            }
          } finally {
            retained.fill(0);
          }
        } catch (error) {
          if (error instanceof FoundationCeremonyError) throw error;
          fail("OUTPUT_FAILED", "Foundation retained-output publication did not finish cleanly");
        } finally {
          bytes.fill(0);
          await closePreserving();
        }
      },
    });
  } catch (error) {
    await handle.close().catch(() => undefined);
    // Never remove the durable reservation: its presence records that this
    // ceremony attempt reached the output-commit boundary.
    if (error instanceof FoundationCeremonyError) throw error;
    fail("OUTPUT_FAILED", "Foundation retained-output reservation failed");
  }
}

async function writeFoundationBytesCreateOnly(
  path: string,
  repositoryRoot: string,
  suffix: string,
  bytes: Buffer,
): Promise<void> {
  const absolute = await validateExternalDestination(path, repositoryRoot, suffix);
  if (bytes.length <= 0 || bytes.length > MAX_OUTPUT_BYTES) {
    bytes.fill(0);
    fail("OUTPUT_FAILED", "Foundation retained output size is invalid");
  }
  const parent = await guardCanonicalParent(dirname(absolute), "output");
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      absolute,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.nlink !== 1n ||
      opened.uid !== currentUserId(opened.uid) ||
      (Number(opened.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation retained output file is unsafe");
    }
    await handle.writeFile(bytes);
    await handle.sync();
    const written = await handle.stat({ bigint: true });
    const pathStat = await lstat(absolute, { bigint: true }).catch(() => undefined);
    if (
      pathStat === undefined ||
      !sameFile(opened, written) ||
      !sameFile(written, pathStat) ||
      written.nlink !== 1n ||
      written.size !== BigInt(bytes.length) ||
      (Number(written.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation retained output changed during publication");
    }
    await assertDirectoryGuard(parent);
    await syncDirectory(parent.path);
    const retained = await readUniqueOwnerFile(absolute, MAX_OUTPUT_BYTES, parent);
    try {
      if (retained.length !== bytes.length || !timingSafeEqual(retained, bytes)) {
        fail("OUTPUT_FAILED", "Foundation retained output did not verify after publication");
      }
    } finally {
      retained.fill(0);
    }
  } catch (error) {
    if (error instanceof FoundationCeremonyError) throw error;
    fail("OUTPUT_FAILED", "Foundation retained output could not be published create-only");
  } finally {
    bytes.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

async function validateExternalFile(
  path: string,
  repositoryRoot: string,
  suffix: string,
): Promise<{ readonly parent: DirectoryGuard; readonly path: string }> {
  const absolute = validateExternalPath(path, repositoryRoot, suffix);
  const parent = await guardCanonicalParent(dirname(absolute), "evidence");
  const stats = await lstat(absolute).catch(() => null);
  if (
    stats === null ||
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.uid !== process.getuid?.() ||
    stats.nlink !== 1 ||
    (stats.mode & 0o077) !== 0
  ) {
    fail("INPUT_INVALID", "Foundation evidence file is not owner-only and unique");
  }
  return Object.freeze({ parent, path: absolute });
}

async function validateExternalDestination(
  path: string,
  repositoryRoot: string,
  suffix: string,
): Promise<string> {
  const absolute = validateExternalPath(path, repositoryRoot, suffix);
  await guardCanonicalParent(dirname(absolute), "output");
  if ((await lstat(absolute).catch(() => null)) !== null) {
    fail("OUTPUT_FAILED", "Foundation output already exists");
  }
  return absolute;
}

function validateExternalPath(path: string, repositoryRoot: string, suffix: string): string {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.length > 1_024 ||
    !isAbsolute(path) ||
    resolve(path) !== path ||
    !path.endsWith(suffix) ||
    /[\u0000-\u001f\u007f]/u.test(path)
  ) {
    fail("INPUT_INVALID", "Foundation ceremony path is invalid");
  }
  const within = relative(resolve(repositoryRoot), path);
  if (within === "" || (!within.startsWith(`..${sep}`) && within !== ".." && !isAbsolute(within))) {
    fail("INPUT_INVALID", "Foundation ceremony files must remain outside the repository");
  }
  return path;
}

async function guardCanonicalParent(
  parent: string,
  role: "evidence" | "output",
): Promise<DirectoryGuard> {
  const stats = await lstat(parent, { bigint: true }).catch(() => null);
  const uid =
    stats === null || typeof process.getuid !== "function" ? stats?.uid : BigInt(process.getuid());
  if (
    stats === null ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.uid !== uid ||
    (Number(stats.mode) & 0o077) !== 0 ||
    (await realpath(parent)) !== parent
  ) {
    fail(
      "INPUT_INVALID",
      role === "output"
        ? "Foundation output parent is not an owner-only canonical directory"
        : "Foundation evidence parent is not an owner-only canonical directory",
    );
  }
  return Object.freeze({
    device: stats.dev,
    inode: stats.ino,
    mode: Number(stats.mode) & 0o777,
    path: parent,
    uid: stats.uid,
  });
}

async function readUniqueOwnerFile(
  path: string,
  maxBytes: number,
  parent: DirectoryGuard,
  hooks: FoundationEvidenceReadHooksForTest = {},
): Promise<Buffer> {
  const before = await lstat(path, { bigint: true }).catch(() => undefined);
  if (
    before === undefined ||
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.uid !== currentUserId(before.uid) ||
    (Number(before.mode) & 0o077) !== 0 ||
    before.size <= 0n ||
    before.size > BigInt(maxBytes)
  ) {
    fail("INPUT_INVALID", "Foundation evidence file is missing, partial, or unsafe");
  }
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    if (!sameEvidenceFile(before, opened)) {
      fail("INPUT_INVALID", "Foundation evidence file changed during open");
    }
    if (hooks.afterOpen !== undefined) await hooks.afterOpen();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true }).catch(() => undefined);
    if (
      pathAfter === undefined ||
      !sameEvidenceFile(opened, after) ||
      !sameEvidenceFile(after, pathAfter)
    ) {
      bytes.fill(0);
      fail("INPUT_INVALID", "Foundation evidence file changed while reading");
    }
    await assertDirectoryGuard(parent);
    return bytes;
  } catch (error) {
    if (error instanceof FoundationCeremonyError) throw error;
    throw new FoundationCeremonyError(
      "INPUT_INVALID",
      "Foundation evidence file could not be read safely",
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function sameEvidenceFile(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.isFile() &&
    right.isFile() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === 1n &&
    right.nlink === 1n
  );
}

async function assertDirectoryGuard(guard: DirectoryGuard): Promise<void> {
  const stats = await lstat(guard.path, { bigint: true }).catch(() => undefined);
  if (
    stats === undefined ||
    !stats.isDirectory() ||
    stats.dev !== guard.device ||
    stats.ino !== guard.inode ||
    stats.uid !== guard.uid ||
    (Number(stats.mode) & 0o777) !== guard.mode ||
    (await realpath(guard.path).catch(() => "")) !== guard.path
  ) {
    fail("INPUT_INVALID", "Foundation ceremony directory changed during use");
  }
}

function gitText(root: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", [...HARDENED_GIT_OPTIONS, ...args], {
    cwd: root,
    encoding: "utf8",
    env: HARDENED_GIT_ENV,
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    fail("REPOSITORY_STATE", "Foundation identity Git inspection failed");
  }
  return result.stdout;
}

function gitBlob(root: string, commitSha: string, path: string): Buffer {
  const result = spawnSync(
    "/usr/bin/git",
    [...HARDENED_GIT_OPTIONS, "show", `${commitSha}:${path}`],
    {
      cwd: root,
      encoding: "buffer",
      env: HARDENED_GIT_ENV,
      maxBuffer: MAX_EVIDENCE_BYTES,
      shell: false,
      timeout: 20_000,
    },
  );
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  stderr.fill(0);
  if (result.status !== 0 || result.signal !== null || stdout.length === 0) {
    stdout.fill(0);
    fail("CUSTODY_FAILED", "Repository-pinned release identity evidence is unavailable");
  }
  return stdout;
}

function gitIsAncestor(root: string, ancestor: string, descendant: string): boolean {
  const result = spawnSync(
    "/usr/bin/git",
    [...HARDENED_GIT_OPTIONS, "merge-base", "--is-ancestor", ancestor, descendant],
    {
      cwd: root,
      encoding: "buffer",
      env: HARDENED_GIT_ENV,
      maxBuffer: 16 * 1024,
      shell: false,
      timeout: 20_000,
    },
  );
  wipeProcessOutput(result.stdout, result.stderr);
  if (
    result.signal !== null ||
    result.status === null ||
    (result.status !== 0 && result.status !== 1)
  ) {
    fail("REPOSITORY_STATE", "Foundation identity ancestry inspection failed");
  }
  return result.status === 0;
}

function assertUnambiguousGitHistory(root: string): void {
  const graftsPath = resolve(
    root,
    gitText(root, ["rev-parse", "--git-path", "info/grafts"]).trim(),
  );
  if (
    gitText(root, ["for-each-ref", "--format=%(refname)", "refs/replace"]).trim() !== "" ||
    existsSync(graftsPath) ||
    gitText(root, ["rev-parse", "--is-shallow-repository"]).trim() !== "false"
  ) {
    fail("REPOSITORY_STATE", "Foundation identity Git history is ambiguous");
  }
}

function readMacosBuildIdentifiers(): {
  readonly buildVersion: string;
  readonly productVersion: string;
} {
  return Object.freeze({
    buildVersion: swVers("-buildVersion"),
    productVersion: swVers("-productVersion"),
  });
}

function swVers(argument: "-buildVersion" | "-productVersion"): string {
  const result = spawnSync("/usr/bin/sw_vers", [argument], {
    encoding: "buffer",
    env: MINIMAL_ENV,
    maxBuffer: 4 * 1024,
    shell: false,
    timeout: 5_000,
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  try {
    if (result.status !== 0 || result.signal !== null || stdout.length === 0) {
      fail("CUSTODY_FAILED", "Foundation helper macOS build identity is unavailable");
    }
    const value = new TextDecoder("utf-8", { fatal: true }).decode(stdout).trim();
    if (value.length === 0 || value.length > 64 || /[\u0000-\u001f\u007f]/u.test(value)) {
      fail("CUSTODY_FAILED", "Foundation helper macOS build identity is invalid");
    }
    return value;
  } catch (error) {
    if (error instanceof FoundationCeremonyError) throw error;
    fail("CUSTODY_FAILED", "Foundation helper macOS build identity is invalid");
  } finally {
    stdout.fill(0);
    stderr.fill(0);
  }
}

function pnpmVersion(): string {
  const value = /(?:^|\s)pnpm\/([^\s]+)/u.exec(process.env.npm_config_user_agent ?? "")?.[1];
  if (value === undefined) {
    fail("CUSTODY_FAILED", "Foundation helper pnpm runtime identity is unavailable");
  }
  return value;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.isFile() && right.isFile() && left.dev === right.dev && left.ino === right.ino;
}

function currentUserId(fallback: bigint): bigint {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : fallback;
}

async function syncDirectory(path: string): Promise<void> {
  let directory: FileHandle | undefined;
  try {
    directory = await open(
      path,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    await directory.sync();
  } catch {
    fail("OUTPUT_FAILED", "Foundation output directory sync failed");
  } finally {
    await directory?.close().catch(() => undefined);
  }
}

function wipeProcessOutput(stdout: unknown, stderr: unknown): void {
  if (Buffer.isBuffer(stdout)) stdout.fill(0);
  if (Buffer.isBuffer(stderr)) stderr.fill(0);
}
