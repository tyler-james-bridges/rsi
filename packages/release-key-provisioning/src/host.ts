import { spawnSync } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { constants as fsConstants, existsSync, type BigIntStats } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { sha256 } from "./canonical.js";
import { fail, ReleaseKeyProvisioningError } from "./errors.js";
import {
  assertReleaseKeyHelperCompatibilityRepositoryBindings,
  assertReleaseKeyHelperCompatibilityRuntimeBindings,
  decodeReleaseKeyHelperCompatibilityEvidence,
  RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH,
  RELEASE_KEY_HELPER_PATH,
} from "./helper-compatibility-evidence.js";
import {
  RECOVERY_FILE_NAMES,
  type KeychainHelperEvidenceV1,
  type KeychainProvisioningAdapter,
  type PassphrasePhase,
  type RecoveryCopyIndex,
  type RecoveryTarget,
  type ReleaseKeyProvisioningRepositoryEligibilityV1,
} from "./types.js";

const APPROVED_REMOTE = "https://github.com/tyler-james-bridges/rsi.git";
const EXPECTED_NODE = "24.19.0";
const EXPECTED_PNPM = "11.20.0";
const MAX_ENVELOPE_BYTES = 16 * 1024;
const MAX_PUBLIC_FILE_BYTES = 64 * 1024;
const UUID_PATTERN =
  /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u;
const HELPER_REPOSITORY_PATH = RELEASE_KEY_HELPER_PATH;
const PROVISIONING_INTENT_SUFFIX = ".release-key-provisioning-intent.json" as const;
const PARTIAL_PUBLICATION_PREFIX = ".rsi-create-only-" as const;
const PARTIAL_PUBLICATION_SUFFIX = ".partial" as const;
const LEGACY_HELPER_REFUSAL =
  "V1 ad-hoc helper compatibility is inspection-only and cannot authorize secret custody";
const MINIMAL_ENV = Object.freeze({ LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" });
const HARDENED_GIT_ENV = Object.freeze({
  ...MINIMAL_ENV,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
});
const HARDENED_GIT_ARGUMENTS = Object.freeze([
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
] as const);
const APPROVED_SSH_REMOTE = "git@github.com:tyler-james-bridges/rsi.git";
const helperSourcePath = fileURLToPath(new URL("../native/keychain-helper.swift", import.meta.url));

interface DirectoryGuard {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: number;
  readonly path: string;
  readonly uid: bigint;
}

export interface DiskTargetIdentity {
  readonly physicalDeviceId: string;
  readonly physicalStoreId: string;
  readonly volumeId: string;
}

interface ValidatedEncryptedExternalVolume {
  readonly physicalStoreSubject: string;
  readonly volumeId: string;
}

interface ValidatedPhysicalStore {
  readonly physicalDeviceId: string;
  readonly physicalStoreId: string;
}

export interface DisposableKeychainAdapter extends KeychainProvisioningAdapter {
  readonly dispose: () => Promise<void>;
  readonly signReleaseManifest: (message: Uint8Array) => Promise<Uint8Array>;
  readonly signFoundationTag: (message: Uint8Array) => Promise<Uint8Array>;
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
  if (modelName === undefined) {
    fail("HOST_REFUSED", "Release-key provisioning could not verify MacBook hardware");
  }
  return "MacBook";
}

export async function readPlatformIdentitySha256(): Promise<string> {
  const result = spawnSync("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], {
    encoding: "buffer",
    env: MINIMAL_ENV,
    maxBuffer: 64 * 1024,
    shell: false,
    timeout: 15_000,
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  try {
    if (result.status !== 0 || result.signal !== null || stdout.length === 0) {
      fail("HOST_REFUSED", "Release-key provisioning could not identify the designated MacBook");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
    const platformUuid = /"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"/u.exec(text)?.[1];
    if (
      platformUuid === undefined ||
      !/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u.test(
        platformUuid,
      )
    ) {
      fail("HOST_REFUSED", "Release-key provisioning platform identity is invalid");
    }
    return sha256(`rsi-release-platform-identity-v1\0${platformUuid.toUpperCase()}`);
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError && error.code === "HOST_REFUSED") {
      throw error;
    }
    fail("HOST_REFUSED", "Release-key provisioning platform identity is invalid");
  } finally {
    stdout.fill(0);
    stderr.fill(0);
  }
}

export async function assertHostOffline(): Promise<void> {
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
      fail("HOST_REFUSED", "Release-key provisioning requires no IPv4 or IPv6 default route");
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
      fail("HOST_REFUSED", "Release-key provisioning could not inspect network interfaces");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
    if (hasActiveNonLoopbackInterface(text)) {
      fail("HOST_REFUSED", "Release-key provisioning requires every non-loopback interface down");
    }
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError) throw error;
    fail("HOST_REFUSED", "Release-key provisioning network-interface evidence is invalid");
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

export async function assertProvisioningRepositoryEligible(
  repositoryRoot: string,
  helperEvidence: KeychainHelperEvidenceV1,
): Promise<ReleaseKeyProvisioningRepositoryEligibilityV1> {
  const currentPnpmVersion = pnpmVersion();
  if (process.versions.node !== EXPECTED_NODE || currentPnpmVersion !== EXPECTED_PNPM) {
    fail("REPOSITORY_STATE", "Release-key provisioning runtime does not match exact pins");
  }
  const root = resolve(repositoryRoot);
  assertUnambiguousGitHistory(root);
  const commit = git(root, ["rev-parse", "HEAD"]).trim();
  const remoteUrls = git(root, [
    "config",
    "--local",
    "--no-includes",
    "--get-all",
    "remote.origin.url",
  ]);
  if (
    git(root, ["status", "--porcelain=v1"]) !== "" ||
    git(root, ["branch", "--show-current"]).trim() !== "main" ||
    !/^[0-9a-f]{40}$/u.test(commit) ||
    git(root, ["rev-parse", "refs/remotes/origin/main"]).trim() !== commit ||
    !hasExactlyOneApprovedRemoteUrl(remoteUrls) ||
    git(root, ["tag", "--list", "foundation-v1"]).trim() !== ""
  ) {
    fail("REPOSITORY_STATE", "Release-key provisioning repository identity is ineligible");
  }

  let compatibilityBytes: Buffer | undefined;
  let currentHelperSource: Buffer | undefined;
  let testedHelperSource: Buffer | undefined;
  try {
    compatibilityBytes = gitBytes(root, [
      "show",
      `HEAD:${RELEASE_KEY_HELPER_COMPATIBILITY_EVIDENCE_PATH}`,
    ]);
    const compatibility = decodeReleaseKeyHelperCompatibilityEvidence(compatibilityBytes);
    currentHelperSource = gitBytes(root, ["show", `HEAD:${HELPER_REPOSITORY_PATH}`]);
    testedHelperSource = gitBytes(root, [
      "show",
      `${compatibility.testedCommitSha}:${HELPER_REPOSITORY_PATH}`,
    ]);
    assertReleaseKeyHelperCompatibilityRepositoryBindings(compatibility, {
      currentHelperSourceSha256: sha256(currentHelperSource),
      testedCommitIsAncestorOfCurrentCommit: gitIsAncestor(
        root,
        compatibility.testedCommitSha,
        commit,
      ),
      testedHelperSourceSha256: sha256(testedHelperSource),
    });
    if (process.arch !== "arm64" && process.arch !== "x64") {
      fail("REPOSITORY_STATE", "Release-key provisioning architecture is unsupported");
    }
    const macos = readMacosBuildIdentifiers();
    assertReleaseKeyHelperCompatibilityRuntimeBindings(compatibility, {
      architecture: process.arch,
      helper: helperEvidence,
      macosBuildVersion: macos.buildVersion,
      macosProductVersion: macos.productVersion,
      nodeVersion: process.version,
      pnpmVersion: currentPnpmVersion,
    });
    assertUnambiguousGitHistory(root);
    if (git(root, ["rev-parse", "HEAD"]).trim() !== commit) {
      fail("REPOSITORY_STATE", "Release-key provisioning repository changed during inspection");
    }
    return fail(
      "REPOSITORY_STATE",
      "V1 helper compatibility evidence is inspection-only and cannot authorize release-key provisioning",
    );
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError && error.code === "REPOSITORY_STATE") {
      throw error;
    }
    return fail(
      "REPOSITORY_STATE",
      "Tracked helper compatibility evidence is invalid or mismatched",
    );
  } finally {
    compatibilityBytes?.fill(0);
    currentHelperSource?.fill(0);
    testedHelperSource?.fill(0);
  }
}

export async function inspectRecoveryTarget(
  directoryPath: string,
  copyIndex: RecoveryCopyIndex,
): Promise<RecoveryTarget> {
  if (
    typeof directoryPath !== "string" ||
    directoryPath.length === 0 ||
    directoryPath.length > 1_024 ||
    !isAbsolute(directoryPath) ||
    resolve(directoryPath) !== directoryPath ||
    !directoryPath.startsWith(`/Volumes${sep}`) ||
    /[\u0000-\u001f\u007f]/u.test(directoryPath)
  ) {
    fail("TARGET_REFUSED", "Recovery directory path is invalid");
  }
  const guard = await guardOwnerDirectory(directoryPath, "recovery");
  const disk = inspectEncryptedExternalDisk(directoryPath);
  const envelopePath = join(
    directoryPath,
    copyIndex === 1 ? RECOVERY_FILE_NAMES[0] : RECOVERY_FILE_NAMES[1],
  );
  if ((await lstatIfExists(publicationTemporaryPath(envelopePath))) !== undefined) {
    fail(
      "RESUME_REQUIRED",
      "Recovery target has a retained partial envelope publication; preserve it for remediation",
    );
  }
  const existing = await lstatIfExists(envelopePath);
  if (
    existing !== undefined &&
    (!existing.isFile() ||
      existing.isSymbolicLink() ||
      existing.uid !== currentUserId(existing.uid) ||
      existing.nlink !== 1n ||
      (Number(existing.mode) & 0o077) !== 0 ||
      existing.size <= 0n ||
      existing.size > BigInt(MAX_ENVELOPE_BYTES))
  ) {
    fail("TARGET_REFUSED", "Existing recovery envelope is unsafe");
  }
  return Object.freeze({
    directoryDevice: guard.device,
    directoryInode: guard.inode,
    directoryPath,
    envelopeExists: existing !== undefined,
    envelopePath,
    physicalDeviceId: disk.physicalDeviceId,
    physicalStoreId: disk.physicalStoreId,
    volumeId: disk.volumeId,
  });
}

export async function readRecoveryEnvelope(target: RecoveryTarget): Promise<Buffer> {
  await assertTargetStillMounted(target);
  const bytes = await readUniqueOwnerFile(target.envelopePath, MAX_ENVELOPE_BYTES);
  await assertTargetStillMounted(target);
  return bytes;
}

export async function writeRecoveryEnvelopeCreateOnly(
  target: RecoveryTarget,
  bytes: Buffer,
  hooks: ProvisioningOutputHooksForTest = {},
): Promise<void> {
  if (!Buffer.isBuffer(bytes) || bytes.length <= 0 || bytes.length > MAX_ENVELOPE_BYTES) {
    fail("OUTPUT_FAILED", "Recovery envelope bytes are outside their bound");
  }
  await assertTargetStillMounted(target);
  await publishCreateOnlyFile(
    target.envelopePath,
    bytes,
    MAX_ENVELOPE_BYTES,
    () => assertTargetStillMounted(target),
    hooks,
    "Recovery envelope",
  );
}

export async function reverifyRecoveryTargetAfterRemount(
  target: RecoveryTarget,
  copyIndex: RecoveryCopyIndex,
): Promise<RecoveryTarget> {
  try {
    const mountedIdentity = await assertTargetStillMounted({ ...target, envelopeExists: true });
    const eject = spawnSync("/usr/sbin/diskutil", ["eject", mountedIdentity.physicalDeviceId], {
      encoding: "buffer",
      env: MINIMAL_ENV,
      maxBuffer: 64 * 1024,
      shell: false,
      timeout: 30_000,
    });
    wipeProcessOutput(eject.stdout, eject.stderr);
    if (eject.status !== 0 || eject.signal !== null) {
      fail("RESUME_REQUIRED", "Recovery disk could not be safely ejected for restore verification");
    }
    const tty = await open("/dev/tty", fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
    const response = Buffer.alloc(2);
    const prompt = Buffer.from(
      `Physically disconnect and reconnect recovery disk ${copyIndex}, unlock it, then press Return: `,
      "utf8",
    );
    try {
      await tty.write(prompt);
      const { bytesRead } = await tty.read(response, 0, response.length, null);
      await tty.write(Buffer.from("\n", "ascii"));
      if (
        bytesRead === 0 ||
        response.subarray(0, bytesRead).some((byte) => byte !== 0x0a && byte !== 0x0d)
      ) {
        fail("RESUME_REQUIRED", "Recovery remount confirmation was not received");
      }
    } finally {
      response.fill(0);
      prompt.fill(0);
      await tty.close();
    }
    const refreshed = await inspectRecoveryTarget(target.directoryPath, copyIndex);
    return assertRecoveryTargetRemountIdentity(target, refreshed);
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError && error.code === "RESUME_REQUIRED") {
      throw error;
    }
    fail(
      "RESUME_REQUIRED",
      "Recovery disk remount evidence is incomplete; preserve the copy and resume",
    );
  }
}

export function assertRecoveryTargetRemountIdentity(
  target: RecoveryTarget,
  refreshed: RecoveryTarget,
): RecoveryTarget {
  if (
    !refreshed.envelopeExists ||
    refreshed.physicalStoreId !== target.physicalStoreId ||
    refreshed.volumeId !== target.volumeId
  ) {
    fail("RESUME_REQUIRED", "Recovery disk identity changed after physical remount");
  }
  return refreshed;
}

export async function readOptionalPublicFile(
  path: string,
  repositoryRoot: string,
  suffix: string,
): Promise<Buffer | undefined> {
  const absolute = validateExternalPath(path, repositoryRoot, suffix);
  await guardOwnerDirectory(dirname(absolute), "evidence");
  const pending = await lstatIfExists(publicationTemporaryPath(absolute));
  if (pending !== undefined) {
    fail(
      "RESUME_REQUIRED",
      "Provisioning evidence has a retained partial publication; preserve it for remediation",
    );
  }
  const existing = await lstatIfExists(absolute);
  if (existing === undefined) return undefined;
  return readUniqueOwnerFile(absolute, MAX_PUBLIC_FILE_BYTES);
}

export interface ProvisioningOutputHooksForTest {
  readonly afterCreate?: () => Promise<void> | void;
  readonly afterFileSync?: () => Promise<void> | void;
  readonly afterTemporaryClose?: () => Promise<void> | void;
  readonly afterTemporaryUnlink?: () => Promise<void> | void;
  readonly afterLink?: () => Promise<void> | void;
  readonly beforeDirectorySync?: (
    stage: "temporary" | "destination" | "cleanup",
  ) => Promise<void> | void;
  readonly beforeLink?: () => Promise<void> | void;
  readonly beforeTemporaryClose?: () => Promise<void> | void;
}

export async function writePublicFileCreateOnly(
  path: string,
  repositoryRoot: string,
  suffix: string,
  bytes: Buffer,
  hooks: ProvisioningOutputHooksForTest = {},
): Promise<void> {
  const absolute = validateExternalPath(path, repositoryRoot, suffix);
  const parent = await guardOwnerDirectory(dirname(absolute), "evidence");
  if (!Buffer.isBuffer(bytes) || bytes.length <= 0 || bytes.length > MAX_PUBLIC_FILE_BYTES) {
    fail("OUTPUT_FAILED", "Provisioning evidence bytes are outside their bound");
  }
  await publishCreateOnlyFile(
    absolute,
    bytes,
    MAX_PUBLIC_FILE_BYTES,
    () => assertDirectoryGuard(parent),
    hooks,
    "Provisioning evidence",
  );
}

async function publishCreateOnlyFile(
  destination: string,
  bytes: Buffer,
  maximumBytes: number,
  assertBoundary: () => Promise<unknown>,
  hooks: ProvisioningOutputHooksForTest,
  role: string,
): Promise<void> {
  const temporary = publicationTemporaryPath(destination);
  let handle: FileHandle | undefined;
  let temporaryCreated = false;
  let destinationLinked = false;
  let opened: BigIntStats | undefined;
  try {
    if ((await lstatIfExists(destination)) !== undefined) {
      fail("RESUME_REQUIRED", `${role} destination already exists; use the fixed resume workflow`);
    }
    await assertBoundary();
    handle = await open(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    temporaryCreated = true;
    await handle.chmod(0o600);
    if (hooks.afterCreate !== undefined) await hooks.afterCreate();
    opened = await handle.stat({ bigint: true });
    if (!safePublicationFile(opened, 1n, 0n)) {
      fail("OUTPUT_FAILED", `${role} temporary file is unsafe`);
    }
    await handle.writeFile(bytes);
    await handle.sync();
    if (hooks.afterFileSync !== undefined) await hooks.afterFileSync();
    const written = await handle.stat({ bigint: true });
    const temporaryStat = await lstat(temporary, { bigint: true });
    if (
      !sameFile(opened, written) ||
      !sameFile(written, temporaryStat) ||
      !safePublicationFile(written, 1n, BigInt(bytes.length))
    ) {
      fail("OUTPUT_FAILED", `${role} temporary file changed during commit`);
    }
    if (hooks.beforeTemporaryClose !== undefined) await hooks.beforeTemporaryClose();
    await handle.close();
    handle = undefined;
    if (hooks.afterTemporaryClose !== undefined) await hooks.afterTemporaryClose();

    await assertBoundary();
    if (hooks.beforeDirectorySync !== undefined) {
      await hooks.beforeDirectorySync("temporary");
    }
    await syncDirectory(dirname(destination));
    await assertBoundary();
    await assertPublishedBytes(temporary, bytes, maximumBytes, 1n, role);

    if (hooks.beforeLink !== undefined) await hooks.beforeLink();
    await link(temporary, destination);
    destinationLinked = true;
    if (hooks.afterLink !== undefined) await hooks.afterLink();

    const linkedTemporary = await lstat(temporary, { bigint: true });
    const linkedDestination = await lstat(destination, { bigint: true });
    if (
      opened === undefined ||
      !sameFile(opened, linkedTemporary) ||
      !sameFile(linkedTemporary, linkedDestination) ||
      !safePublicationFile(linkedTemporary, 2n, BigInt(bytes.length)) ||
      !safePublicationFile(linkedDestination, 2n, BigInt(bytes.length))
    ) {
      fail("OUTPUT_FAILED", `${role} hard-link publication changed unexpectedly`);
    }
    await assertPublishedBytes(destination, bytes, maximumBytes, 2n, role);
    await assertBoundary();
    if (hooks.beforeDirectorySync !== undefined) {
      await hooks.beforeDirectorySync("destination");
    }
    await syncDirectory(dirname(destination));
    await assertBoundary();
    const durableTemporary = await lstat(temporary, { bigint: true });
    const durableDestination = await lstat(destination, { bigint: true });
    if (
      opened === undefined ||
      !sameFile(opened, durableTemporary) ||
      !sameFile(durableTemporary, durableDestination) ||
      !safePublicationFile(durableTemporary, 2n, BigInt(bytes.length)) ||
      !safePublicationFile(durableDestination, 2n, BigInt(bytes.length))
    ) {
      fail("OUTPUT_FAILED", `${role} changed after its destination directory sync`);
    }
    await assertPublishedBytes(destination, bytes, maximumBytes, 2n, role);

    // The destination is already durable before cleanup begins. Unlinking the
    // temporary name requires its own directory sync so a crash cannot
    // resurrect a stale partial path and wedge otherwise-complete state.
    await unlink(temporary);
    if (hooks.afterTemporaryUnlink !== undefined) await hooks.afterTemporaryUnlink();
    if (hooks.beforeDirectorySync !== undefined) {
      await hooks.beforeDirectorySync("cleanup");
    }
    await syncDirectory(dirname(destination));
    await assertBoundary();
    await assertPublishedBytes(destination, bytes, maximumBytes, 1n, role);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    handle = undefined;
    if (
      temporaryCreated ||
      destinationLinked ||
      isErrno(error, "EEXIST") ||
      (error instanceof ReleaseKeyProvisioningError && error.code === "RESUME_REQUIRED")
    ) {
      fail(
        "RESUME_REQUIRED",
        `${role} publication is durable or uncertain; preserve every retained path and resume`,
      );
    }
    if (error instanceof ReleaseKeyProvisioningError) throw error;
    fail("OUTPUT_FAILED", `${role} could not be published create-only`);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function assertPublishedBytes(
  path: string,
  expected: Buffer,
  maximumBytes: number,
  expectedLinks: bigint,
  role: string,
): Promise<void> {
  const retained = await readUniqueOwnerFile(path, maximumBytes, expectedLinks);
  try {
    if (retained.length !== expected.length || !timingSafeEqual(retained, expected)) {
      fail("OUTPUT_FAILED", `${role} bytes did not verify after publication`);
    }
  } finally {
    retained.fill(0);
  }
}

function publicationTemporaryPath(destination: string): string {
  return join(
    dirname(destination),
    `${PARTIAL_PUBLICATION_PREFIX}${sha256(destination).slice(0, 32)}${PARTIAL_PUBLICATION_SUFFIX}`,
  );
}

export function fixedProvisioningIntentPath(): string {
  return join(
    homedir(),
    "Library",
    "Application Support",
    "RSI",
    `foundation${PROVISIONING_INTENT_SUFFIX}`,
  );
}

export async function readFixedProvisioningIntent(
  repositoryRoot: string,
): Promise<Buffer | undefined> {
  return readOptionalPublicFile(
    fixedProvisioningIntentPath(),
    repositoryRoot,
    PROVISIONING_INTENT_SUFFIX,
  );
}

export async function writeFixedProvisioningIntentCreateOnly(
  repositoryRoot: string,
  bytes: Buffer,
): Promise<void> {
  return writePublicFileCreateOnly(
    fixedProvisioningIntentPath(),
    repositoryRoot,
    PROVISIONING_INTENT_SUFFIX,
    bytes,
  );
}

export async function promptRecoveryPassphrase(
  copyIndex: RecoveryCopyIndex,
  phase: PassphrasePhase,
): Promise<Buffer> {
  const prompt = Buffer.from(
    `Recovery copy ${copyIndex} ${phase} passphrase (terminal only): `,
    "utf8",
  );
  const tty = await open("/dev/tty", fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
  const buffer = Buffer.alloc(257);
  let echoDisabled = false;
  try {
    const disabled = spawnSync("/bin/stty", ["-f", "/dev/tty", "-echo"], {
      encoding: "buffer",
      env: MINIMAL_ENV,
      maxBuffer: 4 * 1024,
      shell: false,
      timeout: 5_000,
    });
    wipeProcessOutput(disabled.stdout, disabled.stderr);
    if (disabled.status !== 0 || disabled.signal !== null) {
      fail("PASSPHRASE_REFUSED", "Terminal echo could not be disabled");
    }
    echoDisabled = true;
    await tty.write(prompt);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await tty.read(buffer, length, buffer.length - length, null);
      if (bytesRead === 0) break;
      const newline = buffer
        .subarray(length, length + bytesRead)
        .findIndex((byte) => byte === 0x0a || byte === 0x0d);
      if (newline >= 0) {
        length += newline;
        break;
      }
      length += bytesRead;
    }
    await tty.write(Buffer.from("\n", "ascii"));
    if (length < 24 || length > 256) {
      fail("PASSPHRASE_REFUSED", "Recovery passphrase length is outside the fixed policy");
    }
    return Buffer.from(buffer.subarray(0, length));
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError && error.code === "PASSPHRASE_REFUSED") {
      throw error;
    }
    return fail("PASSPHRASE_REFUSED", "Recovery passphrase could not be read from the terminal");
  } finally {
    buffer.fill(0);
    prompt.fill(0);
    if (echoDisabled) {
      const restored = spawnSync("/bin/stty", ["-f", "/dev/tty", "echo"], {
        encoding: "buffer",
        env: MINIMAL_ENV,
        maxBuffer: 4 * 1024,
        shell: false,
        timeout: 5_000,
      });
      wipeProcessOutput(restored.stdout, restored.stderr);
    }
    await tty.close();
  }
}

export function createNativeKeychainAdapter(repositoryRoot: string): DisposableKeychainAdapter {
  const root = resolve(repositoryRoot);
  let approvedSource: Buffer | undefined;
  let helperBinarySha256: string | undefined;
  let helperCompilerIdentitySha256: string | undefined;
  let helperSourceSha256: string | undefined;
  let helperDirectory: string | undefined;
  let helperPath: string | undefined;

  async function captureApprovedSource(): Promise<Buffer> {
    if (approvedSource !== undefined) return approvedSource;
    const [headSource, workingSource] = await Promise.all([
      Promise.resolve(gitBytes(root, ["show", `HEAD:${HELPER_REPOSITORY_PATH}`])),
      readFile(helperSourcePath),
    ]);
    try {
      if (
        headSource.length === 0 ||
        headSource.length > 1024 * 1024 ||
        workingSource.length !== headSource.length ||
        !timingSafeEqual(workingSource, headSource)
      ) {
        fail("REPOSITORY_STATE", "Keychain helper source does not match the tracked HEAD blob");
      }
      approvedSource = Buffer.from(headSource);
      helperSourceSha256 = sha256(approvedSource);
      return approvedSource;
    } finally {
      headSource.fill(0);
      workingSource.fill(0);
    }
  }

  async function ensureHelper(): Promise<string> {
    if (helperPath !== undefined) {
      await assertHelperStillApproved(helperPath);
      return helperPath;
    }
    const source = await captureApprovedSource();
    helperDirectory = await mkdtemp(join(tmpdir(), "rsi-release-key-helper-"));
    await chmod(helperDirectory, 0o700);
    const snapshot = join(helperDirectory, "keychain-helper.swift");
    const snapshotHandle = await open(
      snapshot,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    try {
      await snapshotHandle.writeFile(source);
      await snapshotHandle.sync();
    } finally {
      await snapshotHandle.close();
    }
    const candidate = join(helperDirectory, "rsi-release-key-helper");
    helperCompilerIdentitySha256 = compilerIdentitySha256();
    const compile = spawnSync(
      "/usr/bin/xcrun",
      [
        "swiftc",
        "-O",
        "-module-name",
        "RSIReleaseKeyHelper",
        "-file-prefix-map",
        `${helperDirectory}=/rsi/foundation-helper-build`,
        "-Xlinker",
        "-no_uuid",
        snapshot,
        "-o",
        candidate,
      ],
      {
        cwd: helperDirectory,
        encoding: "buffer",
        env: MINIMAL_ENV,
        maxBuffer: 128 * 1024,
        shell: false,
        timeout: 60_000,
      },
    );
    wipeProcessOutput(compile.stdout, compile.stderr);
    if (compile.status !== 0 || compile.signal !== null) {
      fail("KEYCHAIN_FAILED", "Fixed Keychain helper compilation failed");
    }
    await chmod(candidate, 0o700);
    const sign = spawnSync(
      "/usr/bin/codesign",
      ["--force", "--sign", "-", "--timestamp=none", candidate],
      {
        encoding: "buffer",
        env: MINIMAL_ENV,
        maxBuffer: 64 * 1024,
        shell: false,
        timeout: 30_000,
      },
    );
    wipeProcessOutput(sign.stdout, sign.stderr);
    if (sign.status !== 0 || sign.signal !== null) {
      fail("KEYCHAIN_FAILED", "Fixed Keychain helper signing failed");
    }
    const verify = spawnSync("/usr/bin/codesign", ["--verify", "--strict", candidate], {
      encoding: "buffer",
      env: MINIMAL_ENV,
      maxBuffer: 64 * 1024,
      shell: false,
      timeout: 30_000,
    });
    wipeProcessOutput(verify.stdout, verify.stderr);
    if (verify.status !== 0 || verify.signal !== null) {
      fail("KEYCHAIN_FAILED", "Fixed Keychain helper identity verification failed");
    }
    const binary = await readFile(candidate);
    try {
      helperBinarySha256 = sha256(binary);
    } finally {
      binary.fill(0);
    }
    helperPath = candidate;
    await assertHelperStillApproved(candidate);
    return candidate;
  }

  async function assertHelperStillApproved(candidate: string): Promise<void> {
    const source = await captureApprovedSource();
    const [workingSource, headSource, binary] = await Promise.all([
      readFile(helperSourcePath),
      Promise.resolve(gitBytes(root, ["show", `HEAD:${HELPER_REPOSITORY_PATH}`])),
      readFile(candidate),
    ]);
    try {
      if (
        workingSource.length !== source.length ||
        headSource.length !== source.length ||
        !timingSafeEqual(workingSource, source) ||
        !timingSafeEqual(headSource, source) ||
        helperBinarySha256 === undefined ||
        sha256(binary) !== helperBinarySha256 ||
        compilerIdentitySha256() !== helperCompilerIdentitySha256
      ) {
        fail("KEYCHAIN_FAILED", "Fixed Keychain helper identity changed during use");
      }
    } finally {
      workingSource.fill(0);
      headSource.fill(0);
      binary.fill(0);
    }
    const verify = spawnSync("/usr/bin/codesign", ["--verify", "--strict", candidate], {
      encoding: "buffer",
      env: MINIMAL_ENV,
      maxBuffer: 64 * 1024,
      shell: false,
      timeout: 30_000,
    });
    wipeProcessOutput(verify.stdout, verify.stderr);
    if (verify.status !== 0 || verify.signal !== null) {
      fail("KEYCHAIN_FAILED", "Fixed Keychain helper code signature changed during use");
    }
  }

  async function invokePresence(): Promise<number> {
    const executable = await ensureHelper();
    const result = spawnSync(executable, ["presence"], {
      encoding: "buffer",
      env: MINIMAL_ENV,
      maxBuffer: 4 * 1024,
      shell: false,
      timeout: 20_000,
    });
    wipeProcessOutput(result.stdout, result.stderr);
    if (result.signal !== null || result.status === null) {
      fail("KEYCHAIN_FAILED", "Fixed Keychain helper did not complete");
    }
    return result.status;
  }

  return Object.freeze({
    async addCreateOnly(_encodedKey: Buffer): Promise<void> {
      fail("KEYCHAIN_FAILED", LEGACY_HELPER_REFUSAL);
    },
    async dispose(): Promise<void> {
      if (helperDirectory !== undefined) {
        const exact = helperDirectory;
        helperDirectory = undefined;
        helperPath = undefined;
        helperBinarySha256 = undefined;
        helperCompilerIdentitySha256 = undefined;
        await rm(exact, { force: true, recursive: true });
      }
      approvedSource?.fill(0);
      approvedSource = undefined;
      helperSourceSha256 = undefined;
    },
    async helperEvidence() {
      await ensureHelper();
      if (
        helperBinarySha256 === undefined ||
        helperCompilerIdentitySha256 === undefined ||
        helperSourceSha256 === undefined
      ) {
        fail("KEYCHAIN_FAILED", "Fixed Keychain helper evidence is unavailable");
      }
      return Object.freeze({
        binarySha256: helperBinarySha256,
        compilerIdentitySha256: helperCompilerIdentitySha256,
        sourceSha256: helperSourceSha256,
      });
    },
    async inspectPresence(): Promise<boolean> {
      const status = await invokePresence();
      if (status === 0) return true;
      if (status === 2) return false;
      fail("KEYCHAIN_FAILED", "Fixed Keychain identity presence is indeterminate");
    },
    async signFoundationTag(_message: Uint8Array): Promise<Uint8Array> {
      fail("KEYCHAIN_FAILED", LEGACY_HELPER_REFUSAL);
    },
    async signReleaseManifest(_message: Uint8Array): Promise<Uint8Array> {
      fail("KEYCHAIN_FAILED", LEGACY_HELPER_REFUSAL);
    },
    async verifyAclAndMatch(_encodedKey: Buffer): Promise<boolean> {
      fail("KEYCHAIN_FAILED", LEGACY_HELPER_REFUSAL);
    },
  });
}

function inspectEncryptedExternalDisk(path: string): DiskTargetIdentity {
  const volume = diskutilInfo(path);
  const validatedVolume = validateEncryptedExternalVolumeMetadata(path, volume);
  const physical = diskutilInfo(validatedVolume.physicalStoreSubject);
  const validatedPhysical = validatePhysicalStoreMetadata(
    physical,
    validatedVolume.physicalStoreSubject,
  );
  const wholeDisk = diskutilInfo(validatedPhysical.physicalDeviceId);
  return validateEncryptedExternalDiskMetadata(path, volume, physical, wholeDisk);
}

export function validateEncryptedExternalDiskMetadata(
  path: string,
  volume: unknown,
  physical: unknown,
  wholeDisk: unknown,
): DiskTargetIdentity {
  const validatedVolume = validateEncryptedExternalVolumeMetadata(path, volume);
  const validatedPhysical = validatePhysicalStoreMetadata(
    physical,
    validatedVolume.physicalStoreSubject,
  );
  if (
    !isPlainRecord(wholeDisk) ||
    wholeDisk.DeviceIdentifier !== validatedPhysical.physicalDeviceId ||
    wholeDisk.Internal !== false ||
    wholeDisk.RemovableMediaOrExternalDevice !== true ||
    wholeDisk.VirtualOrPhysical !== "Physical" ||
    wholeDisk.WritableMedia !== true ||
    typeof wholeDisk.BusProtocol !== "string" ||
    !/^[A-Za-z][A-Za-z0-9 ._-]{0,63}$/u.test(wholeDisk.BusProtocol) ||
    /(?:disk\s*image|file|virtual)/iu.test(wholeDisk.BusProtocol)
  ) {
    fail("TARGET_REFUSED", "Recovery target is not backed by an external physical disk");
  }
  return Object.freeze({
    // ParentWholeDisk is intentionally retained only as the live diskutil eject
    // handle. macOS may assign a different diskN after physical reconnection.
    physicalDeviceId: validatedPhysical.physicalDeviceId,
    // The APFS physical-store partition UUID is the durable media identity.
    physicalStoreId: validatedPhysical.physicalStoreId,
    volumeId: validatedVolume.volumeId,
  });
}

function validatePhysicalStoreMetadata(
  value: unknown,
  expectedPhysicalStoreSubject: string,
): ValidatedPhysicalStore {
  if (
    !isPlainRecord(value) ||
    value.Internal !== false ||
    value.DeviceIdentifier !== expectedPhysicalStoreSubject ||
    typeof value.ParentWholeDisk !== "string" ||
    !/^disk\d+$/u.test(value.ParentWholeDisk) ||
    typeof value.DiskUUID !== "string" ||
    !UUID_PATTERN.test(value.DiskUUID)
  ) {
    fail("TARGET_REFUSED", "Recovery target physical-store metadata is invalid");
  }
  return Object.freeze({
    physicalDeviceId: value.ParentWholeDisk,
    physicalStoreId: value.DiskUUID.toUpperCase(),
  });
}

function validateEncryptedExternalVolumeMetadata(
  path: string,
  value: unknown,
): ValidatedEncryptedExternalVolume {
  if (!isPlainRecord(value)) {
    fail("TARGET_REFUSED", "Recovery volume metadata is invalid");
  }
  const volume = value;
  if (
    volume.FilesystemType !== "apfs" ||
    volume.Encryption !== true ||
    volume.Internal !== false ||
    volume.Writable !== true ||
    typeof volume.MountPoint !== "string" ||
    typeof volume.VolumeUUID !== "string" ||
    !UUID_PATTERN.test(volume.VolumeUUID)
  ) {
    fail("TARGET_REFUSED", "Recovery target is not a writable encrypted external APFS volume");
  }
  const mountPoint = volume.MountPoint;
  const within = relative(mountPoint, path);
  if (
    !isAbsolute(mountPoint) ||
    within === ".." ||
    within.startsWith(`..${sep}`) ||
    isAbsolute(within)
  ) {
    fail("TARGET_REFUSED", "Recovery directory is outside its reported mount point");
  }
  const stores = volume.APFSPhysicalStores;
  if (!Array.isArray(stores) || stores.length !== 1) {
    fail("TARGET_REFUSED", "Recovery volume must use exactly one physical store");
  }
  const store = stores[0];
  if (!isPlainRecord(store) || typeof store.APFSPhysicalStore !== "string") {
    fail("TARGET_REFUSED", "Recovery physical-store identity is invalid");
  }
  return Object.freeze({
    physicalStoreSubject: store.APFSPhysicalStore,
    volumeId: volume.VolumeUUID.toUpperCase(),
  });
}

function isPlainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function diskutilInfo(subject: string): Record<string, unknown> {
  const plist = spawnSync("/usr/sbin/diskutil", ["info", "-plist", subject], {
    encoding: "buffer",
    env: MINIMAL_ENV,
    maxBuffer: 128 * 1024,
    shell: false,
    timeout: 10_000,
  });
  const plistBytes = Buffer.isBuffer(plist.stdout) ? plist.stdout : Buffer.alloc(0);
  const plistError = Buffer.isBuffer(plist.stderr) ? plist.stderr : Buffer.alloc(0);
  try {
    if (plist.status !== 0 || plist.signal !== null || plistBytes.length === 0) {
      fail("TARGET_REFUSED", "Recovery volume inspection failed");
    }
    const json = spawnSync("/usr/bin/plutil", ["-convert", "json", "-o", "-", "--", "-"], {
      encoding: "buffer",
      env: MINIMAL_ENV,
      input: plistBytes,
      maxBuffer: 128 * 1024,
      shell: false,
      timeout: 10_000,
    });
    const jsonBytes = Buffer.isBuffer(json.stdout) ? json.stdout : Buffer.alloc(0);
    const jsonError = Buffer.isBuffer(json.stderr) ? json.stderr : Buffer.alloc(0);
    try {
      if (json.status !== 0 || json.signal !== null || jsonBytes.length === 0) {
        fail("TARGET_REFUSED", "Recovery volume metadata conversion failed");
      }
      const value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(jsonBytes),
      ) as unknown;
      if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype
      ) {
        fail("TARGET_REFUSED", "Recovery volume metadata is invalid");
      }
      return value as Record<string, unknown>;
    } catch (error) {
      if (error instanceof ReleaseKeyProvisioningError && error.code === "TARGET_REFUSED") {
        throw error;
      }
      fail("TARGET_REFUSED", "Recovery volume metadata is invalid");
    } finally {
      jsonBytes.fill(0);
      jsonError.fill(0);
    }
  } finally {
    plistBytes.fill(0);
    plistError.fill(0);
  }
}

async function assertTargetStillMounted(target: RecoveryTarget): Promise<DiskTargetIdentity> {
  const current = await lstat(target.directoryPath, { bigint: true }).catch(() => undefined);
  if (
    current === undefined ||
    !current.isDirectory() ||
    current.dev !== target.directoryDevice ||
    current.ino !== target.directoryInode ||
    current.uid !== currentUserId(current.uid) ||
    (Number(current.mode) & 0o077) !== 0
  ) {
    fail("TARGET_REFUSED", "Recovery target changed during use");
  }
  const identity = inspectEncryptedExternalDisk(target.directoryPath);
  if (
    identity.physicalStoreId !== target.physicalStoreId ||
    identity.volumeId !== target.volumeId
  ) {
    fail("TARGET_REFUSED", "Recovery volume identity changed during use");
  }
  return identity;
}

async function guardOwnerDirectory(
  path: string,
  role: "evidence" | "recovery",
): Promise<DirectoryGuard> {
  const stats = await lstat(path, { bigint: true }).catch(() => undefined);
  const uid = typeof process.getuid === "function" ? BigInt(process.getuid()) : stats?.uid;
  if (
    stats === undefined ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.uid !== uid ||
    (Number(stats.mode) & 0o077) !== 0 ||
    (await realpath(path).catch(() => "")) !== path
  ) {
    fail(
      role === "recovery" ? "TARGET_REFUSED" : "INPUT_INVALID",
      role === "recovery"
        ? "Recovery directory is not canonical and owner-only"
        : "Provisioning evidence directory is not canonical and owner-only",
    );
  }
  return Object.freeze({
    device: stats.dev,
    inode: stats.ino,
    mode: Number(stats.mode) & 0o777,
    path,
    uid: stats.uid,
  });
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
    fail("INPUT_INVALID", "Provisioning evidence directory changed during use");
  }
}

async function readUniqueOwnerFile(
  path: string,
  maximumBytes: number,
  expectedLinks: bigint = 1n,
): Promise<Buffer> {
  const before = await lstat(path, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== currentUserId(before.uid) ||
    before.nlink !== expectedLinks ||
    (Number(before.mode) & 0o077) !== 0 ||
    before.size <= 0n ||
    before.size > BigInt(maximumBytes)
  ) {
    fail("INPUT_INVALID", "Provisioning input file is unsafe");
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameFileSnapshot(before, opened)) {
      fail("INPUT_INVALID", "Provisioning input changed during open");
    }
    const bytes = await handle.readFile();
    const [after, pathAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (
      bytes.length !== Number(opened.size) ||
      !sameFileSnapshot(opened, after) ||
      !sameFileSnapshot(after, pathAfter)
    ) {
      bytes.fill(0);
      fail("INPUT_INVALID", "Provisioning input changed while reading");
    }
    return bytes;
  } finally {
    await handle.close();
  }
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
    fail("INPUT_INVALID", "Provisioning evidence path is invalid");
  }
  const within = relative(resolve(repositoryRoot), path);
  if (within === "" || (!within.startsWith(`..${sep}`) && within !== ".." && !isAbsolute(within))) {
    fail("INPUT_INVALID", "Provisioning evidence must remain outside the repository");
  }
  return path;
}

function git(root: string, args: readonly string[]): string {
  const result = spawnSync("/usr/bin/git", [...HARDENED_GIT_ARGUMENTS, ...args], {
    cwd: root,
    encoding: "utf8",
    env: HARDENED_GIT_ENV,
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  if (result.status !== 0 || result.signal !== null) {
    fail("REPOSITORY_STATE", "Release-key provisioning Git inspection failed");
  }
  return result.stdout;
}

function gitBytes(root: string, args: readonly string[]): Buffer {
  const result = spawnSync("/usr/bin/git", [...HARDENED_GIT_ARGUMENTS, ...args], {
    cwd: root,
    encoding: "buffer",
    env: HARDENED_GIT_ENV,
    maxBuffer: 2 * 1024 * 1024,
    shell: false,
    timeout: 20_000,
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  stderr.fill(0);
  if (result.status !== 0 || result.signal !== null || stdout.length === 0) {
    stdout.fill(0);
    fail("REPOSITORY_STATE", "Keychain helper tracked-source inspection failed");
  }
  return stdout;
}

function gitIsAncestor(root: string, ancestor: string, descendant: string): boolean {
  const result = spawnSync(
    "/usr/bin/git",
    [...HARDENED_GIT_ARGUMENTS, "merge-base", "--is-ancestor", ancestor, descendant],
    {
      cwd: root,
      encoding: "buffer",
      env: HARDENED_GIT_ENV,
      maxBuffer: 64 * 1024,
      shell: false,
      timeout: 20_000,
    },
  );
  wipeProcessOutput(result.stdout, result.stderr);
  if (result.signal !== null || result.status === null) {
    fail("REPOSITORY_STATE", "Helper compatibility ancestry inspection failed");
  }
  return result.status === 0;
}

function assertUnambiguousGitHistory(root: string): void {
  const graftsPath = resolve(root, git(root, ["rev-parse", "--git-path", "info/grafts"]).trim());
  if (
    git(root, ["for-each-ref", "--format=%(refname)", "refs/replace"]).trim() !== "" ||
    existsSync(graftsPath) ||
    git(root, ["rev-parse", "--is-shallow-repository"]).trim() !== "false"
  ) {
    fail("REPOSITORY_STATE", "Release-key provisioning Git history is ambiguous");
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
      fail("REPOSITORY_STATE", "macOS compatibility build identity is unavailable");
    }
    const value = new TextDecoder("utf-8", { fatal: true }).decode(stdout).trim();
    if (value.length === 0 || value.length > 64 || /[\u0000-\u001f\u007f]/u.test(value)) {
      fail("REPOSITORY_STATE", "macOS compatibility build identity is invalid");
    }
    return value;
  } catch (error) {
    if (error instanceof ReleaseKeyProvisioningError) throw error;
    fail("REPOSITORY_STATE", "macOS compatibility build identity is invalid");
  } finally {
    stdout.fill(0);
    stderr.fill(0);
  }
}

function compilerIdentitySha256(): string {
  const swift = spawnSync("/usr/bin/xcrun", ["swiftc", "--version"], {
    encoding: "buffer",
    env: MINIMAL_ENV,
    maxBuffer: 64 * 1024,
    shell: false,
    timeout: 10_000,
  });
  const xcode = spawnSync("/usr/bin/xcodebuild", ["-version"], {
    encoding: "buffer",
    env: MINIMAL_ENV,
    maxBuffer: 64 * 1024,
    shell: false,
    timeout: 10_000,
  });
  const swiftOut = Buffer.isBuffer(swift.stdout) ? swift.stdout : Buffer.alloc(0);
  const swiftErr = Buffer.isBuffer(swift.stderr) ? swift.stderr : Buffer.alloc(0);
  const xcodeOut = Buffer.isBuffer(xcode.stdout) ? xcode.stdout : Buffer.alloc(0);
  const xcodeErr = Buffer.isBuffer(xcode.stderr) ? xcode.stderr : Buffer.alloc(0);
  let identity = Buffer.alloc(0);
  try {
    if (
      swift.status !== 0 ||
      swift.signal !== null ||
      swiftOut.length === 0 ||
      xcode.status !== 0 ||
      xcode.signal !== null ||
      xcodeOut.length === 0
    ) {
      fail("KEYCHAIN_FAILED", "Fixed Keychain helper compiler identity is unavailable");
    }
    identity = Buffer.concat([
      Buffer.from("rsi-keychain-helper-compiler-v1\0", "ascii"),
      swiftOut,
      Buffer.from("\0", "ascii"),
      xcodeOut,
    ]);
    return sha256(identity);
  } finally {
    identity.fill(0);
    swiftOut.fill(0);
    swiftErr.fill(0);
    xcodeOut.fill(0);
    xcodeErr.fill(0);
  }
}

function pnpmVersion(): string | null {
  return /(?:^|\s)pnpm\/([^\s]+)/u.exec(process.env.npm_config_user_agent ?? "")?.[1] ?? null;
}

function hasExactlyOneApprovedRemoteUrl(rawValues: string): boolean {
  const values = rawValues.endsWith("\n")
    ? rawValues.slice(0, -1).split("\n")
    : rawValues.split("\n");
  return (
    values.length === 1 && (values[0] === APPROVED_REMOTE || values[0] === APPROVED_SSH_REMOTE)
  );
}

function currentUserId(fallback: bigint): bigint {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : fallback;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.isFile() && right.isFile() && left.dev === right.dev && left.ino === right.ino;
}

function sameFileSnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    sameFile(left, right) &&
    left.size === right.size &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === right.nlink
  );
}

async function syncDirectory(path: string): Promise<void> {
  let directory: FileHandle | undefined;
  try {
    const before = await lstat(path, { bigint: true });
    if (
      !before.isDirectory() ||
      before.isSymbolicLink() ||
      before.uid !== currentUserId(before.uid) ||
      (Number(before.mode) & 0o077) !== 0
    ) {
      fail("OUTPUT_FAILED", "Provisioning directory sync target is unsafe");
    }
    directory = await open(
      path,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    const opened = await directory.stat({ bigint: true });
    if (!sameDirectorySnapshot(before, opened)) {
      fail("OUTPUT_FAILED", "Provisioning directory changed before sync");
    }
    await directory.sync();
    const [after, pathAfter] = await Promise.all([
      directory.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (!sameDirectorySnapshot(opened, after) || !sameDirectorySnapshot(after, pathAfter)) {
      fail("OUTPUT_FAILED", "Provisioning directory changed during sync");
    }
  } catch {
    fail("OUTPUT_FAILED", "Provisioning directory sync could not be proven");
  } finally {
    await directory?.close().catch(() => undefined);
  }
}

function sameDirectorySnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.isDirectory() &&
    right.isDirectory() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === right.nlink
  );
}

function safePublicationFile(
  stats: BigIntStats,
  expectedLinks: bigint,
  expectedSize: bigint,
): boolean {
  return (
    stats.isFile() &&
    stats.nlink === expectedLinks &&
    stats.uid === currentUserId(stats.uid) &&
    stats.size === expectedSize &&
    (Number(stats.mode) & 0o777) === 0o600
  );
}

async function lstatIfExists(path: string): Promise<BigIntStats | undefined> {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (isErrno(error, "ENOENT")) return undefined;
    throw error;
  }
}

function wipeProcessOutput(stdout: unknown, stderr: unknown): void {
  if (Buffer.isBuffer(stdout)) stdout.fill(0);
  if (Buffer.isBuffer(stderr)) stderr.fill(0);
}

function isErrno(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
