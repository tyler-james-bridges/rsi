import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants as fsConstants, type BigIntStats } from "node:fs";
import { lstat, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import type { ReleaseBundleReceiptV1, ReleaseBundleSignerV1 } from "@rsi/release-bundle";

import { canonicalJson, sha256, validateHash } from "./canonical.js";
import { foundationCiEvidenceSha256, parseFoundationCiEvidence } from "./ci-evidence.js";
import { FoundationCeremonyError, fail } from "./errors.js";
import type { FoundationCeremonyCustody, FoundationCiEvidenceV1 } from "./types.js";

export const RELEASE_KEYCHAIN_SERVICE = "dev.rsi.macbook.release-signing" as const;
export const RELEASE_KEYCHAIN_ACCOUNT = "release-ed25519-v1" as const;

const MAX_EVIDENCE_BYTES = 64 * 1024;
const MAX_KEYCHAIN_OUTPUT_BYTES = 512;
const MAX_RECEIPT_BYTES = 64 * 1024;

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
): Promise<{ readonly evidence: FoundationCiEvidenceV1; readonly sha256: string }> {
  const validated = await validateExternalFile(path, repositoryRoot, ".json");
  const bytes = await readUniqueOwnerFile(validated.path, MAX_EVIDENCE_BYTES, validated.parent);
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

export async function readPlatformModel(): Promise<string> {
  const result = spawnSync("/usr/sbin/system_profiler", ["SPHardwareDataType"], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 64 * 1_024,
    shell: false,
    timeout: 15_000,
  });
  const modelName =
    result.status === 0 && result.signal === null
      ? /^\s*Model Name:\s*(MacBook(?: Air| Pro)?)\s*$/mu.exec(result.stdout)?.[1]
      : undefined;
  if (modelName === undefined) {
    fail("HOST_REFUSED", "Foundation ceremony could not verify the host model");
  }
  return "MacBook";
}

export function createMacBookKeychainCustody(): FoundationCeremonyCustody {
  return createKeychainCustody(readReleaseKeyFromKeychain);
}

export function createKeychainCustody(readKeyMaterial: () => Buffer): FoundationCeremonyCustody {
  return Object.freeze({
    withSigner: async <T>(operation: (signer: ReleaseBundleSignerV1) => Promise<T>): Promise<T> => {
      const material = readKeyMaterial();
      let privateKey: KeyObject | undefined;
      let publicKeySpkiDer: Buffer;
      try {
        privateKey = createPrivateKey({ format: "der", key: material, type: "pkcs8" });
        if (privateKey.asymmetricKeyType !== "ed25519") {
          fail("CUSTODY_FAILED", "Release Keychain item is not an Ed25519 key");
        }
        publicKeySpkiDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
      } catch (error) {
        material.fill(0);
        if (error instanceof FoundationCeremonyError) throw error;
        fail("CUSTODY_FAILED", "Release Keychain item could not be imported");
      }
      const fingerprint = sha256(publicKeySpkiDer);
      let active = true;
      let signatureCount = 0;
      const signer = Object.freeze({
        keyId: `rsi-release-${fingerprint.slice(0, 16)}`,
        publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
        sign: (message: Uint8Array): Uint8Array => {
          if (!active || privateKey === undefined || signatureCount !== 0) {
            fail("CUSTODY_FAILED", "Release signing capability is no longer available");
          }
          signatureCount += 1;
          return Uint8Array.from(sign(null, Uint8Array.from(message), privateKey));
        },
      });
      try {
        return await operation(signer);
      } finally {
        active = false;
        privateKey = undefined;
        material.fill(0);
        publicKeySpkiDer.fill(0);
        signer.publicKeySpkiDer.fill(0);
      }
    },
  });
}

export async function writeFoundationReceipt(
  path: string,
  repositoryRoot: string,
  receipt: ReleaseBundleReceiptV1,
): Promise<void> {
  const absolute = await validateExternalDestination(path, repositoryRoot, ".receipt.json");
  const bytes = Buffer.from(canonicalJson(receipt), "utf8");
  if (bytes.length <= 0 || bytes.length > MAX_RECEIPT_BYTES) {
    bytes.fill(0);
    fail("OUTPUT_FAILED", "Foundation retained receipt size is invalid");
  }
  const parent = await guardCanonicalParent(dirname(absolute), "output");
  let handle: FileHandle | undefined;
  let opened: BigIntStats | undefined;
  try {
    handle = await open(
      absolute,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.nlink !== 1n ||
      opened.uid !== currentUserId(opened.uid) ||
      (Number(opened.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation retained receipt file is unsafe");
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
      pathStat.nlink !== 1n ||
      written.size !== BigInt(bytes.length) ||
      (Number(written.mode) & 0o777) !== 0o600
    ) {
      fail("OUTPUT_FAILED", "Foundation retained receipt changed during publication");
    }
    await assertDirectoryGuard(parent);
    await syncDirectory(parent.path);
    await assertDirectoryGuard(parent);
  } catch {
    await handle?.close().catch(() => undefined);
    handle = undefined;
    if (opened !== undefined) await removeMatchingFile(absolute, opened);
    fail("OUTPUT_FAILED", "Foundation retained receipt could not be published");
  } finally {
    bytes.fill(0);
    await handle?.close();
  }
}

export async function validateFoundationDestination(
  path: string,
  repositoryRoot: string,
): Promise<string> {
  return validateExternalDestination(path, repositoryRoot, ".rsi-release");
}

export async function validateFoundationReceiptDestination(
  path: string,
  repositoryRoot: string,
): Promise<string> {
  return validateExternalDestination(path, repositoryRoot, ".receipt.json");
}

export async function removeFoundationOwnedOutput(
  path: string,
  repositoryRoot: string,
  receipt: ReleaseBundleReceiptV1,
): Promise<void> {
  const absolute = validateExternalPath(path, repositoryRoot, ".rsi-release");
  const parent = await guardCanonicalParent(dirname(absolute), "output");
  const expectedHash = validateHash(receipt.archiveSha256, "Foundation cleanup archive hash");
  if (
    !Number.isSafeInteger(receipt.archiveSizeBytes) ||
    receipt.archiveSizeBytes <= 0 ||
    receipt.archiveSizeBytes > 32 * 1024 * 1024
  ) {
    fail("OUTPUT_FAILED", "Foundation cleanup receipt size is invalid");
  }
  const before = await lstat(absolute).catch(() => null);
  if (
    before === null ||
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== process.getuid?.() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o600 ||
    before.size !== receipt.archiveSizeBytes
  ) {
    fail("OUTPUT_FAILED", "Foundation cleanup target is not the created bundle");
  }
  const bytes = await readUniqueOwnerFile(absolute, receipt.archiveSizeBytes, parent);
  try {
    if (bytes.length !== receipt.archiveSizeBytes || sha256(bytes) !== expectedHash) {
      fail("OUTPUT_FAILED", "Foundation cleanup target does not match its receipt");
    }
  } finally {
    bytes.fill(0);
  }
  const current = await lstat(absolute).catch(() => null);
  if (
    current === null ||
    current.dev !== before.dev ||
    current.ino !== before.ino ||
    current.size !== before.size ||
    current.nlink !== 1
  ) {
    fail("OUTPUT_FAILED", "Foundation cleanup target changed before removal");
  }
  await assertDirectoryGuard(parent);
  try {
    await unlink(absolute);
  } catch {
    fail("OUTPUT_FAILED", "Foundation ceremony could not remove its incomplete output");
  }
  if ((await lstat(absolute).catch(() => null)) !== null) {
    fail("OUTPUT_FAILED", "Foundation incomplete output still exists after cleanup");
  }
  await syncDirectory(parent.path);
  await assertDirectoryGuard(parent);
}

function readReleaseKeyFromKeychain(): Buffer {
  const result = spawnSync(
    "/usr/bin/security",
    ["find-generic-password", "-s", RELEASE_KEYCHAIN_SERVICE, "-a", RELEASE_KEYCHAIN_ACCOUNT, "-w"],
    {
      encoding: "buffer",
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      maxBuffer: MAX_KEYCHAIN_OUTPUT_BYTES,
      shell: false,
      timeout: 15_000,
    },
  );
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  try {
    if (result.status !== 0 || result.signal !== null || stdout.length === 0) {
      fail("CUSTODY_FAILED", "Release Keychain item is unavailable");
    }
    const text = stdout.toString("ascii").replace(/\n$/u, "");
    if (!/^[A-Za-z0-9_-]{64}$/u.test(text)) {
      fail("CUSTODY_FAILED", "Release Keychain item has an invalid encoding");
    }
    const decoded = Buffer.from(text, "base64url");
    if (decoded.length !== 48 || decoded.toString("base64url") !== text) {
      decoded.fill(0);
      fail("CUSTODY_FAILED", "Release Keychain item has an invalid encoding");
    }
    return decoded;
  } finally {
    stdout.fill(0);
    stderr.fill(0);
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
  const parent = dirname(absolute);
  await guardCanonicalParent(parent, "output");
  const existing = await lstat(absolute).catch(() => null);
  if (existing !== null) fail("OUTPUT_FAILED", "Foundation output already exists");
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
  const parentStats = await lstat(parent, { bigint: true }).catch(() => null);
  const currentUid =
    parentStats === null || typeof process.getuid !== "function"
      ? parentStats?.uid
      : BigInt(process.getuid());
  if (
    parentStats === null ||
    !parentStats.isDirectory() ||
    parentStats.isSymbolicLink() ||
    parentStats.uid !== currentUid ||
    (Number(parentStats.mode) & 0o077) !== 0 ||
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
    device: parentStats.dev,
    inode: parentStats.ino,
    mode: Number(parentStats.mode) & 0o777,
    path: parent,
    uid: parentStats.uid,
  });
}

async function readUniqueOwnerFile(
  path: string,
  maxBytes: number,
  parent: DirectoryGuard,
): Promise<Buffer> {
  const before = await lstat(path);
  if (before.size <= 0 || before.size > maxBytes) {
    fail("INPUT_INVALID", "Foundation evidence file size is invalid");
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.nlink !== 1
    ) {
      fail("INPUT_INVALID", "Foundation evidence file changed during open");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size) {
      bytes.fill(0);
      fail("INPUT_INVALID", "Foundation evidence file changed while reading");
    }
    await assertDirectoryGuard(parent);
    return bytes;
  } finally {
    await handle.close();
  }
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

async function removeMatchingFile(path: string, expected: BigIntStats): Promise<void> {
  const current = await lstat(path, { bigint: true }).catch(() => undefined);
  if (current !== undefined && sameFile(current, expected)) {
    await unlink(path).catch(() => undefined);
  }
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
  } catch (error) {
    if (!isErrno(error, "EINVAL") && !isErrno(error, "ENOTSUP") && !isErrno(error, "EBADF")) {
      fail("OUTPUT_FAILED", "Foundation receipt directory sync failed");
    }
  } finally {
    await directory?.close().catch(() => undefined);
  }
}

function isErrno(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
