#!/usr/bin/env node
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./canonical.js";
import { generateReleaseKeyMaterial } from "./envelope.js";
import { ReleaseKeyProvisioningError } from "./errors.js";
import {
  assertHostOffline,
  assertProvisioningRepositoryEligible,
  createNativeKeychainAdapter,
  readFixedProvisioningIntent,
  inspectRecoveryTarget,
  promptRecoveryPassphrase,
  readOptionalPublicFile,
  readPlatformIdentitySha256,
  readPlatformModel,
  readRecoveryEnvelope,
  reverifyRecoveryTargetAfterRemount,
  writePublicFileCreateOnly,
  writeFixedProvisioningIntentCreateOnly,
  writeRecoveryEnvelopeCreateOnly,
} from "./host.js";
import { runReleaseKeyProvisioning } from "./provisioning.js";
import {
  RELEASE_KEYCHAIN_ACCOUNT,
  type ProvisioningMode,
  type ReleaseKeyProvisioningOptions,
} from "./types.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const PUBLIC_IDENTITY_SUFFIX = ".release-public-identity.json";
const RECEIPT_SUFFIX = ".release-key-provisioning-receipt.json";

function usage(): string {
  return [
    "Usage:",
    "  pnpm foundation:key-provision -- --mode <create|resume> --backup-one <absolute encrypted-volume directory> --backup-two <absolute encrypted-volume directory> --public-identity <absolute .release-public-identity.json> --receipt <absolute .release-key-provisioning-receipt.json> --confirm-account release-ed25519-v1 --confirm-copy-count 2",
    "",
    "MacBook-only, offline, create-only release-key provisioning and recovery.",
    "Passphrases are read only from /dev/tty with echo disabled. No key or passphrase argument exists.",
  ].join("\n");
}

export function parseProvisioningCliOptions(
  args: readonly string[],
): ReleaseKeyProvisioningOptions | "help" {
  const supported = new Set([
    "--mode",
    "--backup-one",
    "--backup-two",
    "--public-identity",
    "--receipt",
    "--confirm-account",
    "--confirm-copy-count",
  ]);
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--") continue;
    if (argument === "--help" || argument === "-h") return "help";
    if (argument === undefined || !supported.has(argument) || values.has(argument)) {
      throw new TypeError("unsupported argument");
    }
    const next = args[index + 1];
    if (next === undefined || next.startsWith("--")) throw new TypeError("missing value");
    values.set(argument, next);
    index += 1;
  }
  if (values.size !== supported.size) throw new TypeError("missing argument");
  const mode = values.get("--mode");
  if (
    (mode !== "create" && mode !== "resume") ||
    values.get("--confirm-account") !== RELEASE_KEYCHAIN_ACCOUNT ||
    values.get("--confirm-copy-count") !== "2"
  ) {
    throw new TypeError("invalid confirmation");
  }
  return Object.freeze({
    backupDirectories: Object.freeze([values.get("--backup-one")!, values.get("--backup-two")!] as [
      string,
      string,
    ]),
    confirmAccount: RELEASE_KEYCHAIN_ACCOUNT,
    confirmCopyCount: 2,
    mode: mode as ProvisioningMode,
    publicIdentityPath: values.get("--public-identity")!,
    receiptPath: values.get("--receipt")!,
  });
}

async function main(): Promise<void> {
  let options: ReleaseKeyProvisioningOptions | "help";
  try {
    options = parseProvisioningCliOptions(process.argv.slice(2));
  } catch {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 64;
    return;
  }
  if (options === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const keychain = createNativeKeychainAdapter(repositoryRoot);
  try {
    const report = await runReleaseKeyProvisioning(options, {
      assertHostOffline,
      assertRepositoryEligible: (helperEvidence) =>
        assertProvisioningRepositoryEligible(repositoryRoot, helperEvidence),
      generateKeyMaterial: generateReleaseKeyMaterial,
      inspectRecoveryTarget,
      keychain,
      now: () => new Date(),
      passphrase: promptRecoveryPassphrase,
      platformIdentitySha256: readPlatformIdentitySha256,
      platformModel: readPlatformModel,
      readEnvelope: readRecoveryEnvelope,
      readIntent: () => readFixedProvisioningIntent(repositoryRoot),
      readPublicIdentity: (path) =>
        readOptionalPublicFile(path, repositoryRoot, PUBLIC_IDENTITY_SUFFIX),
      readReceipt: (path) => readOptionalPublicFile(path, repositoryRoot, RECEIPT_SUFFIX),
      reverifyRecoveryTargetAfterRemount,
      writeEnvelopeCreateOnly: writeRecoveryEnvelopeCreateOnly,
      writeIntentCreateOnly: (bytes) =>
        writeFixedProvisioningIntentCreateOnly(repositoryRoot, bytes),
      writePublicIdentityCreateOnly: (path, bytes) =>
        writePublicFileCreateOnly(path, repositoryRoot, PUBLIC_IDENTITY_SUFFIX, bytes),
      writeReceiptCreateOnly: (path, bytes) =>
        writePublicFileCreateOnly(path, repositoryRoot, RECEIPT_SUFFIX, bytes),
    });
    process.stdout.write(`${canonicalJson(report)}\n`);
  } finally {
    await keychain.dispose();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  void main().catch((error: unknown) => {
    const code = error instanceof ReleaseKeyProvisioningError ? error.code : "VERIFICATION_FAILED";
    process.stderr.write(`RSI release-key provisioning refused: ${code}.\n`);
    process.exitCode = 1;
  });
}
