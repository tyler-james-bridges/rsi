#!/usr/bin/env node
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./canonical.js";
import { runFoundationCeremony } from "./ceremony.js";
import { FoundationCeremonyError } from "./errors.js";
import {
  assertCeremonyHostOffline,
  createMacBookKeychainCustody,
  readFoundationCiEvidenceFile,
  readPinnedFoundationReleaseIdentity,
  readFoundationIndependentReviewEvidenceFile,
  readPlatformModel,
  reserveFoundationOutput,
  validateFoundationConclusionDestination,
  validateFoundationDestination,
  validateFoundationReceiptDestination,
  validateFoundationReportDestination,
  validateFoundationTagObjectDestination,
} from "./host.js";
import { collectFoundationReleaseInventory } from "./inventory.js";
import { FOUNDATION_RELEASE_VERSION, type FoundationCeremonyOptions } from "./types.js";
import { readPlatformIdentitySha256 } from "@rsi/release-key-provisioning/native-signing";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

function usage(): string {
  return [
    "Usage:",
    "  pnpm foundation:ceremony -- --ci-evidence <absolute .json> --review-evidence <absolute .review-evidence.json> --output <absolute .rsi-release> --receipt <absolute .receipt.json> --conclusion <absolute .readiness-conclusion.json> --tag-object <absolute .foundation-tag> --report <absolute .ceremony-report.json> --confirm-commit <40-hex> --confirm-release 0.1.0-foundation.1",
    "",
    "MacBook-only, physically offline, create-only foundation signing ceremony.",
    "Uses only the repository-pinned identity and fixed native Keychain helper.",
    "Creates detached tag bytes only; it never writes a Git object, ref, tag, release, or push.",
  ].join("\n");
}

export function parseCliOptions(args: readonly string[]): FoundationCeremonyOptions | "help" {
  const values = new Map<string, string>();
  const supported = new Set([
    "--ci-evidence",
    "--conclusion",
    "--output",
    "--receipt",
    "--review-evidence",
    "--report",
    "--tag-object",
    "--confirm-commit",
    "--confirm-release",
  ]);
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
  if (values.get("--confirm-release") !== FOUNDATION_RELEASE_VERSION) {
    throw new TypeError("invalid release");
  }
  return Object.freeze({
    ciEvidencePath: values.get("--ci-evidence")!,
    conclusionPath: values.get("--conclusion")!,
    confirmCommit: values.get("--confirm-commit")!,
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    destinationPath: values.get("--output")!,
    receiptPath: values.get("--receipt")!,
    reportPath: values.get("--report")!,
    reviewEvidencePath: values.get("--review-evidence")!,
    tagObjectPath: values.get("--tag-object")!,
  });
}

async function main(): Promise<void> {
  let options: FoundationCeremonyOptions | "help";
  try {
    options = parseCliOptions(process.argv.slice(2));
  } catch {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 64;
    return;
  }
  if (options === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const [destinationPath, receiptPath, conclusionPath, tagObjectPath, reportPath] =
    await Promise.all([
      validateFoundationDestination(options.destinationPath, repositoryRoot),
      validateFoundationReceiptDestination(options.receiptPath, repositoryRoot),
      validateFoundationConclusionDestination(options.conclusionPath, repositoryRoot),
      validateFoundationTagObjectDestination(options.tagObjectPath, repositoryRoot),
      validateFoundationReportDestination(options.reportPath, repositoryRoot),
    ]);
  const report = await runFoundationCeremony(
    {
      ...options,
      conclusionPath,
      destinationPath,
      receiptPath,
      reportPath,
      tagObjectPath,
    },
    {
      assertHostOffline: assertCeremonyHostOffline,
      collectInventory: (evidence, createdAt) =>
        collectFoundationReleaseInventory({
          ciEvidence: evidence,
          createdAt,
          mode: "ceremony",
          repositoryRoot,
        }),
      custody: createMacBookKeychainCustody(repositoryRoot),
      now: () => new Date(),
      platformIdentitySha256: readPlatformIdentitySha256,
      platformModel: readPlatformModel,
      readCiEvidence: (path) => readFoundationCiEvidenceFile(path, repositoryRoot),
      readPinnedIdentity: (commitSha) =>
        readPinnedFoundationReleaseIdentity(repositoryRoot, commitSha),
      readReviewEvidence: (path) =>
        readFoundationIndependentReviewEvidenceFile(path, repositoryRoot, options.confirmCommit),
      reserveOutput: (path, suffix) => reserveFoundationOutput(path, repositoryRoot, suffix),
    },
  );
  process.stdout.write(`${canonicalJson(report)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  void main().catch((error: unknown) => {
    const code = error instanceof FoundationCeremonyError ? error.code : "VERIFICATION_FAILED";
    process.stderr.write(`RSI foundation ceremony refused: ${code}.\n`);
    process.exitCode = 1;
  });
}
