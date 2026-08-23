#!/usr/bin/env node
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, exactArray, validateGitHash } from "./canonical.js";
import { FoundationCeremonyError } from "./errors.js";
import { FOUNDATION_RELEASE_VERSION } from "./types.js";
import {
  verifyFoundationCeremonyOutputs,
  type FoundationCeremonyVerificationOptions,
} from "./verification.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

function usage(): string {
  return [
    "Usage:",
    "  pnpm foundation:verify -- --bundle <absolute .rsi-release> --receipt <absolute .receipt.json> --conclusion <absolute .readiness-conclusion.json> --tag-object <absolute .foundation-tag> --report <absolute .ceremony-report.json> --ci-evidence <absolute .json> --review-evidence <absolute .review-evidence.json> --confirm-commit <40-hex> --confirm-release 0.1.0-foundation.1",
    "",
    "Read-only independent verification of the complete Foundation ceremony evidence set.",
    "Does not access Keychain, sign, restore, publish, or write Git objects or refs.",
  ].join("\n");
}

export function parseFoundationVerificationCliOptions(
  argsValue: readonly string[],
): FoundationCeremonyVerificationOptions | "help" {
  const rawArgs = exactArray(argsValue, "Foundation verification CLI arguments", 19);
  const args = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) return "help";
  if (args.length !== 18) throw new TypeError("invalid argument count");
  const supported = new Set([
    "--bundle",
    "--ci-evidence",
    "--conclusion",
    "--confirm-commit",
    "--confirm-release",
    "--receipt",
    "--report",
    "--review-evidence",
    "--tag-object",
  ]);
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const argument = args[index];
    const next = args[index + 1];
    if (
      typeof argument !== "string" ||
      !supported.has(argument) ||
      values.has(argument) ||
      typeof next !== "string" ||
      next.length === 0 ||
      next.startsWith("--")
    ) {
      throw new TypeError("unsupported argument");
    }
    values.set(argument, next);
  }
  if (values.size !== supported.size) throw new TypeError("missing argument");
  if (values.get("--confirm-release") !== FOUNDATION_RELEASE_VERSION) {
    throw new TypeError("invalid release");
  }
  const paths = [
    values.get("--bundle")!,
    values.get("--ci-evidence")!,
    values.get("--conclusion")!,
    values.get("--receipt")!,
    values.get("--report")!,
    values.get("--review-evidence")!,
    values.get("--tag-object")!,
  ];
  if (
    paths.some(
      (path) =>
        !isAbsolute(path) ||
        resolve(path) !== path ||
        path.length > 1_024 ||
        /[\u0000-\u001f\u007f]/u.test(path),
    ) ||
    new Set(paths).size !== paths.length
  ) {
    throw new TypeError("invalid path");
  }
  return Object.freeze({
    archivePath: values.get("--bundle")!,
    ciEvidencePath: values.get("--ci-evidence")!,
    conclusionPath: values.get("--conclusion")!,
    confirmCommit: validateGitHash(values.get("--confirm-commit"), "Confirmed foundation commit"),
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    receiptPath: values.get("--receipt")!,
    reportPath: values.get("--report")!,
    reviewEvidencePath: values.get("--review-evidence")!,
    tagObjectPath: values.get("--tag-object")!,
  });
}

async function main(): Promise<void> {
  let options: FoundationCeremonyVerificationOptions | "help";
  try {
    options = parseFoundationVerificationCliOptions(process.argv.slice(2));
  } catch {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 64;
    return;
  }
  if (options === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const report = await verifyFoundationCeremonyOutputs(options, repositoryRoot);
  process.stdout.write(
    `${canonicalJson({
      archiveSha256: report.archiveSha256,
      commitSha: report.commitSha,
      gitTreeSha: report.gitTreeSha,
      releaseVersion: report.releaseVersion,
      signerFingerprintSha256: report.signerFingerprintSha256,
      status: "verified-foundation-ceremony-outputs",
      tagGitObjectSha1: report.tagGitObjectSha1,
      tagName: report.tagName,
    })}\n`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  void main().catch((error: unknown) => {
    const code = error instanceof FoundationCeremonyError ? error.code : "VERIFICATION_FAILED";
    process.stderr.write(`RSI foundation ceremony verification refused: ${code}.\n`);
    process.exitCode = 1;
  });
}
