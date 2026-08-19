#!/usr/bin/env node
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./canonical.js";
import { runFoundationCeremony } from "./ceremony.js";
import { FoundationCeremonyError } from "./errors.js";
import {
  createMacBookKeychainCustody,
  readFoundationCiEvidenceFile,
  readPlatformModel,
  removeFoundationOwnedOutput,
  validateFoundationDestination,
  validateFoundationReceiptDestination,
  writeFoundationReceipt,
} from "./host.js";
import { collectFoundationReleaseInventory } from "./inventory.js";
import { FOUNDATION_RELEASE_VERSION, type FoundationCeremonyOptions } from "./types.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

function usage(): string {
  return [
    "Usage:",
    "  pnpm foundation:ceremony -- --ci-evidence <absolute .json> --output <absolute .rsi-release> --receipt <absolute .receipt.json> --confirm-commit <40-hex> --confirm-release 0.1.0-foundation.1",
    "",
    "MacBook-only, offline, create-only foundation signing ceremony.",
    "Reads only the fixed release-signing Keychain alias; no key argument is supported.",
  ].join("\n");
}

export function parseCliOptions(args: readonly string[]): FoundationCeremonyOptions | "help" {
  const values = new Map<string, string>();
  const supported = new Set([
    "--ci-evidence",
    "--output",
    "--receipt",
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
  const release = values.get("--confirm-release");
  if (release !== FOUNDATION_RELEASE_VERSION) throw new TypeError("invalid release");
  return Object.freeze({
    ciEvidencePath: values.get("--ci-evidence")!,
    confirmCommit: values.get("--confirm-commit")!,
    confirmReleaseVersion: FOUNDATION_RELEASE_VERSION,
    destinationPath: values.get("--output")!,
    receiptPath: values.get("--receipt")!,
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
  const destinationPath = await validateFoundationDestination(
    options.destinationPath,
    repositoryRoot,
  );
  const receiptPath = await validateFoundationReceiptDestination(
    options.receiptPath,
    repositoryRoot,
  );
  const report = await runFoundationCeremony(
    { ...options, destinationPath, receiptPath },
    {
      collectInventory: (evidence, createdAt) =>
        collectFoundationReleaseInventory({
          ciEvidence: evidence,
          createdAt,
          mode: "ceremony",
          repositoryRoot,
        }),
      custody: createMacBookKeychainCustody(),
      now: () => new Date(),
      platformModel: readPlatformModel,
      readCiEvidence: (path) => readFoundationCiEvidenceFile(path, repositoryRoot),
      removeOwnOutput: (path, receipt) =>
        removeFoundationOwnedOutput(path, repositoryRoot, receipt),
      writeReceipt: (path, receipt) => writeFoundationReceipt(path, repositoryRoot, receipt),
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
