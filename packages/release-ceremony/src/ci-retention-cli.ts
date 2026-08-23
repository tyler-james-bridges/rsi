#!/usr/bin/env node
import { fileURLToPath } from "node:url";

import { canonicalJson, exactArray, validateGitHash } from "./canonical.js";
import {
  parseFoundationCiRunId,
  retainFoundationCiEvidence,
  type FoundationCiRetentionOptions,
} from "./ci-retention.js";
import { FoundationCeremonyError } from "./errors.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

function usage(): string {
  return [
    "Usage:",
    "  pnpm foundation:ci-retain -- --run-id <decimal> --output <absolute .json> --confirm-commit <40-hex>",
    "",
    "Retains unauthenticated public GitHub CI evidence using fixed read-only endpoints.",
  ].join("\n");
}

export function parseCiRetentionCliOptions(
  argsValue: readonly string[],
): FoundationCiRetentionOptions | "help" {
  const rawArgs = exactArray(argsValue, "Foundation CI retention CLI arguments", 7);
  const args = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    return "help";
  }
  if (args.length !== 6) throw new TypeError("invalid argument count");
  const supported = new Set(["--confirm-commit", "--output", "--run-id"]);
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
  return Object.freeze({
    confirmCommit: validateGitHash(values.get("--confirm-commit"), "Confirmed foundation commit"),
    outputPath: values.get("--output")!,
    runId: parseFoundationCiRunId(values.get("--run-id")),
  });
}

async function main(): Promise<void> {
  let options: FoundationCiRetentionOptions | "help";
  try {
    options = parseCiRetentionCliOptions(process.argv.slice(2));
  } catch {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 64;
    return;
  }
  if (options === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const result = await retainFoundationCiEvidence(options, {
    fetch: globalThis.fetch,
    repositoryRoot,
  });
  process.stdout.write(
    `${canonicalJson({
      commitSha: result.evidence.commitSha,
      evidenceSha256: result.sha256,
      outputPath: result.outputPath,
      runId: result.evidence.runId,
      status: "retained-foundation-ci-evidence",
    })}\n`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  void main().catch((error: unknown) => {
    const code = error instanceof FoundationCeremonyError ? error.code : "VERIFICATION_FAILED";
    process.stderr.write(`RSI foundation CI retention refused: ${code}.\n`);
    process.exitCode = 1;
  });
}
