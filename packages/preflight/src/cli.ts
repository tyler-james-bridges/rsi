#!/usr/bin/env node
import { resolve } from "node:path";

import { DarwinReadOnlyProbeHost } from "./host.js";
import { runPreflight } from "./preflight.js";
import type { PreflightProfile, PreflightReport } from "./types.js";

interface CliOptions {
  readonly profile: PreflightProfile;
  readonly json: boolean;
}

function usage(): string {
  return [
    "Usage: pnpm preflight -- --profile <dev|canary|production-observer> [--json]",
    "",
    "The shorthand observer is normalized to production-observer.",
    "Reports read-only host facts. It never changes macOS settings or reads credential values.",
  ].join("\n");
}

function normalizeProfile(candidate: string | undefined): PreflightProfile | null {
  if (candidate === "observer") return "production-observer";
  if (candidate === "dev" || candidate === "canary" || candidate === "production-observer") {
    return candidate;
  }
  return null;
}

function parseOptions(args: readonly string[]): CliOptions | "help" {
  let profile: PreflightProfile | undefined;
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (value === "--") continue;
    if (value === "--help" || value === "-h") return "help";
    if (value === "--json") {
      json = true;
      continue;
    }
    if (value === "--profile") {
      const candidate = args[index + 1];
      const normalized = normalizeProfile(candidate);
      if (normalized === null) throw new TypeError("invalid profile");
      profile = normalized;
      index += 1;
      continue;
    }
    throw new TypeError("unsupported argument");
  }
  if (profile === undefined) throw new TypeError("profile is required");
  return Object.freeze({ profile, json });
}

function pnpmVersionFromUserAgent(userAgent: string | undefined): string | null {
  const match = /(?:^|\s)pnpm\/([^\s]+)/u.exec(userAgent ?? "");
  return match?.[1] ?? null;
}

function renderHuman(report: PreflightReport): string {
  const lines = [
    `RSI preflight ${report.profile}: ${report.ready ? "READY" : "NOT READY"}`,
    `Observed: ${report.observedAt}`,
  ];
  for (const item of report.observations) {
    lines.push(`${item.status.toUpperCase().padEnd(7)} ${item.checkId}: ${item.summary}`);
  }
  lines.push(
    `Counts: ${report.counts.pass} pass, ${report.counts.warn} warn, ${report.counts.fail} fail, ${report.counts.unknown} unknown`,
  );
  return lines.join("\n");
}

async function main(): Promise<void> {
  let options: CliOptions | "help";
  try {
    options = parseOptions(process.argv.slice(2));
  } catch {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 64;
    return;
  }
  if (options === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const report = await runPreflight({
    profile: options.profile,
    host: new DarwinReadOnlyProbeHost({ workingDirectory: resolve(process.cwd()) }),
    observedAt: new Date(),
    runtime: {
      nodeVersion: process.versions.node,
      pnpmVersion: pnpmVersionFromUserAgent(process.env.npm_config_user_agent),
      architecture: process.arch,
    },
  });
  process.stdout.write(options.json ? `${JSON.stringify(report)}\n` : `${renderHuman(report)}\n`);
  process.exitCode = report.ready ? 0 : 2;
}

void main().catch(() => {
  // Do not print exception messages: a platform error can include filesystem or
  // command-output detail that does not belong in a preflight receipt.
  process.stderr.write("RSI preflight could not produce a sanitized report.\n");
  process.exitCode = 70;
});
