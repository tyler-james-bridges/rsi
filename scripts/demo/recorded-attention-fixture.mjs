import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const FIXTURE_URL = new URL(
  "../../packages/attention/fixtures/recorded-mixed.json",
  import.meta.url,
);

function canonicalTime(value) {
  if (typeof value !== "string") throw new TypeError("evaluated_at_invalid");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError("evaluated_at_invalid");
  }
  return milliseconds;
}

function timestamp(milliseconds, offset) {
  return new Date(milliseconds + offset).toISOString();
}

export function recordedAttentionDemoFixture(evaluatedAt) {
  const evaluatedMilliseconds = canonicalTime(evaluatedAt);
  const fixture = JSON.parse(readFileSync(FIXTURE_URL, "utf8"));
  return {
    ...fixture,
    marketplace: {
      ...fixture.marketplace,
      acquiredAt: timestamp(evaluatedMilliseconds, -30_000),
      validUntil: timestamp(evaluatedMilliseconds, 90_000),
    },
    x: {
      ...fixture.x,
      acquiredAt: timestamp(evaluatedMilliseconds, -20_000),
    },
    base: {
      ...fixture.base,
      acquiredAt: timestamp(evaluatedMilliseconds, -10_000),
      blockTimestamp: timestamp(evaluatedMilliseconds, -15_000),
    },
  };
}

function evaluatedAtArgument(arguments_) {
  const values = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (values.length === 0) return new Date().toISOString();
  if (values.length === 2 && values[0] === "--evaluated-at") return values[1];
  throw new TypeError("usage_invalid");
}

function isMainModule() {
  const entry = process.argv[1];
  return entry !== undefined && pathToFileURL(resolve(entry)).href === import.meta.url;
}

if (isMainModule()) {
  try {
    const evaluatedAt = evaluatedAtArgument(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(recordedAttentionDemoFixture(evaluatedAt), null, 2)}\n`);
  } catch {
    process.stderr.write(
      `Usage: ${fileURLToPath(import.meta.url)} [--evaluated-at YYYY-MM-DDTHH:mm:ss.sssZ]\n`,
    );
    process.exitCode = 2;
  }
}
