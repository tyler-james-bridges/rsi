import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { parseRecordedAttentionBundle } from "../src/index.js";

const SCRIPT_URL = new URL("../../../scripts/demo/recorded-attention-fixture.mjs", import.meta.url);
const SOURCE_FIXTURE_URL = new URL("../fixtures/recorded-mixed.json", import.meta.url);
const EVALUATED_AT = "2026-10-21T12:30:00.000Z";

function dataObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} is not an object`);
  }
  const record: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) record[key] = entry;
  return record;
}

function nestedObject(value: Record<string, unknown>, key: string): Record<string, unknown> {
  return dataObject(value[key], key);
}

function withoutRefreshedTimes(value: unknown): unknown {
  const root = dataObject(value, "fixture");
  const marketplace = nestedObject(root, "marketplace");
  const social = nestedObject(root, "x");
  const base = nestedObject(root, "base");
  return {
    ...root,
    marketplace: { ...marketplace, acquiredAt: "<time>", validUntil: "<time>" },
    x: { ...social, acquiredAt: "<time>" },
    base: { ...base, acquiredAt: "<time>", blockTimestamp: "<time>" },
  };
}

function runFixture(...arguments_: string[]) {
  return spawnSync(process.execPath, [SCRIPT_URL.pathname, ...arguments_], {
    encoding: "utf8",
  });
}

describe("recorded attention demo fixture", () => {
  it("emits strict loadable input and changes only source timestamps", () => {
    const first = runFixture("--evaluated-at", EVALUATED_AT);
    const second = runFixture("--evaluated-at", EVALUATED_AT);
    const pnpmStyle = runFixture("--", "--evaluated-at", EVALUATED_AT);
    const source: unknown = JSON.parse(readFileSync(SOURCE_FIXTURE_URL, "utf8"));
    const output: unknown = JSON.parse(first.stdout);
    const parsed = parseRecordedAttentionBundle(output);
    if (parsed.x.kind !== "recorded_posts" || parsed.base.kind !== "reported_finalized_head") {
      throw new TypeError("mixed fixture sources are absent");
    }

    expect(first.status).toBe(0);
    expect(first.stderr).toBe("");
    expect(second.stdout).toBe(first.stdout);
    expect(pnpmStyle.stdout).toBe(first.stdout);
    expect(parsed.marketplace.acquiredAt).toBe("2026-10-21T12:29:30.000Z");
    expect(parsed.marketplace.validUntil).toBe("2026-10-21T12:31:30.000Z");
    expect(parsed.x.acquiredAt).toBe("2026-10-21T12:29:40.000Z");
    expect(parsed.base.acquiredAt).toBe("2026-10-21T12:29:50.000Z");
    expect(parsed.base.blockTimestamp).toBe("2026-10-21T12:29:45.000Z");
    expect(withoutRefreshedTimes(parsed)).toEqual(withoutRefreshedTimes(source));
  });

  it("writes no JSON for invalid arguments and contains no network client", () => {
    const invalid = runFixture("--evaluated-at", "not-a-time");
    const source = readFileSync(SCRIPT_URL, "utf8");

    expect(invalid.status).toBe(2);
    expect(invalid.stdout).toBe("");
    expect(invalid.stderr).toContain("Usage:");
    expect(source).not.toMatch(/\bfetch\b|node:https?|https?:\/\//u);
  });
});
