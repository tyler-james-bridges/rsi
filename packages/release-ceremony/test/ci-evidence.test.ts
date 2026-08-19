import { REQUIRED_TEST_CHECKS } from "@rsi/release-bundle";
import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import {
  deriveCiCheckResultSha256,
  foundationCiEvidenceSha256,
  parseFoundationCiEvidence,
} from "../src/ci-evidence.js";
import { makeCiEvidence } from "./helpers.js";

describe("foundation CI evidence", () => {
  it("normalizes the exact retained main-run evidence and binds every check", () => {
    const evidence = parseFoundationCiEvidence(makeCiEvidence());
    expect(evidence.runId).toBe("32034831276");
    expect(evidence.requiredChecks).toHaveLength(REQUIRED_TEST_CHECKS.length);
    const hashes = evidence.requiredChecks.map(({ name }) =>
      deriveCiCheckResultSha256(evidence, name),
    );
    expect(new Set(hashes).size).toBe(REQUIRED_TEST_CHECKS.length);
    expect(foundationCiEvidenceSha256(evidence)).toMatch(/^[0-9a-f]{64}$/u);
    expect(JSON.parse(canonicalJson(evidence))).toEqual(evidence);
  });

  it.each([
    ["wrong repository", { repository: "attacker/rsi" }],
    ["pull-request event", { event: "pull_request" }],
    ["wrong branch", { branch: "feature" }],
    ["bad run URL", { runUrl: "https://github.com/example/runs/1" }],
    ["noncanonical timestamp", { completedAt: "2026-08-18T00:00:00Z" }],
  ])("rejects %s", (_label, overrides) => {
    expect(() => parseFoundationCiEvidence(makeCiEvidence(overrides as never))).toThrowError(
      expect.objectContaining({ code: expect.any(String) }),
    );
  });

  it("rejects missing, reordered, failed, or extra checks and jobs", () => {
    const base = makeCiEvidence();
    const cases: unknown[] = [
      { ...base, requiredChecks: base.requiredChecks.slice(1) },
      { ...base, requiredChecks: [...base.requiredChecks].reverse() },
      {
        ...base,
        requiredChecks: base.requiredChecks.map((check, index) =>
          index === 0 ? { ...check, outcome: "failed" } : check,
        ),
      },
      { ...base, jobs: [...base.jobs].reverse() },
      { ...base, jobs: [{ conclusion: "failure", name: "gitleaks-history" }, base.jobs[1]] },
      { ...base, extra: true },
    ];
    for (const value of cases) expect(() => parseFoundationCiEvidence(value)).toThrow();
  });

  it("rejects array properties, accessors, and modified prototypes", () => {
    const withProperty = [...makeCiEvidence().requiredChecks];
    Object.defineProperty(withProperty, "hidden", { value: "ignored" });
    expect(() =>
      parseFoundationCiEvidence({ ...makeCiEvidence(), requiredChecks: withProperty }),
    ).toThrow();

    const withAccessor = [...makeCiEvidence().requiredChecks];
    Object.defineProperty(withAccessor, "0", {
      configurable: true,
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    expect(() =>
      parseFoundationCiEvidence({ ...makeCiEvidence(), requiredChecks: withAccessor }),
    ).toThrowError(expect.not.objectContaining({ message: "accessed" }));

    const withPrototype = [...makeCiEvidence().jobs];
    Object.setPrototypeOf(withPrototype, null);
    expect(() => parseFoundationCiEvidence({ ...makeCiEvidence(), jobs: withPrototype })).toThrow();
  });

  it("rejects proxies and accessors before reading their contents", () => {
    const proxy = new Proxy(makeCiEvidence(), {});
    expect(() => parseFoundationCiEvidence(proxy)).toThrow();
    const hostile = makeCiEvidence() as FoundationCiEvidenceV1 & { runId: string };
    Object.defineProperty(hostile, "runId", {
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    expect(() => parseFoundationCiEvidence(hostile)).toThrowError(
      expect.not.objectContaining({ message: "accessed" }),
    );
  });
});

type FoundationCiEvidenceV1 = ReturnType<typeof makeCiEvidence>;
