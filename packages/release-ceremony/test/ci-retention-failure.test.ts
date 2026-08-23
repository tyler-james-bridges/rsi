import { lstat, mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, describe, expect, it, vi } from "vitest";

const readRetainedEvidence = vi.hoisted(() =>
  vi.fn(async () => {
    throw new Error("synthetic post-fsync verification failure");
  }),
);

vi.mock("../src/host.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/host.js")>();
  return { ...actual, readFoundationCiEvidenceFile: readRetainedEvidence };
});

import { retainFoundationCiEvidence } from "../src/ci-retention.js";

const RUN_ID = "32219360003";
const COMMIT = "d3f1e81183cc13fe51ea85ad21bcc71d31866dee";
const REPOSITORY = "tyler-james-bridges/rsi";
const API_ROOT = `https://api.github.com/repos/${REPOSITORY}`;
const WEB_ROOT = `https://github.com/${REPOSITORY}`;
const API_RUN = `${API_ROOT}/actions/runs/${RUN_ID}`;
const WEB_RUN = `${WEB_ROOT}/actions/runs/${RUN_ID}`;
const REQUIRED_GITLEAKS_STEP_NAMES = [
  "Check out full history without persisted credentials",
  "Install checksum-pinned Gitleaks",
  "Prove scanner detects a synthetic credential",
  "Scan working tree and complete Git history with redaction",
] as const;
const REQUIRED_QUALITY_STEP_NAMES = [
  "Check out full history without persisted credentials",
  "Install exact Node and pnpm releases",
  "Verify runtime pins",
  "Install locked dependencies",
  "Verify action pins",
  "Scan working tree and Git history for secrets",
  "Verify production contract and traceability",
  "Verify format, types, and tests",
  "Verify offline demos",
  "Run Stage A drills with external destinations denied",
  "Audit all dependencies",
  "Reject generated or dirty state",
  "Verify the closed foundation inventory candidate",
] as const;
const roots: string[] = [];

afterEach(async () => {
  readRetainedEvidence.mockClear();
  await Promise.all(roots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("foundation CI evidence fail-stop publication", () => {
  it("preserves an exclusively created file when post-fsync verification is ambiguous", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "rsi-ci-fail-stop-")));
    roots.push(root);
    const repositoryRoot = join(root, "repository");
    const retainedRoot = join(root, "retained");
    const outputPath = join(retainedRoot, "foundation-ci.json");
    await mkdir(repositoryRoot, { mode: 0o700 });
    await mkdir(retainedRoot, { mode: 0o700 });

    await expect(
      retainFoundationCiEvidence(
        { confirmCommit: COMMIT, outputPath, runId: RUN_ID },
        { fetch: githubFetch(), repositoryRoot },
      ),
    ).rejects.toMatchObject({ code: "OUTPUT_FAILED" });

    expect(readRetainedEvidence).toHaveBeenCalledOnce();
    const stats = await lstat(outputPath);
    expect(stats.isFile()).toBe(true);
    expect(stats.mode & 0o777).toBe(0o600);
    expect((await readFile(outputPath)).length).toBeGreaterThan(0);
  });
});

function githubFetch(): typeof globalThis.fetch {
  const repository = {
    full_name: REPOSITORY,
    html_url: WEB_ROOT,
    id: 8675309,
    private: false,
    url: API_ROOT,
  };
  const jobs = [
    job("quality", 4001, "2026-08-19T04:42:27Z"),
    job("gitleaks-history", 4002, "2026-08-19T04:42:29Z"),
  ];
  return vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === API_RUN) {
      return jsonResponse({
        conclusion: "success",
        event: "push",
        head_branch: "main",
        head_repository: repository,
        head_sha: COMMIT,
        html_url: WEB_RUN,
        id: Number(RUN_ID),
        name: "ci",
        path: ".github/workflows/ci.yml",
        repository,
        run_attempt: 1,
        run_started_at: "2026-08-19T04:42:00Z",
        status: "completed",
        updated_at: "2026-08-19T04:42:30Z",
        url: API_RUN,
      });
    }
    if (url === `${API_RUN}/jobs?filter=latest&per_page=100`) {
      return jsonResponse({ jobs, total_count: jobs.length });
    }
    throw new Error("unexpected URL");
  });
}

function job(name: "gitleaks-history" | "quality", id: number, completedAt: string) {
  return {
    completed_at: completedAt,
    conclusion: "success",
    head_branch: "main",
    head_sha: COMMIT,
    html_url: `${WEB_RUN}/job/${id}`,
    id,
    name,
    run_attempt: 1,
    run_id: Number(RUN_ID),
    run_url: API_RUN,
    steps: (name === "quality" ? REQUIRED_QUALITY_STEP_NAMES : REQUIRED_GITLEAKS_STEP_NAMES).map(
      (stepName) => ({ conclusion: "success", name: stepName, status: "completed" }),
    ),
    started_at: "2026-08-19T04:42:10Z",
    status: "completed",
    url: `${API_ROOT}/actions/jobs/${id}`,
    workflow_name: "ci",
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json; charset=utf-8" },
    status: 200,
  });
}
