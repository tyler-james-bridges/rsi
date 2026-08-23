import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { REQUIRED_TEST_CHECKS } from "@rsi/release-bundle";
import { afterEach, describe, expect, it, vi } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import { retainFoundationCiEvidence } from "../src/ci-retention.js";

const RUN_ID = "32219360003";
const COMMIT = "d3f1e81183cc13fe51ea85ad21bcc71d31866dee";
const API_RUN =
  `https://api.github.com/repos/tyler-james-bridges/rsi/actions/runs/${RUN_ID}` as const;
const WEB_RUN = `https://github.com/tyler-james-bridges/rsi/actions/runs/${RUN_ID}` as const;
const JOBS_URL = `${API_RUN}/jobs?filter=latest&per_page=100` as const;
const REPOSITORY_API = "https://api.github.com/repos/tyler-james-bridges/rsi" as const;
const REPOSITORY_WEB = "https://github.com/tyler-james-bridges/rsi" as const;
const REPOSITORY_ID = 8675309;
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
  vi.useRealTimers();
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("foundation CI evidence retention", () => {
  it("retains canonical evidence from exactly two unauthenticated fixed GitHub reads", async () => {
    const fixture = await makePaths();
    const outputPath = join(fixture.retained, "foundation-ci.json");
    const fetchImplementation = githubFetch(workflowRun(), workflowJobs());

    const retained = await retainFoundationCiEvidence(
      { confirmCommit: COMMIT, outputPath, runId: RUN_ID },
      { fetch: fetchImplementation, repositoryRoot: fixture.repository },
    );

    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(fetchImplementation.mock.calls.map(([url]) => url)).toEqual([API_RUN, JOBS_URL]);
    for (const [, init] of fetchImplementation.mock.calls) {
      expect(init).toMatchObject({
        cache: "no-store",
        credentials: "omit",
        method: "GET",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
      const headers = new Headers(init?.headers);
      expect(headers.has("authorization")).toBe(false);
      expect(headers.get("accept")).toBe("application/vnd.github+json");
    }
    expect(retained.evidence).toMatchObject({
      branch: "main",
      commitSha: COMMIT,
      completedAt: "2026-08-19T04:42:29.000Z",
      event: "push",
      jobs: [
        { conclusion: "success", name: "gitleaks-history" },
        { conclusion: "success", name: "quality" },
      ],
      repository: "tyler-james-bridges/rsi",
      runId: RUN_ID,
      runUrl: WEB_RUN,
      workflow: "ci",
    });
    expect(retained.evidence.requiredChecks).toEqual(
      REQUIRED_TEST_CHECKS.map((name) => ({ name, outcome: "passed" })),
    );
    const text = await readFile(outputPath, "utf8");
    expect(text).toBe(canonicalJson(retained.evidence));
    expect(retained.sha256).toBe(createHash("sha256").update(text).digest("hex"));
    expect((await lstat(outputPath)).mode & 0o777).toBe(0o600);
  });

  it.each([
    ["wrong run id", { id: Number(RUN_ID) + 1 }],
    ["wrong API URL", { url: `${API_RUN}/redirected` }],
    ["wrong web URL", { html_url: `${WEB_RUN}/attempts/1` }],
    ["wrong workflow", { name: "other" }],
    ["wrong workflow path", { path: ".github/workflows/other.yml" }],
    ["wrong event", { event: "workflow_dispatch" }],
    ["wrong branch", { head_branch: "feature" }],
    ["wrong commit", { head_sha: "a".repeat(40) }],
    ["rerun attempt", { run_attempt: 2 }],
    ["incomplete", { status: "in_progress" }],
    ["failed", { conclusion: "failure" }],
    ["invalid completion time", { updated_at: "2026-02-31T04:42:30Z" }],
    ["inverted run times", { run_started_at: "2026-08-19T04:42:31Z" }],
    ["private repository", { repository: publicRepository({ private: true }) }],
    ["wrong repository", { repository: publicRepository({ full_name: "attacker/rsi" }) }],
    ["wrong repository API URL", { repository: publicRepository({ url: `${API_RUN}/repo` }) }],
    ["fork head", { head_repository: publicRepository({ full_name: "attacker/rsi" }) }],
    ["different head repository", { head_repository: publicRepository({ id: 8675310 }) }],
  ])("rejects a %s workflow run", async (_label, override) => {
    const fixture = await makePaths();
    const outputPath = join(fixture.retained, "foundation-ci.json");
    await expect(
      retainFoundationCiEvidence(
        { confirmCommit: COMMIT, outputPath, runId: RUN_ID },
        {
          fetch: githubFetch(workflowRun(override), workflowJobs()),
          repositoryRoot: fixture.repository,
        },
      ),
    ).rejects.toMatchObject({ code: "CI_EVIDENCE_INVALID" });
    await expect(lstat(outputPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each([
    [
      "failed",
      workflowJobs({ jobs: [job("quality", { conclusion: "failure" }), job("gitleaks-history")] }),
    ],
    [
      "extra",
      workflowJobs({
        total_count: 3,
        jobs: [job("quality"), job("gitleaks-history"), job("extra")],
      }),
    ],
    ["duplicate", workflowJobs({ jobs: [job("quality"), job("quality", { id: 4002 })] })],
    [
      "wrong run",
      workflowJobs({
        jobs: [job("quality", { run_id: Number(RUN_ID) + 1 }), job("gitleaks-history")],
      }),
    ],
    [
      "wrong commit",
      workflowJobs({
        jobs: [job("quality", { head_sha: "a".repeat(40) }), job("gitleaks-history")],
      }),
    ],
    [
      "wrong API URL",
      workflowJobs({
        jobs: [job("quality", { url: `${API_RUN}/jobs/4001` }), job("gitleaks-history")],
      }),
    ],
    [
      "wrong web URL",
      workflowJobs({
        jobs: [
          job("quality", { html_url: `${WEB_RUN}/attempts/1/job/4001` }),
          job("gitleaks-history"),
        ],
      }),
    ],
    [
      "rerun attempt",
      workflowJobs({
        jobs: [job("quality", { run_attempt: 2 }), job("gitleaks-history")],
      }),
    ],
    [
      "wrong workflow",
      workflowJobs({
        jobs: [job("quality", { workflow_name: "other" }), job("gitleaks-history")],
      }),
    ],
    [
      "wrong branch",
      workflowJobs({
        jobs: [job("quality", { head_branch: "feature" }), job("gitleaks-history")],
      }),
    ],
    [
      "started before run",
      workflowJobs({
        jobs: [job("quality", { started_at: "2026-08-19T04:41:59Z" }), job("gitleaks-history")],
      }),
    ],
    [
      "completed before start",
      workflowJobs({
        jobs: [
          job("quality", {
            completed_at: "2026-08-19T04:42:09Z",
            started_at: "2026-08-19T04:42:10Z",
          }),
          job("gitleaks-history"),
        ],
      }),
    ],
    [
      "late completion",
      workflowJobs({
        jobs: [job("quality", { completed_at: "2026-08-19T04:42:31Z" }), job("gitleaks-history")],
      }),
    ],
    [
      "successful quality job missing one mandatory step",
      workflowJobs({
        jobs: [
          job("quality", {
            steps: jobSteps("quality").filter(
              (step) => step.name !== "Verify format, types, and tests",
            ),
          }),
          job("gitleaks-history"),
        ],
      }),
    ],
    [
      "failed mandatory quality step",
      workflowJobs({
        jobs: [
          job("quality", {
            steps: jobSteps("quality").map((step) =>
              step.name === "Verify offline demos" ? { ...step, conclusion: "failure" } : step,
            ),
          }),
          job("gitleaks-history"),
        ],
      }),
    ],
    [
      "duplicate mandatory gitleaks step",
      workflowJobs({
        jobs: [
          job("quality"),
          job("gitleaks-history", {
            steps: [
              ...jobSteps("gitleaks-history"),
              successfulStep("Install checksum-pinned Gitleaks"),
            ],
          }),
        ],
      }),
    ],
  ])("rejects a %s job set", async (_label, jobsValue) => {
    const fixture = await makePaths();
    await expect(
      retainFoundationCiEvidence(
        {
          confirmCommit: COMMIT,
          outputPath: join(fixture.retained, "foundation-ci.json"),
          runId: RUN_ID,
        },
        {
          fetch: githubFetch(workflowRun(), jobsValue),
          repositoryRoot: fixture.repository,
        },
      ),
    ).rejects.toMatchObject({ code: "CI_EVIDENCE_INVALID" });
  });

  it("refuses redirects, non-JSON, oversized bodies, and non-success status", async () => {
    const fixture = await makePaths();
    const redirected = jsonResponse(workflowRun());
    Object.defineProperty(redirected, "redirected", { value: true });
    const cases = [
      new Response(null, { status: 302 }),
      redirected,
      new Response("{}", { headers: { "content-type": "text/plain" }, status: 200 }),
      new Response("x".repeat(512 * 1024 + 1), {
        headers: { "content-type": "application/json" },
        status: 200,
      }),
      jsonResponse({ message: "rate limited" }, 403),
    ];
    for (const response of cases) {
      const fetchImplementation = vi.fn(async () => response) as unknown as MockFetch;
      await expect(
        retainFoundationCiEvidence(
          {
            confirmCommit: COMMIT,
            outputPath: join(fixture.retained, `foundation-${response.status}.json`),
            runId: RUN_ID,
          },
          { fetch: fetchImplementation, repositoryRoot: fixture.repository },
        ),
      ).rejects.toMatchObject({ code: "CI_EVIDENCE_INVALID" });
      expect(fetchImplementation).toHaveBeenCalledTimes(1);
    }
  });

  it("aborts a GitHub read at the fixed request deadline", async () => {
    vi.useFakeTimers();
    const fixture = await makePaths();
    const fetchImplementation = vi.fn<typeof globalThis.fetch>(
      async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          });
        }),
    );
    const pending = retainFoundationCiEvidence(
      {
        confirmCommit: COMMIT,
        outputPath: join(fixture.retained, "foundation-ci.json"),
        runId: RUN_ID,
      },
      { fetch: fetchImplementation, repositoryRoot: fixture.repository },
    );
    const refusal = expect(pending).rejects.toMatchObject({ code: "CI_EVIDENCE_INVALID" });
    await vi.advanceTimersByTimeAsync(15_000);
    await refusal;
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
  });

  it("rejects overwrite and symlink targets without changing their contents", async () => {
    const fixture = await makePaths();
    const existing = join(fixture.retained, "existing.json");
    const victim = join(fixture.retained, "victim.json");
    const linked = join(fixture.retained, "linked.json");
    await writeFile(existing, "existing", { mode: 0o600 });
    await writeFile(victim, "victim", { mode: 0o600 });
    await symlink(victim, linked);

    for (const outputPath of [existing, linked]) {
      await expect(
        retainFoundationCiEvidence(
          { confirmCommit: COMMIT, outputPath, runId: RUN_ID },
          {
            fetch: githubFetch(workflowRun(), workflowJobs()),
            repositoryRoot: fixture.repository,
          },
        ),
      ).rejects.toMatchObject({ code: "OUTPUT_FAILED" });
    }
    expect(await readFile(existing, "utf8")).toBe("existing");
    expect(await readFile(victim, "utf8")).toBe("victim");
    expect((await lstat(linked)).isSymbolicLink()).toBe(true);
  });

  it("rejects outputs inside the repository and non-owner-only or symlinked parents", async () => {
    const fixture = await makePaths();
    const openParent = join(fixture.root, "open");
    const linkedParent = join(fixture.root, "linked-parent");
    await mkdir(openParent, { mode: 0o700 });
    await chmod(openParent, 0o755);
    await symlink(fixture.retained, linkedParent);
    const outputs = [
      join(fixture.repository, "inside.json"),
      join(openParent, "open.json"),
      join(linkedParent, "linked.json"),
    ];
    for (const outputPath of outputs) {
      await expect(
        retainFoundationCiEvidence(
          { confirmCommit: COMMIT, outputPath, runId: RUN_ID },
          {
            fetch: githubFetch(workflowRun(), workflowJobs()),
            repositoryRoot: fixture.repository,
          },
        ),
      ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    }
  });

  it("rejects hostile option objects and never contacts GitHub", async () => {
    const fixture = await makePaths();
    const fetchImplementation = vi.fn() as unknown as MockFetch;
    const base = {
      confirmCommit: COMMIT,
      outputPath: join(fixture.retained, "foundation-ci.json"),
      runId: RUN_ID,
    };
    const accessor = { ...base };
    Object.defineProperty(accessor, "outputPath", {
      enumerable: true,
      get() {
        throw new Error("accessed");
      },
    });
    const cases: unknown[] = [
      { ...base, token: "not-accepted" },
      new Proxy(base, {}),
      accessor,
      { ...base, outputPath: "relative.json" },
    ];
    for (const value of cases) {
      await expect(
        retainFoundationCiEvidence(value as never, {
          fetch: fetchImplementation,
          repositoryRoot: fixture.repository,
        }),
      ).rejects.not.toMatchObject({ message: "accessed" });
    }
    await expect(
      retainFoundationCiEvidence(base, {
        fetch: fetchImplementation,
        repositoryRoot: fixture.repository,
        token: "not-accepted",
      } as never),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    expect(fetchImplementation).not.toHaveBeenCalled();
  });
});

type MockFetch = ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

async function makePaths(): Promise<{
  readonly repository: string;
  readonly retained: string;
  readonly root: string;
}> {
  const created = await mkdtemp(join(tmpdir(), "rsi-ci-retention-"));
  const root = await realpath(created);
  roots.push(root);
  const repository = join(root, "repository");
  const retained = join(root, "retained");
  await mkdir(repository, { mode: 0o700 });
  await mkdir(retained, { mode: 0o700 });
  return { repository, retained, root };
}

function publicRepository(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    full_name: "tyler-james-bridges/rsi",
    html_url: REPOSITORY_WEB,
    id: REPOSITORY_ID,
    private: false,
    url: REPOSITORY_API,
    ...overrides,
  };
}

function workflowRun(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    conclusion: "success",
    event: "push",
    head_branch: "main",
    head_repository: publicRepository(),
    head_sha: COMMIT,
    html_url: WEB_RUN,
    id: Number(RUN_ID),
    name: "ci",
    path: ".github/workflows/ci.yml",
    repository: publicRepository(),
    run_attempt: 1,
    run_started_at: "2026-08-19T04:42:00Z",
    status: "completed",
    updated_at: "2026-08-19T04:42:30Z",
    url: API_RUN,
    ...overrides,
  };
}

function job(name: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const id = name === "quality" ? 4001 : 4002;
  return {
    completed_at: name === "quality" ? "2026-08-19T04:42:27Z" : "2026-08-19T04:42:29Z",
    conclusion: "success",
    head_branch: "main",
    head_sha: COMMIT,
    html_url: `${WEB_RUN}/job/${id}`,
    id,
    name,
    run_attempt: 1,
    run_id: Number(RUN_ID),
    run_url: API_RUN,
    steps: jobSteps(name),
    started_at: "2026-08-19T04:42:10Z",
    status: "completed",
    url: `${REPOSITORY_API}/actions/jobs/${id}`,
    workflow_name: "ci",
    ...overrides,
  };
}

function jobSteps(name: string): Array<Record<string, unknown>> {
  const requiredNames =
    name === "quality" ? REQUIRED_QUALITY_STEP_NAMES : REQUIRED_GITLEAKS_STEP_NAMES;
  return [
    successfulStep("Set up job"),
    ...requiredNames.map((stepName) => successfulStep(stepName)),
    successfulStep("Complete job"),
  ];
}

function successfulStep(name: string): Record<string, unknown> {
  return { conclusion: "success", name, status: "completed" };
}

function workflowJobs(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jobs: [job("quality"), job("gitleaks-history")],
    total_count: 2,
    ...overrides,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json; charset=utf-8" },
    status,
  });
}

function githubFetch(run: unknown, jobs: unknown): MockFetch {
  return vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === API_RUN) return jsonResponse(run);
    if (url === JOBS_URL) return jsonResponse(jobs);
    throw new Error("unexpected URL");
  });
}
