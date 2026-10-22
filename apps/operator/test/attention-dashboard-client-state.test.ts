import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import { OPERATOR_DASHBOARD_HTML, OPERATOR_DASHBOARD_JS } from "../src/dashboard-assets.js";

type EventHandler = () => void;
type FetchInit = Readonly<{
  body?: string;
  headers?: Readonly<Record<string, string>>;
  method?: string;
}>;
type FetchCall = Readonly<{ init: FetchInit | undefined; path: string }>;

class FakeClassList {
  readonly values = new Set<string>();

  add(...tokens: string[]): void {
    for (const token of tokens) this.values.add(token);
  }

  remove(...tokens: string[]): void {
    for (const token of tokens) this.values.delete(token);
  }
}

class FakeElement {
  readonly attributes = new Map<string, string>();
  checked = false;
  className = "";
  readonly classList = new FakeClassList();
  readonly children: FakeElement[] = [];
  readonly dataset: Record<string, string> = {};
  disabled = false;
  files: readonly FakeFile[] = [];
  hidden = false;
  parentElement: FakeElement | null = null;
  textContent = "";
  value = "";
  readonly #listeners = new Map<string, EventHandler[]>();

  addEventListener(type: string, handler: EventHandler): void {
    const handlers = this.#listeners.get(type) ?? [];
    handlers.push(handler);
    this.#listeners.set(type, handlers);
  }

  append(...children: FakeElement[]): void {
    this.children.push(...children);
  }

  click(): void {
    if (!this.disabled) this.dispatch("click");
  }

  dispatch(type: string): void {
    for (const handler of this.#listeners.get(type) ?? []) handler();
  }

  replaceChildren(...children: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...children);
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }
}

interface FakeFile {
  readonly size: number;
  text(): Promise<string>;
}

function createFakeDocument(): {
  readonly document: Readonly<{
    addEventListener: (type: string, handler: EventHandler) => void;
    createElement: () => FakeElement;
    dispatchEvent: (event: Readonly<{ type: string }>) => boolean;
    getElementById: (id: string) => FakeElement | null;
    querySelectorAll: (selector: string) => readonly FakeElement[];
  }>;
  readonly elements: ReadonlyMap<string, FakeElement>;
} {
  const elements = new Map<string, FakeElement>();
  const documentListeners = new Map<string, EventHandler[]>();
  for (const match of OPERATOR_DASHBOARD_HTML.matchAll(/\bid="([^"]+)"/g)) {
    const id = match[1];
    if (id !== undefined) elements.set(id, new FakeElement());
  }
  const legacyButtons = [...OPERATOR_DASHBOARD_HTML.matchAll(/data-action="([^"]+)"/g)].map(
    (match) => {
      const button = new FakeElement();
      const action = match[1];
      if (action !== undefined) button.dataset.action = action;
      return button;
    },
  );
  const runtimeButtonBindings: readonly Readonly<{ action: string; id: string }>[] = [
    { id: "runtime-research", action: "runtime-enter-research" },
    { id: "runtime-proposals", action: "runtime-enter-propose-only" },
    { id: "runtime-stop", action: "runtime-stop" },
  ];
  const runtimeButtons = runtimeButtonBindings.map(({ id, action }) => {
    const button = elements.get(id);
    if (button === undefined) throw new Error(`Missing dashboard element ${id}`);
    button.dataset.runtimeAction = action;
    return button;
  });
  const connectionStatus = elements.get("connection-status");
  if (connectionStatus === undefined) throw new Error("Missing connection status");
  connectionStatus.parentElement = new FakeElement();
  const canary = elements.get("canary-panel");
  if (canary === undefined) throw new Error("Missing canary panel");
  canary.hidden = true;

  return {
    elements,
    document: Object.freeze({
      addEventListener: (type: string, handler: EventHandler) => {
        const handlers = documentListeners.get(type) ?? [];
        handlers.push(handler);
        documentListeners.set(type, handlers);
      },
      createElement: () => new FakeElement(),
      dispatchEvent: (event: Readonly<{ type: string }>) => {
        for (const handler of documentListeners.get(event.type) ?? []) handler();
        return true;
      },
      getElementById: (id: string) => elements.get(id) ?? null,
      querySelectorAll: (selector: string) => {
        if (selector === "button[data-action]") return legacyButtons;
        if (selector === "button[data-runtime-action]") return runtimeButtons;
        return [];
      },
    }),
  };
}

function element(elements: ReadonlyMap<string, FakeElement>, id: string): FakeElement {
  const value = elements.get(id);
  if (value === undefined) throw new Error(`Missing dashboard element ${id}`);
  return value;
}

function renderedText(root: FakeElement): string {
  return [root.textContent, ...root.children.map(renderedText)].join(" ");
}

function renderedElements(
  elements: ReadonlyMap<string, FakeElement>,
  ids: readonly string[],
): string {
  return ids.map((id) => renderedText(element(elements, id))).join(" ");
}

function jsonResponse(
  body: unknown,
  ok = true,
): Promise<Readonly<{ ok: boolean; json(): Promise<unknown> }>> {
  return Promise.resolve({ ok, json: () => Promise.resolve(body) });
}

function errorResponse(code: string, message: string): ReturnType<typeof jsonResponse> {
  return jsonResponse({ error: { code, message } }, false);
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
} {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  return {
    promise,
    resolve: (value) => {
      if (resolvePromise === undefined) throw new Error("Deferred promise is unavailable");
      resolvePromise(value);
    },
  };
}

async function flushClientTasks(): Promise<void> {
  for (let index = 0; index < 5; index += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

const PROCESS_ID = "018f102a-8f54-4a93-8cce-2461c4f28a12";
const NEXT_PROCESS_ID = "418f102a-8f54-4a93-8cce-2461c4f28a12";
const HISTORY_ID = "118f102a-8f54-4a93-8cce-2461c4f28a12";
const PREVIEW_ID = "218f102a-8f54-4a93-8cce-2461c4f28a12";
const BUNDLE_ID = "b".repeat(64);
const REFRESH_ID = "c".repeat(64);
const COLLECTION_ID = "d".repeat(64);
const WATCH_COLLECTION_ID = "e".repeat(64);
const CANDIDATE_ID = "f".repeat(64);
const EVIDENCE_ID = "1".repeat(64);
const EVENT_HASH = "2".repeat(64);
const DECISION_HASH = "3".repeat(64);
const START = "2026-10-21T12:00:00.000Z";
const DEADLINE = "2026-10-21T12:00:30.000Z";
const VALID_UNTIL = "2026-10-21T12:02:00.000Z";
const X_VALID_UNTIL = "2026-10-21T14:00:00.000Z";
const CONTRACT_A = `0x${"1".repeat(40)}`;
const CONTRACT_B = `0x${"2".repeat(40)}`;

function runtimeSnapshot(mode: "PROPOSE_ONLY" | "RESEARCH" | "STOPPED", revision = 2) {
  return {
    schemaVersion: 1,
    mode,
    revision,
    modeChangedAt: START,
    processInstanceId: PROCESS_ID,
    auditHead: { sequence: revision, hash: "a".repeat(64) },
    capabilities: {
      researchCollection: mode !== "STOPPED",
      proposalPersistence: mode === "PROPOSE_ONLY",
      policyApproval: false,
      paidRead: false,
      walletSign: false,
      executionAdapter: false,
      transactionBroadcast: false,
      externalPublish: false,
    },
  };
}

function attentionInput(): unknown {
  return {
    schemaVersion: 1,
    kind: "recorded_collection_attention",
    marketplace: {
      kind: "recorded_rank_window",
      acquiredAt: START,
      validUntil: VALID_UNTIL,
      hasNextPage: false,
      candidates: [
        { rank: 1, slug: "alpha", contracts: [{ chainId: "8453", address: CONTRACT_A }] },
      ],
    },
    x: {
      kind: "recorded_posts",
      acquiredAt: START,
      hasNextPage: false,
      posts: [{ id: "999999", text: "<img src=x onerror=alert(1)> raw-x-secret" }],
    },
    base: { kind: "absent" },
  };
}

function binding(auditHead: unknown = null): unknown {
  return {
    schemaVersion: 2,
    kind: "attention_preview_binding",
    policyVersion: "attention-v2",
    historyId: HISTORY_ID,
    previewId: PREVIEW_ID,
    bundleId: BUNDLE_ID,
    refreshId: REFRESH_ID,
    auditHead,
    processInstanceId: PROCESS_ID,
    modeRevision: 2,
    evaluatedAt: START,
    deadline: DEADLINE,
    decisionHash: DECISION_HASH,
  };
}

function scorecard(total: number) {
  return {
    rank: total - 10,
    upwardMovement: 5,
    socialPresence: 5,
    total,
    observedContentClusters: 3,
    countedContentClusters: 1,
  };
}

function sourceSummary() {
  return {
    marketplace: {
      acquiredAt: START,
      validUntil: VALID_UNTIL,
      candidateCount: 3,
      hasNextPage: false,
      usable: true,
      priorUsableWindowId: null,
    },
    x: {
      kind: "observed",
      acquiredAt: START,
      validUntil: X_VALID_UNTIL,
      postCount: 1,
      usableBoundClusterCount: 1,
      hasNextPage: false,
    },
    base: { kind: "absent" },
  };
}

function assessment() {
  const provenance = {
    kind: "operator_supplied_unverified",
    streamId: "recorded-base-v1",
    bundleId: BUNDLE_ID,
  };
  return {
    schemaVersion: 1,
    kind: "collection_attention_assessment",
    policyVersion: "attention-v2",
    streamId: "recorded-base-v1",
    bundleId: BUNDLE_ID,
    refreshId: REFRESH_ID,
    predecessorId: null,
    evaluatedAt: START,
    sourceSummary: sourceSummary(),
    diagnostics: [{ evidenceId: EVIDENCE_ID, code: "UNBOUND_SOCIAL" }],
    rows: [
      {
        rowId: COLLECTION_ID,
        subject: {
          kind: "resolved",
          identity: {
            kind: "base_collection",
            chainId: "8453",
            collectionId: COLLECTION_ID,
            contracts: [CONTRACT_A],
          },
        },
        slug: "alpha",
        presence: { kind: "observed", rank: 1 },
        comparison: { kind: "not_comparable", reason: "first_observation" },
        scorecard: scorecard(40),
        evidenceIds: [EVIDENCE_ID],
        assessedAt: START,
        expiresAt: VALID_UNTIL,
        provenance,
        missingChecks: ["authenticated_provenance", "independent_x_authors"],
        notes: ["AUTHORS_UNKNOWN", "BASE_CONTEXT_ONLY"],
        outcome: { kind: "review", priority: 40 },
        nextAction: "continue_recorded_observation",
      },
      {
        rowId: WATCH_COLLECTION_ID,
        subject: {
          kind: "resolved",
          identity: {
            kind: "base_collection",
            chainId: "8453",
            collectionId: WATCH_COLLECTION_ID,
            contracts: [CONTRACT_B],
          },
        },
        slug: "beta",
        presence: { kind: "observed", rank: 4 },
        comparison: { kind: "comparable", previousRank: 7, delta: 3 },
        scorecard: scorecard(32),
        evidenceIds: [],
        assessedAt: START,
        expiresAt: VALID_UNTIL,
        provenance,
        missingChecks: ["base_head_context"],
        notes: ["BASE_CONTEXT_ONLY"],
        outcome: { kind: "watch", reasons: ["MISSING_X"], priority: 32 },
        nextAction: "supply_bounded_social_evidence",
      },
      {
        rowId: CANDIDATE_ID,
        subject: { kind: "unresolved", candidateId: CANDIDATE_ID },
        slug: "hostile-candidate",
        presence: { kind: "observed", rank: 8 },
        comparison: { kind: "not_comparable", reason: "identity_unresolved" },
        scorecard: scorecard(20),
        evidenceIds: [EVIDENCE_ID],
        assessedAt: START,
        expiresAt: VALID_UNTIL,
        provenance,
        missingChecks: ["collection_contract_checks"],
        notes: ["NO_SAFE_VERDICT"],
        outcome: { kind: "rejected", reasons: ["INSTRUCTION_CONTENT"], priority: null },
        nextAction: "inspect_quarantined_indicators_offline",
      },
    ],
  };
}

function previewResponse(): unknown {
  return {
    preview: {
      schemaVersion: 2,
      kind: "preview",
      binding: binding(),
      assessment: assessment(),
    },
  };
}

function emptyAttentionView(): unknown {
  return {
    schemaVersion: 1,
    kind: "available",
    provenance: "operator_supplied_unverified",
    evaluatedAt: START,
    auditHead: null,
    latest: null,
    rows: [],
    history: [],
  };
}

function recordedAttentionView(): unknown {
  const head = { refreshId: REFRESH_ID, eventHash: EVENT_HASH, sequence: 2 };
  const currentAssessment = assessment();
  return {
    schemaVersion: 1,
    kind: "available",
    provenance: "operator_supplied_unverified",
    evaluatedAt: "2026-10-21T12:03:00.000Z",
    auditHead: head,
    latest: {
      schemaVersion: 2,
      kind: "recorded_attention_result",
      binding: binding(),
      assessment: currentAssessment,
      checkpointAt: "2026-10-21T12:00:10.000Z",
    },
    rows: currentAssessment.rows.map((saved, index) => ({
      saved,
      expired: index === 1,
      effectiveOutcome:
        index === 1
          ? { kind: "watch", reasons: ["ASSESSMENT_EXPIRED"], priority: 0 }
          : saved.outcome,
      effectiveNextAction: index === 1 ? "supply_new_recorded_rank_window" : saved.nextAction,
    })),
    history: [
      {
        head,
        bundleId: BUNDLE_ID,
        predecessorId: null,
        acquiredAt: START,
        validUntil: VALID_UNTIL,
        evaluatedAt: START,
        checkpointAt: "2026-10-21T12:00:10.000Z",
        usableRankWindow: true,
      },
    ],
  };
}

function baseFetch(
  calls: FetchCall[],
  getRuntime: () => unknown,
  getAttention: () => unknown,
  override?: (
    path: string,
    init: FetchInit | undefined,
  ) => ReturnType<typeof jsonResponse> | undefined,
) {
  return (path: string, init?: FetchInit) => {
    calls.push({ path, init });
    const overridden = override?.(path, init);
    if (overridden !== undefined) return overridden;
    if (path === "/api/runtime") return jsonResponse({ runtime: getRuntime() });
    if (path === "/api/attention") return jsonResponse({ attention: getAttention() });
    if (path === "/api/research") {
      return jsonResponse({
        research: { schemaVersion: 1, candidateCount: 0, abstentionCount: 0, proposals: [] },
      });
    }
    if (path === "/api/summary") return jsonResponse({ summary: {} });
    if (path === "/api/events?limit=12") return jsonResponse({ events: [] });
    if (path === "/api/control/capabilities") {
      return jsonResponse({
        controls: {
          legacy: { enabled: false, actions: [] },
          runtime: {
            enabled: true,
            actions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
          },
        },
      });
    }
    if (path === "/api/watchlist") {
      return errorResponse("watchlist_unavailable", "Offline watchlist is not configured.");
    }
    if (path === "/api/read-canary") {
      return errorResponse("read_canary_unavailable", "The X read canary is not configured.");
    }
    return errorResponse("not_found", "Not found.");
  };
}

function runDashboard(
  fetch: (path: string, init?: FetchInit) => ReturnType<typeof jsonResponse>,
  now: { value: number } = { value: Date.parse(START) },
) {
  const { document, elements } = createFakeDocument();
  let nextTimerId = 1;
  const timers = new Map<number, EventHandler>();
  class DashboardDate extends Date {
    static override now(): number {
      return now.value;
    }
  }
  class DashboardEvent {
    constructor(readonly type: string) {}
  }
  runInNewContext(OPERATOR_DASHBOARD_JS, {
    Date: DashboardDate,
    Event: DashboardEvent,
    clearTimeout: (id: number) => timers.delete(id),
    crypto: { randomUUID: () => "318f102a-8f54-4a93-8cce-2461c4f28a12" },
    document,
    fetch,
    setTimeout: (handler: EventHandler) => {
      const id = nextTimerId;
      nextTimerId += 1;
      timers.set(id, handler);
      return id;
    },
  });
  return {
    elements,
    fireTimers: () => {
      const pending = [...timers.values()];
      timers.clear();
      for (const handler of pending) handler();
    },
  };
}

function fileFor(value: unknown, size?: number): FakeFile {
  const source = typeof value === "string" ? value : JSON.stringify(value);
  return { size: size ?? source.length, text: () => Promise.resolve(source) };
}

describe("recorded attention dashboard", () => {
  it("starts with read-only GETs and keeps STOPPED imports disabled", async () => {
    const calls: FetchCall[] = [];
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("STOPPED"),
      () => emptyAttentionView(),
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();

    expect(calls.filter(({ init }) => init?.method === "POST")).toEqual([]);
    expect(calls.filter(({ path }) => path === "/api/attention")).toHaveLength(1);
    expect(element(elements, "attention-preview").disabled).toBe(true);
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(OPERATOR_DASHBOARD_HTML).toContain("operator_supplied_unverified");
    expect(OPERATOR_DASHBOARD_HTML).toContain("do not prove legitimacy, expected return");
    expect(OPERATOR_DASHBOARD_JS).not.toContain("innerHTML");
    expect(element(elements, "watchlist-state").textContent).toContain("unavailable");

    element(elements, "attention-file").files = [fileFor(attentionInput())];
    element(elements, "attention-file").dispatch("change");
    expect(element(elements, "attention-preview").disabled).toBe(true);
  });

  it("previews, renders, and records the exact binding once without raw X material", async () => {
    const calls: FetchCall[] = [];
    let recorded = false;
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("RESEARCH"),
      () => (recorded ? recordedAttentionView() : emptyAttentionView()),
      (path, init) => {
        if (path === "/api/attention/preview") return jsonResponse(previewResponse());
        if (path === "/api/attention/record") {
          recorded = true;
          return jsonResponse({
            result: {
              schemaVersion: 2,
              kind: "recorded_attention_result",
              binding: binding(),
              assessment: assessment(),
              checkpointAt: "2026-10-21T12:00:10.000Z",
            },
          });
        }
        return undefined;
      },
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();

    const input = attentionInput();
    element(elements, "attention-file").files = [fileFor(input)];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();

    expect(element(elements, "attention-record").disabled).toBe(false);
    const previewText = renderedElements(elements, [
      "attention-preview-meta",
      "attention-preview-source",
      "attention-preview-diagnostics",
      "attention-preview-rows",
    ]);
    expect(previewText).toContain("alpha");
    expect(previewText).toContain("Rank attention /40 30");
    expect(previewText).toContain("Attention total /60 40");
    expect(previewText).toContain("rank delta 3 (positive means upward)");
    expect(previewText).toContain("Observed clusters 3");
    expect(previewText).toContain("UNBOUND_SOCIAL");
    expect(previewText).not.toContain("raw-x-secret");
    expect(previewText).not.toContain("999999");

    element(elements, "attention-record").click();
    element(elements, "attention-record").click();
    await flushClientTasks();

    const recordCalls = calls.filter(({ path }) => path === "/api/attention/record");
    expect(recordCalls).toHaveLength(1);
    const recordBody = recordCalls[0]?.init?.body;
    expect(recordBody).toBe(JSON.stringify({ input, expected: binding() }));
    expect(recordBody).not.toContain("authorization");
    expect(recordCalls[0]?.init?.headers).toEqual({
      "content-type": "application/json",
      "x-rsi-operator-request": "1",
    });
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("recorded");

    const durableText = renderedElements(elements, [
      "attention-state",
      "attention-audit",
      "attention-source",
      "attention-diagnostics",
      "attention-rows",
      "attention-history",
    ]);
    expect(durableText).toContain("review");
    expect(durableText).toContain("watch");
    expect(durableText).toContain("rejected");
    expect(durableText).toContain(CONTRACT_A);
    expect(durableText).toContain(CANDIDATE_ID);
    expect(durableText).toContain("ASSESSMENT_EXPIRED");
    expect(durableText).toContain("expired overlay");
    expect(durableText).toContain("supply_new_recorded_rank_window");
    expect(durableText).toContain(EVENT_HASH);
    expect(durableText).not.toContain("raw-x-secret");
    expect(durableText).not.toContain("999999");
  });

  it("treats an exact duplicate as a durable read and never enables Record", async () => {
    const calls: FetchCall[] = [];
    const result = {
      schemaVersion: 2,
      kind: "recorded_attention_result",
      binding: binding(),
      assessment: assessment(),
      checkpointAt: "2026-10-21T12:00:10.000Z",
    };
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("RESEARCH"),
      () => recordedAttentionView(),
      (path) =>
        path === "/api/attention/preview"
          ? jsonResponse({ preview: { schemaVersion: 2, kind: "already_recorded", result } })
          : undefined,
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();
    element(elements, "attention-file").files = [fileFor(attentionInput())];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();

    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("already recorded");
    expect(calls.some(({ path }) => path === "/api/attention/record")).toBe(false);
  });

  it("invalidates the exact preview on file, runtime, head, unavailable, deadline, and clock changes", async () => {
    const now = { value: Date.parse(START) };
    const calls: FetchCall[] = [];
    let currentRuntime = runtimeSnapshot("RESEARCH");
    let currentView = emptyAttentionView();
    const fetch = baseFetch(
      calls,
      () => currentRuntime,
      () => currentView,
      (path, init) => {
        if (path === "/api/attention/preview") return jsonResponse(previewResponse());
        if (path === "/api/control" && init?.method === "POST") {
          currentRuntime = runtimeSnapshot("STOPPED", 3);
          return jsonResponse({ result: currentRuntime });
        }
        return undefined;
      },
    );
    const { elements, fireTimers } = runDashboard(fetch, now);
    await flushClientTasks();
    const file = fileFor(attentionInput());
    element(elements, "attention-file").files = [file];
    element(elements, "attention-file").dispatch("change");

    element(elements, "attention-preview").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(false);
    element(elements, "attention-file").dispatch("change");
    expect(element(elements, "attention-record").disabled).toBe(true);

    element(elements, "attention-preview").click();
    await flushClientTasks();
    element(elements, "runtime-stop").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);

    currentRuntime = runtimeSnapshot("RESEARCH");
    element(elements, "refresh").click();
    await flushClientTasks();
    element(elements, "attention-preview").click();
    await flushClientTasks();
    currentView = recordedAttentionView();
    element(elements, "refresh").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("head changed");

    currentView = emptyAttentionView();
    element(elements, "refresh").click();
    await flushClientTasks();
    element(elements, "attention-preview").click();
    await flushClientTasks();
    now.value = Date.parse(DEADLINE);
    fireTimers();
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("expired");

    now.value = Date.parse(START);
    element(elements, "attention-preview").click();
    await flushClientTasks();
    now.value -= 1;
    element(elements, "refresh").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("clock moved backwards");

    currentView = {
      schemaVersion: 1,
      kind: "unavailable",
      reason: "clock_regressed",
      evaluatedAt: "2026-10-21T11:59:59.999Z",
      latestCheckpointAt: START,
    };
    element(elements, "refresh").click();
    await flushClientTasks();
    expect(element(elements, "attention-status").textContent).toBe("Clock regressed");
    expect(element(elements, "attention-record").disabled).toBe(true);
  });

  it("invalidates previews on runtime revision and process changes", async () => {
    const calls: FetchCall[] = [];
    let currentRuntime = runtimeSnapshot("RESEARCH");
    const fetch = baseFetch(
      calls,
      () => currentRuntime,
      () => emptyAttentionView(),
      (path) => (path === "/api/attention/preview" ? jsonResponse(previewResponse()) : undefined),
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();
    element(elements, "attention-file").files = [fileFor(attentionInput())];
    element(elements, "attention-file").dispatch("change");

    element(elements, "attention-preview").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(false);
    currentRuntime = runtimeSnapshot("RESEARCH", 3);
    element(elements, "refresh").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);

    currentRuntime = runtimeSnapshot("RESEARCH");
    element(elements, "refresh").click();
    await flushClientTasks();
    element(elements, "attention-preview").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(false);
    currentRuntime = { ...runtimeSnapshot("RESEARCH"), processInstanceId: NEXT_PROCESS_ID };
    element(elements, "refresh").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("runtime state changed");
  });

  it("consumes the preview before a failed record and requires a fresh preview", async () => {
    const calls: FetchCall[] = [];
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("RESEARCH"),
      () => emptyAttentionView(),
      (path) => {
        if (path === "/api/attention/preview") return jsonResponse(previewResponse());
        if (path === "/api/attention/record") {
          return errorResponse("attention_preview_expired", "The exact preview expired.");
        }
        return undefined;
      },
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();
    element(elements, "attention-file").files = [fileFor(attentionInput())];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();

    element(elements, "attention-record").click();
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain(
      "Preview the file again before retrying.",
    );
    element(elements, "attention-record").click();
    expect(calls.filter(({ path }) => path === "/api/attention/record")).toHaveLength(1);
  });

  it("rechecks preview expiry when Record is clicked before the deadline timer runs", async () => {
    const now = { value: Date.parse(START) };
    const calls: FetchCall[] = [];
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("RESEARCH"),
      () => emptyAttentionView(),
      (path) => (path === "/api/attention/preview" ? jsonResponse(previewResponse()) : undefined),
    );
    const { elements } = runDashboard(fetch, now);
    await flushClientTasks();
    element(elements, "attention-file").files = [fileFor(attentionInput())];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();

    now.value = Date.parse(DEADLINE);
    element(elements, "attention-record").click();
    await flushClientTasks();
    expect(calls.some(({ path }) => path === "/api/attention/record")).toBe(false);
    expect(element(elements, "attention-record").disabled).toBe(true);
    expect(element(elements, "attention-message").textContent).toContain("preview expired");
  });

  it("ignores stale preview and read responses", async () => {
    const calls: FetchCall[] = [];
    const delayedPreview = deferred<Awaited<ReturnType<typeof jsonResponse>>>();
    const delayedOldRead = deferred<Awaited<ReturnType<typeof jsonResponse>>>();
    const delayedNewRead = deferred<Awaited<ReturnType<typeof jsonResponse>>>();
    let attentionReadCount = 0;
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("RESEARCH"),
      () => emptyAttentionView(),
      (path) => {
        if (path === "/api/attention/preview") return delayedPreview.promise;
        if (path === "/api/attention") {
          attentionReadCount += 1;
          if (attentionReadCount === 1) return jsonResponse({ attention: emptyAttentionView() });
          if (attentionReadCount === 2) return delayedOldRead.promise;
          if (attentionReadCount === 3) return delayedNewRead.promise;
        }
        return undefined;
      },
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();
    element(elements, "attention-file").files = [fileFor(attentionInput())];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();
    element(elements, "attention-file").dispatch("change");
    delayedPreview.resolve(await jsonResponse(previewResponse()));
    await flushClientTasks();
    expect(element(elements, "attention-record").disabled).toBe(true);

    element(elements, "refresh").click();
    element(elements, "refresh").click();
    delayedNewRead.resolve(await jsonResponse({ attention: recordedAttentionView() }));
    await flushClientTasks();
    delayedOldRead.resolve(await jsonResponse({ attention: emptyAttentionView() }));
    await flushClientTasks();
    expect(element(elements, "attention-audit").textContent).toContain(EVENT_HASH);
  });

  it("rejects malformed and oversized local files before an attention request", async () => {
    const calls: FetchCall[] = [];
    const fetch = baseFetch(
      calls,
      () => runtimeSnapshot("RESEARCH"),
      () => emptyAttentionView(),
    );
    const { elements } = runDashboard(fetch);
    await flushClientTasks();

    element(elements, "attention-file").files = [fileFor("{raw-x-secret")];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();
    expect(element(elements, "attention-message").textContent).toBe(
      "Choose a valid recorded attention JSON file.",
    );
    expect(element(elements, "attention-message").textContent).not.toContain("raw-x-secret");

    element(elements, "attention-file").files = [fileFor(attentionInput(), 60_001)];
    element(elements, "attention-file").dispatch("change");
    element(elements, "attention-preview").click();
    await flushClientTasks();
    expect(element(elements, "attention-message").textContent).toContain("60,000 bytes");
    expect(calls.filter(({ path }) => path === "/api/attention/preview")).toHaveLength(0);
  });
});
