import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import { OPERATOR_DASHBOARD_HTML, OPERATOR_DASHBOARD_JS } from "../src/dashboard-assets.js";

type ClickHandler = () => void;

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
  checked = false;
  className = "";
  readonly classList = new FakeClassList();
  readonly children: FakeElement[] = [];
  readonly dataset: Record<string, string> = {};
  disabled = false;
  hidden = false;
  parentElement: FakeElement | null = null;
  textContent = "";
  value = "";
  readonly #listeners = new Map<string, ClickHandler[]>();

  addEventListener(type: string, handler: ClickHandler): void {
    const handlers = this.#listeners.get(type) ?? [];
    handlers.push(handler);
    this.#listeners.set(type, handlers);
  }

  append(...children: FakeElement[]): void {
    this.children.push(...children);
  }

  click(): void {
    if (this.disabled) return;
    this.dispatch("click");
  }

  dispatch(type: string): void {
    for (const handler of this.#listeners.get(type) ?? []) handler();
  }

  replaceChildren(...children: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...children);
  }
}

function createFakeDocument(): {
  readonly elements: ReadonlyMap<string, FakeElement>;
  readonly document: Readonly<{
    createElement: () => FakeElement;
    getElementById: (id: string) => FakeElement | null;
    querySelectorAll: (selector: string) => readonly FakeElement[];
  }>;
} {
  const elements = new Map<string, FakeElement>();
  for (const match of OPERATOR_DASHBOARD_HTML.matchAll(/\bid="([^"]+)"/g)) {
    elements.set(match[1]!, new FakeElement());
  }

  const legacyButtons = [...OPERATOR_DASHBOARD_HTML.matchAll(/data-action="([^"]+)"/g)].map(
    (match) => {
      const button = new FakeElement();
      button.dataset.action = match[1]!;
      return button;
    },
  );
  const runtimeButtons = [
    ["runtime-research", "runtime-enter-research"],
    ["runtime-proposals", "runtime-enter-propose-only"],
    ["runtime-stop", "runtime-stop"],
  ].map(([id, action]) => {
    const button = elements.get(id!)!;
    button.dataset.runtimeAction = action!;
    return button;
  });
  elements.get("connection-status")!.parentElement = new FakeElement();
  elements.get("canary-panel")!.hidden = true;

  return {
    elements,
    document: Object.freeze({
      createElement: () => new FakeElement(),
      getElementById: (id: string) => elements.get(id) ?? null,
      querySelectorAll: (selector: string) => {
        if (selector === "button[data-action]") return legacyButtons;
        if (selector === "button[data-runtime-action]") return runtimeButtons;
        return [];
      },
    }),
  };
}

function runtimeSnapshot(mode: "RESEARCH" | "STOPPED", revision: number): unknown {
  return {
    schemaVersion: 1,
    mode,
    revision,
    modeChangedAt: "2026-08-23T12:00:00.000Z",
    processInstanceId: "018f102a-8f54-4a93-8cce-2461c4f28a12",
    auditHead: { sequence: revision, hash: "a".repeat(64) },
    capabilities: {
      researchCollection: mode !== "STOPPED",
      proposalPersistence: false,
      policyApproval: false,
      paidRead: false,
      walletSign: false,
      executionAdapter: false,
      transactionBroadcast: false,
      externalPublish: false,
    },
  };
}

function readCanaryProjection(): unknown {
  return {
    schemaVersion: 1,
    status: "ready",
    credentialStatus: "configured",
    plan: {
      schemaVersion: 1,
      planId: "x-nft-market-pulse-v1",
      providerId: "x-api-v2",
      operation: "x.recent-search.v1",
      endpoint: "https://api.x.com/2/tweets/search/recent",
      method: "GET",
      sortOrder: "recency",
      maximumRequests: 1,
      maximumResults: 10,
      maximumChargeUsdMicros: "50000",
      requestFingerprint: `sha256:${"d".repeat(64)}`,
      rawContentDisposition: "encrypted_ephemeral",
      automaticRetries: 0,
    },
    lastReceipt: null,
  };
}

async function flushClientTasks(): Promise<void> {
  for (let index = 0; index < 3; index += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

describe("operator dashboard runtime controls", () => {
  it("keeps emergency STOP actionable while a mode-transition request is pending", async () => {
    const { document, elements } = createFakeDocument();
    const commands: Array<Record<string, unknown>> = [];
    const pendingTransition = new Promise<never>(() => undefined);
    let uuidSequence = 0;

    const response = (body: unknown) =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(body),
      });
    const fetch = (path: string, init?: Readonly<{ body?: string; method?: string }>) => {
      if (path === "/api/runtime") return response({ runtime: runtimeSnapshot("STOPPED", 1) });
      if (path === "/api/research") {
        return response({
          research: { schemaVersion: 1, candidateCount: 0, abstentionCount: 0, proposals: [] },
        });
      }
      if (path === "/api/read-canary") {
        return Promise.resolve({
          ok: false,
          json: () =>
            Promise.resolve({
              error: {
                code: "read_canary_unavailable",
                message: "The X read canary is not configured.",
              },
            }),
        });
      }
      if (path === "/api/summary") return response({ summary: {} });
      if (path === "/api/events?limit=12") return response({ events: [] });
      if (path === "/api/control/capabilities") {
        return response({
          controls: {
            legacy: { enabled: false, actions: [] },
            runtime: {
              enabled: true,
              actions: ["runtime-enter-research", "runtime-enter-propose-only", "runtime-stop"],
            },
          },
        });
      }
      if (path === "/api/control" && init?.method === "POST" && init.body !== undefined) {
        const command = JSON.parse(init.body) as Record<string, unknown>;
        commands.push(command);
        if (command.action === "runtime-stop") {
          return response({ result: runtimeSnapshot("STOPPED", 2) });
        }
        return pendingTransition;
      }
      return Promise.reject(new Error(`Unexpected dashboard request: ${path}`));
    };

    runInNewContext(OPERATOR_DASHBOARD_JS, {
      crypto: {
        randomUUID: () => {
          uuidSequence += 1;
          return `${String(uuidSequence).padStart(8, "0")}-0000-4000-8000-000000000000`;
        },
      },
      document,
      fetch,
    });
    await flushClientTasks();

    const research = elements.get("runtime-research")!;
    const proposals = elements.get("runtime-proposals")!;
    const stop = elements.get("runtime-stop")!;
    expect(research.disabled).toBe(false);
    expect(stop.disabled).toBe(false);
    expect(elements.get("canary-panel")!.hidden).toBe(true);

    research.click();
    expect(commands.map(({ action }) => action)).toEqual(["runtime-enter-research"]);
    expect(research.disabled).toBe(true);
    expect(proposals.disabled).toBe(true);
    expect(stop.disabled).toBe(false);

    elements.get("refresh")!.click();
    await flushClientTasks();
    expect(research.disabled).toBe(true);
    expect(stop.disabled).toBe(false);

    stop.click();
    expect(commands.map(({ action }) => action)).toEqual([
      "runtime-enter-research",
      "runtime-stop",
    ]);
    await flushClientTasks();
    expect(research.disabled).toBe(true);
    expect(stop.disabled).toBe(false);
  });

  it("keeps STOP actionable while the one-shot read canary is pending", async () => {
    const { document, elements } = createFakeDocument();
    const canaryCommands: Array<Record<string, unknown>> = [];
    const runtimeCommands: Array<Record<string, unknown>> = [];
    const pendingCanary = new Promise<never>(() => undefined);
    let uuidSequence = 0;

    const response = (body: unknown) =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(body),
      });
    const fetch = (path: string, init?: Readonly<{ body?: string; method?: string }>) => {
      if (path === "/api/runtime") return response({ runtime: runtimeSnapshot("RESEARCH", 2) });
      if (path === "/api/research") {
        return response({
          research: { schemaVersion: 1, candidateCount: 0, abstentionCount: 0, proposals: [] },
        });
      }
      if (path === "/api/read-canary") {
        return response({ readCanary: readCanaryProjection() });
      }
      if (path === "/api/summary") return response({ summary: {} });
      if (path === "/api/events?limit=12") return response({ events: [] });
      if (path === "/api/control/capabilities") {
        return response({
          controls: {
            legacy: { enabled: false, actions: [] },
            runtime: { enabled: true, actions: ["runtime-stop"] },
          },
        });
      }
      if (path === "/api/read-canary/run" && init?.method === "POST" && init.body) {
        canaryCommands.push(JSON.parse(init.body) as Record<string, unknown>);
        return pendingCanary;
      }
      if (path === "/api/control" && init?.method === "POST" && init.body) {
        runtimeCommands.push(JSON.parse(init.body) as Record<string, unknown>);
        return response({ result: runtimeSnapshot("STOPPED", 3) });
      }
      return Promise.reject(new Error(`Unexpected dashboard request: ${path}`));
    };

    runInNewContext(OPERATOR_DASHBOARD_JS, {
      crypto: {
        randomUUID: () => {
          uuidSequence += 1;
          return `${String(uuidSequence).padStart(8, "0")}-0000-4000-8000-000000000000`;
        },
      },
      document,
      fetch,
    });
    await flushClientTasks();

    expect(elements.get("canary-maximum-charge")!.textContent).toBe("$0.05");
    expect(elements.get("canary-actual-charge")!.textContent).toBe("UNKNOWN");

    const planAcknowledgement = elements.get("canary-plan-ack")!;
    planAcknowledgement.value = "x-nft-market-pulse-v1";
    planAcknowledgement.dispatch("input");
    elements.get("canary-one-request-ack")!.checked = true;
    elements.get("canary-one-request-ack")!.dispatch("change");
    elements.get("canary-charge-ack")!.checked = true;
    elements.get("canary-charge-ack")!.dispatch("change");

    const run = elements.get("canary-run")!;
    const stop = elements.get("runtime-stop")!;
    expect(run.disabled).toBe(false);
    expect(stop.disabled).toBe(false);
    run.click();

    expect(run.disabled).toBe(true);
    expect(stop.disabled).toBe(false);
    expect(canaryCommands).toEqual([
      {
        schemaVersion: 1,
        planId: "x-nft-market-pulse-v1",
        expectedRuntimeRevision: 2,
        requestId: "00000001-0000-4000-8000-000000000000",
        typedPlanIdAcknowledgement: "x-nft-market-pulse-v1",
        oneRequestAcknowledgement: true,
        maximumChargeUsdMicrosAcknowledgement: "50000",
      },
    ]);

    stop.click();
    await flushClientTasks();
    expect(runtimeCommands).toEqual([
      {
        action: "runtime-stop",
        requestId: "00000002-0000-4000-8000-000000000000",
      },
    ]);
    expect(stop.disabled).toBe(false);
  });

  it("contains no search expression, credential input, or source-content field", () => {
    expect(OPERATOR_DASHBOARD_HTML).toContain("x-nft-market-pulse-v1");
    expect(OPERATOR_DASHBOARD_HTML).toContain("$0.05");
    expect(OPERATOR_DASHBOARD_HTML).not.toContain("NFT OR OpenSea");
    expect(OPERATOR_DASHBOARD_HTML).not.toMatch(
      /<input[^>]*id="[^"]*(?:token|credential|query)[^"]*"/i,
    );
    expect(OPERATOR_DASHBOARD_JS).not.toContain("NFT OR OpenSea");
  });
});
