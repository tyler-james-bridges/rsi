import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import {
  BASE_RPC_OPERATOR_DASHBOARD_HTML,
  BASE_RPC_OPERATOR_DASHBOARD_JS,
} from "../src/base-rpc-dashboard-assets.js";

type EventHandler = () => void;

class FakeElement {
  checked = false;
  className = "";
  disabled = false;
  parentElement: FakeElement | null = null;
  textContent = "";
  value = "";
  readonly #listeners = new Map<string, EventHandler[]>();

  addEventListener(type: string, handler: EventHandler): void {
    const handlers = this.#listeners.get(type) ?? [];
    handlers.push(handler);
    this.#listeners.set(type, handlers);
  }

  click(): void {
    if (!this.disabled) this.dispatch("click");
  }

  dispatch(type: string): void {
    for (const handler of this.#listeners.get(type) ?? []) handler();
  }
}

function fakeDocument(): {
  readonly elements: ReadonlyMap<string, FakeElement>;
  readonly document: Readonly<{ getElementById(id: string): FakeElement | null }>;
} {
  const elements = new Map<string, FakeElement>();
  for (const match of BASE_RPC_OPERATOR_DASHBOARD_HTML.matchAll(/\bid="([^"]+)"/g)) {
    elements.set(match[1]!, new FakeElement());
  }
  elements.get("connection-status")!.parentElement = new FakeElement();
  return {
    elements,
    document: Object.freeze({ getElementById: (id: string) => elements.get(id) ?? null }),
  };
}

function runtime(mode: "RESEARCH" | "STOPPED", revision: number): unknown {
  return { schemaVersion: 1, mode, revision };
}

function projection(status: "completed" | "ready" = "ready"): Record<string, unknown> {
  return {
    schemaVersion: 1,
    status,
    credentialStatus: "configured",
    plan: {
      schemaVersion: 1,
      planId: "base-mainnet-finalized-anchor-v1",
      profile: "canary",
      method: "POST",
      chain: "base-mainnet",
      blockTag: "finalized",
      rpcMethods: ["eth_chainId", "eth_getBlockByNumber"],
      maximumRequests: 1,
      maximumAnchors: 1,
      ledgerReserveUsdMicros: "1",
      actualChargeUsdMicros: null,
      rawContentDisposition: "encrypted_ephemeral",
      automaticRetries: 0,
      automaticFallback: false,
      paymentAuthority: "none",
      transactionAuthority: "none",
    },
    lastReceipt:
      status === "completed"
        ? {
            schemaVersion: 1,
            planId: "base-mainnet-finalized-anchor-v1",
            outcome: "accepted",
            providerReportedFinalized: true,
            freshnessVerdict: "fresh",
          }
        : null,
  };
}

function response(body: unknown): Promise<Readonly<{ ok: true; json(): Promise<unknown> }>> {
  return Promise.resolve({ ok: true as const, json: () => Promise.resolve(body) });
}

async function flushClientTasks(): Promise<void> {
  for (let index = 0; index < 4; index += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

describe("Base RPC operator dashboard", () => {
  it("requires every acknowledgement and keeps STOP available during the read", async () => {
    const { document, elements } = fakeDocument();
    const canaryCommands: Array<Record<string, unknown>> = [];
    const runtimeCommands: Array<Record<string, unknown>> = [];
    const pendingCanary = new Promise<never>(() => undefined);
    let uuidSequence = 0;

    const fetch = (path: string, init?: Readonly<{ body?: string; method?: string }>) => {
      if (path === "/api/runtime") return response({ runtime: runtime("RESEARCH", 2) });
      if (path === "/api/base-rpc-read-canary") {
        return response({ baseRpcReadCanary: projection() });
      }
      if (path === "/api/control/capabilities") {
        return response({
          controls: {
            runtime: {
              enabled: true,
              actions: ["runtime-enter-research", "runtime-stop"],
            },
          },
        });
      }
      if (path === "/api/base-rpc-read-canary/run" && init?.method === "POST" && init.body) {
        canaryCommands.push(JSON.parse(init.body) as Record<string, unknown>);
        return pendingCanary;
      }
      if (path === "/api/control" && init?.method === "POST" && init.body) {
        runtimeCommands.push(JSON.parse(init.body) as Record<string, unknown>);
        return response({ result: runtime("STOPPED", 3) });
      }
      return Promise.reject(new Error(`Unexpected dashboard request: ${path}`));
    };

    runInNewContext(BASE_RPC_OPERATOR_DASHBOARD_JS, {
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

    const run = elements.get("canary-run")!;
    const stop = elements.get("runtime-stop")!;
    expect(run.disabled).toBe(true);
    expect(stop.disabled).toBe(false);

    elements.get("canary-plan-ack")!.value = "base-mainnet-finalized-anchor-v1";
    elements.get("canary-plan-ack")!.dispatch("input");
    for (const id of [
      "canary-one-request-ack",
      "canary-no-payment-ack",
      "canary-reserve-ack",
      "canary-no-transaction-ack",
    ]) {
      elements.get(id)!.checked = true;
      elements.get(id)!.dispatch("change");
    }
    expect(run.disabled).toBe(true);
    elements.get("canary-finality-ack")!.checked = true;
    elements.get("canary-finality-ack")!.dispatch("change");
    expect(run.disabled).toBe(false);

    run.click();
    expect(run.disabled).toBe(true);
    expect(run.textContent).toBe("Running one-shot read…");
    expect(stop.disabled).toBe(false);
    expect(canaryCommands).toEqual([
      {
        schemaVersion: 1,
        planId: "base-mainnet-finalized-anchor-v1",
        expectedRuntimeRevision: 2,
        requestId: "00000001-0000-4000-8000-000000000000",
        typedPlanIdAcknowledgement: "base-mainnet-finalized-anchor-v1",
        oneRequestAcknowledgement: true,
        nonPaymentReadAcknowledgement: true,
        noTransactionAuthorityAcknowledgement: true,
        finalizedAnchorAcknowledgement: true,
        methodSetAcknowledgement: "eth_chainId[]+eth_getBlockByNumber[finalized,false]",
        ledgerReserveUsdMicrosAcknowledgement: "1",
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

  it("labels provider-reported finality without presenting it as independent proof", async () => {
    const { document, elements } = fakeDocument();
    const fetch = (path: string) => {
      if (path === "/api/runtime") return response({ runtime: runtime("STOPPED", 1) });
      if (path === "/api/base-rpc-read-canary") {
        return response({ baseRpcReadCanary: projection("completed") });
      }
      if (path === "/api/control/capabilities") {
        return response({ controls: { runtime: { enabled: true, actions: ["runtime-stop"] } } });
      }
      return Promise.reject(new Error(`Unexpected dashboard request: ${path}`));
    };
    runInNewContext(BASE_RPC_OPERATOR_DASHBOARD_JS, {
      crypto: { randomUUID: () => "00000001-0000-4000-8000-000000000000" },
      document,
      fetch,
    });
    await flushClientTasks();

    expect(elements.get("canary-last-outcome")!.textContent).toBe("accepted");
    expect(elements.get("canary-freshness")!.textContent).toBe("fresh");
    expect(elements.get("canary-finality")!.textContent).toBe("YES — PROVIDER ASSERTION");
    expect(BASE_RPC_OPERATOR_DASHBOARD_HTML).toContain("not an independent finality proof");
  });

  it("keeps the one-shot button latched after submission while terminal status refreshes", async () => {
    const { document, elements } = fakeDocument();
    const canaryCommands: Array<Record<string, unknown>> = [];
    let projectionReads = 0;
    const delayedProjection = new Promise<never>(() => undefined);
    const fetch = (path: string, init?: Readonly<{ body?: string; method?: string }>) => {
      if (path === "/api/runtime") return response({ runtime: runtime("RESEARCH", 2) });
      if (path === "/api/base-rpc-read-canary") {
        projectionReads += 1;
        return projectionReads === 1
          ? response({ baseRpcReadCanary: projection() })
          : delayedProjection;
      }
      if (path === "/api/control/capabilities") {
        return response({
          controls: {
            runtime: {
              enabled: true,
              actions: ["runtime-enter-research", "runtime-stop"],
            },
          },
        });
      }
      if (path === "/api/base-rpc-read-canary/run" && init?.method === "POST" && init.body) {
        canaryCommands.push(JSON.parse(init.body) as Record<string, unknown>);
        return response({
          result: {
            schemaVersion: 1,
            planId: "base-mainnet-finalized-anchor-v1",
            outcome: "accepted",
            providerReportedFinalized: true,
            freshnessVerdict: "fresh",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected dashboard request: ${path}`));
    };

    runInNewContext(BASE_RPC_OPERATOR_DASHBOARD_JS, {
      crypto: { randomUUID: () => "00000001-0000-4000-8000-000000000000" },
      document,
      fetch,
    });
    await flushClientTasks();

    const run = elements.get("canary-run")!;
    elements.get("canary-plan-ack")!.value = "base-mainnet-finalized-anchor-v1";
    elements.get("canary-plan-ack")!.dispatch("input");
    for (const id of [
      "canary-one-request-ack",
      "canary-no-payment-ack",
      "canary-reserve-ack",
      "canary-no-transaction-ack",
      "canary-finality-ack",
    ]) {
      elements.get(id)!.checked = true;
      elements.get(id)!.dispatch("change");
    }
    expect(run.disabled).toBe(false);

    run.click();
    await flushClientTasks();
    expect(canaryCommands).toHaveLength(1);
    expect(projectionReads).toBe(2);
    expect(run.disabled).toBe(true);

    run.click();
    await flushClientTasks();
    expect(canaryCommands).toHaveLength(1);
  });

  it("contains no credential, identifier, arbitrary method, navigation, wallet, or socket control", () => {
    expect(BASE_RPC_OPERATOR_DASHBOARD_HTML).toContain(
      "<dt>Actual charge</dt><dd>UNKNOWN — PROVIDER ACCOUNT</dd>",
    );
    expect(BASE_RPC_OPERATOR_DASHBOARD_HTML).not.toContain("<dt>Actual charge</dt><dd>NONE</dd>");
    expect(BASE_RPC_OPERATOR_DASHBOARD_HTML).not.toMatch(
      /<input[^>]*(?:credential|api-key|block-number|block-hash|provider-id|rpc-id)/i,
    );
    expect(BASE_RPC_OPERATOR_DASHBOARD_HTML).not.toMatch(/<a\b|<form\b/i);
    expect(BASE_RPC_OPERATOR_DASHBOARD_JS).not.toMatch(
      /WebSocket|window\.open|location\.|eth_sendRawTransaction|wallet_requestPermissions|x402/i,
    );
    expect(BASE_RPC_OPERATOR_DASHBOARD_JS).not.toContain("/api/events");
  });
});
