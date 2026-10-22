import { RuntimeConflictError } from "@rsi/runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  startOperatorServer,
  type OperatorAttentionProvider,
  type OperatorSnapshotProvider,
  type RunningOperatorServer,
} from "../src/index.js";

const snapshotProvider: OperatorSnapshotProvider = {
  getSummary: () => ({ status: "ok" }),
  listEvents: () => ({ items: [], nextCursor: null }),
  getDecision: () => null,
};

function controlHeaders(origin: string) {
  return {
    "content-type": "application/json",
    origin,
    "sec-fetch-site": "same-origin",
    "x-rsi-operator-request": "1",
  };
}

describe("operator recorded attention routes", () => {
  let running: RunningOperatorServer;
  let attention: OperatorAttentionProvider;
  const input = { kind: "fixture", value: 1 };
  const binding = { kind: "binding", value: 2 };
  const preview = { kind: "preview", binding, authorization: "must-not-cross-http" };
  const result = { kind: "result", binding, authorization: "must-not-cross-http" };
  const view = { kind: "available", latest: result, authorization: "must-not-cross-http" };

  beforeEach(async () => {
    attention = {
      parsePreviewCommand: vi.fn((value: unknown) => {
        if (JSON.stringify(value) !== JSON.stringify({ input })) throw new TypeError("invalid");
        return { input };
      }),
      parseRecordCommand: vi.fn((value: unknown) => {
        if (JSON.stringify(value) !== JSON.stringify({ input, expected: binding })) {
          throw new TypeError("invalid");
        }
        return { input, expected: binding };
      }),
      projectPreview: vi.fn((value: unknown) => value),
      projectResult: vi.fn((value: unknown) => value),
      projectView: vi.fn((value: unknown) => value),
      previewAttention: vi.fn(() => preview),
      recordAttention: vi.fn(() => result),
      readAttention: vi.fn(() => view),
    };
    running = await startOperatorServer(snapshotProvider, { attention, port: 0 });
  });

  afterEach(async () => {
    await running.close();
    vi.restoreAllMocks();
  });

  it("serves the read view and explicit same-origin preview and record commands", async () => {
    const readResponse = await fetch(`${running.origin}/api/attention`);
    const previewResponse = await fetch(`${running.origin}/api/attention/preview`, {
      method: "POST",
      headers: controlHeaders(running.origin),
      body: JSON.stringify({ input }),
    });
    const recordResponse = await fetch(`${running.origin}/api/attention/record`, {
      method: "POST",
      headers: controlHeaders(running.origin),
      body: JSON.stringify({ input, expected: binding }),
    });

    expect(readResponse.status).toBe(200);
    expect(await readResponse.json()).toEqual({
      attention: { kind: "available", latest: { kind: "result", binding } },
    });
    expect(previewResponse.status).toBe(200);
    expect(await previewResponse.json()).toEqual({ preview: { kind: "preview", binding } });
    expect(recordResponse.status).toBe(200);
    expect(await recordResponse.json()).toEqual({ result: { kind: "result", binding } });
    expect(attention.previewAttention).toHaveBeenCalledWith(input);
    expect(attention.recordAttention).toHaveBeenCalledWith(input, binding);
    expect(attention.projectView).toHaveBeenCalledWith(view);
    expect(attention.projectPreview).toHaveBeenCalledWith(preview);
    expect(attention.projectResult).toHaveBeenCalledWith(result);
    expect(
      JSON.stringify(await (await fetch(`${running.origin}/api/attention`)).json()),
    ).not.toContain("authorization");
  });

  it("rejects malformed, cross-origin, queried, and oversized commands before the provider", async () => {
    const malformed = await fetch(`${running.origin}/api/attention/preview`, {
      method: "POST",
      headers: controlHeaders(running.origin),
      body: JSON.stringify({ input, extra: true }),
    });
    const crossOrigin = await fetch(`${running.origin}/api/attention/preview`, {
      method: "POST",
      headers: controlHeaders("https://attacker.invalid"),
      body: JSON.stringify({ input }),
    });
    const queried = await fetch(`${running.origin}/api/attention/record?retry=1`, {
      method: "POST",
      headers: controlHeaders(running.origin),
      body: JSON.stringify({ input, expected: binding }),
    });
    const oversized = await fetch(`${running.origin}/api/attention/preview`, {
      method: "POST",
      headers: controlHeaders(running.origin),
      body: JSON.stringify({ input, padding: "x".repeat(65_536) }),
    });

    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ error: { code: "invalid_request" } });
    expect(crossOrigin.status).toBe(403);
    expect(await crossOrigin.json()).toMatchObject({ error: { code: "control_origin_rejected" } });
    expect(queried.status).toBe(400);
    expect(await queried.json()).toMatchObject({ error: { code: "invalid_request" } });
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toMatchObject({ error: { code: "request_too_large" } });
    expect(attention.previewAttention).not.toHaveBeenCalled();
    expect(attention.recordAttention).not.toHaveBeenCalled();
  });

  it("maps recoverable conflicts to a generic 409 without reflecting provider text", async () => {
    vi.mocked(attention.previewAttention).mockImplementationOnce(() => {
      throw new RuntimeConflictError("STALE_STATE", "hostile raw text must stay private");
    });

    const response = await fetch(`${running.origin}/api/attention/preview`, {
      method: "POST",
      headers: controlHeaders(running.origin),
      body: JSON.stringify({ input }),
    });
    const body = await response.json();

    expect(response.status).toBe(409);
    expect(body).toEqual({
      error: {
        code: "runtime_conflict",
        message: "Runtime mode changed; refresh and try again.",
      },
    });
    expect(JSON.stringify(body)).not.toContain("hostile raw text");
  });

  it("returns generic server errors when strict output projection fails", async () => {
    vi.mocked(attention.projectView).mockImplementationOnce(() => {
      throw new TypeError("untrusted output detail");
    });

    const response = await fetch(`${running.origin}/api/attention`);
    const body = await response.json();

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: { code: "internal_error", message: "The operator snapshot could not be read." },
    });
    expect(JSON.stringify(body)).not.toContain("untrusted output detail");
  });

  it("returns closed unavailable and method responses", async () => {
    await running.close();
    running = await startOperatorServer(snapshotProvider, { port: 0 });

    const unavailable = await fetch(`${running.origin}/api/attention`);
    const wrongMethod = await fetch(`${running.origin}/api/attention/preview`);

    expect(unavailable.status).toBe(501);
    expect(await unavailable.json()).toMatchObject({ error: { code: "attention_unavailable" } });
    expect(wrongMethod.status).toBe(405);
    expect(await wrongMethod.json()).toMatchObject({ error: { code: "method_not_allowed" } });
  });
});
