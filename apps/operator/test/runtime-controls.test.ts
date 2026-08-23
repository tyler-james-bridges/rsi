import { mkdtempSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteRuntimeController } from "@rsi/runtime";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createRuntimeOperatorControls, isRuntimeOperatorControls } from "../src/index.js";

const PROCESS_ID = "018f102a-8f54-4a93-8cce-2461c4f28a12";

describe("persisted runtime operator controls", () => {
  const directories: string[] = [];

  afterEach(async () => {
    await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
  });

  function openController() {
    const directory = mkdtempSync(join(tmpdir(), "rsi-runtime-controls-"));
    directories.push(directory);
    return SqliteRuntimeController.open({
      openedAt: "2026-08-23T12:00:00.000Z",
      path: join(directory, "runtime.sqlite"),
      processInstanceId: PROCESS_ID,
    });
  }

  it("uses a provider-owned clock for stepwise transitions and revision-free stop", () => {
    const controller = openController();
    let now = "2026-08-23T12:01:00.000Z";
    const controls = createRuntimeOperatorControls({ controller, now: () => now });

    expect(isRuntimeOperatorControls(controls)).toBe(true);
    expect(controls.supportedActions).toEqual([
      "runtime-enter-research",
      "runtime-enter-propose-only",
      "runtime-stop",
    ]);
    expect(controls.getRuntimeSnapshot()).toMatchObject({ mode: "STOPPED", revision: 1 });

    const research = controls.executeRuntimeControl({
      action: "runtime-enter-research",
      expectedMode: "STOPPED",
      expectedRevision: 1,
      requestId: "11111111-1111-4111-8111-111111111111",
    });
    expect(research).toMatchObject({
      mode: "RESEARCH",
      modeChangedAt: now,
      revision: 2,
    });

    now = "2026-08-23T12:02:00.000Z";
    const proposals = controls.executeRuntimeControl({
      action: "runtime-enter-propose-only",
      expectedMode: "RESEARCH",
      expectedRevision: 2,
      requestId: "22222222-2222-4222-8222-222222222222",
    });
    expect(proposals).toMatchObject({
      mode: "PROPOSE_ONLY",
      modeChangedAt: now,
      revision: 3,
    });

    now = "2026-08-23T12:03:00.000Z";
    const stopped = controls.executeRuntimeControl({
      action: "runtime-stop",
      requestId: "33333333-3333-4333-8333-333333333333",
    });
    expect(stopped).toMatchObject({ mode: "STOPPED", modeChangedAt: now, revision: 4 });

    now = "2026-08-23T12:04:00.000Z";
    expect(
      controls.executeRuntimeControl({
        action: "runtime-stop",
        requestId: "33333333-3333-4333-8333-333333333333",
      }),
    ).toEqual(stopped);

    controller.close();
  });

  it("rejects copied controls, fake controllers, proxy options, and client clocks", () => {
    const controller = openController();
    const controls = createRuntimeOperatorControls({ controller });

    expect(isRuntimeOperatorControls({ ...controls })).toBe(false);
    expect(isRuntimeOperatorControls(Object.create(controls))).toBe(false);
    const prototypeTrap = vi.fn(() => {
      throw new Error("must not run");
    });
    expect(() =>
      createRuntimeOperatorControls(
        new Proxy({ controller }, { getPrototypeOf: prototypeTrap }) as {
          controller: SqliteRuntimeController;
        },
      ),
    ).toThrow(/options/i);
    expect(prototypeTrap).not.toHaveBeenCalled();
    expect(() =>
      createRuntimeOperatorControls({
        controller: Object.create(SqliteRuntimeController.prototype) as SqliteRuntimeController,
      }),
    ).toThrow(/genuine/i);
    expect(() =>
      createRuntimeOperatorControls({ controller, now: new Proxy(() => "", {}) }),
    ).toThrow(/clock/i);

    controller.close();
  });
});
