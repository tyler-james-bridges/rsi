import { describe, expect, it } from "vitest";

import { RSI_ADAPTER_CATALOG } from "../src/index.js";

describe("adapter catalog", () => {
  it("deep-freezes every manifest at the capability boundary", () => {
    expect(RSI_ADAPTER_CATALOG.find(({ id }) => id === "x.research")?.status).toBe("quarantined");
    expect(
      RSI_ADAPTER_CATALOG.filter(({ id }) => id !== "x.research").every(
        (manifest) => manifest.status === "disabled",
      ),
    ).toBe(true);
    expect(
      RSI_ADAPTER_CATALOG.filter(({ capability }) => capability === "state_changing").every(
        (manifest) => manifest.status === "disabled",
      ),
    ).toBe(true);
    expect(Object.isFrozen(RSI_ADAPTER_CATALOG)).toBe(true);
    expect(RSI_ADAPTER_CATALOG.every(Object.isFrozen)).toBe(true);
    expect(() => {
      (RSI_ADAPTER_CATALOG[0] as { status: string }).status = "approved";
    }).toThrow();
  });
});
