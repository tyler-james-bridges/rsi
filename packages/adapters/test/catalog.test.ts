import { describe, expect, it } from "vitest";

import { RSI_ADAPTER_CATALOG } from "../src/index.js";

describe("disabled adapter catalog", () => {
  it("deep-freezes every manifest at the capability boundary", () => {
    expect(RSI_ADAPTER_CATALOG.every((manifest) => manifest.status === "disabled")).toBe(true);
    expect(Object.isFrozen(RSI_ADAPTER_CATALOG)).toBe(true);
    expect(RSI_ADAPTER_CATALOG.every(Object.isFrozen)).toBe(true);
    expect(() => {
      (RSI_ADAPTER_CATALOG[0] as { status: string }).status = "approved";
    }).toThrow();
  });
});
