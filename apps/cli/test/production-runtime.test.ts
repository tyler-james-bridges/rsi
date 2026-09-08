import { describe, expect, it } from "vitest";

import {
  PRODUCTION_NODE_VERSION,
  PRODUCTION_PNPM_VERSION,
  PRODUCTION_RUNTIME_FAILURE_MESSAGE,
  assertExactProductionRuntime,
} from "../src/production-runtime.js";

const VALID_IDENTITY = Object.freeze({
  nodeVersion: PRODUCTION_NODE_VERSION,
  packageManagerUserAgent: `pnpm/${PRODUCTION_PNPM_VERSION} npm/? node/v${PRODUCTION_NODE_VERSION} darwin arm64`,
});

describe("production runtime assertion", () => {
  it("accepts only the exact reviewed Node and pnpm identity", () => {
    expect(() => assertExactProductionRuntime(VALID_IDENTITY)).not.toThrow();
  });

  it.each([
    { ...VALID_IDENTITY, nodeVersion: "26.7.0" },
    { ...VALID_IDENTITY, packageManagerUserAgent: "pnpm/11.19.0" },
    { ...VALID_IDENTITY, packageManagerUserAgent: "npm/11.20.0 node/v24.19.0" },
    {
      ...VALID_IDENTITY,
      packageManagerUserAgent: "pnpm/11.20.0 pnpm/11.20.0 node/v24.19.0",
    },
  ])("rejects runtime drift without echoing ambient values", (identity) => {
    expect(() => assertExactProductionRuntime(identity)).toThrow(
      PRODUCTION_RUNTIME_FAILURE_MESSAGE.trim(),
    );
    expect(PRODUCTION_RUNTIME_FAILURE_MESSAGE).not.toContain(identity.nodeVersion);
    expect(PRODUCTION_RUNTIME_FAILURE_MESSAGE).not.toContain(identity.packageManagerUserAgent);
  });
});
