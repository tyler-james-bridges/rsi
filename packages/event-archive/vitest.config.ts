import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@rsi/store": resolve(import.meta.dirname, "../store/src/index.ts"),
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 20_000,
  },
});
