import { resolve } from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@rsi/backup": resolve(import.meta.dirname, "../backup/src/index.ts"),
      "@rsi/event-archive": resolve(import.meta.dirname, "../event-archive/src/index.ts"),
      "@rsi/release-bundle": resolve(import.meta.dirname, "../release-bundle/src/index.ts"),
      "@rsi/session-lifecycle": resolve(import.meta.dirname, "../session-lifecycle/src/index.ts"),
      "@rsi/store": resolve(import.meta.dirname, "../store/src/index.ts"),
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 20_000,
  },
});
