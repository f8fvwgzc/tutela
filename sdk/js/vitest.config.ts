import { defineConfig } from "vitest/config";

// Unit tests: a mocked fetch, no network. The integration test against a
// real tutelad has its own config (vitest.integration.config.ts).
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    restoreMocks: true,
  },
});
