import { defineConfig } from "vitest/config";

// The Console's unit tests: jsdom and Testing Library against a fake tutelad
// behind a mocked fetch.
export default defineConfig({
  oxc: {
    jsx: { runtime: "automatic", importSource: "react" },
  },
  test: {
    include: ["test/**/*.test.tsx", "test/**/*.test.ts"],
    environment: "jsdom",
    restoreMocks: true,
  },
});
