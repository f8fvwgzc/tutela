import { defineConfig } from "vitest/config";

// Component tests in jsdom with Testing Library; fetch is mocked.
export default defineConfig({
  test: {
    include: ["test/**/*.test.tsx", "test/**/*.test.ts"],
    environment: "jsdom",
    restoreMocks: true,
  },
});
