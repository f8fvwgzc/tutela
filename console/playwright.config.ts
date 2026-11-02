import { defineConfig, devices } from "@playwright/test";

// The Phase B exit check (ADR-0053). `crates/tutelad/tests/console_e2e.rs`
// starts the world and runs this with TUTELA_E2E_FIXTURE; `make js-e2e`
// runs that test. Chromium is Playwright's own build 1243 (this version's
// browsers.json); nothing is downloaded here, and a missing browser fails.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    viewport: { width: 1440, height: 900 },
    reducedMotion: "reduce",
    trace: "off",
  },
});
