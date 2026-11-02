import { defineConfig } from "vitest/config";

// The integration test against a real tutelad. The Rust test
// crates/tutelad/tests/js_client.rs starts the service and runs this config
// with TUTELA_JS_FIXTURE set; `make js-it` runs that test.
export default defineConfig({
  test: {
    include: ["test-integration/**/*.it.ts"],
    environment: "node",
    testTimeout: 30_000,
    fileParallelism: false,
  },
});
