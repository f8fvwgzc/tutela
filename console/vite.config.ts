import { defineConfig } from "vite";

// The Console is served by tutelad under /console/ (ADR-0050) with a strict
// Content-Security-Policy: no inline script or style, no data: URLs, so
// nothing is inlined and the module preload polyfill stays in the bundle.
export default defineConfig({
  base: "/console/",
  oxc: {
    jsx: { runtime: "automatic", importSource: "react" },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
    target: "es2022",
  },
});
