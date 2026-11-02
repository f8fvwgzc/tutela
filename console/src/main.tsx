import "@f8fvwgzc/tutela-react/styles.css";
import "./console.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Root } from "./App";
import type { ConsoleConfig, OidcEnv } from "./oidc";

async function start() {
  const root = document.getElementById("root");
  if (root === null) return;
  // Where people sign in comes from tutelad's configuration, never from the page (ADR-0050).
  const res = await fetch("/console/config.json", { credentials: "omit", cache: "no-store" });
  if (!res.ok) {
    root.textContent = "The Console is not set up: tutelad has no Console configuration.";
    return;
  }
  const config = (await res.json()) as ConsoleConfig;
  const env: OidcEnv = {
    fetch: window.fetch.bind(window),
    crypto: window.crypto,
    storage: window.sessionStorage,
    origin: window.location.origin,
    assign: (url) => window.location.assign(url),
  };
  createRoot(root).render(
    <StrictMode>
      <Root config={config} env={env} />
    </StrictMode>,
  );
}

void start();
