// A small router over the History API. tutelad answers every page path
// under /console/ with index.html (ADR-0050); this picks the page.

import { useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function notify() {
  for (const l of listeners) l();
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  window.addEventListener("popstate", l);
  return () => {
    listeners.delete(l);
    window.removeEventListener("popstate", l);
  };
}

/** Goes to `to` (a path under /console/, with a query if any). */
export function navigate(to: string, replace = false): void {
  if (!to.startsWith("/console/")) return;
  if (replace) window.history.replaceState(null, "", to);
  else window.history.pushState(null, "", to);
  notify();
}

/** The current path and query. */
export function useLocation(): { path: string; query: URLSearchParams } {
  const href = useSyncExternalStore(
    subscribe,
    () => window.location.pathname + window.location.search,
    () => "/console/",
  );
  const [path = "/console/", search = ""] = href.split("?");
  return { path: path.replace(/\/+$/, "") || "/console", query: new URLSearchParams(search) };
}
