// @vitest-environment jsdom
//
// TM-06: a browser session keeps its tokens in memory only. The whole flow
// runs in jsdom, with every storage API watched.

import { afterEach, describe, expect, it, vi } from "vitest";

import { TutelaClient } from "../src/index.js";
import { fakeFetch, json, jwt, TokenEndpoint } from "./fake.js";

afterEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});

describe("tokens live in memory only (THREAT-MODEL.md TM-06)", () => {
  it("never touches localStorage, sessionStorage, cookies or IndexedDB", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const getItem = vi.spyOn(Storage.prototype, "getItem");
    const cookie = vi.spyOn(document, "cookie", "set");
    const idb = (globalThis as { indexedDB?: { open: (...a: unknown[]) => unknown } }).indexedDB;
    const open = idb === undefined ? undefined : vi.spyOn(idb, "open");

    const tokens = new TokenEndpoint();
    const { fetch, seen } = fakeFetch((req) => {
      if (req.url.pathname === "/tutela/oauth2/token") return tokens.answer(req);
      if (req.url.pathname === "/tutela/v1/whoami") {
        return json(200, { iss: "x", tid: "t", sub: "user:usr_1", kind: "access", rev: 1 });
      }
      if (req.url.pathname === "/tutela/v1/authz/permissions") {
        return json(200, { rev: 1, ui: {}, actions: {}, fields: {} }, { etag: '"r1-00"' });
      }
      return json(200, { assignments: [] });
    });
    let n = 0;
    const client = new TutelaClient({
      // A path of the page's own origin, as behind a product's proxy.
      baseUrl: "/tutela",
      fetch,
      auth: {
        kind: "browser",
        getUpstreamToken: async () => {
          n++;
          return jwt({
            jti: `kc-${n}`,
            exp: Math.floor(Date.now() / 1000) + 600,
            aud: "tutela-authz",
          });
        },
      },
    });
    await client.assignments.page({ scope: { type: "project", id: "p-1" } });
    await client.permissions({
      resource: { type: "project", id: "p-1", path: [{ type: "org", id: "org_1" }] },
    });
    client.session?.signOut();

    expect(setItem).not.toHaveBeenCalled();
    expect(getItem).not.toHaveBeenCalled();
    expect(cookie).not.toHaveBeenCalled();
    if (open !== undefined) expect(open).not.toHaveBeenCalled();
    expect(document.cookie).toBe("");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    // Relative to the page, and never with credentials.
    expect(seen[0]?.url.origin).toBe(window.location.origin);
    expect(seen[0]?.url.pathname).toBe("/tutela/oauth2/token");
  });
});
