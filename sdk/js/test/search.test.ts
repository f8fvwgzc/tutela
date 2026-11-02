import { describe, expect, it } from "vitest";

import { ForbiddenError, TutelaClient } from "../src/index.js";
import { fakeFetch, type Handler, json, problem } from "./fake.js";

const BASE = "https://tutela.example.test";
const ME = "user:usr_1";

function service(handler: Handler) {
  const { fetch, seen } = fakeFetch(handler);
  const client = new TutelaClient({
    baseUrl: BASE,
    fetch,
    sleep: async () => undefined,
    auth: { kind: "service", getToken: () => "svc-token" },
  });
  return { client, seen };
}

const whoami = () => json(200, { iss: BASE, tid: "ten_1", sub: ME, kind: "access", rev: 3 });

describe("searchResources", () => {
  it("asks for the caller, walks the pages and stops at an empty token", async () => {
    const { client, seen } = service((req) => {
      if (req.url.pathname === "/v1/whoami") return whoami();
      const body = req.json as { page: { token: string } };
      return body.page.token === ""
        ? json(200, { results: [{ type: "org", id: "org_1" }], page: { next_token: "t2" } })
        : json(200, { results: [{ type: "org", id: "org_2" }], page: { next_token: "" } });
    });
    const found = [];
    for await (const r of client.searchResources({ type: "org", action: "org:read" })) {
      found.push(r.id);
    }
    expect(found).toEqual(["org_1", "org_2"]);
    const asks = seen.filter((s) => s.url.pathname === "/access/v1/search/resource");
    expect(asks).toHaveLength(2);
    expect(asks[0]?.json).toEqual({
      subject: { type: "user", id: ME },
      action: { name: "org:read" },
      resource: { type: "org" },
      page: { token: "", limit: 100 },
    });
    expect(asks[0]?.headers.get("authorization")).toBe("Bearer svc-token");
  });

  it("never loops on a token that does not move", async () => {
    const { client, seen } = service((req) =>
      req.url.pathname === "/v1/whoami"
        ? whoami()
        : json(200, { results: [], page: { next_token: "same" } }),
    );
    const found = [];
    for await (const r of client.searchResources({ type: "org", action: "org:read" })) {
      found.push(r);
    }
    expect(found).toEqual([]);
    expect(seen.filter((s) => s.url.pathname === "/access/v1/search/resource")).toHaveLength(2);
  });

  it("sends the revision of the client's own write, and throws typed errors", async () => {
    const { client, seen } = service((req) => {
      if (req.url.pathname === "/v1/whoami") return whoami();
      return problem(403, "forbidden");
    });
    client.observeRevision(9);
    const walk = async () => {
      for await (const _ of client.searchResources({ type: "org", action: "org:read" })) {
        // nothing
      }
    };
    await expect(walk()).rejects.toBeInstanceOf(ForbiddenError);
    const ask = seen.find((s) => s.url.pathname === "/access/v1/search/resource");
    expect(ask?.json).toMatchObject({ context: { at_least_revision: 9 } });
  });
});
