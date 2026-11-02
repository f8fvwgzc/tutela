import { describe, expect, it } from "vitest";

import {
  type Assignment,
  ConflictError,
  ForbiddenError,
  InvalidRequestError,
  MoveRefusedError,
  NetworkError,
  NotFoundError,
  NotHeldError,
  type ProblemError,
  TutelaClient,
  UnauthorizedError,
  UnavailableError,
} from "../src/index.js";
import { fakeFetch, type Handler, json, problem, type Seen } from "./fake.js";

const BASE = "https://tutela.example.test";
const SCOPE = { type: "project", id: "p-1" };
const ORG = { type: "org", id: "org_1" };
const RESOURCE = { ...SCOPE, path: [ORG] };

function service(
  handler: Handler,
  extra: { maxRetries?: number; maxRetryAfterSecs?: number } = {},
) {
  const { fetch, seen } = fakeFetch(handler);
  const slept: number[] = [];
  const audiences: string[] = [];
  const client = new TutelaClient({
    baseUrl: BASE,
    fetch,
    sleep: async (ms) => {
      slept.push(ms);
    },
    ...extra,
    auth: {
      kind: "service",
      getToken: (a) => {
        audiences.push(a);
        return "svc-token";
      },
    },
  });
  return { client, seen, slept, audiences };
}

const assignment = (id: string): Assignment => ({
  id,
  subject: "user:usr_1",
  role: "reader",
  scope: SCOPE,
});

describe("problem documents become typed errors", () => {
  const cases: [Response, new (...a: never[]) => ProblemError, string][] = [
    [problem(400, "invalid_request", "a field is wrong"), InvalidRequestError, "invalid_request"],
    [problem(401, "invalid_token"), UnauthorizedError, "invalid_token"],
    [problem(403, "forbidden"), ForbiddenError, "forbidden"],
    [problem(403, "unknown_tenant"), ForbiddenError, "unknown_tenant"],
    [problem(404, "not_found"), NotFoundError, "not_found"],
    [problem(409, "exists"), ConflictError, "exists"],
    [problem(409, "version_conflict"), ConflictError, "version_conflict"],
    [problem(413, "invalid_request"), InvalidRequestError, "invalid_request"],
  ];
  for (const [res, type, code] of cases) {
    it(`${res.status} ${code}`, async () => {
      const { client } = service(() => res.clone());
      const err = await client.assignments.page({ scope: SCOPE }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(type);
      expect((err as ProblemError).code).toBe(code);
      expect((err as ProblemError).status).toBe(res.status);
    });
  }

  it("403 not_held carries the counts-only detail as sentences", async () => {
    const { client } = service(() =>
      problem(
        403,
        "not_held",
        "1 user gains write on invoice in 1 scope; 1 user gains read on invoice.amount in 1 scope; the check reached its bound before it could rule out more",
      ),
    );
    const err = await client.assignments
      .assign({ subject: "user:usr_2", role: "approver", scope: SCOPE })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NotHeldError);
    expect(err).toBeInstanceOf(ForbiddenError);
    const e = err as NotHeldError;
    expect(e.gains).toEqual([
      "1 user gains write on invoice in 1 scope",
      "1 user gains read on invoice.amount in 1 scope",
    ]);
    expect(e.incomplete).toBe(true);
  });

  it("403 move_refused names the scopes that wait for an owner", async () => {
    const { client } = service(() =>
      problem(
        403,
        "move_refused",
        "needs_approval: the target is looser; an owner must agree at project:p-2, org:org_1",
      ),
    );
    const err = await client.scopes
      .move({ scope: SCOPE, parent: { type: "project", id: "p-2" } })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MoveRefusedError);
    const e = err as MoveRefusedError;
    expect(e.outcome).toBe("needs_approval");
    expect(e.reason).toBe("the target is looser");
    expect(e.waitingFor).toEqual([
      { type: "project", id: "p-2" },
      { type: "org", id: "org_1" },
    ]);
  });

  it("a refused move with no owner to ask has no waiting scopes", async () => {
    const { client } = service(() => problem(403, "move_refused", "refused: moves_out is none"));
    const e = (await client.scopes
      .move({ scope: SCOPE, parent: ORG })
      .catch((x: unknown) => x)) as MoveRefusedError;
    expect(e.outcome).toBe("refused");
    expect(e.waitingFor).toEqual([]);
  });

  it("keeps the request id, and reads an error body that is not a problem", async () => {
    const { client } = service(
      () => new Response("gateway says no", { status: 502, headers: { "x-request-id": "req-7" } }),
      { maxRetries: 0 },
    );
    const err = (await client.tenant.get().catch((e: unknown) => e)) as ProblemError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err.code).toBe("unavailable");
    expect(err.requestId).toBe("req-7");
  });

  it("a 401 with no body is invalid_token", async () => {
    const { client } = service(
      () => new Response(null, { status: 401, headers: { "www-authenticate": "Bearer" } }),
    );
    const err = (await client.tenant.get().catch((e: unknown) => e)) as ProblemError;
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect(err.code).toBe("invalid_token");
  });

  it("a network failure is a NetworkError with no token in its message", async () => {
    const { client } = service(() => {
      throw new TypeError("connection refused");
    });
    const err = (await client.tenant.get().catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).not.toContain("svc-token");
  });
});

describe("503 and Retry-After", () => {
  it("retries a safe call after Retry-After, at most maxRetries times", async () => {
    let left = 2;
    const { client, seen, slept } = service(() =>
      left-- > 0
        ? problem(503, "stale", undefined, { "retry-after": "2" })
        : json(200, { tid: "ten_1", iss: "x" }),
    );
    await expect(client.tenant.get()).resolves.toMatchObject({ tid: "ten_1" });
    expect(seen).toHaveLength(3);
    expect(slept).toEqual([2000, 2000]);
  });

  it("stops after the bound and throws the 503 with its Retry-After", async () => {
    const { client, seen } = service(() =>
      problem(503, "unavailable", undefined, { "retry-after": "1" }),
    );
    const err = (await client.tenant.get().catch((e: unknown) => e)) as UnavailableError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err.retryAfter).toBe(1);
    expect(seen).toHaveLength(3);
  });

  it("does not wait longer than maxRetryAfterSecs by itself", async () => {
    const { client, seen } = service(() =>
      problem(503, "unavailable", undefined, { "retry-after": "60" }),
    );
    const err = (await client.tenant.get().catch((e: unknown) => e)) as UnavailableError;
    expect(err.retryAfter).toBe(60);
    expect(seen).toHaveLength(1);
  });

  it("never retries a call that could make something twice", async () => {
    const { client, seen } = service(() =>
      problem(503, "unavailable", undefined, { "retry-after": "1" }),
    );
    await expect(client.apps.create("crm")).rejects.toBeInstanceOf(UnavailableError);
    await expect(
      client.webhooks.register({ url: "https://hooks.example.test" }),
    ).rejects.toBeInstanceOf(UnavailableError);
    await expect(client.orgs.create("Legal")).rejects.toBeInstanceOf(UnavailableError);
    await expect(client.models.propose({ source: "version = 1" })).rejects.toBeInstanceOf(
      UnavailableError,
    );
    expect(seen).toHaveLength(4);
  });
});

describe("pages are async iterators over next_after", () => {
  it("walks every page and passes the cursor back as after", async () => {
    const { client, seen } = service((req) => {
      const after = (req.json as { after?: string }).after;
      if (after === undefined)
        return json(200, {
          assignments: [assignment("ra_1"), assignment("ra_2")],
          next_after: "ra_2",
        });
      if (after === "ra_2")
        return json(200, { assignments: [assignment("ra_3")], next_after: "ra_3" });
      return json(200, { assignments: [] });
    });
    const ids: string[] = [];
    for await (const a of client.assignments.list({ scope: SCOPE, limit: 2 })) ids.push(a.id);
    expect(ids).toEqual(["ra_1", "ra_2", "ra_3"]);
    expect(seen.map((s) => (s.json as { after?: string }).after)).toEqual([
      undefined,
      "ra_2",
      "ra_3",
    ]);
    expect(seen.every((s) => (s.json as { limit?: number }).limit === 2)).toBe(true);
  });

  it("stops when a cursor does not move", async () => {
    const { client, seen } = service(() => json(200, { scopes: [], next_after: "same" }));
    const got = [];
    for await (const s of client.scopes.list({ under: ORG })) got.push(s);
    expect(seen).toHaveLength(2);
    expect(seen[0]?.url.searchParams.get("under")).toBe("org:org_1");
  });

  it("puts a principal in the body, never in the URL", async () => {
    const { client, seen } = service(() => json(200, { assignments: [] }));
    await client.assignments.page({ subject: "user:usr_0193a1b2" });
    await client.principals.state("user:usr_0193a1b2");
    await client.groups.addMember("legal", "user:usr_0193a1b2");
    for (const s of seen) expect(s.url.toString()).not.toContain("usr_");
    expect(seen[0]?.json).toEqual({ subject: "user:usr_0193a1b2" });
  });

  it("encodes ids in a path", async () => {
    const { client, seen } = service(() => json(200, { rev: 1 }));
    await client.groups.delete("a/b");
    expect(seen[0]?.url.pathname).toBe("/v1/admin/groups/a%2Fb");
  });
});

describe("the revision of a write", () => {
  it("is sent as at_least_revision on the next permission map", async () => {
    const { client, seen } = service((req) => {
      if (req.url.pathname === "/v1/admin/assignments") {
        return json(200, { assignment: assignment("ra_9"), rev: 42 });
      }
      if (req.url.pathname === "/v1/whoami") {
        return json(200, { iss: "x", tid: "t", sub: "sa:sa_1", kind: "access", rev: 3 });
      }
      return json(200, { rev: 42, ui: {}, actions: { "project:manage_access": true }, fields: {} });
    });
    const revs: number[] = [];
    client.onRevision((r) => revs.push(r));
    await client.assignments.assign({ subject: "user:usr_2", role: "reader", scope: SCOPE });
    expect(client.revision).toBe(42);
    expect(revs).toEqual([42]);
    await client.permissions({ resource: RESOURCE, actions: ["project:manage_access"] });
    const map = seen.find((s) => s.url.pathname === "/v1/authz/permissions");
    expect(map?.json).toMatchObject({
      subject: { type: "sa", id: "sa:sa_1" },
      at_least_revision: 42,
      ui_keys: [],
    });
  });

  it("is kept from every write, never moved back, and not taken from reads", async () => {
    const { client } = service((req) =>
      req.method === "GET"
        ? json(200, { rev: 99, version: 1, roles: [], types: [] })
        : json(200, { rev: 7 }),
    );
    await client.assignments.unassign("ra_1");
    expect(client.revision).toBe(7);
    await client.roles();
    expect(client.revision).toBe(7);
    client.observeRevision(3);
    expect(client.revision).toBe(7);
  });

  it("is sent as context.at_least_revision on explain", async () => {
    const { client, seen } = service((req) =>
      req.url.pathname === "/v1/admin/groups"
        ? json(200, { key: "g", org: "o", name: "G", rev: 5 })
        : json(200, {}),
    );
    await client.groups.create({ org: "org_1", key: "g", name: "G" });
    await client.explain({
      subject: { type: "user", id: "user:usr_1" },
      action: { name: "project:read" },
      resource: { type: "project", id: "p-1", properties: { path: [ORG] } },
    });
    expect(seen[1]?.json).toMatchObject({ context: { at_least_revision: 5 } });
  });
});

describe("the permission map", () => {
  const answer = {
    rev: 4,
    ui: {},
    actions: { "project:manage_access": true, "project:read_audit": false },
    fields: { "project.title": "read" },
  };

  it("sends If-None-Match with the ETag and keeps the map on 304", async () => {
    let n = 0;
    const { client, seen } = service((req) => {
      if (req.url.pathname === "/v1/whoami")
        return json(200, { iss: "x", tid: "t", sub: "user:usr_1", kind: "access", rev: 1 });
      n++;
      return n === 1
        ? json(200, answer, { etag: '"r4-0011223344556677"' })
        : new Response(null, { status: 304 });
    });
    const first = await client.permissions({
      resource: RESOURCE,
      actions: ["project:manage_access", "project:read_audit"],
    });
    const second = await client.permissions({
      resource: RESOURCE,
      actions: ["project:manage_access", "project:read_audit"],
    });
    expect(second).toBe(first);
    const maps = seen.filter((s) => s.url.pathname === "/v1/authz/permissions");
    expect(maps[0]?.headers.get("if-none-match")).toBeNull();
    expect(maps[1]?.headers.get("if-none-match")).toBe('"r4-0011223344556677"');
    // whoami was asked once.
    expect(seen.filter((s) => s.url.pathname === "/v1/whoami")).toHaveLength(1);
  });

  it("answers can() from the loaded maps and false for anything unknown", async () => {
    const { client } = service((req) =>
      req.url.pathname === "/v1/whoami"
        ? json(200, { iss: "x", tid: "t", sub: "user:usr_1", kind: "access", rev: 1 })
        : json(200, answer),
    );
    const map = await client.permissions({
      resource: RESOURCE,
      actions: ["project:manage_access"],
    });
    expect(map.can("project:manage_access")).toBe(true);
    expect(map.can("project:read_audit")).toBe(false);
    expect(map.field("project.title")).toBe("read");
    expect(map.field("project.budget")).toBe("none");
    expect(map.ui("x").mode).toBe("hide");
    expect(client.can("project:manage_access", SCOPE)).toBe(true);
    expect(client.can("project:manage_access", { type: "project", id: "other" })).toBe(false);
    expect(client.can("project:delete", SCOPE)).toBe(false);
  });
});

describe("service mode", () => {
  it("asks the caller's getter for each call, with the audience of the route", async () => {
    const { client, seen, audiences } = service((req) =>
      req.url.pathname === "/v1/whoami"
        ? json(200, { iss: "x", tid: "t", sub: "sa:sa_1", kind: "access", rev: 1 })
        : json(200, { tid: "t", iss: "x" }),
    );
    await client.tenant.get();
    await client.whoami();
    expect(audiences).toEqual(["admin", "authz"]);
    expect(seen.every((s) => s.headers.get("authorization") === "Bearer svc-token")).toBe(true);
    // No exchange in service mode.
    expect(seen.some((s) => s.url.pathname === "/oauth2/token")).toBe(false);
  });

  it("sends no cookie and follows no redirect", async () => {
    let init: RequestInit | undefined;
    const client = new TutelaClient({
      baseUrl: BASE,
      fetch: (async (_u: RequestInfo | URL, i?: RequestInit) => {
        init = i;
        return json(200, { tid: "t", iss: "x" });
      }) as typeof fetch,
      auth: { kind: "service", getToken: () => "t" },
    });
    await client.tenant.get();
    expect(init?.credentials).toBe("omit");
    expect(init?.redirect).toBe("error");
  });

  it("refuses a base URL with credentials in it", () => {
    expect(
      () =>
        new TutelaClient({
          baseUrl: "https://user:pw@tutela.example.test",
          fetch: (async () => json(200, {})) as typeof fetch,
          auth: { kind: "service", getToken: () => "t" },
        }),
    ).toThrow(TypeError);
  });

  it("calls every route of the Console at its path and method", async () => {
    const { client, seen } = service(() => json(200, {}));
    const calls: [() => Promise<unknown>, string, string][] = [
      [() => client.tenant.get(), "GET", "/v1/admin/tenant"],
      [() => client.tenant.rename("Acme"), "PATCH", "/v1/admin/tenant"],
      [() => client.tenant.delete(), "DELETE", "/v1/admin/tenant"],
      [() => client.orgs.list(), "GET", "/v1/admin/orgs"],
      [() => client.orgs.create(), "POST", "/v1/admin/orgs"],
      [() => client.orgs.rename("org_1", "B"), "PATCH", "/v1/admin/orgs/org_1"],
      [() => client.orgs.delete("org_1"), "DELETE", "/v1/admin/orgs/org_1"],
      [() => client.orgs.restore("org_1"), "POST", "/v1/admin/orgs/org_1/restore"],
      [() => client.scopes.page({ under: ORG }), "GET", "/v1/admin/scopes"],
      [() => client.scopes.register({ scope: SCOPE, parent: ORG }), "POST", "/v1/admin/scopes"],
      [() => client.scopes.move({ scope: SCOPE, parent: ORG }), "POST", "/v1/admin/scopes/move"],
      [() => client.scopes.delete(SCOPE), "POST", "/v1/admin/scopes/delete"],
      [() => client.scopes.setPrivate(SCOPE, true), "PUT", "/v1/admin/scopes/private"],
      [
        () => client.scopes.setBoundary({ scope: SCOPE, moves_out: "owners" }),
        "PUT",
        "/v1/admin/boundaries",
      ],
      [() => client.assignments.page({ scope: SCOPE }), "POST", "/v1/admin/assignments/list"],
      [
        () => client.assignments.assign({ subject: "user:usr_1", role: "r", scope: SCOPE }),
        "POST",
        "/v1/admin/assignments",
      ],
      [() => client.assignments.setExpiry("ra_1", null), "PATCH", "/v1/admin/assignments/ra_1"],
      [() => client.assignments.unassign("ra_1"), "DELETE", "/v1/admin/assignments/ra_1"],
      [() => client.groups.page({ org: "org_1" }), "GET", "/v1/admin/groups"],
      [
        () => client.groups.create({ org: "org_1", key: "g", name: "G" }),
        "POST",
        "/v1/admin/groups",
      ],
      [() => client.groups.delete("g"), "DELETE", "/v1/admin/groups/g"],
      [() => client.groups.membersPage("g"), "GET", "/v1/admin/groups/g/members"],
      [() => client.groups.addMember("g", "user:usr_1"), "POST", "/v1/admin/groups/g/members"],
      [
        () => client.groups.removeMember("g", "user:usr_1"),
        "POST",
        "/v1/admin/groups/g/members/remove",
      ],
      [() => client.roles(SCOPE), "GET", "/v1/admin/roles"],
      [() => client.models.versions(), "GET", "/v1/models"],
      [() => client.models.version(3), "GET", "/v1/models/3"],
      [() => client.models.active(), "GET", "/v1/models/active"],
      [() => client.models.impact({ source: "x" }), "POST", "/v1/models/impact"],
      [
        () => client.models.publish({ source: "x", expected_version: 3 }),
        "POST",
        "/v1/models/publish",
      ],
      [() => client.models.settings(), "GET", "/v1/models/settings"],
      [() => client.models.putSettings(true), "PUT", "/v1/models/settings"],
      [() => client.models.propose({ source: "x" }), "POST", "/v1/models/proposals"],
      [() => client.models.proposals(), "GET", "/v1/models/proposals"],
      [() => client.models.proposal("mpr_1"), "GET", "/v1/models/proposals/mpr_1"],
      [() => client.models.approve("mpr_1"), "POST", "/v1/models/proposals/mpr_1/approve"],
      [() => client.models.reject("mpr_1"), "POST", "/v1/models/proposals/mpr_1/reject"],
      [() => client.principals.state("user:usr_1"), "POST", "/v1/admin/principals/state"],
      [
        () => client.principals.setDisabled("user:usr_1", true),
        "POST",
        "/v1/admin/principals/disabled",
      ],
      [
        () => client.principals.revokeSessions("user:usr_1"),
        "POST",
        "/v1/admin/principals/revoke-sessions",
      ],
      [() => client.principals.deleteUser("user:usr_1"), "POST", "/v1/admin/users/delete"],
      [() => client.agents.page(), "GET", "/v1/admin/agents"],
      [() => client.agents.register(), "POST", "/v1/admin/agents"],
      [() => client.apps.list(), "GET", "/v1/admin/apps"],
      [() => client.apps.create("crm"), "POST", "/v1/admin/apps"],
      [() => client.apps.rotate("app_1"), "POST", "/v1/admin/apps/app_1/rotate"],
      [() => client.apps.disable("app_1"), "POST", "/v1/admin/apps/app_1/disable"],
      [() => client.webhooks.list(), "GET", "/v1/admin/webhooks"],
      [
        () => client.webhooks.register({ url: "https://h.example.test" }),
        "POST",
        "/v1/admin/webhooks",
      ],
      [() => client.webhooks.rotate("whk_1"), "POST", "/v1/admin/webhooks/whk_1/rotate"],
      [() => client.webhooks.disable("whk_1"), "POST", "/v1/admin/webhooks/whk_1/disable"],
      [
        () => client.webhooks.deliveries("whk_1", { state: "dead" }),
        "GET",
        "/v1/admin/webhooks/whk_1/deliveries",
      ],
      [
        () => client.webhooks.redeliver("whk_1", 7),
        "POST",
        "/v1/admin/webhooks/whk_1/deliveries/7/redeliver",
      ],
    ];
    for (const [call] of calls) await call().catch(() => undefined);
    expect(seen.map((s: Seen) => `${s.method} ${s.url.pathname}`)).toEqual(
      calls.map(([, m, p]) => `${m} ${p}`),
    );
  });
});
