// The client against a real tutelad on a real Postgres. The Rust test
// `crates/tutelad/tests/js_client.rs` makes the world, starts the service
// and runs this file with TUTELA_JS_FIXTURE set; `make js-it` runs it.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  ForbiddenError,
  NotFoundError,
  NotHeldError,
  type ScopeRef,
  StepUpRequiredError,
  TokenExchangeError,
  TutelaClient,
  UnauthorizedError,
} from "../src/index.js";

interface Fixture {
  url: string;
  newcomer: string;
  a: {
    tid: string;
    org: ScopeRef;
    project: ScopeRef;
    owner: string;
    keeper: string;
    reader: string;
  };
  b: { tid: string; org: ScopeRef; project: ScopeRef; assignment: string };
  upstream: Record<
    "owner" | "owner_without_step_up" | "keeper" | "reader" | "b_owner" | "replay",
    string[]
  >;
}

const file = process.env.TUTELA_JS_FIXTURE;
if (file === undefined) throw new Error("TUTELA_JS_FIXTURE is not set: run `make js-it`");
const fx = JSON.parse(readFileSync(file, "utf8")) as Fixture;

/**
 * A person's browser session. Each upstream token is handed out once, across
 * every session of the file: tutelad exchanges an upstream token once.
 */
function person(tokens: string[]): TutelaClient {
  const left = tokens;
  return new TutelaClient({
    baseUrl: fx.url,
    auth: {
      kind: "browser",
      getUpstreamToken: async () => {
        const t = left.shift();
        if (t === undefined) throw new Error("no upstream token left");
        return t;
      },
    },
  });
}

function service(token: string): TutelaClient {
  return new TutelaClient({ baseUrl: fx.url, auth: { kind: "service", getToken: () => token } });
}

const inAWeek = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

describe("tutela-js against tutelad", () => {
  it("exchanges an upstream token for an admin token, then lists, assigns and unassigns a role", async () => {
    const owner = person(fx.upstream.owner);
    const before = await owner.assignments.page({ scope: fx.a.project });
    expect(before.assignments.some((x) => x.subject === fx.a.keeper && x.role === "keeper")).toBe(
      true,
    );
    expect(owner.session?.state).toMatchObject({ status: "ready", admin: true });

    // Assign, with an end.
    const made = await owner.assignments.assign({
      subject: fx.newcomer,
      role: "reader",
      scope: fx.a.project,
      expires_at: inAWeek,
    });
    expect(made.assignment?.role).toBe("reader");
    expect(made.rev).toBeGreaterThan(0);
    expect(owner.revision).toBe(made.rev);
    const id = made.assignment?.id ?? "";

    // The page shows its own write: the list, and the permission map at
    // least as new as the write.
    const ids: string[] = [];
    for await (const x of owner.assignments.list({ scope: fx.a.project, limit: 1 })) ids.push(x.id);
    expect(ids).toContain(id);
    const map = await owner.permissions({
      resource: { ...fx.a.project, path: [fx.a.org] },
      actions: ["project:manage_access", "project:read_audit"],
    });
    expect(map.rev).toBeGreaterThanOrEqual(made.rev);
    expect(map.can("project:manage_access")).toBe(true);
    expect(owner.can("project:manage_access", fx.a.project)).toBe(true);
    // The same question again: 304, the same map.
    const again = await owner.permissions({
      resource: { ...fx.a.project, path: [fx.a.org] },
      actions: ["project:manage_access", "project:read_audit"],
    });
    expect(again).toBe(map);

    // Change the end, then remove it.
    const ended = await owner.assignments.setExpiry(id, null);
    expect(ended.assignment?.expires_at).toBeUndefined();
    const gone = await owner.assignments.unassign(id);
    expect(gone.rev).toBeGreaterThan(made.rev);
    const after = await owner.assignments.page({ scope: fx.a.project });
    expect(after.assignments.some((x) => x.id === id)).toBe(false);

    // The model it runs on, with its text: where a role change starts.
    const active = await owner.models.active();
    expect(active.version).toBe(0);
    expect(active.source).toContain("[roles.keeper]");

    // The permission matrix of the tenant's model.
    const roles = await owner.roles();
    expect(roles.roles.map((r) => r.key)).toEqual(
      expect.arrayContaining(["owner", "reader", "keeper"]),
    );
    expect(roles.types.map((t) => t.name)).toEqual(expect.arrayContaining(["project", "invoice"]));
  });

  it("refuses a grant above what the caller holds with a typed not_held", async () => {
    const keeper = person(fx.upstream.keeper);
    const err = await keeper.assignments
      .assign({ subject: fx.newcomer, role: "approver", scope: fx.a.project })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NotHeldError);
    const e = err as NotHeldError;
    expect(e.status).toBe(403);
    expect(e.gains.length).toBeGreaterThan(0);
    expect(e.gains.join(" ")).toMatch(/gains write on/);
    // Counts only: never a principal.
    expect(e.detail).not.toMatch(/usr_/);
    // What the keeper holds it may give.
    const ok = await keeper.assignments.assign({
      subject: fx.newcomer,
      role: "reader",
      scope: fx.a.project,
    });
    await keeper.assignments.unassign(ok.assignment?.id ?? "");
  });

  it("refuses a caller without manage_access with a typed forbidden", async () => {
    const reader = person(fx.upstream.reader);
    const err = await reader.assignments
      .assign({ subject: fx.newcomer, role: "reader", scope: fx.a.project })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ForbiddenError);
    expect(err).not.toBeInstanceOf(NotHeldError);
    expect((err as ForbiddenError).code).toBe("forbidden");
    await expect(reader.assignments.page({ scope: fx.a.project })).rejects.toBeInstanceOf(
      ForbiddenError,
    );
  });

  it("turns a person without step-up into StepUpRequiredError", async () => {
    const owner = person(fx.upstream.owner_without_step_up);
    await expect(owner.tenant.get()).rejects.toBeInstanceOf(StepUpRequiredError);
    expect(owner.session?.state.status).toBe("step-up-required");
    // The check API still answers it.
    await expect(owner.whoami()).resolves.toMatchObject({ sub: fx.a.owner, tid: fx.a.tid });
  });

  it("refuses a wrong or a missing token, and a person's check-API token on the admin API", async () => {
    await expect(service("not-a-token").tenant.get()).rejects.toBeInstanceOf(UnauthorizedError);
    const forged = `${btoa('{"alg":"ES256","typ":"at+jwt"}')}.${btoa('{"sub":"user:usr_x"}')}.AAAA`;
    await expect(service(forged).assignments.page({ scope: fx.a.project })).rejects.toBeInstanceOf(
      UnauthorizedError,
    );
    const none = await fetch(new URL("/v1/admin/tenant", fx.url));
    expect(none.status).toBe(401);
    // A person's tutela-authz token is 403 forbidden on the admin API (ADR-0032).
    const owner = person(fx.upstream.owner);
    const authz = await owner.session?.token("authz");
    const err = await service(authz ?? "")
      .tenant.get()
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ForbiddenError);
    // And an admin token is refused (401) outside the admin API.
    const admin = await owner.session?.token("admin");
    await expect(service(admin ?? "").whoami()).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it("refuses another tenant's data", async () => {
    const owner = person(fx.upstream.owner);
    const listed = await owner.assignments.page({ scope: fx.b.project }).catch((e: unknown) => e);
    expect(listed instanceof ForbiddenError || listed instanceof NotFoundError).toBe(true);
    await expect(owner.assignments.unassign(fx.b.assignment)).rejects.toBeInstanceOf(NotFoundError);
    await expect(owner.assignments.setExpiry(fx.b.assignment, null)).rejects.toBeInstanceOf(
      NotFoundError,
    );
    // Tenant B's owner still sees it, and A's people are not B's.
    const bOwner = person(fx.upstream.b_owner);
    const page = await bOwner.assignments.page({ scope: fx.b.project });
    expect(page.assignments.map((x) => x.id)).toContain(fx.b.assignment);
    const me = await bOwner.whoami();
    expect(me.tid).toBe(fx.b.tid);
    expect(me.tid).not.toBe(fx.a.tid);
  });

  it("exchanges an upstream token once at the server too", async () => {
    const token = fx.upstream.replay[0] ?? "";
    // Two sessions, so the client's own check does not stop the second.
    await person([token]).whoami();
    const err = await person([token])
      .whoami()
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TokenExchangeError);
    expect((err as TokenExchangeError).error).toBe("invalid_grant");
  });
});
