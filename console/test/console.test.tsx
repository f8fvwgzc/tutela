import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { userEvent } from "@testing-library/user-event";
import axe from "axe-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Root } from "../src/App";
import { PENDING_KEY } from "../src/oidc";
import { CONFIG, json, ORG, PROJECT, problem, World } from "./fake";

afterEach(() => {
  cleanup();
  window.sessionStorage.clear();
});

beforeEach(() => {
  window.history.replaceState(null, "", "/console/");
});

/** Signs in through the Console's own flow and lands on `to`. */
async function signedIn(w: World, to = "/console/") {
  window.history.replaceState(null, "", to);
  const first = render(<Root config={CONFIG} env={w.env()} apiFetch={w.fetch} />);
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
  await waitFor(() => expect(w.assigned).toHaveLength(1));
  first.unmount();
  const pending = JSON.parse(window.sessionStorage.getItem(PENDING_KEY) ?? "{}") as {
    state: string;
  };
  window.history.replaceState(null, "", `/console/callback?code=c-1&state=${pending.state}`);
  render(<Root config={CONFIG} env={w.env()} apiFetch={w.fetch} />);
  await screen.findByRole("navigation", { name: "Pages" });
}

const rail = () =>
  within(screen.getByRole("navigation", { name: "Pages" }))
    .getAllByRole("link")
    .map((a) => a.textContent);

describe("sign-in states", () => {
  it("starts signed out, with a button and the realm's host", () => {
    const w = new World();
    render(<Root config={CONFIG} env={w.env()} apiFetch={w.fetch} />);
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
    expect(screen.getByText("kc.example.test")).toBeTruthy();
    expect(w.seen).toHaveLength(0);
  });

  it("shows the pages the permission map allows an owner, and the code leaves the URL", async () => {
    const w = new World();
    await signedIn(w, "/console/roles");
    await waitFor(() => expect(rail()).toContain("Apps"));
    expect(rail()).toEqual([
      "Overview",
      "Scopes",
      "Roles",
      "Model history",
      "Groups",
      "People and agents",
      "Apps",
      "Webhooks",
      "Tenant and orgs",
      "Explain and simulate",
    ]);
    expect(window.location.search).not.toContain("code=");
    expect(window.location.pathname).toBe("/console/roles");
    // TM-06: nothing kept in browser storage.
    expect(window.sessionStorage.length).toBe(0);
    expect(window.localStorage.length).toBe(0);
    expect(document.cookie).toBe("");
  });

  it("has no accessibility violation on the sign-in screen and the shell", async () => {
    const run = async () => {
      const r = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
      return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
    };
    const w = new World();
    const first = render(<Root config={CONFIG} env={w.env()} apiFetch={w.fetch} />);
    expect(await run()).toEqual([]);
    first.unmount();
    await signedIn(w);
    await waitFor(() => expect(rail()).toContain("Apps"));
    expect(await run()).toEqual([]);
  });

  it("shows a person with no admin key only the overview", async () => {
    const w = new World();
    w.keys.clear();
    await signedIn(w);
    await screen.findByTestId("no-admin-keys");
    expect(rail()).toEqual(["Overview"]);
  });

  it("follows the permission map when it changes", async () => {
    const w = new World();
    w.keys.clear();
    await signedIn(w);
    await screen.findByTestId("no-admin-keys");
    w.keys.add("read_audit");
    await waitFor(() => expect(rail()).toContain("Model history"), { timeout: 3000 });
    expect(rail()).not.toContain("Apps");
    w.keys.clear();
    await waitFor(() => expect(rail()).toEqual(["Overview"]), { timeout: 3000 });
  });

  it("asks for step-up when the admin token needs MFA", async () => {
    const w = new World();
    w.stepUp = false;
    await signedIn(w);
    const banner = await screen.findByRole("region", { name: "Step-up needed" });
    await userEvent.click(within(banner).getByRole("button", { name: "Sign in with MFA" }));
    await waitFor(() => expect(w.assigned).toHaveLength(2));
    expect(new URL(w.assigned[1] ?? "").searchParams.get("acr_values")).toBe("mfa");
  });

  it("goes back to sign-in when tutelad refuses the session", async () => {
    const w = new World();
    await signedIn(w);
    w.revoked = true;
    await screen.findByText("Your session ended. Sign in again.", undefined, { timeout: 3000 });
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  });
});

describe("pages and their error paths", () => {
  it("scopes: lists the tree and hides an org it may not list", async () => {
    const w = new World();
    w.routes.set("GET /v1/admin/scopes", () =>
      json(200, { scopes: [{ scope: PROJECT, ancestors: [ORG], private: false }] }),
    );
    w.routes.set("POST /v1/admin/assignments/list", () => json(200, { assignments: [] }));
    w.routes.set("GET /v1/admin/roles", () => json(200, { version: 1, roles: [], types: [] }));
    await signedIn(w, "/console/scopes");
    const tree = await screen.findByRole("navigation", { name: "Scope tree" });
    await within(tree).findByText("p-1");
    await userEvent.click(within(tree).getByText("p-1"));
    await screen.findByRole("heading", { name: /project p-1/ });
    expect(screen.getByLabelText(/Private/)).toBeTruthy();

    cleanup();
    const v = new World();
    v.keys = new Set(["read_audit"]);
    v.routes.set("GET /v1/admin/scopes", () => problem(403, "forbidden"));
    v.routes.set("POST /v1/admin/assignments/list", () => problem(403, "forbidden"));
    await signedIn(v, "/console/scopes");
    await screen.findByText("You may not list the scopes of some orgs.");
  });

  it("model history: forbidden hides it, 503 offers a retry, 409 loads again", async () => {
    const w = new World();
    w.routes.set("GET /v1/models", () => problem(403, "forbidden"));
    w.routes.set("GET /v1/models/proposals", () => json(200, { proposals: [] }));
    w.routes.set("GET /v1/models/settings", () => json(200, { two_person: false }));
    await signedIn(w, "/console/models");
    await screen.findByText("You may not see the model's history.");
    cleanup();

    const u = new World();
    u.routes.set("GET /v1/models", () => problem(503, "unavailable", { "retry-after": "30" }));
    u.routes.set("GET /v1/models/proposals", () => json(200, { proposals: [] }));
    u.routes.set("GET /v1/models/settings", () => json(200, { two_person: false }));
    await signedIn(u, "/console/models");
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("button", { name: /Try again/ })).toBeTruthy();
    cleanup();

    const c = new World();
    const proposal = {
      id: "prp_1",
      state: "proposed",
      base_version: 1,
      from: "a",
      to: "b",
      class: "narrowing",
      diff: "- x",
      rev: 2,
      proposed_by: "user:usr_other",
    };
    c.routes.set("GET /v1/models", () =>
      json(200, { active: { version: 1, digest: "d", own: true }, versions: [] }),
    );
    c.routes.set("GET /v1/models/proposals", () => json(200, { proposals: [proposal] }));
    c.routes.set("GET /v1/models/settings", () => json(200, { two_person: true }));
    c.routes.set("POST /v1/models/proposals/prp_1/approve", () => problem(409, "stale_proposal"));
    await signedIn(c, "/console/models");
    const before = c.to("GET", "/v1/models").length;
    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(c.to("GET", "/v1/models").length).toBeGreaterThan(before));
  });

  it("apps: a secret is shown once and gone when closed", async () => {
    const w = new World();
    const apps: unknown[] = [];
    w.routes.set("GET /v1/admin/apps", () => json(200, { apps }));
    w.routes.set("POST /v1/admin/apps", () => {
      const app = {
        client_id: "app_1",
        name: "crm",
        principal: "sa:sa_1",
        created_by: "user:usr_owner",
      };
      apps.push(app);
      return json(201, { app, client_secret: "tut_sk_abc_secret" });
    });
    await signedIn(w, "/console/apps");
    await userEvent.type(await screen.findByLabelText("Name"), "crm");
    await userEvent.click(screen.getByRole("button", { name: "Make app" }));
    await screen.findByText("tut_sk_abc_secret");
    await userEvent.click(screen.getByRole("button", { name: "I have stored it" }));
    expect(screen.queryByText("tut_sk_abc_secret")).toBeNull();
    expect(window.sessionStorage.length).toBe(0);
    // Never retried: one create.
    expect(w.to("POST", "/v1/admin/apps")).toHaveLength(1);
  });

  it("tenant, groups and people: a refusal hides what it guards", async () => {
    const w = new World();
    w.routes.set("GET /v1/admin/tenant", () => problem(403, "forbidden"));
    w.routes.set("GET /v1/admin/orgs", () => problem(403, "forbidden"));
    await signedIn(w, "/console/tenant");
    await screen.findByText("You may not see the tenant.");
    cleanup();

    const g = new World();
    g.routes.set("GET /v1/admin/groups", () => problem(403, "forbidden"));
    await signedIn(g, "/console/groups");
    await screen.findByText("You may not see the groups of this org.");
    cleanup();

    const p = new World();
    p.routes.set("POST /v1/admin/principals/state", () => problem(403, "forbidden"));
    p.routes.set("POST /v1/admin/assignments/list", () => problem(403, "forbidden"));
    p.routes.set("GET /v1/admin/agents", () => json(200, { agents: [] }));
    await signedIn(p, "/console/people");
    await userEvent.type(await screen.findByLabelText("Principal"), "user:usr_x");
    await userEvent.click(screen.getByRole("button", { name: "Look up" }));
    await screen.findByText("You may not manage this principal.");
    expect(screen.queryByRole("button", { name: "Disable" })).toBeNull();
    // The principal went in the body, never the URL.
    const ask = p.to("POST", "/v1/admin/principals/state")[0];
    expect(ask?.json).toEqual({ principal: "user:usr_x" });
    expect(ask?.url.search).toBe("");
  });

  it("a page the person may not open says so and shows nothing of it", async () => {
    const w = new World();
    w.keys = new Set(["read_audit"]);
    await signedIn(w, "/console/apps");
    await screen.findByText("You do not hold the admin keys this page needs.");
    expect(w.to("GET", "/v1/admin/apps")).toHaveLength(0);
  });
});
