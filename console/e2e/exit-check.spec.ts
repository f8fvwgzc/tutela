// The Phase B exit check in a real browser (ROADMAP, ADR-0053): sign-in,
// the UI permission map and runtime role editing pass end to end, against
// a real tutelad on a real Postgres and the test OpenID provider. The Rust
// test `crates/tutelad/tests/console_e2e.rs` makes the world and runs this.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type Browser, type BrowserContext, expect, type Page, test } from "@playwright/test";

interface Fixture {
  url: string;
  realm: string;
  org: string;
  owner: { principal: string; name: string };
  member: { principal: string; name: string };
  stale_admin: string[];
  fresh_admin: string;
  shots: string;
}

const path = process.env.TUTELA_E2E_FIXTURE;
if (path === undefined) throw new Error("run through `make js-e2e`: TUTELA_E2E_FIXTURE is not set");
const f = JSON.parse(readFileSync(path, "utf8")) as Fixture;

/** The documented revocation delay (PERMISSION-MODEL.md 16.1). */
const DELAY_MS = 1500;

/** Every CSP violation and page error of every context. */
const violations: string[] = [];

async function contextOf(browser: Browser): Promise<BrowserContext> {
  const c = await browser.newContext();
  await c.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  return c;
}

function watch(page: Page, who: string) {
  page.on("console", (m) => {
    if (/content security policy|CSP violation/i.test(m.text())) {
      violations.push(`${who}: ${m.text()}`);
    }
  });
  page.on("pageerror", (e) => violations.push(`${who}: page error ${e.message}`));
  // Refusals, for the log: method, path and status, never a token or a body.
  page.on("response", (r) => {
    if (r.status() >= 400) {
      const u = new URL(r.url());
      const type = r.headers()["content-type"] ?? "";
      const detail = type.startsWith("application/problem+json")
        ? r.json().then(
            (p: { type?: string; detail?: string }) => ` ${p.type ?? ""} ${p.detail ?? ""}`,
            () => "",
          )
        : Promise.resolve("");
      void detail.then((d) =>
        console.log(`${who}: ${r.request().method()} ${u.pathname} -> ${String(r.status())}${d}`),
      );
    }
  });
}

async function shot(page: Page, name: string) {
  if (f.shots === "") return;
  await page.screenshot({ path: join(f.shots, `${name}.png`) });
}

const rail = (page: Page) => page.getByRole("navigation", { name: "Pages" });

/** Signs `who` in at the realm through the Console, with or without MFA. */
async function signIn(page: Page, who: string, mfa: boolean) {
  const res = await page.goto(`${f.url}/console/`);
  const csp = res?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("script-src 'self';");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(res?.headers()["x-content-type-options"]).toBe("nosniff");
  expect(res?.headers()["referrer-policy"]).toBe("no-referrer");
  await page.getByRole("button", { name: "Sign in" }).click();
  // The realm's form.
  await page.waitForURL(`${f.realm}/**`);
  await page.getByLabel(who).check();
  const box = page.getByLabel(/Use MFA/);
  if (mfa) await box.check();
  else await box.uncheck();
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(rail(page)).toBeVisible();
  // The code left the address bar.
  expect(page.url()).not.toContain("code=");
}

/** TM-06: no token anywhere the browser keeps things. */
async function nothingStored(page: Page) {
  const kept = await page.evaluate(async () => {
    const dbs = typeof indexedDB.databases === "function" ? await indexedDB.databases() : [];
    const all = (s: Storage) =>
      Array.from({ length: s.length }, (_, i) => {
        const k = s.key(i) ?? "";
        return `${k}=${s.getItem(k) ?? ""}`;
      }).join(";");
    return {
      cookie: document.cookie,
      local: all(localStorage),
      session: all(sessionStorage),
      databases: dbs.map((d) => d.name ?? ""),
    };
  });
  expect(kept).toEqual({ cookie: "", local: "", session: "", databases: [] });
  expect(await page.context().cookies()).toEqual([]);
}

/** The status of an admin call with `token`, sent from the page. */
async function adminStatus(page: Page, token: string): Promise<number> {
  return page.evaluate(async (t) => {
    const r = await fetch("/v1/admin/tenant", {
      headers: { authorization: `Bearer ${t}` },
      credentials: "omit",
    });
    return r.status;
  }, token);
}

test("sign-in, the permission map and runtime role editing, end to end", async ({ browser }) => {
  const ownerCtx = await contextOf(browser);
  const memberCtx = await contextOf(browser);
  const owner = await ownerCtx.newPage();
  const member = await memberCtx.newPage();
  watch(owner, "owner");
  watch(member, "member");

  await test.step("an owner signs in with MFA and sees the pages the map allows", async () => {
    await signIn(owner, f.owner.name, true);
    for (const page of [
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
    ]) {
      await expect(rail(owner).getByRole("link", { name: page })).toBeVisible();
    }
    await expect(owner.getByText("MFA", { exact: true })).toBeVisible();
    await expect(owner.getByRole("region", { name: "Step-up needed" })).toHaveCount(0);
    await shot(owner, "owner-overview-light");
  });

  await test.step("a second person sees only what they hold", async () => {
    await signIn(member, f.member.name, true);
    await expect(member.getByTestId("no-admin-keys")).toBeVisible();
    await expect(rail(member).getByRole("link")).toHaveCount(1);
    await member.goto(`${f.url}/console/scopes`);
    await signInAgainIfAsked(member, f.member.name);
    await expect(member.getByText("You do not hold the admin keys this page needs.")).toBeVisible();
    await member.getByRole("link", { name: "Overview" }).click();
  });

  let given = 0;
  await test.step("the owner gives the person a role; their map changes within the delay", async () => {
    await rail(owner).getByRole("link", { name: "Scopes" }).click();
    const give = owner.getByRole("form", { name: "Give a role" });
    await give.getByLabel("Member").fill(f.member.principal);
    await give.getByLabel("Role").selectOption("auditor");
    const answered = owner.waitForResponse(
      (r) =>
        r.request().method() === "POST" && new URL(r.url()).pathname === "/v1/admin/assignments",
    );
    await give.getByRole("button", { name: "Give role" }).click();
    const res = await answered;
    expect(res.status()).toBe(200);
    given = Date.now();
    await member
      .getByRole("navigation", { name: "Pages" })
      .getByRole("link", { name: "Model history" })
      .waitFor({ timeout: 10_000 });
    const took = Date.now() - given;
    console.log(`the person's map showed the new role after ${String(took)} ms`);
    expect(took).toBeLessThanOrEqual(DELAY_MS);
    await expect(
      owner.getByRole("button", { name: `Remove auditor from ${f.member.principal}` }),
    ).toBeVisible();
    await shot(owner, "owner-scopes-light");
  });

  await test.step("the person sees no admin action they do not hold", async () => {
    await rail(member).getByRole("link", { name: "Scopes" }).click();
    await expect(member.getByRole("table", { name: /Members of org/ })).toBeVisible();
    await expect(member.getByRole("button", { name: "Give role" })).toHaveCount(0);
    await expect(member.getByRole("button", { name: /^Remove / })).toHaveCount(0);
    await rail(member).getByRole("link", { name: "Roles" }).click();
    await expect(member.getByRole("table", { name: "Permission matrix" })).toBeVisible();
    await expect(member.getByRole("button", { name: /^Edit / })).toHaveCount(0);
    await expect(rail(member).getByRole("link", { name: "Apps" })).toHaveCount(0);
    await member.getByLabel("Theme").selectOption("dark");
    await shot(member, "member-roles-dark");
    await rail(member).getByRole("link", { name: "Overview" }).click();
  });

  await test.step("the owner removes the role; the person's map changes within the delay", async () => {
    await owner.getByRole("button", { name: `Remove auditor from ${f.member.principal}` }).click();
    const answered = owner.waitForResponse(
      (r) =>
        r.request().method() === "DELETE" &&
        new URL(r.url()).pathname.startsWith("/v1/admin/assignments/"),
    );
    await owner.getByRole("button", { name: /^Remove$/ }).click();
    expect((await answered).status()).toBe(200);
    const removed = Date.now();
    await member
      .getByRole("navigation", { name: "Pages" })
      .getByRole("link", { name: "Model history" })
      .waitFor({ state: "detached", timeout: 10_000 });
    const took = Date.now() - removed;
    console.log(`the person's map lost the role after ${String(took)} ms`);
    expect(took).toBeLessThanOrEqual(DELAY_MS);
    await expect(member.getByTestId("no-admin-keys")).toBeVisible();
  });

  await test.step("the owner edits a role in the RoleEditor, sees the impact and publishes", async () => {
    await rail(owner).getByRole("link", { name: "Roles" }).click();
    await owner.getByRole("button", { name: "Edit reader" }).click();
    await owner.getByLabel("Level of invoice for reader").selectOption("none");
    await owner.getByRole("button", { name: "Review change" }).click();
    await owner.getByRole("button", { name: "Check impact" }).click();
    const impact = owner.getByRole("region", { name: "What this change does" });
    await expect(impact).toBeVisible();
    await expect(impact.getByText("This change narrows access.")).toBeVisible();
    await expect(impact.getByRole("listitem").first()).toContainText(/lose/);
    await shot(owner, "owner-role-impact-light");
    await owner.getByRole("button", { name: "Publish change" }).click();
    await expect(owner.getByText(/Published as version \d+\./).first()).toBeVisible();
    await rail(owner).getByRole("link", { name: "Model history" }).click();
    const versions = owner.getByRole("table", { name: "Model versions" });
    await expect(versions.getByRole("row")).not.toHaveCount(1);
    await owner.getByLabel("Theme").selectOption("dark");
    await shot(owner, "owner-model-history-dark");
    await rail(owner).getByRole("link", { name: "Roles" }).click();
    await expect(owner.getByRole("table", { name: "Permission matrix" })).toBeVisible();
    await shot(owner, "owner-roles-dark");
  });

  await test.step("TM-06: no token in cookies, localStorage, sessionStorage or IndexedDB", async () => {
    await nothingStored(owner);
    await nothingStored(member);
  });

  await test.step("an admin token six minutes old is refused", async () => {
    expect(await adminStatus(owner, f.fresh_admin)).toBe(200);
    for (const t of f.stale_admin) {
      expect(await adminStatus(owner, t)).toBe(401);
    }
  });

  await test.step("a sign-in without step-up is refused admin actions", async () => {
    const plainCtx = await contextOf(browser);
    const plain = await plainCtx.newPage();
    watch(plain, "without MFA");
    let authz = "";
    plain.on("request", (r) => {
      if (new URL(r.url()).pathname === "/v1/authz/permissions") {
        authz = r.headers().authorization ?? "";
      }
    });
    const refused = plain.waitForResponse(
      (r) =>
        new URL(r.url()).pathname === "/oauth2/token" &&
        r.request().postData()?.includes("audience=tutela-admin") === true,
    );
    await signIn(plain, f.owner.name, false);
    const res = await refused;
    expect(res.status()).toBe(400);
    expect(await res.json()).toMatchObject({
      error: "invalid_grant",
      error_description: "step-up authentication is required",
    });
    await expect(plain.getByRole("region", { name: "Step-up needed" })).toBeVisible();
    await shot(plain, "step-up-banner-light");
    // The person's tutela-authz token is refused on the admin API.
    expect(authz).toMatch(/^Bearer /);
    expect(await adminStatus(plain, authz.slice("Bearer ".length))).toBe(403);
    // And the Console's admin pages get nothing.
    await rail(plain).getByRole("link", { name: "Tenant and orgs" }).click();
    await expect(plain.getByRole("button", { name: /Sign in with MFA/ }).first()).toBeVisible();
    await expect(plain.getByRole("table", { name: "Orgs" }).getByRole("row")).toHaveCount(1);
    await nothingStored(plain);
    await plainCtx.close();
  });

  await test.step("no Content-Security-Policy violation and no page error", async () => {
    expect(violations).toEqual([]);
  });

  await ownerCtx.close();
  await memberCtx.close();
});

/** A direct visit loads the page again: the tokens were in memory, so sign in again. */
async function signInAgainIfAsked(page: Page, who: string) {
  const button = page.getByRole("button", { name: "Sign in" });
  if ((await button.count()) === 0) return;
  await button.click();
  await page.waitForURL(`${f.realm}/**`);
  await page.getByLabel(who).check();
  await page.getByLabel(/Use MFA/).check();
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(rail(page)).toBeVisible();
}
