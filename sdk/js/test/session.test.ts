import { describe, expect, it } from "vitest";

import {
  jwtPayload,
  SignedOutError,
  StepUpRequiredError,
  TokenExchangeError,
  TutelaClient,
  UnauthorizedError,
  type UpstreamReason,
  UpstreamTokenReusedError,
} from "../src/index.js";
import { fakeFetch, json, jwt, problem, type Seen, TokenEndpoint } from "./fake.js";

const BASE = "https://tutela.example.test";

/** An upstream (Keycloak) token with a fresh `jti`, valid `life` seconds. */
let jti = 0;
function upstream(now: number, life = 600): string {
  jti++;
  return jwt({
    iss: "https://kc.example.test/realms/acme",
    aud: "tutela-authz",
    jti: `kc-${jti}`,
    exp: Math.floor(now / 1000) + life,
    acr: "mfa",
  });
}

function world(o: { now?: () => number; handler?: (req: Seen) => Response | undefined } = {}) {
  const tokens = new TokenEndpoint();
  let clock = Date.parse("2026-11-02T10:00:00Z");
  const now = o.now ?? (() => clock);
  tokens.now = now;
  const asked: UpstreamReason[] = [];
  const { fetch, seen } = fakeFetch((req) => {
    const custom = o.handler?.(req);
    if (custom !== undefined) return custom;
    if (req.url.pathname === "/oauth2/token") return tokens.answer(req);
    if (req.url.pathname === "/v1/whoami") {
      return json(200, { iss: "x", tid: "ten_1", sub: "user:usr_1", kind: "access", rev: 1 });
    }
    if (req.url.pathname === "/v1/admin/tenant") return json(200, { tid: "ten_1", iss: "x" });
    return problem(404, "not_found");
  });
  let next: () => string = () => upstream(now());
  const client = new TutelaClient({
    baseUrl: BASE,
    fetch,
    auth: {
      kind: "browser",
      now,
      getUpstreamToken: async (reason) => {
        asked.push(reason);
        return next();
      },
    },
  });
  return {
    client,
    seen,
    tokens,
    asked,
    tick: (secs: number) => {
      clock += secs * 1000;
    },
    setNext: (f: () => string) => {
      next = f;
    },
  };
}

const exchanges = (seen: Seen[]) => seen.filter((s) => s.url.pathname === "/oauth2/token");

describe("the browser token flow (ROADMAP notes for part 4b)", () => {
  it("exchanges the upstream token for a tutela-authz token, then that for an admin token, with no client authentication", async () => {
    const w = world();
    await w.client.tenant.get();
    const ex = exchanges(w.seen);
    expect(ex).toHaveLength(2);
    const [first, second] = ex;
    expect(first?.form?.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:token-exchange");
    expect(first?.form?.get("subject_token_type")).toBe(
      "urn:ietf:params:oauth:token-type:access_token",
    );
    expect(first?.form?.get("audience")).toBe("tutela-authz");
    expect(second?.form?.get("audience")).toBe("tutela-admin");
    // The admin token comes from the Tutela token, not the upstream one.
    expect(jwtPayload(second?.form?.get("subject_token") ?? "").aud).toBe("tutela-authz");
    for (const e of ex) {
      expect(e.headers.get("authorization")).toBeNull();
      expect(e.form?.get("client_id")).toBeNull();
      expect(e.form?.get("client_secret")).toBeNull();
    }
    const call = w.seen.find((s) => s.url.pathname === "/v1/admin/tenant");
    expect(jwtPayload(call?.headers.get("authorization")?.slice(7) ?? "").aud).toBe("tutela-admin");
    expect(w.asked).toEqual(["initial"]);
  });

  it("uses the tutela-authz token for the permission map and whoami", async () => {
    const w = world();
    await w.client.whoami();
    const call = w.seen.find((s) => s.url.pathname === "/v1/whoami");
    expect(jwtPayload(call?.headers.get("authorization")?.slice(7) ?? "").aud).toBe("tutela-authz");
    // No admin token was asked for.
    expect(exchanges(w.seen)).toHaveLength(1);
  });

  it("turns the step-up refusal into a typed error, keeps the authz token, and recovers after MFA", async () => {
    const w = world();
    w.tokens.stepUp = false;
    const states: string[] = [];
    w.client.session?.subscribe((s) => states.push(s.status));
    const err = await w.client.tenant.get().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StepUpRequiredError);
    expect((err as StepUpRequiredError).error).toBe("invalid_grant");
    expect(w.client.session?.state.status).toBe("step-up-required");
    expect(states).toContain("step-up-required");
    // The check API still works without step-up.
    await expect(w.client.whoami()).resolves.toMatchObject({ sub: "user:usr_1" });
    // Asking again does not exchange again: the session knows.
    const before = exchanges(w.seen).length;
    await expect(w.client.tenant.get()).rejects.toBeInstanceOf(StepUpRequiredError);
    expect(exchanges(w.seen)).toHaveLength(before);
    // The person does MFA; the next upstream token is asked for as step-up.
    w.tokens.stepUp = true;
    await w.client.session?.stepUp();
    expect(w.asked).toContain("step-up");
    await expect(w.client.tenant.get()).resolves.toMatchObject({ tid: "ten_1" });
    expect(w.client.session?.state.status).toBe("ready");
  });

  it("refreshes from a fresh upstream token before expiry, and never sends one upstream token twice", async () => {
    const w = world();
    await w.client.tenant.get();
    const firstUpstream = exchanges(w.seen)[0]?.form?.get("subject_token");
    w.tick(280); // inside the 30 s margin of the 300 s tokens
    await w.client.tenant.get();
    expect(w.asked).toEqual(["initial", "expiring"]);
    const subjects = exchanges(w.seen)
      .filter((e) => e.form?.get("audience") === "tutela-authz")
      .map((e) => e.form?.get("subject_token"));
    expect(subjects).toHaveLength(2);
    expect(subjects[1]).not.toBe(firstUpstream);
  });

  it("refuses an upstream token it exchanged before, without sending it", async () => {
    const w = world();
    const same = upstream(Date.parse("2026-11-02T10:00:00Z"));
    w.setNext(() => same);
    await w.client.whoami();
    w.tick(290);
    const count = exchanges(w.seen).length;
    await expect(w.client.whoami()).rejects.toBeInstanceOf(UpstreamTokenReusedError);
    expect(exchanges(w.seen)).toHaveLength(count);
  });

  it("never keeps an admin token past the token it came from", async () => {
    const w = world();
    w.tokens.ttl = { "tutela-authz": 100, "tutela-admin": 300 };
    await w.client.tenant.get();
    const state = w.client.session?.state;
    expect(state?.status).toBe("ready");
    const exp = state?.status === "ready" ? state.expiresAt : 0;
    expect(exp).toBeLessThanOrEqual(Date.parse("2026-11-02T10:00:00Z") + 100_000);
    // Past the source's life the admin token is not used: a new exchange.
    w.tick(80);
    await w.client.tenant.get();
    expect(w.asked).toEqual(["initial", "expiring"]);
  });

  it("caps a token's life at its upstream token's exp", async () => {
    const w = world();
    w.setNext(() => upstream(Date.parse("2026-11-02T10:00:00Z"), 60));
    await w.client.whoami();
    const state = w.client.session?.state;
    expect(state?.status === "ready" ? state.expiresAt : 0).toBeLessThanOrEqual(
      Date.parse("2026-11-02T10:01:00Z"),
    );
  });

  it("starts again from upstream after a 401, once", async () => {
    let refused = 1;
    const w = world({
      handler: (req) => {
        if (req.url.pathname === "/v1/admin/tenant" && refused > 0) {
          refused--;
          return problem(401, "invalid_token");
        }
        return undefined;
      },
    });
    await expect(w.client.tenant.get()).resolves.toMatchObject({ tid: "ten_1" });
    expect(w.asked).toEqual(["initial", "rejected"]);
  });

  it("gives up with a typed error after a second 401", async () => {
    const w = world({
      handler: (req) =>
        req.url.pathname === "/v1/admin/tenant" ? problem(401, "invalid_token") : undefined,
    });
    const err = await w.client.tenant.get().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect((err as UnauthorizedError).code).toBe("invalid_token");
  });

  it("asks upstream once for calls made at the same time", async () => {
    const w = world();
    await Promise.all([w.client.tenant.get(), w.client.tenant.get(), w.client.whoami()]);
    expect(w.asked).toEqual(["initial"]);
    expect(exchanges(w.seen)).toHaveLength(2);
  });

  it("turns other token-endpoint refusals into TokenExchangeError", async () => {
    const w = world({
      handler: (req) =>
        req.url.pathname === "/oauth2/token"
          ? json(400, {
              error: "invalid_grant",
              error_description: "the subject token is not valid",
            })
          : undefined,
    });
    const err = await w.client.whoami().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TokenExchangeError);
    expect(err).not.toBeInstanceOf(StepUpRequiredError);
    expect((err as TokenExchangeError).status).toBe(400);
  });

  it("forgets its tokens on sign-out and refuses to go on", async () => {
    const w = world();
    await w.client.tenant.get();
    w.client.session?.signOut();
    expect(w.client.session?.state.status).toBe("signed-out");
    await expect(w.client.tenant.get()).rejects.toBeInstanceOf(SignedOutError);
  });
});
