import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { CALLBACK_PATH, Oidc, PENDING_KEY, SignInError } from "../src/oidc";
import { CONFIG, ISS, ORIGIN, World } from "./fake";

afterEach(() => window.sessionStorage.clear());

function b64url(b: Buffer): string {
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Starts a sign-in and answers the realm's redirect parameters. */
async function started(w: World, oidc: Oidc) {
  await oidc.signIn("/console/scopes");
  const url = new URL(w.assigned.at(-1) ?? "");
  const pending = JSON.parse(window.sessionStorage.getItem(PENDING_KEY) ?? "{}") as {
    verifier: string;
    state: string;
  };
  return { url, pending };
}

describe("sign-in at the realm (authorization code with PKCE S256)", () => {
  it("asks for a code with an S256 challenge, the step-up acr and the exact callback", async () => {
    const w = new World();
    const oidc = new Oidc(CONFIG, w.env());
    const { url, pending } = await started(w, oidc);
    expect(url.origin + url.pathname).toBe(`${ISS}/auth`);
    const q = url.searchParams;
    expect(q.get("response_type")).toBe("code");
    expect(q.get("client_id")).toBe("tutela-console");
    expect(q.get("redirect_uri")).toBe(`${ORIGIN}${CALLBACK_PATH}`);
    expect(q.get("code_challenge_method")).toBe("S256");
    expect(q.get("acr_values")).toBe("mfa");
    expect(q.get("state")).toBe(pending.state);
    expect(q.get("code_challenge")).toBe(
      b64url(createHash("sha256").update(pending.verifier).digest()),
    );
    expect(pending.verifier.length).toBeGreaterThanOrEqual(43);
    // Only the pending sign-in is kept; no token anywhere.
    expect(window.sessionStorage.length).toBe(1);
  });

  it("trades the code with the verifier, then forgets the pending sign-in", async () => {
    const w = new World();
    const oidc = new Oidc(CONFIG, w.env());
    const { pending } = await started(w, oidc);
    const to = await oidc.callback(
      `?code=c-1&state=${pending.state}&iss=${encodeURIComponent(ISS)}`,
    );
    expect(to).toBe("/console/scopes");
    expect(window.sessionStorage.length).toBe(0);
    const ask = w.seen.find((s) => s.url.href === `${ISS}/token`);
    expect(ask?.form?.get("grant_type")).toBe("authorization_code");
    expect(ask?.form?.get("code")).toBe("c-1");
    expect(ask?.form?.get("code_verifier")).toBe(pending.verifier);
    expect(ask?.form?.get("redirect_uri")).toBe(`${ORIGIN}${CALLBACK_PATH}`);
    expect(oidc.person).toEqual({ name: "Olivia Owner", acr: "mfa" });

    // The code's token first, once; then a fresh one from the refresh token.
    const first = await oidc.upstream("initial");
    const second = await oidc.upstream("expiring");
    expect(second).not.toBe(first);
    const refresh = w.seen.filter((s) => s.form?.get("grant_type") === "refresh_token");
    expect(refresh).toHaveLength(1);
  });

  it("refuses an answer it did not start, another state, another issuer, or an error", async () => {
    const w = new World();
    const oidc = new Oidc(CONFIG, w.env());
    await expect(oidc.callback("?code=c&state=s")).rejects.toBeInstanceOf(SignInError);

    let { pending } = await started(w, oidc);
    await expect(oidc.callback("?code=c&state=other")).rejects.toThrow(/did not match/);
    expect(window.sessionStorage.length).toBe(0);

    ({ pending } = await started(w, oidc));
    await expect(
      oidc.callback(`?code=c&state=${pending.state}&iss=https%3A%2F%2Fevil.example.test`),
    ).rejects.toThrow(/another issuer/);

    ({ pending } = await started(w, oidc));
    await expect(oidc.callback(`?error=access_denied&state=${pending.state}`)).rejects.toThrow(
      /cancelled/,
    );
    // No code was ever traded.
    expect(w.seen.filter((s) => s.url.href === `${ISS}/token`)).toHaveLength(0);
  });

  it("refuses an ID token with another nonce", async () => {
    const w = new World();
    const oidc = new Oidc(CONFIG, w.env());
    const { pending } = await started(w, oidc);
    w.nonce = "someone-else";
    await expect(oidc.callback(`?code=c&state=${pending.state}`)).rejects.toThrow(/did not match/);
    expect(oidc.signedIn).toBe(false);
  });

  it("refuses a discovery document that names another issuer", async () => {
    const w = new World();
    w.routes.set(`GET ${ISS}/.well-known/openid-configuration`, () =>
      Response.json({ issuer: "https://evil.example.test", authorization_endpoint: "x" }),
    );
    const oidc = new Oidc(CONFIG, w.env());
    await expect(oidc.signIn("/console/")).rejects.toThrow(/another issuer/);
    expect(w.assigned).toHaveLength(0);
  });

  it("signs out without putting a token in the URL", async () => {
    const w = new World();
    const oidc = new Oidc(CONFIG, w.env());
    const { pending } = await started(w, oidc);
    await oidc.callback(`?code=c&state=${pending.state}`);
    await oidc.signOut();
    const out = new URL(w.assigned.at(-1) ?? "");
    expect(out.href.startsWith(`${ISS}/logout`)).toBe(true);
    expect(out.searchParams.get("post_logout_redirect_uri")).toBe(`${ORIGIN}/console/`);
    expect(out.searchParams.has("id_token_hint")).toBe(false);
    expect(oidc.signedIn).toBe(false);
    await expect(oidc.upstream("rejected")).rejects.toBeInstanceOf(SignInError);
  });
});
