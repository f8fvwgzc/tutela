// Sign-in at the tenant's realm: the authorization code flow with PKCE
// (S256) as a public client (ADR-0052). Tokens live in this object only.
// The one thing kept across the redirect to the realm and back is the
// pending sign-in (state, nonce, PKCE verifier, where to return), in
// sessionStorage, removed as soon as the callback reads it: it is not a
// token, and it is useless once its code is spent.

import type { UpstreamReason } from "@f8fvwgzc/tutela-js";

/** `GET /console/config.json`, from tutelad's configuration (ADR-0050). */
export interface ConsoleConfig {
  issuer: string;
  client_id: string;
  step_up_acr: string;
  audience: string;
}

interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
}

interface Pending {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

interface TokenAnswer {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  error?: string;
  error_description?: string;
}

/** The key of the pending sign-in in sessionStorage. */
export const PENDING_KEY = "tutela-console:pending-sign-in";
/** The Console's callback path. */
export const CALLBACK_PATH = "/console/callback";

/** A sign-in that did not work, with a sentence to show. */
export class SignInError extends Error {
  override name = "SignInError";
}

/** What the Console needs from the browser; tests pass their own. */
export interface OidcEnv {
  fetch: typeof fetch;
  crypto: Crypto;
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">;
  origin: string;
  assign: (url: string) => void;
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The claims of a JWT, unverified: the Console only reads them for display. */
export function claims(jwt: string | undefined): Record<string, unknown> {
  const part = jwt?.split(".")[1];
  if (part === undefined) return {};
  try {
    const text = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(text, (c) => c.charCodeAt(0));
    const v: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** The sign-in of one person, in memory. */
export class Oidc {
  readonly config: ConsoleConfig;
  readonly #env: OidcEnv;
  #discovery: Discovery | undefined;
  #access: string | undefined;
  #accessSent = false;
  #refresh: string | undefined;
  #idToken: string | undefined;

  constructor(config: ConsoleConfig, env: OidcEnv) {
    this.config = config;
    this.#env = env;
  }

  /** Where the realm sends the browser back. */
  get redirectUri(): string {
    return `${this.#env.origin}${CALLBACK_PATH}`;
  }

  /** The person's name and acr, from the realm's latest tokens. */
  get person(): { name: string | undefined; acr: string | undefined } {
    const id = claims(this.#idToken);
    const at = claims(this.#access);
    const name = id.name ?? id.preferred_username ?? at.name;
    const acr = at.acr ?? id.acr;
    return {
      name: typeof name === "string" ? name : undefined,
      acr: typeof acr === "string" ? acr : undefined,
    };
  }

  /** `true` once a code was exchanged. */
  get signedIn(): boolean {
    return this.#access !== undefined || this.#refresh !== undefined;
  }

  async #discover(): Promise<Discovery> {
    if (this.#discovery !== undefined) return this.#discovery;
    const url = `${this.config.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    const res = await this.#env.fetch(url, { credentials: "omit", redirect: "error" });
    if (!res.ok) throw new SignInError("The sign-in service did not answer. Try again.");
    const d = (await res.json()) as Discovery;
    // OIDC Discovery 4.3: the document must name the issuer it was read from.
    if (d.issuer !== this.config.issuer) {
      throw new SignInError("The sign-in service named another issuer. Ask your operator.");
    }
    this.#discovery = d;
    return d;
  }

  #random(): string {
    const b = new Uint8Array(32);
    this.#env.crypto.getRandomValues(b);
    return b64url(b);
  }

  /**
   * Sends the browser to the realm's sign-in, asking for the step-up `acr`
   * (an admin token needs it, ADR-0032).
   */
  async signIn(returnTo: string): Promise<void> {
    const d = await this.#discover();
    const verifier = this.#random();
    const digest = await this.#env.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier),
    );
    const pending: Pending = {
      state: this.#random(),
      nonce: this.#random(),
      verifier,
      returnTo: returnTo.startsWith("/console/") ? returnTo : "/console/",
    };
    this.#env.storage.setItem(PENDING_KEY, JSON.stringify(pending));
    const url = new URL(d.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.config.client_id,
      redirect_uri: this.redirectUri,
      scope: "openid",
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: b64url(new Uint8Array(digest)),
      code_challenge_method: "S256",
      acr_values: this.config.step_up_acr,
    }).toString();
    this.#env.assign(url.toString());
  }

  /**
   * The realm sent the browser back: checks `state` and `iss`, and trades
   * the code (with the PKCE verifier) for tokens, kept here. Answers where
   * to go next.
   */
  async callback(search: string): Promise<string> {
    const raw = this.#env.storage.getItem(PENDING_KEY);
    this.#env.storage.removeItem(PENDING_KEY);
    const q = new URLSearchParams(search);
    if (raw === null) throw new SignInError("This sign-in was not started here. Sign in again.");
    const pending = JSON.parse(raw) as Pending;
    if (q.get("state") !== pending.state) {
      throw new SignInError("The sign-in answer did not match. Sign in again.");
    }
    const iss = q.get("iss");
    if (iss !== null && iss !== this.config.issuer) {
      throw new SignInError("The sign-in answer came from another issuer. Sign in again.");
    }
    const error = q.get("error");
    if (error !== null) {
      throw new SignInError(
        error === "access_denied" ? "Sign-in was cancelled." : `Sign-in failed (${error}).`,
      );
    }
    const code = q.get("code");
    if (code === null) throw new SignInError("The sign-in answer had no code. Sign in again.");
    const t = await this.#token({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.redirectUri,
      code_verifier: pending.verifier,
    });
    if (claims(t.id_token).nonce !== pending.nonce) {
      this.forget();
      throw new SignInError("The sign-in answer did not match. Sign in again.");
    }
    return pending.returnTo;
  }

  async #token(form: Record<string, string>): Promise<TokenAnswer> {
    const d = await this.#discover();
    const res = await this.#env.fetch(d.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ ...form, client_id: this.config.client_id }).toString(),
      credentials: "omit",
      redirect: "error",
    });
    const t = (await res.json().catch(() => ({}))) as TokenAnswer;
    if (!res.ok || t.access_token === undefined) {
      throw new SignInError("Your sign-in has ended. Sign in again.");
    }
    this.#access = t.access_token;
    this.#accessSent = false;
    if (t.refresh_token !== undefined) this.#refresh = t.refresh_token;
    if (t.id_token !== undefined) this.#idToken = t.id_token;
    return t;
  }

  /**
   * A realm access token this session has not handed out before, for
   * `tutelad`'s token exchange (each one is exchanged once): the one from
   * the code first, then one from the refresh token.
   */
  async upstream(_reason: UpstreamReason): Promise<string> {
    if (this.#access !== undefined && !this.#accessSent) {
      this.#accessSent = true;
      return this.#access;
    }
    if (this.#refresh === undefined) throw new SignInError("Sign in again.");
    await this.#token({ grant_type: "refresh_token", refresh_token: this.#refresh });
    this.#accessSent = true;
    return this.#access ?? "";
  }

  /** Drops every token. */
  forget(): void {
    this.#access = undefined;
    this.#refresh = undefined;
    this.#idToken = undefined;
  }

  /** Signs out: drops the tokens and ends the realm's session. */
  async signOut(): Promise<void> {
    this.forget();
    const d = await this.#discover().catch(() => undefined);
    if (d?.end_session_endpoint === undefined) {
      this.#env.assign("/console/");
      return;
    }
    const url = new URL(d.end_session_endpoint);
    url.search = new URLSearchParams({
      client_id: this.config.client_id,
      // Never id_token_hint: a token never goes into a URL.
      post_logout_redirect_uri: `${this.#env.origin}/console/`,
    }).toString();
    this.#env.assign(url.toString());
  }
}
