/**
 * Where the client's bearer tokens come from.
 *
 * - {@link BrowserSession}: a person in a browser, a public client (ADR-0044
 *   item 7). The flow of the ROADMAP notes for part 4b: the upstream
 *   (Keycloak) token is exchanged once at `POST /oauth2/token` for a
 *   `tutela-authz` token, with no client authentication; that token is
 *   exchanged for an admin token (`audience=tutela-admin`, at most 300 s,
 *   only after step-up). Tokens live in this object's memory only: never
 *   `localStorage`, `sessionStorage`, cookies or IndexedDB (TM-06).
 * - {@link serviceAuth}: a pipeline or a core written in TypeScript, whose
 *   own code gets its service token (an app's `client_credentials` token).
 */

import {
  NetworkError,
  SignedOutError,
  StepUpRequiredError,
  TokenExchangeError,
  UpstreamTokenReusedError,
} from "./errors.js";
import { retryAfter, type Transport } from "./http.js";

/** Which token a route takes: the admin API's, or the check API's. */
export type TokenAudience = "admin" | "authz";

/** What the client asks for a token. */
export interface TokenSource {
  /** A token for `audience` that is good for at least a few more seconds. */
  token(audience: TokenAudience, signal?: AbortSignal): Promise<string>;
  /**
   * `tutelad` refused `token` with 401: drop it, so the next call gets
   * another. Returns `true` when another may be had at once.
   */
  rejected(audience: TokenAudience, token: string): boolean;
}

/** A pipeline's or a core's own bearer token, for both audiences. */
export function serviceAuth(
  getToken: (audience: TokenAudience) => string | Promise<string>,
): TokenSource {
  return {
    async token(audience) {
      return getToken(audience);
    },
    rejected() {
      return false;
    },
  };
}

/** Why the session asks for an upstream token. */
export type UpstreamReason =
  /** The first token of the session. */
  | "initial"
  /** The tokens are about to expire. */
  | "expiring"
  /** `tutelad` refused a token (a revoked session, a disabled person). */
  | "rejected"
  /** The person did MFA; the new token should carry the step-up `acr`. */
  | "step-up";

/** The browser session's options. */
export interface BrowserSessionOptions {
  /**
   * Returns a **fresh** upstream access token: one this session has not
   * exchanged before, whose `aud` is `tutelad`'s audience (`tutela-authz`).
   * With keycloak-js: `await kc.updateToken(-1); return kc.token`. For
   * `reason: "step-up"`, sign in again with the step-up `acr` first.
   */
  getUpstreamToken: (reason: UpstreamReason) => Promise<string>;
  /** `tutelad`'s own audience (`TUTELA_AUDIENCE`). Default `tutela-authz`. */
  authzAudience?: string;
  /** Renew this many seconds before a token expires. Default 30. */
  refreshMarginSecs?: number;
  /** Milliseconds since the epoch; tests replace it. */
  now?: () => number;
}

/** What the UI may want to know about the session. */
export type SessionState =
  | { status: "signed-out" }
  | { status: "ready"; admin: boolean; expiresAt: number }
  | { status: "step-up-required" };

const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
const ADMIN_AUDIENCE = "tutela-admin";
const STEP_UP = "step-up authentication is required";

interface Held {
  token: string;
  /** Milliseconds since the epoch. */
  expiresAt: number;
}

/**
 * A person's session in a browser: the token flow of the ROADMAP notes for
 * part 4b. One object per signed-in person; it holds its tokens in memory.
 */
export class BrowserSession implements TokenSource {
  readonly #transport: Transport;
  readonly #getUpstream: (reason: UpstreamReason) => Promise<string>;
  readonly #authzAudience: string;
  readonly #margin: number;
  readonly #now: () => number;
  #authz: Held | undefined;
  #admin: Held | undefined;
  #stepUp: StepUpRequiredError | undefined;
  #pending: Promise<void> | undefined;
  #pendingAdmin: Promise<void> | undefined;
  #closed = false;
  /** Why the next upstream token is asked for, when there is no token. */
  #why: UpstreamReason = "initial";
  /** Upstream tokens exchanged, by `jti` (or the token), until they expire. */
  readonly #used = new Map<string, number>();
  readonly #listeners = new Set<(s: SessionState) => void>();

  constructor(transport: Transport, o: BrowserSessionOptions) {
    this.#transport = transport;
    this.#getUpstream = o.getUpstreamToken;
    this.#authzAudience = o.authzAudience ?? "tutela-authz";
    this.#margin = (o.refreshMarginSecs ?? 30) * 1000;
    this.#now = o.now ?? Date.now;
  }

  #snapshot: SessionState = { status: "signed-out" };

  /** The session's state now. The same object until it changes. */
  get state(): SessionState {
    return this.#snapshot;
  }

  #compute(): SessionState {
    if (this.#stepUp !== undefined) return { status: "step-up-required" };
    if (this.#authz === undefined) return { status: "signed-out" };
    return {
      status: "ready",
      admin: this.#admin !== undefined,
      expiresAt: this.#admin?.expiresAt ?? this.#authz.expiresAt,
    };
  }

  /** Calls `listener` on every change of {@link state}. Returns an unsubscribe. */
  subscribe(listener: (s: SessionState) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async token(audience: TokenAudience, signal?: AbortSignal): Promise<string> {
    if (this.#closed) throw new SignedOutError("the session was signed out");
    if (!this.#fresh(this.#authz)) {
      await this.#refresh(this.#authz === undefined ? this.#why : "expiring", signal);
    }
    if (audience === "authz") return this.#must(this.#authz).token;
    if (this.#stepUp !== undefined) throw this.#stepUp;
    if (!this.#fresh(this.#admin)) {
      try {
        await this.#exchangeAdmin(signal);
      } catch (e) {
        // A Tutela token refused as a subject (a raised epoch): start again
        // from upstream, once.
        if (
          !(e instanceof TokenExchangeError) ||
          e instanceof StepUpRequiredError ||
          e.error !== "invalid_grant"
        ) {
          throw e;
        }
        this.#authz = undefined;
        await this.#refresh("rejected", signal);
        await this.#exchangeAdmin(signal);
      }
    }
    return this.#must(this.#admin).token;
  }

  rejected(audience: TokenAudience, token: string): boolean {
    if (audience === "admin" && this.#admin?.token === token) {
      this.#admin = undefined;
    }
    if (this.#authz?.token === token || audience === "admin") {
      // A refused admin token usually means a raised epoch: the authz token
      // it came from is refused too. Start again from upstream.
      this.#authz = undefined;
      this.#admin = undefined;
      this.#why = "rejected";
    }
    this.#emit();
    return !this.#closed;
  }

  /**
   * Starts again after the person did MFA at the identity provider: the
   * next upstream token (asked with reason `step-up`) must carry the
   * step-up `acr`.
   */
  async stepUp(signal?: AbortSignal): Promise<void> {
    if (this.#closed) throw new SignedOutError("the session was signed out");
    this.#stepUp = undefined;
    this.#authz = undefined;
    this.#admin = undefined;
    await this.#refresh("step-up", signal);
    await this.#exchangeAdmin(signal);
  }

  /** Forgets every token. The session cannot be used again. */
  signOut(): void {
    this.#closed = true;
    this.#authz = undefined;
    this.#admin = undefined;
    this.#stepUp = undefined;
    this.#used.clear();
    this.#emit();
  }

  #fresh(h: Held | undefined): h is Held {
    return h !== undefined && h.expiresAt - this.#margin > this.#now();
  }

  #must(h: Held | undefined): Held {
    if (h === undefined) throw new SignedOutError("no token");
    return h;
  }

  #emit(): void {
    const next = this.#compute();
    const prev = this.#snapshot;
    if (JSON.stringify(next) === JSON.stringify(prev)) return;
    this.#snapshot = next;
    for (const l of this.#listeners) l(next);
  }

  /** One upstream exchange at a time; callers that come meanwhile wait for it. */
  async #refresh(reason: UpstreamReason, signal?: AbortSignal): Promise<void> {
    this.#pending ??= this.#doRefresh(reason, signal).finally(() => {
      this.#pending = undefined;
    });
    return this.#pending;
  }

  async #doRefresh(reason: UpstreamReason, signal?: AbortSignal): Promise<void> {
    const upstream = await this.#getUpstream(reason);
    const claims = payload(upstream);
    const mark = typeof claims.jti === "string" ? `jti:${claims.jti}` : `tok:${upstream}`;
    this.#prune();
    if (this.#used.has(mark)) {
      throw new UpstreamTokenReusedError(
        "the upstream token was exchanged before; refresh it at the identity provider",
      );
    }
    // Marked before it is sent: a lost answer may still have used it.
    this.#used.set(
      mark,
      typeof claims.exp === "number" ? claims.exp * 1000 : this.#now() + 3_600_000,
    );
    const authz = await this.#exchange(upstream, this.#authzAudience, signal);
    if (this.#closed) throw new SignedOutError("the session was signed out");
    // Never past the token it came from.
    if (typeof claims.exp === "number") {
      authz.expiresAt = Math.min(authz.expiresAt, claims.exp * 1000);
    }
    this.#authz = authz;
    this.#admin = undefined;
    this.#why = "expiring";
    this.#emit();
  }

  async #exchangeAdmin(signal?: AbortSignal): Promise<void> {
    this.#pendingAdmin ??= this.#doExchangeAdmin(signal).finally(() => {
      this.#pendingAdmin = undefined;
    });
    return this.#pendingAdmin;
  }

  async #doExchangeAdmin(signal?: AbortSignal): Promise<void> {
    if (!this.#fresh(this.#authz)) await this.#refresh("expiring", signal);
    const source = this.#must(this.#authz);
    try {
      const admin = await this.#exchange(source.token, ADMIN_AUDIENCE, signal);
      admin.expiresAt = Math.min(admin.expiresAt, source.expiresAt);
      if (this.#closed) throw new SignedOutError("the session was signed out");
      this.#admin = admin;
      this.#stepUp = undefined;
    } catch (e) {
      if (e instanceof StepUpRequiredError) this.#stepUp = e;
      throw e;
    } finally {
      this.#emit();
    }
  }

  /** `POST /oauth2/token`, token exchange, no client authentication. */
  async #exchange(subject: string, audience: string, signal?: AbortSignal): Promise<Held> {
    const sent = this.#now();
    const call = {
      method: "POST" as const,
      path: "/oauth2/token",
      form: {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subject,
        subject_token_type: ACCESS_TOKEN,
        audience,
      },
      retry: false,
      ...(signal === undefined ? {} : { signal }),
    };
    const res = await this.#transport.raw(call);
    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      // An empty or broken body is handled below.
    }
    if (!res.ok) {
      const error = typeof body.error === "string" ? body.error : "server_error";
      const description =
        typeof body.error_description === "string" ? body.error_description : undefined;
      const after = retryAfter(res.headers);
      if (error === "invalid_grant" && description === STEP_UP) {
        throw new StepUpRequiredError(res.status, error, description, after);
      }
      throw new TokenExchangeError(res.status, error, description, after);
    }
    const token = body.access_token;
    const expiresIn = body.expires_in;
    if (typeof token !== "string" || typeof expiresIn !== "number") {
      throw new NetworkError("the token endpoint gave no token");
    }
    const exp = payload(token).exp;
    let expiresAt = sent + expiresIn * 1000;
    if (typeof exp === "number") expiresAt = Math.min(expiresAt, exp * 1000);
    return { token, expiresAt };
  }

  #prune(): void {
    const now = this.#now();
    for (const [k, exp] of this.#used) if (exp <= now) this.#used.delete(k);
  }
}

/**
 * The claims of a JWT, read without checking it: only for when to renew and
 * which upstream token was used. `tutelad` checks every token itself.
 */
export function payload(
  jwt: string,
): Record<string, unknown> & { exp?: unknown; jti?: unknown; sub?: unknown } {
  const part = jwt.split(".")[1];
  if (part === undefined) return {};
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const v: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
