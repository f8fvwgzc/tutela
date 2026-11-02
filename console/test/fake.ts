// A fake realm and a fake tutelad behind one mocked fetch: every request is
// recorded, and each route answers from the world's state. No network.

import { webcrypto } from "node:crypto";
import type { ConsoleConfig, OidcEnv } from "../src/oidc";

export const ISS = "https://kc.example.test/realms/acme";
export const ORIGIN = "http://localhost:3000";
export const ME = "user:usr_owner";
export const ORG = { type: "org", id: "org_1" };
export const PROJECT = { type: "project", id: "p-1" };

export const CONFIG: ConsoleConfig = {
  issuer: ISS,
  client_id: "tutela-console",
  step_up_acr: "mfa",
  audience: "tutela-authz",
};

export interface Seen {
  method: string;
  url: URL;
  headers: Headers;
  form: URLSearchParams | undefined;
  json: unknown;
}

export function jwt(claims: Record<string, unknown>): string {
  const b64 = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${b64({ alg: "RS256", typ: "JWT" })}.${b64(claims)}.c2ln`;
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function problem(status: number, code: string, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify({ type: `urn:tutela:problem:${code}`, title: code, status }), {
    status,
    headers: { "content-type": "application/problem+json", ...headers },
  });
}

const ALL_KEYS = [
  "read_audit",
  "manage_access",
  "manage_fields",
  "manage_boundaries",
  "manage_agents",
  "approve_move",
];

/** The world the fake answers from. Tests change it, or add `routes`. */
export class World {
  seen: Seen[] = [];
  assigned: string[] = [];
  /** The admin keys the person holds at ORG. */
  keys = new Set(ALL_KEYS);
  /** Without it, the admin token exchange asks for step-up. */
  stepUp = true;
  nonce = "";
  /** Extra answers by "METHOD /path", tried first. */
  routes = new Map<string, (s: Seen) => Response>();
  /** 401 on every API call (a revoked session). */
  revoked = false;

  env(): OidcEnv {
    return {
      fetch: this.fetch,
      crypto: webcrypto as unknown as Crypto,
      storage: window.sessionStorage,
      origin: ORIGIN,
      assign: (url) => {
        this.assigned.push(url);
        const u = new URL(url);
        const nonce = u.searchParams.get("nonce");
        if (nonce !== null) this.nonce = nonce;
      },
    };
  }

  fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input), ORIGIN);
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? init.body : undefined;
    const type = headers.get("content-type") ?? "";
    const s: Seen = {
      method: init?.method ?? "GET",
      url,
      headers,
      form: type.startsWith("application/x-www-form-urlencoded")
        ? new URLSearchParams(body)
        : undefined,
      json:
        type.startsWith("application/json") && body !== undefined ? JSON.parse(body) : undefined,
    };
    this.seen.push(s);
    return this.answer(s);
  }) as typeof fetch;

  answer(s: Seen): Response {
    const path = s.url.origin === ORIGIN ? s.url.pathname : s.url.href.split("?")[0];
    const extra = this.routes.get(`${s.method} ${path}`);
    if (extra !== undefined) return extra(s);
    const now = Math.floor(Date.now() / 1000);
    switch (`${s.method} ${path}`) {
      case `GET ${ISS}/.well-known/openid-configuration`:
        return json(200, {
          issuer: ISS,
          authorization_endpoint: `${ISS}/auth`,
          token_endpoint: `${ISS}/token`,
          end_session_endpoint: `${ISS}/logout`,
        });
      case `POST ${ISS}/token`: {
        const acr = this.stepUp ? "mfa" : "1";
        return json(200, {
          access_token: jwt({
            iss: ISS,
            sub: "kc-owner",
            acr,
            exp: now + 300,
            jti: crypto.randomUUID(),
          }),
          refresh_token: `r-${String(this.seen.length)}`,
          id_token: jwt({ nonce: this.nonce, name: "Olivia Owner", acr }),
        });
      }
      case "POST /oauth2/token": {
        const audience = s.form?.get("audience") ?? "";
        if (audience === "tutela-admin" && !this.stepUp) {
          return json(400, {
            error: "invalid_grant",
            error_description: "step-up authentication is required",
          });
        }
        return json(200, {
          access_token: jwt({ aud: audience, exp: now + 300, sub: ME }),
          issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
          token_type: "Bearer",
          expires_in: 300,
        });
      }
    }
    if (this.revoked) return problem(401, "invalid_token");
    switch (`${s.method} ${path}`) {
      case "GET /v1/whoami":
        return json(200, { iss: ISS, tid: "ten_1", sub: ME, kind: "access", rev: 1 });
      case "POST /access/v1/search/resource":
        return json(200, { results: [ORG], page: { next_token: "" } });
      case "POST /v1/authz/permissions": {
        const actions = (s.json as { actions?: string[] }).actions ?? [];
        return json(200, {
          rev: 1,
          ui: {},
          actions: Object.fromEntries(
            actions.map((a) => [a, this.keys.has(a.split(":")[1] ?? "")]),
          ),
          fields: {},
        });
      }
    }
    return problem(404, "not_found");
  }

  /** The requests to `path` (on tutelad). */
  to(method: string, path: string): Seen[] {
    return this.seen.filter((s) => s.method === method && s.url.pathname === path);
  }
}
