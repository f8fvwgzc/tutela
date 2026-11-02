// A fake tutelad behind a mocked fetch: every request is recorded, and a
// handler answers it. No network.

export interface Seen {
  method: string;
  url: URL;
  headers: Headers;
  body: string | undefined;
  /** The form of a token-endpoint call. */
  form: URLSearchParams | undefined;
  /** The JSON body of an API call. */
  json: unknown;
}

export type Handler = (req: Seen) => Response | Promise<Response>;

export function fakeFetch(handler: Handler): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const f = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? init.body : undefined;
    const type = headers.get("content-type") ?? "";
    const req: Seen = {
      method: init?.method ?? "GET",
      url,
      headers,
      body,
      form: type.startsWith("application/x-www-form-urlencoded")
        ? new URLSearchParams(body)
        : undefined,
      json:
        type.startsWith("application/json") && body !== undefined ? JSON.parse(body) : undefined,
    };
    seen.push(req);
    return handler(req);
  };
  return { fetch: f as typeof fetch, seen };
}

export function json(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function problem(
  status: number,
  code: string,
  detail?: string,
  headers: Record<string, string> = {},
): Response {
  return new Response(
    JSON.stringify({
      type: `urn:tutela:problem:${code}`,
      title: code,
      status,
      ...(detail === undefined ? {} : { detail }),
    }),
    { status, headers: { "content-type": "application/problem+json", ...headers } },
  );
}

/** An unsigned JWT with these claims: the client only reads them. */
export function jwt(claims: Record<string, unknown>): string {
  const b64 = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${b64({ alg: "ES256", typ: "at+jwt" })}.${b64(claims)}.c2ln`;
}

/** A token endpoint that issues `<audience>-<n>` tokens of `ttl` seconds. */
export class TokenEndpoint {
  n = 0;
  stepUp = true;
  ttl: Record<string, number> = { "tutela-authz": 300, "tutela-admin": 300 };
  now: () => number = () => Date.now();

  answer(req: Seen): Response {
    const form = req.form ?? new URLSearchParams();
    const audience = form.get("audience") ?? "";
    if (audience === "tutela-admin" && !this.stepUp) {
      return json(400, {
        error: "invalid_grant",
        error_description: "step-up authentication is required",
      });
    }
    this.n++;
    const ttl = this.ttl[audience] ?? 300;
    const exp = Math.floor(this.now() / 1000) + ttl;
    return json(200, {
      access_token: jwt({ aud: audience, exp, n: this.n, sub: "user:usr_1" }),
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer",
      expires_in: ttl,
    });
  }
}
