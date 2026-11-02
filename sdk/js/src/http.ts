/**
 * One HTTP call to `tutelad`: a timeout, problem documents turned into typed
 * errors, and a bounded retry on 503 that honours `Retry-After`.
 *
 * Only `fetch`, `URL`, `Headers` and `AbortSignal`: the same code runs in a
 * browser and in Node 22.
 */

import { NetworkError, type ProblemError, problemError } from "./errors.js";

/** How the client reaches `tutelad`. */
export interface TransportOptions {
  /**
   * `tutelad`'s API address, for example `https://tutela.example.com`, or a
   * path of the page's own origin (`/tutela`) when the product proxies it.
   */
  baseUrl: string;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Per request, in milliseconds. Default 15000. */
  timeoutMs?: number;
  /**
   * Retries of a 503 for a request that is safe to send again. Default 2;
   * 0 turns retrying off.
   */
  maxRetries?: number;
  /**
   * The longest `Retry-After` the client waits by itself, in seconds.
   * Default 5. A longer one is thrown as an `UnavailableError` for the UI.
   */
  maxRetryAfterSecs?: number;
  /**
   * `credentials` of every fetch. Default `"omit"`: bearer tokens only, so no
   * cookie of the page's origin is ever sent. A product that proxies
   * `tutelad` behind its own session may set `"same-origin"`.
   */
  credentials?: RequestCredentials;
  /** Waits; tests replace it. */
  sleep?: (ms: number) => Promise<void>;
}

/** One request. */
export interface Call {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** The path, starting with `/`. Never holds a principal or a token. */
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  /** Sent as JSON. */
  json?: unknown;
  /** Sent as `application/x-www-form-urlencoded`. */
  form?: Record<string, string>;
  /** `Authorization: Bearer …`. */
  token?: string;
  headers?: Record<string, string>;
  /** `true` when sending it twice does no harm (a read, or a write the server refuses twice). */
  retry: boolean;
  signal?: AbortSignal;
}

/** An answer that was not an error. */
export interface Answer {
  status: number;
  headers: Headers;
  /** The parsed JSON body; `undefined` for 304 or an empty body. */
  body: unknown;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_RETRIES = 2;
const DEFAULT_MAX_RETRY_AFTER = 5;

/** The HTTP side of the client. */
export class Transport {
  readonly #base: URL;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #maxRetryAfter: number;
  readonly #credentials: RequestCredentials;
  readonly #sleep: (ms: number) => Promise<void>;

  constructor(o: TransportOptions) {
    const page = (globalThis as { location?: { href?: string } }).location?.href;
    const base = o.baseUrl.endsWith("/") ? o.baseUrl : `${o.baseUrl}/`;
    this.#base = page === undefined ? new URL(base) : new URL(base, page);
    if (this.#base.username !== "" || this.#base.password !== "") {
      throw new TypeError("baseUrl must not hold credentials");
    }
    const f = o.fetch ?? globalThis.fetch;
    if (typeof f !== "function") {
      throw new TypeError("no fetch: pass one in the options");
    }
    this.#fetch = f.bind(globalThis);
    this.#timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxRetries = o.maxRetries ?? DEFAULT_RETRIES;
    this.#maxRetryAfter = o.maxRetryAfterSecs ?? DEFAULT_MAX_RETRY_AFTER;
    this.#credentials = o.credentials ?? "omit";
    this.#sleep = o.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  /** The URL of `path` under the base. */
  url(path: string, query?: Call["query"]): URL {
    const u = new URL(path.replace(/^\//, ""), this.#base);
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined) u.searchParams.set(k, String(v));
    }
    return u;
  }

  /**
   * Sends `call`. A 2xx or a 304 is an {@link Answer}; anything else throws
   * a {@link ProblemError}, or a {@link NetworkError} when nothing came back.
   */
  async send(call: Call): Promise<Answer> {
    for (let attempt = 0; ; attempt++) {
      const res = await this.#once(call);
      if (res.ok || res.status === 304) {
        return { status: res.status, headers: res.headers, body: await readJson(res) };
      }
      const err = await toProblem(res);
      const wait = err.retryAfter ?? 1;
      const again =
        call.retry &&
        err.status === 503 &&
        attempt < this.#maxRetries &&
        wait <= this.#maxRetryAfter &&
        !(call.signal?.aborted ?? false);
      if (!again) throw err;
      await this.#sleep(wait * 1000);
    }
  }

  /** Sends `call` once and returns the response as it is. */
  async raw(call: Call): Promise<Response> {
    return this.#once(call);
  }

  async #once(call: Call): Promise<Response> {
    const headers = new Headers(call.headers);
    headers.set("accept", "application/json, application/problem+json");
    if (call.token !== undefined) headers.set("authorization", `Bearer ${call.token}`);
    let body: string | undefined;
    if (call.form !== undefined) {
      headers.set("content-type", "application/x-www-form-urlencoded");
      body = new URLSearchParams(call.form).toString();
    } else if (call.json !== undefined) {
      headers.set("content-type", "application/json");
      body = JSON.stringify(call.json);
    }
    const signals = [AbortSignal.timeout(this.#timeoutMs)];
    if (call.signal !== undefined) signals.push(call.signal);
    const init: RequestInit = {
      method: call.method,
      headers,
      credentials: this.#credentials,
      redirect: "error",
      cache: "no-store",
      signal: signals.length === 1 ? (signals[0] ?? null) : AbortSignal.any(signals),
    };
    if (body !== undefined) init.body = body;
    try {
      return await this.#fetch(this.url(call.path, call.query), init);
    } catch (e) {
      if (call.signal?.aborted) throw call.signal.reason;
      throw new NetworkError(`${call.method} ${call.path} failed`, { cause: e });
    }
  }
}

async function readJson(res: Response): Promise<unknown> {
  if (res.status === 204 || res.status === 304) return undefined;
  const text = await res.text();
  if (text.length === 0) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** `Retry-After` in whole seconds: a number, or an HTTP date. */
export function retryAfter(h: Headers): number | undefined {
  const v = h.get("retry-after");
  if (v === null) return undefined;
  if (/^\d+$/.test(v.trim())) return Number.parseInt(v.trim(), 10);
  const at = Date.parse(v);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - Date.now()) / 1000));
}

const FALLBACK_CODES: Record<number, string> = {
  400: "invalid_request",
  401: "invalid_token",
  403: "forbidden",
  404: "not_found",
  409: "conflict",
  413: "invalid_request",
  415: "invalid_request",
  429: "unavailable",
  503: "unavailable",
};

/** The typed error of a refused answer. */
export async function toProblem(res: Response): Promise<ProblemError> {
  const body = (await readJson(res)) as
    | { type?: unknown; title?: unknown; detail?: unknown; status?: unknown }
    | undefined;
  const type = typeof body?.type === "string" ? body.type : "";
  const code = type.startsWith("urn:tutela:problem:")
    ? type.slice("urn:tutela:problem:".length)
    : (FALLBACK_CODES[res.status] ?? (res.status >= 500 ? "unavailable" : "invalid_request"));
  return problemError({
    status: res.status,
    code,
    title: typeof body?.title === "string" ? body.title : res.statusText,
    detail: typeof body?.detail === "string" ? body.detail : undefined,
    retryAfter: retryAfter(res.headers),
    requestId: res.headers.get("x-request-id") ?? undefined,
  });
}
