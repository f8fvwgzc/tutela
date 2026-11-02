/**
 * Typed errors. A problem document of `tutelad` (CONTRACTS.md 7.1, RFC 9457)
 * becomes a {@link ProblemError} subclass chosen by its status and code; a
 * refusal at the token endpoint (RFC 6749 5.2) becomes a
 * {@link TokenExchangeError}. A UI switches on the class or on `code`.
 *
 * No error ever holds a token. A problem's `detail` is the server's, which
 * never holds secrets or personal data.
 */

import type { ScopeRef } from "./types.js";

/** Every error this package throws. */
export class TutelaError extends Error {
  override name = "TutelaError";
}

/** The problem codes of the API (CONTRACTS.md 7.1, 7.9, 7.13). Others may come. */
export type ProblemCode =
  | "invalid_request"
  | "invalid_manifest"
  | "invalid_page"
  | "invalid_url"
  | "app_mismatch"
  | "too_many_items"
  | "unknown_key"
  | "filter_too_large"
  | "invalid_token"
  | "forbidden"
  | "unknown_tenant"
  | "approval_required"
  | "two_person_required"
  | "same_person"
  | "not_held"
  | "move_refused"
  | "not_found"
  | "version_conflict"
  | "no_change"
  | "no_source"
  | "stale_proposal"
  | "not_open"
  | "busy"
  | "exists"
  | "not_additive"
  | "last_org"
  | "refused"
  | "unavailable"
  | "stale"
  | "no_data"
  | "expired";

/** What a problem document carries. */
export interface ProblemFields {
  status: number;
  /** The `<code>` of `urn:tutela:problem:<code>`. */
  code: ProblemCode | (string & {});
  title: string;
  detail?: string | undefined;
  /** `Retry-After`, in seconds. */
  retryAfter?: number | undefined;
  /** `x-request-id` of the answer, to find it in `tutelad`'s logs. */
  requestId?: string | undefined;
}

/** A problem document from `tutelad`. */
export class ProblemError extends TutelaError {
  override name = "ProblemError";
  readonly status: number;
  readonly code: ProblemCode | (string & {});
  readonly title: string;
  readonly detail: string | undefined;
  readonly retryAfter: number | undefined;
  readonly requestId: string | undefined;

  constructor(p: ProblemFields) {
    super(p.detail ? `${p.code}: ${p.detail}` : `${p.code}: ${p.title}`);
    this.status = p.status;
    this.code = p.code;
    this.title = p.title;
    this.detail = p.detail;
    this.retryAfter = p.retryAfter;
    this.requestId = p.requestId;
  }
}

/** 400, 413, 415: the request is wrong. */
export class InvalidRequestError extends ProblemError {
  override name = "InvalidRequestError";
}

/** 401: no token, or one that does not verify. Sign in again. */
export class UnauthorizedError extends ProblemError {
  override name = "UnauthorizedError";
}

/**
 * 403: the caller may not do this (`forbidden`, `unknown_tenant`,
 * `approval_required`, `two_person_required`, `same_person`). A UI hides
 * what the person may not do.
 */
export class ForbiddenError extends ProblemError {
  override name = "ForbiddenError";
}

/**
 * 403 `not_held`: the change would give someone more than the caller holds
 * (ADR-0043). `gains` are the server's sentences, counts only, never a
 * principal: "1 user gains write on invoice in 1 scope". Offer to ask an
 * admin who holds more.
 */
export class NotHeldError extends ForbiddenError {
  override name = "NotHeldError";
  /** What would be gained, one sentence each. */
  readonly gains: string[];
  /** `true` when the check stopped at its bound and there may be more. */
  readonly incomplete: boolean;

  constructor(p: ProblemFields) {
    super(p);
    const parts = (p.detail ?? "")
      .split("; ")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    this.incomplete = parts.some((s) => s.startsWith("the check reached its bound"));
    this.gains = parts.filter((s) => !s.startsWith("the check reached its bound"));
  }
}

/**
 * 403 `move_refused`: `write_check`'s move verdict did not allow the move.
 * `waitingFor` names the scopes where an owner must agree.
 */
export class MoveRefusedError extends ForbiddenError {
  override name = "MoveRefusedError";
  /** `refused` or `needs_approval` (or `unknown` for an older server). */
  readonly outcome: "refused" | "needs_approval" | "unknown";
  /** The verdict's reason, in the server's words. */
  readonly reason: string;
  /** The scopes whose owner must agree; empty when the move is refused. */
  readonly waitingFor: ScopeRef[];

  constructor(p: ProblemFields) {
    super(p);
    const detail = p.detail ?? "";
    const [head = "", tail] = splitOnce(detail, "; an owner must agree at ");
    const [outcome, reason] = splitOnce(head, ": ");
    this.outcome = outcome === "refused" || outcome === "needs_approval" ? outcome : "unknown";
    this.reason = reason ?? head;
    this.waitingFor = (tail ?? "")
      .split(", ")
      .filter((s) => s.includes(":"))
      .map((s) => {
        const [type = "", id = ""] = splitOnce(s.trim(), ":");
        return { type, id: id ?? "" };
      });
  }
}

/** 404: not there, or of another tenant. */
export class NotFoundError extends ProblemError {
  override name = "NotFoundError";
}

/** 409: the data moved (`version_conflict`, `exists`, `busy`, …). Reload. */
export class ConflictError extends ProblemError {
  override name = "ConflictError";
}

/**
 * 503 (and 429, and any 5xx): try again after `retryAfter` seconds. Never a
 * hidden allow: the caller fails closed.
 */
export class UnavailableError extends ProblemError {
  override name = "UnavailableError";
}

/** A refusal at `POST /oauth2/token` (RFC 6749 5.2). */
export class TokenExchangeError extends TutelaError {
  override name = "TokenExchangeError";
  readonly status: number;
  /** `invalid_grant`, `invalid_request`, `invalid_target`, `invalid_client`, … */
  readonly error: string;
  readonly description: string | undefined;
  readonly retryAfter: number | undefined;

  constructor(status: number, error: string, description?: string, retryAfter?: number) {
    super(description ? `${error}: ${description}` : error);
    this.status = status;
    this.error = error;
    this.description = description;
    this.retryAfter = retryAfter;
  }
}

/**
 * The upstream token has no step-up (`TUTELA_ADMIN_ACR`): ask the identity
 * provider for MFA, then call `session.stepUp()`. The one refusal of the
 * token endpoint that says why (ADR-0032).
 */
export class StepUpRequiredError extends TokenExchangeError {
  override name = "StepUpRequiredError";
}

/** The network failed, or the request timed out. Nothing is known. */
export class NetworkError extends TutelaError {
  override name = "NetworkError";
}

/**
 * The upstream-token callback gave a token that was exchanged before. Each
 * upstream token is exchanged once (CONTRACTS.md 4.8): refresh it at the
 * identity provider first.
 */
export class UpstreamTokenReusedError extends TutelaError {
  override name = "UpstreamTokenReusedError";
}

/** The session was closed with `signOut()`. */
export class SignedOutError extends TutelaError {
  override name = "SignedOutError";
}

/** The problem error for an answer. */
export function problemError(p: ProblemFields): ProblemError {
  if (p.status === 401) return new UnauthorizedError(p);
  if (p.status === 403) {
    if (p.code === "not_held") return new NotHeldError(p);
    if (p.code === "move_refused") return new MoveRefusedError(p);
    return new ForbiddenError(p);
  }
  if (p.status === 404) return new NotFoundError(p);
  if (p.status === 409) return new ConflictError(p);
  if (p.status === 429 || p.status >= 500) return new UnavailableError(p);
  if (p.status >= 400) return new InvalidRequestError(p);
  return new ProblemError(p);
}

function splitOnce(s: string, sep: string): [string, string | undefined] {
  const i = s.indexOf(sep);
  return i < 0 ? [s, undefined] : [s.slice(0, i), s.slice(i + sep.length)];
}
