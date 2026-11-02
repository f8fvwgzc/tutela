import {
  ConflictError,
  ForbiddenError,
  InvalidRequestError,
  MoveRefusedError,
  NetworkError,
  NotFoundError,
  NotHeldError,
  ProblemError,
  StepUpRequiredError,
  TokenExchangeError,
  UnauthorizedError,
  UnavailableError,
} from "@f8fvwgzc/tutela-js";
import { useMemo } from "react";

import { useCountdown } from "./hooks.js";

/** The props of {@link ErrorNotice}. */
export interface ErrorNoticeProps {
  error: unknown;
  /** For a 503: what to call when the person (or the countdown) tries again. */
  onRetry?: (() => void) | undefined;
  /** For `not_held`: offer to ask an admin who holds more. */
  onAskAdmin?: (() => void) | undefined;
  /** For a step-up refusal: the host signs the person in again with MFA. */
  onStepUp?: (() => void) | undefined;
  onDismiss?: (() => void) | undefined;
}

function scopeLabel(s: { type: string; id: string }): string {
  return `${s.type} ${s.id}`;
}

/** What a page says about one typed error of `@f8fvwgzc/tutela-js`. */
export function describeError(error: unknown): { title: string; body?: string; items?: string[] } {
  if (error instanceof NotHeldError) {
    return {
      title: "You can't give this much access.",
      body: "The change would give more than you hold here:",
      items: error.incomplete ? [...error.gains, "There may be more."] : error.gains,
    };
  }
  if (error instanceof MoveRefusedError) {
    if (error.outcome === "needs_approval") {
      return {
        title: "This move waits for an owner.",
        body: "An owner must agree at:",
        items: error.waitingFor.map(scopeLabel),
      };
    }
    return { title: "This move is not allowed.", body: error.reason };
  }
  if (error instanceof StepUpRequiredError) {
    return { title: "Confirm it's you.", body: "Managing access needs a sign-in with MFA." };
  }
  if (error instanceof ForbiddenError) {
    switch (error.code) {
      case "approval_required":
        return { title: "This change widens access.", body: "It needs an approval token." };
      case "two_person_required":
        return { title: "A second person must approve.", body: "Propose the change instead." };
      case "same_person":
        return { title: "Another person must approve this.", body: "You proposed it." };
      case "unknown_tenant":
        return { title: "This tenant is not known here." };
      default:
        return { title: "You don't have access to do this here." };
    }
  }
  if (error instanceof UnauthorizedError) {
    return { title: "Your sign-in ended.", body: "Sign in again." };
  }
  if (error instanceof ConflictError) {
    if (error.code === "version_conflict" || error.code === "stale_proposal") {
      return { title: "The model changed since you opened it.", body: "It was loaded again." };
    }
    if (error.code === "exists") {
      return { title: "That is there already.", body: "The list was loaded again." };
    }
    return { title: "This changed while you were looking.", body: "It was loaded again." };
  }
  if (error instanceof NotFoundError) {
    return { title: "It is no longer there." };
  }
  if (error instanceof UnavailableError) {
    return { title: "Tutela is busy." };
  }
  if (error instanceof InvalidRequestError) {
    return error.detail === undefined
      ? { title: "The request was not accepted." }
      : { title: "The request was not accepted.", body: error.detail };
  }
  if (error instanceof TokenExchangeError) {
    return { title: "Signing in to Tutela failed.", body: "Sign in again." };
  }
  if (error instanceof NetworkError) {
    return { title: "Tutela could not be reached." };
  }
  if (error instanceof ProblemError) {
    return { title: "Something went wrong.", body: error.title };
  }
  return { title: "Something went wrong." };
}

/**
 * One typed error, said plainly, with what the person can do next: ask an
 * admin who holds more (`not_held`), wait for a retry (503), sign in with
 * MFA (step-up). Announced to screen readers as an alert.
 */
export function ErrorNotice({ error, onRetry, onAskAdmin, onStepUp, onDismiss }: ErrorNoticeProps) {
  const text = describeError(error);
  const retryAt = useMemo(
    () =>
      error instanceof UnavailableError ? Date.now() + (error.retryAfter ?? 1) * 1000 : undefined,
    [error],
  );
  const left = useCountdown(retryAt);
  const tone =
    error instanceof NotHeldError ||
    error instanceof ConflictError ||
    error instanceof UnavailableError
      ? "warn"
      : "error";
  return (
    <div className="tutela-notice" data-tone={tone} role="alert">
      <div className="tutela-notice-text">
        <strong className="tutela-notice-title">{text.title}</strong>
        {text.body === undefined ? null : <span>{` ${text.body}`}</span>}
        {error instanceof UnavailableError && left > 0 ? (
          <span className="tutela-muted">{` Trying again in ${left} s.`}</span>
        ) : null}
        {text.items !== undefined && text.items.length > 0 ? (
          <ul className="tutela-notice-list">
            {text.items.map((i) => (
              <li key={i}>{i}</li>
            ))}
          </ul>
        ) : null}
      </div>
      <div className="tutela-notice-actions">
        {error instanceof NotHeldError && onAskAdmin !== undefined ? (
          <button type="button" className="tutela-button" onClick={onAskAdmin}>
            Ask an admin who holds more
          </button>
        ) : null}
        {error instanceof StepUpRequiredError && onStepUp !== undefined ? (
          <button type="button" className="tutela-button" onClick={onStepUp}>
            Sign in with MFA
          </button>
        ) : null}
        {error instanceof UnavailableError && onRetry !== undefined ? (
          <button type="button" className="tutela-button tutela-ghost" onClick={onRetry}>
            Try again now
          </button>
        ) : null}
        {onDismiss === undefined ? null : (
          <button
            type="button"
            className="tutela-button tutela-ghost tutela-icon"
            onClick={onDismiss}
            aria-label="Dismiss"
          >
            <svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.5" fill="none" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}
