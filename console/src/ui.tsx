// Small pieces every page shares: the Console's context, a page header,
// an action runner that turns answers into notices (ROADMAP notes for
// part 4b: forbidden hides, not_held explains, 409 reloads, 503 retries).

import { ConflictError, ForbiddenError, type ScopeRef } from "@f8fvwgzc/tutela-js";
import { ErrorNotice, type Theme } from "@f8fvwgzc/tutela-react";
import { createContext, type ReactNode, useCallback, useContext, useState } from "react";
import type { Access } from "./access";

export interface ConsoleContext {
  access: Access;
  theme: Theme;
  /** Signs in again at the realm with MFA, back to this page. */
  stepUp: () => void;
}

const Ctx = createContext<ConsoleContext | undefined>(undefined);
export const ConsoleProvider = Ctx.Provider;

export function useConsole(): ConsoleContext {
  const c = useContext(Ctx);
  if (c === undefined) throw new Error("useConsole needs a ConsoleProvider");
  return c;
}

export function scopeText(s: ScopeRef): string {
  return `${s.type}:${s.id}`;
}

export function PageHeader(props: { title: string; detail?: ReactNode; children?: ReactNode }) {
  return (
    <header className="c-page-head">
      <div>
        <h1 className="c-title">{props.title}</h1>
        {props.detail === undefined ? null : <p className="c-muted">{props.detail}</p>}
      </div>
      {props.children === undefined ? null : <div className="c-actions">{props.children}</div>}
    </header>
  );
}

export function Empty(props: { children: ReactNode }) {
  return <p className="c-empty">{props.children}</p>;
}

/** `true` when an error means "you may not": the page hides what it guards. */
export function isForbidden(e: unknown): boolean {
  return e instanceof ForbiddenError && e.code === "forbidden";
}

/** A notice for an error, with step-up and retry wired. */
export function Notice(props: { error: unknown; onRetry?: () => void; onDismiss?: () => void }) {
  const { stepUp } = useConsole();
  if (props.error === undefined) return null;
  return (
    <ErrorNotice
      error={props.error}
      onStepUp={stepUp}
      {...(props.onRetry === undefined ? {} : { onRetry: props.onRetry })}
      {...(props.onDismiss === undefined ? {} : { onDismiss: props.onDismiss })}
    />
  );
}

/**
 * Runs one change at a time. A success says so politely; a refusal becomes
 * a notice; a 409 reloads the page's data (it moved).
 */
export function useAction(reload?: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(undefined);
  const [done, setDone] = useState("");
  const run = useCallback(
    async (what: string, change: () => Promise<unknown>): Promise<boolean> => {
      setBusy(true);
      setError(undefined);
      setDone("");
      try {
        await change();
        setDone(what);
        reload?.();
        return true;
      } catch (e) {
        setError(e);
        if (e instanceof ConflictError) reload?.();
        return false;
      } finally {
        setBusy(false);
      }
    },
    [reload],
  );
  const status = (
    <>
      <p className="c-sr" role="status" aria-live="polite">
        {done}
      </p>
      <Notice error={error} onDismiss={() => setError(undefined)} />
    </>
  );
  return { busy, run, status, done, error };
}

/** A principal or group as written, in mono; the person's own id says so. */
export function Subject(props: { id: string }) {
  const { access } = useConsole();
  const me = access.me?.sub === props.id;
  return (
    <span className="c-mono">
      {props.id}
      {me ? <span className="c-muted"> (you)</span> : null}
    </span>
  );
}

/** A time from the API, in the person's locale, with the exact value on hover. */
export function When(props: { at: string | undefined }) {
  if (props.at === undefined) return <span className="c-muted">–</span>;
  const d = new Date(props.at);
  return (
    <time dateTime={props.at} title={props.at}>
      {Number.isNaN(d.getTime()) ? props.at : d.toLocaleString()}
    </time>
  );
}
