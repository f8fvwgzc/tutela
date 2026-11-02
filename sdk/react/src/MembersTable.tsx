import {
  type Assignment,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  NotHeldError,
  type ScopeRef,
  UnavailableError,
} from "@f8fvwgzc/tutela-js";
import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from "react";

import { useTutela } from "./context.js";
import { ErrorNotice } from "./ErrorNotice.js";
import { useAssignments, usePermissionMap, useRoles } from "./hooks.js";
import { type Theme, themeAttr } from "./theme.js";

/** What a person asks an admin for after a `not_held` refusal. */
export interface AccessRequest {
  scope: ScopeRef;
  subject: string;
  role: string;
  expires_at?: string;
  /** The server's sentences: what the grant would give, counts only. */
  gains: string[];
}

/** The props of {@link MembersTable}. */
export interface MembersTableProps {
  /** The scope whose members are shown: an org or a registered scope. */
  scope: ScopeRef;
  /** The scope's ancestors, nearest first, the org last (`ancestors` of `GET /v1/admin/scopes`). Empty for an org. */
  path: ScopeRef[];
  /** Assignments per page. Default 50. */
  pageSize?: number;
  /** The roles offered when giving one. Default: the model's roles. */
  roles?: string[];
  /** How a subject is shown. Tutela keeps no names: the product shows its own. */
  renderSubject?: (subject: string) => ReactNode;
  /** After a `not_held` refusal: ask an admin who holds more. The button shows only when this is set. */
  onAskAdmin?: (request: AccessRequest) => void;
  /** After a step-up refusal: sign the person in again with MFA. */
  onStepUp?: () => void;
  /** Default `system`: light or dark from the browser. */
  theme?: Theme;
  className?: string;
  /** The table's accessible name. Default: "Members of <type> <id>". */
  label?: string;
}

const SUBJECT = /^(user|sa|key|agent|workload|group):\S+$/;
const MAX_WRITE_RETRY_SECS = 30;

function endOf(date: string): string {
  return new Date(`${date}T00:00:00Z`).toISOString();
}

function day(iso: string | undefined): string {
  return iso === undefined ? "" : iso.slice(0, 10);
}

function tomorrow(): string {
  return new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
}

interface Notice {
  error: unknown;
  retry?: () => void;
  request?: AccessRequest;
}

/**
 * The members of one scope, paged: who holds which role there, until when.
 * A person who may change access (`<type>:manage_access` in the permission
 * map) gives roles with an optional end, changes an end, and removes a role.
 * What the person may not do is hidden; every change is checked again by
 * `tutelad` (the narrow-only rule, ADR-0043).
 */
export function MembersTable(props: MembersTableProps) {
  const {
    scope,
    path,
    pageSize = 50,
    renderSubject,
    onAskAdmin,
    onStepUp,
    theme,
    className,
  } = props;
  const client = useTutela();
  const resource = { ...scope, path };
  const manageKey = `${scope.type}:manage_access`;
  const map = usePermissionMap(resource, [manageKey, `${scope.type}:read_audit`]);
  const members = useAssignments(scope, pageSize);
  const roles = useRoles(scope);
  const [denied, setDenied] = useState(false);
  const [notice, setNotice] = useState<Notice | undefined>(undefined);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(retryTimer.current), []);

  const canManage = map.data?.can(manageKey) === true && !denied;
  const roleKeys = props.roles ?? roles.data?.roles.map((r) => r.key) ?? [];

  async function write(
    what: string,
    fn: () => Promise<unknown>,
    request?: AccessRequest,
  ): Promise<boolean> {
    clearTimeout(retryTimer.current);
    setBusy(true);
    setNotice(undefined);
    setStatus("");
    try {
      await fn();
      setStatus(what);
      members.reload();
      return true;
    } catch (e) {
      if (e instanceof ForbiddenError && !(e instanceof NotHeldError) && e.code === "forbidden") {
        // The map said yes, the server says no: hide the controls.
        setDenied(true);
      }
      if (e instanceof ConflictError || e instanceof NotFoundError) members.reload();
      const again = () => {
        void write(what, fn, request);
      };
      if (e instanceof UnavailableError) {
        const secs = Math.min(e.retryAfter ?? 1, MAX_WRITE_RETRY_SECS);
        retryTimer.current = setTimeout(again, secs * 1000);
      }
      const n: Notice = { error: e };
      if (e instanceof UnavailableError) n.retry = again;
      if (e instanceof NotHeldError && request !== undefined)
        n.request = { ...request, gains: e.gains };
      setNotice(n);
      return false;
    } finally {
      setBusy(false);
    }
  }

  const label = props.label ?? `Members of ${scope.type} ${scope.id}`;
  const listError = members.error;

  return (
    <div className={`tutela tutela-members ${className ?? ""}`} {...themeAttr(theme)}>
      <p className="tutela-sr" role="status" aria-live="polite">
        {status}
      </p>
      {listError instanceof ForbiddenError ? (
        <p className="tutela-empty">You can't see who has access here.</p>
      ) : (
        <>
          {canManage ? (
            <AssignForm
              roles={roleKeys}
              rolesInfo={roles.data?.roles}
              busy={busy}
              onAssign={(subject, role, ends) => {
                const body = {
                  subject,
                  role,
                  scope,
                  ...(ends === "" ? {} : { expires_at: endOf(ends) }),
                };
                return write("Role given.", () => client.assignments.assign(body), {
                  ...body,
                  gains: [],
                });
              }}
            />
          ) : null}
          {notice === undefined ? null : (
            <ErrorNotice
              error={notice.error}
              onRetry={notice.retry}
              onAskAdmin={
                notice.request !== undefined && onAskAdmin !== undefined
                  ? () => onAskAdmin(notice.request as AccessRequest)
                  : undefined
              }
              onStepUp={onStepUp}
              onDismiss={() => setNotice(undefined)}
            />
          )}
          {listError !== undefined && !(listError instanceof ForbiddenError) ? (
            <ErrorNotice error={listError} onRetry={members.reload} onStepUp={onStepUp} />
          ) : null}
          <div className="tutela-table-wrap">
            <table className="tutela-table" aria-label={label} aria-busy={members.loading}>
              <thead>
                <tr>
                  <th scope="col">Member</th>
                  <th scope="col">Role</th>
                  <th scope="col">Ends</th>
                  <th scope="col">Given by</th>
                  {canManage ? (
                    <th scope="col" className="tutela-actions-col">
                      <span className="tutela-sr">Actions</span>
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {members.data?.map((a) => (
                  <MemberRow
                    key={a.id}
                    a={a}
                    canManage={canManage}
                    busy={busy}
                    renderSubject={renderSubject}
                    onExpiry={(ends) =>
                      write(
                        "End changed.",
                        () =>
                          client.assignments.setExpiry(a.id, ends === null ? null : endOf(ends)),
                        {
                          scope,
                          subject: a.subject,
                          role: a.role,
                          ...(ends === null ? {} : { expires_at: endOf(ends) }),
                          gains: [],
                        },
                      )
                    }
                    onRemove={() => write("Role removed.", () => client.assignments.unassign(a.id))}
                  />
                ))}
                {members.data !== undefined && members.data.length === 0 ? (
                  <tr>
                    <td colSpan={canManage ? 5 : 4} className="tutela-empty">
                      Nobody holds a role here yet.
                    </td>
                  </tr>
                ) : null}
                {members.data === undefined && members.loading ? (
                  <tr>
                    <td colSpan={canManage ? 5 : 4} className="tutela-muted">
                      Loading…
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          {members.hasMore ? (
            <div className="tutela-footer">
              <button
                type="button"
                className="tutela-button tutela-ghost"
                onClick={members.loadMore}
                disabled={members.loadingMore}
              >
                {members.loadingMore ? "Loading…" : "Load more"}
              </button>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

interface RowProps {
  a: Assignment;
  canManage: boolean;
  busy: boolean;
  renderSubject: ((s: string) => ReactNode) | undefined;
  onExpiry: (ends: string | null) => Promise<boolean>;
  onRemove: () => Promise<boolean>;
}

function MemberRow({ a, canManage, busy, renderSubject, onExpiry, onRemove }: RowProps) {
  const [mode, setMode] = useState<"view" | "end" | "remove">("view");
  const [ends, setEnds] = useState(day(a.expires_at));
  const id = useId();
  const who =
    renderSubject === undefined ? (
      <code className="tutela-mono">{a.subject}</code>
    ) : (
      renderSubject(a.subject)
    );
  return (
    <tr>
      <td>{who}</td>
      <td>{a.role}</td>
      <td className="tutela-num">
        {mode === "end" ? (
          <span className="tutela-inline">
            <label className="tutela-sr" htmlFor={`${id}-end`}>
              New end for {a.subject}
            </label>
            <input
              id={`${id}-end`}
              className="tutela-input"
              type="date"
              min={tomorrow()}
              value={ends}
              onChange={(e) => setEnds(e.target.value)}
            />
          </span>
        ) : a.expires_at === undefined ? (
          <span className="tutela-muted">No end</span>
        ) : (
          <time dateTime={a.expires_at}>{day(a.expires_at)}</time>
        )}
      </td>
      <td>
        {a.granted_by === undefined ? (
          <span className="tutela-muted">—</span>
        ) : renderSubject === undefined ? (
          <code className="tutela-mono">{a.granted_by}</code>
        ) : (
          renderSubject(a.granted_by)
        )}
      </td>
      {canManage ? (
        <td className="tutela-actions">
          {mode === "view" ? (
            <>
              <button
                type="button"
                className="tutela-button tutela-ghost"
                disabled={busy}
                aria-label={`Change end of ${a.role} for ${a.subject}`}
                onClick={() => setMode("end")}
              >
                Change end
              </button>
              <button
                type="button"
                className="tutela-button tutela-ghost"
                disabled={busy}
                aria-label={`Remove ${a.role} from ${a.subject}`}
                onClick={() => setMode("remove")}
              >
                Remove
              </button>
            </>
          ) : null}
          {mode === "end" ? (
            <>
              <button
                type="button"
                className="tutela-button tutela-primary"
                disabled={busy || ends === ""}
                onClick={async () => {
                  if (await onExpiry(ends)) setMode("view");
                }}
              >
                Save end
              </button>
              <button
                type="button"
                className="tutela-button tutela-ghost"
                disabled={busy}
                onClick={async () => {
                  if (await onExpiry(null)) setMode("view");
                }}
              >
                No end
              </button>
              <button
                type="button"
                className="tutela-button tutela-ghost"
                onClick={() => setMode("view")}
              >
                Cancel
              </button>
            </>
          ) : null}
          {mode === "remove" ? (
            <>
              <span className="tutela-muted">Remove {a.role}?</span>
              <button
                type="button"
                className="tutela-button tutela-danger"
                disabled={busy}
                onClick={async () => {
                  if (!(await onRemove())) setMode("view");
                }}
              >
                Remove
              </button>
              <button
                type="button"
                className="tutela-button tutela-ghost"
                onClick={() => setMode("view")}
              >
                Cancel
              </button>
            </>
          ) : null}
        </td>
      ) : null}
    </tr>
  );
}

interface AssignFormProps {
  roles: string[];
  rolesInfo: { key: string; assignable_to: string[]; label?: string }[] | undefined;
  busy: boolean;
  onAssign: (subject: string, role: string, ends: string) => Promise<boolean>;
}

function AssignForm({ roles, rolesInfo, busy, onAssign }: AssignFormProps) {
  const id = useId();
  const [subject, setSubject] = useState("");
  const [role, setRole] = useState("");
  const [ends, setEnds] = useState("");
  const [invalid, setInvalid] = useState(false);
  const kind = subject.split(":")[0] ?? "";
  const offered = roles.filter((r) => {
    const info = rolesInfo?.find((x) => x.key === r);
    return info === undefined || !SUBJECT.test(subject) || info.assignable_to.includes(kind);
  });
  // The most powerful role is never the one picked by default.
  offered.sort((a, b) => Number(a === "owner") - Number(b === "owner"));
  const chosen = offered.includes(role) ? role : (offered[0] ?? "");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!SUBJECT.test(subject.trim())) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    if (await onAssign(subject.trim(), chosen, ends)) {
      setSubject("");
      setEnds("");
    }
  };
  return (
    <form className="tutela-toolbar" onSubmit={submit} aria-label="Give a role">
      <span className="tutela-field">
        <label htmlFor={`${id}-who`}>Member</label>
        <input
          id={`${id}-who`}
          className="tutela-input tutela-mono"
          value={subject}
          placeholder="user:usr_… or group:key"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={invalid}
          aria-describedby={invalid ? `${id}-who-err` : undefined}
          onChange={(e) => setSubject(e.target.value)}
        />
      </span>
      <span className="tutela-field">
        <label htmlFor={`${id}-role`}>Role</label>
        <select
          id={`${id}-role`}
          className="tutela-input"
          value={chosen}
          onChange={(e) => setRole(e.target.value)}
        >
          {offered.map((r) => (
            <option key={r} value={r}>
              {rolesInfo?.find((x) => x.key === r)?.label ?? r}
            </option>
          ))}
        </select>
      </span>
      <span className="tutela-field">
        <label htmlFor={`${id}-ends`}>Ends (UTC, optional)</label>
        <input
          id={`${id}-ends`}
          className="tutela-input"
          type="date"
          min={tomorrow()}
          value={ends}
          onChange={(e) => setEnds(e.target.value)}
        />
      </span>
      <button
        type="submit"
        className="tutela-button tutela-primary"
        disabled={busy || chosen === ""}
      >
        Give role
      </button>
      {invalid ? (
        <span id={`${id}-who-err`} className="tutela-field-error">
          A member is a principal (user:usr_…) or a group (group:key).
        </span>
      ) : null}
    </form>
  );
}
