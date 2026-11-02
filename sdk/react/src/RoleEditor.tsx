import {
  ConflictError,
  draftOf,
  ForbiddenError,
  impactSentences,
  type MatrixRow,
  type ModelChange,
  ModelEditError,
  type Proposal,
  type PublishResult,
  permissionMatrix,
  type Role,
  type RoleDraft,
  setRoleGrants,
} from "@f8fvwgzc/tutela-js";
import { Fragment, useEffect, useId, useMemo, useState } from "react";

import { CellInput } from "./cells.js";
import { useTutela } from "./context.js";
import { ErrorNotice } from "./ErrorNotice.js";
import { useModel, useRoles } from "./hooks.js";
import { type Theme, themeAttr } from "./theme.js";

/** What a RoleEditor did. */
export type RoleEditorResult =
  | { kind: "published"; result: PublishResult }
  | { kind: "proposed"; proposal: Proposal };

/** The props of {@link RoleEditor}. */
export interface RoleEditorProps {
  /** The role's key. A key the model does not have makes a new role. */
  roleKey: string;
  /** Where to start, for example a draft from {@link PermissionMatrix}'s editable mode. */
  draft?: RoleDraft;
  /** Show field, feature, action and admin-key rows. Default `true`. */
  detail?: boolean;
  onDone?: (r: RoleEditorResult) => void;
  onCancel?: () => void;
  onStepUp?: () => void;
  theme?: Theme;
  className?: string;
}

const EMPTY: RoleDraft = { key: "", levels: {}, field_levels: {}, grants: [] };

/**
 * One role's levels, field levels and grants. A role change is a model
 * change: the editor rewrites the role in the tenant's active model, shows
 * `POST /v1/models/impact` as plain sentences ("12 users gain read on
 * contract"), asks for an approval token when the change widens, and then
 * publishes with `expected_version`, or proposes it when the tenant needs
 * two people (ADR-0029).
 */
export function RoleEditor(props: RoleEditorProps) {
  const { roleKey: key, detail = true, onDone, onCancel, onStepUp, theme, className } = props;
  const client = useTutela();
  const roles = useRoles();
  const model = useModel();
  const id = useId();
  const existing: Role | undefined = roles.data?.roles.find((r) => r.key === key);
  const [draft, setDraft] = useState<RoleDraft | undefined>(props.draft);
  const [checked, setChecked] = useState<
    { change: ModelChange; source: string; expected: number } | undefined
  >();
  const [approval, setApproval] = useState("");
  const [error, setError] = useState<unknown>(undefined);
  const [busy, setBusy] = useState(false);
  const [denied, setDenied] = useState(false);
  const [done, setDone] = useState("");

  // Start from the role as the model has it, once it is loaded.
  useEffect(() => {
    if (draft === undefined && roles.data !== undefined) {
      setDraft(existing === undefined ? { ...EMPTY, key } : draftOf(existing));
    }
  }, [draft, roles.data, existing, key]);

  const rows = useMemo(() => {
    if (roles.data === undefined) return [];
    const all = permissionMatrix(roles.data).rows;
    return detail ? all : all.filter((r) => r.kind === "type");
  }, [roles.data, detail]);

  const edit = (d: RoleDraft) => {
    setDraft(d);
    setChecked(undefined);
    setDone("");
  };

  const fail = (e: unknown) => {
    setError(e);
    if (e instanceof ConflictError) {
      // The model moved: load it again and check again.
      setChecked(undefined);
      model.reload();
      roles.reload();
    }
    if (e instanceof ForbiddenError && e.code === "forbidden") setDenied(true);
    if (e instanceof ForbiddenError && e.code === "two_person_required") model.reload();
  };

  async function check() {
    if (draft === undefined || model.data === undefined) return;
    setBusy(true);
    setError(undefined);
    try {
      const source = setRoleGrants(model.data.active.source, { ...draft, key });
      const expected = model.data.active.version;
      const change = await client.models.impact({ source, expected_version: expected });
      setChecked({ change, source, expected });
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (checked === undefined || model.data === undefined) return;
    setBusy(true);
    setError(undefined);
    const widening = checked.change.class === "widening";
    const token = approval.trim();
    try {
      if (model.data.settings.two_person) {
        const proposal = await client.models.propose({
          source: checked.source,
          expected_version: checked.expected,
        });
        setDone("Proposed. Another admin approves it before it counts.");
        onDone?.({ kind: "proposed", proposal });
      } else {
        const result = await client.models.publish({
          source: checked.source,
          expected_version: checked.expected,
          ...(widening && token !== "" ? { approval: token } : {}),
        });
        setDone(`Published as version ${result.version}.`);
        onDone?.({ kind: "published", result });
      }
      setChecked(undefined);
      setApproval("");
      model.reload();
      roles.reload();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  const loadError = roles.error ?? model.error;
  const owner = key === "owner";
  const twoPerson = model.data?.settings.two_person === true;
  const widening = checked?.change.class === "widening";
  const label = existing?.label ?? key;

  return (
    <div className={`tutela tutela-role-editor ${className ?? ""}`} {...themeAttr(theme)}>
      <p className="tutela-sr" role="status" aria-live="polite">
        {done}
      </p>
      {loadError !== undefined && draft === undefined ? (
        <ErrorNotice
          error={loadError}
          onRetry={() => {
            roles.reload();
            model.reload();
          }}
          onStepUp={onStepUp}
        />
      ) : null}
      {owner ? (
        <p className="tutela-empty">
          The owner role holds everything and cannot be changed (MANIFEST.md 5.1).
        </p>
      ) : null}
      {draft === undefined ? (
        loadError === undefined ? (
          <p className="tutela-muted">Loading…</p>
        ) : null
      ) : (
        <form
          className="tutela-editor"
          aria-labelledby={`${id}-title`}
          onSubmit={(e) => {
            e.preventDefault();
            void (checked === undefined ? check() : save());
          }}
        >
          <div className="tutela-toolbar">
            <span id={`${id}-title`} className="tutela-title">
              {existing === undefined ? `New role ${key}` : `Role ${label}`}
            </span>
            {twoPerson ? <span className="tutela-muted">Two-person publish is on.</span> : null}
          </div>
          <div className="tutela-table-wrap">
            <table className="tutela-table" aria-label={`Grants of ${label}`}>
              <thead>
                <tr>
                  <th scope="col">Permission</th>
                  <th scope="col">{label}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row: MatrixRow) => (
                  <Fragment key={row.key}>
                    <tr data-kind={row.kind}>
                      <th
                        scope="row"
                        className={row.kind === "type" ? "tutela-row-type" : "tutela-row-sub"}
                      >
                        {row.kind === "type" ? row.label : row.key.slice(row.type.length + 1)}
                        {row.kind === "type" ? null : (
                          <>
                            {" "}
                            <span className="tutela-kind">
                              {row.kind === "admin" ? "admin key" : row.kind}
                            </span>
                          </>
                        )}
                      </th>
                      <td>
                        {owner || denied ? (
                          <span className="tutela-muted">—</span>
                        ) : (
                          <CellInput draft={draft} row={row} roleLabel={label} onChange={edit} />
                        )}
                      </td>
                    </tr>
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>

          {error === undefined ? null : (
            <ErrorNotice
              error={
                error instanceof ModelEditError
                  ? new Error(
                      "This role is written in a form the editor does not change. Edit the manifest by hand.",
                    )
                  : error
              }
              onRetry={() => void (checked === undefined ? check() : save())}
              onStepUp={onStepUp}
              onDismiss={() => setError(undefined)}
            />
          )}
          {error instanceof ModelEditError ? <p className="tutela-muted">{error.message}</p> : null}

          {checked === undefined ? null : (
            <section className="tutela-impact" aria-label="What this change does">
              <p className="tutela-impact-class" data-class={checked.change.class}>
                {checked.change.class === "widening"
                  ? "This change widens access."
                  : checked.change.class === "narrowing"
                    ? "This change narrows access."
                    : "This change neither widens nor narrows access."}
              </p>
              <ul className="tutela-impact-lines">
                {impactSentences(checked.change.impact).map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
              <details>
                <summary>Show the model diff</summary>
                <pre className="tutela-diff">{checked.change.diff}</pre>
              </details>
              {widening && !twoPerson ? (
                <div className="tutela-field tutela-approval">
                  <label htmlFor={`${id}-approval`}>Approval token</label>
                  <textarea
                    id={`${id}-approval`}
                    className="tutela-input tutela-mono"
                    rows={2}
                    value={approval}
                    spellCheck={false}
                    aria-describedby={`${id}-approval-help`}
                    onChange={(e) => setApproval(e.target.value)}
                  />
                  <span id={`${id}-approval-help`} className="tutela-muted">
                    A widening change needs an approver's token for this tenant, from{" "}
                    {checked.change.from.slice(0, 12)}… to {checked.change.to.slice(0, 12)}…:{" "}
                    <code className="tutela-mono">
                      tutela approve --tenant &lt;tid&gt; --from {checked.change.from} --to{" "}
                      {checked.change.to}
                    </code>
                  </span>
                </div>
              ) : null}
            </section>
          )}

          <div className="tutela-footer">
            {checked === undefined ? (
              <button
                type="submit"
                className="tutela-button tutela-primary"
                disabled={busy || owner || denied || model.data === undefined}
              >
                Check impact
              </button>
            ) : (
              <button
                type="submit"
                className="tutela-button tutela-primary"
                disabled={
                  busy ||
                  denied ||
                  (widening && !twoPerson && approval.trim() === "") ||
                  (checked.change.impact.no_impact &&
                    checked.change.class === "neutral" &&
                    checked.change.diff === "")
                }
              >
                {twoPerson ? "Propose change" : "Publish change"}
              </button>
            )}
            {onCancel === undefined ? null : (
              <button type="button" className="tutela-button tutela-ghost" onClick={onCancel}>
                Cancel
              </button>
            )}
            {done === "" ? null : <span className="tutela-muted">{done}</span>}
          </div>
        </form>
      )}
    </div>
  );
}
