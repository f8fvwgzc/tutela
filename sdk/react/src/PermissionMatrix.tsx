import {
  draftOf,
  type MatrixRow,
  permissionMatrix,
  type Role,
  type RoleDraft,
  type ScopeRef,
} from "@f8fvwgzc/tutela-js";
import { Fragment, useMemo, useState } from "react";

import { CellInput, CellView } from "./cells.js";
import { ErrorNotice } from "./ErrorNotice.js";
import { useRoles } from "./hooks.js";
import { type Theme, themeAttr } from "./theme.js";

/** The props of {@link PermissionMatrix}. */
export interface PermissionMatrixProps {
  /** The roles as seen at a scope (`GET /v1/admin/roles?scope=`); default: the tenant. */
  scope?: ScopeRef;
  /** Show field, feature, action and admin-key rows under each type. Default `true`. */
  detail?: boolean;
  /** Lets a person change one role's column and hand the change to {@link RoleEditor}. */
  editable?: boolean;
  /** In editable mode: the edited role, to review in a RoleEditor. */
  onReview?: (draft: RoleDraft, role: Role) => void;
  theme?: Theme;
  className?: string;
  /** The table's accessible name. Default "Permission matrix". */
  label?: string;
}

const KIND_LABEL: Record<MatrixRow["kind"], string> = {
  type: "type",
  field: "field",
  feature: "feature",
  action: "action",
  admin: "admin key",
};

/**
 * Roles × types, read-only from `GET /v1/admin/roles`: a type's row with its
 * fields, features, custom actions and admin keys under it. A field's level
 * is never shown above its item level. In editable mode one role's column
 * becomes inputs, and "Review change" hands the draft on: a role change is a
 * model change, made in {@link RoleEditor}.
 */
export function PermissionMatrix(props: PermissionMatrixProps) {
  const { scope, detail = true, editable = false, onReview, theme, className } = props;
  const roles = useRoles(scope);
  const matrix = useMemo(
    () => (roles.data === undefined ? undefined : permissionMatrix(roles.data)),
    [roles.data],
  );
  const [editing, setEditing] = useState<{ role: Role; draft: RoleDraft } | undefined>(undefined);

  if (roles.error !== undefined && matrix === undefined) {
    return (
      <div className={`tutela tutela-matrix ${className ?? ""}`} {...themeAttr(theme)}>
        <ErrorNotice error={roles.error} onRetry={roles.reload} />
      </div>
    );
  }
  if (matrix === undefined) {
    return (
      <div className={`tutela tutela-matrix ${className ?? ""}`} {...themeAttr(theme)}>
        <p className="tutela-muted">Loading…</p>
      </div>
    );
  }
  const rows = detail ? matrix.rows : matrix.rows.filter((r) => r.kind === "type");
  const label = (r: Role) => r.label ?? r.key;

  return (
    <div className={`tutela tutela-matrix ${className ?? ""}`} {...themeAttr(theme)}>
      <div className="tutela-table-wrap">
        <table className="tutela-table" aria-label={props.label ?? "Permission matrix"}>
          <thead>
            <tr>
              <th scope="col">Permission</th>
              {matrix.roles.map((r) => (
                <th
                  scope="col"
                  key={r.key}
                  className="tutela-role-col"
                  data-editing={editing?.role.key === r.key || undefined}
                >
                  <span className="tutela-role-head">
                    <span>{label(r)}</span>
                    {r.seeded === undefined ? null : <span className="tutela-muted"> seeded</span>}
                    {editable && editing === undefined && r.key !== "owner" ? (
                      <button
                        type="button"
                        className="tutela-button tutela-ghost tutela-small"
                        aria-label={`Edit ${label(r)}`}
                        onClick={() => setEditing({ role: r, draft: draftOf(r) })}
                      >
                        Edit
                      </button>
                    ) : null}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
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
                        <span className="tutela-kind">{KIND_LABEL[row.kind]}</span>
                      </>
                    )}
                    {row.sensitivity === "confidential" || row.sensitivity === "secret" ? (
                      <>
                        {" "}
                        <span className="tutela-kind">· {row.sensitivity}</span>
                      </>
                    ) : null}
                  </th>
                  {matrix.roles.map((r) => (
                    <td key={r.key} data-editing={editing?.role.key === r.key || undefined}>
                      {editing?.role.key === r.key ? (
                        <CellInput
                          draft={editing.draft}
                          row={row}
                          roleLabel={label(r)}
                          onChange={(draft) => setEditing({ role: r, draft })}
                        />
                      ) : (
                        <CellView cell={matrix.cell(r, row)} />
                      )}
                    </td>
                  ))}
                </tr>
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {editing === undefined ? null : (
        <div className="tutela-footer">
          <span className="tutela-muted">
            Editing {label(editing.role)}. Nothing changes until you publish.
          </span>
          <button
            type="button"
            className="tutela-button tutela-primary"
            onClick={() => onReview?.(editing.draft, editing.role)}
            disabled={onReview === undefined}
          >
            Review change
          </button>
          <button
            type="button"
            className="tutela-button tutela-ghost"
            onClick={() => setEditing(undefined)}
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}
