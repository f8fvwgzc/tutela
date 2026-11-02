import type { Role, RoleDraft } from "@f8fvwgzc/tutela-js";
import { PermissionMatrix, RoleEditor } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { holds } from "../access";
import { PageHeader, useConsole } from "../ui";

/**
 * The permission matrix (roles × types). With `manage_access` and
 * `manage_fields` at every org, one role's column can be edited and handed
 * to the RoleEditor, which shows the impact before it publishes or proposes.
 */
export function RolesPage() {
  const { access, stepUp, theme } = useConsole();
  const canEdit =
    holds(access, "manage_access", "every") && holds(access, "manage_fields", "every");
  const [review, setReview] = useState<{ draft: RoleDraft; role: Role } | undefined>(undefined);
  const [done, setDone] = useState("");
  const [round, setRound] = useState(0);
  return (
    <section>
      <PageHeader
        title="Roles"
        detail={
          canEdit
            ? "A role change is a model change: check its impact, then publish or propose it."
            : "You can see the roles. Changing them needs manage_access and manage_fields at every org."
        }
      />
      <p className="c-sr" role="status" aria-live="polite">
        {done}
      </p>
      {review === undefined ? (
        <PermissionMatrix
          key={round}
          editable={canEdit}
          theme={theme}
          onReview={(draft, role) => {
            setDone("");
            setReview({ draft, role });
          }}
        />
      ) : (
        <RoleEditor
          roleKey={review.role.key}
          draft={review.draft}
          theme={theme}
          onStepUp={stepUp}
          onCancel={() => setReview(undefined)}
          onDone={(r) => {
            setReview(undefined);
            setRound((n) => n + 1);
            setDone(
              r.kind === "published"
                ? `Published as version ${String(r.result.version)}.`
                : "Proposed. Another person approves it on Model history.",
            );
          }}
        />
      )}
      {done === "" ? null : <p className="c-note">{done}</p>}
    </section>
  );
}
