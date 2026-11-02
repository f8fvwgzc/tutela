import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { ADMIN_KEYS, holds } from "../access";
import { Empty, isForbidden, Notice, PageHeader, useAction, useConsole, When } from "../ui";

/** The tenant (its name, a soft delete) and its orgs. */
export function TenantPage() {
  const client = useTutela();
  const { access } = useConsole();
  const owner = ADMIN_KEYS.every((k) => holds(access, k, "every"));
  const data = useLoad("tenant", async (signal) => {
    const [tenant, orgs] = await Promise.all([
      client.tenant.get({ signal }),
      client.orgs.list({ signal }),
    ]);
    return { tenant, orgs };
  });
  const action = useAction(data.reload);
  const [name, setName] = useState<string | undefined>(undefined);
  const [orgName, setOrgName] = useState("");
  const [confirm, setConfirm] = useState("");
  if (isForbidden(data.error)) {
    return (
      <section>
        <PageHeader title="Tenant and orgs" />
        <Empty>You may not see the tenant.</Empty>
      </section>
    );
  }
  const t = data.data?.tenant;
  return (
    <section>
      <PageHeader title="Tenant and orgs" detail={t?.name ?? t?.tid} />
      <Notice error={data.error} onRetry={data.reload} />
      {action.status}
      {t === undefined ? null : (
        <dl className="c-facts">
          <dt>Tenant id</dt>
          <dd className="c-mono">{t.tid}</dd>
          <dt>Issuer</dt>
          <dd className="c-mono">{t.iss}</dd>
          <dt>Made</dt>
          <dd>
            <When at={t.created_at} />
          </dd>
          {t.purge_after === undefined ? null : (
            <>
              <dt>Purged after</dt>
              <dd>
                <When at={t.purge_after} />
              </dd>
            </>
          )}
        </dl>
      )}
      {owner && t !== undefined ? (
        <form
          className="c-toolbar"
          aria-label="Rename the tenant"
          onSubmit={(e) => {
            e.preventDefault();
            const n = (name ?? "").trim();
            void action.run("The tenant is renamed.", () =>
              client.tenant.rename(n === "" ? null : n),
            );
          }}
        >
          <label className="c-field">
            <span>Name</span>
            <input
              className="c-input"
              value={name ?? t.name ?? ""}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <button type="submit" className="c-button" disabled={action.busy}>
            Rename
          </button>
        </form>
      ) : null}

      <h2 className="c-h2">Orgs</h2>
      {owner ? (
        <form
          className="c-toolbar"
          aria-label="New org"
          onSubmit={(e) => {
            e.preventDefault();
            const n = orgName.trim();
            void action
              .run("The org is made; you own it.", () =>
                client.orgs.create(n === "" ? undefined : n),
              )
              .then((ok) => ok && setOrgName(""));
          }}
        >
          <label className="c-field">
            <span>Name (optional)</span>
            <input
              className="c-input"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
            />
          </label>
          <button type="submit" className="c-button" disabled={action.busy}>
            Make org
          </button>
        </form>
      ) : null}
      <div className="c-scroll">
        <table className="c-table" aria-label="Orgs">
          <thead>
            <tr>
              <th scope="col">Org</th>
              <th scope="col">Name</th>
              <th scope="col">Made</th>
              <th scope="col">State</th>
              <th scope="col">
                <span className="c-sr">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(data.data?.orgs ?? []).map((o) => (
              <tr key={o.org}>
                <th scope="row" className="c-mono">
                  {o.org}
                </th>
                <td>{o.name ?? "–"}</td>
                <td>
                  <When at={o.created_at} />
                </td>
                <td>{o.deleted_at === undefined ? "Live" : "Deleted"}</td>
                <td>
                  {!owner ? null : o.deleted_at === undefined ? (
                    <button
                      type="button"
                      className="c-button c-ghost c-small"
                      aria-label={`Delete org ${o.org}`}
                      disabled={action.busy}
                      onClick={() =>
                        void action.run(
                          "The org is deleted; it can be restored until the purge.",
                          () => client.orgs.delete(o.org),
                        )
                      }
                    >
                      Delete
                    </button>
                  ) : o.purged_at === undefined ? (
                    <button
                      type="button"
                      className="c-button c-small"
                      aria-label={`Restore org ${o.org}`}
                      disabled={action.busy}
                      onClick={() =>
                        void action.run("The org is restored.", () => client.orgs.restore(o.org))
                      }
                    >
                      Restore
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {owner && t !== undefined && t.purge_after === undefined ? (
        <section className="c-danger-zone" aria-labelledby="delete-tenant">
          <h2 id="delete-tenant" className="c-h2">
            Delete the tenant
          </h2>
          <p className="c-muted">
            Every decision is refused at once. The data is purged after the grace period; until then
            the operator can restore it.
          </p>
          <form
            className="c-toolbar"
            onSubmit={(e) => {
              e.preventDefault();
              if (confirm !== t.tid) return;
              void action.run("The tenant is deleted.", () => client.tenant.delete());
            }}
          >
            <label className="c-field c-grow">
              <span>Type the tenant id to confirm</span>
              <input
                className="c-input c-mono"
                value={confirm}
                autoComplete="off"
                onChange={(e) => setConfirm(e.target.value)}
              />
            </label>
            <button
              type="submit"
              className="c-button c-danger"
              disabled={action.busy || confirm !== t.tid}
            >
              Delete tenant
            </button>
          </form>
        </section>
      ) : null}
    </section>
  );
}
