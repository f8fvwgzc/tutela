import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { Empty, isForbidden, Notice, PageHeader, Subject, useAction, When } from "../ui";
import { OnceSecret } from "./Secret";

/** Apps of the tenant: client credentials for products. A secret is shown once. */
export function AppsPage() {
  const client = useTutela();
  const apps = useLoad("apps", (signal) => client.apps.list({ signal }));
  const action = useAction(apps.reload);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState<{ label: string; value: string } | undefined>(undefined);
  return (
    <section>
      <PageHeader
        title="Apps"
        detail="Each app has a service account and a client secret. Give its service account roles on Scopes."
      />
      {isForbidden(apps.error) ? (
        <Empty>Only the tenant's owner manages apps.</Empty>
      ) : (
        <Notice error={apps.error} onRetry={apps.reload} />
      )}
      {secret === undefined ? null : (
        <OnceSecret
          label={secret.label}
          secret={secret.value}
          onClose={() => setSecret(undefined)}
        />
      )}
      {action.status}
      <form
        className="c-toolbar"
        aria-label="New app"
        onSubmit={(e) => {
          e.preventDefault();
          void action.run("The app is made.", async () => {
            const made = await client.apps.create(name.trim());
            setSecret({ label: `Client secret of ${made.app.name}.`, value: made.client_secret });
            setName("");
          });
        }}
      >
        <label className="c-field">
          <span>Name</span>
          <input
            className="c-input"
            value={name}
            required
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <button type="submit" className="c-button c-primary" disabled={action.busy}>
          Make app
        </button>
      </form>
      <div className="c-scroll">
        <table className="c-table" aria-label="Apps">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Client id</th>
              <th scope="col">Service account</th>
              <th scope="col">Made</th>
              <th scope="col">State</th>
              <th scope="col">
                <span className="c-sr">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(apps.data ?? []).map((a) => (
              <tr key={a.client_id}>
                <th scope="row">{a.name}</th>
                <td className="c-mono">{a.client_id}</td>
                <td>
                  <Subject id={a.principal} />
                </td>
                <td>
                  <When at={a.created_at} />
                </td>
                <td>{a.disabled_at === undefined ? "Active" : "Disabled"}</td>
                <td className="c-row">
                  {a.disabled_at === undefined ? (
                    <>
                      <button
                        type="button"
                        className="c-button c-small"
                        aria-label={`Rotate the secret of ${a.name}`}
                        disabled={action.busy}
                        onClick={() =>
                          void action.run(
                            "A new secret is made; the old one works for an hour.",
                            async () => {
                              const r = await client.apps.rotate(a.client_id);
                              setSecret({
                                label: `New client secret of ${a.name}.`,
                                value: r.client_secret,
                              });
                            },
                          )
                        }
                      >
                        Rotate secret
                      </button>
                      <button
                        type="button"
                        className="c-button c-ghost c-small"
                        aria-label={`Disable ${a.name}`}
                        disabled={action.busy}
                        onClick={() =>
                          void action.run("The app is disabled.", () =>
                            client.apps.disable(a.client_id),
                          )
                        }
                      >
                        Disable
                      </button>
                    </>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {apps.data?.length === 0 ? <Empty>No app yet.</Empty> : null}
    </section>
  );
}
