import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { Empty, isForbidden, Notice, PageHeader, useAction } from "../ui";
import { OnceSecret } from "./Secret";

/** Webhooks: register, rotate, disable; dead deliveries and sending one again. */
export function WebhooksPage() {
  const client = useTutela();
  const hooks = useLoad("webhooks", (signal) => client.webhooks.list({ signal }));
  const action = useAction(hooks.reload);
  const [url, setUrl] = useState("");
  const [types, setTypes] = useState("");
  const [secret, setSecret] = useState<{ label: string; value: string } | undefined>(undefined);
  const [picked, setPicked] = useState<string | undefined>(undefined);
  return (
    <section>
      <PageHeader
        title="Webhooks"
        detail="Events of the tenant, signed with Standard Webhooks. https only."
      />
      {isForbidden(hooks.error) ? (
        <Empty>You may not manage webhooks.</Empty>
      ) : (
        <Notice error={hooks.error} onRetry={hooks.reload} />
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
        aria-label="New webhook"
        onSubmit={(e) => {
          e.preventDefault();
          const list = types
            .split(",")
            .map((t) => t.trim())
            .filter((t) => t !== "");
          void action.run("The webhook is registered.", async () => {
            const made = await client.webhooks.register({
              url: url.trim(),
              ...(list.length === 0 ? {} : { types: list }),
            });
            setSecret({ label: `Signing secret of ${made.webhook.url}.`, value: made.secret });
            setUrl("");
            setTypes("");
          });
        }}
      >
        <label className="c-field c-grow">
          <span>URL</span>
          <input
            className="c-input c-mono"
            type="url"
            value={url}
            required
            placeholder="https://…"
            onChange={(e) => setUrl(e.target.value)}
          />
        </label>
        <label className="c-field">
          <span>Event types (optional, comma-separated)</span>
          <input
            className="c-input c-mono"
            value={types}
            onChange={(e) => setTypes(e.target.value)}
          />
        </label>
        <button type="submit" className="c-button c-primary" disabled={action.busy}>
          Register
        </button>
      </form>
      <div className="c-scroll">
        <table className="c-table" aria-label="Webhooks">
          <thead>
            <tr>
              <th scope="col">URL</th>
              <th scope="col">Types</th>
              <th scope="col">State</th>
              <th scope="col">
                <span className="c-sr">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(hooks.data ?? []).map((h) => (
              <tr key={h.id}>
                <th scope="row" className="c-mono">
                  {h.url}
                </th>
                <td className="c-mono">{h.types.length === 0 ? "all" : h.types.join(", ")}</td>
                <td>{h.disabled ? "Disabled" : "Active"}</td>
                <td className="c-row">
                  <button
                    type="button"
                    className="c-button c-ghost c-small"
                    aria-label={`Dead deliveries of ${h.url}`}
                    onClick={() => setPicked(h.id)}
                  >
                    Dead deliveries
                  </button>
                  {h.disabled ? null : (
                    <>
                      <button
                        type="button"
                        className="c-button c-small"
                        aria-label={`Rotate the secret of ${h.url}`}
                        disabled={action.busy}
                        onClick={() =>
                          void action.run("A new secret is made.", async () => {
                            const r = await client.webhooks.rotate(h.id);
                            setSecret({
                              label: `New signing secret of ${h.url}.`,
                              value: r.secret,
                            });
                          })
                        }
                      >
                        Rotate secret
                      </button>
                      <button
                        type="button"
                        className="c-button c-ghost c-small"
                        aria-label={`Disable ${h.url}`}
                        disabled={action.busy}
                        onClick={() =>
                          void action.run("The webhook is disabled.", () =>
                            client.webhooks.disable(h.id),
                          )
                        }
                      >
                        Disable
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hooks.data?.length === 0 ? <Empty>No webhook yet.</Empty> : null}
      {picked === undefined ? null : <DeadDeliveries key={picked} id={picked} />}
    </section>
  );
}

function DeadDeliveries(props: { id: string }) {
  const client = useTutela();
  const dead = useLoad(`dead:${props.id}`, (signal) =>
    client.webhooks.deliveries(props.id, { state: "dead", limit: 100 }, { signal }),
  );
  const action = useAction(dead.reload);
  return (
    <section aria-labelledby="dead-title" className="c-detail">
      <h2 id="dead-title" className="c-h2">
        Dead deliveries
      </h2>
      <Notice error={dead.error} onRetry={dead.reload} />
      {action.status}
      {dead.data?.deliveries.length === 0 ? <Empty>No dead delivery.</Empty> : null}
      <ul className="c-list">
        {(dead.data?.deliveries ?? []).map((d) => (
          <li key={d.seq}>
            <span className="c-num">#{d.seq}</span>{" "}
            <span className="c-muted">
              {d.attempts} attempts
              {d.last_status === undefined ? "" : `, last status ${String(d.last_status)}`}
            </span>
            <button
              type="button"
              className="c-button c-small"
              aria-label={`Send delivery ${String(d.seq)} again`}
              disabled={action.busy}
              onClick={() =>
                void action.run("Sent again.", () => client.webhooks.redeliver(props.id, d.seq))
              }
            >
              Send again
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
