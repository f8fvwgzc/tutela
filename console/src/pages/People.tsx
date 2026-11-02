import type { Assignment, PrincipalState } from "@f8fvwgzc/tutela-js";
import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { holds } from "../access";
import {
  Empty,
  isForbidden,
  Notice,
  PageHeader,
  Subject,
  scopeText,
  useAction,
  useConsole,
} from "../ui";

const PRINCIPAL = /^(user|agent|sa):\S+$/;

/**
 * A person or an agent: its state, disabling, revoking its sessions, its
 * role assignments; deleting a person. Principals go in request bodies,
 * never in a URL (ADR-0048 item 9).
 */
export function PeoplePage() {
  const { access } = useConsole();
  const people = holds(access, "manage_access", "every");
  const agents = holds(access, "manage_agents", "every");
  const [who, setWho] = useState("");
  const [looked, setLooked] = useState<string | undefined>(undefined);
  return (
    <section>
      <PageHeader
        title="People and agents"
        detail="Tutela keeps no names: find a principal by its id."
      />
      <form
        className="c-toolbar"
        aria-label="Find a principal"
        onSubmit={(e) => {
          e.preventDefault();
          if (PRINCIPAL.test(who.trim())) setLooked(who.trim());
        }}
      >
        <label className="c-field">
          <span>Principal</span>
          <input
            className="c-input c-mono"
            value={who}
            placeholder="user:usr_… or agent:agt_…"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setWho(e.target.value)}
          />
        </label>
        <button type="submit" className="c-button">
          Look up
        </button>
      </form>
      {looked === undefined ? null : (
        <PrincipalView key={looked} principal={looked} canDelete={people} />
      )}
      {agents ? <Agents /> : null}
    </section>
  );
}

function PrincipalView(props: { principal: string; canDelete: boolean }) {
  const client = useTutela();
  const { principal, canDelete } = props;
  const state = useLoad(`principal:${principal}`, (signal) =>
    client.principals.state(principal, { signal }),
  );
  const roles = useLoad(`roles-of:${principal}`, async (signal) => {
    const all: Assignment[] = [];
    for await (const a of client.assignments.list({ subject: principal, limit: 200 }, { signal })) {
      all.push(a);
    }
    return all;
  });
  const action = useAction(state.reload);
  const [confirm, setConfirm] = useState(false);
  const s = state.data;
  const isPerson = principal.startsWith("user:");
  return (
    <article className="c-detail" aria-label={`Principal ${principal}`}>
      <h2 className="c-h2">
        <Subject id={principal} />
      </h2>
      {isForbidden(state.error) ? (
        <Empty>You may not manage this principal.</Empty>
      ) : (
        <Notice error={state.error} onRetry={state.reload} />
      )}
      {action.status}
      {s === undefined ? null : (
        <>
          <dl className="c-facts">
            <dt>State</dt>
            <dd>{s.disabled ? "Disabled" : "Enabled"}</dd>
            <dt>Epoch</dt>
            <dd className="c-num">{s.epoch}</dd>
            {s.workload === undefined ? null : (
              <>
                <dt>Workload</dt>
                <dd className="c-mono">{s.workload}</dd>
              </>
            )}
          </dl>
          <div className="c-row">
            <button
              type="button"
              className="c-button"
              disabled={action.busy}
              onClick={() =>
                void action.run(s.disabled ? "Enabled." : "Disabled.", () =>
                  client.principals.setDisabled(principal, !s.disabled),
                )
              }
            >
              {s.disabled ? "Enable" : "Disable"}
            </button>
            <button
              type="button"
              className="c-button"
              disabled={action.busy}
              onClick={() =>
                void action.run("Every session is revoked.", () =>
                  client.principals.revokeSessions(principal),
                )
              }
            >
              Revoke sessions
            </button>
            {isPerson && canDelete ? (
              confirm ? (
                <>
                  <span className="c-muted">Delete this person for good?</span>
                  <button
                    type="button"
                    className="c-button c-danger"
                    disabled={action.busy}
                    onClick={() =>
                      void action.run("The person is deleted.", () =>
                        client.principals.deleteUser(principal),
                      )
                    }
                  >
                    Delete for good
                  </button>
                  <button
                    type="button"
                    className="c-button c-ghost"
                    onClick={() => setConfirm(false)}
                  >
                    Keep
                  </button>
                </>
              ) : (
                <button type="button" className="c-button c-ghost" onClick={() => setConfirm(true)}>
                  Delete person…
                </button>
              )
            ) : null}
          </div>
        </>
      )}
      <h3 className="c-h3">Role assignments</h3>
      {isForbidden(roles.error) ? (
        <Empty>You may not list this principal's roles.</Empty>
      ) : (
        <Notice error={roles.error} onRetry={roles.reload} />
      )}
      {roles.data?.length === 0 ? <Empty>No role.</Empty> : null}
      <ul className="c-list">
        {(roles.data ?? []).map((a) => (
          <li key={a.id}>
            <span className="c-chip">{a.role}</span> at{" "}
            <span className="c-mono">{scopeText(a.scope)}</span>
            {a.expires_at === undefined ? null : (
              <span className="c-muted"> until {a.expires_at.slice(0, 10)}</span>
            )}
          </li>
        ))}
      </ul>
    </article>
  );
}

function Agents() {
  const client = useTutela();
  const list = useLoad("agents", async (signal) => {
    const all: PrincipalState[] = [];
    for await (const a of client.agents.list({ limit: 200 }, { signal })) all.push(a);
    return all;
  });
  const action = useAction(list.reload);
  const [workload, setWorkload] = useState("");
  return (
    <section aria-labelledby="agents-title">
      <h2 id="agents-title" className="c-h2">
        Agents
      </h2>
      <Notice error={list.error} onRetry={list.reload} />
      {action.status}
      <form
        className="c-toolbar"
        aria-label="Register an agent"
        onSubmit={(e) => {
          e.preventDefault();
          const w = workload.trim();
          void action
            .run("The agent is registered.", () => client.agents.register(w === "" ? undefined : w))
            .then((ok) => ok && setWorkload(""));
        }}
      >
        <label className="c-field">
          <span>Workload (SPIFFE id, optional)</span>
          <input
            className="c-input c-mono"
            value={workload}
            placeholder="spiffe://…/ns/<ns>/svc/<service>"
            onChange={(e) => setWorkload(e.target.value)}
          />
        </label>
        <button type="submit" className="c-button" disabled={action.busy}>
          Register agent
        </button>
      </form>
      <div className="c-scroll">
        <table className="c-table" aria-label="Agents">
          <thead>
            <tr>
              <th scope="col">Agent</th>
              <th scope="col">Workload</th>
              <th scope="col">State</th>
              <th scope="col">Epoch</th>
            </tr>
          </thead>
          <tbody>
            {(list.data ?? []).map((a) => (
              <tr key={a.principal}>
                <th scope="row" className="c-mono">
                  {a.principal}
                </th>
                <td className="c-mono">{a.workload ?? "–"}</td>
                <td>{a.disabled ? "Disabled" : "Enabled"}</td>
                <td className="c-num">{a.epoch}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {list.data?.length === 0 ? <Empty>No agent is registered.</Empty> : null}
    </section>
  );
}
