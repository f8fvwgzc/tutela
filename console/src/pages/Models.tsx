import { impactSentences, type ModelVersion, type Proposal } from "@f8fvwgzc/tutela-js";
import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { holds } from "../access";
import {
  Empty,
  isForbidden,
  Notice,
  PageHeader,
  Subject,
  useAction,
  useConsole,
  When,
} from "../ui";

/** The model's versions, the open proposals and the two-person setting. */
export function ModelsPage() {
  const client = useTutela();
  const { access } = useConsole();
  const canChange =
    holds(access, "manage_access", "every") && holds(access, "manage_fields", "every");
  const data = useLoad("models", async (signal) => {
    const [versions, proposals, settings] = await Promise.all([
      client.models.versions({ limit: 50 }, { signal }),
      client.models.proposals({ signal }),
      client.models.settings({ signal }),
    ]);
    return { versions, proposals, settings };
  });
  const action = useAction(data.reload);
  const [open, setOpen] = useState<number | undefined>(undefined);
  if (isForbidden(data.error)) {
    return (
      <section>
        <PageHeader title="Model history" />
        <Empty>You may not see the model's history.</Empty>
      </section>
    );
  }
  const d = data.data;
  const waiting = d?.proposals.filter((p) => p.state === "proposed") ?? [];
  return (
    <section>
      <PageHeader
        title="Model history"
        detail={
          d === undefined
            ? undefined
            : `Active: version ${String(d.versions.active.version)}${d.versions.active.own ? "" : " (the app's default)"}`
        }
      >
        {d === undefined ? null : (
          <label className="c-check">
            <input
              type="checkbox"
              checked={d.settings.two_person}
              disabled={!canChange || action.busy}
              onChange={(e) => {
                const on = e.target.checked;
                void action.run(
                  on ? "Two-person publish is on." : "Two-person publish: change sent.",
                  () => client.models.putSettings(on),
                );
              }}
            />
            Two-person publish
          </label>
        )}
      </PageHeader>
      <Notice error={data.error} onRetry={data.reload} />
      {action.status}
      {d?.settings.off_requested_by === undefined ? null : (
        <p className="c-note">
          Turning two-person publish off was asked by <Subject id={d.settings.off_requested_by} />.
          Another person must agree.
        </p>
      )}

      <h2 className="c-h2">Proposals waiting</h2>
      {waiting.length === 0 ? (
        <Empty>No proposal waits.</Empty>
      ) : (
        <ul className="c-cards">
          {waiting.map((p) => (
            <ProposalItem key={p.id} p={p} canChange={canChange} onChanged={data.reload} />
          ))}
        </ul>
      )}

      <h2 className="c-h2">Versions</h2>
      {d === undefined ? (
        <p className="c-muted">Loading…</p>
      ) : d.versions.versions.length === 0 ? (
        <Empty>The tenant runs on the app's model; it has published no version of its own.</Empty>
      ) : (
        <div className="c-scroll">
          <table className="c-table" aria-label="Model versions">
            <thead>
              <tr>
                <th scope="col">Version</th>
                <th scope="col">Published</th>
                <th scope="col">Class</th>
                <th scope="col">By</th>
                <th scope="col">Origin</th>
                <th scope="col">
                  <span className="c-sr">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {d.versions.versions.map((v) => (
                <VersionRow
                  key={v.version}
                  v={v}
                  open={open === v.version}
                  onToggle={() => setOpen(open === v.version ? undefined : v.version)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function VersionRow(props: { v: ModelVersion; open: boolean; onToggle: () => void }) {
  const { v, open, onToggle } = props;
  return (
    <>
      <tr>
        <th scope="row" className="c-num">
          {v.version}
        </th>
        <td>
          <When at={v.published_at} />
        </td>
        <td>{v.class}</td>
        <td>{v.author === undefined ? "–" : <Subject id={v.author} />}</td>
        <td>
          {v.origin}
          {v.restores === undefined ? null : ` (restores ${String(v.restores)})`}
        </td>
        <td>
          <button
            type="button"
            className="c-button c-ghost c-small"
            aria-expanded={open}
            aria-label={`${open ? "Hide" : "Show"} version ${String(v.version)}`}
            onClick={onToggle}
          >
            {open ? "Hide" : "Show"}
          </button>
        </td>
      </tr>
      {open ? (
        <tr>
          <td colSpan={6}>
            {v.impact === undefined ? null : (
              <ul className="c-lines">
                {impactSentences(v.impact).map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            )}
            <pre className="c-diff">{v.diff === "" ? "No change." : v.diff}</pre>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function ProposalItem(props: { p: Proposal; canChange: boolean; onChanged: () => void }) {
  const { p, canChange, onChanged } = props;
  const client = useTutela();
  const { access } = useConsole();
  const action = useAction(onChanged);
  const [approval, setApproval] = useState("");
  const mine = p.proposed_by === access.me?.sub;
  const widening = p.class === "widening";
  return (
    <li className="c-card" aria-label={`Proposal ${p.id}`}>
      <p>
        <span className="c-mono">{p.id}</span> · {p.class} · from version {String(p.base_version)}
      </p>
      {p.impact == null ? null : (
        <ul className="c-lines">
          {impactSentences(p.impact).map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      )}
      <details>
        <summary>Show the model diff</summary>
        <pre className="c-diff">{p.diff}</pre>
      </details>
      {canChange ? (
        <div className="c-row">
          {widening ? (
            <label className="c-field">
              <span>Approval token</span>
              <input
                className="c-input c-mono"
                value={approval}
                onChange={(e) => setApproval(e.target.value)}
                spellCheck={false}
                autoComplete="off"
              />
            </label>
          ) : null}
          <button
            type="button"
            className="c-button c-primary"
            disabled={action.busy || mine || (widening && approval.trim() === "")}
            title={mine ? "Another person must approve your proposal." : undefined}
            onClick={() =>
              void action.run("Approved and published.", () =>
                client.models.approve(p.id, widening ? approval.trim() : undefined),
              )
            }
          >
            Approve
          </button>
          <button
            type="button"
            className="c-button c-ghost"
            disabled={action.busy}
            onClick={() => void action.run("Rejected.", () => client.models.reject(p.id))}
          >
            Reject
          </button>
        </div>
      ) : null}
      {action.status}
    </li>
  );
}
