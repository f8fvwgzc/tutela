import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { orgsWith } from "../access";
import { Empty, isForbidden, Notice, PageHeader, Subject, useAction, useConsole } from "../ui";

const MEMBER = /^(user|sa|key|agent|workload|group):\S+$/;

/** Groups of an org and their members. */
export function GroupsPage() {
  const client = useTutela();
  const { access } = useConsole();
  const orgs = orgsWith(access, "read_audit", "manage_access");
  const [org, setOrg] = useState(orgs[0]?.id ?? "");
  const canChange = access.orgs.some((o) => o.org.id === org && o.keys.manage_access);
  const groups = useLoad(`groups:${org}`, async (signal) => {
    const all = [];
    for await (const g of client.groups.list({ org, limit: 200 }, { signal })) all.push(g);
    return all;
  });
  const [picked, setPicked] = useState<string | undefined>(undefined);
  const [draft, setDraft] = useState({ key: "", name: "" });
  const action = useAction(groups.reload);
  return (
    <section>
      <PageHeader title="Groups" detail="A group's members get the roles given to the group.">
        <label className="c-field c-inline">
          <span>Org</span>
          <select className="c-input" value={org} onChange={(e) => setOrg(e.target.value)}>
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>
                {o.id}
              </option>
            ))}
          </select>
        </label>
      </PageHeader>
      {isForbidden(groups.error) ? (
        <Empty>You may not see the groups of this org.</Empty>
      ) : (
        <Notice error={groups.error} onRetry={groups.reload} />
      )}
      {canChange ? (
        <form
          className="c-toolbar"
          aria-label="New group"
          onSubmit={(e) => {
            e.preventDefault();
            void action
              .run("The group is made.", () => client.groups.create({ org, ...draft }))
              .then((ok) => ok && setDraft({ key: "", name: "" }));
          }}
        >
          <label className="c-field">
            <span>Key</span>
            <input
              className="c-input c-mono"
              value={draft.key}
              required
              pattern="[a-z0-9][a-z0-9_-]*"
              onChange={(e) => setDraft({ ...draft, key: e.target.value })}
            />
          </label>
          <label className="c-field">
            <span>Name</span>
            <input
              className="c-input"
              value={draft.name}
              required
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </label>
          <button type="submit" className="c-button c-primary" disabled={action.busy}>
            Make group
          </button>
        </form>
      ) : null}
      {action.status}
      <div className="c-split">
        <div className="c-scroll">
          <table className="c-table" aria-label="Groups">
            <thead>
              <tr>
                <th scope="col">Key</th>
                <th scope="col">Name</th>
                <th scope="col">Members</th>
                <th scope="col">
                  <span className="c-sr">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {(groups.data ?? []).map((g) => (
                <tr key={g.key} aria-selected={picked === g.key}>
                  <th scope="row">
                    <button
                      type="button"
                      className="c-link c-mono"
                      onClick={() => setPicked(g.key)}
                    >
                      {g.key}
                    </button>
                  </th>
                  <td>{g.name}</td>
                  <td className="c-num">{g.members ?? "–"}</td>
                  <td>
                    {canChange ? (
                      <button
                        type="button"
                        className="c-button c-ghost c-small"
                        aria-label={`Delete group ${g.key}`}
                        disabled={action.busy}
                        onClick={() =>
                          void action.run("The group is deleted.", () =>
                            client.groups.delete(g.key),
                          )
                        }
                      >
                        Delete
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {groups.data?.length === 0 ? <Empty>No group in this org.</Empty> : null}
        </div>
        {picked === undefined ? null : (
          <GroupMembers key={picked} group={picked} canChange={canChange} />
        )}
      </div>
    </section>
  );
}

function GroupMembers(props: { group: string; canChange: boolean }) {
  const client = useTutela();
  const { group, canChange } = props;
  const members = useLoad(`members:${group}`, async (signal) => {
    const all: string[] = [];
    for await (const m of client.groups.members(group, { limit: 200 }, { signal })) all.push(m);
    return all;
  });
  const action = useAction(members.reload);
  const [who, setWho] = useState("");
  return (
    <div className="c-detail">
      <h2 className="c-h2">
        Members of <span className="c-mono">{group}</span>
      </h2>
      <Notice error={members.error} onRetry={members.reload} />
      {action.status}
      {canChange ? (
        <form
          className="c-toolbar"
          aria-label={`Add a member to ${group}`}
          onSubmit={(e) => {
            e.preventDefault();
            if (!MEMBER.test(who.trim())) return;
            void action
              .run("The member is added.", () => client.groups.addMember(group, who.trim()))
              .then((ok) => ok && setWho(""));
          }}
        >
          <label className="c-field">
            <span>Member</span>
            <input
              className="c-input c-mono"
              value={who}
              placeholder="user:usr_… or group:key"
              onChange={(e) => setWho(e.target.value)}
            />
          </label>
          <button type="submit" className="c-button" disabled={action.busy}>
            Add member
          </button>
        </form>
      ) : null}
      <ul className="c-list">
        {(members.data ?? []).map((m) => (
          <li key={m}>
            <Subject id={m} />
            {canChange ? (
              <button
                type="button"
                className="c-button c-ghost c-small"
                aria-label={`Remove ${m} from ${group}`}
                disabled={action.busy}
                onClick={() =>
                  void action.run("The member is removed.", () =>
                    client.groups.removeMember(group, m),
                  )
                }
              >
                Remove
              </button>
            ) : null}
          </li>
        ))}
      </ul>
      {members.data?.length === 0 ? <Empty>No member.</Empty> : null}
    </div>
  );
}
