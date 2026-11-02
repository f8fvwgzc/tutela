import { ADMIN_KEYS, PAGES, visiblePages } from "../access";
import { navigate } from "../router";
import { Empty, PageHeader, Subject, useConsole } from "../ui";

/** Who you are, and the admin keys you hold at each org you can see. */
export function OverviewPage() {
  const { access } = useConsole();
  const visible = visiblePages(access);
  const holdsAny = access.orgs.some((o) => Object.values(o.keys).some(Boolean));
  return (
    <section aria-labelledby="overview-title">
      <PageHeader
        title="Overview"
        detail={access.me === undefined ? undefined : <Subject id={access.me.sub} />}
      />
      <h2 id="overview-title" className="c-h2">
        Your admin keys
      </h2>
      {access.orgs.length === 0 ? (
        <Empty>You can see no org of this tenant.</Empty>
      ) : (
        <div className="c-scroll">
          <table className="c-table" aria-label="Your admin keys by org">
            <thead>
              <tr>
                <th scope="col">Org</th>
                {ADMIN_KEYS.map((k) => (
                  <th scope="col" key={k}>
                    {k}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {access.orgs.map((o) => (
                <tr key={o.org.id}>
                  <th scope="row" className="c-mono">
                    {o.org.id}
                  </th>
                  {ADMIN_KEYS.map((k) => (
                    <td key={k} data-held={o.keys[k] || undefined}>
                      {o.keys[k] ? "Held" : <span className="c-muted">No</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {holdsAny ? null : (
        <p className="c-empty" data-testid="no-admin-keys">
          You hold no admin keys in this tenant. An owner can give you a role.
        </p>
      )}
      <h2 className="c-h2">Pages you can open</h2>
      <ul className="c-links">
        {PAGES.filter((p) => p.key !== "overview" && visible.has(p.key)).map((p) => (
          <li key={p.key}>
            <a
              href={p.path}
              onClick={(e) => {
                e.preventDefault();
                navigate(p.path);
              }}
            >
              {p.label}
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}
