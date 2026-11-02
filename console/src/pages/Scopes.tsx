import type { Scope, ScopeRef } from "@f8fvwgzc/tutela-js";
import { MembersTable, useLoad, usePermissionMap, useTutela } from "@f8fvwgzc/tutela-react";
import { type KeyboardEvent, useState } from "react";
import { orgsWith } from "../access";
import { navigate, useLocation } from "../router";
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

/** The most scopes listed under one org. */
const MAX_SCOPES = 2000;

interface Node {
  ref: ScopeRef;
  /** Nearest first, the org last; empty for an org. */
  path: ScopeRef[];
  scope?: Scope;
}

function key(s: ScopeRef): string {
  return `${s.type}:${s.id}`;
}

/** Moves focus between the tree's buttons with the arrow keys. */
function arrows(e: KeyboardEvent<HTMLButtonElement>) {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  const tree = e.currentTarget.closest("nav");
  if (tree === null) return;
  const all = Array.from(tree.querySelectorAll<HTMLButtonElement>("button[data-node]"));
  const i = all.indexOf(e.currentTarget);
  const next = all[e.key === "ArrowDown" ? i + 1 : i - 1];
  if (next !== undefined) {
    e.preventDefault();
    next.focus();
  }
}

/** The scope tree of the orgs you may look into, and the members of the one you pick. */
export function ScopesPage() {
  const client = useTutela();
  const { access } = useConsole();
  const { query } = useLocation();
  const orgs = orgsWith(access, "read_audit", "manage_access");
  const tree = useLoad(`scopes:${orgs.map(key).join(",")}`, async (signal) => {
    const nodes: Node[] = [];
    const refused: string[] = [];
    for (const org of orgs) {
      nodes.push({ ref: org, path: [] });
      try {
        for await (const s of client.scopes.list({ under: org, limit: 500 }, { signal })) {
          nodes.push({ ref: s.scope, path: s.ancestors, scope: s });
          if (nodes.length > MAX_SCOPES) break;
        }
      } catch (e) {
        if (!isForbidden(e)) throw e;
        refused.push(org.id);
      }
    }
    return { nodes, refused };
  });
  const nodes = tree.data?.nodes ?? [];
  // The selection is looked up in the tree, never taken as written: a
  // scope's path always comes from tutelad (ADR-0049 item 3).
  const picked = nodes.find((n) => key(n.ref) === query.get("scope")) ?? nodes[0];
  const children = (parent: ScopeRef) =>
    nodes.filter((n) => n.path[0] !== undefined && key(n.path[0]) === key(parent));

  const branch = (n: Node, depth: number) => (
    <li key={key(n.ref)}>
      <button
        type="button"
        data-node
        className="c-node"
        onKeyDown={arrows}
        data-depth={Math.min(depth, 6)}
        aria-current={picked !== undefined && key(picked.ref) === key(n.ref) ? "true" : undefined}
        onClick={() => navigate(`/console/scopes?scope=${encodeURIComponent(key(n.ref))}`, true)}
      >
        <span className="c-kind">{n.ref.type}</span> <span className="c-mono">{n.ref.id}</span>
        {n.scope?.private ? <span className="c-chip">private</span> : null}
      </button>
      {children(n.ref).length === 0 ? null : (
        <ul>{children(n.ref).map((c) => branch(c, depth + 1))}</ul>
      )}
    </li>
  );

  return (
    <section>
      <PageHeader title="Scopes" detail="Orgs and the scopes registered below them." />
      <Notice error={tree.error} onRetry={tree.reload} />
      <div className="c-split">
        <nav className="c-tree" aria-label="Scope tree">
          {tree.loading && nodes.length === 0 ? <p className="c-muted">Loading…</p> : null}
          <ul>{nodes.filter((n) => n.path.length === 0).map((n) => branch(n, 0))}</ul>
          {tree.data?.refused.length ? (
            <p className="c-muted">You may not list the scopes of some orgs.</p>
          ) : null}
        </nav>
        <div className="c-detail">
          {picked === undefined ? (
            <Empty>Pick a scope.</Empty>
          ) : (
            <ScopeDetail key={key(picked.ref)} node={picked} reload={tree.reload} />
          )}
        </div>
      </div>
    </section>
  );
}

function ScopeDetail(props: { node: Node; reload: () => void }) {
  const { node, reload } = props;
  const client = useTutela();
  const { stepUp, theme } = useConsole();
  const { ref, path, scope } = node;
  const t = ref.type;
  const map = usePermissionMap({ ...ref, path }, [
    `${t}:manage_access`,
    `${t}:manage_boundaries`,
    `${t}:read_audit`,
  ]);
  const canAccess = map.data?.can(`${t}:manage_access`) ?? false;
  const canBounds = map.data?.can(`${t}:manage_boundaries`) ?? false;
  const action = useAction(reload);

  return (
    <article aria-labelledby="scope-title">
      <header className="c-detail-head">
        <h2 id="scope-title" className="c-h2">
          <span className="c-kind">{t}</span> <span className="c-mono">{ref.id}</span>
        </h2>
        <p className="c-path">
          <span className="c-sr">Path: </span>
          {[...path].reverse().map((p) => (
            <span key={key(p)} className="c-mono">
              {scopeText(p)} ›{" "}
            </span>
          ))}
          <span className="c-mono">{scopeText(ref)}</span>
        </p>
      </header>
      {action.status}
      {scope === undefined ? null : (
        <div className="c-props">
          <label className="c-check">
            <input
              type="checkbox"
              checked={scope.private}
              disabled={!canAccess || action.busy}
              onChange={(e) => {
                const value = e.target.checked;
                void action.run(
                  value ? "The scope is private now." : "The scope is open now.",
                  () => client.scopes.setPrivate(ref, value),
                );
              }}
            />
            Private (stops inheritance from above)
          </label>
          <Boundaries scope={scope} canChange={canBounds} />
        </div>
      )}
      <h3 className="c-h3">Members</h3>
      <MembersTable
        scope={ref}
        path={path}
        theme={theme}
        onStepUp={stepUp}
        renderSubject={(s) => <Subject id={s} />}
      />
    </article>
  );
}

const MOVES = ["members", "owners", "none"] as const;
const LOOSER = ["approve", "block"] as const;
const LINKS = ["any", "team", "none"] as const;

function Boundaries(props: { scope: Scope; canChange: boolean }) {
  const client = useTutela();
  const { scope, canChange } = props;
  const [draft, setDraft] = useState({
    moves_out: scope.moves_out ?? "members",
    moves_in: scope.moves_in ?? "members",
    on_looser: scope.on_looser ?? "approve",
    links_from: scope.links_from ?? "any",
  });
  const action = useAction();
  const field = <K extends keyof typeof draft>(
    name: K,
    label: string,
    options: readonly (typeof draft)[K][],
  ) => (
    <label className="c-field">
      <span>{label}</span>
      <select
        className="c-input"
        value={draft[name]}
        disabled={!canChange || action.busy}
        onChange={(e) => setDraft({ ...draft, [name]: e.target.value })}
      >
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
  return (
    <form
      className="c-bounds"
      aria-label="Boundaries"
      onSubmit={(e) => {
        e.preventDefault();
        void action.run("The boundaries are saved.", () =>
          client.scopes.setBoundary({ scope: scope.scope, ...draft }),
        );
      }}
    >
      {field("moves_out", "Moves out", MOVES)}
      {field("moves_in", "Moves in", MOVES)}
      {field("on_looser", "Into a looser scope", LOOSER)}
      {field("links_from", "Links from", LINKS)}
      {canChange ? (
        <button type="submit" className="c-button" disabled={action.busy}>
          Save boundaries
        </button>
      ) : null}
      {action.status}
    </form>
  );
}
