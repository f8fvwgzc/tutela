import type { EvaluationBody, Scope, ScopeRef } from "@f8fvwgzc/tutela-js";
import { useLoad, useTutela } from "@f8fvwgzc/tutela-react";
import { useState } from "react";
import { orgsWith } from "../access";
import { Notice, PageHeader, scopeText, useAction, useConsole } from "../ui";

interface Target {
  ref: ScopeRef;
  path: ScopeRef[];
}

/**
 * Why a principal may or may not do an action on a resource (explain), and
 * what a changed model or a role given or taken would decide (simulate).
 * Both need `read_audit` on the resource; nothing is written.
 */
export function ExplainPage() {
  const client = useTutela();
  const { access } = useConsole();
  const orgs = orgsWith(access, "read_audit");
  const targets = useLoad(`targets:${orgs.map(scopeText).join(",")}`, async (signal) => {
    const all: Target[] = [];
    for (const org of orgs) {
      all.push({ ref: org, path: [] });
      for await (const s of client.scopes.list({ under: org, limit: 500 }, { signal })) {
        all.push({ ref: (s as Scope).scope, path: s.ancestors });
        if (all.length > 1000) break;
      }
    }
    return all;
  });
  const [subject, setSubject] = useState(access.me?.sub ?? "");
  const [at, setAt] = useState("");
  const [action, setAction] = useState("");
  const [item, setItem] = useState({ type: "", id: "" });
  const [role, setRole] = useState("");
  const [answer, setAnswer] = useState<unknown>(undefined);
  const run = useAction();

  const target = targets.data?.find((t) => scopeText(t.ref) === at) ?? targets.data?.[0];
  const body = (): EvaluationBody | undefined => {
    if (target === undefined) return undefined;
    const [kind = "user"] = subject.split(":");
    const child = item.type.trim() !== "" && item.id.trim() !== "";
    return {
      subject: { type: kind, id: subject.trim() },
      action: { name: action.trim() },
      resource: child
        ? {
            type: item.type.trim(),
            id: item.id.trim(),
            properties: { path: [target.ref, ...target.path] },
          }
        : { type: target.ref.type, id: target.ref.id, properties: { path: target.path } },
    };
  };

  return (
    <section>
      <PageHeader
        title="Explain and simulate"
        detail="Why a decision is what it is, and what a change would decide. Nothing is written."
      />
      <Notice error={targets.error} onRetry={targets.reload} />
      <form
        className="c-form"
        aria-label="Question"
        onSubmit={(e) => {
          e.preventDefault();
          const b = body();
          if (b === undefined) return;
          void run.run("Explained.", async () => setAnswer(await client.explain(b)));
        }}
      >
        <label className="c-field">
          <span>Principal</span>
          <input
            className="c-input c-mono"
            value={subject}
            required
            onChange={(e) => setSubject(e.target.value)}
          />
        </label>
        <label className="c-field">
          <span>Action</span>
          <input
            className="c-input c-mono"
            value={action}
            required
            placeholder="project:read"
            onChange={(e) => setAction(e.target.value)}
          />
        </label>
        <label className="c-field">
          <span>Scope</span>
          <select
            className="c-input c-mono"
            value={target === undefined ? "" : scopeText(target.ref)}
            onChange={(e) => setAt(e.target.value)}
          >
            {(targets.data ?? []).map((t) => (
              <option key={scopeText(t.ref)} value={scopeText(t.ref)}>
                {scopeText(t.ref)}
              </option>
            ))}
          </select>
        </label>
        <fieldset className="c-fieldset">
          <legend>An item in the scope (optional)</legend>
          <label className="c-field">
            <span>Type</span>
            <input
              className="c-input c-mono"
              value={item.type}
              onChange={(e) => setItem({ ...item, type: e.target.value })}
            />
          </label>
          <label className="c-field">
            <span>Id</span>
            <input
              className="c-input c-mono"
              value={item.id}
              onChange={(e) => setItem({ ...item, id: e.target.value })}
            />
          </label>
        </fieldset>
        <div className="c-row">
          <button type="submit" className="c-button c-primary" disabled={run.busy}>
            Explain
          </button>
          <label className="c-field c-inline">
            <span>Simulate giving the role</span>
            <input
              className="c-input c-mono"
              value={role}
              placeholder="reader"
              onChange={(e) => setRole(e.target.value)}
            />
          </label>
          <button
            type="button"
            className="c-button"
            disabled={run.busy || role.trim() === "" || target === undefined}
            onClick={() => {
              const b = body();
              if (b === undefined || target === undefined) return;
              void run.run("Simulated.", async () =>
                setAnswer(
                  await client.simulate(b, {
                    add: [{ subject: subject.trim(), role: role.trim(), scope: target.ref }],
                  }),
                ),
              );
            }}
          >
            Simulate
          </button>
        </div>
      </form>
      {run.status}
      {answer === undefined ? null : (
        <section aria-label="Answer" className="c-detail">
          <pre className="c-diff">{JSON.stringify(answer, null, 2)}</pre>
        </section>
      )}
    </section>
  );
}
