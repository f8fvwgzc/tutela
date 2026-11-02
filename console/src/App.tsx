// The Console: sign-in, the shell (a rail of pages, a header, the step-up
// banner) and the pages. The rail shows only the pages the permission map
// allows; every route checks again (ADR-0052).

import { TutelaClient } from "@f8fvwgzc/tutela-js";
import { type Theme, TutelaProvider, useSessionState } from "@f8fvwgzc/tutela-react";
import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { PAGES, type PageKey, useAccess, visiblePages } from "./access";
import { CALLBACK_PATH, type ConsoleConfig, Oidc, type OidcEnv, SignInError } from "./oidc";
import { AppsPage } from "./pages/Apps";
import { ExplainPage } from "./pages/Explain";
import { GroupsPage } from "./pages/Groups";
import { ModelsPage } from "./pages/Models";
import { OverviewPage } from "./pages/Overview";
import { PeoplePage } from "./pages/People";
import { RolesPage } from "./pages/Roles";
import { ScopesPage } from "./pages/Scopes";
import { TenantPage } from "./pages/Tenant";
import { WebhooksPage } from "./pages/Webhooks";
import { navigate, useLocation } from "./router";
import { ConsoleProvider } from "./ui";

/** The client of one signed-in person: tokens from the realm, exchanged at tutelad. */
export function clientFor(oidc: Oidc, fetchFn?: typeof fetch): TutelaClient {
  return new TutelaClient({
    baseUrl: "",
    ...(fetchFn === undefined ? {} : { fetch: fetchFn }),
    auth: { kind: "browser", getUpstreamToken: (reason) => oidc.upstream(reason) },
  });
}

function here(): string {
  return window.location.pathname + window.location.search;
}

/** Sign-in, the callback, then the shell. */
export function Root(props: { config: ConsoleConfig; env: OidcEnv; apiFetch?: typeof fetch }) {
  const { config, env, apiFetch } = props;
  const oidc = useMemo(() => new Oidc(config, env), [config, env]);
  const [client, setClient] = useState<TutelaClient | undefined>(undefined);
  const [error, setError] = useState<unknown>(undefined);
  const [busy, setBusy] = useState(window.location.pathname === CALLBACK_PATH);

  useEffect(() => {
    if (window.location.pathname !== CALLBACK_PATH) return;
    const search = window.location.search;
    // The code leaves the address bar at once.
    window.history.replaceState(null, "", "/console/");
    oidc.callback(search).then(
      (returnTo) => {
        navigate(returnTo, true);
        setClient(clientFor(oidc, apiFetch));
        setBusy(false);
      },
      (e: unknown) => {
        setError(e);
        setBusy(false);
      },
    );
  }, [oidc, apiFetch]);

  const signIn = useCallback(() => {
    setError(undefined);
    oidc.signIn(here()).catch((e: unknown) => setError(e));
  }, [oidc]);

  const signedOut = useCallback(() => {
    setClient((c) => {
      c?.session?.signOut();
      return undefined;
    });
    oidc.forget();
    setError(new SignInError("Your session ended. Sign in again."));
  }, [oidc]);

  if (client === undefined) {
    return <SignIn config={config} busy={busy} error={error} onSignIn={signIn} />;
  }
  return (
    <TutelaProvider client={client}>
      <Shell client={client} oidc={oidc} onSignedOut={signedOut} />
    </TutelaProvider>
  );
}

function SignIn(props: {
  config: ConsoleConfig;
  busy: boolean;
  error: unknown;
  onSignIn: () => void;
}) {
  let realm = props.config.issuer;
  try {
    realm = new URL(props.config.issuer).host;
  } catch {
    // Shown as written.
  }
  const message =
    props.error instanceof SignInError
      ? props.error.message
      : props.error === undefined
        ? undefined
        : "Sign-in failed. Try again.";
  return (
    <main className="c-signin">
      <div className="c-signin-panel">
        <p className="c-brand">
          <Mark /> Tutela Console
        </p>
        <h1 className="c-title">Sign in to manage access</h1>
        <p className="c-muted">
          You sign in at <span className="c-mono">{realm}</span>. Admin changes need MFA.
        </p>
        {message === undefined ? null : (
          <p className="c-alert" role="alert">
            {message}
          </p>
        )}
        <button
          type="button"
          className="c-button c-primary"
          onClick={props.onSignIn}
          disabled={props.busy}
        >
          {props.busy ? "Signing in…" : "Sign in"}
        </button>
      </div>
    </main>
  );
}

function Mark() {
  return (
    <svg className="c-mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path d="M16 5l9 3.4v6.4c0 5.6-3.7 10.3-9 12-5.3-1.7-9-6.4-9-12V8.4z" />
    </svg>
  );
}

const THEMES: Theme[] = ["system", "light", "dark"];

function Shell(props: { client: TutelaClient; oidc: Oidc; onSignedOut: () => void }) {
  const { client, oidc, onSignedOut } = props;
  const access = useAccess(client, onSignedOut);
  const session = useSessionState();
  const { path } = useLocation();
  const [theme, setTheme] = useState<Theme>("system");
  const visible = visiblePages(access);
  const page: PageKey | undefined =
    PAGES.find((p) => p.path.replace(/\/$/, "") === path)?.key ??
    (path === "/console" ? "overview" : undefined);
  const holdsAny = access.orgs.some((o) => Object.values(o.keys).some(Boolean));

  // Ask for the admin token early, so the step-up banner shows at once.
  useEffect(() => {
    if (holdsAny) client.session?.token("admin").catch(() => undefined);
  }, [client, holdsAny]);

  const stepUp = useCallback(() => {
    oidc.signIn(here()).catch(() => undefined);
  }, [oidc]);
  const signOut = () => {
    client.session?.signOut();
    void oidc.signOut();
  };
  const person = oidc.person;
  const mfa = person.acr !== undefined && person.acr === oidc.config.step_up_acr;

  return (
    <ConsoleProvider value={{ access, theme, stepUp }}>
      <div className="c-app" data-theme={theme === "system" ? undefined : theme}>
        <a className="c-skip" href="#content">
          Skip to content
        </a>
        <nav className="c-rail" aria-label="Pages">
          <p className="c-brand">
            <Mark /> Tutela
          </p>
          <ul>
            {PAGES.filter((p) => visible.has(p.key)).map((p) => (
              <li key={p.key}>
                <a
                  href={p.path}
                  aria-current={p.key === page ? "page" : undefined}
                  onClick={(e) => {
                    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
                    e.preventDefault();
                    navigate(p.path);
                  }}
                >
                  {p.label}
                </a>
              </li>
            ))}
          </ul>
          <div className="c-rail-foot">
            <span className="c-muted">Tenant</span>
            <span className="c-mono c-ellipsis" title={access.me?.tid}>
              {access.me?.tid ?? "…"}
            </span>
          </div>
        </nav>
        <div className="c-main">
          <header className="c-top">
            <span className="c-who">
              <span>{person.name ?? access.me?.sub ?? "Signed in"}</span>
              {mfa ? <span className="c-chip">MFA</span> : null}
            </span>
            <label className="c-theme">
              <span className="c-muted">Theme</span>
              <select
                className="c-input c-small"
                value={theme}
                onChange={(e) => setTheme(e.target.value as Theme)}
              >
                {THEMES.map((t) => (
                  <option key={t} value={t}>
                    {t[0]?.toUpperCase()}
                    {t.slice(1)}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="c-button c-ghost" onClick={signOut}>
              Sign out
            </button>
          </header>
          {session.status === "step-up-required" ? (
            <section className="c-banner" aria-label="Step-up needed">
              <p>
                Admin actions need a sign-in with MFA. You can look around; changes are refused
                until you step up.
              </p>
              <button type="button" className="c-button c-primary" onClick={stepUp}>
                Sign in with MFA
              </button>
            </section>
          ) : null}
          {access.error === undefined ? null : (
            <p className="c-alert" role="alert">
              Could not refresh your permissions. Showing the last answer.
            </p>
          )}
          <main id="content" className="c-content" tabIndex={-1}>
            {!access.loaded ? (
              <p className="c-muted">Loading your permissions…</p>
            ) : page === undefined ? (
              <p className="c-empty">There is no such page.</p>
            ) : !visible.has(page) ? (
              <p className="c-empty">You do not hold the admin keys this page needs.</p>
            ) : (
              <PageView page={page} />
            )}
          </main>
        </div>
      </div>
    </ConsoleProvider>
  );
}

function PageView(props: { page: PageKey }): ReactNode {
  switch (props.page) {
    case "overview":
      return <OverviewPage />;
    case "scopes":
      return <ScopesPage />;
    case "roles":
      return <RolesPage />;
    case "models":
      return <ModelsPage />;
    case "groups":
      return <GroupsPage />;
    case "people":
      return <PeoplePage />;
    case "apps":
      return <AppsPage />;
    case "webhooks":
      return <WebhooksPage />;
    case "tenant":
      return <TenantPage />;
    case "explain":
      return <ExplainPage />;
  }
}
