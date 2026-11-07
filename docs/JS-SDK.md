# Tutela's JavaScript SDKs

**Status: Phase B, parts 4b1 and 4b2, built.** Two npm packages in `sdk/`, and the Tutela Console built on them ([The Console](#the-console)):

| Package | What | Runs in |
|---|---|---|
| `@f8fvwgzc/tutela-js` | The client of `tutelad`: the token flow of a person in a browser, a service mode, every route the Console calls, typed errors, the permission map | Browsers and Node 22; no dependency |
| `@f8fvwgzc/tutela-react` | React 19 admin components: `MembersTable`, `RoleEditor`, `PermissionMatrix`, a provider and hooks | Browsers; React 19 as a peer |

The decisions are [ADR-0047](DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make) (the toolchain), [ADR-0048](DECISIONS.md#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice) (the client) and [ADR-0049](DECISIONS.md#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people) (the components). The routes and shapes are [CONTRACTS.md](CONTRACTS.md) 4.8, 7.1, 7.5, 7.9, 7.10 and 7.13. The packages are not published yet (see [Releasing](#releasing)).

Contents: [Embed MembersTable behind your own sign-in](#embed-memberstable-behind-your-own-sign-in) · [The token flow](#the-token-flow) · [Service mode](#service-mode) · [The client](#the-client) · [Errors](#errors) · [The components](#the-components) · [The Console](#the-console) · [Develop and test](#develop-and-test) · [Releasing](#releasing)

## Embed MembersTable behind your own sign-in

A product lets its customers' admins manage who may do what, inside the product's own pages (INTEGRATION.md step 8). The person signs in with the product's Keycloak, as always.

**1. Keycloak.** The product's public client (authorization code with PKCE) asks for an access token whose audience is `tutelad`'s (`TUTELA_AUDIENCE`, `tutela-authz`): add an audience mapper to the client. For admin work the token must carry a step-up `acr` that `tutelad` counts as MFA (`TUTELA_ADMIN_ACR`, for example Keycloak's `acr` level for OTP). Each token must have a `jti` (Keycloak's do).

**2. `tutelad`.** Its trust file maps the realm to the product's tenant, with `external = true` (CONTRACTS.md 1.6, 4.6). Set `TUTELA_ADMIN_ACR`. The person's account in Tutela is made the first time it signs in (just-in-time, keyed by `(iss, sub)`); an owner gives it roles.

**3. Reach `tutelad` from the page.** Either list the page's origin in `tutelad`'s `TUTELA_CORS_ORIGINS` (exact origins, `https`; [ADR-0054](DECISIONS.md#adr-0054-cors-exact-origins-from-configuration-off-by-default-never-credentials)) and give the client `tutelad`'s URL as `baseUrl`, or reach it on the page's own origin: proxy `/tutela/` to `tutelad`'s API port, at least `POST /oauth2/token`, `/v1/admin/`, `/v1/models/`, `/v1/authz/` and `GET /v1/whoami`. The proxy passes the `Authorization` header and the body as they are, adds no cookie, and keeps `ETag`, `If-None-Match`, `Retry-After` and `x-request-id`. The Console of part 4b2 is served by `tutelad` itself and needs no proxy.

**4. The page.**

```tsx
import Keycloak from "keycloak-js";
import { TutelaClient } from "@f8fvwgzc/tutela-js";
import { MembersTable, TutelaProvider } from "@f8fvwgzc/tutela-react";
import "@f8fvwgzc/tutela-react/styles.css";

const keycloak = new Keycloak({ url: "https://kc.example.com", realm: "acme", clientId: "crm-web" });
await keycloak.init({ onLoad: "login-required", pkceMethod: "S256" });

const tutela = new TutelaClient({
  baseUrl: "/tutela",
  auth: {
    kind: "browser",
    // A fresh upstream token each time: tutelad exchanges each one once.
    getUpstreamToken: async () => {
      await keycloak.updateToken(-1);
      if (keycloak.token === undefined) throw new Error("signed out");
      return keycloak.token;
    },
  },
});

export function ProjectAccess({ project, org }: { project: string; org: string }) {
  return (
    <TutelaProvider client={tutela}>
      <MembersTable
        scope={{ type: "project", id: project }}
        path={[{ type: "org", id: org }]}
        renderSubject={(principal) => <PersonName principal={principal} />}
        onAskAdmin={(request) => openAccessRequest(request)}
        onStepUp={() => keycloak.login({ acr: { values: ["mfa"], essential: true } })}
      />
    </TutelaProvider>
  );
}
```

- `path` is the scope's ancestors, nearest first, the org last: what `GET /v1/admin/scopes` gives as `ancestors`, or what the product's own tree knows. Never take it from a person's input.
- `renderSubject` shows names from the product's own user directory: Tutela keeps no names.
- `onAskAdmin` gets `{scope, subject, role, expires_at?, gains}` after a `not_held` refusal: send it to an owner the product's way.
- After the person did MFA, `tutela.session.stepUp()` takes the new token; `onStepUp` is where the product starts that sign-in.

A product that keeps every token on its server (backend-for-frontend, TM-06's default) does the exchange there and gives the page a `custom` token source that asks its backend, or runs the client on the server in [service mode](#service-mode).

## The token flow

The ROADMAP notes for part 4b give the flow; `BrowserSession` does it ([ADR-0048](DECISIONS.md#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice)):

1. `getUpstreamToken("initial")` gives a Keycloak access token.
2. `POST /oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token=<upstream>`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `audience=tutela-authz`, **no client authentication** (the browser is a public client, ADR-0044 item 7). The answer is a `tutela-authz` token for the person, for the check API (`/v1/whoami`, `/v1/authz/permissions`).
3. The same call with `subject_token=<the tutela-authz token>` and `audience=tutela-admin` gives the admin token (at most 300 s) for the admin API. One upstream token gives both: `tutelad` exchanges an upstream token once, and copies its `acr` into its own token.
4. Without step-up, step 3 answers `invalid_grant` "step-up authentication is required": the session throws `StepUpRequiredError`, says `step-up-required` (`session.state`, `session.subscribe`), and keeps the `tutela-authz` token. After MFA, `session.stepUp()` starts again with `getUpstreamToken("step-up")`.
5. 30 s before a token expires the session asks `getUpstreamToken("expiring")` for a **fresh** token and exchanges it. A token is never used past its `exp`, `expires_in`, or the `exp` of the token it came from. An upstream token the session sent before is refused before any request (`UpstreamTokenReusedError`).
6. A 401 from `tutelad` (a revoked session, a raised epoch) drops the tokens and starts again once with `getUpstreamToken("rejected")`.
7. Tokens live in the session object only: never `localStorage`, `sessionStorage`, cookies or IndexedDB. `fetch` runs with `credentials: "omit"` and `redirect: "error"`. `session.signOut()` forgets them.

## Service mode

A pipeline, a core written in TypeScript, or a product's server, uses its own token for every route: an app's `client_credentials` token (CONTRACTS.md 4.9).

```ts
const tutela = new TutelaClient({
  baseUrl: process.env.TUTELA_URL!,
  auth: { kind: "service", getToken: (audience) => appToken() },
});
```

`audience` is `"admin"` or `"authz"`: a service sends its `tutela-authz` token to both (ADR-0032). The service needs the admin keys the route asks for, given by ordinary assignments.

## The client

```ts
for await (const a of tutela.assignments.list({ scope: { type: "project", id: "p-1" } })) {
  console.log(a.subject, a.role, a.expires_at);
}
const { assignment, rev } = await tutela.assignments.assign({
  subject: "user:usr_…",
  role: "reader",
  scope: { type: "project", id: "p-1" },
  expires_at: "2027-01-01T00:00:00Z",
});
const map = await tutela.permissions({
  resource: { type: "project", id: "p-1", path: [{ type: "org", id: "org_…" }] },
  actions: ["project:manage_access"],
});
map.can("project:manage_access"); // also tutela.can("project:manage_access", scope)
```

| Namespace | Routes |
|---|---|
| `tenant` | `get`, `rename`, `delete` |
| `orgs` | `list`, `create`, `rename`, `delete`, `restore` |
| `scopes` | `page`, `list` (iterator), `register`, `move`, `delete`, `setPrivate`, `setBoundary` |
| `assignments` | `page`, `list` (iterator), `assign`, `setExpiry`, `unassign` |
| `groups` | `page`, `list`, `create`, `delete`, `membersPage`, `members`, `addMember`, `removeMember` |
| `roles(scope?)` | the permission matrix's roles and types |
| `models` | `versions`, `version`, `active`, `impact`, `publish`, `settings`, `putSettings`, `propose`, `proposals`, `proposal`, `approve`, `reject` |
| `principals` | `state`, `setDisabled`, `revokeSessions`, `deleteUser` |
| `agents` | `page`, `list`, `register` |
| `apps` | `list`, `create`, `rotate`, `disable` |
| `webhooks` | `list`, `register`, `rotate`, `disable`, `deliveries`, `redeliver` |
| check API | `whoami`, `permissions`, `can`, `searchResources` (7.4, an async iterator), `explain`, `simulate` |

- **Pages.** `page()` answers the wire shape (`{assignments, next_after?}`); `list()` is an async iterator that passes `next_after` back as `after`.
- **Your own write.** Each write's `rev` is kept (`tutela.revision`, `tutela.onRevision`) and sent as `at_least_revision` on the next permission map and explain, so the page shows its own write.
- **The permission map.** Asked for the caller itself (from `whoami`), with `ui_keys: []` unless asked; `If-None-Match` with the tag held, the same map on 304; kept in `tutela.permissionStore`. `can()` is `false` for anything not loaded. It is a UI hint: every route checks again.
- **Principals** go in JSON bodies, never in a URL.
- **The model as text.** `permissionMatrix(roles)`, `draftOf(role)`, `setRoleGrants(source, draft)`, `impactSentences(impact)`.

## Errors

| Status, code | Error | What a page does |
|---|---|---|
| 400, 413, 415 | `InvalidRequestError` | Show `detail` (for `invalid_manifest`, the compiler's problems) |
| 401 `invalid_token` | `UnauthorizedError` | The client already tried a fresh token once; sign in again |
| 403 `forbidden` | `ForbiddenError` | Hide what the person may not do |
| 403 `not_held` | `NotHeldError` (`gains`, `incomplete`) | Show the counts-only sentences; offer to ask an admin who holds more |
| 403 `move_refused` | `MoveRefusedError` (`outcome`, `reason`, `waitingFor`) | Show which scopes wait for an owner |
| 403 `approval_required`, `two_person_required`, `same_person`, `unknown_tenant` | `ForbiddenError` | Ask for an approval token; propose instead; another person approves |
| 404 | `NotFoundError` | It is gone (or of another tenant) |
| 409 | `ConflictError` | Load again: the data moved |
| 503 (and 429, 5xx) | `UnavailableError` (`retryAfter`) | Try again after `Retry-After` |
| token endpoint, step-up | `StepUpRequiredError` | Sign in with MFA, then `session.stepUp()` |
| token endpoint, other | `TokenExchangeError` (`error`, `description`) | Sign in again |
| no answer | `NetworkError` | Tell the person |

Every `ProblemError` has `status`, `code`, `title`, `detail`, `retryAfter` and `requestId` (the `x-request-id`, to find the call in `tutelad`'s logs). No error holds a token.

**503.** The client retries a 503 by itself after `Retry-After`, at most `maxRetries` (default 2) times, when `Retry-After` is at most `maxRetryAfterSecs` (default 5), and **only** for a call that is safe to send twice. A call that makes something (an org, an agent, an app or a webhook and their secrets, a proposal) is never retried by the client: a lost answer could make two.

## The components

| Component | Props (main) |
|---|---|
| `MembersTable` | `scope`, `path`, `pageSize?`, `roles?`, `renderSubject?`, `onAskAdmin?`, `onStepUp?`, `theme?` |
| `RoleEditor` | `roleKey`, `draft?`, `detail?`, `onDone?`, `onCancel?`, `onStepUp?`, `theme?` |
| `PermissionMatrix` | `scope?`, `detail?`, `editable?`, `onReview?`, `theme?` |
| `ErrorNotice` | `error`, `onRetry?`, `onAskAdmin?`, `onStepUp?`, `onDismiss?` |

Hooks: `useTutela`, `useCan(action, resource)`, `usePermissionMap(resource, actions)`, `useAssignments(scope, pageSize?)`, `useRoles(scope?)`, `useModel()`, `useSessionState()`.

**Looks.** Import `@f8fvwgzc/tutela-react/styles.css` once. It styles only the components' `.tutela` root and what is inside it. Override `--tutela-*` variables (`--tutela-accent`, `--tutela-font`, `--tutela-size`, `--tutela-row`, `--tutela-bg`, `--tutela-fg`, …) on `.tutela` or an ancestor. `theme="light" | "dark" | "system"` (default `system`). No inline styles, so a strict Content-Security-Policy needs no exception.

**Accessible.** Real tables with headers, labelled inputs, buttons named for what they act on, a polite status for each success and an alert for each refusal, visible focus, keyboard use, and no animation under `prefers-reduced-motion`. axe-core runs on each component in the tests.

## The Console

**Status: Phase B, part 4b2, built.** The Tutela Console is `console/` in this workspace: a single-page app (React 19, TypeScript strict, built by Vite) on `@f8fvwgzc/tutela-js` and `@f8fvwgzc/tutela-react`. `tutelad` serves it under `/console/` on its API port ([ADR-0050](DECISIONS.md#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start)); the decisions are [ADR-0052](DECISIONS.md#adr-0052-the-console-a-vite-app-on-the-sdks-sign-in-by-code-with-pkce-the-permission-map-asked-again-every-half-second) and, for its browser check, [ADR-0053](DECISIONS.md#adr-0053-the-exit-check-in-a-real-browser-playwrights-chromium-a-real-tutelad-and-the-test-provider-run-by-make).

- **Sign-in:** the authorization code flow with PKCE (S256) at the realm `/console/config.json` names, as a public client, asking for the step-up `acr`. Tokens stay in memory; a reload signs in again. Without MFA a banner offers "Sign in with MFA".
- **What you see** follows your permission map: the orgs you can see (a resource search for `org:read`) and your admin keys at each, asked again every 500 ms while the tab is visible. A page you may not use is not in the rail. The server checks every call again.
- **Pages:** Overview; Scopes (the tree, `MembersTable`, the private flag, boundaries); Roles (`PermissionMatrix` into `RoleEditor`: the impact before you publish or propose); Model history (versions, proposals, approve and reject, two-person publish); Groups; People and agents; Apps and Webhooks (a secret is shown once); Tenant and orgs; Explain and simulate.

### Run it locally against the test provider

The repo has a test OpenID provider shaped like Keycloak 26 (`crates/tutela-test-idp`, [ADR-0051](DECISIONS.md#adr-0051-a-test-openid-provider-shaped-like-keycloak-a-dev-only-crate-on-loopback)). It has no passwords: a form picks a test person, with or without MFA. Loopback only, never in production.

1. Build the Console: `pnpm install && pnpm -r run build` (writes `console/dist`).
2. Start a Postgres, and migrate it as the owner role: `TUTELA_OWNER_DATABASE_URL=<owner url> TUTELA_SERVICE_ROLE=<service role> cargo run -p tutelad -- migrate`.
3. Start the provider. It prints its issuer:
   ```sh
   cargo run -p tutela-test-idp -- --listen 127.0.0.1:18555 \
     --redirect-uri http://127.0.0.1:8080/console/callback \
     --person kc-owner="Olivia Owner" --person kc-member="Max Member"
   # {"issuer":"http://127.0.0.1:18555/realms/tutela", ...}
   ```
4. Make a tenant whose first owner is the provider's `kc-owner`: `TUTELA_DEV_MODE=1 TUTELA_OWNER_DATABASE_URL=<owner url> TUTELA_ISSUER=http://127.0.0.1:8080 cargo run -p tutelad -- tenant create --name Demo --admin-upstream http://127.0.0.1:18555/realms/tutela=kc-owner`. It prints the `tid`.
5. A trust file for the realm:
   ```toml
   [[issuer]]
   iss = "http://127.0.0.1:18555/realms/tutela"
   jwks_uri = "http://127.0.0.1:18555/realms/tutela/protocol/openid-connect/certs"
   algs = ["RS256"]
   tenants = ["<tid>"]
   external = true
   allow_typ_jwt = true
   ```
6. Start `tutelad` in dev mode (loopback `http` issuers) with the Console on:
   ```sh
   TUTELA_DEV_MODE=1 TUTELA_LISTEN=127.0.0.1:8080 TUTELA_OPS_LISTEN=127.0.0.1:9090 \
   TUTELA_DATABASE_URL=<service url> TUTELA_TRUST_FILE=trust.toml \
   TUTELA_ISSUER=http://127.0.0.1:8080 TUTELA_MASTER_KEY=<test key> TUTELA_KEY_PEPPER=<test pepper> \
   TUTELA_ADMIN_ACR=mfa \
   TUTELA_CONSOLE_DIR=console/dist \
   TUTELA_CONSOLE_ISSUER=http://127.0.0.1:18555/realms/tutela \
   TUTELA_CONSOLE_CLIENT_ID=tutela-console \
   cargo run -p tutelad
   ```
7. Open `http://127.0.0.1:8080/console/`, sign in as Olivia Owner with "Use MFA" ticked. The Console is read once at start: restart `tutelad` after a new build.

### Configure Keycloak for it

One public client per deployment, in the realm `TUTELA_CONSOLE_ISSUER` names (an external issuer of the trust file, written exactly as there):

| Setting | Value |
|---|---|
| Client id | `TUTELA_CONSOLE_CLIENT_ID`, for example `tutela-console` |
| Client authentication | off (public client) |
| Flows | standard flow only; no implicit flow, no direct access grants |
| PKCE | `S256` required (advanced settings, "Proof Key for Code Exchange Code Challenge Method") |
| Valid redirect URIs | `https://<tutelad host>/console/callback` |
| Web origins | `https://<tutelad host>` (CORS for discovery and the token endpoint) |
| Valid post-logout redirect URIs | `https://<tutelad host>/console/` |
| Audience | an "Audience" mapper that adds `TUTELA_AUDIENCE` (`tutela-authz`) to the access token |
| Step-up | an ACR-to-LoA mapping whose MFA level is named as the first value of `TUTELA_ADMIN_ACR` (for example `{"mfa": 2}`), and a browser flow that asks for OTP at that level; the Console asks for it with `acr_values` |

Each Keycloak access token must have a `jti` (Keycloak's do): `tutelad` exchanges each one once.

### The browser check

`make js-e2e` (part of `make`) runs the Phase B exit check in Playwright's Chromium against a real `tutelad`, a real Postgres and the test provider (ADR-0053). It needs `TUTELA_TEST_DATABASE_URL` like every database test, and Chromium build 1243, which `@playwright/test` 1.63.0 uses: install it once with `pnpm --filter @f8fvwgzc/tutela-console exec playwright install chromium` if your machine does not have it. Set `TUTELA_E2E_SHOTS=<dir>` to keep screenshots of the main pages.

## Develop and test

```sh
pnpm install          # node >= 22.12, pnpm 10
make js               # build, tsc, Biome, vitest, the integration test, the browser check, pnpm audit, licences
make js-it            # only the integration test: needs TUTELA_TEST_DATABASE_URL
make js-e2e           # only the Console's browser check: needs TUTELA_TEST_DATABASE_URL and Chromium 1243
```

- `sdk/js/test`: unit tests against a mocked `fetch`, one per error path, and a jsdom test that no storage API is touched.
- `sdk/js/test-integration`: the client against a real `tutelad` on a real Postgres. `crates/tutelad/tests/js_client.rs` makes two tenants with Keycloak-shaped realms, people and roles, starts the service, writes the upstream tokens to a fixture file and runs the file with vitest. It runs only with `TUTELA_JS_INTEGRATION=1` (`make js-it`), so plain `cargo test` needs no node.
- `sdk/react/test`: Testing Library in jsdom against a fake `tutelad`, and axe-core.
- `console/test`: the Console's sign-in states and every page's error paths, in jsdom against a fake realm and a fake `tutelad`, and axe-core.
- `console/e2e`: the Phase B exit check in Playwright's Chromium, run by `crates/tutelad/tests/console_e2e.rs` against a real `tutelad` ([The browser check](#the-browser-check)).

## Releasing

Nothing is published yet; publishing is the owner's step ([ADR-0047](DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make) item 7):

1. Set the release version in `sdk/js/package.json`, `sdk/react/package.json` and the `VERSION` constant of `sdk/js/src/index.ts` (the same version as the crates and the tag, CONTRACTS.md 10.5).
2. On a clean checkout of the signed tag, run `make` (it must pass).
3. `pnpm -r publish --access restricted` with a token that may write the `@f8fvwgzc` scope on GitHub Packages (`publishConfig.registry`). pnpm turns `workspace:*` into the exact version.
4. Products install with the `.npmrc` of INTEGRATION.md. Before any public npm release, register the `@f8fvwgzc` scope on npmjs.com (TM-21).
