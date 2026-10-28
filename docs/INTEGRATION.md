# Integrating with Tutela

> **Status: all of this page is planned.** Tutela is pre-alpha. In the first
> commit only the design docs, the `tutela-contracts` crate and CI exist.
> No repo can adopt Tutela yet. Each step below names the Tutela phase it
> needs: **A** (packages, library mode), **B** (`tutelad` service and Tutela
> Console), **C** (own login server, optional), **D** (hardening).
> See [ROADMAP.md](ROADMAP.md).

Related docs: [README](../README.md) ·
[AGENTS.md](../AGENTS.md) · [SECURITY.md](../SECURITY.md) ·
[ARCHITECTURE.md](ARCHITECTURE.md) · [PERMISSION-MODEL.md](PERMISSION-MODEL.md) ·
[CONTRACTS.md](CONTRACTS.md) · [THREAT-MODEL.md](THREAT-MODEL.md) ·
[ROADMAP.md](ROADMAP.md) · [DECISIONS.md](DECISIONS.md)

This page has two parts:

- **Part 1**: how the existing repos adopt Tutela, in order.
- **Part 2**: how to build a new product on Tutela.

File paths in Part 1 point into the other repos as of 2026-10-25. They may
move; check them before you start.

## Contents

- [Part 1: existing repos](#part-1-existing-repos)
  - [1. Rules for every repo](#1-rules-for-every-repo)
  - [2. texc-symphony](#2-texc-symphony)
  - [3. attache](#3-attache)
  - [4. onto-intelli](#4-onto-intelli)
  - [5. nexc-engine (product)](#5-nexc-engine-product)
  - [6. Summary: what each repo stops doing](#6-summary-what-each-repo-stops-doing)
- [Part 2: build a new product on Tutela](#part-2-build-a-new-product-on-tutela)

---

# Part 1: existing repos

## 1. Rules for every repo

### Order

| # | Repo | Kind | Effort | Tutela phase needed | Why this place in the order |
| --- | --- | --- | --- | --- | --- |
| 1 | texc-symphony | core | 0.5–1 person-week | A (B for delegated agent tokens) | Smallest change. It proves the `tutela-sdk` axum layer. |
| 2 | attache (`f8fvwgzc/agent-sidecar`) | core | 1–2 person-weeks | A, then B | Agent principals must exist before other repos accept agent tokens. |
| 3 | onto-intelli | core | 6–9 person-weeks | A, then B | The largest core change (per-property masking everywhere). |
| 4 | nexc-engine | **product** | to be estimated | A, then B | A product, so it comes last and uses all four cores. |

Each repo changes its own code in its own pull requests, in its own session.
The Tutela repo only documents the plan.

### How a repo depends on Tutela

- Install only published Tutela packages, pinned to a release tag
  (for example `v0.1.0`, the planned Phase A tag). Never a path dependency, a
  sibling checkout or a copied file.
- Every binary that links `tutela-sdk` installs **one** rustls crypto
  provider, **aws-lc-rs**, at startup. No OpenSSL.
- Keep a **standalone mode**: the repo must still build, test and run with
  only Postgres, Tutela in library mode and a dev OIDC issuer (Keycloak dev
  realm). Test it in the repo's CI.
- Keep the old login behind a flag until the dual run below has passed.

### The shadow-decision dual run

Use this whenever Tutela replaces an existing permission check (attache's
role-on-diff, onto-intelli's permissions, nexc-engine's role checks).

| Stage | Old check | Tutela check | Move on when |
| --- | --- | --- | --- |
| 1. Shadow | **decides** | runs and is logged, but does not decide | 1–2 weeks of logged decisions; every mismatch is explained and fixed (in the model or in the old code) |
| 2. Flip | runs and is logged | **decides** | one release with no unexplained mismatch |
| 3. Remove | deleted | **decides** | — |

A shadow call looks like this (illustrative; the API is fixed in Phase A):

```rust
// The old check still decides in stage 1.
let old_allowed = legacy_can(&member, LegacyAction::EditIssue);

// Tutela runs next to it. Its answer is only logged.
let decision = pdp.check(&caller, perms::ISSUE_WRITE, &resource)?;
if old_allowed != decision.is_allowed() {
    tracing::warn!(
        target: "tutela.shadow",
        action = "issue:write",
        resource_id = %resource.id,   // opaque ids only
        old = old_allowed,
        new = decision.is_allowed(),
        rules = ?decision.rule_ids,
        rev = decision.rev,
    );
}
```

Log opaque ids only. Never log tokens, e-mails or names.

### Dual-acceptance windows for old credentials

Old credentials do not stop working on one day. Each one goes through a
window:

| Step | Behaviour |
| --- | --- |
| 1 | Tutela credentials are accepted. Old credentials are still accepted. New old-style credentials are no longer issued. |
| 2 (one release later) | Old credentials sit behind a flag that is **off by default**. |
| 3 (the release after) | The old code is deleted. |

Old API keys are stored as hashes, so they cannot be copied into Tutela.
During the window, owners create new Tutela keys (`tut_sk_…` for apps and
service accounts, `tut_ak_…` for agents) and retire the old ones.

| Repo | Old credential | Replaced by |
| --- | --- | --- |
| texc-symphony | None today: the API router has no token check | Tutela access token with `aud=symphony` |
| attache | `att_` operator tokens (`services/embassy/src/token.rs`) | Humans: OIDC sign-in. Machines: Tutela service-account keys `tut_sk_…` |
| onto-intelli | `onto1.` session tokens, `onto_sk_` project keys, `x-onto-act-*` headers (all in `crates/onto-grpc/src/auth.rs`) | Tutela access tokens, delegated agent tokens, `tut_sk_…` keys |
| nexc-engine | HS256 session JWTs (`NEXC_JWT_SECRET`), `nexc_agt_` firewall API tokens (`backend/src/security/api_token.rs`), `NEXC_ONTO_TOKEN` | Tutela access tokens; `tut_ak_…` agent keys (the firewall moves to attache); one exchanged token per audience |

One exception: onto-intelli refuses `x-onto-act-*` headers **whenever a
Tutela token is present**, from the first day of its window.

---

## 2. texc-symphony

**Goal:** symphony's task API accepts only Tutela-verified callers.
**Effort:** 0.5–1 person-week. **Needs:** Tutela Phase A (`tutela-sdk`);
Phase B for delegated agent tokens.

### Steps

1. Add `tutela-sdk` to `crates/symphony-server/Cargo.toml` (git dependency
   pinned to a Tutela release tag).
2. In `crates/symphony-server/src/app.rs`, wrap the API routes with the
   `tutela-sdk` axum layer. The layer requires **exactly one audience,
   `aud=symphony`**. The trust list names the issuer (Keycloak in Phases A–B)
   and the tenants it may speak for.
3. Install the aws-lc-rs crypto provider at startup in the server binary.
4. Callers:
   - another service: a Tutela service-account key or `client_credentials`
     token for `aud=symphony`;
   - an agent working for a person (Phase B): a delegated agent token
     (`typ: agent+jwt`) issued for `aud=symphony`. Turn on delegation support
     in the layer and register symphony as `delegation_aware = true`.
     Symphony never forwards that token; for any downstream call it gets a
     new token for that audience.
5. Browser events: a browser `EventSource` cannot send headers. Never put a
   token in the SSE URL. Use a same-site session cookie or a fetch-based
   stream.
6. Add tests: no token → 401; wrong audience → 401; agent token while
   delegation support is off → refused.

### Shadow run and old credentials

No shadow run is needed: symphony has no permission checks to replace.
There is no old credential either. Suggested: keep a local single-user mode
that listens on `127.0.0.1` only; any other listen address requires tokens.

### What symphony stops doing

Serving its task API without checking who calls.

---

## 3. attache

Repo `f8fvwgzc/agent-sidecar` (local folder `attache`).

**Goal:** humans and machines that change attache's configuration are
Tutela principals; agents are Tutela principals; attache keeps every agent
decision (tool, host, model, risk).
**Effort:** 1–2 person-weeks. **Needs:** Tutela Phase A for sign-in and
`tutela-pdp`; Phase B for service-account keys, agent principals and
delegated tokens.

### Steps

1. **Crypto provider first.** Today `services/agentscd/src/lib.rs` and
   `services/embassy/src/main.rs` install the `ring` provider. Switch both to
   aws-lc-rs before linking `tutela-sdk`.
2. **Embassy console sign-in (A).** Humans sign in through OIDC
   (Keycloak in Phases A–B), with an HttpOnly, SameSite session cookie.
   Code: `services/embassy/src/auth/` (`mod.rs`, `session.rs`, `http.rs`).
3. **Role-on-diff (A).** `required_role(old, new)` in
   `crates/agentsc-charter/src/diff.rs` returns a fixed `Role` today. Change
   it to return **permission keys**. Embassy checks those keys for the caller
   with `tutela-pdp`. Run the shadow dual run on this check.
4. **Operator tokens (B).** `att_` operator tokens become Tutela
   service-account keys (`tut_sk_…`), with a dual-acceptance window.
5. **Agent principals (B).** attache's agent registry stays the system of
   record for agents. When it creates an agent, it creates the principal
   `agent:agt_<uuidv7>` through `tutela.admin.v1`. When it quarantines an
   agent, it disables that principal (Tutela then emits
   `tutela.principal.disabled.v1`).
6. **Delegated tokens (B).** When an agent acts for a person, attache
   exchanges the person's token at `tutelad` (RFC 8693) for a delegated agent
   token: `sub` = the person, `act = {sub: agent:agt_…}`, `cap` = attache's
   capability snapshot (Tutela does not read it), run and node ids, exactly
   one audience, TTL 60–120 s. The effective access is always the overlap
   (person AND agent), capped by `cap`.
7. **Audit (optional).** attache offers an acknowledged Append API on its
   evidence ledger. Tutela forwards copies of its audit events there when
   configured (not through the OpenTelemetry collector, which can drop data).
8. **SPIFFE stays in attache.** Workload principals are
   `workload:<spiffe uri>`, bound to a trust bundle. The trust domain must be
   unique per cluster; today it is the constant `agentsc` in
   `crates/agentsc-common/src/identity.rs`, so it must become configurable.

### What attache stops doing

- Its own role list for charter changes (the fixed `Role` in `diff.rs`).
- Long-lived `att_` tokens for humans.
- Deciding "may this person touch this data". That is Tutela's question.
  attache keeps "may this agent use this tool, host or model, and at what
  risk".

---

## 4. onto-intelli

**Goal:** onto-intelli signs nobody in by itself, takes tenants and
permissions from Tutela, and masks hidden properties everywhere data leaves.
**Effort:** 6–9 person-weeks. **Needs:** Tutela Phase A (`tutela-sdk`,
`tutela-pdp`, `tutela-vault`, `tutela-safenet`); Phase B (memberships and
groups from `tutelad`, `PutResourceTypes`, Console pages, delegated tokens).

### Steps

1. **Authentication.** `Auth::authenticate` in
   `crates/onto-grpc/src/auth.rs` accepts Tutela access tokens and delegated
   agent tokens, verified offline with `tutela-sdk`. The tenant comes from
   the token (`iss`, `tid`). A header may narrow a call, never pick another
   tenant.
2. **Impersonation headers.** `x-onto-act-*` headers are refused whenever a
   Tutela token is present. New installs ship with impersonation off.
3. **Permissions.** Permissions come from `tutela-pdp`. Membership and
   groups come from Tutela. Run the shadow dual run against onto's current
   decisions.
4. **Per-entity visibility stays in onto.** `policy::check` / `visible`
   (`crates/onto-core/src/policy.rs`) still run once per entity, in-process,
   inside graph traversal, now fed by Tutela's permissions. The `acl` stays
   on the entity, but only admins may edit it.
5. **Per-property masking** across ask, reason, explain, export, MCP output,
   traces and the vector index. Hidden fields are removed **before** a
   prompt is built. Agents never read outside their `ai_reach`.
6. **Resource types (B).** onto owns a small adapter that pushes its object,
   link and action types to Tutela through `tutela.admin.v1`
   `PutResourceTypes`. Tutela never parses onto's events. The change is
   additive; a widening change needs approval; a new confidential or secret
   field starts at None.
7. **Console pages (B).** onto console's Keys, Members, Projects and
   Sessions pages move to the Tutela Console.
8. **Old credentials.** `onto1.` sessions and `onto_sk_` keys follow the
   dual-acceptance window.
9. **Shared crates.** Tutela's `tutela-vault` and `tutela-safenet` are built
   from onto's `crates/onto-control/src/vault.rs`,
   `crates/onto-control/src/net.rs` and `crates/onto-intelli/src/net.rs`.
   After Tutela v0.1, onto switches to the crates and deletes its copies, so
   one owner keeps them.

### What onto-intelli stops doing

- Its own sign-in, sessions and upstream SSO (`crates/onto-control/src/oidc.rs`,
  `crates/onto-control/src/signin.rs`).
- Its own orgs, members, keys and key pepper (`crates/onto-control/src/keys.rs`).
- Trusting `x-onto-act-*` headers.
- Its own copies of the vault and the safe HTTP client.

It keeps: per-entity visibility inside traversal, schema governance, and its
data.

---

## 5. nexc-engine (product)

nexc-engine is a **product** (a Linear-style work tracker), not a core.
Its AgentSecOps code (firewall, approvals, agent registry, runtime, model
gateway, ledger) moves to attache. That move has its own plan in the attache
repo; this section covers only the Tutela part.

**Goal:** nexc-engine keeps no users, roles or secrets code of its own.
**Effort:** to be estimated. **Needs:** Tutela Phase A for checks, vault and
safenet; Phase B for runtime roles, the Console and delegated tokens.

### Steps

1. **Token check.** The `Caller` extractor in `backend/src/http/extract.rs`
   verifies Tutela tokens with `tutela-sdk`.
2. **Users, workspaces, teams, roles move to Tutela.** A workspace becomes a
   Tutela **org**. `WorkspaceRole` and `TeamRole`
   (`backend/src/domain/workspace.rs`) become **seeded roles** in nexc's
   `tutela.resources.toml`.
3. **Role call sites.** About 38 call sites (`can()` / `TeamAccess` and
   `role_of` / `find_for`, in `backend/src/http/handlers/` and
   `backend/src/repo/`) switch to `tutela-pdp` **after 1–2 weeks of logged
   shadow decisions**.
4. **Lists.** Issue, project and search lists use `Pdp::list_filter` inside
   SQL. Responses strip masked fields.
5. **Secrets.** `backend/src/security/secret_box.rs` is replaced by
   `tutela-vault`. Re-encrypt stored secrets once, then delete the old code.
6. **Outbound URLs.** `check_production_url` in
   `backend/src/http/handlers/settings.rs` checks only the URL text. It is
   replaced by `tutela-safenet`, which checks the resolved address at connect
   time.
7. **Login.** `backend/src/security/` `password.rs`, `totp.rs`, `session.rs`,
   `gate.rs` and `oidc.rs` are replaced by the OIDC issuer (Keycloak in
   Phases A–B) plus Tutela tokens. Local login stays behind a flag until the
   dual run passes. User import: try importing the Argon2id hashes into
   Keycloak during the dual run; if the format is not accepted, users reset
   their passwords.
8. **Agent tokens (B).** Per-run agent tokens (`backend/src/security/agent_token.rs`)
   stop being minted by nexc. Delegated agent tokens come from `tutelad`
   token exchange, requested by attache's runtime. The overlap rule applies
   to chat, task work and scheduled work, using the person who caused the
   work.
9. **UI.** The frontend uses `@f8fvwgzc/tutela-react` (`<Can>`, `<Field>`,
   `<Protect>`) with UI keys from the manifest.

### What nexc-engine stops doing

- Its own users, sessions, passwords, TOTP, SSO and role tables.
- `secret_box.rs` and the URL-text SSRF check.
- Minting agent tokens and API tokens for agents.
- AgentSecOps in general (moves to attache).

---

## 6. Summary: what each repo stops doing

| Duplicated today | Where today | Single owner after integration |
| --- | --- | --- |
| Login, sessions, SSO | onto-intelli, nexc-engine, attache (embassy) | OIDC issuer (Keycloak) + Tutela; Tutela's own login server later (C, optional) |
| Users, orgs/workspaces, members, groups | onto-intelli, nexc-engine | Tutela |
| Hard-coded role sets | four different sets across the repos | Tutela roles, defined per tenant |
| API keys and their peppers | onto-intelli, attache, nexc-engine | Tutela (`tut_sk_…`, `tut_ak_…`) |
| Secret encryption | onto-intelli `vault.rs`, nexc-engine `secret_box.rs` | `tutela-vault` |
| SSRF-safe outbound HTTP | onto-intelli `net.rs` (two copies), nexc-engine URL check | `tutela-safenet` |
| Agent tokens | nexc-engine `agent_token.rs` | `tutelad` delegated tokens (requested by attache) |
| Agent firewall, approvals, registry, runtime, model gateway, ledger | nexc-engine (part), attache (part) | attache |

---

# Part 2: build a new product on Tutela

All planned. Example names below are illustrative (a CRM with invoices).
Exact file formats and APIs are fixed in Phase A; the permission rules are in
[PERMISSION-MODEL.md](PERMISSION-MODEL.md).

## Step 1. Install the packages

Pick by backend language:

| Backend | Packages | Mode |
| --- | --- | --- |
| Rust | `tutela-sdk`, `tutela-pdp` (+ `tutela-store` in library mode) | Library or service |
| Node | `@f8fvwgzc/tutela-node` | Service (checks need `tutelad`) |
| Python | `tutela-py` | Service (checks need `tutelad`) |
| Any web UI | `@f8fvwgzc/tutela-react` (or `@f8fvwgzc/tutela-js` without React) | — |

Rust (`api/Cargo.toml`):

```toml
[dependencies]
tutela-sdk   = { git = "ssh://git@github.com/f8fvwgzc/tutela.git", tag = "v0.1.0" }
tutela-pdp   = { git = "ssh://git@github.com/f8fvwgzc/tutela.git", tag = "v0.1.0" }
tutela-store = { git = "ssh://git@github.com/f8fvwgzc/tutela.git", tag = "v0.1.0" } # library mode only
```

```toml
# api/.cargo/config.toml
[net]
git-fetch-with-cli = true   # cargo uses your SSH agent locally and a read token in CI
```

In `main`, install the one crypto provider before anything else:

```rust
rustls::crypto::aws_lc_rs::default_provider()
    .install_default()
    .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;
```

Web (`web/package.json` and `web/.npmrc`):

```json
{ "dependencies": { "@f8fvwgzc/tutela-react": "0.1.0" } }
```

```ini
@f8fvwgzc:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

Python (`pyproject.toml`, with uv):

```toml
[project]
dependencies = ["tutela-py"]

[tool.uv.sources]
tutela-py = { git = "ssh://git@github.com/f8fvwgzc/tutela.git", tag = "v0.1.0", subdirectory = "sdk/python" } # planned location
```

## Step 2. Register the app

- **Service mode (B):** `tutela apps create` registers the client id,
  redirect URIs, allowed origins and the API audience (for example
  `aud=crm-api`). Set `delegation_aware = true` only if the API must accept
  delegated agent tokens.
- **Library mode (A):** there is no `tutelad`. Create the client in your
  OIDC issuer (the Keycloak dev realm in compose) and add that issuer and its
  tenants to the `tutela-sdk` trust list.

Every access token must carry **exactly one audience**.

## Step 3. Write `tutela.resources.toml`

Run `tutela init` for a starter file (planned, Phase A). The manifest
declares resource types, fields with their sensitivity, actions, roles, field
rules, conditions and UI keys. The format is fixed in
[MANIFEST.md](MANIFEST.md). An example:

```toml
# tutela.resources.toml  (format v1; full rules in docs/MANIFEST.md)
version = 1

[app]
name     = "crm"
audience = "crm-api"

# Every resource has exactly one parent.
[types.project]
parent    = "org"
container = true

[types.invoice]
parent = "project"

[types.invoice.actions]
approve = { needs = "write" }   # needs Write and the grant on the role
export  = { needs = "read" }

[types.invoice.fields]
number       = { sensitivity = "internal" }
status       = { sensitivity = "internal" }
amount       = { sensitivity = "confidential" } # new confidential field: starts at None
bank_account = { sensitivity = "secret" }       # new secret field: starts at None

# Levels: none < read < write < full. Seeded roles (owner, member, viewer,
# guest, agent) exist already; this entry replaces the seeded viewer.
[roles.finance]
grants = { "project" = "read", "invoice" = "write", "invoice.amount" = "read", "invoice:approve" = true }

[roles.viewer]
grants = { "project" = "read", "invoice" = "read" }

# amount starts hidden for every role; open it for finance only.
[[field_rules]]
field = "invoice.amount"
role  = "finance"
max   = "read"

# Each UI key names the actions AND the API routes behind it.
[ui."invoices.approve_button"]
actions     = ["invoice:approve"]
routes      = ["POST /api/invoices/{id}/approve"]
when_denied = "disable"          # show | disable | hide | readonly
reason      = "Only finance can approve invoices."

[ui."invoices.export_button"]
actions     = ["invoice:export"]
routes      = ["POST /api/invoices/export"]
when_denied = "hide"
```

Then:

```sh
tutela apply      # shows the diff first; a widening diff fails without an approval token
tutela codegen    # typed permission constants, React UI-key constants, server route guards
```

Because `tutela codegen` makes typed constants, a renamed action breaks the
build, not production.

## Step 4. Guard every handler

The `tutela-sdk` layer verifies the token. Each handler then checks the
action on the resource, using the path and attributes loaded **from your own
database by id**, never from the request body.

```rust
// illustrative; the API is fixed in Phase A
async fn approve_invoice(
    caller: tutela_sdk::Caller,           // set by the tutela-sdk layer
    State(app): State<App>,
    Path(id): Path<InvoiceId>,
) -> Result<Json<InvoiceOut>, AppError> {
    let resource = app.db.invoice_resource(caller.tenant(), id).await?; // path + attrs by id
    let decision = app.pdp.check(&caller, perms::INVOICE_APPROVE, &resource)?;
    if !decision.is_allowed() {
        return Err(AppError::forbidden(decision.reason));
    }
    let invoice = app.db.approve(caller.tenant(), id).await?;
    Ok(Json(InvoiceOut::masked(invoice, &decision.field_mask)))
}
```

- For writes, use `Pdp::write_check`: it gives a verdict per field.
  Changing a field that grants access needs `manage_access`.
- The SDK **refuses to start** if a route declared in the manifest has no
  guard.
- A generated test calls each declared route as a denied principal.
- After your own write, send `at_least_revision` on the next check, so you
  read your own change.

## Step 5. Filter lists inside SQL

Never load rows and then drop the hidden ones: page sizes and counts would
leak. `Pdp::list_filter` returns `ids_in` + `container_in` + a condition AST.
The SDK turns it into SQL with **bound parameters only**. The result has this
shape:

```sql
SELECT id, number, status                     -- columns from field_mask.read
FROM invoice
WHERE tenant_id = $1
  AND (id = ANY($2) OR ancestors && $3)        -- ids_in, container_in
  AND (status = $4)                            -- condition AST
ORDER BY created_at DESC
LIMIT $5;
```

Counts use the same filter. `ancestors` holds the ids on each row's path, so
`container_in` matches rows at any depth below a scope. It is an array of
ancestor ids, nearest first, with a GIN index
([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator)).

## Step 6. Strip masked fields everywhere data leaves

`field_mask.read` lists what the caller may see. Apply it to:

- API responses;
- search and vector indexes;
- exports and notifications;
- audit (store before/after as digests or per-field encrypted);
- AI prompts: remove hidden fields **before** the prompt is built.

## Step 7. Use the UI components

Default is backend-for-frontend: the browser has an HttpOnly, SameSite
session cookie and never holds the access token. The product backend serves
the permission map:

- library mode: it computes the map with `tutela-pdp`;
- service mode: it calls `POST /v1/authz/permissions` on `tutelad` with its
  own client credentials plus the user's subject (ETag / 304).

```tsx
// illustrative; the API is fixed in Phase A
import { TutelaProvider, Can, Field, Protect, useCan } from "@f8fvwgzc/tutela-react";
import { ui } from "./generated/tutela"; // from `tutela codegen`

export function InvoicePage({ invoice }: { invoice: Invoice }) {
  const res = { type: "invoice", id: invoice.id };
  return (
    <TutelaProvider mapUrl="/api/tutela/permissions">
      <Protect component={ui.ADMIN_NAV}>
        <AdminMenu />
      </Protect>
      <Can component={ui.INVOICES_APPROVE_BUTTON} resource={res}>
        <Button onClick={() => approve(invoice.id)}>Approve</Button>
      </Can>
      <Field resource={res} name="amount">
        {invoice.amount}
      </Field>
    </TutelaProvider>
  );
}
```

UI hiding is never security. The server checks again (Step 4).

## Step 8. Embed the admin components (optional, service mode, Phase B)

So your own customers can manage roles at runtime, embed `RoleEditor`,
`MembersTable` and the permission matrix from `@f8fvwgzc/tutela-react`.

- They use a separate token with `aud=tutela-admin`, a 5-minute TTL and
  step-up MFA.
- Every change goes through `tutelad`: narrow-only delegation, an impact
  report, and approval for widening changes.

## Step 9. Local development

Library mode needs no `tutelad`. `tutela-pdp` and `tutela-store` run inside
your backend; `tutela-sdk` trusts the Keycloak dev realm.

```yaml
# compose.yaml  (illustrative; pin exact image tags)
services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: dev-only-password        # test value only
  keycloak:
    image: quay.io/keycloak/keycloak:26.4.0      # any pinned 26.x
    command: ["start-dev", "--import-realm"]     # one realm, Keycloak Organizations on
    volumes:
      - ./dev/realm.json:/opt/keycloak/data/import/realm.json:ro
  # Service mode only (Phase B):
  # tutelad:
  #   image: ghcr.io/f8fvwgzc/tutelad:<release>
  #   environment:
  #     TUTELA_DATABASE_URL: postgres://tutela:dev@postgres/tutela
  #     TUTELA_MASTER_KEY: ${TUTELA_MASTER_KEY}            # dev value from .env.example
  #     TUTELA_KEY_PEPPER: ${TUTELA_KEY_PEPPER}            # separate from the master key
  #     TUTELA_KEY_PEPPER_VERSION: "1"
```

- Test users live in seed and fixture files. Never use real credentials.
- Run `cargo run` in `api/` and your web dev server in `web/`.

## Step 10. Deploy with Helm (service mode: Phase B; chart hardening: Phase D)

```yaml
# deploy/Chart.yaml  (excerpt, illustrative)
dependencies:
  - name: tutela
    version: <tutela release>
    repository: oci://ghcr.io/f8fvwgzc/charts
```

- Run **2 or more** `tutelad` replicas.
- A bootstrap job creates client credentials and webhook secrets before the
  other charts start. Secrets live in Kubernetes Secrets, not in values
  files.
- `tutela apply` runs as a deploy hook and prints its diff. A widening diff
  fails without an approval token.
- `TUTELA_KEY_PEPPER` is separate from `TUTELA_MASTER_KEY` and versioned.
  Never derive one from the other.

## Before you go live

- [ ] Every handler has a guard; the generated denied-principal tests pass.
- [ ] A test calls the API directly, without the UI, and is refused.
- [ ] A cross-tenant read fails.
- [ ] List pages and counts do not change because of hidden rows.
- [ ] Masked fields are absent from responses, indexes, exports,
      notifications, audit and prompts.
- [ ] Only one rustls provider (aws-lc-rs) is installed; no OpenSSL.
- [ ] Logs, URLs and span attributes contain no tokens and no personal data.

Threats and mitigations: [THREAT-MODEL.md](THREAT-MODEL.md).
Wire contracts: [CONTRACTS.md](CONTRACTS.md).
