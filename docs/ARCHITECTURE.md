# Tutela architecture

> **Status: pre-alpha.** In the first commit only the design docs, the
> `tutela-contracts` crate and CI exist. Everything else on this page is
> **planned**. Each part is marked with the phase that builds it:
> **A** (packages, library mode), **B** (`tutelad` service and Tutela Console),
> **C** (own login server, optional), **D** (hardening).
> See [ROADMAP.md](ROADMAP.md).

Related docs: [README](../README.md) ·
[AGENTS.md](../AGENTS.md) · [SECURITY.md](../SECURITY.md) ·
[PERMISSION-MODEL.md](PERMISSION-MODEL.md) · [CONTRACTS.md](CONTRACTS.md) ·
[THREAT-MODEL.md](THREAT-MODEL.md) · [INTEGRATION.md](INTEGRATION.md) ·
[ROADMAP.md](ROADMAP.md) · [DECISIONS.md](DECISIONS.md)

## Contents

1. [Tutela in the platform](#1-tutela-in-the-platform)
2. [Components](#2-components)
3. [Two ways to use Tutela: library mode and service mode](#3-two-ways-to-use-tutela-library-mode-and-service-mode)
4. [Data ownership](#4-data-ownership)
5. [Request path](#5-request-path)
6. [Admin path](#6-admin-path)
7. [Availability](#7-availability)
8. [Dependency rules for Tutela itself](#8-dependency-rules-for-tutela-itself)

---

## 1. Tutela in the platform

### Four cores, products on top

The platform has four independent **core** repos. Each core has its own CI,
its own releases and its own roadmap. Products install the cores' published
packages. Products never copy core code.

| Core | Repo | Its job |
| --- | --- | --- |
| **Tutela** (new) | `f8fvwgzc/tutela` | Identity and permissions. Clerk/Auth0-like. Its own backend service and its own UI (console and embeddable admin components). |
| **attache** | `f8fvwgzc/agent-sidecar` | AgentSecOps: agent sidecar and mesh (SPIFFE mTLS), guardrails, taint, budgets, policy decisions, approvals, the agent firewall API, the agent registry, the agent runtime, the model gateway (every model call goes through trusted attache code), the tamper-evident evidence ledger. |
| **onto-intelli** | `f8fvwgzc/onto-intelli` | Fully automated enterprise ontology: connectors, dynamic modeling, reasoning, knowledge, long-term agent memory, MCP data tools. |
| **texc-symphony** | `f8fvwgzc/texc-symphony` | AI task executor: any task assigned to AI and handled to completion, with any LLM provider (Codex, Claude Code, any Anthropic or OpenAI-compatible model), with a task API. |

**Products** are not cores. They sit on top and use all four cores.

| Product | Status |
| --- | --- |
| **nexc-engine** | First product: a Linear-style work tracker. Today it also holds AgentSecOps code; that code moves to attache. |
| CRM-like, ERP/SAP-like, Salesforce-like products | Later. |

### Dependency direction

Arrows point **down only**. A higher layer may also use any lower layer
directly (for example, every product uses Tutela directly for sign-in and
permission checks). There are no cycles.

```
  PRODUCTS     nexc-engine (Linear-style)    later: CRM, ERP/SAP-like, Salesforce-like
                      |                                  |
                      v                                  v
  CORES        onto-intelli                       texc-symphony
                      \                                  /
                       v                                v
                                   attache
                         (AgentSecOps, agent runtime, model gateway, ledger)
                                      |
                                      v
                                   Tutela
                         (identity and permissions; depends on no core)
```

Rules:

- **Tutela depends on no other core.** It is the lowest layer.
- A core may depend on another core **only through that core's published
  client or contract packages**. Never through a server crate, a path
  dependency, a sibling checkout or a vendored copy.
- Tutela never reads another core's internal events. When a core needs
  Tutela to know something, the core calls Tutela's API
  (`tutela.admin.v1`). Example: onto-intelli owns a small adapter that pushes
  its object, link and action types to Tutela with `PutResourceTypes`.

### The boundary rule

> Tutela answers: "may this principal touch this data or resource?"
> attache answers: "may this agent use this tool, host or model, and at what risk?"
> onto-intelli keeps per-entity visibility inside graph traversal (called once per entity, in-process), fed by Tutela's permissions.
> UI hiding is never security. Every server checks again.

What Tutela **never** does:

- store a product's records;
- decide an agent's tool, host or model use (attache does that);
- run workload mTLS (attache owns SPIFFE).

### Is Tutela required? (three answers)

| Part | Required? | Why |
| --- | --- | --- |
| Tutela core packages (`tutela-sdk`, `tutela-pdp`, ...) | **Yes** | Every product needs login, keys, roles and permission checks. Today four different hard-coded role sets exist, and no tenant can define roles. |
| A running `tutelad` | **Yes**, for runtime tenant-defined roles and for non-Rust apps | See [section 3](#3-two-ways-to-use-tutela-library-mode-and-service-mode). |
| Tutela's own login server (OIDC provider) | **Optional** (Phase C) | Keycloak 26.x (Apache-2.0) is the login server first, and it can stay for good. |

---

## 2. Components

### Overview

| Component | Kind | Job | Data it owns | Phase |
| --- | --- | --- | --- | --- |
| `tutela-contracts` | Rust crate (later also `.proto` files and JSON Schemas) | Wire types shared by every package and every consumer | None (types only) | **Exists** (first commit); filled in during A |
| `tutela-pdp` | Rust crate, linked in-process | The embedded decision engine (PDP = policy decision point) | None on disk; in-memory model per (tenant, rev) | A |
| `tutela-store` | Rust crate | Postgres schema, migrations and data access for the permission tables | The permission tables (see [section 4](#4-data-ownership)) | A |
| `tutela-sdk` | Rust crate | Token verifier, axum and tonic layers, decision cache, resource loaders | In-memory JWKS cache and decision cache | A |
| `tutela-vault` | Rust crate | Envelope encryption with a KMS trait | None (callers keep the encrypted values in their own tables) | A |
| `tutela-safenet` | Rust crate | SSRF-safe outbound HTTP | None | A |
| `tutelad` | Service binary (OCI image `ghcr.io/f8fvwgzc/tutelad`) | The Tutela service: APIs, admin, events, audit, token exchange; later the login server | Tenants, orgs, users, memberships, groups, roles, bindings, apps, key hashes, signing keys, webhooks, outbox, audit chain | B (login server: C) |
| Tutela Console | Web UI, served by `tutelad` | Admin screens for the whole deployment | None of its own; it uses `tutelad` | B |
| `tutela` CLI | Binary | `tutela init`, `tutela apply`, `tutela codegen`, `tutela apps create`, `tutela keys rotate` | None (local files only) | `init`, `apply`, `codegen`: A. `apps create`, `keys rotate`: B (they need `tutelad`) |
| `@f8fvwgzc/tutela-react` | npm package | `<Can>`, `<Field>`, `<Protect>`, `useCan`; embeddable admin parts | The permission map, in browser memory | A (admin parts: B) |
| `@f8fvwgzc/tutela-node` | npm package | Server middleware for Node: verify tokens, call the check API | None | A (checks need `tutelad`: B) |
| `@f8fvwgzc/tutela-js` | npm package | Browser client without React; `tutela-react` builds on it | None | A |
| `tutela-py` (import `tutela`) | Python package | Token verifier, FastAPI dependency, check client | None | A (checks need `tutelad`: B) |

### `tutela-contracts` (exists)

The shared language. Every other package and every consumer uses these types.

- Principal strings (opaque ids; names are only display labels):
  `user:usr_<uuidv7>`, `sa:sa_<uuidv7>`, `key:key_<uuidv7>`,
  `agent:agt_<uuidv7>`, `workload:<spiffe uri>`.
- Access-token claims, the decision object, `audit.v1`, the CloudEvents
  envelope and event types `tutela.<entity>.<verb>.v1`.
- Later (Phase B): the `.proto` files for `tutela.authz.v1` and
  `tutela.admin.v1`. They are not in the first commit.
- Contracts are additive only. Details: [CONTRACTS.md](CONTRACTS.md).

### `tutela-pdp` (Phase A)

A small native Rust evaluator over the permission tables. No network calls.

- API: `Pdp::check`, `Pdp::batch`, `Pdp::list_filter`, `Pdp::write_check`.
- It also holds the model compiler (module `model`): it reads
  `tutela.resources.toml` ([MANIFEST.md](MANIFEST.md)), refuses anything the
  rules do not allow, and classifies a model change as narrowing, neutral or
  widening. The evaluator uses the same compiled model (both built,
  [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening),
  [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).
- It resolves the effective level **once per (principal, scope)**. From the
  same code it produces both the decision and the SQL list filter
  (`ids_in` + `container_in` + condition AST; all values are bound
  parameters). For the filter it gets scope paths from a provider keyed by
  (tenant, type, id) and fails closed when a path is missing.
- A property test proves: rows returned by `list_filter` == rows that
  `check()` allows.
- Decision object: `effect`, `level`, `field_mask {read, write}`, rule ids,
  `reason`, `rev`, `obligations`.
- `write_check` gives a verdict per field for a write. Changes to fields that
  grant access need `manage_access`.
- Agent rule: an agent acting for a person always gets the overlap
  (person allowed AND agent allowed), capped by attache's capability limits.
- Cedar (`cedar-policy`) may be used later, only for vetted condition
  templates.
- The model rules (four levels, closest role wins, private scopes, field
  rules) are in [PERMISSION-MODEL.md](PERMISSION-MODEL.md).

### `tutela-store` (Phase A)

The Postgres tables and migrations for bindings, field rules, groups,
boundary settings, scope paths and model revisions. **The same schema is
used in library mode (inside the product's own database) and by
`tutelad`.** Every call runs in the product's own transaction: it sets the
tenant with `SET LOCAL` (every tenant table has `FORCE ROW LEVEL SECURITY`),
bumps the per-tenant revision in the same transaction as the change, and
checks the whole tenant data with the evaluator's load checks before the
commit. `load` reads a tenant's revision, `TenantData` and scope paths in one
consistent view ([ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)).
Assignments, groups and the group and path closures read back through the same
transaction, and `expire_assignments` removes what has expired and bumps the
revision ([ADR-0020](DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry)).

### `tutela-sdk` (Phase A)

What a Rust product links to talk to Tutela.

- Verifies access tokens from **any OIDC issuer**, offline, with a cached
  JWKS: alg allow-list, `iss`, exactly one `aud`, `exp`, `nbf`, `epoch`.
  Built: `Verifier` follows the CONTRACTS §4.2 order; the JWKS comes through
  `tutela-safenet`, is refreshed after a TTL, refetched at most once per
  interval for an unknown `kid`, used for at most an hour when the issuer
  is down, and a `kid` deny-list applies at once.
- A trust list maps each issuer to the tenants it may speak for. The tenant
  key everywhere is the pair (`iss`, `tid`).
- Refuses delegated agent tokens (`typ: agent+jwt`) unless delegation support
  is turned on.
- axum and tonic layers, a decision cache, and helpers that load a
  resource's path and attributes **server-side by id** (never from the
  request body). Built: `CachedPdp` (cleared on every load) and the
  `list_filter` SQL adapter `tutela_sdk::sql` (bound parameters, mapped
  columns, a statement timeout that fails closed). Route guards receive the
  ids from the path; the product loads the resource by id.
- Refuses to start if a route declared in `tutela.resources.toml` has no
  guard. Built: `tutela_sdk::http::AuthLayer` (one tower layer for axum and
  tonic: 401, or `grpc-status: 16`), `Guards::check_complete` over the
  codegen `ROUTES` table, `GuardLayer` (a declared route without a guard is
  403), and `assert_routes_deny` for the generated denied-route test.

### `tutela-vault` (Phase A)

Envelope encryption: each secret gets its own data key; the data key is
encrypted with a master key behind a KMS trait. Keys come from
`TUTELA_MASTER_KEY`, with `TUTELA_MASTER_KEY_PREVIOUS` for rotation. Its
design comes from onto-intelli `crates/onto-control/src/vault.rs`. Built: the
blob is versioned and names the key that wrapped its data key; the data key
and the secret are both bound to a purpose and a context (length-prefixed in
the AES-256-GCM associated data); `rewrap` moves a blob to the current key
without touching the secret's ciphertext; a missing master key is an error,
never a made-up key.

### `tutela-safenet` (Phase A)

Outbound HTTP that cannot be pointed at internal services. It checks the
**resolved** IP address at connect time (not only the URL text) and on every
redirect. Its design comes from onto-intelli `crates/onto-control/src/net.rs`
and `crates/onto-intelli/src/net.rs`. `tutela-sdk` uses it for JWKS and
discovery fetches, and `tutelad` for webhooks. Built: the host is resolved once
in the client's own resolver and every address is checked there, so the
connection uses exactly the checked addresses; redirects are never followed
(a redirect is returned, not followed); `https` only (`http` to loopback in dev
mode); timeouts and a body size limit; an exact allow-list for private hosts
an operator needs; TLS is rustls on aws-lc-rs.

### `tutelad` (Phase B; login server Phase C)

The Tutela service. Run **2 or more replicas**.

Built so far ([ADR-0018](DECISIONS.md#adr-0018-tutelad-the-stack-the-two-ports-and-the-config)): the
service itself. Config from `TUTELA_*` and a trust file, the API port (HTTP and
gRPC, axum and tonic, every request behind `tutela-sdk`'s `AuthLayer`), the ops
port (`/healthz`, `/readyz`, `/metrics`), JSON logs and the graceful shutdown.
Tenant isolation is built too
([ADR-0019](DECISIONS.md#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked)).
`tutelad migrate` runs the migrations and grants as the owner, apart from the
service. A timer removes expired assignments, tenant by tenant, and bumps each
revision. Production settings are in `deploy/`. The evaluation API is built
([ADR-0021](DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease)):
each replica answers from an in-memory snapshot per tenant, and checks the
tenant's revision against Postgres once a second while the tenant is in use.
The rest of this list is planned.

- **Check API** (AuthZEN 1.0 shape): `POST /access/v1/evaluation`,
  `/access/v1/evaluations` (up to 200 items) and gRPC `tutela.authz.v1` are
  built; `/access/v1/search/resource` and `/access/v1/search/subject` are
  planned.
- **UI permission map**: `POST /v1/authz/permissions` (ETag / 304).
- **Admin API** `tutela.admin.v1`: tenants, orgs, members, groups, roles,
  bindings, resource types, apps, keys, agent principals.
- Model versioning, impact report, explain and simulate, optional two-person
  publish.
- Signed bundles per (tenant, rev) for PDP caches.
- Events: transactional outbox, Standard Webhooks, SSE `/v1/events`.
- Local hash-chained audit log; optional forwarding to attache's evidence
  ledger.
- **Token exchange**: accepts a Keycloak (or other OIDC) token and issues a
  short-lived Tutela access token with Tutela claims, with just-in-time user
  provisioning. Issues delegated agent tokens (RFC 8693, `act` claim).
- **Tenant isolation**: `tenant_id` on every row, `FORCE ROW LEVEL SECURITY`,
  tenant set with `SET LOCAL` per transaction from the verified token, app
  roles never own tables. A test with no tenant set must return zero rows.
  Tenants are soft-deleted with a grace period; never `DROP SCHEMA CASCADE`.
- **Phase C (optional)**: `tutelad` becomes an OIDC provider. Swapping
  Keycloak for `tutelad` must be a config change only.

### Tutela Console (Phase B)

The admin web UI, served by `tutelad`. Orgs, members, groups, roles, the
permission matrix, apps, API keys, sessions, impact reports, the audit view.
It also replaces pages that cores built for themselves (for example
onto-intelli's Keys, Members, Projects and Sessions pages).

### `tutela` CLI

| Command | What it does | Phase |
| --- | --- | --- |
| `tutela init` | Writes a starter `tutela.resources.toml` (never overwrites a file) | A, built |
| `tutela check` | Compiles a manifest and lists every problem | A, built |
| `tutela migrate` | Creates or updates the `tutela` schema (`tutela-store`), as the database owner. A remote database needs `sslmode=require` (TLS, certificate always verified) | A, built |
| `tutela apply` | Applies the manifest. Shows the diff first. Refuses a **widening** diff without an approval token. | A (library mode, built), B (against `tutelad`) |
| `tutela approve`, `tutela approvers keygen\|add\|list\|revoke` | Approval tokens for widening diffs in library mode ([ADR-0015](DECISIONS.md#adr-0015-approval-tokens-for-tutela-apply-in-library-mode)) | A, built |
| `tutela codegen` | Generates typed permission constants (Rust and TypeScript), the UI map and the route table for the server's guards from the same manifest entries; `--check` fails when they are out of date | A, built; the generated denied-route test comes with the `tutela-sdk` guard |
| `tutela apps create` | Registers an app (client, redirect URIs, audience) in `tutelad` | B |
| `tutela keys rotate` | Rotates keys | B |

### SDKs for other languages

- `@f8fvwgzc/tutela-react`: `<Can>`, `<Field>`, `<Protect>`, `useCan`.
  UI modes: show, disable (with a reason tooltip), hide, readonly. Admin
  parts for embedding (RoleEditor, MembersTable, permission matrix) need
  `tutelad` (Phase B).
- `@f8fvwgzc/tutela-node` and `tutela-py`: verify tokens locally; permission
  checks go to `tutelad` (there is no PDP for these languages).
- `@f8fvwgzc/tutela-js`: the framework-free browser client.

### Not a Tutela component: the login server in Phases A and B

Phases A and B work with **any OIDC issuer**. Keycloak 26.x is recommended:
**one realm per deployment**, using Keycloak Organizations (not a realm per
tenant). Keycloak keeps passwords, MFA and upstream SSO in those phases.

---

## 3. Two ways to use Tutela: library mode and service mode

### Library mode (Phase A)

```
  Product backend (Rust)
  +--------------------------------------------------+
  |  tutela-sdk  -- verifies tokens from any OIDC    |
  |                 issuer (e.g. Keycloak)           |
  |  tutela-pdp  -- checks in-process                |
  |  tutela-store -- permission tables in the        |
  |                  product's own Postgres database |
  +--------------------------------------------------+
         no tutelad
```

- Parts: `tutela-pdp` + `tutela-store` + any OIDC issuer. **No `tutelad`.**
- The model (resource types, fields, actions, roles, UI keys) comes from
  `tutela.resources.toml`, applied with `tutela apply`.
- Role assignments and groups live in `tutela-store` tables. The product's
  own Rust code writes them.
- The product backend computes the UI permission map itself with
  `tutela-pdp`.
- Works offline, in unit tests and in local dev.
- Limits: no Console, no runtime tenant-defined roles, no embeddable admin
  parts, no webhooks, no impact report, no token exchange, no delegated
  agent tokens. Only Rust backends can check permissions.

### Service mode (Phase B)

```
  Product backend (any language)            tutelad (2+ replicas)
  +----------------------------+   bundles  +----------------------------+
  | tutela-sdk + tutela-pdp    | <--------- | Postgres (tutela-store,    |
  |  (Rust: checks in-process) |            |  RLS per tenant)           |
  | tutela-node / tutela-py    | ---------> | AuthZEN check API          |
  |  (checks over HTTP)        |   checks   | permission map, admin API, |
  +----------------------------+            | webhooks, SSE, audit,      |
                                            | token exchange, Console    |
                                            +----------------------------+
```

- `tutelad` adds: runtime role editing by tenants (Console and embeddable
  admin parts), the UI permission map for non-Rust apps, the AuthZEN check
  API, webhooks and SSE, impact reports and approvals, token exchange and
  delegated agent tokens, and later (Phase C) the login server.
- Rust products still check **in-process** with `tutela-pdp`. Their PDP
  loads signed bundles from `tutelad` instead of reading tables directly.
- `tutela-store` is the same schema in both modes. Moving from library mode
  to service mode is a data move, not a code rewrite. The exact steps come
  with Phase B.

### Which mode to use

| Situation | Mode |
| --- | --- |
| Unit tests, local dev, offline work | Library |
| One Rust product, roles fixed by you in the manifest | Library |
| The product's own customers create and edit roles at runtime | Service |
| You want to embed RoleEditor, MembersTable or the permission matrix | Service |
| The backend is Node or Python | Service |
| Other services must react to permission changes (webhooks, SSE) | Service |
| Several products share one set of users and orgs | Service |
| Agents act for people (delegated agent tokens) | Service |
| You want Tutela to be the login server | Service, Phase C |

---

## 4. Data ownership

### What Tutela stores

| Data | Where | Phase |
| --- | --- | --- |
| Resource types, fields and their sensitivity, actions (`resource_type`, `field_registry`) | `tutela-store` tables | A |
| Roles, role assignments, groups (`role`, `role_assignment`, `group`) | `tutela-store` tables | A |
| Field rules, boundary rules, conditions (`field_rule`, `boundary_rule`, `condition`) | `tutela-store` tables | A |
| UI keys with their actions and routes (`ui_component`) | `tutela-store` tables | A |
| Per-tenant revision (`model_revision`) | `tutela-store` tables | A |
| Audit events (`audit_event`), hash-chained; UPDATE and DELETE refused | `tutelad` database | B |
| Tenants and orgs; users keyed by (`iss`, `sub`), never by e-mail; memberships | `tutelad` database | B |
| Apps (clients, redirect URIs, audiences, `delegation_aware`) | `tutelad` database | B |
| API keys: only SHA-256(pepper ‖ key) plus the pepper version | `tutelad` database | B |
| Service accounts and agent principals (ids, state, role bindings) | `tutelad` database | B |
| Token signing keys, encrypted with `tutela-vault` | `tutelad` database | B |
| Webhook subscriptions and the outbox | `tutelad` database | B |
| Password hashes (Argon2id), TOTP, recovery codes, passkeys | `tutelad` database | C (optional) |

### What Tutela never stores

| Never stored | Who keeps it instead |
| --- | --- |
| A product's records (invoices, issues, contracts, ...) | The product's own database |
| The resource hierarchy (which project an item belongs to) | The caller's own database, or onto-intelli's graph. SDK helpers load the path by id at check time. |
| Plain API keys or plain secrets | Nobody. Keys are shown once; only hashes are kept. |
| Permission lists inside tokens | Nobody. Tokens carry identity; the PDP decides. |
| Agent tool, host and model policy; capability limits | attache (Tutela carries attache's `cap` snapshot in delegated tokens without reading it) |
| SPIFFE certificates and workload mTLS | attache |
| Passwords and MFA in Phases A and B | The OIDC issuer (Keycloak) |
| Tokens or personal data in logs, URLs or span attributes | Nobody |

---

## 5. Request path

How a product checks one request. No call to `tutelad` happens on this path.

```
 Browser
   |   HttpOnly, SameSite session cookie (backend-for-frontend; the
   |   browser never holds the access token)
   v
 Product backend
   |
   |  1. tutela-sdk: verify the access token OFFLINE
   |       cached JWKS, alg allow-list, iss, exactly one aud, exp, nbf, epoch
   |       -> principal "user:usr_..." and tenant key (iss, tid)
   |
   |  2. tutela-sdk helper: load the resource's path and attributes
   |       from the PRODUCT DB by id (never from the request body)
   |
   |  3. tutela-pdp, in-process:
   |       one item:  Pdp::check(principal, action, resource)
   |                    -> Decision { effect, level, field_mask,
   |                                  rule_ids, reason, rev, obligations }
   |       a list:    Pdp::list_filter(principal, "<type>:read")
   |                    -> ids_in + container_in + condition AST
   |       a write:   Pdp::write_check(...) -> a verdict per field
   |
   |  4. deny  -> 403 and an audit.v1 event
   |     allow -> continue
   v
 Product DB
   |   list_filter becomes part of the SQL WHERE clause;
   |   every value is a bound parameter.
   |   Hidden rows never reach page sizes or counts
   |   (never load rows and then drop them).
   v
 Product backend
   |   strip every field that field_mask.read hides
   v
 Response
```

Field masks apply wherever data leaves the product: API responses, search and
vector indexes, exports, notifications, audit (before/after stored as digests
or per-field encrypted) and AI prompts (hidden fields are removed **before**
a prompt is built).

---

## 6. Admin path

How a permission change reaches every PDP (service mode, Phase B).

```
 Tutela Console
   (or RoleEditor embedded in a product: separate aud=tutela-admin token,
    5-minute TTL, step-up MFA)
   |
   v
 tutelad  (tutela.admin.v1)
   |  1. the caller must hold manage_access
   |     (owner-only admin actions sit above the four levels)
   |  2. narrow-only: nobody grants a permission they do not hold
   |  3. impact report, e.g. "12 users gain read on contract"
   |  4. a widening change needs approval (two-person publish optional)
   |
   |  5. ONE Postgres transaction (tenant set with SET LOCAL, RLS forced):
   |       the change
   |       + revision bump  rev N -> N+1
   |       + local hash-chained audit entry
   |       + outbox rows
   v
 signed bundle (tenant, rev N+1, issued_at, expires_at)
   |
   +--> outbox --> webhooks (Standard Webhooks, HMAC-SHA256, retries)
   |          --> SSE /v1/events
   |              event tutela.permissions.changed.v1
   |              (a notification only; receivers re-read state)
   v
 PDP caches in every Rust product (tutela-pdp)
   - fetch bundle N+1 and verify its signature
   - refuse a lower rev than already seen; refuse an expired bundle
   v
 Browsers
   - the product backend refetches the permission map (ETag / 304)
   - the UI re-renders; nothing is deployed and nothing restarts
```

Read-your-writes: after its own write, a caller sends `at_least_revision`.
The PDP does not answer from an older revision.

---

## 7. Availability

Goal: a short `tutelad` outage must not stop products from serving reads,
and must never turn into a wrong "allow".

| Situation | What happens |
| --- | --- |
| Normal request | Tokens are verified offline with the cached JWKS. Checks run in-process. No network call to Tutela. |
| `tutelad` unreachable, bundle still fresh | PDPs keep answering from the **last good bundle**. |
| Bundle older than the max age for writes and admin actions | Those actions **fail closed** (they are refused). Max bundle age is configurable per action class; writes and admin actions fail closed sooner than reads. |
| Bundle past `expires_at` | Reads return **503**, never a stale allow. |
| PDP gets a bundle with a lower rev than it has seen | Refused. |
| PDP gets a bundle in a newer format than it understands | Refused; the PDP fails closed and raises an alert. (Planned: bundles carry a schema version and a minimum PDP version.) |
| A user is disabled or a session is revoked | The `epoch` claim gives fast revocation; access tokens live at most 10 minutes; `tutela.principal.disabled.v1` and `tutela.session.revoked.v1` events go out. Scheduled work caused by that person stops. |
| The OIDC issuer (Keycloak) is down | Existing access tokens keep working until they expire. New sign-ins and token exchanges fail. |
| A webhook receiver is down | The outbox retries with backoff. Delivery is at-least-once; receivers dedupe by event id; order is kept per subject. |
| One `tutelad` replica dies | Other replicas serve. **Run 2 or more replicas** (a Phase B exit condition). |
| `tutelad`'s Postgres is down | Admin changes fail. PDPs keep answering from cached bundles until the age limits above. |
| Library mode | There is no `tutelad`. The PDP reads `tutela-store` in the product's own database, so Tutela is as available as that database. |

Key rotation (Phase B for exchanged tokens, Phase C for the login server):
the next signing key is published at least twice the JWKS cache time before
it is used, and a `kid` deny-list exists for emergencies.

---

## 8. Dependency rules for Tutela itself

1. **Tutela depends on no core.** No crate, proto or package from attache,
   onto-intelli, texc-symphony or nexc-engine may appear in Tutela's
   `Cargo.lock` or `package.json`. Other cores call Tutela's APIs; Tutela
   never parses their events.
2. **Consumers use published packages only**, pinned to a release tag. Never a
   path dependency, a sibling checkout or a vendored copy.
3. **Only pure crates are linked into products**: `tutela-contracts`,
   `tutela-pdp`, `tutela-sdk`, `tutela-store`, `tutela-vault`,
   `tutela-safenet`. `tutelad` is never linked; it runs as a service.
   "Pure" means:

   | Rule | Why |
   | --- | --- |
   | No C or FFI code, except `aws-lc-sys` (used by aws-lc-rs) | One native dependency to audit. |
   | No SQLite | Cargo allows only one `links = "sqlite3"` per binary; other cores already link SQLite. |
   | No exact version pins (`=x.y.z`) on shared crates such as `sqlx` or `tokio` | The host product must stay free to pick its versions. |
   | Never turn on a rustls crypto provider feature | The host binary installs the one provider. |
   | No global side effects: no logger or tracing subscriber install, no background threads started without being asked | The host owns its runtime. |
   | `tutela-store` is the only crate with a database dependency: Postgres only | Library mode needs it; nothing else does. |

4. **One rustls CryptoProvider: aws-lc-rs.** Every Tutela binary installs it
   explicitly at startup. `jsonwebtoken` uses its `aws_lc_rs` feature.
   Products that link `tutela-sdk` must also install aws-lc-rs (today attache
   installs `ring`; see [INTEGRATION.md](INTEGRATION.md#3-attache)).
5. **No OpenSSL.** `openssl`, `openssl-sys` and `native-tls` are banned in
   `deny.toml`. CI blocks on `cargo-deny` and `cargo-audit`.
6. **Licences.** Every crate and SDK stays permissive (MIT or Apache-2.0),
   because products link them in-process. The licence of `tutelad` itself is
   an open decision for the owner before Phase C or any public release
   (see [DECISIONS.md](DECISIONS.md)).
7. **Contracts are additive only** from day one: `tutela.authz.v1`,
   `tutela.admin.v1`, `audit.v1`, token claims and event types. See
   [CONTRACTS.md](CONTRACTS.md).
8. **Tracing**: W3C `traceparent` on every hop, OTLP to an OpenTelemetry
   collector. Never tokens or personal data in logs, URLs or span attributes.
9. **Engineering rules** (no merge on red CI, no `unsafe`, no `unwrap` outside
   tests, human review for auth changes) are in [AGENTS.md](../AGENTS.md).
   Security reporting is in [SECURITY.md](../SECURITY.md); threats and
   mitigations are in [THREAT-MODEL.md](THREAT-MODEL.md).
