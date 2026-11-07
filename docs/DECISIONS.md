# Tutela decisions (ADRs)

This file holds the architecture decision records (ADRs) for Tutela. Each ADR says what we decided, why, and what we gave up.

Status: **pre-alpha**. Most of these decisions describe code that does not exist yet. The phase (A, B, C, D) in each ADR says when it gets built. See [ROADMAP.md](ROADMAP.md).

Other docs: [README](../README.md) · [AGENTS](../AGENTS.md) · [SECURITY](../SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [PERMISSION-MODEL](PERMISSION-MODEL.md) · [CONTRACTS](CONTRACTS.md) · [THREAT-MODEL](THREAT-MODEL.md) · [INTEGRATION](INTEGRATION.md)

## Rules for this file

- ADRs are numbered in order: ADR-0001, ADR-0002, and so on. Numbers are never reused.
- Status is one of: **Proposed**, **Accepted**, **Open** (owner decision needed), **Superseded by ADR-XXXX**.
- Do not rewrite an accepted ADR to change its meaning. Write a new ADR that supersedes it.
- Change the ADR and the code in the same commit (see [AGENTS.md](../AGENTS.md)).

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](#adr-0001-the-name-tutela-and-the-naming-system) | The name Tutela and the naming system | Accepted |
| [0002](#adr-0002-tutela-is-its-own-core-repo-at-the-lowest-layer) | Tutela is its own core repo, at the lowest layer | Accepted |
| [0003](#adr-0003-build-led-hybrid-with-keycloak-as-interim-and-fallback-issuer) | Build-led hybrid, with Keycloak as interim and fallback issuer | Accepted |
| [0004](#adr-0004-a-native-evaluator-not-cedar-only-or-openfga) | A native evaluator, not Cedar-only or OpenFGA | Accepted |
| [0005](#adr-0005-the-access-blueprint-is-the-v1-permission-model-with-two-corrections) | The access-blueprint is the v1 permission model, with two corrections | Accepted |
| [0006](#adr-0006-delegated-agent-tokens-in-phase-b-not-optional) | Delegated agent tokens in Phase B, not optional | Accepted |
| [0007](#adr-0007-the-boundary-between-tutela-and-attache) | The boundary between Tutela and attache | Accepted |
| [0008](#adr-0008-tenant-key-is-iss-tid-accounts-are-keyed-by-iss-sub) | Tenant key is (iss, tid); accounts are keyed by (iss, sub) | Accepted |
| [0009](#adr-0009-lists-are-filtered-in-sql-from-the-same-evaluator) | Lists are filtered in SQL, from the same evaluator | Accepted |
| [0010](#adr-0010-licence-mit-now-permissive-sdks-forever-tutelad-licence-open) | Licence: MIT now, permissive SDKs forever, tutelad licence open | **Open** |
| [0011](#adr-0011-week-1-spike-go-for-the-native-evaluator) | Week-1 spike: go for the native evaluator | Accepted |
| [0012](#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening) | Manifest v1: seeded roles, org-root rules, and what counts as widening | Accepted |
| [0013](#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits) | The evaluator: deciding roles, reasons, scope paths and Phase A limits | Accepted |
| [0014](#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes) | tutela-store in Phase A: the schema, row-level security and checked writes | Accepted |
| [0015](#adr-0015-approval-tokens-for-tutela-apply-in-library-mode) | Approval tokens for `tutela apply` in library mode | Accepted |
| [0016](#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits) | The list query: grouped terms, hashed scope tests and lower filter limits | Accepted |
| [0017](#adr-0017-opaque-public-errors-for-the-crates-that-touch-the-outside-world) | Opaque public errors for the crates that touch the outside world | Accepted |
| [0018](#adr-0018-tutelad-the-stack-the-two-ports-and-the-config) | `tutelad`: the stack, the two ports and the config | Accepted |
| [0019](#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked) | Tenants in `tutelad`: the tenant comes from the token, and RLS is checked | Accepted |
| [0020](#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry) | The bindings store: closures at read time, and assignment expiry | Accepted |
| [0021](#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease) | The check API: one code path, a snapshot per tenant, and a revision lease | Accepted |
| [0022](#adr-0022-the-searches-live-next-to-the-evaluator) | The searches live next to the evaluator | Accepted |
| [0023](#adr-0023-the-permission-map-and-a-tag-that-covers-the-answer) | The permission map, and a tag that covers the answer | Accepted |
| [0024](#adr-0024-signed-bundles-wait-for-part-3) | Signed bundles wait for part 3 | Accepted |
| [0025](#adr-0025-moves-and-links-in-write_check) | Moves and links in `write_check` | Accepted |
| [0026](#adr-0026-a-tenant-owns-its-model-versions) | A tenant owns its model versions | Accepted |
| [0027](#adr-0027-the-impact-report) | The impact report | Accepted |
| [0028](#adr-0028-explain-and-simulate-need-read_audit-on-the-resource) | Explain and simulate need `read_audit` on the resource | Accepted |
| [0029](#adr-0029-two-person-publish) | Two-person publish | Accepted |
| [0030](#adr-0030-tutelads-own-issuer-signing-keys-the-jwks-and-paths-without-a-token) | `tutelad`'s own issuer: signing keys, the JWKS, and paths without a token | Accepted |
| [0031](#adr-0031-token-exchange-the-tenant-from-the-trust-list-a-person-from-iss-sub) | Token exchange: the tenant from the trust list, a person from (iss, sub) | Accepted |
| [0032](#adr-0032-admin-tokens-a-person-steps-up-a-pipeline-keeps-its-service-token) | Admin tokens: a person steps up, a pipeline keeps its service token | Accepted |
| [0033](#adr-0033-delegated-agent-tokens-from-token-exchange) | Delegated agent tokens from token exchange | Accepted |
| [0034](#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change) | The local audit log: one chain per tenant, written with the change | Accepted |
| [0035](#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order) | The outbox: events numbered per tenant, in commit order | Accepted |
| [0036](#adr-0036-webhooks-delivered-from-the-outbox-registered-by-part-3c) | Webhooks: delivered from the outbox, registered by part 3c | Accepted |
| [0037](#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded) | The event stream: services only, one feed per tenant, bounded | Accepted |
| [0038](#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp) | Signed bundles: a service with `read_audit` everywhere, its own `typ`, and no skew at `exp` | Accepted |
| [0039](#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable) | Forwarding to attache's evidence ledger: signed, acknowledged, resumable | Accepted |
| [0040](#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org) | `tutela.admin.v1`: one code path, the admin token rule on gRPC, and keys at every org | Accepted |
| [0041](#adr-0041-the-lifecycle-of-tenants-orgs-and-people-the-operator-makes-a-tenant-soft-delete-with-a-grace-a-purge-that-keeps-the-audit-chain) | The lifecycle of tenants, orgs and people: the operator makes a tenant, soft-delete with a grace, a purge that keeps the audit chain | Accepted |
| [0042](#adr-0042-the-audit-logs-leftovers-a-chain-check-on-a-timer-the-callers-trace-in-each-record) | The audit log's leftovers: a chain check on a timer, the caller's trace in each record | Accepted |
| [0043](#adr-0043-scopes-assignments-and-groups-over-the-admin-api-checked-on-the-data-they-change) | Scopes, assignments and groups over the admin API, checked on the data they change | Accepted |
| [0044](#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated) | Apps: one tenant each, a hashed client secret, and `azp` bound to the client that authenticated | Accepted |
| [0045](#adr-0045-the-audit-producer-key-sealed-in-the-database-rotated-with-its-old-keys-kept) | The audit producer key sealed in the database, rotated with its old keys kept | Accepted |
| [0046](#adr-0046-the-cli-against-tutelad-apply-with-the-impact-report-apps-and-keys-through-the-key-store) | The CLI against `tutelad`: `apply` with the impact report, `apps`, and `keys` through the key store | Accepted |
| [0047](#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make) | The JavaScript SDKs: a pnpm workspace under `sdk/`, checked by `make` | Accepted |
| [0048](#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice) | `tutela-js`: the browser token flow in memory, typed errors, and a retry that never makes twice | Accepted |
| [0049](#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people) | `tutela-react`: embeddable admin components, scoped CSS variables, and the host names the people | Accepted |
| [0050](#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start) | The Console is served by `tutelad` under `/console/`, from files read at start | Accepted |
| [0051](#adr-0051-a-test-openid-provider-shaped-like-keycloak-a-dev-only-crate-on-loopback) | A test OpenID provider shaped like Keycloak: a dev-only crate on loopback | Accepted |
| [0052](#adr-0052-the-console-a-vite-app-on-the-sdks-sign-in-by-code-with-pkce-the-permission-map-asked-again-every-half-second) | The Console: a Vite app on the SDKs, sign-in by code with PKCE, the permission map asked again every half second | Accepted |
| [0053](#adr-0053-the-exit-check-in-a-real-browser-playwrights-chromium-a-real-tutelad-and-the-test-provider-run-by-make) | The exit check in a real browser: Playwright's Chromium, a real `tutelad` and the test provider, run by `make` | Accepted |
| [0054](#adr-0054-cors-exact-origins-from-configuration-off-by-default-never-credentials) | CORS: exact origins from configuration, off by default, never credentials | Accepted |
| [0055](#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release) | The OCI image: three stages, a distroless runtime, the Console on, and publishing left to a release | Accepted |
| [0056](#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing) | The Helm chart and its bootstrap job: a pre-install hook that makes only what is missing | Accepted |

---

## ADR-0001: The name Tutela and the naming system

**Status:** Accepted, 2026-10-25.

**Context.** The product needed a name. In the earlier design round it was only called "iam". That word is generic. It clashes with cloud IAM products, it is hard to search for, and it makes poor package names.

**Decision.** The product is called **Tutela**. Tutela was the Roman goddess of protection and guardianship. In Roman law, *tutela* is a guardian's legal power to act for someone else. That is what delegation is: an agent acting for a person.

All names follow one system:

| Thing | Name |
|---|---|
| Repo | `f8fvwgzc/tutela` (private) |
| Service binary | `tutelad` |
| CLI | `tutela` (`tutela init`, `tutela apply`, `tutela codegen`, `tutela apps create`, `tutela keys rotate`) |
| Web UI | Tutela Console, served by `tutelad` |
| Rust crates | `tutela-contracts`, `tutela-pdp`, `tutela-sdk`, `tutela-store`, `tutela-vault`, `tutela-safenet` |
| npm | `@f8fvwgzc/tutela-react`, `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js` |
| Python | `tutela-py` (import name `tutela`) |
| Manifest in products | `tutela.resources.toml` |
| Proto packages | `tutela.authz.v1`, `tutela.admin.v1` |
| Events | `tutela.<entity>.<verb>.v1`; audit schema `audit.v1` |
| Env vars | prefix `TUTELA_` |
| API keys | `tut_sk_...` (apps, service accounts), `tut_ak_...` (agents) |
| Principals | `user:usr_<uuidv7>`, `sa:sa_<uuidv7>`, `key:key_<uuidv7>`, `agent:agt_<uuidv7>`, `workload:<spiffe uri>` |

Principal ids are opaque. Names are display labels only.

**Consequences.**
- Every doc, crate and package uses these exact names. "iam" is not used as the product name.
- A `tut_` prefix lets secret scanners find leaked keys.
- Opaque ids mean a new agent with an old agent's name never inherits the old bindings or audit history.

**Alternatives considered.**
- "iam": too generic (see Context).
- A name close to an existing identity product: confusing, and a trademark risk.

---

## ADR-0002: Tutela is its own core repo, at the lowest layer

**Status:** Accepted, 2026-10-25.

**Context.** Every product needs login, keys, roles and permission checks. Today each project hard-codes its own roles (for example nexc-engine's `WorkspaceRole` and `TeamRole`, onto-intelli's `Role` and `OrgRole`, attache's viewer/editor/admin). No tenant can define roles. Without a shared identity core, every new product writes login, keys and roles again.

The owner's platform (decided 2026-10-25) has four independent core repos and, on top, products:

1. **Tutela**: identity and permissions (new).
2. **attache** (`f8fvwgzc/agent-sidecar`): the AgentSecOps core.
3. **onto-intelli**: the enterprise ontology core.
4. **texc-symphony**: the AI task executor core.

nexc-engine is no longer a core. It is the first **product** (a Linear-style work tracker). So Tutela is the fifth repo of the platform, and one of its four cores.

**Decision.** Tutela lives in its own repo, with its own CI, releases and roadmap. It is the lowest layer.

Dependency direction: products → onto-intelli / texc-symphony → attache → Tutela.

- Tutela depends on no other core.
- No cycles.
- Other cores and products use Tutela only through its published packages (`tutela-*` crates, npm packages, `tutela-py`) and its APIs. They never copy its code.

**Consequences.**
- Tutela must build, test and run with no other core installed.
- Tutela becomes a shared dependency of everything. It needs offline token checks, 2+ `tutelad` replicas and clear failure rules (see [ARCHITECTURE.md](ARCHITECTURE.md)).
- The three-part answer to "is IAM required?": the Tutela packages are required; a running `tutelad` is required for runtime, tenant-defined roles and for non-Rust apps; Tutela's own login server is optional.

**Alternatives considered.**
- **Inside nexc-engine.** nexc-engine is now a product. Cores would then depend on a product, which breaks the direction rule.
- **Inside onto-intelli.** onto-intelli depends on Tutela, not the other way round. Its server crates are heavy and would force their database driver versions on every product.
- **Inside attache.** attache answers a different question (see [ADR-0007](#adr-0007-the-boundary-between-tutela-and-attache)). People and apps with no agents need identity too.
- **One monorepo for all cores.** The owner wants each core to have its own CI, releases and roadmap.

---

## ADR-0003: Build-led hybrid, with Keycloak as interim and fallback issuer

**Status:** Accepted, 2026-10-25.

**Context.** We must choose what to build and what to adopt. No open-source project covers, together: tenant-defined types (CMS-level), rules on single fields, UI keys, and a library mode that runs inside the product's process. A self-written login server is the most valuable attack target: one bug compromises every connected app.

**Decision.** Build-led hybrid.

| Build | Adopt (libraries) | Adopt (external issuer) |
|---|---|---|
| The packages (Phase A) | `jsonwebtoken` (with `aws_lc_rs`) | **Keycloak 26.x** (Apache-2.0): interim issuer, fallback, and bring-your-own IdP. One realm per deployment, using Keycloak Organizations. |
| `tutelad` (Phase B) | `argon2` | Zitadel only as an unmodified bring-your-own IdP (its core is AGPL). |
| Tutela Console (Phase B) | `webauthn-rs` (MPL-2.0) | |
| Own login server, last and optional (Phase C) | `lettre` | |
| | `cedar-policy` (condition templates only; see [ADR-0004](#adr-0004-a-native-evaluator-not-cedar-only-or-openfga)) | |
| | The OpenID Foundation conformance suite | |

Zitadel and OpenFGA are **not** required.

**Consequences.**
- Phases A and B work with any OIDC issuer. Keycloak is recommended.
- Keycloak can stay the login server for good. Then Phase C is skipped.
- Nobody uses Tutela's own login server before the login-server gate passes: conformance in CI, fuzzing, an external security review, a key-restore drill. Without that gate, Keycloak stays.
- Swapping Keycloak for `tutelad` must be a config change only.

**Alternatives considered.**
- **Adopt Keycloak + OpenFGA as the whole product.** No library mode. Cannot express the blueprint rules. A second source of truth. See [ADR-0004](#adr-0004-a-native-evaluator-not-cedar-only-or-openfga).
- **Build the login server first.** Highest risk, and it does not unblock products. Built last instead.
- **A hosted service (Clerk, Auth0).** Not self-hostable, and tenant data leaves our systems.

---

## ADR-0004: A native evaluator, not Cedar-only or OpenFGA

**Status:** Accepted, 2026-10-25. Built in Phase A (`tutela-pdp`).

**Context.** The permission model ([ADR-0005](#adr-0005-the-access-blueprint-is-the-v1-permission-model-with-two-corrections)) has rules that are not monotone:
- The closest role assignment wins.
- A private scope stops inheritance from above.
- Field level = the lower of (role level, closest field rule).

Cedar joins permits together and has no idea of "closest". To filter lists with Cedar, we would need a second, separate compiler. Then `check()` and the list filter could disagree, and rows or counts would leak.

OpenFGA does not fit either:
- Its own multi-tenant guidance is one store for all tenants, with a default 256 KB model cap.
- It has no library mode.
- It cannot express "closest role wins" or single-field rules.
- It would be a second source of truth next to our tables.

The owner's blueprint itself says: start with your own Postgres tables, and use Cedar or OPA only once conditions grow past a handful.

**Decision.** `tutela-pdp` is a small native Rust evaluator over the blueprint tables.
- It resolves the effective level once per (principal, scope).
- It emits **both** the decision **and** the SQL list filter from the same code (see [ADR-0009](#adr-0009-lists-are-filtered-in-sql-from-the-same-evaluator)).
- `cedar-policy` is used only for vetted condition templates, possibly later.
- A differential property test proves: rows returned by `list_filter` == rows that `check()` allows.

**Consequences.**
- We own security-critical evaluator code. It needs property tests, fuzzing and the external review.
- Only condition templates that both the decision and the SQL filter support are allowed. A model that uses anything else is rejected.
- Speed must be proven. The week-1 spike checks `check` p99 < 1 ms (see [ROADMAP.md](ROADMAP.md#very-next-steps)).

**Alternatives considered.**
- **Cedar only.** Cannot express "closest"; needs a second compiler for lists (see Context).
- **OpenFGA.** See Context.
- **OPA/Rego.** Same problem as Cedar for list filters, and another language for tenants to learn.

---

## ADR-0005: The access-blueprint is the v1 permission model, with two corrections

**Status:** Accepted, 2026-10-25. Built in Phases A and B.

**Context.** The owner wrote an access-blueprint (`/Users/amraaone/Documents/access-blueprint/access-blueprint.html`, English and Korean). It uses a fixed tree: workspace → team → project → issue → task. Tutela must let each tenant define its own resource types. A review found two holes in the blueprint.

**Decision.** The blueprint is the v1 model, generalised to tenant-defined resource types. Full details: [PERMISSION-MODEL.md](PERMISSION-MODEL.md).

- Tables (blueprint names kept): `role_assignment`, `field_rule`, `boundary_rule`, `condition`, `field_registry`, `audit_event`; plus `resource_type`, `role`, `group`, `ui_component`, `model_revision`.
- Four levels on every item, field and feature: None < Read < Write < Full. Owner-only admin actions sit above these and are never granted by default.
- Every resource has exactly one parent. The closest role assignment wins. A private scope stops inheritance.
- Links never grant access. Nobody grants a permission they do not hold.
- New teams and projects start open, as in the blueprint.

**Correction 1: confidential fields start at None.** A new field marked confidential or secret starts at None, not open.

**Correction 2: agents always use the overlap rule.** An agent acting for a person always gets (person allowed) AND (agent allowed), capped by attache's capability limits. This holds for chat, task work and scheduled work. The person is the one who caused the work (assigner or requester). The blueprint said "on task work the agent uses its own role". That is a confused-deputy hole: anyone who can assign a task could borrow the agent's wider access. It is replaced. When the person is disabled, their scheduled work stops. Output carries the highest label of its inputs.

**Consequences.**
- One model serves nexc-engine, onto-intelli and future products. nexc-engine's roles become seeded roles.
- Agents can never see more than the person behind them.
- Property tests check: delegation ≤ person AND agent; no widening; no cross-tenant grant.

**Alternatives considered.**
- **Fixed roles hard-coded per product.** Today's state. Tenants cannot define roles.
- **Pure relationship tuples (Zanzibar style).** No "closest wins", no single-field rules.
- **The blueprint without corrections.** Leaves the two holes above.

---

## ADR-0006: Delegated agent tokens in Phase B, not optional

**Status:** Accepted, 2026-10-25. Built in Phase B.

**Context.** An earlier plan put token exchange in the optional login-server phase. But the agent overlap rule ([ADR-0005](#adr-0005-the-access-blueprint-is-the-v1-permission-model-with-two-corrections)) and attache need delegated tokens whoever logs people in. The design round judged Keycloak's delegation support to be only a preview. Also, a delegated token looks like a normal user token (`sub` = the person). A server that checks JWTs with a generic library and ignores `act` would treat the agent as the full person.

**Decision.** `tutelad` runs a token-exchange service in Phase B. It is not optional.
- RFC 8693 token exchange. `sub` = the person, `act = {sub: agent:agt_…}`.
- Header `typ: agent+jwt`. The SDKs refuse this type unless delegation support is switched on.
- `cap`: attache's capability snapshot. It is opaque to Tutela.
- Run and node ids for tracing.
- Issued only to audiences registered with `delegation_aware = true`. Exactly one audience.
- TTL 60–120 s for downstream hops. Optional mTLS binding (RFC 8705 `cnf`).
- A service that receives an agent token never forwards it. It exchanges it for a new one per audience.

**Consequences.**
- Keeping Keycloak forever saves only Phase C (about 8–12 pw), not this service.
- Every SDK gets a conformance test: on a route the agent may not use, a delegated token is denied even when the person may use it.
- Old impersonation headers (for example onto-intelli's `x-onto-act-*`) are refused whenever a Tutela token is present.

**Alternatives considered.**
- **Keep it optional in Phase C.** Then the overlap rule has no token to stand on.
- **Use Keycloak's token exchange.** Judged a preview, and it cannot issue Tutela claims.
- **Agents use the person's normal token.** The agent acts as the full person.
- **Impersonation headers.** The source of onto-intelli's tenant-escape class of bugs.

---

## ADR-0007: The boundary between Tutela and attache

**Status:** Accepted, 2026-10-25.

**Context.** In the earlier design round, nexc-engine owned the ledger, the firewall, the agent registry and the model gateway. The owner moved all AgentSecOps into attache (ledger, firewall, approvals, registry, runtime, model gateway). Tutela and attache both "decide" things about agents, so the line between them must be sharp.

**Decision.** The boundary rule:

> Tutela answers: "may this principal touch this data or resource?"
> attache answers: "may this agent use this tool, host or model, and at what risk?"
> onto-intelli keeps per-entity visibility inside graph traversal (called once per entity, in-process), fed by Tutela's permissions.
> UI hiding is never security. Every server checks again.

Tutela never: stores a product's records; decides an agent's tool, host or model use; runs workload mTLS (attache owns SPIFFE).

Where they meet:
- Agent principals are created and disabled through `tutela.admin.v1`. attache's quarantine disables the principal.
- The `cap` claim in delegated tokens carries attache's capability snapshot. Tutela does not read it.
- An agent's final access = person AND agent, capped by attache's capability limits.
- Tutela keeps its own hash-chained audit log. When configured, it forwards copies to attache's evidence ledger through an acknowledged Append API.

**Consequences.**
- Each core can be tested alone.
- No AgentSecOps code lives in Tutela.

**Alternatives considered.**
- **Tutela also decides tools and models.** Agent runtime risk does not belong in the identity core.
- **attache also decides data access.** People and non-agent apps need the same answers. Two role models would drift.
- **nexc-engine keeps the firewall and ledger.** Outdated: nexc-engine is now a product.

---

## ADR-0008: Tenant key is (iss, tid); accounts are keyed by (iss, sub)

**Status:** Accepted, 2026-10-25.

**Context.** The SDKs trust more than one issuer (Keycloak, later `tutelad`). A tenant id from one issuer can collide with a tenant of another. onto-intelli already has a bug of this kind (tenant-id normalisation). Also, in a Clerk-like service each org can connect its own upstream IdP. A tenant admin controls that IdP and can claim `email_verified = true` for any address, including someone else's. nexc-engine already has a bug of this kind.

**Decision.**
- The tenant key everywhere is the pair **(iss, tid)**: in `tutela-pdp`, in database keys, in audit records, in mappings in other cores.
- The SDK trust list maps each issuer to the tenants it may speak for.
- Tenant ids are opaque and canonical. No normalisation.
- Accounts are keyed by **(iss, sub)**, never by e-mail.
- An org's upstream IdP may assert e-mails only in domains the org proved with a DNS TXT record.
- Linking to an existing account needs that account's own credential in the same session.
- Never auto-link across orgs.

**Consequences.**
- A changed e-mail does not change who a person is.
- A person who signs in through two IdPs has two accounts until they link them.
- Negative tests use a hostile IdP that claims another org's domain.

**Alternatives considered.**
- **Tenant id alone.** Collides across issuers.
- **E-mail as the account key, or auto-link on a verified e-mail.** Lets a hostile org take over accounts.

---

## ADR-0009: Lists are filtered in SQL, from the same evaluator

**Status:** Accepted, 2026-10-25. Built in Phase A (`Pdp::list_filter`).

**Context.** A list endpoint can load rows and then drop the ones the caller may not see. Then counts and page sizes show that hidden rows exist. The blueprint names this as a leak path. A list filter written apart from `check()` can also disagree with it.

**Decision.**
- `Pdp::list_filter` returns a filter (`ids_in` + `container_in` + a condition AST). The SDK turns it into SQL. All values are bound as parameters; text is never spliced in.
- Lists are filtered inside SQL. Never load-then-drop.
- The filter comes from the same code that makes the `check()` decision ([ADR-0004](#adr-0004-a-native-evaluator-not-cedar-only-or-openfga)).
- A differential property test runs on every commit: rows returned by `list_filter` == rows that `check()` allows.
- The SQL compiler is fuzzed.
- Resource paths and attributes are loaded server-side by id, never taken from the request body.

**Consequences.**
- Counts and pages are correct and leak nothing.
- Conditions are limited to templates the SQL filter supports.
- The SDKs need a SQL adapter for each database they support. Postgres comes first.

**Alternatives considered.**
- **Load, then drop.** Leaks counts and breaks paging.
- **First ask for the full list of allowed ids.** Large lists, and a second source of truth.
- **A separate list compiler (for example Cedar partial evaluation).** Can disagree with `check()`.

---

## ADR-0010: Licence: MIT now, permissive SDKs forever, tutelad licence open

**Status:** **Open — owner decision needed** before Phase C or any public release.

**Context.** The repo starts under MIT, like onto-intelli, attache and nexc-engine. Products link the Tutela crates and SDKs into their own process. If those were AGPL, every product and every MIT core that links them would have to become AGPL too.

**Decided so far.**
- The repo is MIT today.
- The SDKs, crates and contracts always stay permissive (MIT or Apache-2.0). This covers `tutela-contracts`, `tutela-pdp`, `tutela-sdk`, `tutela-store` (it is used in library mode), `tutela-vault`, `tutela-safenet`, the npm packages and `tutela-py`.

**Still open.** The licence of `tutelad` itself:

| Option | For | Against |
|---|---|---|
| MIT | Simple. Same as the other repos. | Anyone can sell it as a hosted service. |
| Apache-2.0 | Patent grant. Permissive. | Same as MIT on hosting. |
| AGPL or BSL, plus a commercial licence | Protects a hosted business. | Fewer adopters. `tutelad` must stay a separate process, never linked into a product. |

**Consequences.**
- Keep server-only code in `tutelad`'s own crates, apart from the crates products link, so every option stays possible.
- `webauthn-rs` is MPL-2.0: changes to its files must be shared.
- When decided, set this ADR to Accepted and update `LICENSE` and the crate metadata in the same commit.

**Alternatives considered.** The three options in the table above.

---

## ADR-0011: Week-1 spike: go for the native evaluator

**Status:** Accepted, 2026-10-28. Decided by the go/no-go rules that were committed before any spike code ran.

**Context.** [ROADMAP.md "Very next steps" §2](ROADMAP.md#2-week-1-spike-gono-go) asks for a short spike before more Phase A code: is the native evaluator fast enough ([ADR-0004](#adr-0004-a-native-evaluator-not-cedar-only-or-openfga)), are group and path closures fast enough in Postgres at path depth 32, and does `list_filter` give exactly the rows that `check` allows ([ADR-0009](#adr-0009-lists-are-filtered-in-sql-from-the-same-evaluator))? The sizes, the machine, the thresholds and the rules were fixed in [SPIKE-WEEK1.md](SPIKE-WEEK1.md) (commit `424597e`) before the spike code was committed (`d9b4ae2`) and run. The machine: Apple M2 Pro, 10 cores, 16 GiB, macOS 26.6.2, Rust 1.99.0 `--release`, PostgreSQL 16.14 with the default configuration on 127.0.0.1:5442. The raw outputs are in [`docs/spike-week1-results/`](spike-week1-results/). The throwaway code is in `spike/week1/` (outside the Cargo workspace and the CI gates); it is kept only until `tutela-pdp` has its own benchmarks and differential tests.

**Result.**

| # | Question | Go if | Result | |
|---|---|---|---|---|
| 1 | `check` latency, in process, warm cache, 1,000,000 calls per workload | p99 < 1 ms in W1, W2 and W3 | p99 **2.5 µs** (W1), **2.4 µs** (W2), **2.0 µs** (W3) | **go** |
| 2 | Closure latency in Postgres, 10,000 runs per query | G1 and P1, else G2 and P2: p99 < 5 ms | G1 p99 **0.18 ms**, P1 p99 **0.13 ms** (read time); G2 0.10 ms, P2 0.06 ms | **go** (first rule) |
| 3 | `list_filter` ≡ `check`, 20 random models (seeds 1–20), 100k rows each | zero mismatches | **0 mismatches** in 162,452,240 row checks and 5,000 filters, in Rust and in SQL; 0 count mismatches | **go** |

Details of question 1 (model of SPIKE-WEEK1.md §4.1: 200 types, 100 roles, 5,000 field rules, 10,000 bindings, 10,000 users in 500 groups nested 8 deep, 220,000 resources with paths up to 32): p50 0.4–0.5 µs, p99.9 at most 5.3 µs, slowest single call 115 µs. The model is generated and compiled in under 0.1 s. The pre-registered workload is mostly denials (2.3% allowed in W1, 0.0% in W3), because a random resource is rarely under a random user's assignments. So, as information only and measured after the gated run (code at `0429ee3`, output in `docs/spike-week1-results/check-latency-info.txt`): allowed calls alone have p99 6.1 µs (W1) and 5.8 µs (W2); a workload of the 300 users bound at the org root (14.5% allowed, 5.5 readable fields per call on average) has p99 3.2 µs, 5.8 µs for its allowed calls, and a slowest call of 437 µs. One `list_filter` call on this model: p99 0.48 ms (information).

Details of question 2: 10,000 users in 500 groups, 8 levels, one group with all 10,000 users as direct members: 444,387 closure rows, 43.9 transitive groups per user on average (at most 111). The first run was **void**: another session's `cargo` ran during 71 of its 101 samples. It is kept in `docs/spike-week1-results/void/`. The second run was valid. Information only: A1 (all assignments that apply to a user, through the closure table) p99 0.32 ms; G3 (all 7,514 transitive members of a top group, recursive CTE) p99 3.6 ms; W1 (nest one group in another and update the closure table, about 2,200 closure rows each time) p50 9.8 ms, p99 77 ms, slowest 0.48 s.

Details of question 3:
- The run hit every case the notes list: 2,921,680 checks at path length 32; 14,214,800 on rows with a private scope inside a private scope; 1,498,544 where an assigned scope sat inside a private scope inside another assigned scope; 1,045,600 closer lower assignments; 6,214,157 decided through a group and 4,660,816 where a direct assignment beat a group one; 1,764,125 true and 2,907,991 false conditions (2,602,227 of them on rows with a null attribute); 25,459 assignments on the row itself; 6,079,828 denies caused by the delegation overlap; 4,944,424 decisions for an org Owner.
- The 20 tenants shared one Postgres table with overlapping row ids, so a filter that leaked another tenant's rows would have shown up as a mismatch. None did.
- The test catches bugs. Each of these bugs, planted on the list side only (`SPIKE_MUTATE`), was caught at once on development seeds 101–103: private scopes ignored (5.5M row mismatches), nested exclusions dropped (7.8M), conditions below a scope applied everywhere (206k–361k), conditions above the deciding scope dropped (263k–265k), the agent side of the overlap dropped (673k), only the allowed scopes of the next level excluded (6.6M). A planted SQL bug (no `COALESCE`, so a `NULL` leaks through `NOT`) was caught by the SQL comparison on dev seeds 103–108 (3 filters, 48 rows, all on seed 106).
- No mismatch was found while the spike was written. The first dev run (seeds 101–102, not the gated seeds) already had zero.

**Decision.** **Go.** Phase A builds `tutela-pdp` as the native evaluator. The spike also settles these points:

1. **Ancestors column** ([PERMISSION-MODEL.md open point 4](PERMISSION-MODEL.md#19-open-points)): an array of ancestor ids, nearest first, with a GIN index (with `tenant_id` through `btree_gin`). The spike measured `bigint[]`. Products often use UUID ids, so the element type and the query plan are measured again under F2. "Row is under scope S" is `ancestors && $n`. A closure table (`item_ancestor`) gave the same rows but was slower on the same filters (seed 1: p50 78 ms against 20 ms, p99 3.6 s against 1.5 s). `ltree` was not measured: the filter names scopes by id, and `ltree` would need each scope's full path to test descent. The depth cap stays at **32**.
2. **Filter shape.** Group the deciding scopes by nesting level: a row's deepest deciding scope is at level k exactly when the row is at or under a level-k scope and not under any level-(k+1) scope, because the deciding scopes on one row's path form a chain. So the filter needs one term per (level, role with conditions), plus one per level for all roles without conditions. Each role condition is guarded by "at or under its scope", which makes it valid for every scope. This form gave 0 mismatches. The first form (one term per deciding scope) was also correct on the dev seeds, but about 3× larger there (1,028 against 310 AST nodes).
3. **Group closure.** Reading group membership at read time (a recursive CTE) is fast enough: p99 0.18 ms with 8 nested levels. A closure table is optional: it halves the read time, but nesting one group in another then costs p99 77 ms. [PERMISSION-MODEL.md §6.4](PERMISSION-MODEL.md#64-groups-new) says Tutela keeps a closure table; the `tutela-store` step decides between the two and updates that line. Inside `tutela-pdp` each principal's groups are held in memory per revision either way.
4. The spike semantics in SPIKE-WEEK1.md §3 work for both `check` and `list_filter`. The `tutela-pdp` step writes them into PERMISSION-MODEL.md, with these two clarifications:
   - The role's level for a **data field** is capped by the item level **after conditions** (step 5). Without the cap, a condition that drops an item to Read would leave a field the role sets to Write still writable. Features are different: [PERMISSION-MODEL.md §17.4](PERMISSION-MODEL.md#174-jae-asks-clause-ai-in-chat-is-c-204-over-budget) lets a Viewer ask the AI (`@ai` Write on a Read item), so a feature drops to None only when the item level is None. (The spike capped features too; field masks do not change which rows a list returns.)
   - "Org Owner" means: the deciding role at the org root is Owner, using the same direct-beats-group rule as every scope.

**Findings that need work later (not blockers).**

- **F1. `list_filter` needs scope paths.** To build the filter, the evaluator must know how the deciding scopes nest: assigned scopes, private scopes inside them, and scopes of conditions. `ListFilterRequest` in [CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter) has no place for them, and Tutela does not store the product's tree. The spike passed a scope-path provider to `list_filter`. **Decision for `tutela-pdp`:** the Rust API takes such a provider, and CONTRACTS.md §6.6 is changed in that PR. The provider:
  - is keyed by **(tenant, type, id)** and returns a `Result` with the ancestors, nearest first;
  - an unknown id, a path that does not end at the tenant's own org, or a path longer than 32 makes `list_filter` return an **error**. The caller fails closed (no rows). It never treats a missing path as "no ancestors";
  - the `tutela-pdp` differential tests cover provider misses, wrong-tenant paths and ids that are the same across tenants.

  Where the provider reads paths from (the product's own tables by id, or a `tutela-store` table kept in the same transaction as moves) is decided with `tutela-store` and `tutela-sdk`, with a test that a move changes list results at once. A stale path would make `list_filter` and `check` disagree, so a cache of paths is not allowed without that test. [THREAT-MODEL.md TM-10](THREAT-MODEL.md#tm-10-list-and-count-leaks) carries this control. Owner: ROADMAP Phase A item 4 (`tutela-pdp`).
- **F2. List queries can be slow.** On the random models (principals with up to ~600 deciding scopes) the SQL list query on 100k rows had p50 3.9 ms, p99 1.34 s, max 4.4 s in the question-3 run. That run overlapped another session's build (F5), so these times are high. A second run with the same code and seeds overlapped another build for only 21 of its 301 samples, so `run.sh` stamped it VOID too ([`differential-quiet.txt`](spike-week1-results/differential-quiet.txt), information only): p50 3.0 ms, p99 1.20 s, max 2.2 s, and again 0 mismatches. So the slowness is real, not caused by the load. No threshold was set. The plan ([`explain-slow-list-query.txt`](spike-week1-results/explain-slow-list-query.txt), taken on a one-tenant table; the command is in the file) shows why: Postgres scans every row of the type and evaluates `ancestors && $n` on each one, a nested loop over both arrays. A hashed `unnest` form was 5× slower. Owners: the SDK's SQL adapter (ROADMAP Phase A item 6) must look at the plan and use a statement timeout that fails closed (CONTRACTS.md §6.6), and the library gate gets a list-query p99 check at the filter limits.
- **F2, measured with the SQL adapter (2026-10-29, [#22](https://github.com/f8fvwgzc/tutela/issues/22)).** `cargo bench -p tutela-sdk --bench list_query`: Apple M2 Pro, 16 GiB, macOS 26.6.2, PostgreSQL 16.14 default config, 20 tenants × 100k rows, GIN on (`tenant_tid`, `ancestors`); 200 `count(*)` queries per workload, 5 s statement timeout. Run 1 (`coalesce` around the top-level `container_in` test): typical p50 16.7 ms, p99 28.0 ms; limits 194 of 200 timed out. Run 2 (the top-level test bare, so the index serves it): typical **p50 1.87 ms, p99 16.2 ms**; limits **186 of 200 timed out** (p99 5.0 s). The library gate (p99 < 100 ms at the limits) **fails**: at the limits every row of the tenant is a candidate and the 1,000-term condition runs on each. The timeout fails closed. Fixed in [ADR-0016](#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits) ([#26](https://github.com/f8fvwgzc/tutela/issues/26)): limits p99 79.8 ms, typical p99 3.7 ms. The machine was not fully quiet (load 3 to 4, no `cargo`/`rustc`); raw output in [`docs/bench-results/`](bench-results/).
- **F3. Filter limits** ([CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter)). The largest filter seen: 1,150 AST nodes, depth 7, `ids_in` 119, `container_in` 592. The limits are **headroom, not measurements**: at most 4,096 AST nodes, depth 32, 10,000 `ids_in`, 10,000 `container_in`, and 20,000 entries in total (scope and id entries, plus every value of `in`). The spike models were far smaller than the limits the manifest allows, so a real tenant may need more, and the limits may change. Above a limit, `list_filter` fails closed.
- **F4. The property tests must make `NULL` cases often.** The planted `NULL` bug showed up on only 1 of 6 dev seeds. The random models in the `tutela-pdp` property tests must generate `not` over comparisons on fields that are often null.
- **F5. Machine note.** The question-3 run overlapped another session's `cargo` build (see `docs/spike-week1-results/differential.sampler.txt`). The quiet-machine rule applies only to the latency runs (SPIKE-WEEK1.md §2), and the latency runs that count were valid (no `cargo` or `rustc` ran during them). The first question-2 run was void and was run again.

**Consequences.**
- Phase A goes on in the order of the roadmap: the model language and compiler, then `tutela-pdp` with the property tests from day one.
- The spike code stays in `spike/week1/` until `tutela-pdp` has its own benchmarks and differential tests; then it is deleted. The notes and the raw outputs in `docs/` stay.
- The `tutela-pdp` benchmarks also measure **allowed delegated calls**, where the agent's and the person's scopes overlap: W3 here was almost only denies (19 allowed calls in 1,000,000).
- F1 changes CONTRACTS.md §6.6 in the `tutela-pdp` PR (ROADMAP item 4). F2 must be solved before the SDK SQL adapter is called done (ROADMAP item 6 and the library gate). F3's limits and the statement timeout are in CONTRACTS.md §6.6 now.

**Alternatives considered.** None: the result is go. The no-go answers fixed in advance (change the compiled layout, keep a closure table, lower the depth cap, stop and fix the evaluator) were not needed.

---

## ADR-0012: Manifest v1: seeded roles, org-root rules, and what counts as widening

**Status:** Accepted, 2026-10-28. Built in Phase A (`tutela-pdp`, module `model`). ADR-0011 (the week-1 spike) is the go decision this work follows.

**Context.** ROADMAP Phase A item 3 fixes the format of `tutela.resources.toml` and builds its compiler. [MANIFEST.md](MANIFEST.md) is the contract. Some choices there are decisions, not just format, and a review of the first version found that the widening check missed real widening changes and that deep input could crash the host process. This ADR records the decisions and the fixes.

**Decision.**

1. **The compiler lives in `tutela-pdp`** (module `model`). No new crate name. The evaluator will use the same compiled model.
2. **Seeded roles.** Every model has `owner`, `member`, `viewer`, `guest` and `agent` ([MANIFEST.md §5.1](MANIFEST.md#51-seeded-roles)).
   - `owner` is fixed: it cannot be declared, changed or given conditions. It is never assignable to an agent or to a group (groups may hold agents).
   - A manifest entry for another seeded role **replaces** it completely, but keeps the seeded `assignable_to` unless it sets its own (a declared `agent` stays agents only).
   - The seeded `agent` is Read only. "Write when assigned" needs a principal field, so the product declares it with a condition. PERMISSION-MODEL.md §6.1 and §17.1 say so.
   - A role with an admin key or an owner-only action can never be assigned to an agent or a group.
   - An owner-only custom action (`needs = "owner"`) needs Full on the item **and** the grant, in the compiler, the diff and the evaluator.
3. **Manifest field rules and conditions sit at the org root.** Rules and boundary settings at one scope, and bindings, are `tutela-store` data (ROADMAP item 5).
4. **What counts as widening** ([MANIFEST.md §10](MANIFEST.md#10-diffs-narrowing-neutral-widening)): the diff compares effective permissions, not text.
   - A type or role the old model does not have is compared against a baseline where it gives nobody anything. So removing a type (narrowing, no token) and adding it back weaker cannot slip through, and neither can a rename or a rollback.
   - Field and feature levels are compared at every item level a condition could leave, through one function the evaluator will share (`Model::effective_field_level`), and also at the org root.
   - A lower `needs` or a dropped `grant` of a custom action is widening by itself.
   - A new field in an existing type is widening when some role could read it at some item level, before field rules (an unknown field was masked). This includes a confidential or secret field: a per-scope rule in `tutela-store` could open it. A changed condition is widening (remove + add). A removed or weaker UI key is widening (a route loses its declared guard).
5. **Hostile input gives an error, never a crash.** The `toml` crate builds and drops its whole tree recursively, also for input it then refuses. So the compiler runs on its own thread with a fixed 32 MiB stack; the crate's own limits (80 nested brackets, 80 parts per key) keep its deepest tree far inside it. This thread is the real bound. A conservative scan before parsing refuses most deep input early (32 nested brackets, matching closers, 8 `.` per line outside strings, quotes only where a key or value starts, single-line strings that end on their line); two rounds of review found places where a scan can drift from the lexer, so it is not the guard. Templates have their own depth limit (4), and every other value is read by a flat visitor. Count limits stop the compiler at once. Text from the manifest is escaped (control characters and every default-ignorable character) and cut in every problem report, and problems and diff lines are capped in memory, not just in output.
6. **Conditions fail closed.** A template that names a group that does not exist makes the whole condition false, even under `not`. A condition may not read a confidential or secret field.

This closes [PERMISSION-MODEL.md open points](PERMISSION-MODEL.md#19-open-points) 6 (the templates) and 7 for the admin key names. The obligation kinds in point 7 stay open.

**Consequences.**
- Adding a type, or a role that gives access, is widening. The first `tutela apply` of a new product is all widening, so the CLI (ROADMAP item 9) needs a clear first-apply path with an approval token.
- The evaluator must use `Model::effective_field_level` and `Model::allows_custom_at`, each with a role's own item level after its own conditions; must combine group roles at one scope component-wise, with a custom action allowed when any deciding role allows it (raw grants are never pooled) and admin keys as a union; must drop admin keys and owner-only actions for agents however they are reached; and must treat an unknown group as "the whole condition is false".
- The reason codes of [CONTRACTS.md §6.2](CONTRACTS.md#62-reason-codes) (`no_role`, `level_too_low`, `missing_grant`, `condition_failed`) are written for one deciding role. The evaluator PR covers several deciding roles, a role that is gone, and the mixed case where one role has the grant and another the level.
- An assignment whose role the model no longer has, or no longer allows for that kind of subject, still decides its node and gives None and no grants. The diff's "a removed role is narrowing" relies on this, and so does narrowing `assignable_to`.
- An org Owner is a direct assignment of `owner` at the org root, never through a group.
- The diff is sound only if the roles a principal gets through groups at one scope combine **component-wise**: the highest item level, the highest level per field and feature, a custom action allowed when any of the roles allows it with its own item level (never a pool of raw grants), and the union of admin keys. [PERMISSION-MODEL.md open point 1](PERMISSION-MODEL.md#19-open-points) is closed that way when the evaluator lands (the week-1 spike picked one whole group role instead; that is not used).
- A valid manifest can still give a `list_filter` above the filter limits of [CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter) (many deciding scopes, roles with conditions, nesting levels). Such a list fails closed. ROADMAP item 4 measures this and either raises the limits or bounds the inputs.

**Alternatives considered.**
- **Compare only types and roles that both models have.** Lets a removed and re-added type widen without approval.
- **Let tutela-store delete a removed role's bindings** instead of comparing new roles against the baseline. It needs a store guarantee that the compiler cannot check; the baseline is checked here.
- **Edit seeded roles in place** (merge a manifest entry into the seeded role). Harder to read and to diff; replacing is simpler.

---

## ADR-0013: The evaluator: deciding roles, reasons, scope paths and Phase A limits

**Status:** Accepted, 2026-10-28. Built in Phase A (`tutela-pdp`: `Pdp::check`, `Pdp::batch`, `Pdp::list_filter`, `Pdp::write_check`). It follows ADR-0011 (the week-1 spike) and [ADR-0012](#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening) (the manifest), and closes [PERMISSION-MODEL.md open point 1](PERMISSION-MODEL.md#19-open-points).

**Context.** ROADMAP Phase A item 4 builds the evaluator. ADR-0011 and ADR-0012 left choices to it: how several deciding roles combine, which reason codes explain them, where `list_filter` gets scope paths (ADR-0011 F1), how the filter limits are enforced, and what the evaluator does with `ai_reach`, groups and moves while `tutela-store` (item 5) does not exist yet. The spike's evaluator was throwaway; it picked one whole group role, which ADR-0012 rejects, so it was not copied.

**Decision.**

1. **One code path.** `check`, `write_check` and `list_filter` use the same functions for the walk (closest assignment wins, a private scope stops inheritance, the org Owner path), for each role's conditions, and for field levels (`Model::effective_field_level` at each role's own item level after its own conditions, then the closest field rule). `list_filter` asks the same "is this role allowed" question level by level (`Model::allows_custom_at` at each item level for custom actions). The differential property test proves `list_filter` ≡ `check` on random worlds. The filter keeps `under` for every scope, whatever its type's `container` flag: `check` does not read the flag, and a path stored before a type stopped being a container (a change the diff calls neutral) still runs through it. Dropping `under` there would drop an exclusion and list rows that `check` denies.
2. **Deciding roles at one scope** ([PERMISSION-MODEL.md §6.3](PERMISSION-MODEL.md#63-role-assignments)): the direct assignment wins; else every group role there counts. Each role is evaluated on its own. They combine component-wise: the highest item level, the highest level per field and feature, a custom action allowed when any role allows it at its own item level after its own conditions (raw grants are never pooled), and admin keys as a union.
3. **Gone roles.** An assignment whose role the model no longer has, or whose role may not be given to that kind of subject (`assignable_to`, checked when the role is used), still decides its node and gives None and no grants.
4. **The org Owner** is a `user` with a direct `owner` assignment at the org root. Other principal kinds (service accounts, keys, workloads) with `owner` at the org root walk the tree like everyone else, so private scopes stop them.
5. **Agents and delegation.** Admin keys and owner-only custom actions never go to an `agent` principal, as subject or as actor, however the role was reached, and never through delegation. A delegated request needs a `user` subject and 1 to 4 `agent` actors; anything else is an error. The overlap: the item level is the lowest, each field level is the lowest, and the action is allowed only if the person and every actor allow it.
6. **`ai_reach` only narrows.** With "closest assignment wins", an agent's deciding scope is always on the resource's path, so `project` reach holds by itself. The evaluator adds one rule: an agent whose closest assignment is at the org root gets None (`outside_ai_reach`), because `ai_reach` is never the whole org. **In Phase A, `team` is the same as `project`**: it never adds access. If `team` should open sibling scopes where the agent has no assignment, that is a widening rule and needs its own ADR. PERMISSION-MODEL.md §8, §9, §11.2 and step 7, MANIFEST.md §4 and THREAT-MODEL.md TM-03 say so.
7. **Conditions.** The model's conditions sit at the org root and apply in every scope. A condition that names a group the tenant does not have is false as a whole, in `check` and in the filter. Conditions at one scope are not in Phase A.
8. **Reason codes for several roles** ([CONTRACTS.md §6.2](CONTRACTS.md#62-reason-codes)): `no_role` also when every deciding role is gone (the detail names the assignments); for a custom action, `missing_grant` when no deciding role holds the grant, else `condition_failed` or `level_too_low` judged on the roles that hold it, and the detail says so when another role has the level but not the grant; `delegation_overlap` when the person is allowed and an actor is not, except that the actor's own `outside_ai_reach` or `admin_only` is passed on.
9. **Tenant data until `tutela-store`.** The evaluator reads `TenantData`: the tenant's orgs, role assignments, groups, private scopes and field rules at single scopes. A scope is private only when it is listed, so `tutela-store` must write the private flag **in the same transaction** as the scope and the revision bump (a late flag would fail open until the next bundle), with a test. Group keys are unique in the tenant in Phase A. Field rules at the org root come only from the manifest. Loading refuses, for that tenant only (other tenants keep working):
   - two assignments for one (subject, scope), unknown groups, group cycles, and `org` scopes that are not the tenant's;
   - an org that another loaded tenant already claims (one org belongs to one tenant; scopes are keyed by (type, id), so a shared org could mix two tenants' assignments);
   - groups nested more than **32** levels deep, or a group closure of more than **1,000,000** (principal, group) pairs or more than **4,000,000** steps to compute, so one tenant's data cannot make the process allocate or work without bound (each group's closure is computed once, parents first, and each principal's is the union of its groups');
   - a revision lower than one loaded before (no going back).

   A refused load changes nothing: the tenant keeps its bundle, revision and org claims.

   A resource whose path ends at an org that is not the tenant's is denied with `tenant_mismatch`.
10. **Scope paths (ADR-0011 F1).** `list_filter` takes a provider keyed by (tenant, type, id). It asks for the path of every scope where the principal has an assignment and of every private scope of the tenant, each at most once per call. These make `list_filter` return `PdpError::ScopePath`, and the list fails closed: a provider error; a path longer than 32; a path that does not end at the tenant's own org; an `org` before the end; a path that holds the scope itself or one entry twice; and placed paths that disagree: every entry of every placed path gets one parent, and an entry with two parents is refused, also when it was never placed itself; this also catches cycles. A repeated entry would otherwise put a deciding scope one level too deep and drop the exclusion of the level above. The evaluator never treats an unplaced scope as having no ancestors. Because every private scope is placed, **one private scope the provider does not know fails every list** of a principal with any assignment: fail closed, but an outage. So a deleted scope must leave `TenantData` in the same revision as the delete. CONTRACTS.md §6.6 says so.
11. **Filter limits** (CONTRACTS.md §6.6) are enforced; above one, `list_filter` returns `PdpError::FilterTooLarge` and the list fails closed. Measured: at the library-gate size the largest filter had 472 condition nodes, depth 7 and 2,661 entries; the week-1 spike's largest had 1,150 nodes. A valid manifest can still pass the limits: each nesting level of a principal's deciding scopes repeats the conditions of its conditioned roles, so one role with 40 conditions at 8 nested scopes gives about 960 nodes (a test shows the list fails closed and `check` still answers). **The manifest is not bounded further** (the limits themselves were lowered by measurement in [ADR-0016](#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits)), because the size grows with the bindings (nesting levels times conditioned roles), which the manifest cannot bound. A warning for admins when a principal's filter nears the limits is later tooling (Phase B, Tutela Console).
12. **Obligations in Phase A.** On an allow: `label` with the highest sensitivity among the readable data fields, and for a delegated request `audit` with `on_behalf_of`. `restricted` and `recheck_online` are not sent yet; masked fields are removed, which is the safe default.
13. **`write_check` and the write mask.** Each changed field needs Write for the person and every actor. A `grants_access` field also needs the admin key `<type>:manage_access`, so agents and delegated tokens never change one. `check` follows the same rule: a `grants_access` field is in `field_mask.write` only when `manage_access` holds on every side, so a product that trusts the mask (CONTRACTS.md §6.1) cannot let an agent reassign an item. A name that is not a declared data field of the type (a feature, an unknown field) is denied. A write with no changed field is an error. **A move (`new_path`) is an error** until boundary rules (`moves_out`, `moves_in`, `on_looser`) exist with `tutela-store`: without them a move into a looser scope could leak, so it is refused.
14. **No cache across calls.** Each call resolves each (principal, scope) once. Without a cache, `check` has p99 16–30 µs at the library-gate size (below). A decision cache belongs to `tutela-sdk` (ROADMAP item 6), with the revision in its key. Loading the same revision again replaces the bundle (a retry after a failure is allowed), so the revision alone cannot prove that nothing changed: `tutela-store` bumps the revision in the same transaction as every change (item 5), and the `tutela-sdk` cache is also cleared on every load, not only keyed by revision. The work of one call grows with its answer, not with the square of it: group assignments at a scope are indexed by group (the smaller of the scope's group assignments and the principal's groups is walked), and rule ids are de-duplicated with a set. A principal with thousands of deciding group roles still gets every one in `rule_ids`; a limit on deciding roles per scope, if one is needed, belongs to `tutela-store` with the other load limits.
15. **Rule ids of model rules.** Conditions and org-root field rules come from the manifest and have no stored ids. Decisions name them `model:condition:<n>` and `model:field_rule:<n>`, the index in the compiled model, valid for that revision only.
16. **Requests are checked, never repaired.** A field value must have its declared type (a `principal` field holds a valid principal string); otherwise the request is invalid. A mistyped value is never read as null, because under `not` a null makes a comparison true while SQL compares the real column. For the same reason every `grants_access` field of the type must be sent, `null` included: a field left out is an invalid request, not a null (conditions read only those fields). Integers in `attrs` and in conditions are from −(2^53 − 1) to 2^53 − 1, so SDKs in every language read them exactly. A path holds no entry twice and not the resource itself. Size bounds: at most 1,000 requests in a `batch`, at most 512 entries in `fields`, `attrs` and `new_attrs`.
17. **The list filter names its tenant**, which the SQL adapter binds as the tenant predicate. A row with more than 32 ancestors never passes (`check` refuses its path), so the adapter adds that bound too. For the same reason the product's rows must be well formed (the SDK migration adds CHECK constraints), and a row that is not never passes: the ancestors column ends at an org of the row's tenant and holds no other org, it never holds an entry twice or the row itself, field columns have their declared types, and a `principal` column holds only valid principal strings or `NULL`.
18. **Field masks of listed rows are per row.** `list_filter` returns no mask, because masks can differ per row (field rules at single scopes, roles with conditions). The product masks each returned row with its own decision, a `batch` of read checks for the page, before the rows leave the server. An intersection over the deciding scopes would not be enough: a field rule below a deciding scope can change one row only.

Benchmark (`cargo bench -p tutela-pdp`): the tenant has the sizes of the week-1 spike (SPIKE-WEEK1.md §4.1), which the library gate names: 200 types, 100 roles, 5,000 field rules, 200 conditions, 10,000 role assignments (300 at the org root, 1,500 to groups, 500 to agents), 10,000 users and 100 agents, 500 groups nested 8 deep with one group of all users, 20,000 scopes (10% private) and 200,000 items with paths up to 32. The run fails when a `check` workload has p99 of 1 ms or more. Apple M2 Pro, 10 cores, 16 GiB, macOS 26.6.2, Rust 1.99.0 release; another session's build overlapped about 6 s of the run:
- `check`, mixed (1.5% allowed): p99 16.1 µs;
- `check`, allowed calls only: p99 30.0 µs;
- `check`, allowed delegated calls (a user and an agent assigned at the same project): p99 22.8 µs;
- `write_check` of two fields, delegated: p99 19.5 µs (90 calls);
- `list_filter` with an in-memory provider: p99 13.8 ms, and 18.1 ms delegated. Most of it is placing the 2,000 private scopes on every call; the `tutela-store` index of private scopes (consequences below) is what makes lists fast. The largest filter had 472 condition nodes and 2,661 entries.

**Gate: pass** (worst `check` p99 30.0 µs).

**Consequences.**
- [PERMISSION-MODEL.md open point 1](PERMISSION-MODEL.md#19-open-points) is closed.
- The property tests of the library gate exist in `tutela-pdp`:
  - `tm10_list_filter_returns_exactly_the_rows_check_allows`, with a fixed-seed run that counts deep paths, rows one level too deep, private scopes inside private scopes, scopes of a type that is not a container with rows below, ids reused across types, groups, gone roles, `not` over often-null fields, the overlap, the org Owner and assignments on the row itself;
  - `tm10_a_provider_miss_fails_exactly_the_lists_that_need_it` (a missing private scope and a missing assigned scope);
  - `tm05_no_cross_tenant_grant` (two tenants with the same resource ids);
  - `tm03_delegation_is_at_most_person_and_agent`;
  - `tm08_a_change_the_diff_calls_safe_never_widens`, which ties the diff of ADR-0012 to the evaluator: a change the diff does not call widening never widens a decision. Its changes include levels, field and feature levels, grants, conditions, org-root rules, `needs`, the `grant` flag, `assignable_to`, sensitivity, and fields, features, actions and roles added or removed;
  - `check_matches_the_reference_evaluator`: an oracle written from PERMISSION-MODEL.md §7.1 and this ADR, sharing no code with the evaluator, so a bug in shared code cannot hide behind list ≡ check;
  - `write_check_agrees_with_the_field_mask`: a data field is in `field_mask.write` exactly when `write_check` allows it, a write of all fields gives the verdicts of the writes one by one, and a delegated write needs the person and every actor.
- `crates/tutela-pdp/mutants/mutants.py` plants 26 bugs (35 since [ADR-0022](#adr-0022-the-searches-live-next-to-the-evaluator)) (in the walk, conditions, field rules, delegation, tenant checks, request checks, loading, the group closure, the write mask, the placer and the filter) and runs the tests against each; `results.txt` next to it is the committed output. Every one is caught. One guard cannot be a mutant: "admin keys and owner-only actions never pass through delegation" is also kept by the compiler (a role that holds them is never given to an agent, and every actor is an agent), so removing the evaluator's guard alone changes no answer. It stays as defense in depth.
- `tutela-store` (item 5) must record private scopes, keep group keys unique in the tenant (or change this ADR), and provide scope paths by (tenant, type, id). `list_filter` asks for every private scope of the tenant on each call, so its cost grows with the number of private scopes; the store should index private scopes by org or by ancestor before large tenants.
- Moves stay refused until boundary rules exist. Break-glass for the org Owner, disabled principals (token step 1, `tutela-sdk`), clearance for labelled output, and signed bundles with expiry (Phase B) are not in this evaluator.
- The week-1 spike code (`spike/week1/`) may be deleted once this lands, as ADR-0011 planned.

**Alternatives considered.**
- **Copy the spike evaluator.** It picked one whole group role (ADR-0012 rejects that), capped features by the item level, and treated a missing path as an empty one.
- **Let `team` reach open sibling scopes.** That widens access through a boundary setting; not done without a decision of its own.
- **Cache levels per (principal, scope) across calls.** Not needed for the latency gate, and a cache is one more place for a stale allow.
- **Bound the manifest (conditions per role and type) to keep filters small.** It does not bound the filter, which also grows with the bindings.

---

## ADR-0014: tutela-store in Phase A: the schema, row-level security and checked writes

**Status:** Accepted, 2026-10-28. Built in Phase A (`tutela-store`, ROADMAP item 5).

**Context.** The evaluator reads `TenantData` (ADR-0013), and ADR-0013 left the store several duties:
- record private scopes in the same transaction as the scope;
- keep group keys unique and enforce the group limits;
- leave no trace of a deleted scope;
- give `list_filter` scope paths that are current after a move (ADR-0011 F1).

[PERMISSION-MODEL.md §18](PERMISSION-MODEL.md#18-tables) lists the tables, and §16.2 asks for tenant isolation in the database itself. This ADR records how Phase A builds them.

**Decision.**

1. **One schema, `tutela`, created by numbered migrations embedded in the crate** (`tutela_store::migrate`):
   - All pending migrations run in one transaction, under an advisory lock, and are recorded in `tutela.schema_migration`.
   - A database with a migration this build does not know is refused, so an old binary never writes to a newer schema.
   - Migrations are additive only. They never drop a column, and never `DROP SCHEMA ... CASCADE`.
2. **Tables (Phase A).**
   - **With tenant data:** `tenant_rev`, `org`, `group`, `group_member`, `role_assignment`, `field_rule`, `boundary_rule`, `scope_path` and `model_revision`. The columns follow §18.
   - **Without tenant data:** `tenant` (the directory: tenant id and issuer) and `app_manifest` (the applied manifest text, its SHA-256 and a version).
   - Ids are new UUIDv7s with a prefix (`ten_`, `org_`, `grp_`, `ra_`, `fr_`) and are never reused.
3. **Row-level security.** Every table with tenant data has `tenant_id` first, `ENABLE` and `FORCE ROW LEVEL SECURITY`, and a policy on `tenant_id = current_setting('tutela.tenant_id', true)`.
   - Each store call checks the tenant key `(iss, tid)` against the directory. It then sets `tutela.tenant_id` with `set_config(..., true)` (the same as `SET LOCAL`) for the rest of the transaction.
   - With no tenant set, every query returns zero rows, also for the table owner. A row for another tenant cannot be written.
   - A superuser or a `BYPASSRLS` role still sees everything, so the product's runtime role must be neither (§16.2: app roles never own tables).
4. **Every call runs in the product's own transaction** (`&tokio_postgres::Transaction`).
   - So a change to Tutela's tables commits or rolls back with the product's change. For example, a new scope and its private flag, or a move and its new paths.
   - A write first bumps the tenant revision. That locks the tenant's revision row, so writes to one tenant are serialized.
   - It then makes the change and **checks the whole tenant data with `Pdp::load`'s own checks**: unknown or duplicate groups, cycles, nesting over 32, the closure limits, duplicate assignments, rules at an org root.
   - A refused change is an error, and the caller rolls back. The checks do not depend on the model, so a fixed one is used.
   - This reads the whole tenant on each write. That is fine for Phase A, where writes are admin work; a tenant with very many writes may need an incremental check later.
5. **Consistent reads.** `load` takes a share lock on the revision row first, then reads the data and the scope paths. It waits for a write in progress, and no write commits until the caller's transaction ends.
6. **Scopes are registered** (`put_scope`) with their ancestors, nearest first, ending at an org of the tenant.
   - A scope must be registered before it can hold an assignment, a field rule or a private flag.
   - `put_scope` writes the private flag in the same transaction as the registration and the revision bump.
   - A path that disagrees with a registered ancestor's path is refused, so `list_filter` never meets inconsistent paths.
   - `move_scope` rewrites the scope's path and every path below it in the caller's transaction. It refuses a cycle and any path over 32.
   - `delete_scope` removes the scope and every registered scope below it, with their assignments, field rules and private flags, in one revision.
   - `load` returns the paths as a `ScopePathSnapshot` (a `ScopePaths` provider). It answers only for its own tenant and only for registered scopes; anything else is `NotFound`, so the list fails closed.
7. **The model in library mode is the applied manifest.**
   - `publish_manifest` replaces `app_manifest`, refuses a publish that was compared against an older version, and records each change in each tenant's `model_revision`. In the same transaction, it bumps every tenant's revision.
   - The normalised model tables of §18 (`resource_type`, `role`, `field_registry`, `condition`, `ui_component`) come with Phase B, when the Console edits models at runtime. Library mode has no runtime role editing (ARCHITECTURE.md, library mode), and two copies of the model could disagree.
   - Phase A keeps one app per `tutela` schema for role keys: assignments name role keys without an app.
8. **Not yet.**
   - **Moves:** `boundary_rule` has the move and link columns of §18, but Phase A reads only `private`. `Pdp::write_check` still refuses moves. Moves need the before/after comparison of §10.3, which is the impact calculation of Phase B. `move_scope` keeps paths current for a move the product makes after its own check.
   - **Assignment expiry:** a row with `expires_at` set is not read at all (fail closed). Expiry needs a revision bump when it passes, which comes with Phase B.
   - **Private-scope placement:** done in [#6](https://github.com/f8fvwgzc/tutela/issues/6). `ScopePaths::below` returns the scopes under the principal's assigned scopes, and `list_filter` places only the private scopes among them. `ScopePathSnapshot` answers it from its snapshot; a provider over `scope_path` can answer it with the GIN index on `ancestors`.

**Consequences.**
- A product in library mode runs `tutela_store::migrate` as the owner role, gives its runtime role DML grants only, and calls the store inside its own transactions.
- After each write it sends the returned revision as `at_least_revision`.
- The store's tests run against a real Postgres: `TUTELA_TEST_DATABASE_URL`. CI has a Postgres service and sets `TUTELA_REQUIRE_DATABASE=1`, so a missing database fails there. Each test makes its own database, owned by a role that is not a superuser, so forced row-level security applies to every query in it.

**Alternatives considered.**
- **Row-level security without FORCE.** The table owner would bypass it, and small products often run with one role.
- **A bypass setting for admin work.** Any code could set it, so an injected bug would read every tenant. `publish_manifest` instead enters each tenant in turn, and the tenant directory, which holds no tenant data, has no policy.
- **Store the normalised model tables now.** Two copies of the model (text and tables) in Phase A, with nothing that edits the tables.
- **Let the product's tables be the only scope-path source.** Possible (ADR-0011 F1). But then the store could not refuse inconsistent paths or delete a subtree, and the product would have to answer `ScopePaths` itself.

---

## ADR-0015: Approval tokens for `tutela apply` in library mode

**Status:** Accepted, 2026-10-28. Built in Phase A (`tutela-cli`, ROADMAP item 9). Closes [PERMISSION-MODEL.md open point 2](PERMISSION-MODEL.md#19-open-points).

**Context.** `tutela apply` must refuse a widening diff unless it has an approval token bound to that exact diff (PERMISSION-MODEL.md §15.2). In library mode there is no `tutelad` to issue one. ADR-0012 also notes that a first apply is all widening, so the first apply needs a clear path.

**Decision.**

1. **The token** is `tutela-approval-v1.<payload>.<signature>` ([MANIFEST.md §12](MANIFEST.md#12-applying-tutela-apply-and-approval-tokens)):
   - The payload binds the app and the SHA-256 digests of the applied manifest (`from`, `none` for a first apply) and the new one (`to`).
   - The diff is a function of the two manifests, so the token approves exactly one diff. Binding the digests is simpler and exact; hashing the printed diff text would tie the token to the diff's wording.
   - The signature is Ed25519 (`ed25519-dalek`, BSD-3-Clause, pure Rust), verified with `verify_strict`, over the prefix and the payload. A token lives at most 24 hours.
2. **Approver keys.**
   - `tutela approvers keygen` makes a key pair and writes the private key to a new file with mode 0600. The private key never goes into the database.
   - `tutela approvers add` stores the public key in `tutela.approver_key` (store migration 0002). The key id is derived from the public key, so a signer names its key without asking the database.
   - A revoked key approves nothing, also tokens it signed before. Whoever may write that table may also change the model directly, so the table needs no more protection than the rest of the schema.
3. **Who checks what.**
   - The token holds no secret and approves one change only, so passing it on the command line or in `TUTELA_APPROVAL` is fine.
   - `apply` checks the key, the signature, the change and the times inside the same transaction that publishes. A change made by someone else in between is refused by the store's version check.
4. **The first apply** is compared against an empty model of the same app, so it is widening. The refusal prints the exact `tutela approve` command.
5. **Database connections.** With `sslmode=require` the CLI connects over TLS on the one stack (rustls on aws-lc-rs, the operating system's verifier, through `tutela_safenet::tls_client_config`) and **always verifies the certificate**, which is stricter than libpq's `require`. Without it, only a Unix socket or a loopback host is accepted; `sslmode=prefer` could fall back to plain text, so it does not count. A password and a manifest never cross a network in plain text.

**Consequences.**
- Library mode has the full refusal path: diff, class, refusal and approval.
- Phase B replaces these tokens with approvals in `tutelad` (impact report, two-person publish). The CLI against `tutelad` still refuses a widening diff without an approval.
- A product's deploy pipeline applies narrowing and neutral changes on its own. A widening change waits for a person with an approver key.

**Alternatives considered.**
- **A shared secret (HMAC).** Every applier could then mint approvals.
- **Sign the printed diff text.** It ties the token to the diff's wording, and two diffs of the same manifests would need two tokens.
- **No first-apply approval.** Any new product, or a wiped table, would grant everything without a human seeing it.

---

## ADR-0016: The list query: grouped terms, hashed scope tests and lower filter limits

**Status:** Accepted, 2026-10-29. Built in `tutela-sdk::sql` and `tutela-pdp` ([#26](https://github.com/f8fvwgzc/tutela/issues/26)).

**Context.** The library gate asks for a list-query p99 under 100 ms at the `list_filter` limits. The first measurement ([ADR-0011](#adr-0011-week-1-spike-go-for-the-native-evaluator) F2, [#22](https://github.com/f8fvwgzc/tutela/issues/22)) failed: at the old limits, 186 of 200 queries hit the 5 s statement timeout. Two costs caused it:
- array overlap (`ancestors && $n`) compares every pair, which is slow with thousands of scopes;
- every row evaluated a condition of 1,000 terms.

**Decision.**

1. **Grouped terms (option 1 of #26).**
   - Inside an `or`, the terms of the form `under[S] AND rest`, where `rest` reads fields only, are grouped by the shape of `rest`: the same leaves, with different values.
   - A group of 4 or more terms becomes one test. The group's scopes are bound as one array, and the terms as one JSON map from scope to the terms' values. A row is matched only against its own ancestors (at most 32): first an `= ANY` (hashed) test against the group's scopes, then the map lookup and `rest` with the term's values.
   - A term holds exactly when one of its scopes is an ancestor and `rest` holds. The lookup tests exactly that, so the grouped SQL lists the same rows as the term-by-term SQL. A property test on Postgres checks it over random rows with nulls and random filters of every shape.
   - The aliases it uses (`tutela_anc`, `tutela_scope`, `tutela_term`, `tutela_vals`) are refused as product column names.
2. **Hashed scope tests.** A scope list over 64 entries (the top-level `container_in`, or an `under` in the condition) is tested per ancestor with `= ANY`, which Postgres hashes. Shorter lists keep `&&`, which a GIN index serves. At the top level a `NULL` ancestors column can only exclude a row, so that test is bare and indexable. Inside the condition every test keeps its `coalesce`, so a `NULL` never passes `not`.
3. **Lower limits (option 2 of #26).** Options 1 and 2 together gave p99 144 ms at the old limits, still over the gate. The limits are now:
   - 512 condition nodes (was 4,096) and depth 32;
   - 2,000 entries each in `ids_in` and `container_in` (was 10,000 each);
   - 4,000 entries in total (was 20,000).

   They sit above the largest filter measured at the library-gate size (472 nodes and 2,661 entries, ADR-0013 #11). The condition terms drive the cost: 256 terms gave p99 99 ms, so 128 terms (512 nodes) leaves room. A filter above a limit still fails closed.

**Measured** (`cargo bench -p tutela-sdk --bench list_query`):
- Machine: Apple M2 Pro, 16 GiB, macOS 26.6.2, PostgreSQL 16.14 with the default config, load about 2, no `cargo` or `rustc` running.
- Data: 20 tenants × 100k rows, GIN on (`tenant_tid`, `ancestors`), 200 `count(*)` queries per workload, 5 s timeout.
- **typical:** p50 1.86 ms, p99 3.65 ms.
- **limits** (2,000 `container_in`, 1,872 `ids_in`, 128 terms): p50 72.5 ms, p99 **79.8 ms**, no timeouts. **The gate passes.**
- Raw runs 1 to 5 are in [`docs/bench-results/`](bench-results/).

**Consequences.**
- Principals whose filters pass the lower limits now fail closed: an error, no rows, while `check` still answers. Above about 128 condition terms, the product must split the work (for example by type or by scope).
- The `tutela-pdp` property tests (`list_filter` ≡ `check`, no cross-tenant grant, delegation, no widening) and the SQL differential test pass unchanged at the new limits.
- `cargo bench -p tutela-sdk --bench list_query` exits 1 when the gate fails. Its "limits" workload follows the constants in `tutela-pdp`.

**Alternatives considered.**
- **Materialize each principal's visible scopes per revision** (option 3). It needs store tables and invalidation for every binding change. Options 1 and 2 meet the gate without it.
- **Lower the limits only.** The cost per row stayed: with the old SQL even small limits timed out on the array overlap.

---

## ADR-0017: Opaque public errors for the crates that touch the outside world

**Status:** Accepted, 2026-11-02. Built for v0.2.0 ([#43](https://github.com/f8fvwgzc/tutela/issues/43)).

**Context.** Four public errors held a dependency's type or flattened a cause into a `String`:
- `StoreError::Db(tokio_postgres::Error)` and `SqlError::Query(tokio_postgres::Error)`: a bump of the driver would be a breaking change for us;
- `SafenetError::Http(String)`: `reqwest::Error`'s own text leaves its cause out, so the real reason (for example, connection refused) was lost;
- `VaultError::Kms(String)`: a backend's error had no `source()`.

Our public errors were `#[non_exhaustive]` enums with public variants, so every variant, field and tuple position was public API. v0.2.0 is the moment to break them; texc-symphony and attache stay on `v0.1.0` until they choose to bump.

**Decision.**

1. **`StoreError`, `SqlError`, `SafenetError` and `VaultError` are opaque.** Each is a struct with one private field, a private `thiserror` enum, and `#[error(transparent)]`. So `Display` and `source()` come from the private enum, and nothing of it is public.
2. **Callers branch on a kind.** Each has `kind()`, which returns a `Copy`, `#[non_exhaustive]` enum: `StoreErrorKind`, `SqlErrorKind`, `SafenetErrorKind`, `VaultErrorKind`. Data lives behind accessors:
   - `StoreError::detail`, `refusal` and `sqlstate`;
   - `SqlError::sqlstate`;
   - `SafenetError::host` and `limit`;
   - `VaultError::key` and `variable`.
3. **There is no public `From<tokio_postgres::Error>`.** It would keep the driver's type in the API, and `?` would keep working only by accident. `tutela-store` converts inside with a private `.db()`.
4. **A SQLSTATE is text.** `sqlstate()` gives a caller what it needs from the driver (`42501` when row-level security refuses a row, `40001` to retry, `57014` for a statement timeout) without the driver's types.
5. **The `Kms` trait stays open to other backends.** `VaultError::kms`, `unknown_key` and `decrypt` are public constructors, because a backend outside this repo must return them.
6. **`SafenetErrorKind::Http` keeps `reqwest::Error` privately, with its URL removed** (`without_url`). The chain now holds the reason and still no part of the URL, and a test checks both.
7. **`tutela_contracts::error_chain` is public.** It replaces the private copies, and `{err}` reporters in other repos can use it at their bump ([#44](https://github.com/f8fvwgzc/tutela/issues/44)).
8. **Only these four change.** The other public errors stay `#[non_exhaustive]` enums or small structs:
   - the parse errors of `tutela-contracts` and the errors of `tutela-pdp` hold no dependency's type and no flattened cause, and they describe stable categories (the `library-errors` skill's middle ground);
   - `AuthError` is already opaque;
   - `CliError` belongs to a binary; its `Postgres` variant now holds a boxed cause.

**Consequences.**
- `VaultError` is no longer `Clone`, `PartialEq` or `Eq`: a boxed cause has none of these. Compare `kind()`.
- A product that used `?` on a `tokio_postgres::Error` in a function returning `StoreError` needs its own error type. A failed `commit` is the product's error, not the store's.
- `tutela_store` still takes `&tokio_postgres::Transaction` and re-exports `tokio_postgres`, because every call runs in the product's own transaction. So a major driver bump can still be a breaking change. This ADR closes the error path only.
- The migration note is [MIGRATION-0.2.md](MIGRATION-0.2.md).

**Alternatives considered.**
- **Keep public enums and box only the causes** (the skill's middle ground). This keeps every variant public. The store's and the safenet's categories are still moving in Phase B.
- **`anyhow` in the libraries.** It gives callers nothing to branch on.
- **Make every error in the workspace opaque.** About thirty parse errors would change, with no dependency type to hide, and two consumers would pay for it.

---

## ADR-0018: `tutelad`: the stack, the two ports and the config

**Status:** Accepted, 2026-11-02. Built in Phase B ([#48](https://github.com/f8fvwgzc/tutela/issues/48)).

**Context.** The docs name `tutelad`, its env prefix, its image and what it serves. They name axum and tonic for the SDK's layers, and gRPC `tutela.authz.v1` for the service. They leave open the layout, the ports, the config format, the metrics and the pool.

**Decision.**

1. **A library plus a thin binary**, in `crates/tutelad`. The tests run the same `Server` as production, and `Server::bind` takes port 0. The modules are `config`, `api`, `db`, `telemetry` and `server`.
2. **axum and tonic on one listener.** `api::api_router` looks at `content-type`: `application/grpc...` goes to the gRPC router, the rest to the HTTP router. They are two routers because each needs `AuthLayer` with its own `Protocol`, and because tonic's router has its own fallback. A later part adds an HTTP route in `api_router`, and a gRPC service next to the health service in `Server::bind`.
3. **Two ports.**
   - The API port needs a token on every request, also for an unknown path, so it says nothing to a caller without one.
   - The ops port has `/healthz`, `/readyz` and `/metrics` with no token. It stays out of the public load balancer. A probe needs no token, and metrics never share a port with the API.
4. **Config is `TUTELA_*` variables plus a trust file.**
   - The trust file is TOML (`TUTELA_TRUST_FILE`), because a list of issuers with their tenants does not fit a variable. It holds no secret, so it can be a ConfigMap. Unknown keys are refused, and so is a file with no issuer.
   - `TUTELA_DEV_MODE=1` allows `http` issuers and JWKS on loopback only.
   - `Config`'s `Debug` leaves the database URL out, and errors never hold it.
5. **Readiness needs the exact schema.** `/readyz` fails unless the newest migration in the database is the one this build knows. This keeps ADR-0014's rule that an old binary never writes to a newer schema. So during an upgrade, old replicas go not ready when the migration lands, and stop answering queries at their next check ([#57](https://github.com/f8fvwgzc/tutela/issues/57)). Rust products keep answering from their bundles; the deploy should start new replicas right after the migration.
6. **Liveness never reads the database.** A database outage must not restart every replica.
7. **Metrics are the Prometheus text format** (`prometheus-client`), prefix `tutelad_`. A collector can scrape them. Labels hold a method, a route pattern, a status or a verification step, never a tenant, a token or a URL.
8. **Logs are JSON on stdout** (`tracing-subscriber`), filter `TUTELA_LOG`. A request is logged by its route pattern, with a request id and the `traceparent` trace id. The tenant id goes in the request span once a handler has it. OTLP export is not built yet (ROADMAP Phase B status).
9. **`AuthLayer` puts the failed `Step` in the response's extensions.** The wire still says nothing, and an outer layer can log and count the step, as CONTRACTS.md 4.2 asks. The SDK stays free of `tracing`.
10. **The pool is `deadpool-postgres` with `RecyclingMethod::Clean`**, so `RESET ALL` runs on every reuse. Sessions start with `statement_timeout=5000` and `idle_in_transaction_session_timeout=10000`. The TLS rule is the CLI's: `tutela_store::database_config` is now the one copy of it. A database that is not on this machine needs `sslmode=require`, and the certificate is always verified.
11. **Shutdown order.** On SIGTERM: readiness fails and gRPC health says not serving; the service keeps serving for `TUTELA_SHUTDOWN_DRAIN_SECS`; the API port stops and running requests get `TUTELA_SHUTDOWN_TIMEOUT_SECS` to finish; the ops port stops last.
12. **The licence stays the workspace's MIT for now.** ADR-0010 leaves `tutelad`'s licence open until before Phase C or a public release.

**Consequences.**
- `RUST_BACKTRACE=1 RUST_LIB_BACKTRACE=0` is in `deploy/tutelad.env`, which `deploy/compose.yaml` reads ([#45](https://github.com/f8fvwgzc/tutela/issues/45)). A test keeps both there. The Helm chart must set the same values when it exists.
- `TUTELA_MASTER_KEY` and `TUTELA_KEY_PEPPER` are not read yet, because nothing in `tutelad` uses them. The part that adds signing keys and API keys must make them required at start-up (TM-22).
- Delegated tokens stay off in the verifier until the part that adds them.
- The trust file is static. Tenants that token exchange makes at runtime will need the service's own issuer to trust the tenant directory; that part must change this.

**Alternatives considered.**
- **One port for everything.** Metrics would need auth or would leak on the public port, and a probe would need a token or an exception.
- **gRPC health on the ops port.** It would prove nothing about gRPC on the API port. Health behind the token check proves `AuthLayer` with `Protocol::Grpc` over real HTTP/2.
- **Add tonic with the first real gRPC service.** Then part 2 would have to solve the shared listener and the second auth layer together with the API.
- **`sqlx`.** The store is built on `tokio-postgres`, and every call takes its `Transaction`.

---

## ADR-0019: Tenants in `tutelad`: the tenant comes from the token, and RLS is checked

**Status:** Accepted, 2026-11-02. Built in Phase B ([#51](https://github.com/f8fvwgzc/tutela/issues/51)). It builds on ADR-0014, which it does not change.

**Context.** ADR-0014 put forced row-level security on every tenant table. That stops a code bug only when three other things hold: the role cannot bypass it, the tenant comes from the verified token, and the setting never outlives its transaction. TM-14 lists how each one goes wrong. The Service gate wants two checks proved: a query with no tenant set returns zero rows, and a cross-tenant read fails at RLS even with an injected code bug.

**Decision.**

1. **The type system carries the tenant.** `tutelad::tenant::Tenant` has a private field and one constructor, `Tenant::of(&Identity)`. It does not deserialize and has no `From`. A handler takes it as an argument, and the extractor reads the `Identity` that `AuthLayer` verified. So a header, a query or a body cannot become a tenant. A `compile_fail` test holds this.
2. **A handler has one way to the database.** `Db::conn()` gives a `Conn` with no query methods. `Conn::begin(&Tenant)` starts a transaction and calls `tutela_store::enter`, which checks `(iss, tid)` against the directory and runs `set_config('tutela.tenant_id', ..., true)`, the same as `SET LOCAL`. `TenantTx` derefs to the driver's `Transaction`, so every store call takes `&tx`.
3. **A transaction belongs to one tenant.** `tutela_store::enter` refuses a second tenant (`TenantMismatch`). Before, a store call with another key switched the transaction, so a bug that passed the wrong key would have read the wrong tenant, past RLS. `publish_manifest` is the one write that spans tenants: it sets each in turn and leaves none set.
4. **The service role owns nothing.** `tutela_store::grant_service` gives it read and write on the tables with forced RLS, found in the catalog, and read on `tenant`, `app_manifest` and `schema_migration`. It has no access to `approver_key`, no write to the tenant directory or the manifest, and no `CREATE`. A later part that needs more adds it here on purpose.
5. **`tutelad migrate` is the deploy step.** It reads `TUTELA_OWNER_DATABASE_URL` and `TUTELA_SERVICE_ROLE`, runs the migrations and grants, and needs nothing else. A migration cannot create the role: a library-mode owner usually lacks `CREATEROLE`, and `tutela-store`'s migrations must run there too. The operator creates the role once.
6. **Isolation is checked, not assumed.** `tutela_store::check_isolation` reads the catalogs:
   - the role is not a superuser, has no `BYPASSRLS`, owns nothing, is not a member of an owner, and cannot create objects;
   - every table with a `tenant_id` column, except the directory, has RLS, `FORCE` and a policy;
   - there is no `SECURITY DEFINER` function and no owner-rights view.

   `tutelad` refuses to start when this fails. It runs the check again in readiness and stops every query if a later check fails. If the database is down at start-up, the service starts not ready, and no query runs until the check has passed.
7. **Recycling clears the session.** `RecyclingMethod::Clean` runs `RESET ALL` on every reuse, so even a bug that sets the tenant for the session does not reach the next request. Readiness also checks that a fresh connection has no tenant set.
8. **The errors say nothing.** An unknown tenant is 403 `unknown_tenant`. Everything else is 503 `unavailable`. The log gets the kind and the SQLSTATE, not the server's message, which can hold a value from a row.

**How the gate is proved** (`crates/tutelad/tests/rls.rs`, real Postgres, a role that owns nothing):
- **No tenant set:** every tenant table the catalog lists returns zero rows, in and out of a transaction, even with a filter that names a tenant. A superuser sees rows for both tenants on the same tables, so the zero means something. A new tenant table with no seed rows fails the test.
- **Injected bug:** a real handler behind the real token check and pool runs a query with no tenant filter, and one that names another tenant from the request. It gets its own rows and none of the other's. The test then turns RLS off on that table, and the same request with the same token returns the other tenant's row. So RLS stopped it, not code. The test goes around the application's filter: the store's `WHERE tenant_id = $1` is not in that query.
- Every table is checked the same way, and so are writes: another tenant's id on a new row is refused with SQLSTATE `42501`, and an update or a delete of its rows reaches nothing.

Planting bugs confirms the tests can fail: an open policy, no `FORCE`, `RecyclingMethod::Fast`, and no mismatch check each fail the tests that should catch them.

**Consequences.**
- A superuser or a `BYPASSRLS` role still sees everything (ADR-0014). The difference is that `tutelad` now refuses to run as one.
- The tenant directory stays free of RLS. Any role with `SELECT` can list tenant ids and issuers, which hold no tenant data, so that a request can be checked before a tenant is set.
- RLS trusts `tutela.tenant_id`. Code that can run arbitrary SQL could call `set_config`. Bound parameters keep SQL injection out; RLS is the second wall, not the first.
- Soft-delete of tenants is not built. It comes with the admin API (`tutela.admin.v1`).

**Alternatives considered.**
- **Set the tenant in a tower layer.** A layer cannot hold a transaction open across a handler without boxing it, and a handler that opened its own would miss it. `Conn::begin` puts it where the transaction starts.
- **Run the migrations at start-up.** The service would need the owner's credentials, and TM-14 wants them apart.
- **Put the check in CI only.** TM-14 asks for a CI check. Running it in the service as well also covers a role changed in production.

---

## ADR-0020: The bindings store: closures at read time, and assignment expiry

**Status:** Accepted, 2026-11-02. Built in Phase B ([#53](https://github.com/f8fvwgzc/tutela/issues/53)). It builds what ADR-0014 item 8 left for Phase B, and settles what ADR-0011 item 3 left to the store.

**Context.** ADR-0014 gave the store checked writes for assignments and groups, but no way to read them back. It ignored a row with `expires_at`, because expiry needs a revision bump when it passes. ADR-0011 left open whether the group closure is a table or a query, and [PERMISSION-MODEL.md 6.4](PERMISSION-MODEL.md#64-groups-new) still said table.

**Decision.**

1. **Reads** run in the caller's transaction, like everything in the store:
   - `assignment`, and `assignments` with a filter on subject or scope, a page of at most 1,000, ordered by id;
   - `assignments_for`: a principal's own, plus those of its groups;
   - `groups` and `group_members`;
   - `groups_of` and `members_of`: the group closure, up and down;
   - `ancestors` and `scopes_below`: the path closure, up and down.
2. **The group closure is read at query time**, with a recursive query. There is no closure table. ADR-0011 measured p99 0.18 ms that way, against 0.10 ms from a table that costs p99 77 ms to update when one group nests in another. A write must then keep a second copy of the truth correct, and a bug there grants access. The evaluator already holds each principal's groups in memory per revision. Migration 3 adds the index the walk up needs.
3. **An assignment can end.** `assign_until` sets `expires_at`, and `set_assignment_expiry` changes it. A time already past is refused, by the database's clock, so all replicas share one clock.
4. **An expiry takes effect at once for new reads, and the revision follows.** The two are separate on purpose:
   - Every read drops a row past its expiry, with `clock_timestamp()`. `now()` is the start of the transaction, so a long transaction would keep an expired row. This is the fail-closed part: it needs no sweep.
   - `expire_assignments` removes those rows and bumps the revision in one transaction, so caches at an older revision reload. It returns what it removed, so the audit log can record it in that transaction when it exists.
   - With nothing expired there is no bump, and the check takes no lock. Replicas that sweep at once wait on the revision row, and the second finds nothing, so one expiry makes one revision.
   - It runs no load checks. Taking a row out cannot break them, and a tenant whose data no longer loads must still lose an expired grant.
5. **`tutelad` sweeps on a timer** (`TUTELA_EXPIRY_SWEEP_SECS`, default 30 s). It enters each tenant in turn, as ADR-0014 does for `publish_manifest`, because row-level security hides every other tenant's rows. There is no bypass. A failure in one tenant does not stop the others. A job has no token, so `Conn` has crate-private methods for this one job; a handler cannot use them, and `Tenant` stays token-only.
6. **`TenantBundle::next_expiry`** says when a loaded view stops being true. Between an expiry and the sweep, two loads at one revision can differ: the later one has less. So `(tenant, rev)` alone no longer fixes the data, in the narrowing direction only.
7. **`remove_principal`** takes a principal's assignments and memberships in one revision (PERMISSION-MODEL.md 6.4).
8. **An expired row does not hold its place.** `assign` removes a row past its expiry for the same (subject, scope) in its own transaction.

**Measured** ([#55](https://github.com/f8fvwgzc/tutela/issues/55), `cargo bench -p tutela-store --bench closure`):
- Machine: Apple M2 Pro, 16 GiB, macOS 26.6.2, PostgreSQL 16.14 (Homebrew) in a new cluster with the default config and `--locale=C`, on loopback TCP, load about 2.
- Data: the spike's closure world in each of 20 tenants, in one set of tables (613,115 `group_member`, 400,000 `scope_path` and 200,000 `role_assignment` rows). Each tenant has 10,000 users, 500 groups in 8 levels, a chain of 32 nested groups, 20,000 scopes with paths of 1 to 32, and 10,000 assignments.
- Each run is a real request: a role that owns nothing, forced row-level security, a new transaction, `enter`, the store call, `COMMIT`, with a random tenant and input. 1,000 warm-up runs, then 10,000 measured, with unprepared statements. The `tx` figures are the whole transaction; `call` is the store call alone.
- The gate is the threshold fixed before the spike: p99 under 5 ms for G, G32 and P. **All five runs pass.** Each p99 below is the worst of the five; each p50 is their mean.

| Query | p50 tx | p99 call | p99 tx | Gated? |
|---|---|---|---|---|
| **G** groups of a user (about 50 rows) | 0.99 ms | 0.90 ms | **1.44 ms** | yes |
| **G32** groups of a user at the bottom of 32 levels | 1.07 ms | | **1.46 ms** | yes |
| **P** path of a scope at depth 32 | 0.43 ms | 0.32 ms | **0.67 ms** | yes |
| A assignments that apply to a user (about 125 rows) | 1.78 ms | | 2.49 ms | information |
| M32 members at the end of the chain | 0.58 ms | | 0.95 ms | information |
| **B** scopes below a scope at depth 16 | 8.17 ms | | **11.0 ms** | information |
| M members of the group that holds everyone (10,000 rows) | 20.0 ms | | 22.9 ms | information |
| L a whole tenant loaded | 84.3 ms | | 90.6 ms | information |
| W a checked membership write, and its removal | 95.6 ms | | 104 ms | information |

M, L and W ran 200 times, because they read a whole tenant or a whole group. Raw runs 1 to 5 are in [`docs/bench-results/`](bench-results/) as `closure-run*.txt`.

**What the numbers say.**
- Going up is fast, so read-time closure holds. The real calls cost more than the spike's prepared statement (p99 0.18 ms), because they plan each statement and pay a transaction. They are still a third of the budget.
- **The path closure going down (B) is over 5 ms, and it does not use the GIN index.** ADR-0014 item 8 said a provider over `scope_path` could answer `ScopePaths::below` with that index. Under row-level security it cannot: `@>` on arrays is not `leakproof`, so Postgres must run the policy first, and it reads all of the tenant's rows (`EXPLAIN` as the service role shows a scan on `scope_path_pkey` with 20,000 rows filtered). `tutela-pdp` does not need this path, because `ScopePathSnapshot` answers from memory. A SQL provider for `below` would be O(tenant's scopes). Do not build one without measuring it.
- W is the cost ADR-0014 item 4 warned about: a write reads the whole tenant, about 48 ms each at this size. It is fine for admin work, and it is not fine for bulk imports. The sweep skips this check.

**Consequences.**
- **Part 2 must honour `next_expiry`.** A signed bundle's `expires_at` must be no later than its `next_expiry`, or a PDP keeps allowing until the sweep and a push. `tutela_pdp::Pdp` does not know about expiry; the loader does.
- A cache that ignores `next_expiry` is late by up to the sweep interval, plus the time to reach it. PERMISSION-MODEL.md 16.1 has the row.
- In library mode nothing sweeps. The product calls `expire_assignments` on a timer. Until it does, an expired assignment does not count, but the revision does not move.
- A sweep is one short transaction per tenant, on one connection. Its cost grows with the number of tenants, not with the rows.
- The expired row is gone. Until the audit log exists (a later part of Phase B), the log line is the only trace.

**Alternatives considered.**
- **A closure table** (above).
- **Filter by time only, with no sweep.** Caches would never learn of an expiry.
- **Sweep only, with no time filter on reads.** That is a stale allow for up to one interval, and it fails open if the sweep stops.
- **Sweep inside `load`.** A read would have to take a write lock and bump a revision.
- **Keep expired rows, marked.** The unique rule on (subject, scope) would block a new assignment, and every read would have to skip them. The audit log is the right place for history.
- **A list of what is due, outside row-level security.** It would be faster with many tenants, but it is a table with tenant data and no policy.

---

## ADR-0021: The check API: one code path, a snapshot per tenant, and a revision lease

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2a.

**Context.** `tutelad` must answer "may this principal do this?" from `tutela-pdp`, at a known revision, over HTTP and gRPC, on 2+ replicas. A whole-tenant load is about 84 ms at the benchmark's size (ADR-0020), so it cannot run per request. The docs leave open how a replica holds a tenant's data, how it learns that a revision moved, who may ask, and how a batch reports a bad item. Two rules from part 1 shape the answer: two loads at one revision can differ when an assignment expires, and a service with no database must never turn stale data into an allow.

**Decision.**

1. **One code path.** `tutelad::authz` holds the logic, on the types of `authz::wire`. HTTP deserializes those types, gRPC builds them, and neither adapter decides anything. A test asks both the same questions and compares every field.
2. **One immutable snapshot per tenant** (`tutelad::cache`): a `Pdp` holding that tenant only, the scope paths, the model and its digest. A new revision builds a new snapshot and swaps it in. A `Pdp` per tenant, not one shared `Pdp`, means one tenant's bad data or a lookup bug cannot reach another, and a load takes no lock that other tenants wait on.
3. **A replica learns of a change through a lease.** A snapshot is trusted for `TUTELA_REVISION_CHECK_MS` (default 1000) after it was last proved current. The first request after that reads `tenant_rev` while the other requests for that tenant wait, and a moved revision loads a new snapshot. The lease starts **before** the read, so a change that commits during the read is not counted as absent. `0` reads the revision on every request. An idle tenant costs nothing, and the load on Postgres does not grow with the request rate.
4. **`at_least_revision` and the token's `rev`** go past the lease: a snapshot below them forces the read. The read comes first, so a caller who sends a huge number costs one small query, never a whole-tenant load. If the database is behind that revision the answer is 503 `stale`.
5. **Failing closed.** While the database gives no answer, a snapshot may serve until the max age of the action's class: `TUTELA_MAX_AGE_READ_SECS` (default 60) for `read`, `TUTELA_MAX_AGE_WRITE_SECS` (default 10) for every other action, and no staleness at all for admin keys and owner-only actions, which are revocation-sensitive (PERMISSION-MODEL.md 16). The age counts from before the last good read. Past it, 503. A batch uses the strictest class among its items. After a failed read, requests do not try the database for 1 s, so an outage answers at once instead of queueing behind a timeout. No snapshot and no database is 503.
6. **A snapshot stops at `next_expiry`**, also when the revision has not moved. The deadline is measured from the database's clock (`TenantBundle::read_at`), counted on this process's monotonic clock from before the read, so a replica whose clock is behind cannot keep an expired assignment. Past the deadline the snapshot is never used: it reloads, or the answer is 503.
7. **No going back.** A revision below the one in hand is refused and logged. A database restored from an old backup needs a restart of the replicas, on purpose (TM-13).
8. **The model.** A schema holds one app (ADR-0014 item 7), so `tutela_store::applied_manifest` reads the one manifest and refuses a schema with two. It is read after the revision's share lock, in one transaction, so a view never pairs a new revision with an old model. A compiled model is kept by digest, because a large manifest takes seconds to compile.
9. **Who may ask.** A service (`sa`, `key`) asks about its whole tenant. A person or an agent asks about itself only, or any token could read anyone's permissions. A delegated token asks about its own person and its own full chain. An external token cannot ask until token exchange gives it a principal.
10. **A subject of another tenant is `no_role`, not `tenant_mismatch`.** This changes CONTRACTS.md 7.1, which said `tenant_mismatch`. Tutela has no table of principals per tenant to say so from, and it should not: a different answer would tell one tenant that a subject exists in another. A test compares the two answers.
11. **A bad batch item gets its own error** with `decision: false`, as AuthZEN says, not a failed batch. `Pdp::batch` fails the whole batch, so the service runs `check` per item on one snapshot. Limits and permissions are checked before any item runs.
12. **gRPC messages are generated at build time by `protox`**, a protobuf compiler written in Rust, so a build needs no `protoc` on the machine or in CI. The `.proto` file lives in `tutela-contracts`.

**Consequences.**
- In normal running, a revoked role stops within `TUTELA_REVISION_CHECK_MS` plus one read, on every replica. A replica cut off from the database can serve an old answer up to the max age of the class. PERMISSION-MODEL.md 16.1 has the measured numbers.
- A snapshot per tenant stays in memory while the process runs. The trust file bounds the tenants that can reach it today. When token exchange adds tenants at runtime, this needs an eviction rule.
- Each replica reads each active tenant's revision once per second: four round trips. Thousands of active tenants would feel this; the interval is a setting, and a push is the next step (below).
- Part 2b: `write_check` over the network goes through `authz` as a new operation, with `ActionClass::Write` or stricter. A model publish needs no hook in the cache: `publish_manifest` bumps every revision, so the next check loads the new manifest.

**Alternatives considered.**
- **Read the revision on every request.** Simple and has no delay, but it puts a query on every check, and during an outage nothing can answer. `TUTELA_REVISION_CHECK_MS=0` gives this to whoever wants it.
- **`LISTEN`/`NOTIFY`.** Delay of milliseconds, but it needs a trigger, a connection outside the pool with its own reconnect and TLS, does not pass through a transaction-mode PgBouncer, and a lost notification goes unseen, so the lease would still be needed as the safety net. It can be added on top later without changing this contract.
- **Serve the stale snapshot while a background read runs.** A tenant with little traffic would then get its first answer from data up to the max age old, in normal running. A request waits for the read instead, and uses stale data only when the read fails.
- **One shared `Pdp`.** It has org claims across tenants and one lock for all of them.
- **`protoc` at build time.** One more tool on every machine, in CI and in the image build.

---

## ADR-0022: The searches live next to the evaluator

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2a.

**Context.** CONTRACTS.md 7.4 asks for `search/resource` and `search/subject`, bounded and paged. TM-10 requires that they use the same evaluator as `check`, and the property tests of that rule are in `tutela-pdp`, with a random world generator that nothing outside the crate can use. Two facts make the question harder than a loop over `check`. Tutela holds no field values, so `check` cannot be asked about a resource whose type has `grants_access` fields. And a scan over every member of a tenant's groups could cost a third of a second per call.

**Decision.**

1. **`Pdp::search_resources` and `Pdp::search_subjects` are in `tutela-pdp`.** `tutelad` only checks who asks, finds a view and runs them on a blocking thread. So they can use the private index, and the property test in `tests_props` can reach them. That test extends the `list_filter` ≡ `check` differential: `tm10_search_agrees_with_check` runs on random worlds, and 9 new planted bugs (M27 to M35 in `mutants.py`) are all caught.
2. **A resource search reads the filter with three values.** `list_filter` is proved equal to `check`, so it is read here for one known scope. A node that needs a field value answers "unknown". `and`, `or` and `not` follow three-valued logic, and only a certain true is listed. Treating unknown as false is not enough: under a `not` it would turn into true. So a named resource passes for every field value, and the test re-checks each one with other rows' values.
3. **A subject search asks `check` itself**, on the resource the caller sent. There `check` has what it needs. Candidates are the principals of assignments on the resource and on its path, and the members of those groups, because with no assignment on the path the answer is a default deny. The test compares the result with `check` for every principal of the world in both directions.
4. **A page has two bounds**: the limit (default 100, at most 1,000) and 10,000 candidates looked at. A page cut by the second keeps a cursor at the last candidate looked at, not the last result, so the list is never ended early. This is why a short page does not mean the end.
5. **The cursor is keyset, and the token is not signed.** A list is decided again on every page, so a forged token can only skip ahead through what the caller may see anyway. Binding the token to a revision would break every paging client on each revision.
6. **Only a service may list subjects.** It is a question about other principals.
7. **The errors.** A scope that cannot be placed is 503: the tenant's data is at fault, and a list must not come back partial. A filter over a limit is 400 `filter_too_large`.

**Consequences.**
- A product with conditions over fields gets fewer names from `search/resource`, and the same complete answer from the filter. This matches CONTRACTS.md 7.4: names are a convenience, and the filter is the list.
- `ScopePaths` providers must answer `below` to serve a search. `ScopePathSnapshot` does.
- The cost of a call is bounded, not small: up to 10,000 candidates. Rate limits for search are open (TM-23, Phase D).

**Alternatives considered.**
- **Call `check` for each known resource with null fields.** Under `not`, a null makes a comparison true, so it would name a resource that its real values deny.
- **Put search in `tutelad`.** It would need the private index, and the property test could not see it.
- **A `total` in the page.** It needs the whole list on every page, which is the cost the scan bound exists to avoid.

---

## ADR-0023: The permission map, and a tag that covers the answer

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2a.

**Context.** CONTRACTS.md 7.5 said the ETag covers the revision, the subject and the request body. ADR-0020 came later: an assignment can expire before the sweep moves the revision, so two answers at one revision can differ. A tag of (revision, subject, request) would then give a 304 to a UI that still shows a button the person has lost.

**Decision.**

1. **The answer is worked out on every call, and it is part of the tag.** A hash of the tenant, the revision, the model digest, the subject, the actors, the request and the map itself. The work is a few `check` calls in memory, with no database read, so a 304 saves bandwidth, not safety. The revision and the model stay in the tag even though the answer covers most of what they change: the contract wants a new tag at a new revision, and a client can see that one moved.
2. **The caller is judged first**, so a 304 cannot confirm a map to someone who may not ask for it.
3. **`*` never gives a 304.** RFC 9110 lets it match any current answer, and the caller would keep a map it may not hold.
4. **Each mode comes from `check`**, one call per action, so the map cannot say more than `check` does. A UI key about another type cannot be decided on this resource, so it counts as denied. `readonly` with a field at `none` becomes `hide`, because `readonly` shows the value.
5. **`resource.attrs` is added to 7.5.** `check` needs every `grants_access` field, and a request without one is invalid; a null would be a guess (ADR-0013 item 16). A field-free type needs none.
6. **A UI key that is not in the model is 400**, like an unknown action, and the UI falls back to denying.

**Consequences.**
- The map is a UI hint. A route still checks again, so `ActionClass::Read` is enough here, whatever the actions in it are.
- A client that polls pays for the evaluation each time. That is in-memory work, and the response body is what the tag saves.

**Alternatives considered.**
- **A tag of (revision, subject, request), and force a sweep at each expiry.** A 304 would hang on a timer, and on the sweep having run.
- **Add the next expiry to the tag.** It covers this case but not the next one; hashing the answer covers them all.

---

## ADR-0024: Signed bundles wait for part 3

**Status:** Accepted, 2026-11-02. It moves a planned item: the ROADMAP status table said signed bundles come with the AuthZEN API.

**Context.** The docs do call for signed bundles at this point: "Signed bundles come with it", and TM-13 lists tests for them. Their job is to let a Rust product check in process, offline, from data `tutelad` signed. Part 2a built the API and the cache that fails closed, and found what a bundle would still need. Each of the following is built in part 3.

**Decision.** Signed bundles are built in part 3, after token exchange and SSE, not in part 2a.

1. **Signing keys.** A bundle needs a signing key that every replica shares. ARCHITECTURE.md section 4 keeps signing keys encrypted with `tutela-vault` in the database, and TM-22 then makes `TUTELA_MASTER_KEY` required at start-up. Token exchange builds that store, with rotation and publication of the public keys. Doing it here would give two key stores, or one built for the smaller job and rebuilt for the bigger one. A key store is not the place to guess.
2. **Who may pull one.** A bundle is the whole tenant's assignments, groups and scope paths. Today any `sa` token of the tenant could fetch it, because no record says which app that token belongs to or what it may pull. That needs apps (`tutela apps create`) or at least a registered audience, and neither exists. Every other endpoint answers one question; this one hands out the data behind all of them, so it should not ship with the weakest rule in the service.
3. **Delivery.** The docs have bundles pushed over SSE, with a pull by ETag behind it. SSE is part 3. A pull alone has a revocation delay of the poll interval, which is a number nobody has chosen.
4. **No consumer needs it now.** `tutelad` replicas share one Postgres and read it directly, with the delay and the failure rules of ADR-0021, so "bundles for replicas" has no job. attache and texc-symphony stay on `v0.1.0`, and Node and Python call the API. An unused format would be fixed by guesswork, and CONTRACTS.md section 10 makes a wire format additive only from then on.

**What this does not give up.** A replica's cache follows the rules a bundle would: no going back, an age limit per action class, and a hard stop at `next_expiry`. The two-process tests in `crates/tutelad/tests/ha.rs` prove them for the cache: a stale limit and an expiry during an outage both fail closed.

**What part 3 must do.**
- Build bundles on the key store of token exchange, and only with a rule for who may pull one.
- `expires_at` is no later than `TenantBundle::next_expiry`, converted with `TenantBundle::read_at` as `tutelad::cache::deadline` does, so a clock that disagrees with the database cannot extend it.
- `tutela_pdp::TenantData` and its parts need `Deserialize`, and a loaded bundle goes through `Pdp::load`'s checks.
- The PDP side refuses a lower `rev` than it has seen, an expired bundle, a bad signature and a newer format (`PdpError::ExpiredBundle` and `UnsupportedBundle` exist for this, and are never returned today).
- Add the TM-13 tests for it, and a two-process test of a PDP that outlives `tutelad` until `expires_at`.

**Consequences.**
- The service gate keeps its "Bundle expiry" check open. The cache half is proved; the signed half is not built. The gate cannot pass before part 3.
- Until then a Rust product checks through the API, or in library mode. It cannot check offline against `tutelad`'s data.
- ARCHITECTURE.md's service-mode picture still shows bundles. It describes the end of Phase B, and the status table says what is built.

**Alternatives considered.**
- **Build them now with one key from an environment variable.** It is the cheapest honest version, and items 2 to 4 still hold. Part 3 would then migrate deployed PDPs off a key scheme nobody meant to keep.
- **Sign with a key per replica.** PDPs would have to trust every replica, and a replica restart would change the key.

---

## ADR-0025: Moves and links in `write_check`

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2b. It closes the "Moves stay refused" items of [ADR-0013](#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits) (item 13) and [ADR-0014](#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes) (item 8).

**Context.** PERMISSION-MODEL.md 9 and 10 give the rules in the blueprint's words: "owners and members", "owners of both projects only", "the source owner's approval", "looser". Tenant trees are not the blueprint's tree, and Tutela holds no field values and no tree below a resource, so each word needs a meaning that works on any tree and fails closed.

**Decision.**

1. **Crossed scopes.** The item leaves and enters the scopes below the part the two paths share. Boundary rules guard crossing, so a scope the item stays inside has no say.
2. **Rules.** The nearest scope on each side has the default `members`. A scope further out adds a rule only when it set one. `members` is `write` on the scope; `owners` is the admin key `approve_move` on it, so a tenant can build its own owner role. PERMISSION-MODEL.md 10.1 has the table.
3. **Across teams** means more than one crossed scope on a side. "Team" has no meaning in a tenant's tree, and this errs strict: a row moved between issues of two projects of one team counts as across teams.
4. **A scope's field values are not known**, so conditions on a scope's type count as false in these checks.
5. **Looser** means anyone gains anything: item level, a field or feature level, a custom action or an admin key. It uses the same functions as `check`. Below the item there are no field values, so a role's level is a range, and a change that cannot be ruled out counts. Lines that depend on this are `conditional`. The comparison is the first half of the impact report (`tutela-pdp`, module `impact`).
6. **A cap per role, for what sits below.** `write_check` does not know the tree below the item, and a principal assigned there is on neither path. Field rules above an assignment still cap it (7.1 step 5), so a cap that goes up for a role that holds any binding counts as a gain. The property test found this hole; `tm08_a_rule_left_behind_counts_for_whoever_sits_below_the_moved_scope` keeps it shut. It can flag a move that nobody below benefits from, which costs an approval and nothing else.
7. **Bounds.** 10,000 principals and 1,000,000 comparisons. Past a bound the move is looser and `complete` is `false`: stopping early never reads as "no change".
8. **Approval lives in the product.** A move waits for the owner of each scope it leaves, or of the old parent when it leaves none. The product collects the approval and asks again with `approved_by`. Tutela judges each name at this revision, and the person moving counts unless delegated. So there is no pending-move table, and an approver who lost the key since agreeing counts for nothing. Part 3 audits the moved scopes and who approved.
9. **Only a service may send `approved_by`**: it already speaks for its users. A person's own question is a UI hint (CONTRACTS.md 7.1).
10. **A link stays inside its org, and needs `read` on the target.** A deny for a target the person cannot read gives no detail. `links_from` is `any`, `team` or `none`, on every scope the link reaches into. A link changes no decision, because Tutela does not store links.
11. **`POST /v1/authz/write-check`** sits beside the permission map, because it is not an AuthZEN operation. gRPC carries the verdict as JSON text, as `SearchResource` does for a filter.
12. **New reason codes** `boundary_rule` and `approval_required`, both safe to show (CONTRACTS.md 10.2 allows new codes inside v1).

**Consequences.**
- `restricted_links` and `ai_reach` of `boundary_rule` are still not read. Showing a link as "Restricted" or dropping it is the product's work, and `ai_reach` stays as ADR-0013 item 6 has it.
- A type that stopped being a container can still hold rows (ADR-0013 item 1). The model's `parent` rules do not show them, so a move of such a resource compares its own row only. The `tm08` property test leaves those scopes out on purpose. Part 3's audit shows such moves; a fix needs the product to say what is below an item.
- `tutela_store::set_boundary` writes the rules. It trusts its caller on `manage_boundaries`; the admin API (part 3) checks it.
- Rate limits on the comparison are open (TM-23, Phase D).
- The property tests are `tm08_no_move_widens_past_the_rules` (it compares the verdict with what `check` says before and after, for every principal on everything below the moved item), `tm09_links_follow_their_rules` and `tm10_list_filter_equals_check_after_a_move`. A sweep of 4,000 seeds passed. 21 more planted bugs (M36 to M56 in `mutants.py`) are all caught; the first run left four alive, each now has its own test. The mutants are a script, not part of `make`; the tests that catch them are.

**Alternatives considered.**
- **Read the rule of the source and target only.** A team could not close its boundary with one rule.
- **Require a rule on every crossed scope.** A team that says nothing would stop its projects' owners from moving items, against the blueprint's "owners of both".
- **A pending-move table in Tutela.** One more store of state for what the product already holds, and an approval that can go stale inside it.
- **Enumerate the scopes below the moved item.** It needs a provider in `write_check`, covers only registered scopes, and rows are never registered.

---

## ADR-0026: A tenant owns its model versions

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2b. It changes [ADR-0014](#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes) item 7 for `tutelad`, and adds to [ADR-0015](#adr-0015-approval-tokens-for-tutela-apply-in-library-mode).

**Context.** `tutela_store::publish_manifest` replaces `app_manifest`, one row for the whole schema, and bumps every tenant. That is right for library mode, where one product owns the database. The ROADMAP notes planned to call it from the service, with a grant on `app_manifest`. But `tutelad` is multi-tenant, and a publish is made with a tenant's token. A tenant admin's publish would change every other tenant's permissions: the one thing the service exists to stop. Two-person publish "optional per tenant" would mean nothing, because a tenant with it off could change a tenant with it on. The docs lean the same way: PERMISSION-MODEL.md 4 says a tenant has one permission model, 17.8 prints a diff "against tenant", and the Phase B goal is that tenants change roles at runtime. The ROADMAP notes name this option.

**Decision.**

1. **A publish through `tutelad` changes one tenant.** It writes one row and bumps one revision, inside that tenant's row-level security, in one transaction. So it needs **no grant on `app_manifest`**, and `grant_service` gives none: this is the narrowest grant that works. `publish_manifest` stays out of every request, so its advisory lock and its lock per tenant never meet a request's transaction. **This departs from the ROADMAP note** that planned a grant.
2. **Versions live in `model_revision`**, the table PERMISSION-MODEL.md 18 already gives them, with new columns `version`, `source`, `origin` and `restores` (migration 4). `version` counts per tenant from 1. Migration 4 numbers the rows that exist; only the current manifest's text is known, so an older row cannot be restored.
3. **A tenant's active model** is its newest row when that row has `origin = tenant`; otherwise the app's manifest. So a tenant follows the app until it publishes for itself, and `tutela apply` in library mode keeps working unchanged.
4. **`publish_manifest` leaves a tenant with its own model alone.** It bumps the revision and writes no row. Otherwise an operator's apply could widen a tenant that narrowed its own model, with nobody in that tenant seeing the change. There is no way yet to go back to following the app.
5. **History is never rewritten.** A trigger refuses `UPDATE` and `DELETE` on `model_revision` for every role, the owner too. A rollback is a new version with the old text and `restores` set, and passes every check of a publish.
6. **What came before is kept.** A tenant made after the last app publish has no row, so its first publish records the manifest it ran on as version 1.
7. **Approval tokens stay** (ADR-0015), with a new optional `tid`. `tutelad` needs a token bound to this tenant: two tenants can share the same two manifests, and the approver looked at one of them. `tutela apply` refuses a token with a `tid`, which approves one tenant and not the app. The token code moved to `tutela_store::approval`, so the CLI and the service share it, and the service role may read `approver_key`. The keys stay the operator's, as ADR-0015 has them. `tutela approve` gets `--tenant`.
8. **Who may publish.** `manage_access` and `manage_fields`, on `org`, at **every org of the tenant**: a model covers them all, so the admin of one org must not change another's. Looking needs `read_audit` the same way. All of it on data that has just been checked. "Nobody grants what they do not hold" (PERMISSION-MODEL.md 15.1 step 1) needs no check per key here: a manifest's rules sit at the org root, and a change that gives anyone more needs an approval token anyway.
9. **The tag of a compiled model stays its digest**, and a replica keeps the last 32 models. The compile runs outside the lock, so one tenant's large model does not stop another's load.
10. **HTTP only for now.** These are admin calls, and `tutela.admin.v1` is part 3.

**Consequences.**
- Part 4's `tutela apply` calls `POST /v1/models/publish` per tenant, with `expected_version`.
- The routes take a token with the service's own audience, `tutela-authz`. THREAT-MODEL.md TM-01 and CONTRACTS.md 4.4 want `aud=tutela-admin` with step-up MFA for the Console. Nothing issues such a token before part 3, and the keys above are the stronger check. **Part 3 or 4 must add that audience to these routes.**
- A tenant has no way to read the model's text unless it holds `read_audit`. The permission map stays the UI's view.
- Each tenant row holds the whole text, so a large manifest costs its size once per tenant per app publish.

**Alternatives considered.**
- **Keep one model and let tenants call `publish_manifest`.** It is what the note planned. It lets one tenant change the others, and any test of that endpoint would have to call that a feature.
- **Keep one model, and let only an operator publish.** `tutelad` has no operator identity, and PERMISSION-MODEL.md 15 has tenants publish.
- **A new table for versions.** Two records of the same event.
- **Delete a tenant's model to go back to the app.** That rewrites history.

---

## ADR-0027: The impact report

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2b.

**Context.** PERMISSION-MODEL.md 15.1 step 3 asks for "12 users gain read on contract", from the tenant's real data. Tutela holds no rows and no field values, a tenant can have thousands of scopes and a group of everyone, and a report that stops early must not read as "no impact". The calculation also has to be the one a move uses (ADR-0025), so the two cannot disagree.

**Decision.**

1. **`tutela_pdp::model_impact(before, after, tenant, paths, limit)`** compares two evaluators that hold the same tenant data and two models. `tutelad` builds both for each report, on a blocking thread, from one fresh read; the live snapshots never change.
2. **Places.** A scope that holds something: an assignment, a field rule, a private flag or a boundary rule, an org root included. Anywhere else the answer is its parent's. Each place is asked for every type that can be there or below it in either model.
3. **Who.** Only principals that hold a changed role on the place's path, directly or through a group. Everyone else has the same deciding role in both models, so the same answer. What changed is worked out from the two models first: a type whose definition changed, or an all-roles field rule, counts for every role.
4. **The same comparison as a move.** A role's level is a range when field values are not known, and a change that cannot be ruled out counts and is marked `conditional`. A scope of a type that holds nothing by the model can still hold old rows (ADR-0013 item 1), so there every changed type counts, conditionally.
5. **One comparison per set of deciding assignments** at a place: without field values the answer depends on nothing else. A group of thousands costs one comparison and one step each.
6. **The bound** is a count of steps, `TUTELA_IMPACT_MAX_WORK` (default 2,000,000): a principal at a place, or a key compared. Not a timer, so the same data gives the same report, which two-person publish needs. A report that reaches it ends with `complete: false`; `no_impact` needs `complete`.
7. **The report names principals**, with the scopes, so its digest covers who and not only how many. A response caps lines and names; the digest does not.
8. **Who may ask:** what looking at the model needs (ADR-0026). The report shows other people's access.

**Consequences.**
- The property test `tm08_the_impact_report_holds_every_change` asks `check` under both models for every principal on every row, and finds each change in the report. `a_report_that_stops_early_never_says_no_impact` cuts the bound at random. Seven planted bugs (M57 to M64, without M61) are caught. M61 left out the org roots that hold nothing; it was an equivalent mutant, so that code went.
- A tenant of the benchmark's size with a changed role held by a group of everyone can reach the bound. Its report says so, and a widening change still needs its token. A cheaper walk for such groups is later work.
- The report counts what can change, not rows: a conditional line may hold for no row at all.

**Alternatives considered.**
- **Compare `check` on a sample of resources.** Tutela holds no rows, and a sample can miss.
- **A time limit.** Two runs on the same data could differ, and a proposal could go stale for nothing.
- **Report counts only.** A count can stay the same while the people change.

---

## ADR-0028: Explain and simulate need `read_audit` on the resource

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2b.

**Context.** PERMISSION-MODEL.md 15.1 gives the Console "explain" and "simulate". A plain check already returns `rule_ids` and `reason`; explain says what each id is, and walks the tree, so it shows other principals' assignments and the model. Simulate does the same for a model or assignments that are not there. The brief asks for a stronger right than a check, decided from the docs.

**Decision.**

1. **The right is `<type>:read_audit` on the resource**, held by the caller's own principal, with the same walk as any key. PERMISSION-MODEL.md 5.3 and 8 already say who reads the audit log: org admins for everything, scope owners for their own scope. Explain and simulate show what the audit log shows, so they take its key.
2. **No exception for a question about oneself**: it would show the reasons the permission map hides (CONTRACTS.md 6.2, "safe to show"). And a service is not trusted for this by being a service: its principal needs the key too.
3. **On data that has just been checked** (`ActionClass::Admin`), like every admin key. An agent never holds an admin key, and a delegated or an external token never passes one on.
4. **The path is checked against the store.** The path comes from the caller, and the key is walked on it. Without a check, a scope owner could put any resource under its scope and read who holds it. Each registered scope on the path, and the resource if it is one, must have the stored path. An unregistered entry has no assignment and no rule, so it cannot help.
5. **Simulate builds its own evaluators** from one fresh read: today's model and data, and the candidate's. Nothing is written, and no snapshot changes. A candidate is a manifest, a kept version, assignments to add (at most 100) and assignment ids to remove.
6. **One code path.** `Pdp::explain` runs `check` and adds the walks and the rules, so the decision in an explanation is the decision.

**Consequences.**
- The Console (part 4) calls these with the admin's own token. Until `aud=tutela-admin` exists, that is a `tutela-authz` token (ADR-0026).
- A product cannot explain a denial to its end user with these: it shows the permission map's reason, which keeps only codes safe to show.
- Part 3's audit log should record every explain and simulate, with who asked: they read other people's access.

**Alternatives considered.**
- **`manage_access` for simulate.** Simulate changes nothing; it reads.
- **Any service may explain.** A product backend would learn every assignment of its tenant through one token.
- **Trust the path, as a check does.** A check answers about the asked subject only; explain answers about everyone who holds the path.

---

## ADR-0029: Two-person publish

**Status:** Accepted, 2026-11-02. Built in Phase B, part 2b.

**Context.** PERMISSION-MODEL.md 15.1 step 4: two-person publish is optional per tenant, and the approver must be a different person from the author. The brief adds: not through a second session or a delegated token, and a proposal goes stale when the active model or the tenant's data moved in a way that changes its impact report. ADR-0026 made models per tenant, which is what makes "per tenant" mean something.

**Decision.**

1. **A proposal is stored, then approved.** `POST /v1/models/proposals` stores the text, the version it was compared against, the diff, the impact report and that report's digest, and the revision. Approval by another principal publishes it as a version in the same transaction as the proposal's new state. Rejecting closes it; its proposer may withdraw it.
2. **"The same person" is the token's `sub`.** A second session has the same `sub`. A delegated token never holds the right at all (ADR-0026 item 8), so a person cannot approve through an agent, nor can an agent approve. Checked in `tutelad`, again in `publish_proposal`, and a `CHECK` in the database refuses a published proposal whose approver is its proposer. A person with two principals (a user and a service account of their own) is two principals to Tutela; nothing records who holds a service account. Part 3's audit log shows both names.
3. **Staleness, decided here.** At approval, a proposal is stale when:
   - the active model is not the version it was compared against; or
   - its impact report, made again now on the same text, has another digest. The digest covers every principal of every line, so a new holder of a changed role makes it stale, and a change the report does not see does not; or
   - its report was cut short at its bound and the tenant's revision moved at all: a partial report cannot tell what it did not reach.
   A stale proposal is closed as `stale`, and the caller proposes again. Between the check and the write the tenant can move, so the write names the revision it checked, and the approval checks again, at most three times.
4. **The setting** lives in a tenant table, `tenant_setting`. Turning it on takes one principal who may change the model. **Turning it off takes two**: the first asks, a second agrees. Otherwise one person could turn it off, publish alone and turn it on again.
5. **While it is on, a direct publish is refused** by the store, in the publish's own transaction, so a setting turned on during a publish is never skipped.
6. **A widening change still needs its approval token** at approval (ADR-0015, ADR-0026). The approver's principal and the token's key both go into `approvers`; the proposer is the `author`.
7. **A proposal bumps no revision.** It changes nobody's access, and the evaluator never reads it.

**Consequences.**
- The same principal cannot do both, but an org admin can still turn the setting off with a second admin's agreement, which part 3's audit log and events must make visible.
- An open proposal holds its text. They are listed newest first, at most 100; there is no expiry yet.
- A tenant whose report always reaches the bound will see proposals go stale often. Raising `TUTELA_IMPACT_MAX_WORK` or a cheaper report (ADR-0027) helps.

**Alternatives considered.**
- **Compare `sid` or `jti`.** A second session would count as another person.
- **Stale on any revision change.** Every unrelated assignment would undo a review.
- **Stale only when the model moved.** A new holder of the changed role would get access nobody reviewed.
- **Off by one person.** It undoes the setting in one call.

---

## ADR-0030: `tutelad`'s own issuer: signing keys, the JWKS, and paths without a token

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3a. It builds what [ADR-0024](#adr-0024-signed-bundles-wait-for-part-3) item 1 left to token exchange, and it **changes [ADR-0018](#adr-0018-tutelad-the-stack-the-two-ports-and-the-config) item 3**: one path of the API port needs no token.

**Context.** Token exchange, admin tokens, delegated tokens and later signed bundles all need `tutelad` to sign. TM-15 wants the rotation timing and a `kid` deny-list to work from the first token, and a `Signer` trait from the start. TM-22 wants `TUTELA_MASTER_KEY` and `TUTELA_KEY_PEPPER` required. ADR-0018 left two problems: every request to the API port needs a token, but a verifier must fetch the JWKS before it has one; and the trust file is static, so a tenant made at runtime could never be trusted.

**Decision.**

1. **`TUTELA_ISSUER` names the service's own issuer.** It is required, and it must not be an issuer of the trust file. `http` is allowed only on loopback in dev mode, as for any issuer.
2. **The own issuer is trusted for every tenant of the directory.** `TrustList::insert_directory` (new, in `tutela-contracts`) trusts an issuer for any tenant id; the tenant is then checked against the directory when a request enters it (`tutela_store::enter`, ADR-0019), so a tenant id the directory holds under another issuer is refused (TM-05). A tenant made at runtime is trusted with no change to the trust file. Such an issuer has no sole tenant, so it can never stand in for an external issuer. Products do not use this: they name their tenants.
3. **One key set for the deployment, ES256.** Per-tenant keys are Phase C (TM-15). ES256 is the default of CONTRACTS.md 4.1. Publishing an RS256 key for OIDC Discovery waits for the login server (Phase C).
4. **Storage.** `tutela.signing_key` (migration 6) holds the public JWK and the private key as a `tutela-vault` envelope, sealed for the purpose `signing_key` and the key's `kid`. A private key is never stored, returned or logged in plain text. The table is not tenant data, so it has no row-level security; the service role may read, add and update rows, never delete them. A trigger keeps a key's identity and its denial, for every role.
5. **Times are the database's.** A key is in the JWKS from when it is made until `retire_at`. It signs from `signs_from`. The key that signs is the latest whose time has come.
6. **The store API** (`tutela_store::signing_keys`), for `tutelad` and for part 4's `tutela keys rotate`:
   - `rotate_signing_key(tx, vault, times)`: the next key is published now and signs at `times.lead`; the old one leaves the JWKS at `times.keep` after the switch. `tutelad::keys::rotation_times` gives `lead` = 2 × `TUTELA_JWKS_CACHE_SECS` (default 300) and `keep` = 600 s + 60 s (CONTRACTS.md 10.4). A rotation that already waits is returned, not made twice.
   - `deny_signing_key(tx, vault, kid)`: the emergency. The key leaves the JWKS at once and stays on the deny-list. If nothing may sign after it, a waiting next key signs at once, or a new key is made.
   - `ensure_signing_key` makes a first key under an advisory lock, so replicas that start together make one. `rewrap_signing_keys` moves keys sealed under `TUTELA_MASTER_KEY_PREVIOUS` to the current master key.
7. **Replicas.** A `KeyRing` opens the keys in memory and reads the table every `TUTELA_KEY_REFRESH_SECS` (default 10). A denied `kid` goes on the verifier's deny-list at once, and a change in the published keys makes the verifier forget its cached copy of the JWKS (`Verifier::forget_jwks`, new in `tutela-sdk`): the forced refetch TM-15 asks for. The verifier reads the own JWKS from memory, never over the network.
8. **Signing goes through a `Signer` trait**, so a KMS or HSM backend (Phase C) changes no call site.
9. **`GET /.well-known/jwks.json` needs no token.** A verifier must read it before it can check one. Only exact paths in `api::PUBLIC_PATHS` are open; an unknown path still needs a token and says nothing without one. The answer is cacheable for `TUTELA_JWKS_CACHE_SECS`.
10. **TM-22.** `TUTELA_MASTER_KEY`, `TUTELA_KEY_PEPPER` and `TUTELA_ISSUER` are required. Start-up fails and names the variable, never its value. The pepper must be at least 32 bytes as base64 or hex, and must not be the master key (CONTRACTS.md 5.4). Nothing uses the pepper until API keys (part 4); it is required now so that no deployment runs without one.

**Consequences.**
- Rotation is started by an operator. There is no timer that rotates by itself yet; `tutela keys rotate` (part 4) calls the store API.
- Across replicas, a denial takes effect within `TUTELA_KEY_REFRESH_SECS`; on the replica that read it, at once. Products learn of it from their own JWKS refresh, or from the `kid` deny-list over SSE when part 3b builds it.
- A replica that cannot read the table keeps the keys in hand. With none at all, what needs a signature answers 503.
- Each replica keeps a tenant's snapshot in memory for every tenant that reaches it (ADR-0021). Tenants are now bounded by the directory, not the trust file; an eviction rule is still open.
- Part 3b's audit log should record key operations: a rotation, a denial, a first key, a re-wrap.

**Alternatives considered.**
- **A key from an environment variable.** Every replica would need the same secret, rotation would be a redeploy, and there would be no pre-publication.
- **A key per replica.** Every verifier would have to trust every replica, and a restart would change the key (ADR-0024).
- **Reload the verifier's trust list from the directory.** A tenant made between reloads would be refused, and the verifier would need a database.
- **Serve the JWKS on the ops port.** It is kept out of the public load balancer, where products and SDKs must reach it.

---

## ADR-0031: Token exchange: the tenant from the trust list, a person from (iss, sub)

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3a. It builds the token-exchange service of [ADR-0006](#adr-0006-delegated-agent-tokens-in-phase-b-not-optional) and ROADMAP Phase B, and closes the gap of [ADR-0021](#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease) item 9: an external token has no principal, so it cannot ask.

**Context.** A person signs in at Keycloak (or any issuer of the trust file marked `external`). Its token names the realm's subject, no Tutela principal, no tenant, no `epoch` and no `rev` (CONTRACTS.md 4.6). Tutela keys accounts by `(iss, sub)`, never by e-mail (ADR-0008, TM-04), and a tenant comes from the trust list, never from a request (CONTRACTS.md 1.6, TM-05). `tutelad` now signs tokens (ADR-0030). Apps and client credentials do not exist yet (part 4).

**Decision.**

1. **`POST /oauth2/token`, RFC 8693.** A form body (RFC 6749 3.2): `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type` (an access token or a JWT; an ID token never), and one `audience`. `resource` is refused: name the service. It needs no bearer token, like the JWKS (ADR-0030 item 9). The metadata is at `/.well-known/oauth-authorization-server` (RFC 8414).
2. **Which subject tokens.**
   - A token of an **external issuer** of the trust file, addressed to `tutelad`'s own audience (`TUTELA_AUDIENCE`, `tutela-authz`).
   - A token of **`tutelad`'s own issuer**, of any audience it issues, to get one for another audience.
   - Nothing else. A token of another Tutela-format issuer of the trust file is refused: its tenant is not this service's to issue for.
3. **The tenant comes from the trust list.** An external issuer maps to exactly one tenant id. The exchanged token's tenant key is `(TUTELA_ISSUER, tid)`, and the directory must hold that tenant under `TUTELA_ISSUER`. A `tid` claim in the external token, or a parameter in the request, is never read. A tenant that the directory holds under the external issuer itself (the Phase A way) is not exchanged.
4. **Just-in-time provisioning.** `tutela_store::provision_user` finds the person by the upstream `(iss, sub)` in `tutela.upstream_account` (migration 7), and makes a new `user:usr_<uuidv7>` the first time. Never by e-mail: two realms with the same subject or the same e-mail are two people. Making a person bumps no revision: with no assignment it holds nothing.
5. **The issued token** (`typ: at+jwt`, ES256, CONTRACTS.md 4.2):
   - `iss` = `TUTELA_ISSUER`, `sub` = the principal, `aud` = the one registered audience asked for, `azp` = the subject token's (required), `jti` new;
   - `exp` = the earlier of now + `TUTELA_TOKEN_TTL_SECS` (default 300, 60 to 600) and the subject token's `exp`: it never outlives it;
   - `epoch` = the principal's now, `rev` = the tenant's revision now;
   - `sid`: a new `ses_<uuidv7>` per exchange of an external token, kept when an own token is exchanged again;
   - `amr`: the external token's, or `["ext"]` when it has none: the issuer authenticated the person and did not say how. `ext` is never a step-up method;
   - `acr`: copied, for step-up checks (CONTRACTS.md 4.4);
   - `scope`: as asked, but only narrower than the subject token's when it has one;
   - no `org` (membership is not modeled yet), no e-mail or name.
   Every issued token passes the claim checks a verifier runs before it is signed.
6. **Once per external token.** `tutela_store::note_exchange` records the issuer and the SHA-256 of the external token's `jti` until it expires; a second exchange is refused, and a token with no `jti` too. A client that needs several audiences exchanges its Tutela token again: a token of `tutelad` may be exchanged again for another audience, and the new token never outlives it. This is the answer to "a replayed subject token" while there is no client authentication: a stolen realm token wins at most a race.
7. **One transaction.** The note, the provisioning and the revision are read in the tenant's transaction, which commits only after the new token is signed. A 503 uses nothing up.
8. **Revocation.** A principal has an `epoch` and a disabled flag in `tutela.principal`. `revoke_sessions` and `set_disabled` raise the epoch and the tenant revision in one transaction; enabling again keeps the raised epoch. On the API port, after the token check, a token whose `epoch` is below its subject's, or whose subject or an actor is disabled, is refused with 401, and the log names the step `epoch`. Each replica keeps a book per tenant of the principals that refuse something, read again after `TUTELA_REVISION_CHECK_MS`, with the snapshot's failure rules (ADR-0021): stale until `TUTELA_MAX_AGE_READ_SECS`, then 503. An exchange of an own token reads the epoch from the database. gRPC health is not held: it needs no database and says nothing about anyone.
9. **The audiences** are the service's own and the trust file's `[[audience]]` entries (`name`, `delegation_aware`). The trust file is operator config with no secret, like the issuers. `tutela-admin` is reserved for the admin audience (CONTRACTS.md 4.4).
10. **Errors** are RFC 6749 5.2 JSON with `Cache-Control: no-store`: `invalid_request`, `unsupported_grant_type`, `invalid_target` (an audience nobody registered), `invalid_scope`, and `invalid_grant` for **every** problem with the subject token, with one text: the log names the check, never the token. 503 `temporarily_unavailable` when the database or the keys fail.
11. **Metrics and logs.** `tutelad_token_operations_total{operation, outcome}`: the kind asked for (`access`) and `issued` or the error code. The log names the issued token's `jti`, never a token, a subject or an e-mail.

**Consequences.**
- After an exchange the check API accepts the token where it refused the external one, and a tenant made at runtime is reached through `TUTELA_ISSUER` (ADR-0030).
- **No client authentication yet.** Apps and client credentials come with part 4 (`tutela apps create`); the token endpoint should then authenticate the client and bind `azp` to it.
- A product that verifies `tutelad`'s tokens trusts `TUTELA_ISSUER` for its tenants (MIGRATION-0.2.md).
- Revocation reaches a product's SDK through events: `tutela.session.revoked.v1` and `tutela.principal.disabled.v1` are part 3b. Until then a product waits for the token to expire (at most `TUTELA_TOKEN_TTL_SECS` plus the skew).
- Part 3b's audit log records each issued token (its `jti`, the principal, the audience, the kind), each refusal with its reason, each provisioning, and each revocation and disabling.
- Keycloak-shaped tokens are tested against a local signer, not a real Keycloak (no image could be pulled); a test against a real Keycloak is [#87](https://github.com/f8fvwgzc/tutela/issues/87).

**Alternatives considered.**
- **Keep the external tenant key `(realm, tid)`.** The tenant would change its key when its people switch to exchanged tokens, and a runtime tenant could never be reached.
- **Exchange an external token once per audience.** A stolen token could still be spent for every other audience.
- **Read the tenant from an `organization` claim.** A tenant-controlled IdP could name another tenant (TM-04, TM-05); the trust list is the operator's.
- **Check the epoch per request in the database.** One more query on every check; the book follows the snapshot's lease instead.

---

## ADR-0032: Admin tokens: a person steps up, a pipeline keeps its service token

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3a. It does what [ADR-0026](#adr-0026-a-tenant-owns-its-model-versions) and [ADR-0028](#adr-0028-explain-and-simulate-need-read_audit-on-the-resource) left to part 3: the model routes, explain and simulate take `aud=tutela-admin`.

**Context.** CONTRACTS.md 4.4, TM-01 and TM-06 want the Console and the embeddable admin components to use their own audience, `tutela-admin`, with a 5-minute life and step-up MFA (`acr`), never accepted by a product API. Until now the model routes, explain and simulate took a `tutela-authz` token with admin keys at every org (or `read_audit` on the resource). `tutela apply` in a pipeline (part 4) calls `POST /v1/models/publish` with a service account, which cannot do MFA. The ROADMAP asks to decide whether `tutela-authz` tokens keep working there.

**Decision.**

1. **Token exchange issues `aud=tutela-admin`** (CONTRACTS.md 4.8) only:
   - for a person (`user:`), never for a service, a key or an agent, and never with an actor;
   - when the subject token's `acr` is one of `TUTELA_ADMIN_ACR`, a comma-separated list the operator sets (CONTRACTS.md 4.4: "the values the deployment configures as MFA"). With the variable unset, no admin token is issued at all: there is no default that could be mistaken for MFA. `amr` is not read: `["ext"]` says nothing, and RFC 8176 values are not the deployment's policy;
   - for the earlier of 300 s and `TUTELA_TOKEN_TTL_SECS`, and never past the subject token's `exp`.
   A subject token without step-up gets `invalid_grant` with the description "step-up authentication is required", the one refusal that says why: the Console must know to ask for MFA.
2. **The admin routes** are `/v1/models` and everything under it, `POST /v1/authz/explain` and `POST /v1/authz/simulate`. On them:
   - a **person** must present an admin token: `aud=tutela-admin`, and its `acr` in `TUTELA_ADMIN_ACR`, checked again at the route;
   - a **service** (`sa`, `key`) keeps its `tutela-authz` token. **This is the answer for `tutela apply` in a pipeline**: a service account cannot step up, and the checks that matter for it stay: admin keys at every org of the tenant on data that has just been checked (ADR-0026 item 8), an approval token for any widening change (ADR-0015), and two-person publish where the tenant has it (ADR-0029). An admin token for a service is refused;
   - an agent, a delegated token and an external token are refused, as before.
3. **Every other route refuses an admin token** (TM-01): the main verifier's audience is `tutela-authz`, so an admin token fails its audience step there with 401. Only the admin routes run a second verifier, for `tutela-admin`, which trusts the trust file's Tutela-format issuers and the own issuer, never an external issuer, and never accepts a delegated token. The audience a token names picks the verifier; each verifier still checks everything.
4. **gRPC** has no admin verifier. Its `Explain` and `Simulate` are for services; a person's `tutela-authz` token is refused there.
5. **The lifetime limit** of 300 s for `tutela-admin` is the verifier's (`tutela-contracts`), so a 6-minute admin token is refused wherever it is presented.

**Consequences.**
- The Console (part 4) exchanges the person's Keycloak token, after step-up, for an admin token, and calls the admin routes with it. It needs `TUTELA_ADMIN_ACR` set to what Keycloak's step-up gives.
- A person's `tutela-authz` token that worked on these routes before now gets 403. No release had it.
- A service account that holds the admin keys at every org can still publish without MFA. That is the pipeline's job; part 3b's audit log must show who published and with which approval.
- Part 3c's `tutela.admin.v1` (gRPC) needs the same rule: either an admin verifier on its own audience, or services only.

**Alternatives considered.**
- **`tutela-admin` only.** A pipeline would need a person's MFA for every deploy, or a way for a service to fake it.
- **Both audiences for everyone.** Step-up would mean nothing: a person would send the `tutela-authz` token.
- **A third audience for pipelines.** The service account already is the difference, and the admin keys and the approval token are the stronger checks.
- **Check `amr` contains `mfa`.** Each IdP writes `amr` its own way; the deployment's `acr` policy is what CONTRACTS.md 4.4 names.

---

## ADR-0033: Delegated agent tokens from token exchange

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3a. It builds [ADR-0006](#adr-0006-delegated-agent-tokens-in-phase-b-not-optional) on the token exchange of [ADR-0031](#adr-0031-token-exchange-the-tenant-from-the-trust-list-a-person-from-iss-sub), and turns delegated tokens on in `tutelad`'s verifier.

**Context.** ADR-0006 fixed the token (`typ: agent+jwt`, `sub` = the person, `act` = the agent, `cap`, the run, one audience, 60 to 120 s). CONTRACTS.md 4.5 and TM-02 add: only for `delegation_aware` audiences; at most 4 actors; every actor an agent; at issue time the agent exists, is enabled and is in the same tenant; disabling the person or the agent stops the tokens. TM-03 asks that a delegated token never decides more than the person AND the agent. attache runs agents as workloads named `spiffe://<trust domain>/ns/<namespace>/svc/<service>` (CONTRACTS.md 1.4). The PDP's overlap and `may_ask`'s full chain exist already (ADR-0013, ADR-0021).

**Decision.**

1. **The request** is a token exchange (CONTRACTS.md 4.8) with:
   - `subject_token`: the person. An external issuer's token, an access token of `tutelad` whose subject is a person, or a delegated token of `tutelad` (the next hop, or one more actor);
   - `actor_token` and `actor_token_type`: the agent that acts now. Not needed to exchange a delegated token for the next hop;
   - `audience`: one audience registered `delegation_aware`. `tutelad`'s own audience is: the check API evaluates the chain. `tutela-admin` never is;
   - `cap`: attache's capability snapshot, a JSON object of at most 4096 bytes, copied and never read or widened; `run_id` (required for a first delegation, kept for a hop) and `node_id`.
2. **The actor** is one of:
   - an access token (`at+jwt`) of an issuer of the trust list whose `sub` is an `agent`, addressed to `tutelad`'s own audience, for the person's tenant id (attache as a Tutela-format issuer, or `tutelad` itself); or
   - a token of an issuer marked `workloads = true` in the trust file (attache's embassy: a JWT-SVID, `typ: JWT`), naming a SPIFFE id on attache's path `/ns/<namespace>/svc/<service>`. It stands for the agent registered for that workload (`tutela_store::register_agent` with a workload; a `/sa/...` path is refused). Such an issuer's token is never a person.

   Either way the agent must be registered in the person's tenant and enabled, and an agent token's `epoch` must be current. A person never acts.
3. **The chain.** The new actor comes first; a delegated subject's chain nests inside it (RFC 8693 4.1). At most 4 actors: a fifth is `invalid_grant`. Exchanging a delegated token checks the person and every actor again.
4. **The token** (`typ: agent+jwt`, ES256): `sub` the person, `act` the chain, `cap`, `run_id`, `node_id`, `aud`, `azp` the actor token's (the client that acts, for example `attache-sidecar`) or else the subject's, `epoch` the person's, `rev`, and the person's `sid`, `amr` and `acr`. `exp` is the earliest of now + `TUTELA_DELEGATED_TTL_SECS` (default 90, 60 to 120), the person's token and the agent's token. No `cnf`: the token endpoint sees no client certificate yet. No `org`.
5. **The verifier.** `verifier_config` turns delegation on, and the service's own audience is `delegation_aware`. The admin verifier never accepts a delegated token, and `models::principal` refuses one, so a delegated principal never reads or publishes a model, approves a proposal, explains or simulates (ADR-0028, ADR-0029, ADR-0032).
6. **Revocation.** Disabling the agent or the person refuses the next exchange at once, and the issued delegated tokens on `tutelad`'s API within `TUTELA_REVISION_CHECK_MS` (ADR-0031 item 8 checks the person's epoch and whether any actor is disabled). Raising the person's epoch does the same. Raising an agent's epoch refuses its old agent tokens at the next exchange; a delegated token carries no epoch of its agents, so the ones already issued end with their life (at most 120 s). To stop them at once, disable the agent. Enabling again never brings an old token back.
7. **The overlap is the PDP's.** A delegated token asks about its own person with its whole chain (`may_ask`), and the evaluator takes the overlap of the person and every agent (PERMISSION-MODEL.md 6.4). attache's `cap` limits apply inside attache.

**Consequences.**
- Agents must be registered in their tenant. attache gets the API to do it in part 3c (`tutela.admin.v1`); until then an operator calls `tutela_store::register_agent`.
- A product verifying delegated tokens turns delegation on in `tutela-sdk` and is registered `delegation_aware` in `tutelad`'s trust file. It learns of a disabled agent through `tutela.principal.disabled.v1` (part 3b); until then, at most the token's life (120 s) plus the skew.
- mTLS binding (`cnf`, RFC 8705) needs a client certificate at the token endpoint; `tutelad` sits behind a proxy that ends TLS. Open.
- Part 3b's audit log records each delegated token issued (the person, the chain, the audience, `run_id`, `node_id`, the `jti`) and each refusal with its reason.

**Alternatives considered.**
- **Trust attache to name any agent with a service token.** attache would then speak for agents it does not run; the actor token proves the agent, and the registry check proves it belongs to the tenant.
- **Map a workload by its SPIFFE id alone, without registration.** A workload of another tenant on the same trust domain could act; registration ties one workload to one agent of one tenant.
- **Copy `cap` only from the actor token.** Tutela never reads `cap`; the request is where attache puts its snapshot, as CONTRACTS.md 4.5 says.
- **Let a delegated token outlive the person's token.** Revoking the person's session would not end the agent's work within the token's life.

---

## ADR-0034: The local audit log: one chain per tenant, written with the change

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3b. It builds the local log of CONTRACTS.md 9.4 and TM-20, and **changes CONTRACTS.md 9.3** on when `seq` is given (below).

**Context.** CONTRACTS.md 9.4 wants each audit record in the transaction of its change, a local hash chain, and UPDATE and DELETE refused. 9.3 wants a producer signature and a `seq` per (service, tenant) with no gap, and says the outbox relay gives `seq` when it ships a record. The ROADMAP notes for part 3 and 3b list what each operation must record: many of those values (a token's `jti`, its audience and `exp`, an `act` chain, a model version, the approvers) have no field in audit.v1. Some operations change nothing (a refused publish, an explain, a refused exchange), so they have no transaction to join. Signing keys belong to the deployment, not to a tenant, and audit.v1 always names a tenant.

**Decision.**

1. **One chain per tenant**, in `tutela.audit_record` (migration 8), under the tenant's row-level security. A record is stored as its *body*: the RFC 8785 canonical JSON of the audit.v1 record with `seq` and without `signature` (`AuditDraft::body`, the bytes the producer signs in 9.3). `hash = SHA-256("tutela-audit-chain-v1" LF prev_hash LF body)`, hex; the first `prev_hash` is 64 zeros. `prev_hash` and `hash` are storage columns, as 9.4 says.
2. **`seq` is the chain position**, given when the record is written, not when it is shipped. It counts per (`tutelad`, tenant) from 1 with no gap and is never reused, which is what 9.3 asks of it; the chain gives it for free, so a relay never has to. **This changes 9.3**, which had the relay give it.
3. **One writer at a time per tenant.** `audit_head` holds the chain's last link; a writer locks its row, appends, and moves it, in the caller's transaction. So two writers in one tenant make one chain, in commit order, and a rolled-back change leaves no record and no gap. A writer appends **last**, just before the commit, so it never waits for another lock while it holds this one.
4. **Append-only, by the database.** A trigger refuses UPDATE, DELETE and TRUNCATE of a record for every role, the owner too; the head only moves forward. `grant_service` gives the service role `SELECT, INSERT` on records and no DELETE on the head, and `check_isolation` (readiness) fails when the role could change the log or a trigger is switched off.
5. **The verifier** (`tutela_store::verify_audit_chain`) walks the chain from the first record and reports the first broken link: a missing record (`gap`), a record whose hash does not fit its body (`hash`), a link that does not fit the record before (`prev_hash`), a body that is not its row's (`body`), or a head past the last record (`head`).
6. **`details`, a new optional field of audit.v1** (CONTRACTS.md 10.2 allows it): a JSON object of ids, numbers and codes, at most 8 KiB, with no `null` and no fraction, so it has one canonical form. It holds what the notes ask for that has no field: a token's `jti`, `aud`, `azp`, `exp` and `act` chain, a version and its approvers, a move verdict. Never a token, a secret, an e-mail or a field value.
7. **What has no transaction gets its own.** A refused publish, an impact report, explain, simulate and a write check write their record in a transaction of their own, and the answer leaves only after it commits: if the record cannot be written, the answer is 503. A refused token exchange is refused whatever happens; its record is best effort, logged and counted (`tutelad_audit_records{operation="token",outcome="error"}`).
8. **A refused exchange is recorded only once its tenant is known**, that is after the subject token verified. A request refused before that names no tenant, so it is logged and counted only: an unauthenticated caller cannot grow any tenant's log.
9. **`tutelad` itself is a reserved principal**, `sa:sa_00000000-0000-7000-8000-000000000000` (`tutelad::audit::SYSTEM`): the actor of the expiry sweep, of signing-key operations, and of a refused exchange before any principal is known. No token is issued for it, and the API refuses one that names it.
10. **The deployment has its own chain**, for its signing keys, under the tenant id `ten_00000000-0000-7000-8000-000000000000`, which is never in the directory, so no token can enter it. A record's tenant key is `(TUTELA_ISSUER, that id)`. `KeyRing::rotate` and `KeyRing::deny` (for part 4's `tutela keys rotate`) write the record in the key's own transaction; start-up records a first key and a re-wrap.
11. **Who calls the store writes the record.** The store calls that change tenant data take no actor, so `tutelad` records the operations it runs. `revoke_sessions`, `set_disabled`, `register_agent`, `set_boundary` and `move_scope` have no route in `tutelad` yet; part 3c's admin routes record them with who asked. A product in library mode records its own calls with `tutela_store::append_audit` in its transaction.

**Consequences.**
- Every audited operation in one tenant waits for the one before it to commit. Token exchange and the model routes take a few milliseconds each, so this holds hundreds of operations per second per tenant; a tenant that needs more would need a chain per (tenant, shard).
- A database owner who switches off the triggers can rewrite a chain from the edit to the end. The copy in attache's evidence ledger, in another trust zone, is what shows that (TM-20); readiness shows a switched-off trigger.
- Records are not signed until they are forwarded (9.3). The local chain protects them until then.
- Erasure of personal data in records (TM-20, an open item) is still open: `upstream_sub` and actor ids are in bodies that the chain covers.

**Alternatives considered.**
- **A chainer that links records after commit.** No lock on the write path, but a record is unchained for a while, and a crash leaves records the verifier must treat as pending.
- **Postgres advisory locks instead of a head row.** One lock space for the whole server, and nothing to read back for the verifier's head check.
- **Sign every record at write time.** Every replica would need the producer key on the write path, and the store could not record a call by itself.
- **Fold the extra values into `reason`.** `reason` is short text for people; ids and numbers belong in a field a ledger can read.

---

## ADR-0035: The outbox: events numbered per tenant, in commit order

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3b. It builds the transactional outbox of CONTRACTS.md 8.5, and adds one event type.

**Context.** CONTRACTS.md 8.5 wants each event row in the transaction of its change, at least once with a stable id, and order per subject. Webhooks and SSE read the same rows. A reader that keeps "the last event I saw" must never skip an event whose transaction commits after a later one, and a resumed SSE stream (`Last-Event-ID`) must find its place. Parts 3a and 2b left the list of what to emit: a publish, a data change, a session revocation and a disabling with the new epoch.

**Decision.**

1. **`tutela.event`** (migration 9) holds a tenant's events under its row-level security: the id (a UUIDv7, the idempotency key), the type, the subject, the org, the `data` object as text and the time. The CloudEvents envelope is made when the event is sent, with `source = tutela://<host of TUTELA_ISSUER>/<tid>`, so the store needs no host.
2. **Each event gets the tenant's next number, `seq`**, from a counter on the tenant's revision row (`tenant_rev.event_seq`), which the writer keeps locked until it commits. Numbers are then given in commit order with no gap, a rolled-back change uses none, and a reader that walks `seq` never skips an event that commits late: the next number does not exist until it does. A write that bumps the revision holds that lock already; a provisioning, which bumps nothing, now waits for a write in progress in its tenant.
3. **What is emitted, by whom.** In the store, in the caller's transaction: `tutela.permissions.changed.v1 {rev}` by every data write (assignments, groups, field rules, scopes, boundary rules, moves, deletes) and by the expiry sweep; `tutela.model.published.v1 {rev}` by `publish_tenant_model`, `publish_proposal`, and `publish_manifest` for each tenant that follows the app (a tenant with its own model gets `permissions.changed` for its new revision); `tutela.user.created.v1` when `provision_user` makes a person; `tutela.session.revoked.v1 {principal, epoch}` by `revoke_sessions` of a user; `tutela.principal.disabled.v1 {principal, epoch}` and, for a user, `tutela.user.disabled.v1` by `set_disabled(true)`; and **`tutela.principal.enabled.v1 {principal, epoch}`** by `set_disabled(false)`.
4. **`tutela.principal.enabled.v1` is new** (CONTRACTS.md 10.2 allows a new type). Without it an SDK that marked a principal disabled from an event could never learn it was enabled again, and would refuse its new tokens until it restarted.
5. **Not emitted.** `revoke_sessions` of an agent: only users have sessions; to stop an agent's delegated tokens at once, disable it (ADR-0033 item 6). `register_agent` and `tutela.membership.changed.v1`: there is no event type for the first, and org membership is not modeled yet. `tutela.key.*`: API keys come with part 4. The org lifecycle events and `tutela.user.deleted.v1` are variants of `tutela_store::OutboxEvent` already; part 3c emits each with one line, `tutela_store::emit(tx, tenant, OutboxEvent::OrgCreated { org })`.
6. **This departs from a ROADMAP note** for part 3b, "Provisioning bumps no revision and needs no event": CONTRACTS.md 8.3 lists `tutela.user.created.v1` "also by just-in-time provisioning", and the contract is the source of truth. It still bumps no revision.
7. **Events never change** (a trigger), and old ones are pruned (`tutela_store::prune_events`); the service role gets `SELECT, INSERT, DELETE` on them.
8. **Library mode** writes the same events, because the store writes them. Nothing delivers them there; a product that does not read them prunes them.

**Consequences.**
- A tenant's events are totally ordered, which is stronger than "order per subject": a receiver that processes them in `seq` order keeps per-subject order for free.
- Writers of one tenant were already serialized by the revision row; provisioning joins them. Two people of one tenant signing in at once for the first time wait for each other, for one short transaction.
- A gap in `seq` is impossible by construction, so a reader that sees one has lost rows to pruning.

**Alternatives considered.**
- **Order by transaction id (`pg_current_xact_id()`) and read only below the snapshot's `xmin`.** No new lock, but `xmin` is the whole server's: any long transaction in any database of the server, the operator's own included, holds back every tenant's events. Tried and dropped: on a shared test server events were hidden for seconds.
- **A table of its own for the counter.** A second lock to order against the revision row, and a deadlock to avoid by convention.
- **Order by the event's UUIDv7.** Time of writing is not time of commit; a reader would skip an event of a transaction that commits late.

---

## ADR-0036: Webhooks: delivered from the outbox, registered by part 3c

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3b. It fixes the retry schedule CONTRACTS.md 8.5 and open point 6 left to Phase B.

**Context.** CONTRACTS.md 8.4 and 8.5 fix the signature (Standard Webhooks), at least once, order per subject, retries for at least 24 hours, a dead-letter state, 15 s per attempt, no redirects, and `tutela-safenet` at registration and before each send. TM-18 and TM-19 add the rest. Two replicas must never send one event to one webhook at once. Who may register a webhook is not decided, and ADR-0032 has a rule for admin routes.

**Decision.**

1. **Store** (migration 10): `tutela.webhook` (URL, types, the secret and during a rotation the previous one, each sealed by `tutela-vault` for the purpose `webhook_secret` and the context `<tid>/<id>/<version>`, and `after_seq`, how far the tenant's events were handed to it) and `tutela.webhook_delivery` (one row per event per webhook), both under the tenant's row-level security. A secret is `whsec_<base64 of 32 random bytes>` and is returned once, at registration or rotation.
2. **The relay** (`tutelad::webhooks::Relay`) runs on every replica every `TUTELA_WEBHOOK_POLL_MS` (default 1000; `0` turns it off on a replica). For each tenant of the directory, as the expiry sweep does, it hands new events to each webhook of their type, prunes, and **claims** due deliveries in one short transaction, then sends them with no database connection held, then records each end in a transaction of its own.
3. **A claim is a lease** (`claimed_by`, `claimed_until`, 60 s, longer than one attempt), taken with `FOR UPDATE SKIP LOCKED`. Another replica skips a held delivery, so two never send one event to one webhook at once; a replica that dies mid-send leaves its lease to run out, and the next replica sends again: at least once. An end is recorded only by the replica that holds the lease.
4. **Order per subject:** a delivery is claimed only when no earlier delivery of the same subject to the same webhook is pending. A dead one no longer holds the next back.
5. **Retries:** the delay before try n+1 is 5 s × 2^(n−1), at most 1 hour, with up to a fifth taken off at random (jitter only shortens). A delivery not delivered 24 hours after its first try is **dead**: kept with its last status and an error code (`status`, `timeout`, `not_public`, `url`, `connect`, …), never a body or a URL, and sent again by hand with `tutela_store::webhooks::redeliver` (for the Console). That is about 30 tries.
6. **Sending:** a `POST` of the CloudEvent (`application/cloudevents+json`) with `webhook-id` (the event id), `webhook-timestamp` and `webhook-signature` (`v1,<base64 HMAC-SHA256 of id.timestamp.body>`, one per secret, space-separated, during a rotation), through `tutela-safenet`: https only, every resolved address public, checked again at each send, no redirects, 15 s, a 64 KiB answer limit. A 2xx is delivered. `traceparent` is never sent to a webhook (CONTRACTS.md 8.1: outside hosts). Signatures match the Standard Webhooks test vector.
7. **Rotation with an overlap:** `rotate_webhook_secret(…, overlap)` keeps the old secret signing until the overlap ends; then only the new one signs.
8. **Registration is checked twice:** `tutelad::webhooks::register` runs `tutela_safenet::Client::check` (new: the URL rules and the DNS answer, every address, without a request) before the store keeps the URL, and each send checks again.
9. **Who registers, and through which route: part 3c.** A webhook receives every event of its tenant and is a standing outbound channel to a URL a tenant names, so registering one is an admin action under ADR-0032: a person with a stepped-up admin token or a service with its `tutela-authz` token, holding `read_audit` **and** `manage_access` at every org of the tenant (the keys to look at and to change the whole tenant's access), on data that has just been checked. The route belongs with `tutela.admin.v1` (and its HTTP admin routes), so **part 3c builds it** on `tutelad::webhooks::register`, `rotate_webhook_secret`, `disable_webhook`, `webhooks`, `deliveries` and `redeliver`. Part 3b builds the store and delivery, and tests them through the store.
10. **Retention:** events and ended deliveries are kept `TUTELA_EVENT_RETENTION_SECS` (default 7 days, at least 2), and an event a pending delivery still needs is never pruned. A delivery whose event is gone is dead (`pruned`).
11. **Metrics:** `tutelad_webhook_deliveries{result}`: `delivered`, `retry`, `dead`, `blocked` (not a public address).

**Consequences.**
- Each replica visits every tenant of the directory once per tick, like the expiry sweep: a small query per tenant. Thousands of tenants would want a list of tenants with webhooks; that is an index the directory does not have yet.
- A receiver gets each event at least once and must dedupe by `webhook-id`.
- A tenant whose receiver is down for more than 24 hours loses nothing: the deliveries are dead and kept, and the Console (part 4) or part 3c's API sends them again.

**Alternatives considered.**
- **Hold a row lock while sending.** A database connection per open request, for up to 15 s each.
- **Make delivery rows in the change's transaction.** The change would read every webhook of its tenant and grow with them; handing events out afterwards keeps the change's transaction small.
- **Registration now, on an HTTP route of its own.** It would fix the admin rule for webhooks before `tutela.admin.v1` fixes it for everything else.

---

## ADR-0037: The event stream: services only, one feed per tenant, bounded

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3b. It builds CONTRACTS.md 8.6, the push of the `kid` deny-list TM-15 asks for (CONTRACTS.md open point 1), and the push of revisions.

**Context.** CONTRACTS.md 8.6 fixes the message format, `Last-Event-ID`, `reset`, the tenant scope and the `types` filter. It does not say who may listen, how a deny-list or a revision reaches an SDK, or how a slow client is kept from holding memory or a database connection. ADR-0030 left the `kid` deny-list over SSE to this part; ADR-0021 and ADR-0031 left a push that lets a cache stop waiting for its lease.

**Decision.**

1. **Only a service listens:** an access token of the service's own audience whose subject is an `sa` or a `key` of the tenant. A stream names every principal of the tenant that was revoked or disabled, so it is a question about other principals, as `search/subject` is (ADR-0022 item 6). A person, an agent, a delegated token and an external token get 403; an admin token is refused by the verifier (401). A browser listens through its product's backend, which holds the service token (8.6).
2. **Messages.** Each event: `id:` its id, `event:` its type, `data:` the CloudEvent on one line. Three control messages, with no `id:` so they never move a client's `Last-Event-ID`:
   - `event: denied_kids`, `data: {"iss", "jwks_uri", "kids"}`: the whole `kid` deny-list of `tutelad`'s own issuer (`KeyRing::denied()`), first and again whenever it changes. A receiver puts every `kid` on its deny-list and forgets the cached JWKS at `jwks_uri` (`Verifier::forget_jwks`): the forced refetch of TM-15. The whole list each time, so a missed message changes nothing. **This answers CONTRACTS.md open point 1** for SSE; it is not an event type, because signing keys belong to the deployment, not to a tenant, and an event per tenant per denial would add nothing.
   - `event: rev`, `data: {"rev"}`: the tenant's revision, first and whenever it moves, the expiry sweep included. A cache that sees a newer one reloads at once instead of at the end of its lease.
   - `event: reset`, `data: {}`: the client's `Last-Event-ID` is not one this tenant still has (pruned, or never its own); reload. It also ends a stream that fell behind (item 5).
3. **Resume** from `Last-Event-ID`: the stream reads what came after it from the outbox, a page at a time, then follows the feed. Because events are numbered with no gap (ADR-0035), a stream that sees a jump in numbers knows it missed something and reads the gap from the outbox first.
4. **One feed per tenant per replica.** The first stream of a tenant starts a feed that reads the outbox, the revision and the deny-list every `TUTELA_EVENTS_POLL_MS` (default 500) and hands them to every stream of the tenant through a bounded channel; the feed stops with its last stream. So the database load grows with the active tenants, not with the streams, and no stream holds a connection.
5. **Bounds.** At most `TUTELA_SSE_MAX_STREAMS` streams per replica (default 1000; then 503). A stream lasts at most `TUTELA_SSE_MAX_SECS` (default 900) and never past its token's `exp`; the client reconnects with a fresh token and its `Last-Event-ID`. A stream that falls more than `TUTELA_SSE_BUFFER` messages (default 256) behind gets `reset` and ends, so a slow or stuck client holds a bounded buffer. Every 5 s a stream checks that its token's principal was not revoked or disabled, and ends if it was. A shutdown ends every stream first, so clients move to another replica while requests drain.
6. **The SDK side** (`tutela_sdk::events`): `apply_event` moves a verifier's `EpochBook` on `session.revoked`, `principal.disabled` and the new `principal.enabled` (ADR-0035); `apply_denied_kids` applies a `denied_kids` message. A product's revocation delay is then the time to receive the event, as TM-13 says.
7. **Metrics:** `tutelad_event_streams{result}` (`opened`, `forbidden`, `invalid`, `full`) and `tutelad_event_streams_open`.

**Consequences.**
- Revocation reaches a product's SDK within one poll (half a second) instead of the token's life.
- `tutelad`'s own replicas still use their lease (ADR-0021); a replica that wants the push can listen to another replica's stream later. The stream is there; the lease stays the safety net.
- A deny-list change made on another replica reaches a stream within `TUTELA_KEY_REFRESH_SECS` plus one poll.

**Alternatives considered.**
- **Let a person listen to events about itself.** A filter per principal on every message; nothing needs it yet.
- **A `tutela.signing_key.revoked.v1` event in every tenant's outbox.** A deployment-wide fact copied into every tenant, and webhooks would carry it to outside receivers that have no use for it.
- **A query per stream per poll.** The load would grow with streams; one feed per tenant keeps it per tenant.
- **`LISTEN`/`NOTIFY`** to wake feeds. Lower delay, but a connection outside the pool per replica, and the poll is still needed when a notification is lost (ADR-0021).

---

## ADR-0038: Signed bundles: a service with `read_audit` everywhere, its own `typ`, and no skew at `exp`

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3b. It does what [ADR-0024](#adr-0024-signed-bundles-wait-for-part-3) left to part 3, and closes the "bundle expiry" check of the service gate.

**Context.** ADR-0024 waited for the key store (ADR-0030), a rule for who may pull a whole tenant, and SSE (ADR-0037). It asked for `expires_at` no later than `TenantBundle::next_expiry` measured as `cache::deadline` does, a loaded bundle through `Pdp::load`'s checks, the PDP side refusing a lower revision, an expired bundle, a bad signature and a newer format, the TM-13 tests, and a PDP that outlives `tutelad` until `expires_at`. The part 3a notes asked to decide whether bundles get their own `typ`, and to keep the bundle's `kid` on the deny-list rules.

**Decision.**

1. **`GET /v1/authz/bundle`** on the API port, behind the token check. It answers a JWS (`application/jwt`, `Cache-Control: no-store`).
2. **Who:** a service (`sa`, `key`) with a token of `tutelad`'s own audience that holds `read_audit` at **every** org of its tenant, on data that has just been checked (`models::admin`, `ActionClass::Admin`). A bundle is everyone's access in the tenant, as the impact report is (ADR-0027 item 8), so it takes the key that looks at the whole tenant's model (ADR-0026 item 8). A person, an agent, a delegated and an external token get 403: a person never needs a whole tenant offline. Every pull writes an audit record first (`tutela_bundle:pull`, ADR-0034). This is stronger than "any service of the tenant", the weak rule ADR-0024 item 2 refused; apps (part 4) may narrow it further to a registered audience.
3. **Its own `typ`: `tutela-bundle+jwt`.** No token verifier accepts it (CONTRACTS.md 4.1 accepts only `at+jwt` and `agent+jwt`), and the bundle verifier accepts nothing else, so a bundle can never pass as a credential, nor a token as a bundle.
4. **Claims:** `iss` (`tutelad`'s own issuer, the signer), `tid`, `tenant_iss` (the issuer of the tenant key the data is kept under), `rev`, `iat`, `exp`, `jti`, `format: 1`, `model {digest, source}` (the tenant's **active** model, ADR-0026, with the SHA-256 of its text), `data` (`TenantData` in its new JSON form) and `paths` (every registered scope and its ancestors). Signed with `KeyRing::signer()`, ES256, the key the JWKS names.
5. **`exp`** is the earlier of now + `TUTELA_BUNDLE_TTL_SECS` (default 300, 1 to 3600) and the first assignment in the bundle that expires: `next_expiry − read_at` on the database's clock, added to this clock's time **before** the read, rounded down (`bundle::expires_at`). A bundle whose data expires now is not issued (503).
6. **The verifier** (`tutela_sdk::Verifier::verify_bundle`) reads the bundle like a token of a Tutela-format issuer: the header (no forbidden header, the `alg` the issuer allows), the issuer on the trust list (never an external issuer), the `kid` not on the deny-list, the key from the same JWKS cache and named by its thumbprint, the signature; then the format (a newer one is `Unsupported`, never guessed), `(iss, tid)` allowed by the trust list, and `exp` **with no clock skew**: a bundle is refused from the second it ends.
7. **The PDP side** (`tutela_sdk::bundle::OfflinePdp`): `load` refuses a lower revision than the one it has (a replayed older bundle), another tenant's bundle, an expired one, and a model whose text is not its digest or does not compile; the data goes through `Pdp::load`'s checks. `check` answers `PdpError::ExpiredBundle` from `exp` on, also with `tutelad` gone: never an allow from an expired bundle. `paths()` serves `list_filter`.
8. **A denied `kid`.** A product learns of it from SSE `denied_kids` (ADR-0037) and `apply_denied_kids` puts it on the verifier's deny-list: every bundle signed with it is refused at once, whatever its `exp`. A replica of `tutelad` signs with the next key at once (ADR-0030).
9. **`TenantData` and its parts get a JSON form** in `tutela-pdp` (serde): subjects and members as principal strings or `group:<key>`, boundary rules as a list of `{"scope", "rule"}`, unknown fields refused. Reading only parses; `Pdp::load` still checks.
10. **Metrics:** `tutelad_bundles{result}` (`issued`, `forbidden`, `unavailable`).

**Consequences.**
- **The service gate's "bundle expiry" check passes**: a replica's cache (ADR-0021, `tests/ha.rs`) and a product's offline PDP (`tests/bundle.rs`) both stop at their limit and at the first expiry, and fail closed. The offline test stops the in-process `tutelad` and keeps checking from the bundle until `exp`; it is not a second process.
- A bundle is as large as its tenant (about the size of a whole-tenant read). Pull it on a timer below `exp`, or when SSE says `rev` moved.
- Rotating the signing key keeps old bundles valid until the old key leaves the JWKS (`retire_at`); a denial ends them at once.

**Alternatives considered.**
- **Any service of the tenant.** The weakest rule in the service for its strongest read (ADR-0024 item 2).
- **`typ: at+jwt`** or a plain `JWT`. A bundle could then be presented as a token to a verifier that reads `typ` loosely.
- **A clock skew on `exp`**, as tokens have. A bundle carries grants, not identity; a minute past `exp` is a minute of an expired grant.
- **Push whole bundles over SSE.** One tenant's data per message per stream; the stream says `rev` moved, and the product pulls.

---

## ADR-0039: Forwarding to attache's evidence ledger: signed, acknowledged, resumable

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3b. It builds the forwarding of CONTRACTS.md 9.3 and 9.4 and TM-20, against attache's Append API as attache documents it (`docs/operations.md` "Forwarding audit records to the ledger", `docs/design/evidence-ledger.md` decision 13, `docs/api/openapi.yaml` `/ledger/append`).

**Context.** TM-20's honest limit is that someone with full database and key access can rebuild the local chain; a copy in attache's ledger, in another trust zone, shows it. attache already serves `POST /api/v1/ledger/append`: up to 500 audit.v1 records per request, a `200` only when all are durable, a key `(service, id)` that dedupes a retry and refuses a changed payload, a gap in `seq` reported and kept, and every record checked against the producer's Ed25519 keys named in its `ledger.producers`. The caller is an `auth.tokens` entry (an `att_` bearer token) and sends `X-Agentsc-CSRF: 1`. attache reads records with `tutela-contracts` v0.1.0, which ignores fields it does not know (`details`).

**Decision.**

1. **Off unless configured.** `TUTELA_LEDGER_URL` (the Append API's URL) turns it on; then `TUTELA_LEDGER_TOKEN` (the `att_` token) and `TUTELA_AUDIT_KEY` (the producer's Ed25519 seed, 32 bytes in base64) are required, and start-up fails naming the missing one. Both are secrets: never logged, `Debug` redacted.
2. **One producer key for the deployment**, from the environment, the same on every replica, like attache's own `--ledger-key-file`. Its public key (standard base64) and `key_id` (the RFC 7638 thumbprint of its OKP JWK, as attache computes it) are logged at start, for attache's `ledger.producers[].keys`. Rotation: give attache both keys, then change `TUTELA_AUDIT_KEY`. Sealing it in the database like the signing keys (ADR-0030) is part 4's, with `tutela keys rotate`.
3. **What is signed** is the record's body as the local chain keeps it (ADR-0034): the canonical JSON with `seq` and without `signature`. `signature = {key_id, value}`, pure Ed25519, base64url. So the bytes the ledger verifies are the bytes the local chain hashed.
4. **Every replica forwards**, every 2 s: for each chain (each tenant of the directory, and the deployment's own), it claims the chain for a 60 s lease (`tutela.audit_forward`, migration 11), reads up to 500 records past `shipped_seq`, signs them, sends them through `tutela-safenet`, and only on a `200` that acknowledges every record moves `shipped_seq`. Anything else leaves it; the next tick sends the same batch, and the ledger dedupes. Two replicas never send one chain at once.
5. **The ledger's host may be private.** It is the operator's own URL, not a tenant's, so its host is allowed through `tutela-safenet`'s allow-list for private hosts; https only outside dev mode, no redirects.
6. **Never in the way of a local write.** Records are written in their change's transaction whatever the ledger does; forwarding reads them afterwards, and a ledger that is down only makes them wait (`tutelad_ledger_records{result="refused"}` counts the batches it did not take).

**Consequences.**
- attache's chains for Tutela are `forwarded:tutelad:<tenant>:<day>`; a gap there means a record lost between the two, which this design cannot cause short of a deleted local record (which the local verifier also finds).
- Nothing in attache had to change. The test runs against a stand-in of the Append API that checks what attache's code checks; a test against a running attache is not part of `make` (no image could be pulled).
- Records of the deployment's chain name the reserved tenant `ten_00000000-0000-7000-8000-000000000000`; attache keeps them in a chain of their own.

**Alternatives considered.**
- **Ship through the OpenTelemetry Collector.** It may drop data (CONTRACTS.md 9.4).
- **Mark shipped on send.** A record lost on the way would never be sent again.
- **One relay with a lease for the whole deployment** (CONTRACTS.md 9.3 had one give `seq`). The chain gives `seq` now (ADR-0034), so per-chain claims are enough, and every replica shares the work.

---

## ADR-0040: `tutela.admin.v1`: one code path, the admin token rule on gRPC, and keys at every org

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3c ([#106](https://github.com/f8fvwgzc/tutela/issues/106)). It gives the model routes of [ADR-0026](#adr-0026-a-tenant-owns-its-model-versions) their gRPC methods, builds the agent management [ADR-0033](#adr-0033-delegated-agent-tokens-from-token-exchange) left to this part, the `set_boundary` route [ADR-0025](#adr-0025-moves-and-links-in-write_check) asked for, and `PutResourceTypes` (PERMISSION-MODEL.md 15.2, INTEGRATION.md onto-intelli step 6). It **adds to [ADR-0032](#adr-0032-admin-tokens-a-person-steps-up-a-pipeline-keeps-its-service-token) item 4**: gRPC now has the admin token check, for `tutela.admin.v1` only.

**Context.** attache creates, quarantines and enables its agents through `tutela.admin.v1` (INTEGRATION.md attache step 5, TM-02). onto-intelli pushes its types with `PutResourceTypes`, and "imported changes become a proposal that a tenant admin publishes; they are never published automatically" (PERMISSION-MODEL.md 15.2). ADR-0032 left gRPC with no admin verifier and asked part 3c to give `tutela.admin.v1` the same rule as the HTTP admin routes, or make it services-only. The store calls (`register_agent`, `set_disabled`, `revoke_sessions`, `set_boundary`, `move_scope`) trust their caller and take no actor (ADR-0034 item 11).

**Decision.**

1. **One service, `tutela.admin.v1.Admin`, and HTTP routes under `/v1/admin/`** beside the model routes under `/v1/models`. Each operation is one function in `tutelad::admin` or `tutelad::models`; `admin::http` and `admin::grpc` only adapt, as the decision APIs do (ADR-0021). A gRPC method answers typed messages where the answer is small, and the route's JSON as text (`result_json`) where it is a report: a model version, an impact report, a proposal.
2. **The admin token rule on gRPC too.** A request whose path starts with `/tutela.admin.v1.Admin/` goes through the admin token check of the HTTP admin routes (`api::admin_identity`): a person sends an admin token (`aud=tutela-admin`, `acr` a step-up value), a service (`sa`, `key`) its `tutela-authz` token. An agent, a delegated token and an external token never pass. So the Console and a pipeline use either protocol with the same token. `tutela.authz.v1`'s `Explain` and `Simulate` stay services-only (ADR-0032 item 4): they live in the check API's service, which has one verifier.
3. **Who may ask:** the admin keys of MANIFEST.md 6, on data that has just been checked (`ActionClass::Admin`):
   - an agent (register, list, read, disable, enable, revoke): `manage_agents` at **every org** of the tenant. An agent is a principal of the whole tenant, not of one org, so the admin of one org must not reach it;
   - a person (read, disable, enable, revoke sessions): `manage_access` at every org, for the same reason;
   - a scope's move and link rules: `<type>:manage_boundaries` on the scope, at the path the store holds for it (item 6);
   - `PutResourceTypes`: what proposing a model needs, `manage_access` and `manage_fields` at every org (ADR-0026 item 8).
4. **Agents.** `POST /v1/admin/agents` makes the id, `agent:agt_<uuidv7>` (CONTRACTS.md 1.2: Tutela makes its ids; attache keeps the mapping to its own). A workload, when given, is on attache's path `/ns/<namespace>/svc/<service>`; one workload names one agent per tenant (409 `exists`), and `GET /v1/admin/agents?workload=` finds it again, so attache can recover from a lost answer. Registering bumps no revision and emits no event (ADR-0035 item 5): a new agent holds nothing.
5. **A principal of another tenant is not there.** An agent must be registered in the caller's tenant to be read or changed: 404 otherwise. A person may have no row yet (a person of a trusted Tutela-format issuer, CONTRACTS.md 1.6) and is then enabled at epoch 0; disabling one writes a row in the caller's tenant only, under its row-level security, and changes nothing anywhere else.
6. **Principals go in the body, never in the URL.** A principal id is personal data (CONTRACTS.md 9.5), and 7.1 keeps personal data out of URLs, so the routes that name one are `POST` with `{"principal"}`.
7. **`PUT /v1/admin/boundaries`** checks the key on the scope at its stored path: a caller cannot place a scope under one it owns to set its rules. An org has no rules (400); an unregistered scope is 404. The store bumps the revision and emits `tutela.permissions.changed.v1` in the same transaction.
8. **`move_scope` gets no route.** A move is the product's write after its `write_check` (CONTRACTS.md 6.7, ADR-0025 item 8). A route that moved a registered scope would skip the boundary rules the move verdict applies. In service mode a product also has no route yet to register scopes, assign roles or manage groups; that API, with a move that runs the verdict and `move_scope` in one transaction, is [#107](https://github.com/f8fvwgzc/tutela/issues/107).
9. **`PutResourceTypes` stores a proposal.** `POST /v1/admin/resource-types {types, expected_version?}` merges the pushed types into the tenant's active model and stores the result through the same code as `POST /v1/models/proposals`, with `origin: resource_types` in its audit record. Only additions are taken: a new type, and new fields, actions, features and parents of a type. A push that would change or remove what the model has is 409 `not_additive`; one that adds nothing is 409 `no_change`. Nothing is published until another principal approves (ADR-0029), with an approval token when it widens; a new confidential or secret field holds nothing for anyone (MANIFEST.md 4). The merged text is the active model parsed and written again: it keeps every value, not the comments. When the tenant followed the app's manifest, approving the proposal gives it its own model (ADR-0026 item 3).
10. **Audit** (ADR-0034). Every change writes its record in its transaction, with who asked and what moved (the principal, its new epoch, the revision; the scope and the rule). Every refusal for want of a key writes a `denied` record in a transaction of its own before the answer (`admin::guard`), so an admin call is never refused unseen. Reads of agents and of a principal's state are not recorded, as the model routes' reads are not: ADR-0034's list is of reads that show other people's access.
11. **Errors** are the problem documents of CONTRACTS.md 7.1, with `not_found` (404), `exists`, `not_additive`, `no_change` and `version_conflict` (409). gRPC maps 400 to `INVALID_ARGUMENT`, 401 `UNAUTHENTICATED`, 403 `PERMISSION_DENIED`, 404 `NOT_FOUND`, 409 `ABORTED`, everything else `UNAVAILABLE`, with `<code>: <text>` as the message.
12. **Metrics:** `tutelad_admin_operations_total{operation, outcome}` (`ok`, `forbidden`, `refused`, `not_found`, `conflict`, `invalid`, `error`). The model methods count in `tutelad_model_operations_total` over gRPC as over HTTP.

**Consequences.**
- attache registers, quarantines and enables agents with its service account's `tutela-authz` token; that account needs `manage_agents` at every org of the tenant (an Owner-like role at each org, given when the org is made). MIGRATION-0.2.md says how.
- A refused admin call grows its own tenant's audit log by one record. Only a verified principal of that tenant can cause it, as for a refused write check.
- The Console can use HTTP or gRPC with the person's admin token.
- Service-mode scopes, bindings and groups are open ([#107](https://github.com/f8fvwgzc/tutela/issues/107)).

**Alternatives considered.**
- **`tutela.admin.v1` for services only.** attache and onto-intelli are services, but the Console is a person, and two rules for one API invite drift. The admin verifier already existed for HTTP.
- **Principals in the URL path** (`/v1/admin/principals/{principal}`). Shorter, but it puts personal data in URLs and access logs.
- **Keys on one org for agents.** An agent may be assigned roles in every org of its tenant; one org's admin could quarantine another org's agents.
- **`PutResourceTypes` publishing at once.** PERMISSION-MODEL.md 15.2 refuses it.
- **Keep the comments of the active model.** It needs a TOML editor that keeps the document; the tree has `toml` only, and the model's meaning is what the proposal's diff and impact report show.

---

## ADR-0041: The lifecycle of tenants, orgs and people: the operator makes a tenant, soft-delete with a grace, a purge that keeps the audit chain

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3c ([#108](https://github.com/f8fvwgzc/tutela/issues/108)). It builds the soft-delete that [ADR-0014](#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes) and [ADR-0019](#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked) left to the admin API, emits the org lifecycle events and `tutela.user.deleted.v1` that [ADR-0035](#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order) item 5 prepared, and **changes [ADR-0019](#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked) item 4**: the service role may now update the lifecycle columns of the tenant it entered, and the directory has row-level security for updates.

**Context.** AGENTS.md, ARCHITECTURE.md and TM-14: "Tenants are soft-deleted with a grace period. Never `DROP SCHEMA ... CASCADE`." CONTRACTS.md 8.3 has `tutela.org.created|updated|deleted.v1` (`deleted` with `purge_after`) and `tutela.user.deleted.v1`. The ROADMAP notes for part 3c: a deleted tenant keeps its audit chain, append-only and never deleted, and stops its feeds and relays when it leaves the directory. A tenant is above any one tenant, so who may make one is not a tenant permission (TM-08: "Operator settings ... are not tenant permissions"), and `tutelad` has no operator identity (ADR-0026). `grant_service` gave no write on `tenant` at all.

**Decision.**

1. **The operator makes a tenant, not the API.** `tutelad tenant create` runs as the owner role (`TUTELA_OWNER_DATABASE_URL`, like `tutelad migrate`) under `TUTELA_ISSUER`. It makes the tenant, its first org and the first owners: each `--admin <principal>` (a `user:` or `sa:` principal) and each `--admin-upstream <iss>=<sub>` (a person found or made by the upstream `(iss, sub)` of an external issuer, as token exchange does) gets the seeded `owner` role at the first org. Without a first owner nobody could ever administer the tenant, because every admin call needs keys at every org. The tenant chain gets a `tutela_tenant:create` record and the deployment chain one too, both by `tutelad` itself (ADR-0034 item 9). Part 4's Helm bootstrap job and CLI call the same function (`tutelad::lifecycle::create_tenant`). `tutelad tenant restore <tid>` undoes a soft delete before the purge. No route of the API makes or restores a tenant, and the service role has no `INSERT` on the directory.
2. **A tenant's own admin names it and soft-deletes it** (`PATCH /v1/admin/tenant`, `DELETE /v1/admin/tenant`), holding **every admin key at every org** (the tenant's owner). The service role gets `UPDATE` on the directory's lifecycle columns only (`name`, `deleted_at`, `purge_after`, `purged_at`), and the directory gets row-level security for updates: a runtime role updates only the row of the tenant its transaction entered. Reading stays open (a `SELECT` policy of `true`), as ADR-0019 has it. Not forced, so the owner, the operator, makes and restores tenants.
3. **A soft-deleted tenant stops answering at once.** `tutela_store::enter` refuses it (`UnknownTenant`, 403 `unknown_tenant`) unless the transaction entered it before the delete, so the deleting transaction can still write its own audit record last. So every route, token exchange and the revocation book refuse it; an event stream ends at its next revocation check (5 s); `tutela_store::tenants` leaves it out, so the expiry sweep, the webhook relay and the ledger forwarder no longer visit it. **Its audit chain stays**, readable with `tutela_store::audit_records` and verifiable with `verify_audit_chain`, which enter a kept tenant. A tenant's deletion is recorded last in its own chain and in the deployment's chain; records written to its chain after the forwarder's last tick are not forwarded, and the deployment chain, which is, holds the deletion.
4. **The grace** is `TUTELA_PURGE_GRACE_SECS` (default 2,592,000: 30 days; at least 3,600). After `purge_after`, the purge (on the expiry sweep's timer, every replica, one purge per tenant by a row lock on its directory row) deletes every row of the tenant's tables: assignments, groups, rules, scopes, orgs, principals and their upstream accounts, exchanged tokens, model versions and proposals, settings, events, webhooks and deliveries. It keeps the audit chain (`audit_record`, `audit_head`, `audit_forward`), the revision row and the directory row with `purged_at`, so a tenant id is never reused. Model versions are history that is never rewritten (ADR-0026 item 5); their trigger now lets a delete through only for a tenant whose grace has passed. The audit tables refuse it whatever happens (ADR-0034 item 4).
5. **No event for a tenant's deletion.** Its outbox stops with it: nothing would deliver one. Receivers learn that its tokens and its API answer nothing; the operator tells the products, as the operator made the tenant.
6. **Orgs.** `POST /v1/admin/orgs` makes an org and gives the caller the seeded `owner` role there, in one transaction: otherwise the new org would have no admin, and every admin call that needs keys at every org would fail for everyone. So making an org takes every admin key at every org, and the caller gives no more than it holds. `PATCH /v1/admin/orgs/{org}` renames it (`org:manage_access` on that org). `DELETE /v1/admin/orgs/{org}` soft-deletes it (every admin key at every org; never the last org: 409 `last_org`): the load leaves out the org, every registered scope under it and their assignments, field rules and boundary rules at once, in the same revision, so every check on a resource there is denied (`tenant_mismatch`) and a list fails closed. `POST /v1/admin/orgs/{org}/restore` brings it back before the purge. The purge of an org deletes its scopes, assignments and rules and keeps its row; groups stay, because a group of the org may be assigned in another one. Events: `tutela.org.created.v1`, `tutela.org.updated.v1` (a rename or a restore), `tutela.org.deleted.v1 {org, purge_after}`, each in the change's transaction. An org id is in a URL path: it names a container, not a person.
7. **Deleting a person** (`POST /v1/admin/users/delete {principal}`, `manage_access` at every org): its assignments and group memberships go, in one revision; its link to its upstream account goes; the principal stays as a disabled row with a raised epoch, so no token of it works again and it can never be enabled (400). Events: `tutela.user.deleted.v1` and `tutela.principal.disabled.v1` with the new epoch, so an SDK that feeds its `EpochBook` from events drops the person's tokens. If the same upstream account signs in again, just-in-time provisioning makes a **new** principal that holds nothing: the upstream IdP decides who may sign in, and the old principal stays deleted.
8. **Personal data inside audit bodies stays open** (TM-20). Purging a tenant or deleting a person leaves its records as they were: an actor id, an `upstream_sub` in a provisioning record. The chain hashes every body, so erasing one would break it; crypto-shredding with a key per subject, or a redacted copy with the hashes kept, is a decision for later (THREAT-MODEL.md section 7). The docs have not decided it, and this part does not.

**Consequences.**
- A tenant is offboarded in two steps: its owner (or the operator) soft-deletes it, and the purge runs after the grace. Restoring takes the operator.
- The directory's row-level security is for updates only; `check_isolation` now fails when the runtime role may insert or delete tenants, or when the directory has no row-level security.
- A purge is one transaction per tenant; a very large tenant may need it in batches later.
- An org's purge and a tenant's purge bump no revision anyone can see (a purged tenant answers nothing; an org's data was already out of every decision), but an org's purge still bumps its tenant's revision, as every data change must (ADR-0021).

**Alternatives considered.**
- **Tenants made through the API by a deployment admin.** It needs an identity above every tenant, which `tutelad` does not have and TM-08 keeps out of tenant roles. The Helm bootstrap job (part 4) runs with the owner's credentials anyway.
- **A tenant table of its own for the lifecycle, under forced RLS.** `enter` must refuse a deleted tenant before it has entered it, so the state must be readable without a tenant set: in the directory.
- **Delete a tenant's rows at once and keep a backup.** No grace, and a mistake is final.
- **Keep relaying a deleted tenant's events until the purge.** Its receivers would hear of changes nobody can act on, and the relay would need a second notion of "in the directory".
- **Erase personal data from audit bodies at purge.** It breaks the chain that TM-20 relies on, and the ledger copy keeps the original anyway.

---

## ADR-0042: The audit log's leftovers: a chain check on a timer, the caller's trace in each record

**Status:** Accepted, 2026-11-02. Built in Phase B, part 3c ([#113](https://github.com/f8fvwgzc/tutela/issues/113)). It closes what the ROADMAP notes for part 3c left open from part 3b, and the two-process test [ADR-0024](#adr-0024-signed-bundles-wait-for-part-3) asked for.

**Context.** [ADR-0034](#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change) built the verifier, but nothing ran it: a chain rewritten behind the service's back stayed unseen until someone looked. CONTRACTS.md 9.1 has `trace_id`, `span_id`, `request_id` and `ip`, and part 3b left them empty. `tutelad` logs the `traceparent` trace id and a request id per request (ADR-0018 item 8), and exports no spans of its own (OTLP is open). ADR-0038's offline test stopped the in-process service, not a separate process.

**Decision.**

1. **A chain check on a timer.** Every replica walks every chain every `TUTELA_AUDIT_VERIFY_SECS` (default 3600; `0` off): each tenant of the directory and the deployment's own chain, with `verify_audit_chain`. A broken link is an error log (the tenant id, the `seq`, what is wrong there; never a body) and counts in `tutelad_audit_chain_checks_total{result}` (`intact`, `broken`, `failed`); `tutelad_audit_chains_broken` is the number found by the last pass, so an alert is "above 0". A soft-deleted tenant's chain is not walked: no request can enter it, and the deployment's chain records its deletion and purge (ADR-0041). Replicas check on their own; the check only reads.
2. **The ids of the request in each record.** `telemetry::observe` keeps the request's context for the handler's task: the request id (the caller's `x-request-id`, else a new one), and the trace id and parent span id of a well-formed `traceparent`. `audit::Record::build` fills `request_id`, `trace_id` and `span_id` from it, over HTTP and gRPC. `span_id` is **the caller's span**, the one that made the request: `tutelad` has no span id of its own until it exports traces. A background job (the sweep, the purge, key work) has no request, so its records have none.
3. **`ip` stays empty.** The docs call it personal data (CONTRACTS.md 9.5) and decide neither how to read it behind a proxy nor how long to keep it; recording it waits for that decision.
4. **The two-process bundle test.** `tests/ha.rs` runs the shipped binary, pulls a signed bundle over HTTP, stops the process (its port answers nothing), and a product's `OfflinePdp` on the wall clock answers from the bundle until `exp`, then `ExpiredBundle`. This is what ADR-0024 asked for.

**Consequences.**
- Walking a chain reads it whole: a tenant with millions of records makes each pass long. An incremental check (from the last verified `seq` and hash) is later work.
- A record of a request names the caller's trace, so it can be found from the caller's trace view.

**Alternatives considered.**
- **Check only the newest records.** Cheaper, but a rewrite of an old record is the attack the chain exists to show.
- **A span id of `tutelad`'s own, made up per request.** It would name a span nobody can see until OTLP export exists.

---

## ADR-0043: Scopes, assignments and groups over the admin API, checked on the data they change

**Status:** Accepted, 2026-11-02. Built in Phase B, part 4a ([#107](https://github.com/f8fvwgzc/tutela/issues/107)). It builds what [ADR-0040](#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org) item 8 left open, and gives PERMISSION-MODEL.md 7.1 step 6 ("nobody grants what they do not hold") its first code.

**Context.** In library mode a product calls `tutela-store` in its own transaction to register, move and delete scopes, assign roles and manage groups. In service mode it had no way to, and the Console's members and role pages (part 4b) need the same calls. PERMISSION-MODEL.md 15 says binding changes need `manage_access`, "pass role-on-diff and the narrow-only rule, bump the tenant revision and are audited". The store's calls trust their caller. A move must stay behind `write_check` (ADR-0025 item 8).

**Decision.**

1. **Routes and methods** (CONTRACTS.md 7.13.7), each in `tutela.admin.v1` with the route's JSON as `result_json`, under the admin token rule of ADR-0040: `GET`/`POST /v1/admin/scopes`, `POST /v1/admin/scopes/move`, `POST /v1/admin/scopes/delete`, `PUT /v1/admin/scopes/private`; `POST /v1/admin/assignments`, `POST /v1/admin/assignments/list`, `PATCH`/`DELETE /v1/admin/assignments/{id}`; `GET`/`POST /v1/admin/groups`, `DELETE /v1/admin/groups/{key}`, `GET`/`POST /v1/admin/groups/{key}/members`, `POST …/members/remove`; `GET /v1/admin/roles`. A principal is never in a URL: the list of assignments takes its filter as a body.
2. **Who may ask.** An assignment: `<type>:manage_access` on its scope. A group and its members: `org:manage_access` on the group's org (a group belongs to one org, PERMISSION-MODEL.md 6.4). Registering a scope: `write` on its parent (a new child is a write on its parent). Deleting one: `delete` on it. Its private flag: `manage_boundaries` on it. A page at one scope or org: `read_audit` or `manage_access` there; a page of the whole tenant, and the roles without a scope: `read_audit` at every org. A path is always the store's: a body names a parent, never a path.
3. **Narrow-only, before and after.** Every change of data is compared before and after, with the calculation of the impact report (ADR-0027), for every principal it can reach (its own assignments, its groups', and everyone below a scope whose private flag or field rules change), at every place below the scopes that changed. Each gain is held up to what the caller holds at the same place before the change; a gain above it is refused with 403 `not_held`, whose detail says what in counts (never a principal). This is `tutela_pdp::grant_excess`. It counts removals too: taking away a narrow direct assignment can uncover a wider one through a group (6.3), and a caller who does not hold that may not uncover it. A check that reaches its bound (`TUTELA_IMPACT_MAX_WORK`) refuses.
   - The grantee is taken at the highest its conditions can leave it, and the caller at the lowest. So **a caller whose own role has conditions may give only what it holds with every condition false**, even its own role (a known limit that refuses; pairing the two sides' conditions is possible only for conditions that do not name the principal).
   - The rule holds at every place a grant reaches, not only at its scope: a caller with a narrower assignment of its own deeper down may not give a wider one above it.
4. **A later end is a grant.** `PATCH /v1/admin/assignments/{id}` with a later `expires_at`, or `null`, is checked as if the assignment were new: the base of the comparison is the data without it. An earlier end needs `manage_access` only.
5. **Checked on the data the change writes.** The change runs in one transaction that locks the tenant's revision row (`tutela_store::lock`), reads the tenant, checks the key on that read, writes, reads again and compares. Nothing can change between the check and the commit; a refusal rolls the write back and records the refusal in its own transaction. Each such change reads the tenant twice more than a store write does (about 48 ms at the benchmark's size, ADR-0014 item 4).
6. **A move is `write_check`'s.** `POST /v1/admin/scopes/move {scope, parent, approved_by?}` runs `Pdp::write_check` with the new path on that locked read, for the caller, and moves the scope and everything below it with `move_scope` in the same transaction only when the verdict allows it. A verdict that refuses or waits for an owner is 403 `move_refused`, with the scopes that wait in its detail, and is recorded with both paths. `approved_by` is a service's only (CONTRACTS.md 7.8). The narrow-only rule does not run on a move: its looser check is the verdict's (ADR-0025).
7. **Store rules stand.** One assignment per subject and scope (409 `exists`), an expiry in the future (400), a role the model has and may give to that kind of subject (400), group cycles, nesting and closure limits (409 `refused`), a soft-deleted org takes nothing (404). The store bumps the revision and emits `tutela.permissions.changed.v1` in the change's transaction; the record of who asked is written last in it (`tutela_assignment:create|update|delete`, `tutela_group:create|delete|add_member|remove_member`, `tutela_scope:create|move|delete|update`).
8. **Pages** are at most 1000 (default 100) with `next_after`: assignments by id, groups by key (with their member counts), members and scopes by text, ordered by bytes so a cursor is stable on every collation.
9. **`GET /v1/admin/roles`** gives the active model's roles (levels per type, field levels, grants and admin keys, who may hold them) and types (fields with their sensitivity, features, actions): the rows and columns of the Console's permission matrix.

**Consequences.**
- A product in service mode registers, moves and deletes its scopes with its service account's token; that account needs the roles the rules ask for, given by ordinary assignments (for example the owner role at each org it serves).
- An org's owner (a person) may give anything in its org. A scope's owner may give what the owner role holds there. A role with `manage_access` and little else may give only what it holds.
- An admin change costs two extra reads of the tenant and two evaluator builds.

**Alternatives considered.**
- **Narrow-only only at the grant's scope, and for new grants only** (the literal words of 7.1 step 6). Simpler, but a removal can widen, and a grant reaches every place below its scope.
- **Pair the caller's and the grantee's conditions.** Correct only for conditions that do not name the principal, and the rule would need to know which; it refuses instead.
- **Check on the cached snapshot, write in another transaction.** Cheaper, but another write could land between the check and the commit.
- **A bare `move_scope` route.** It would skip the boundary rules.

---

## ADR-0044: Apps: one tenant each, a hashed client secret, and `azp` bound to the client that authenticated

**Status:** Accepted, 2026-11-02. Built in Phase B, part 4a. It builds the client authentication [ADR-0031](#adr-0031-token-exchange-the-tenant-from-the-trust-list-a-person-from-iss-sub) left to part 4 ("the token endpoint should then authenticate the client and bind `azp` to it"), and decides the plan of the notes for part 4 on how apps attach to tenants.

**Context.** Until now the token endpoint had no client authentication: a subject token was the only credential, and the issued token's `azp` was copied from it. A product's backend had no credential of its own at `tutelad`: it got a service token from Keycloak and exchanged it, or used a token of a Tutela-format issuer. CONTRACTS.md 5 defines API keys (`tut_sk_…`, stored as SHA-256(pepper ‖ key)), and `TUTELA_KEY_PEPPER` has been required at start-up since part 3a for this. The Console is a browser app: it cannot keep a secret.

**Decision.**

1. **An app belongs to one tenant.** `POST /v1/admin/apps {name}` (and `tutela.admin.v1` `CreateApp`) makes it in the caller's tenant: a client id `app_<uuidv7>`, a service account `sa:sa_<uuidv7>` of that tenant, and a first client secret. It needs every admin key at every org (the tenant's owner), as making an org does: an app's credentials speak for the tenant. The operator makes apps for the bootstrap with `tutelad apps create --tenant <tid> --name <n>`, as the owner role, as for `tutelad tenant create` (ADR-0041); the Helm bootstrap job (part 4c) calls the same `tutelad::lifecycle::create_app`. A tenant under another issuer than `TUTELA_ISSUER` has no apps: `tutelad` issues tokens for its own tenants only.
2. **The service account holds what assignments give it, nothing by default.** It is an ordinary principal: the owner gives it roles with `POST /v1/admin/assignments` (ADR-0043), under the narrow-only rule. No admin key comes with an app.
3. **A client secret is an API key** of CONTRACTS.md 5 (`tut_sk_<prefix>_<secret>`, 59 characters), owned by the app's service account, and authenticates as that service account. It is shown once, in the answer of create and rotate, and stored only as SHA-256(pepper ‖ key) with `pepper_version`, never in plain text and never sealed: nothing needs it back. A prefix is unique in the deployment. Records and logs name the key id and the display prefix, never the secret.
4. **Client authentication at `POST /oauth2/token`**: `client_secret_basic` or `client_secret_post` (RFC 6749 2.3.1), never both (`invalid_request`). Every failure is `401 invalid_client` with one description and `WWW-Authenticate: Basic`, after a hash computed on every path. The token endpoint finds the app's tenant in `tutela.app_directory` (client id to tenant, no secret: every role reads it, a runtime role adds a row only for the tenant its transaction entered), then reads the secret under the tenant's row-level security.
5. **`grant_type=client_credentials`** gives the app's service account an access token: `sub` the service account, `tid` its tenant from the app's record (never from the request), `azp` the client id, `aud` the asked audience (`TUTELA_AUDIENCE` by default, or an `[[audience]]` of the trust file; never `tutela-admin`, never delegated), `epoch` the service account's, no `sid` or `amr`, at most `TUTELA_TOKEN_TTL_SECS`. Each one is recorded (kind `client`, the app).
6. **`azp` is bound to the client that authenticated.** In a token exchange with client authentication, the client must be an app of the subject's tenant (else `invalid_grant`), and the issued token's `azp` is its client id. A subject token whose `azp` is the client id of an app of the tenant is exchanged only by that app, authenticated: another app gets `invalid_grant`, and no client authentication gets `invalid_client`.
7. **An exchange with no client authentication stays open, for public clients.** The Console runs in a browser and cannot keep a secret; neither can a mobile app. Such an exchange keeps the subject token's `azp`. It may not name an app: a `client_id` of a registered app without its secret is `invalid_client`, and so is a subject token whose `azp` is an app's (item 6). The other rules of ADR-0031 (each external token once, the tenant from the trust list) stand.
8. **Rotation with an overlap.** `POST /v1/admin/apps/{id}/rotate {overlap_secs?}` adds a new secret, shown once, and lets every older one work for `overlap_secs` more (default 3600, at most 604800, 0 ends them now), as webhook secrets rotate (ADR-0036). The app moves to the new secret within the overlap.
9. **Disabling.** `POST /v1/admin/apps/{id}/disable` ends every secret at once and disables the service account with a raised epoch, in one transaction: the tokens it holds are refused on `tutelad`'s API within `TUTELA_REVISION_CHECK_MS`, and products hear `tutela.principal.disabled.v1`. Migration 13 lets a service account have an epoch for this.
10. **A pepper rotation** makes old hashes unverifiable until a secret is rotated: a secret hashed under another `pepper_version` is refused (and logged). `TUTELA_KEY_PEPPER_PREVIOUS` (CONTRACTS.md 10.4) is still only proposed.
11. **Signed bundles stay as ADR-0038 says**: a service with `read_audit` at every org. Narrowing them to an app's registered audience waits until the products that pull bundles authenticate as apps (MIGRATION-0.2.md); doing it now would break every product that has a service token today, and the rule would add no key the owner does not already give.

**Consequences.**
- attache and texc-symphony authenticate as apps when they move to `v0.2.0`: the tenant's owner (or the bootstrap job) makes one per product, gives its service account roles, and the product calls `client_credentials` for its own token (MIGRATION-0.2.md).
- A product's `azp` in tokens it exchanges is its client id, so a product can tell its own users' tokens from another app's.
- A stolen Keycloak token can still be exchanged once by a public client (ADR-0031 item 6); an app's token cannot be exchanged by anyone but the app.

**Alternatives considered.**
- **Seal the secrets with `tutela-vault`.** It would keep them recoverable, which nothing needs; a hash with a pepper is what CONTRACTS.md 5 decided for keys.
- **Refuse every exchange without client authentication once apps exist.** The Console and other browser apps could not sign in.
- **Apps shared by tenants.** One app per tenant keeps its tenant in the record, never in a request, and lets the tenant's owner make and disable it.
- **Private-key JWT client authentication (RFC 7523).** Stronger, but every product would need a key pair and a JWKS; it can come beside the secret later.

---

## ADR-0045: The audit producer key sealed in the database, rotated with its old keys kept

**Status:** Accepted, 2026-11-02. Built in Phase B, part 4a. It changes how [ADR-0039](#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable) holds the producer key: `TUTELA_AUDIT_KEY` in the environment becomes a one-time import.

**Context.** Forwarding to attache's evidence ledger signs every record with the deployment's Ed25519 producer key (CONTRACTS.md 9.3). Part 3b read its seed from `TUTELA_AUDIT_KEY` on every replica. A secret in the environment of every replica is what ADR-0030 moved the token signing keys away from: they are sealed by `tutela-vault` in the database, rotated by the operator, and re-wrapped when the master key changes. There was no rotation for the producer key at all: a new seed would have left attache holding records it could no longer tie to a key.

**Decision.**

1. **Sealed in the database.** Migration 14 adds `tutela.audit_key` (`kid`, `public_key`, `sealed`, `origin`, `created_at`, `retired_at`): the seed only as a `tutela-vault` envelope, purpose `audit_key`, additional data its `kid` (the RFC 7638 thumbprint, `signature.key_id`). It is the deployment's, not a tenant's: no row-level security; the runtime role may read, add and update, never delete (`grant_service`).
2. **One key signs; old keys stay.** The key with no `retired_at` signs (a unique index allows one). A trigger keeps every key's identity and public key, keeps a retirement, and refuses a delete, for every role. So a record signed by any key, ever, verifies against the table (`tutelad::ledger::verify_record`), and attache's operator keeps every public key the deployment has used in `ledger.producers[].keys`.
3. **Made at start, when forwarding is on.** With `TUTELA_LEDGER_URL` set, `tutelad` makes sure a key signs before it forwards (`tutela_store::ensure_audit_key`), records `tutela_audit_key:create` or `tutela_audit_key:import` in the deployment's chain, and logs the `key_id` and public key for attache.
4. **The migration path.** A deployment that set `TUTELA_AUDIT_KEY` keeps it set for its first start on this version: with no key in the table, that seed is sealed and signs (`origin = imported`), so attache needs no change. After that the stored key wins: an env seed that differs is ignored with a warning, and the variable can be removed. `TUTELA_AUDIT_KEY` is no longer required with `TUTELA_LEDGER_URL`; without it a new key is made.
5. **Rotation.** `tutela keys rotate --audit` (the operator, with `TUTELA_MASTER_KEY`) retires the key that signs and makes the next, in one transaction, recorded as `tutela_audit_key:rotate` with both `kid`s. Every replica signs with the new key from its next tick, because the forwarder reads the key that signs at each tick. A record is signed when it is forwarded, so records written before the rotation and not yet shipped are signed by the new key; those already shipped keep the old key's signature, which still verifies. The operator adds the new public key to attache before rotating, or attache refuses the next batch until it has it (the batch waits, nothing is lost: ADR-0039).
6. **Re-wrap.** `tutela keys rewrap` seals the audit keys again under the current master key, with the signing keys.

**Consequences.**
- No replica holds the producer seed in its environment after the first start; a leaked environment no longer leaks it.
- Rotating the producer key is an operator command, recorded, with no gap in what verifies.
- A deployment that never set `TUTELA_AUDIT_KEY` gets a new key at its first start with forwarding on; its operator gives attache the logged public key.

**Alternatives considered.**
- **Keep the seed in the environment.** Every replica holds it, and no rotation keeps old records tied to their key.
- **Sign records when they are written, not when forwarded.** It would freeze a key into each local record; the local log is hash-chained already (ADR-0034), and signing at forwarding keeps one key to rotate.
- **Delete retired keys after a while.** A record in attache's ledger could then never be checked again against Tutela's keys.

---

## ADR-0046: The CLI against `tutelad`: `apply` with the impact report, `apps`, and `keys` through the key store

**Status:** Accepted, 2026-11-02. Built in Phase B, part 4a. It builds the CLI items of the Phase B work list (`tutela apply` against `tutelad`, `tutela apps create`, `tutela keys rotate`) on the routes of [ADR-0026](#adr-0026-a-tenant-owns-its-model-versions) to [ADR-0029](#adr-0029-two-person-publish) and [ADR-0044](#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated), and the key stores of [ADR-0030](#adr-0030-tutelads-own-issuer-signing-keys-the-jwks-and-paths-without-a-token) and [ADR-0045](#adr-0045-the-audit-producer-key-sealed-in-the-database-rotated-with-its-old-keys-kept).

**Decision.**

1. **Library mode is unchanged.** `tutela apply` without `--server` applies to the database of `TUTELA_DATABASE_URL`, as in Phase A (ADR-0015).
2. **`tutela apply --server <url>`** (or `TUTELA_URL`) with `--token` (or `TUTELA_TOKEN`): a pipeline's service token (an app's `client_credentials` token) or a person's admin token. It compiles the manifest, asks `POST /v1/models/impact`, and prints the tenant, the versions and digests, the class, the diff and the impact report's sentences (counts, never names). Then:
   - no change: done;
   - a widening change without `--approval`: refused before anything is sent, with the `tutela approve --app … --from … --to … --tenant …` line an approver runs; exit 3. `tutelad` refuses it too;
   - `--dry-run`: nothing is written;
   - two-person publish on (`GET /v1/models/settings`): `POST /v1/models/proposals` with `expected_version` and the approval token; the proposal id is printed;
   - else `POST /v1/models/publish` with `expected_version` (the version the report was made against, so a publish that raced another is 409) and the approval token.
3. **The connection.** `https` only, except `http` on a loopback host; no credentials in the URL; no redirects; a token is never printed. A refusal prints the problem's code and detail.
4. **`tutela apps create | list | rotate | disable`** call the admin routes of 7.13.8 with the caller's token (the tenant's owner); `create` and `rotate` print the client secret once, with a line saying so.
5. **`tutela keys list | rotate [--audit] | deny <kid> | rewrap`** call the key stores in the database directly, with the vault of `TUTELA_MASTER_KEY` (and `TUTELA_MASTER_KEY_PREVIOUS`), as an operator command, and write each change's record to the deployment's audit chain under `TUTELA_ISSUER`, by `tutelad`'s system actor with `by: operator`, as `tutelad tenant create` does. `rotate` uses `tutelad`'s rotation times (twice `TUTELA_JWKS_CACHE_SECS` ahead; the longest token life and the skew after). Replicas pick a change up within `TUTELA_KEY_REFRESH_SECS` (signing keys) or at their next forwarding tick (the audit key).

**Consequences.**
- texc-symphony's pipeline publishes a product's manifest to each tenant with its app's token, and gets the same diff, report and refusal it gets in library mode.
- The CLI needs the database and the master key for `keys`, as `tutelad` does: it runs where the operator runs `tutelad migrate`.

**Alternatives considered.**
- **`tutela keys` over an admin route.** There is no operator identity on the API (ADR-0041, TM-08), and a tenant's admin must never reach the deployment's keys.
- **Let `tutelad` refuse a widening change alone.** It does; refusing in the CLI first keeps a refused publish out of the tenant's audit log as an attempt, and prints the approver's command.

---

## ADR-0047: The JavaScript SDKs: a pnpm workspace under `sdk/`, checked by `make`

**Status:** Accepted, 2026-11-02. Phase B, part 4b1 ([#126](https://github.com/f8fvwgzc/tutela/issues/126)). It sets up the toolchain for `@f8fvwgzc/tutela-js` and `@f8fvwgzc/tutela-react` (ADR-0001's npm names), which the Console of part 4b2 builds on.

**Context.** The repo had no JavaScript except a generated fixture of `tutela codegen`. AGENTS.md section 2 plans the packages at `sdk/js` and `sdk/react`. INTEGRATION.md names GitHub Packages (`https://npm.pkg.github.com`) as the registry of the `@f8fvwgzc` scope. TM-21 wants pinned dependencies, no unknown sources and a gate that blocks. The machines that run `make` have node 22.12 and pnpm 10.18. GitHub Actions cannot run (account billing), so `make` is the only gate, and plain `cargo build` and `cargo test` must still work where there is no node.

**Decision.**

1. **Layout.** A pnpm workspace at the repo root (`package.json` private, `pnpm-workspace.yaml`, one `pnpm-lock.yaml`, committed) with `sdk/js` (`@f8fvwgzc/tutela-js`) and `sdk/react` (`@f8fvwgzc/tutela-react`), as AGENTS.md section 2 has them. The Console of part 4b2 joins as another member. `tutela-react` depends on `tutela-js` with `workspace:*`, which a publish turns into the exact version.
2. **Pinned versions.** Every version is exact (`save-exact`), the lockfile is installed with `--frozen-lockfile`, and node (`>=22.12`) and pnpm (`10.18`, `packageManager`) are enforced (`engine-strict`). A version must be a week old before pnpm installs it (`minimumReleaseAge`), and no dependency runs an install script (`onlyBuiltDependencies: []`).
3. **TypeScript, strict.** `tsconfig.base.json`: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, ES2022, `module: NodeNext`. Each package builds with `tsc` alone to ES modules with type declarations (`dist/`); there is no bundler: a product's bundler takes the modules as they are. The browser client is built with the DOM library and **no Node types**, so a Node-only API in `sdk/js/src` does not compile; tests have Node types.
4. **Lint: Biome, not ESLint.** ESLint 10 and typescript-eslint 8 need node 22.13 or later, and ESLint 9 is out of support. Biome 2 is one native binary with no install script and no node version rule. `biome ci --error-on-warnings` checks formatting and lints with its recommended rules, every accessibility rule, the React hooks rules, `noFloatingPromises` and `noMisusedPromises`, `noExplicitAny`, `noNonNullAssertion` and `noConsole`. In `sdk/*/src` it refuses `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, Node globals and `node:` imports (TM-06: tokens live in memory only).
5. **Tests: vitest.** Unit tests in node or jsdom (`jsdom` 28: the newest that runs on node 22.12), Testing Library for React, and axe-core for accessibility. An integration test against a real `tutelad` comes with `tutela-js`.
6. **`make` runs it.** `make` (= `make all`) runs the Rust gates, then `make js`: `js-install` (frozen lockfile), `js-build`, `js-typecheck`, `js-lint`, `js-test`, `js-audit` (`pnpm audit` over every dependency, dev tools too, as `cargo audit` covers dev dependencies) and `js-licenses` (a production dependency of the SDKs must have a licence of the permissive part of `deny.toml`; dev tools never reach a product). The Rust targets are unchanged, so `cargo build` and `cargo test` need no node.
7. **Publishing is the owner's step.** Nothing here publishes. A release sets the same version in every artifact (CONTRACTS.md 10.5), and the owner publishes from a clean checkout of the tag with `pnpm -r publish --access restricted` to GitHub Packages (`publishConfig.registry` in each package), after `make` passes on that commit. Registering the `@f8fvwgzc` scope on the public npm registry (TM-21) stays an owner step before any public publish.

**Consequences.**
- `make` needs node 22.12+ and pnpm 10 besides Rust. A machine without them runs the Rust targets one by one.
- The lockfile is part of every change that adds a dependency: run `pnpm install` once, then commit `pnpm-lock.yaml`.
- `.github/workflows/ci.yml` gets a `js` job that runs `make js` (it does not run while Actions is off).

**Alternatives considered.**
- **ESLint with typescript-eslint and jsx-a11y.** Typed rules are richer, but it needs a newer node than the machines have, or an ESLint version out of support.
- **npm workspaces.** No `minimumReleaseAge`, and install scripts run by default.
- **A bundler (tsup, Vite library mode).** Another tool in the supply chain; `tsc` already emits what bundlers and node take.
- **`packages/` at the root.** AGENTS.md section 2 already planned `sdk/js` and `sdk/react`.

---

## ADR-0048: `tutela-js`: the browser token flow in memory, typed errors, and a retry that never makes twice

**Status:** Accepted, 2026-11-02. Phase B, part 4b1. It builds `@f8fvwgzc/tutela-js` on the toolchain of [ADR-0047](#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make), for the token flow and the routes of the ROADMAP notes for part 4b, and the Console of part 4b2.

**Context.** The Console is a public client in a browser (ADR-0044 item 7). A person signs in at Keycloak; `tutelad` exchanges an external token once (CONTRACTS.md 4.8) and issues an admin token only after step-up (ADR-0032); the admin token is refused outside the admin API and the person's `tutela-authz` token on it. TM-06 keeps tokens out of browser storage. Pipelines and cores written in TypeScript call the same routes with a service token. Problem documents, pages with `next_after`, the `rev` of a write, the ETag of the permission map and `Retry-After` are in CONTRACTS.md 7.1, 7.5 and 7.13.

**Decision.**

1. **One client, two ways to authenticate.** `new TutelaClient({ baseUrl, auth })`: `auth.kind = "browser"` with a `getUpstreamToken(reason)` callback, or `"service"` with `getToken(audience)`. Each route knows its audience: the admin API (`/v1/admin`, `/v1/models`, explain, simulate) takes the admin token, the check API (`/v1/whoami`, `/v1/authz/permissions`) the `tutela-authz` token; a service returns its own token for both.
2. **The browser flow.** The session exchanges the upstream token at `POST /oauth2/token` (token exchange, no client authentication) for a `tutela-authz` token, then exchanges **that** token for the admin token (`audience=tutela-admin`). One upstream token gives both, so each upstream token is exchanged once. `tutelad` copies `acr` into its own token, so the step-up check holds on the second exchange. The client never keeps a token past its `exp`, the `exp` of the token it came from or `expires_in`; it renews 30 s before, from a fresh upstream token. It refuses to send an upstream token it sent before (by `jti`) with `UpstreamTokenReusedError`, before the request: a lost answer may still have used the token. Exchanges are single-flight. A 401 drops the session's tokens and starts again from upstream once.
3. **Step-up is a state, not only an error.** The `invalid_grant` "step-up authentication is required" answer is `StepUpRequiredError`; the session keeps its `tutela-authz` token (the check API still works), says `step-up-required`, and `stepUp()` starts again after the person did MFA.
4. **Tokens live in memory only.** No storage API is used anywhere in the package; Biome refuses one in `sdk/*/src`, and a test runs the whole flow in jsdom with every storage API watched. `fetch` runs with `credentials: "omit"` (no cookie of the page's origin goes to `tutelad`) and `redirect: "error"`; a `baseUrl` with credentials is refused.
5. **Typed errors.** A problem document becomes a `ProblemError` subclass by status and code, with `status`, `code`, `title`, `detail`, `retryAfter` and `requestId`: `NotHeldError` splits the counts-only detail into `gains`; `MoveRefusedError` parses the scopes that wait for an owner into `waitingFor`. A body that is not a problem gets the code of its status. Token-endpoint refusals are `TokenExchangeError`.
6. **A retry that never makes twice.** A 503 is retried after `Retry-After`, at most `maxRetries` (2) times and only when `Retry-After` is at most `maxRetryAfterSecs` (5); a longer wait is thrown for the page to show. Only calls that are safe to send again are retried: reads, and writes the server refuses a second time (an assignment is `exists`, a removal `not_found`, a publish `version_conflict`). A call that makes something (an org, an agent, an app or its secret, a webhook or its secret, a proposal) is never retried by the client.
7. **The revision.** The client keeps the highest `rev` its writes answered and sends it as `at_least_revision` on the permission map and as `context.at_least_revision` on explain and simulate. Reads never move it.
8. **The permission map.** `permissions({resource, actions})` asks for the caller itself (from `GET /v1/whoami`, asked once), with `ui_keys: []` unless asked, sends `If-None-Match` with the tag it holds and keeps the map on 304. `can(action, resource)` answers from loaded maps and is `false` for anything not loaded.
9. **Principals stay out of URLs.** Lists by subject, principal state and group members send principals in JSON bodies (CONTRACTS.md 9.5); ids in a path are encoded.
10. **The model as text.** `permissionMatrix(roles)` builds the matrix of the ROADMAP notes (a field never above its item level; a feature may be). `setRoleGrants(source, draft)` rewrites one role's `grants` in the active manifest (from `GET /v1/models/active`, added in this part) and leaves every other byte; it refuses `owner`, a `[roles]` table and dotted grants with `ModelEditError`. It is a text edit: `tutelad` compiles, reports the impact and refuses a widening change without an approval token.
11. **Tested on both sides.** Unit tests against a mocked fetch for every error path; an integration test (`crates/tutelad/tests/js_client.rs` runs `sdk/js/test-integration` with vitest) against a real `tutelad` on a real Postgres, in `make js-it`.

**Consequences.**
- The Console (part 4b2) and a product embedding the admin components need the page's origin to reach `tutelad`: either `tutelad` serves the page (the Console), or the product proxies `/oauth2/token`, `/v1/admin`, `/v1/models`, `/v1/authz` and `/v1/whoami` on its own origin. `tutelad` sends no CORS headers yet ([#135](https://github.com/f8fvwgzc/tutela/issues/135)).
- A product that keeps backend-for-frontend (TM-06's default) uses service mode on its server, or a `custom` token source that asks its backend.
- A 503 longer than 5 s, or on a call that makes something, reaches the page as `UnavailableError` with `retryAfter`.

**Alternatives considered.**
- **Exchange the upstream token twice, once per audience.** `tutelad` refuses the second: each external token is exchanged once.
- **Exchange the upstream token for the admin token first.** An admin token cannot be the subject of another exchange, and without step-up the person would get nothing, not even the check API's token.
- **Keep tokens in `sessionStorage` to survive a reload.** TM-06 refuses it; a reload signs in again through Keycloak's own session.
- **Retry every 503.** A lost answer to a create would make two apps or two webhook secrets.

---

## ADR-0049: `tutela-react`: embeddable admin components, scoped CSS variables, and the host names the people

**Status:** Accepted, 2026-11-02. Phase B, part 4b1. It builds `@f8fvwgzc/tutela-react` (React 19) on [ADR-0048](#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice): `MembersTable`, `RoleEditor` and `PermissionMatrix`, which the Console of part 4b2 and products embed (INTEGRATION.md step 8).

**Context.** The components run inside someone else's app: they must not force a CSS framework, restyle the host page, or need a Content-Security-Policy exception (the Console sends a strict one, TM-06). Tutela keeps no names or e-mails of people (principals are opaque, ADR-0001). The ROADMAP notes for part 4b say what a page does with each answer. The owner wants dense, full-width pages in the style of Linear, and has reduced motion on.

**Decision.**

1. **One stylesheet, scoped and themed by variables.** `@f8fvwgzc/tutela-react/styles.css` is a plain CSS file the host imports once; no CSS-in-JS, no inline `<style>`, so no CSP exception. Every rule is under the components' root class `.tutela`; nothing styles `html`, `body` or a bare element. Colours, font, sizes and radii are `--tutela-*` variables the host overrides. Light by default, dark from `prefers-color-scheme` or `theme="dark"` (`data-theme` on the root). Dense: 13 px text, 32 px rows, full width, sticky table headers, tabular numbers, one accent. Motion: a 120 ms colour change on buttons, none under `prefers-reduced-motion`.
2. **The host names the people.** A subject is shown as its principal string unless the host passes `renderSubject(principal)`, so a product shows its own names without giving them to Tutela.
3. **The host knows the path.** `MembersTable` takes `scope` and its `path` (the `ancestors` of `GET /v1/admin/scopes`): the permission map needs the path, and a scope's path always comes from the scope tree, never from a person's input.
4. **What a page does with each answer**, as the ROADMAP notes give it: the permission map (`<type>:manage_access`) decides what is shown; a 403 `forbidden` on a change hides the controls; a 403 `forbidden` on the list shows that the person may not see it; `not_held` shows the server's counts-only sentences and, when the host passes `onAskAdmin`, a button that hands the host an access request (Tutela has no route for requests yet); `move_refused` lists the scopes that wait for an owner (`ErrorNotice`, for the scope tree of part 4b2); a 409 loads again; a 503 tries a read again after `Retry-After` (at most 30 s) and shows a countdown, and tries a change again once after it (the changes of the table are safe to repeat: ADR-0048 item 6) or at once on "Try again now"; a step-up refusal offers `onStepUp`.
5. **A role change is a model change.** `RoleEditor` starts from `GET /v1/models/active`, rewrites the role with `setRoleGrants`, shows `POST /v1/models/impact` as sentences and its class, asks for an approval token when the change widens, and publishes with `expected_version`, or proposes when the tenant has two-person publish on. The `owner` role is shown and never changed. `PermissionMatrix` in `editable` mode edits one role's column and hands the draft to `onReview`, for a `RoleEditor`.
6. **Accessible.** Tables with column and row headers, labelled inputs, buttons with names that say what they act on, a polite status region for each success and an alert for each refusal, visible focus, and the whole table usable with the keyboard. The tests run axe-core on each component (colour contrast is not checked in jsdom).

**Consequences.**
- A product embeds the components behind its own Keycloak sign-in with a `BrowserSession` and, until [#135](https://github.com/f8fvwgzc/tutela/issues/135), a same-origin proxy of `tutelad`.
- Access requests after `not_held` are the host's to send (a ticket, a message to an owner); a Tutela route for them is later work.
- A host that wants other looks overrides variables, or styles its own wrapper; the components' markup and class names are part of the package's API from v0.2.0.

**Alternatives considered.**
- **CSS-in-JS or inline styles.** They need `style-src 'unsafe-inline'` or a nonce in the host's CSP.
- **A component library (shadcn, Radix, MUI).** It would force its styles, versions and size on every host.
- **Ask Tutela for display names.** Tutela keeps no personal data beyond `(iss, sub)` (CONTRACTS.md 9.5).

---

## ADR-0050: The Console is served by `tutelad` under `/console/`, from files read at start

**Status:** Accepted, 2026-11-02. Phase B, part 4b2. It decides the plan of the ROADMAP notes for part 4b2 on how the Console is served, and **changes [ADR-0030](#adr-0030-tutelads-own-issuer-signing-keys-the-jwks-and-paths-without-a-token) item 9**: besides the exact paths of `api::PUBLIC_PATHS`, the paths under `/console/` need no token when the Console is on.

**Context.** The Tutela Console is a single-page app (part 4b2, `console/`). It runs in a browser as a public client (ADR-0044 item 7) with tokens in memory only (ADR-0048, TM-06). It must reach `tutelad`'s token endpoint and admin API; `tutelad` sends no CORS headers ([#135](https://github.com/f8fvwgzc/tutela/issues/135)). TM-06 wants the Console to send a strict Content-Security-Policy and `frame-ancestors`. Plain `cargo build` must not need node (ADR-0047). The OCI image of part 4c must be able to ship the Console with `tutelad`.

**Decision.**

1. **Same origin, one prefix.** `tutelad` serves the Console on the API port under `/console/`. The page and the API share an origin: no CORS, and the client keeps `credentials: "omit"`. The prefix is fixed.
2. **From a directory set by configuration.** `TUTELA_CONSOLE_DIR` names the built Console (`console/dist`). Unset: nothing is served, and `/console/` is a path like any other, behind the token check. Set: every plain file in it is read into memory once at start (at most 2,048 files and 64 MiB, eight levels deep), and start-up fails when it cannot be read or has no `index.html`. The Rust build never runs node; the image copies the built files.
3. **Exact paths only, no token.** `GET` and `HEAD` only (else 405). A request is answered by looking its path up in the list read at start, never by joining it to the directory, so `..`, encoded separators and links reach nothing. Symbolic links, hidden files and names outside a plain character set are not served. `/console` redirects to `/console/`; `/console/` is `index.html`.
4. **Page paths get `index.html`; nothing else does.** A path of one to six segments of `a-z`, `0-9`, `-` and `_`, with no dot, is a page of the Console's own router and gets `index.html`. Any other path under `/console/` is 404. The fallback never reaches beyond `/console/`: `/v1/...`, `/consoles` and every other path still need a token and say nothing without one (ADR-0030 item 9).
5. **Headers on every answer under `/console/`:** `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self' <the realm's origin>; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (the authorization code in the callback URL never leaves in a referrer), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`. The components and the Console use no inline script or style, so the policy has no exception. Files under `assets/` (named by their content hash) are `immutable` for a year; everything else is `no-cache`.
6. **Where people sign in comes from `tutelad`, never from the person.** `GET /console/config.json` answers `{issuer, client_id, step_up_acr, audience}` with `Cache-Control: no-store`: `TUTELA_CONSOLE_ISSUER` (the realm), `TUTELA_CONSOLE_CLIENT_ID` (the Console's public client there), the first value of `TUTELA_ADMIN_ACR` (what the Console asks for at sign-in) and `TUTELA_AUDIENCE`. `TUTELA_CONSOLE_ISSUER` must be an external issuer of the trust file, written as there: `tutelad` exchanges that realm's tokens, and its tenant comes from the trust list as always (ADR-0031). `TUTELA_ADMIN_ACR` must be set, or no admin token could ever be issued. With one realm per deployment (ARCHITECTURE.md) one value is enough.
7. **Counted, not logged per file.** Console answers go through the request metrics (`route="unmatched"`) and get an `x-request-id`; they read no database and no token.

**Consequences.**
- A deployment turns the Console on with three settings (`deploy/tutelad.env`). The OCI image of part 4c copies `console/dist` to the directory it names (the example is `/srv/tutela/console`).
- A rebuilt Console needs a restart of `tutelad` (the files are read once).
- The realm's origin is in `connect-src`, for OIDC discovery and its token endpoint. A realm whose token endpoint is on another origin is not supported.
- Products that embed the components on their own origin still need a proxy or CORS ([#135](https://github.com/f8fvwgzc/tutela/issues/135)).

**Alternatives considered.**
- **Serve from disk on each request.** A file changed or linked after start could be served, and every request would touch the disk; the Console is a few hundred kilobytes.
- **Embed the Console in the binary.** `cargo build` would need node, or a built copy in the repo.
- **A separate static server or a CDN.** Another origin needs CORS and another CSP to keep right; part 4c may still put a CDN in front, the headers stay the same.
- **A page fallback for every unknown path.** An API path would answer 200 with HTML and say something without a token.
- **Hash routing (`/console/#/scopes`).** It needs no fallback, but every link to a page carries a fragment and the callback of the sign-in would need one; the fallback is narrow enough.

---

## ADR-0051: A test OpenID provider shaped like Keycloak: a dev-only crate on loopback

**Status:** Accepted, 2026-11-03. Phase B, part 4b2. It answers the ROADMAP notes for part 4b2: the end-to-end exit check needs a sign-in with an authorization endpoint, and the repo had none.

**Context.** The exit check "sign-in, the UI permission map and runtime role editing pass end to end" needs a person to sign in in a real browser. `crates/tutelad/tests/exchange.rs` and `js_client.rs` sign Keycloak-shaped tokens locally, with no authorization endpoint. A real Keycloak is [#87](https://github.com/f8fvwgzc/tutela/issues/87): no image can be pulled on the owner's Mac. The provider must never ship in `tutelad`.

**Decision.**

1. **A crate of its own, `crates/tutela-test-idp`**, with a library (the tests start it in-process) and a small binary `tutela-test-idp` (a local demo of the Console). `publish = false`. Only tests depend on it (`[dev-dependencies]`), so `tutelad` never links it.
2. **Loopback only.** `start` refuses an address that is not loopback; the binary too. Its issuer is `http://127.0.0.1:<port>/realms/<realm>`, which `tutelad` trusts only in dev mode (ADR-0018).
3. **Keycloak's paths and shapes.** One realm under `/realms/<realm>`: discovery, `protocol/openid-connect/auth`, `/token`, `/certs`, `/logout`. Access tokens are RS256 with `typ: JWT` (Keycloak 26's default), `aud` the configured audience (`TUTELA_AUDIENCE`, as Keycloak's audience mapper gives), `azp` the client, `jti`, `sid`, `acr`, `typ: Bearer`, `scope`, `allowed-origins` and profile claims; an ID token with `nonce`; an opaque refresh token. CORS on the token endpoint and discovery for the client's web origins (the origins of its redirect URIs), as Keycloak answers them.
4. **The authorization endpoint is a small form**: pick a test person, tick "Use MFA" or not. With MFA the token's `acr` is the step-up value (`mfa`), else `"1"`. `acr_values` naming the step-up value ticks the box. No password: it is a test provider.
5. **The rules of a careful provider (TM-07)**: the client id and the exact redirect URI are checked first, and a bad one gets a page, never a redirect; `state` is required; PKCE S256 is required (`plain` and none are refused); a code lasts 60 s and is used once (taken out before it is checked); the verifier is checked; a refresh token is used once and rotated; the redirect carries `iss` (RFC 9207). `logout` redirects only to a registered URI.
6. **Tested on its own** (`crates/tutela-test-idp/tests/flow.rs`): the code flow, the token shapes and signature against the JWKS, a code used twice, a wrong verifier, a foreign redirect URI, `plain` PKCE, refresh rotation, CORS and loopback only. The end-to-end check of part 4b2 runs it with a real `tutelad` and a real browser.

**Consequences.**
- The exit check runs in `make` without Docker or a network.
- A deployment never uses this provider: it has no passwords and accepts any listed person. A real Keycloak test stays [#87](https://github.com/f8fvwgzc/tutela/issues/87).
- The Console can be run locally against it (JS-SDK.md, "The Console").

**Alternatives considered.**
- **A test binary inside `tutelad`'s tests.** A local demo could not start it.
- **A feature flag of `tutelad`.** The provider could reach a shipped build by mistake.
- **Keycloak in a container.** Image pulls hang on the owner's Mac; it stays the goal of #87.
- **ES256 tokens.** Keycloak signs RS256 by default; RS256 also tests that path of `tutelad`'s verifier.

---

## ADR-0052: The Console: a Vite app on the SDKs, sign-in by code with PKCE, the permission map asked again every half second

**Status:** Accepted, 2026-11-03. Phase B, part 4b2. It builds the Tutela Console the ROADMAP notes for part 4b2 plan, on `@f8fvwgzc/tutela-js` and `@f8fvwgzc/tutela-react` ([ADR-0048](#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice), [ADR-0049](#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people)), served as [ADR-0050](#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start) says. It includes one **server change**: a resource search for `org` names orgs (item 4).

**Context.** The Console is a public client in a browser: it keeps no secret (ADR-0044 item 7) and no token in storage (TM-06). A person signs in at the tenant's realm (Keycloak), and `tutelad` exchanges that token once for a `tutela-authz` token and an admin token after step-up (ADR-0031, ADR-0032). What a page shows must follow the permission map, and a role change must show within the documented revocation delay (1.5 s, PERMISSION-MODEL.md 16.1). The event stream is for services only (ADR-0037). A person who is not an org's admin may not list orgs or scopes over the admin API.

**Decision.**

1. **A workspace member, `console/`**, private, React 19 and TypeScript strict, built by Vite 8 (already in the lockfile through vitest) into `console/dist` with the base `/console/`. Nothing is inlined (no inline script or style, no `data:` URL), so the CSP of ADR-0050 needs no exception. `make js` builds it and runs its tests (vitest, Testing Library, axe-core); Biome lints it, and refuses `localStorage`, `indexedDB` and `document.cookie` in `console/src`.
2. **Sign-in: the authorization code flow with PKCE (S256), as a public client** of the realm named by `/console/config.json`. The discovery document must name exactly that issuer. Each sign-in asks for the step-up `acr` (`acr_values`, the first value of `TUTELA_ADMIN_ACR`): the Console is for admin work. The callback checks `state`, the RFC 9207 `iss` when present and the ID token's `nonce`, removes the code from the address bar at once, and trades the code with the verifier. The redirect URI is `<origin>/console/callback`.
3. **Tokens in memory only.** The realm's access, refresh and ID tokens and `tutelad`'s tokens live in JavaScript objects; a reload signs in again (with Keycloak's own session, without a form). **One departure:** the pending sign-in (`state`, `nonce`, the PKCE verifier and the page to return to) is kept in `sessionStorage` for the round trip to the realm, and removed when the callback reads it, before the code is traded. It is not a token, and it is useless once its code is spent; the browser check asserts that every storage is empty after sign-in. Sign-out drops every token and ends the realm's session without `id_token_hint` (no token in a URL).
4. **What the person sees comes from the permission map.** The Console finds the orgs the person can see with a resource search for `org:read` (CONTRACTS.md 7.4, `searchResources`, new in `tutela-js`), and asks the permission map at each for the six admin keys. **Server change:** `tutela-pdp`'s resource search took an org's path from the scope-path provider, which holds only scopes below orgs, so a search for `org` failed with 503; an org is a root, so its path is now empty, as in a check (regression test `a_search_for_orgs_names_the_orgs_check_allows`). The rail shows a page only when the keys allow it ("every org" means every org the person sees); a hidden page is not rendered, and a page opened by its path says the keys are missing. Every route checks again.
5. **Asked again every 500 ms while the page is visible**, with the map's ETag, so most answers are a 304 with no body; the orgs are searched again every 20 rounds. With `TUTELA_REVISION_CHECK_MS` at 1 s, a role given or taken shows in the other person's Console within the 1.5 s delay (measured in the browser check). Server-sent events would be quieter, but they are for services only (ADR-0037).
6. **Step-up as a banner.** When the person holds any admin key, the admin token is asked for at once; without step-up the session says `step-up-required` and the Console shows a banner whose "Sign in with MFA" signs in again with the step-up `acr`. The check API keeps working meanwhile.
7. **Pages** (Overview, Scopes, Roles, Model history, Groups, People and agents, Apps, Webhooks, Tenant and orgs, Explain and simulate) use `MembersTable`, `PermissionMatrix`, `RoleEditor` and `ErrorNotice` where they exist and the client elsewhere, and do what the notes for part 4b say with each answer: 403 `forbidden` hides, `not_held` and `move_refused` explain, 409 loads again, 503 retries. A scope's path always comes from the scope tree, never from the address bar. A secret is shown once, in a component's state, and dropped when closed. Principals go in request bodies, never in a URL.
8. **Looks:** dense and full width, a left rail of pages, the components' palette (one accent), a theme switch (system, light, dark), a skip link, visible focus, arrow keys in the scope tree, and no motion under `prefers-reduced-motion`.

**Consequences.**
- The Keycloak client of the Console is public, standard flow only, PKCE S256 required, the redirect URI `https://<tutelad host>/console/callback`, the web origin `https://<tutelad host>`, the post-logout redirect URI `https://<tutelad host>/console/`, an audience mapper to `TUTELA_AUDIENCE`, and an ACR-to-LoA mapping whose step-up level is named as in `TUTELA_ADMIN_ACR` (the notes for part 4c).
- An open Console tab asks `tutelad` twice a second per org it shows; a hidden tab does not ask.
- A person who can see no org (no role at any org, only below) sees only the overview: the scopes below an org are found from an org.

**Alternatives considered.**
- **keycloak-js.** Its silent check-SSO needs an iframe (`frame-src`) and third-party cookies, and it keeps state in storage.
- **oidc-client-ts.** It keeps its state and, by default, its user in storage; the flow the Console needs is a hundred lines.
- **A popup sign-in that keeps the verifier in memory.** Popups are blocked unless clicked, and `Cross-Origin-Opener-Policy: same-origin` cuts the popup from its opener once it visits the realm.
- **Listing orgs with `GET /v1/admin/orgs`.** It needs `read_audit` at every org, and every refusal is audited: polling it would fill the audit chain.
- **Server-sent events for browsers.** ADR-0037 keeps the stream for services.

---

## ADR-0053: The exit check in a real browser: Playwright's Chromium, a real `tutelad` and the test provider, run by `make`

**Status:** Accepted, 2026-11-03. Phase B, part 4b2. It builds the Phase B exit check "sign-in, the UI permission map and runtime role editing pass end to end" and the browser test of TM-06, on the Console (ADR-0052), its serving (ADR-0050) and the test provider (ADR-0051).

**Context.** The check must run in a real browser against a real `tutelad` on a real Postgres. GitHub Actions cannot run, so `make` is the gate. Docker image pulls hang on the owner's Mac, but Playwright's Chromium build 1243 is already installed there (nexc-engine pins `@playwright/test` 1.63.0). TM-06 asks for an admin token six minutes old to be refused, which a browser test cannot wait for.

**Decision.**

1. **A Rust test makes the world and runs Playwright**, as `js_client.rs` does for the client: `crates/tutelad/tests/console_e2e.rs` publishes a manifest, makes a tenant under `tutelad`'s own issuer, starts the test provider as the tenant's realm, provisions an owner (`owner` at the org) and a second person (who sees the org through the group `staff` with `viewer`, because a subject has one assignment per scope and the owner must still be able to give them a role there), and starts `tutelad` with the Console on (`console/dist`), in dev mode for the loopback realm, fetching the realm's JWKS over HTTP through `tutela-safenet` as production does. Then it runs `pnpm exec playwright test` in `console/` with a fixture file, and afterwards checks the tenant's audit chain for the owner's assignment, removal and publish.
2. **In `make`.** `make js-e2e` (part of `make js`, after `js-build` and `js-it`) runs it with `TUTELA_CONSOLE_E2E=1`. Without a database it says it is skipped, unless `TUTELA_REQUIRE_DATABASE=1`, which fails it, as for every database test. A missing built Console or a missing browser fails it; nothing is skipped in that mode.
3. **The browser is pinned, never downloaded.** `@playwright/test` is pinned at 1.63.0, whose `browsers.json` names Chromium 1243; Playwright finds it in its cache (`~/Library/Caches/ms-playwright` on macOS). Another machine installs it once with `pnpm --filter @f8fvwgzc/tutela-console exec playwright install chromium`.
4. **What it checks**, in one run (`console/e2e/exit-check.spec.ts`):
   - the owner signs in with MFA through the Console and the realm's form; the strict headers are on the page; the rail shows every page the permission map allows;
   - the second person, in another browser context, sees only the overview and is told a page needs keys they lack;
   - the owner gives them `auditor` (`org:read_audit`) in `MembersTable`; their Console shows the new pages within the documented revocation delay (1.5 s; measured from the answer of the write to the page changing), and no admin action they do not hold (no "Give role", no "Remove", no "Edit" in the matrix, no Apps page); the owner removes it and the pages go, within the delay;
   - the owner edits the role `reader` in the permission matrix, the RoleEditor shows the impact sentence ("…lose…", "This change narrows access."), and publishes; Model history shows the new version;
   - TM-06: in every context, `document.cookie`, `localStorage`, `sessionStorage`, IndexedDB and the context's cookies hold nothing;
   - an admin token six minutes old is refused (401): the test mints, with `tutelad`'s own signing key, one issued 360 s ago that expired 60 s ago and one with a 420 s life; a fresh one with the same claims is accepted (200), so the refusal is the age;
   - a sign-in without MFA: the admin exchange answers `invalid_grant` "step-up authentication is required", the Console shows the step-up banner, an admin page gets nothing, and the person's `tutela-authz` token is refused on the admin API (403);
   - no Content-Security-Policy violation (a `securitypolicyviolation` listener in every page) and no page error.
5. **Screenshots** of the main pages, light and dark, are written when `TUTELA_E2E_SHOTS` names a directory; never into the repo.

**Consequences.**
- `make` needs Playwright's Chromium 1243 besides node and pnpm.
- The check proves the Console against a provider shaped like Keycloak 26, not Keycloak itself: a real Keycloak stays [#87](https://github.com/f8fvwgzc/tutela/issues/87).
- The measured delay is printed in the run's log.

**Alternatives considered.**
- **The installed Google Chrome (`channel: "chrome"`).** It works, but its version moves under the test; the pinned build does not.
- **Wait six minutes for a real admin token to age.** It would make `make` six minutes longer for one assertion.
- **The `tutelad` binary as a separate process.** `ha.rs` already runs it; in-process gives the test the key ring for the minted tokens, and the library is the binary's code.

---

## ADR-0054: CORS: exact origins from configuration, off by default, never credentials

**Status:** Accepted, 2026-11-07. Phase B, part 4b2 ([#135](https://github.com/f8fvwgzc/tutela/issues/135)). It answers what [ADR-0048](#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice) and [ADR-0049](#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people) left open: a product page on another origin that embeds the components had to proxy `tutelad`.

**Context.** `@f8fvwgzc/tutela-js` sends its token in `Authorization` with `credentials: "omit"`, so no cookie of the page's origin ever reaches `tutelad`. A browser still refuses to give the page an answer from another origin without CORS headers, and sends a preflight before a request with `Authorization` or JSON. The preflight carries no token. TM-06 wants nothing that lets a hostile page act with someone's session.

**Decision.**

1. **Off by default.** `TUTELA_CORS_ORIGINS` is a comma-separated list of exact origins, `scheme://host[:port]`: `https`, or `http` only on loopback in dev mode. `*`, `null`, a wildcard host, a path, a trailing slash or credentials are refused at start-up.
2. **Only a listed origin gets headers**, and the answer names that origin, never `*`, with `Vary: Origin`. It may read `etag`, `retry-after`, `x-request-id` and `www-authenticate` besides the safe headers. A refusal (401, 403, 503) carries them too, so the page can tell why.
3. **Never credentials.** `Access-Control-Allow-Credentials` is never sent. A listed page can only use a token it holds; a cookie would not reach `tutelad` anyway.
4. **A listed origin's preflight is answered without a token**, 204, with the methods of the HTTP API, the headers the client sends (`authorization`, `content-type`, `if-none-match`, `x-request-id`, `traceparent`) and a 600 s cache. It holds no data. Any other `OPTIONS`, and any other origin's preflight, goes to the token check as before (401).
5. **Not for gRPC or the Console**: gRPC is for services, and `/console/` is same-origin with its own headers (ADR-0050).

**Consequences.**
- A product lists its page origins and passes `tutelad`'s URL as `baseUrl`; the proxy of JS-SDK.md stays an option.
- A listed origin with an XSS can call `tutelad` with the tokens that page holds, as it could through a proxy; CORS adds no reach beyond them.

**Alternatives considered.**
- **A wildcard or a pattern of origins.** One typo or a takeover of a subdomain would open the API to it; exact origins are simple to review.
- **Allow credentials.** Nothing uses a cookie at `tutelad`; allowing them would only add a risk if one ever did.
- **`tower-http`'s CORS layer.** It needs another feature of the crate and answers preflights for any path on its own rules; twenty lines keep the rules here and tested.

---

## ADR-0055: The OCI image: three stages, a distroless runtime, the Console on, and publishing left to a release

**Status:** Accepted, 2026-11-07. Phase B, part 4c ([#49](https://github.com/f8fvwgzc/tutela/issues/49)). It builds the image the notes for part 4c plan ("What the image must copy").

**Context.** The README lists `ghcr.io/f8fvwgzc/tutelad` as a package of Phase B: the service and the Tutela Console. The Console is read from `TUTELA_CONSOLE_DIR` once at start (ADR-0050) and is built by node 22.12 and pnpm 10.18 (ADR-0047); `cargo build` never runs node. `deploy/tutelad.env` sets `RUST_BACKTRACE=1` and `RUST_LIB_BACKTRACE=0`. GitHub Actions cannot run (billing), so nothing in CI builds or pushes an image. Image pulls hung on the owner's Mac: it was the Docker CLI's credential helper (`credsStore: desktop`), not the network; with an empty `DOCKER_CONFIG` pulls work.

**Decision.**

1. **One `Dockerfile` at the repo root, three stages.** `console`: node 22.12 (bookworm-slim) installs pnpm 10.18.1, runs `pnpm install --frozen-lockfile` (the lockfile, the one-week release age and no install scripts of ADR-0047 hold) and `pnpm -r run build`, and checks that `console/dist/index.html` is there. `build`: Rust 1.99.0 (the version `rust-toolchain.toml` pins) runs `cargo build --release --locked -p tutelad`, with cache mounts for the registry and `target/`. The runtime gets only `/usr/local/bin/tutelad` and `/srv/tutela/console/`. `.dockerignore` keeps `target/`, `node_modules/`, `.git` and the docs out of the context.
2. **The runtime is `gcr.io/distroless/cc-debian12:nonroot`**: glibc, `libgcc`, CA certificates and tzdata, no shell and no package manager, user `65532:65532`. `tutelad` is linked against glibc (aws-lc-rs and rustls), so `static` would need a musl build; `cc` is the smallest image that runs the glibc binary. The TLS roots are the image's CA bundle, which the base image names in `SSL_CERT_FILE`; a private CA (a database's) is added with `SSL_CERT_DIR` naming its directory, and `rustls-native-certs` then reads both.
3. **Base images pinned by digest**, each an image index (linux/amd64 and linux/arm64), as build arguments (`NODE_IMAGE`, `RUST_IMAGE`, `RUNTIME_IMAGE`) so a mirror can be named. A digest changes on purpose, in a pull request.
4. **What the image sets**: `RUST_BACKTRACE=1`, `RUST_LIB_BACKTRACE=0`, `TUTELA_LISTEN=0.0.0.0:8080`, `TUTELA_OPS_LISTEN=0.0.0.0:9090` and `TUTELA_CONSOLE_DIR=/srv/tutela/console`, as the notes say. So the Console is **on** in the image: start-up then needs `TUTELA_CONSOLE_ISSUER`, `TUTELA_CONSOLE_CLIENT_ID` and `TUTELA_ADMIN_ACR` (ADR-0050). An empty `TUTELA_CONSOLE_DIR` turns it off; `deploy/tutelad.env` now sets it empty, so Compose starts without the Console until its settings are made. `ENTRYPOINT ["/usr/local/bin/tutelad"]`, `CMD ["serve"]`: the same image runs `tutelad migrate`, `tenant` and `apps`, so the Helm chart's bootstrap job needs no image of its own. The `tutela` CLI is not in the image.
5. **No `HEALTHCHECK`.** Kubernetes probes `/healthz` and `/readyz` on the ops port; a shell-less image has no command to run one with anyway.
6. **OCI labels**: `title`, `description`, `source`, `url`, `documentation`, `licenses` (MIT), `vendor`, and `version` and `revision` from build arguments.
7. **Checked by `make`**: `make image-lint` runs `hadolint Dockerfile`, skipped without hadolint unless `TUTELA_REQUIRE_HADOLINT=1`, like the database tests; `config::tests::the_image_stays_true` checks the settings above, the non-root user, no `HEALTHCHECK` and the digests under plain `cargo test`.
8. **Publishing is a release step, not done here.** A release builds both platforms from the tag and pushes to `ghcr.io/f8fvwgzc/tutelad` with the version and the digest recorded in the release notes:

   ```sh
   git checkout v0.2.0
   echo "$GHCR_TOKEN" | docker login ghcr.io -u f8fvwgzc --password-stdin   # a token with write:packages
   docker buildx build --platform linux/amd64,linux/arm64 \
     --build-arg VERSION=0.2.0 --build-arg REVISION="$(git rev-parse HEAD)" \
     -t ghcr.io/f8fvwgzc/tutelad:0.2.0 --push .
   docker buildx imagetools inspect ghcr.io/f8fvwgzc/tutelad:0.2.0   # the digest for the release notes and the chart's image.digest
   ```

   No `latest` tag: deployments name a version, and the chart its digest. When Actions can run, a workflow on a `v*` tag does the same with `GITHUB_TOKEN` (`packages: write`), and may add provenance and an SBOM (`--provenance --sbom`).

**Consequences.**
- One image serves, migrates and bootstraps; a new Console is a new image.
- A deployment that uses the image and not the chart must set the Console's three settings or empty `TUTELA_CONSOLE_DIR`.
- The image is not published until the owner runs the release step; `deploy/compose.yaml` and the chart name `ghcr.io/f8fvwgzc/tutelad:<version>`.

**Alternatives considered.**
- **`scratch` with a static musl binary.** No CA certificates or tzdata unless copied by hand, and a second libc to build aws-lc-rs for.
- **`debian:bookworm-slim` as the runtime.** It has a shell and apt: more to patch and more to use after a break-in.
- **The Console off in the image, on in the chart.** The notes for part 4c set `TUTELA_CONSOLE_DIR` in the image; an empty value turns it off where it is not wanted.
- **A `HEALTHCHECK` with a small probe binary.** Kubernetes ignores it, and Compose users can probe the ops port from outside.

---

## ADR-0056: The Helm chart and its bootstrap job: a pre-install hook that makes only what is missing

**Status:** Accepted, 2026-11-07. Phase B, part 4c. It builds the chart and the job the notes for part 4b ("For part 4c") and the notes for part 4c plan, on the image of [ADR-0055](#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release). It **departs from the notes** in three places, each said below: the tenant id comes from the values (item 3), webhooks are registered in-process rather than over `POST /v1/admin/webhooks` (item 7), and the Keycloak client is shipped as an import file rather than made by the job (item 9).

**Context.** The README names the chart `oci://ghcr.io/f8fvwgzc/charts/tutela`. The service needs `deploy/tutelad.env`'s settings, the Console's (the notes for part 4c), a trust file and three secrets; migrations run as the owner role apart from the service (TM-14); the operator makes the tenant and the apps (ADR-0041, ADR-0044), and a secret is shown once. Products read their client secret from a Kubernetes Secret. GitHub Actions cannot run.

**Decision.**

1. **`deploy/helm/tutela`, chart `tutela` 0.2.0, appVersion 0.2.0.** Secrets are never values: `secrets.*` names Secrets the operator makes (the service database URL, the owner's for the job, the master key, the pepper, optionally the previous master key, the ledger token and a database CA). Every setting of `deploy/tutelad.env` is under `config` with the file's value as its default (checked), and never `TUTELA_AUDIT_KEY` (ADR-0045). The defaults are `example.com` examples so that `helm template` renders; `NOTES.txt` warns while one is in use. `helm template` refuses fewer than 2 replicas, `revisionCheckMs` above 1000, a tenant id that is not a UUIDv7, an http issuer outside dev mode, the Console without `TUTELA_ADMIN_ACR`, the ledger without its token, and no first owner.
2. **The trust file** is a ConfigMap: the realm as the notes say (`external = true`, `allow_typ_jwt = true`, `algs = ["RS256"]`, one tenant, its `jwks_uri`; its host in `private_hosts` with `keycloak.privateNetwork`), then the extra `trust.issuers` and `trust.audiences`. `TUTELA_CONSOLE_ISSUER` is the same realm value.
3. **The tenant id is a value** (`tenant.id`, from `tutelad tenant new-id`), not made by the job: the trust file must name the tenant before it exists. `tutela_store::create_tenant_with_id` and `tutelad::lifecycle::create_tenant_with_id` make a tenant with an id the operator chose, refused when the id is in the directory in any state.
4. **The job is `tutelad bootstrap`** in the same image (CONTRACTS.md 7.13.9): migrate, the tenant with its first owners (`tenant.owners`, Keycloak user ids of the realm, as `--admin-upstream`), each app of `apps`, each role of its service account, each webhook of `webhooks`, and the Console's URL printed. One JSON line per step, never a secret.
5. **A `pre-install,pre-upgrade` hook**, not `post-install`: the schema is migrated before the new version's pods start (a new version on an old schema could fail its readiness or worse), and the tenant and apps exist before anyone signs in. Its plan ConfigMap, ServiceAccount, Role, RoleBinding and NetworkPolicy are hooks of weight -10 removed when the hooks succeed; the Job (weight 0) stays until the next run, for its log. `helm uninstall` leaves the last Job and the Secrets the job wrote: the tenant lives in the database, and the products' credentials outlive a reinstall.
6. **Idempotent.** An enabled app found by name is kept when its Secret names it; a missing Secret (or one naming another app) means a rotation with the usual one-hour overlap, because a secret is shown once. A role is given only when the service account has no assignment at that scope; an owner's later change is kept (`left`). A webhook found by URL is kept or rotated the same way. The tenant is never changed after it is made: its name and owners are the Console's then. Every change is recorded in the tenant's chain by `tutelad`, as the operator, like `tutelad tenant create`; roles are given as the first owners are, above the tenant (ADR-0041), so the narrow-only rule of the admin API does not apply.
7. **Webhooks are registered in-process.** The notes say a webhook secret comes from `POST /v1/admin/webhooks` with an app's token; in a pre-install hook no `tutelad` is serving yet. The job calls the same store function after the same `tutela-safenet` check of the URL and its DNS answer (CONTRACTS.md 8.5), with the app's service account as the actor of the record. A product may still register its own webhooks over the API.
8. **The job writes Secrets through the Kubernetes API itself** (`tutelad::bootstrap::kube`): `GET`, `POST` and, on 409, `PUT` of `/api/v1/namespaces/<ns>/secrets`, with the pod's service account token, trusting only the cluster CA, never through a proxy, refusing a name that is not a Kubernetes name. Its Role allows `get` and `update` on the named Secrets and `create` (which Kubernetes cannot limit by name), nothing else; the service's own account mounts no token. An app's Secret has `client_id`, `client_secret`, `principal`, `tenant`, `issuer` and `token_url`; a webhook's `webhook_id`, `secret` and `url`. `--secrets-dir` writes files instead (tests, a deployment without Kubernetes).
9. **The Console's Keycloak client is an import file, not admin API calls.** The chart renders, in the ConfigMap `<release>-keycloak-client`, a Keycloak partial import (`ifResourceExists: SKIP`) with the client exactly as the notes say: public, standard flow only (no implicit flow, no direct access grants, no service account), `pkce.code.challenge.method: S256`, redirect URI `https://<host>/console/callback`, web origin `https://<host>`, post-logout redirect URI `https://<host>/console/`, an audience mapper adding `TUTELA_AUDIENCE` to the access token, and the client's ACR-to-LoA mapping naming the first value of `TUTELA_ADMIN_ACR` at `keycloak.stepUpLevel`. A realm admin imports it once (`kcadm.sh create partialImport`). Why: calling the admin API needs a Keycloak admin credential inside the cluster, and the import can be checked without a Keycloak, which this repo cannot run ([#87](https://github.com/f8fvwgzc/tutela/issues/87)). **Not covered:** the realm's browser flow that asks for OTP at that level; a partial import cannot carry a flow, so the realm admin sets it.
10. **The pods**: `replicaCount` 2 by default, a rolling update with `maxUnavailable: 0`, preferred anti-affinity by host; probes on the ops port (startup and liveness `/healthz`, readiness `/readyz`); uid/gid 65532, `runAsNonRoot`, read-only root filesystem, no privilege escalation, every capability dropped, seccomp `RuntimeDefault`, no service account token, a small in-memory `/tmp`; a grace period of the drain plus the timeout plus 5 s; a checksum of the settings so a change rolls the pods. The job has the same security context.
11. **Around them**: a Service with the API port only (the ops port stays off it); an optional Ingress with one `/` prefix rule to that port and no annotation that adds or loosens a header (the Console's CSP is `tutelad`'s, ADR-0050); a PodDisruptionBudget (`maxUnavailable: 1`); a NetworkPolicy that lets everyone (or `apiFrom`) reach the API port, only `opsFrom` reach the ops port, and lets the pods out to DNS, the database port and 443; the job's own policy lets it out to DNS, the database and the API server (443, 6443).
12. **A database with a private CA**: `secrets.databaseCA` is mounted and named in `SSL_CERT_DIR`; with the image's `SSL_CERT_FILE` both are trusted (ADR-0055 item 2). A database not on the pod's host needs `sslmode=require`, as everywhere (ADR-0018).
13. **Checked by `make helm`**, part of `make`: `scripts/helm-check.mjs` runs `helm lint` and `helm template` with the default values and with `ci/production-values.yaml`, and checks the rendered manifests: every key of `deploy/tutelad.env` and of the Console in the ConfigMap (the defaults equal the file), no Secret made and no secret inlined, the pods' security settings and probes, the trust file, the job's hook, command and environment, the plan, the Role, and every field of the Keycloak client; and that the wrong values above are refused. Without helm it is skipped unless `TUTELA_REQUIRE_HELM=1`. `crates/tutelad/tests/bootstrap.rs` runs the job against a real Postgres (made, kept, rotated, left, refused), and `bootstrap::kube` has unit tests against a fake API server. A run in a kind cluster was done by hand for part 4c (the PR says what it showed); it is not part of `make`.
14. **Not published here.** A release packages and pushes the chart: `helm package deploy/helm/tutela && helm push tutela-0.2.0.tgz oci://ghcr.io/f8fvwgzc/charts`, after the image of the same version (ADR-0055 item 8); set `image.digest` to the pushed image's digest.

**Consequences.**
- An install needs the operator's Secrets, a tenant id, the realm and the first owner's Keycloak id; the products' charts read their Secrets by name.
- The job holds the owner's database URL and the master key for its run; the service never holds the owner's URL.
- Re-running the job is safe; deleting a product's Secret and upgrading gives it a new secret, and the old one ends within an hour.
- The realm's step-up flow and the client import are the realm admin's work, outside the chart.

**Alternatives considered.**
- **A post-install hook calling the admin API with an app's token.** The schema would not be migrated before an upgrade's pods start, and the first app's token needs an app first.
- **`kubectl` in a second image to write the Secrets.** Another image to pin and pull, and a shell to pass secrets between containers.
- **Helm generates the client secrets (`randAlphaNum` with `lookup`).** The secrets would sit in Helm's release records, `lookup` is empty under `helm template` (Argo CD), so every render would rotate them, and `tutelad` would have to accept a secret it did not make.
- **The job makes the tenant and writes its id somewhere.** The trust file is rendered before the job runs and must name the tenant.
- **Keycloak's admin API from the job, or the Keycloak Operator's `KeycloakRealmImport`.** The first needs a realm-admin credential in the cluster; the second makes whole realms only, and neither can be tested here.

