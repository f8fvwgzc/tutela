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
- `crates/tutela-pdp/mutants/mutants.py` plants 26 bugs (in the walk, conditions, field rules, delegation, tenant checks, request checks, loading, the group closure, the write mask, the placer and the filter) and runs the tests against each; `results.txt` next to it is the committed output. Every one is caught. One guard cannot be a mutant: "admin keys and owner-only actions never pass through delegation" is also kept by the compiler (a role that holds them is never given to an agent, and every actor is an agent), so removing the evaluator's guard alone changes no answer. It stays as defense in depth.
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
5. **Readiness needs the exact schema.** `/readyz` fails unless the newest migration in the database is the one this build knows. This keeps ADR-0014's rule that an old binary never writes to a newer schema. So during an upgrade, old replicas go not ready when the migration lands. Rust products keep answering from their bundles; the deploy should start new replicas right after the migration.
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
