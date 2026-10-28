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

