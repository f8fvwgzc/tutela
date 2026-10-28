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
| [0012](#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening) | Manifest v1: seeded roles, org-root rules, and what counts as widening | Accepted |
| [0013](#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits) | The evaluator: deciding roles, reasons, scope paths and Phase A limits | Accepted |

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

1. **One code path.** `check`, `write_check` and `list_filter` use the same functions for the walk (closest assignment wins, a private scope stops inheritance, the org Owner path), for each role's conditions, and for field levels (`Model::effective_field_level` at each role's own item level after its own conditions, then the closest field rule). `list_filter` asks the same "is this role allowed" question level by level (`Model::allows_custom_at` at each item level for custom actions). The differential property test proves `list_filter` ≡ `check` on random worlds.
2. **Deciding roles at one scope** ([PERMISSION-MODEL.md §6.3](PERMISSION-MODEL.md#63-role-assignments)): the direct assignment wins; else every group role there counts. Each role is evaluated on its own. They combine component-wise: the highest item level, the highest level per field and feature, a custom action allowed when any role allows it at its own item level after its own conditions (raw grants are never pooled), and admin keys as a union.
3. **Gone roles.** An assignment whose role the model no longer has, or whose role may not be given to that kind of subject (`assignable_to`, checked when the role is used), still decides its node and gives None and no grants.
4. **The org Owner** is a `user` with a direct `owner` assignment at the org root. Other principal kinds (service accounts, keys, workloads) with `owner` at the org root walk the tree like everyone else, so private scopes stop them.
5. **Agents and delegation.** Admin keys and owner-only custom actions never go to an `agent` principal, as subject or as actor, however the role was reached, and never through delegation. A delegated request needs a `user` subject and 1 to 4 `agent` actors; anything else is an error. The overlap: the item level is the lowest, each field level is the lowest, and the action is allowed only if the person and every actor allow it.
6. **`ai_reach` only narrows.** With "closest assignment wins", an agent's deciding scope is always on the resource's path, so `project` reach holds by itself. The evaluator adds one rule: an agent whose closest assignment is at the org root gets None (`outside_ai_reach`), because `ai_reach` is never the whole org. `team` reach never adds access. If `team` should open sibling scopes where the agent has no assignment, that is a widening rule and needs its own decision.
7. **Conditions.** The model's conditions sit at the org root and apply in every scope. A condition that names a group the tenant does not have is false as a whole, in `check` and in the filter. Conditions at one scope are not in Phase A.
8. **Reason codes for several roles** ([CONTRACTS.md §6.2](CONTRACTS.md#62-reason-codes)): `no_role` also when every deciding role is gone (the detail names the assignments); for a custom action, `missing_grant` when no deciding role holds the grant, else `condition_failed` or `level_too_low` judged on the roles that hold it, and the detail says so when another role has the level but not the grant; `delegation_overlap` when the person is allowed and an actor is not, except that the actor's own `outside_ai_reach` or `admin_only` is passed on.
9. **Tenant data until `tutela-store`.** The evaluator reads `TenantData`: the tenant's orgs, role assignments, groups, private scopes and field rules at single scopes. A scope is private only when it is listed (`tutela-store` records it when the scope is made, from its type's `starts`). Group keys are unique in the tenant in Phase A. Field rules at the org root come only from the manifest. Loading refuses two assignments for one (subject, scope), unknown groups, group cycles, `org` scopes that are not the tenant's, and a revision lower than one loaded before (no going back). A resource whose path ends at an org that is not the tenant's is denied with `tenant_mismatch`.
10. **Scope paths (ADR-0011 F1).** `list_filter` takes a provider keyed by (tenant, type, id). It asks for the path of every scope where the principal has an assignment and of every private scope of the tenant, each at most once per call. A provider error, a path longer than 32, a path that does not end at the tenant's own org, or a malformed path makes `list_filter` return `PdpError::ScopePath`: the list fails closed. CONTRACTS.md §6.6 says so.
11. **Filter limits** (CONTRACTS.md §6.6) are enforced; above one, `list_filter` returns `PdpError::FilterTooLarge` and the list fails closed. Measured: the benchmark tenant's largest filter had 39 condition nodes, depth 7 and 490 entries; the week-1 spike's largest had 1,150 nodes. A valid manifest can still pass the limits: each nesting level of a principal's deciding scopes repeats the conditions of its conditioned roles, so one role with 200 conditions at 8 nested scopes gives about 4,800 nodes (a test shows the list fails closed and `check` still answers). **The limits stay, and the manifest is not bounded further**, because the size grows with the bindings (nesting levels times conditioned roles), which the manifest cannot bound. A warning for admins when a principal's filter nears the limits is later tooling (Phase B, Tutela Console).
12. **Obligations in Phase A.** On an allow: `label` with the highest sensitivity among the readable data fields, and for a delegated request `audit` with `on_behalf_of`. `restricted` and `recheck_online` are not sent yet; masked fields are removed, which is the safe default.
13. **`write_check`.** Each changed field needs Write for the person and every actor. A `grants_access` field also needs the admin key `<type>:manage_access`, so agents and delegated tokens never change one. A name that is not a declared data field of the type (a feature, an unknown field) is denied. A write with no changed field is an error. **A move (`new_path`) is an error** until boundary rules (`moves_out`, `moves_in`, `on_looser`) exist with `tutela-store`: without them a move into a looser scope could leak, so it is refused.
14. **No cache across calls.** Each call resolves each (principal, scope) once. Without a cache, `check` has p99 12–17 µs on the benchmark tenant (below). A decision cache belongs to `tutela-sdk` (ROADMAP item 6), with the revision in its key.
15. **Rule ids of model rules.** Conditions and org-root field rules come from the manifest and have no stored ids. Decisions name them `model:condition:<n>` and `model:field_rule:<n>`, the index in the compiled model, valid for that revision only.

Benchmark (`cargo bench -p tutela-pdp`; information, not a gate run: another session's build overlapped part of the second run): Apple M2 Pro, 10 cores, 16 GiB, macOS 26.6.2, Rust 1.99.0 release. A tenant of 5,000 users in 200 groups nested 6 deep, 50 agents, 65 roles (60 declared) and 43 types, 10,000 assignments, 300 private scopes, 500 field rules at single scopes, 2,100 scopes with paths up to 31 and 20,000 items. Two runs: `check`, mixed (16% allowed): p99 11.9–12.0 µs. `check`, allowed calls only: p99 15.5–16.0 µs. `check`, allowed delegated calls (a user and an agent assigned at the same project): p99 12.5–16.7 µs. `write_check` of two fields, delegated: p99 3.0–3.3 µs. `list_filter` with an in-memory provider: p99 0.46–0.49 ms, mostly placing the 300 private scopes. The slowest single `check` was 7 ms, in the run with the other build.

**Consequences.**
- [PERMISSION-MODEL.md open point 1](PERMISSION-MODEL.md#19-open-points) is closed.
- The property tests of the library gate exist in `tutela-pdp`: `tm10_list_filter_returns_exactly_the_rows_check_allows` (with a fixed-seed run that counts deep paths, private scopes inside private scopes, groups, gone roles, `not` over often-null fields, the overlap, the org Owner and assignments on the row itself), `tm05_no_cross_tenant_grant` (two tenants with the same resource ids), `tm03_delegation_is_at_most_person_and_agent`, and `tm08_a_change_the_diff_calls_safe_never_widens`, which ties the diff of ADR-0012 to the evaluator: a change the diff does not call widening never widens a decision. Six bugs planted on the list side were each caught by the differential test.
- `tutela-store` (item 5) must record private scopes, keep group keys unique in the tenant (or change this ADR), and provide scope paths by (tenant, type, id). `list_filter` asks for every private scope of the tenant on each call, so its cost grows with the number of private scopes; the store should index private scopes by org or by ancestor before large tenants.
- Moves stay refused until boundary rules exist. Break-glass for the org Owner, disabled principals (token step 1, `tutela-sdk`), clearance for labelled output, and signed bundles with expiry (Phase B) are not in this evaluator.
- The week-1 spike code (`spike/week1/`) may be deleted once this lands, as ADR-0011 planned.

**Alternatives considered.**
- **Copy the spike evaluator.** It picked one whole group role (ADR-0012 rejects that), capped features by the item level, and treated a missing path as an empty one.
- **Let `team` reach open sibling scopes.** That widens access through a boundary setting; not done without a decision of its own.
- **Cache levels per (principal, scope) across calls.** Not needed for the latency gate, and a cache is one more place for a stale allow.
- **Bound the manifest (conditions per role and type) to keep filters small.** It does not bound the filter, which also grows with the bindings.
