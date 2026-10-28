# Tutela roadmap

Status: **pre-alpha**. As of the first commit, only the design docs, the `tutela-contracts` crate and CI exist. Nothing is usable in production yet.

This file lists the four phases (A, B, C, D), what each one builds, how we know it is done, and how long it takes. The reasons behind the big choices are in [DECISIONS.md](DECISIONS.md). The design is in [ARCHITECTURE.md](ARCHITECTURE.md) and [PERMISSION-MODEL.md](PERMISSION-MODEL.md).

Other docs: [README](../README.md) · [AGENTS](../AGENTS.md) · [SECURITY](../SECURITY.md) · [CONTRACTS](CONTRACTS.md) · [THREAT-MODEL](THREAT-MODEL.md) · [INTEGRATION](INTEGRATION.md)

## Overview

| Phase | What it delivers | Effort (person-weeks) | Required? | Gate at the end |
|---|---|---|---|---|
| A | Packages, library mode | about 10–12 | Yes | Library gate |
| B | `tutelad` service + Tutela Console | about 9–12 | Yes | Service gate |
| C | Tutela's own login server (OIDC provider) | about 8–12 | **Optional** | Login-server gate |
| D | Hardening | about 6–9 | Yes | v1 release |

- A "person-week" (pw) is one week of work for one strong engineer.
- Honest total for Tutela alone: **about 35–45 person-weeks**.
- If Keycloak stays the login server for good, Phase C is skipped. That saves about 8–12 pw. It does **not** remove the token-exchange service or delegated agent tokens: those are in Phase B (see [ADR-0006](DECISIONS.md#adr-0006-delegated-agent-tokens-in-phase-b-not-optional)).
- These numbers do not include the work in the other repos to adopt Tutela. That is listed in [Adoption by the other repos](#adoption-by-the-other-repos).

## The three gates

A gate is a list of checks. A phase is not done until its gate passes. No product or other core installs a Tutela package or service before the matching gate passes.

| Gate | Covers | Checks |
|---|---|---|
| **Library gate** (end of A) | Crates and SDKs: `tutela-pdp`, `tutela-sdk`, `tutela-store`, `tutela-vault`, `tutela-safenet`, `tutela-contracts`, `@f8fvwgzc/tutela-*`, `tutela-py` | Fuzzing of the model compiler, token verifier and SQL filter compiler. Property tests (no cross-tenant grant, no widening, delegation ≤ person AND agent, `list_filter` ≡ `check`). `check` p99 under 1 ms in process. List query in Postgres: p99 under 100 ms at the `list_filter` limits on the reference machine (table size fixed by item 6, for example 100k rows per tenant and 20 tenants), with the statement timeout failing closed ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F2). |
| **Service gate** (end of B) | `tutelad` and the Tutela Console | Row-level security (a query with no tenant set returns zero rows; a cross-tenant read fails at RLS even with an injected code bug). Group and path closure p99. High availability: 2+ replicas, bundle expiry, a revoked role takes effect within the documented delay. |
| **Login-server gate** (end of C) | `tutelad` as an OIDC provider | OpenID Foundation Basic OP + Config OP conformance in CI. Fuzzing. An external security review. A key-restore drill. Swapping Keycloak for `tutelad` is a config change only. |

## Phase A: packages, library mode

**Goal.** A product can sign people in through Keycloak (or any OIDC issuer) and check permissions in its own process, with no `tutelad` running. The permission model comes from a file.

**Effort.** About 10–12 pw. About 5–7 calendar weeks with AI help. After this, a first product can start building on Tutela.

**Work list.**

| # | Item | Notes |
|---|---|---|
| 1 | First commit | Repo, docs, `tutela-contracts`, blocking CI. **Done.** See [First-commit checklist](#first-commit-checklist). |
| 2 | Week-1 spike | Go/no-go numbers before more code. **Done: go** ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator)). |
| 3 | Model language and compiler | Reads `tutela.resources.toml`: tenant-defined resource types, roles, field rules, boundary rules, condition templates, UI keys. Rejects condition templates that the SQL filter cannot express. Detects widening changes. **Done:** format v1 in [MANIFEST.md](MANIFEST.md), compiler in `tutela-pdp` (module `model`). Per-scope rules and bindings are `tutela-store` data (item 5). A valid manifest can still produce a `list_filter` above the CONTRACTS §6.6 limits; item 4 measured it and keeps the limits, failing closed ([ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening), [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). |
| 4 | `tutela-pdp` | The native evaluator: `Pdp::check`, `Pdp::batch`, `Pdp::list_filter`, `Pdp::write_check`. Resolves the effective level once per (principal, scope). Emits the decision and the SQL filter from the same code. Evaluates delegation as person AND agent. `list_filter` takes a scope-path provider that fails closed ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F1). **Done:** [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits), with the property tests (`list_filter` ≡ `check`, no cross-tenant grant, delegation ≤ person AND agent, no widening) and benchmarks in `tutela-pdp`. Moves wait for boundary rules (item 5). |
| 5 | `tutela-store` | Postgres schema and migrations for bindings, field rules and groups. The same schema `tutelad` uses later. It fills the evaluator's `TenantData` ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)), with tests for each of these: the private flag is written in the same transaction as the scope and the revision bump; a deleted scope leaves the tenant data in the same revision; group keys are unique in the tenant, groups nest at most 32 deep, and the closure holds at most 1,000,000 pairs and takes at most 4,000,000 steps to compute; scope paths for `list_filter` are current after a move. It also indexes private scopes by org or ancestor, so `list_filter` does not ask for every private scope of the tenant. **Done:** schema `tutela` with numbered migrations, forced row-level security on every tenant table, checked writes in the product's own transaction, scope paths with `move_scope`, the applied manifest and `model_revision` ([ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)). The `scope_path` GIN index is in; `list_filter` still places every private scope ([#6](https://github.com/f8fvwgzc/tutela/issues/6)). Boundary rules for moves and links: the `boundary_rule` columns are in, but `write_check` still refuses moves until the impact calculation (Phase B). |
| 6 | `tutela-sdk` | Token verifier for any OIDC issuer, with a trust list that maps each issuer to the tenants it may speak for. axum and tonic layers. Decision cache. Refuses `typ: agent+jwt` unless delegation support is on. The SQL adapter for `list_filter`: bound parameters only, a statement timeout that fails closed, and a query plan that is fast at the filter limits; it also defines the gate benchmark (table size, tenants, reference machine) ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F2). |
| 7 | `tutela-vault` | Envelope encryption with a KMS trait. Ported from the design of onto-intelli `crates/onto-control/src/vault.rs`. |
| 8 | `tutela-safenet` | SSRF-safe outbound HTTP. Ported from onto-intelli `crates/onto-control/src/net.rs` and `crates/onto-intelli/src/net.rs`. |
| 9 | Codegen and CLI | `tutela init`, `tutela apply` (library mode: shows the diff and refuses a widening diff without an approval token), `tutela codegen`. Codegen makes the React constants and the server route guards from the same UI-key entry, plus a test that calls each route as a denied principal. **Built:** `init`, `check`, `migrate`, `apply` with approval tokens ([ADR-0015](DECISIONS.md#adr-0015-approval-tokens-for-tutela-apply-in-library-mode)). **Next:** `codegen`. |
| 10 | JS and Python SDKs | `@f8fvwgzc/tutela-react` (`<Can>`, `<Field>`, `<Protect>`, `useCan`), `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js`, `tutela-py`. Shared test vectors so Rust, TypeScript and Python give the same answers. |
| 11 | Product template | A small product that uses all of the above. |

**Exit criteria.**

- The template product signs in through Keycloak, checks permissions in process, and renders `<Can>` and `<Field>` correctly.
- Property tests pass: no cross-tenant grant, no widening, delegation ≤ person AND agent, `list_filter` ≡ `check`.
- The library gate passes.
- v0.1 is tagged and signed.

## Phase B: `tutelad` service and Tutela Console

**Goal.** Tenants define and change roles at runtime. Non-Rust apps check permissions over the network. Agents get delegated tokens.

**Effort.** About 9–12 pw.

**Work list.**

- Tenants with row-level security: `tenant_id` on every row, `FORCE ROW LEVEL SECURITY`, tenant set with `SET LOCAL` per transaction from the verified token.
- Bindings and groups store with a per-tenant revision.
- AuthZEN 1.0-shaped API: `/access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/resource`, `/access/v1/search/subject`; gRPC `tutela.authz.v1`.
- Permission map for UIs: `POST /v1/authz/permissions` with ETag/304.
- Model versioning, impact report ("12 users gain read on contract"), explain and simulate, two-person publish (optional per tenant).
- Moves and links across scopes: `moves_out`, `moves_in`, `on_looser` and `links_from` from `boundary_rule`, checked in `write_check` with the before/after impact calculation (PERMISSION-MODEL §9, §10). Assignment expiry with a revision bump when it passes ([ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)).
- CLI: `tutela apply` against `tutelad` (adds the impact report and approvals; still refuses a widening diff without an approval token), `tutela apps create`, `tutela keys rotate`.
- Webhooks (transactional outbox, Standard Webhooks signatures) and SSE `/v1/events`.
- Local hash-chained audit log. Optional forwarding to attache's evidence ledger through its Append API.
- **Token-exchange service**: accepts the Keycloak token and issues a short-lived Tutela access token, with just-in-time user provisioning.
- **Delegated agent tokens** (RFC 8693, `act` claim, `typ: agent+jwt`, only for `delegation_aware` audiences). Not optional.
- Org lifecycle events (`tutela.org.created|updated|deleted.v1`, `tutela.user.deleted.v1`, ...).
- Tutela Console, plus embeddable admin components (RoleEditor, MembersTable, permission matrix) using a separate `aud=tutela-admin` token.
- A Helm bootstrap job that creates client credentials and webhook secrets before other charts start.

**Exit criteria.**

- Sign-in, the UI permission map and runtime role editing pass end to end.
- A cross-tenant read fails at RLS even with an injected code bug.
- A revoked role takes effect within the documented delay.
- 2+ replicas run.
- The service gate passes.

## Phase C: own login server (optional)

**Goal.** `tutelad` becomes the OIDC provider, so Keycloak is no longer needed. This phase is optional. Keycloak 26.x can stay the login server for good.

**Effort.** About 8–12 pw.

**Work list.** Authorization code + PKCE S256 only. Exact redirect-URI match. `state` and `nonce` required. RFC 9207 `iss`. Single-use codes (≤ 60 s). Rotating refresh tokens with family revocation. `client_credentials`. RFC 9068 `at+jwt`. Signing keys per tenant behind a `Signer` trait (ES256 default, RS256 always published, EdDSA allowed). Key pre-publication and a kid deny-list. Argon2id passwords, TOTP and recovery codes, passkeys (webauthn-rs), SMTP outbox (lettre). Details: [ARCHITECTURE.md](ARCHITECTURE.md) and [THREAT-MODEL.md](THREAT-MODEL.md).

**Exit criteria.** The login-server gate passes. Nobody uses the Tutela login server before that.

**Before Phase C starts:** the owner decides the `tutelad` licence ([ADR-0010](DECISIONS.md#adr-0010-licence-mit-now-permissive-sdks-forever-tutelad-licence-open)).

## Phase D: hardening

**Goal.** Tutela is safe to run for other people. This phase is not optional.

**Effort.** About 6–9 pw.

**Work list.** Webhook hardening. Load and soak tests. Helm chart and compose file. Backups and restore drills. Docs. SCIM comes after v1.

**Exit criteria.** Soak tests pass. A backup restore drill passes. v1 is tagged and signed.

## Out of v1

These are not in v1. Each may come later if a real user needs it.

| Item | Instead, for now |
|---|---|
| SAML | Broker it through an upstream OIDC IdP |
| DPoP | Short token lifetimes; optional mTLS binding (RFC 8705) for agent tokens |
| Device flow | Not supported |
| ACME custom domains | Not supported |
| SCIM | After v1 |
| Hosted multi-instance SaaS | Self-hosted only |

## What AI help speeds up, and what it does not

The owner builds with AI coding agents. That changes some estimates, but not all.

| Speeds up 2–3× | Does not speed up much |
|---|---|
| CRUD handlers and migrations | OpenID conformance cycles |
| SDKs in three languages | The external security review (2–4 calendar weeks plus fixes) |
| Console pages | Fuzzing CPU time |
| Tests and test vectors | Soak tests (1–2 weeks) |
| Codegen, docs | Interop with real Google, Entra and Okta tenants |
| | User-migration rehearsals and dual-run windows |
| | A pilot with a real user (4–8 weeks) |

AI also writes code faster than one person can check it. So the rules in [AGENTS.md](../AGENTS.md) still hold: no merge on red CI, and every auth-related change gets a human review and a regression test.

## Adoption by the other repos

This work happens in the other repos, not here. It is not part of the 35–45 pw above. Order: texc-symphony → attache → onto-intelli → nexc-engine. Details: [INTEGRATION.md](INTEGRATION.md).

| Repo | What changes | Effort | Earliest Tutela phase |
|---|---|---|---|
| texc-symphony | A `tutela-sdk` axum layer that requires `aud=symphony` on its API | 0.5–1 pw | A |
| attache | Console sign-in through OIDC; role-on-diff returns permission keys that `tutela-pdp` checks; `att_` operator tokens become service-account keys; agent principals created and disabled through `tutela.admin.v1` | 1–2 pw | A (sign-in, checks), B (principals) |
| onto-intelli | Accepts Tutela and delegated tokens; permissions from `tutela-pdp`; members and groups from Tutela; per-property masking everywhere; pushes its types through `tutela.admin.v1`; its Keys, Members, Projects and Sessions pages move to the Tutela Console | 6–9 pw | A (token checks, permissions, vault, safenet), B (members, groups, types, Console pages) |
| nexc-engine (product) | Users, workspaces, teams and roles move to Tutela; about 38 role call sites switch to `tutela-pdp` after 1–2 weeks of logged shadow decisions; `secret_box.rs` → `tutela-vault`; SSRF checks → `tutela-safenet` | not yet re-estimated (earlier round: 3–4 pw) | A (vault, safenet, checks), B (runtime roles) |

## Risks to the schedule

| Risk | What we do about it |
|---|---|
| Too much scope for one person | Hard gates per phase. Phase C is optional. Ship Phase A early so products can start. |
| The self-written login server is the most valuable attack target | Build it last. Gate it. Keycloak stays a safe exit, because the SDKs accept any issuer. |
| Rust, TypeScript and Python SDKs drift apart on delegation | Shared test vectors and per-SDK conformance tests. |
| Stale permissions after a revoke | `rev` in tokens and decisions, `at_least_revision` after writes, bundle expiry, a documented worst-case delay. |
| The native evaluator is too slow | The week-1 spike measures it before we build on it. |

## First-commit checklist

- [x] Docs: [README.md](../README.md), [AGENTS.md](../AGENTS.md), [SECURITY.md](../SECURITY.md), and in `docs/`: [ARCHITECTURE](ARCHITECTURE.md), [PERMISSION-MODEL](PERMISSION-MODEL.md), [CONTRACTS](CONTRACTS.md), [THREAT-MODEL](THREAT-MODEL.md), [INTEGRATION](INTEGRATION.md), this roadmap, [DECISIONS](DECISIONS.md).
- [x] `tutela-contracts`: the wire-types crate. It is the only Rust crate in the first commit.
- [x] Blocking CI (`.github/workflows/ci.yml`): `cargo fmt --check`, `clippy -D warnings`, `cargo doc` with warnings as errors, tests, `cargo-deny`, `cargo-audit`. Every job blocks the merge.
- [x] Workspace rules: `unsafe` forbidden; `unwrap`, `expect`, `panic!`, `todo!` denied by clippy; toolchain pinned in `rust-toolchain.toml`; MIT licence.
- [ ] Not in the first commit: every other crate, `tutelad`, the console, the SDKs, the CLI.

## Very next steps

### 1. Turn on branch protection

Require the CI checks on `main` in the GitHub settings of `f8fvwgzc/tutela`. Without this, "no merge on red CI" is only a promise. (Owner action.)

### 2. Week-1 spike: go/no-go

Before the real Phase A code, a short spike proves that the native evaluator can be fast and correct. The notes, the numbers and the raw outputs are kept in `docs/`. The spike code is kept in `spike/week1/` only until `tutela-pdp` has its own benchmarks and differential tests.

| Test | Setup | Go if | If no-go |
|---|---|---|---|
| `check` latency | A large per-tenant model, in process, warm cache. Proposed size: 200 resource types, 100 roles, 5,000 field rules, 10,000 bindings. | p99 **< 1 ms** | Change the compiled model layout (for example, precompute effective levels per scope) before more Phase A work. |
| Closure latency | Resource paths of depth **32**, big groups. Proposed: 10,000 members, groups nested 8 deep, in Postgres. | p99 under a threshold written down before the run (proposed: 5 ms) | Keep a closure table that is updated on write, or lower the depth cap. |
| `list_filter` correctness | **100k rows**, random models and principals. | Rows returned by `list_filter` == rows `check()` allows. Zero mismatches. Counts match. | Stop. Fix the evaluator. Nothing in Phase A is built on a mismatch. |

The model and group sizes above are **proposals**. Fix them, and the machine the spike runs on, in the spike notes before running, so the result cannot be bent afterwards. Record the result (go or no-go, with numbers) as the next ADR in [DECISIONS.md](DECISIONS.md).

**Done, 2026-10-28: go.** Notes: [SPIKE-WEEK1.md](SPIKE-WEEK1.md). Result: [ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator).

### 3. Then, in order

1. Model language and compiler.
2. `tutela-pdp`, with the property tests from day one.
3. `tutela-store`.
4. `tutela-sdk`.
5. `tutela-vault` and `tutela-safenet`.
6. `tutela codegen` and the React, Node and Python SDKs, with shared test vectors.
7. The product template, signing in through Keycloak.
