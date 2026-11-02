# Tutela roadmap

Status: **pre-alpha**. `v0.1.0` is a pre-release of the Rust crates in library mode. Parts 1, 2a, 2b, 3a and 3b of Phase B are merged: the `tutelad` service, tenant isolation, the bindings store, the check API, the permission map, the replica checks, `write_check` with moves and links, model versions per tenant, the impact report, explain and simulate, two-person publish, the service's own issuer with token exchange, admin and delegated tokens, the local audit log, events with webhooks and SSE, and signed bundles. Nothing is usable in production yet. See [Phase B status](#phase-b-status).

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
| 5 | `tutela-store` | Postgres schema and migrations for bindings, field rules and groups. The same schema `tutelad` uses later. It fills the evaluator's `TenantData` ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)), with tests for each of these: the private flag is written in the same transaction as the scope and the revision bump; a deleted scope leaves the tenant data in the same revision; group keys are unique in the tenant, groups nest at most 32 deep, and the closure holds at most 1,000,000 pairs and takes at most 4,000,000 steps to compute; scope paths for `list_filter` are current after a move. It also indexes private scopes by org or ancestor, so `list_filter` does not ask for every private scope of the tenant. **Done:** schema `tutela` with numbered migrations, forced row-level security on every tenant table, checked writes in the product's own transaction, scope paths with `move_scope`, the applied manifest and `model_revision` ([ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)). `list_filter` places only the private scopes under the principal's scopes (`ScopePaths::below`, [#6](https://github.com/f8fvwgzc/tutela/issues/6)). Boundary rules for moves and links: the `boundary_rule` columns are in, but `write_check` still refuses moves until the impact calculation (Phase B). |
| 6 | `tutela-sdk` | Token verifier for any OIDC issuer, with a trust list that maps each issuer to the tenants it may speak for. axum and tonic layers. Decision cache. Refuses `typ: agent+jwt` unless delegation support is on. The SQL adapter for `list_filter`: bound parameters only, a statement timeout that fails closed, and a query plan that is fast at the filter limits; it also defines the gate benchmark (table size, tenants, reference machine) ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F2). **Built:** the token verifier (CONTRACTS §4.2 order; ES256, RS256 and EdDSA on aws-lc-rs; the JWKS through `tutela-safenet` with a TTL, a rate-limited refetch, a `kid` deny-list and a stale limit; epochs and disabled principals; delegation steps; external issuers per §4.6). The axum and tonic auth layer (`AuthLayer`), route guards over the codegen table that refuse to start with an unguarded declared route (`Guards::check_complete`), and `assert_routes_deny` for the denied-route test. The decision cache (`CachedPdp`: keyed by revision and request, cleared on every load) and the SQL adapter (`tutela_sdk::sql`: bound parameters, mapped columns only, the tenant predicate and the 32-ancestor bound, `coalesce` on every comparison, a statement timeout that fails closed), with a differential test against `check` on Postgres. The gate benchmark exists (`cargo bench -p tutela-sdk --bench list_query`, [#22](https://github.com/f8fvwgzc/tutela/issues/22)): **passes**: p99 79.8 ms at the filter limits and 3.7 ms typical, with grouped terms, hashed scope tests and lower limits ([ADR-0016](DECISIONS.md#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits), [#26](https://github.com/f8fvwgzc/tutela/issues/26)). |
| 7 | `tutela-vault` | Envelope encryption with a KMS trait. Ported from the design of onto-intelli `crates/onto-control/src/vault.rs`. **Done:** a random data key per secret (AES-256-GCM), wrapped by a `Kms` (`LocalKms` from `TUTELA_MASTER_KEY`, with `TUTELA_MASTER_KEY_PREVIOUS` for rotation); every blob bound to a purpose and a context; `rewrap` keeps the secret's ciphertext. A cloud KMS backend comes with `tutelad` (Phase B). |
| 8 | `tutela-safenet` | SSRF-safe outbound HTTP. Ported from onto-intelli `crates/onto-control/src/net.rs` and `crates/onto-intelli/src/net.rs`. **Done:** public addresses only, checked in the client's own resolver (one lookup, no rebinding); `https` only (`http` to loopback in dev mode); no redirects and no proxy; timeouts and a body size limit; an exact allow-list for private hosts; rustls on aws-lc-rs. Fuzzing the URL parser stays in the library gate. |
| 9 | Codegen and CLI | `tutela init`, `tutela apply` (library mode: shows the diff and refuses a widening diff without an approval token), `tutela codegen`. Codegen makes the React constants and the server route guards from the same UI-key entry, plus a test that calls each route as a denied principal. **Built:** `init`, `check`, `migrate`, `apply` with approval tokens ([ADR-0015](DECISIONS.md#adr-0015-approval-tokens-for-tutela-apply-in-library-mode)). `codegen` (Rust and TypeScript constants, the UI map and the route table, with `--check`). The generated `route_pairs()` feeds `tutela_sdk::http::Guards` and the denied-route test, `assert_routes_deny(app, perms::route_pairs(), token)`, which the product calls with its own router. |
| 10 | JS and Python SDKs | `@f8fvwgzc/tutela-react` (`<Can>`, `<Field>`, `<Protect>`, `useCan`), `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js`, `tutela-py`. Shared test vectors so Rust, TypeScript and Python give the same answers. |
| 11 | Product template | A small product that uses all of the above. |

**Exit criteria.**

- The template product signs in through Keycloak, checks permissions in process, and renders `<Can>` and `<Field>` correctly.
- Property tests pass: no cross-tenant grant, no widening, delegation ≤ person AND agent, `list_filter` ≡ `check`.
- The library gate passes.
- v0.1 is tagged and signed.

**State on 2026-10-29: the Rust side of Phase A is built; Phase A is not done.**

| Built (items) | What a product can use |
|---|---|
| 1–4 | `tutela-contracts`; the week-1 spike (go); the model compiler and diff; the evaluator `tutela-pdp` (`check`, `batch`, `list_filter`, `write_check`) with property tests, a reference evaluator and 26 of 26 mutants caught. |
| 5 | `tutela-store`: Postgres schema, migrations, forced row-level security, checked writes in the product's transaction, scope paths. |
| 6 | `tutela-sdk`: the token verifier (any OIDC issuer, cached JWKS through `tutela-safenet`), the axum/tonic auth layer, route guards, the decision cache, the `list_filter` SQL adapter. |
| 7–8 | `tutela-vault` (envelope encryption, KMS trait) and `tutela-safenet` (SSRF-safe outbound HTTP, rustls on aws-lc-rs). |
| 9 | The `tutela` CLI: `init`, `check`, `codegen`, `migrate`, `apply` with approval tokens, TLS to the database. |

| Open before the exit criteria hold | Where |
|---|---|
| Fuzzing of the model compiler, the token verifier and the SQL filter compiler | library gate |
| Items 10–11: the JS and Python SDKs and the template product (Keycloak sign-in, `<Can>`, `<Field>`) | not started |
| v0.1 tag and signature | after the gate |
| GitHub Actions has not run since the first commit (account billing); every merge was gated by local `make` | owner |

## Phase B: `tutelad` service and Tutela Console

**Goal.** Tenants define and change roles at runtime. Non-Rust apps check permissions over the network. Agents get delegated tokens.

**Effort.** About 9–12 pw.

**Work list.**

- Tenants with row-level security: `tenant_id` on every row, `FORCE ROW LEVEL SECURITY`, tenant set with `SET LOCAL` per transaction from the verified token. **Done** (see [Phase B status](#phase-b-status)).
- Bindings and groups store with a per-tenant revision. **Done.**
- AuthZEN 1.0-shaped API: `/access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/resource`, `/access/v1/search/subject`; gRPC `tutela.authz.v1`. **Done.**
- Permission map for UIs: `POST /v1/authz/permissions` with ETag/304. **Done.**
- Signed bundles for PDP caches and offline checks: **done** in part 3b ([ADR-0038](DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp)).
- Model versioning, impact report ("12 users gain read on contract"), explain and simulate, two-person publish (optional per tenant): **done** ([ADR-0026](DECISIONS.md#adr-0026-a-tenant-owns-its-model-versions) to [ADR-0029](DECISIONS.md#adr-0029-two-person-publish)).
- Moves and links across scopes: `moves_out`, `moves_in`, `on_looser` and `links_from` from `boundary_rule`, checked in `write_check` with the before/after impact calculation (PERMISSION-MODEL §9, §10): **done** ([ADR-0025](DECISIONS.md#adr-0025-moves-and-links-in-write_check)). Assignment expiry with a revision bump when it passes ([ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)): **done** ([ADR-0020](DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry)).
- CLI: `tutela apply` against `tutelad` (adds the impact report and approvals; still refuses a widening diff without an approval token), `tutela apps create`, `tutela keys rotate`.
- Webhooks (transactional outbox, Standard Webhooks signatures) and SSE `/v1/events`: **done** in part 3b ([ADR-0035](DECISIONS.md#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order) to [ADR-0037](DECISIONS.md#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded)); registering a webhook is part 3c's route.
- Local hash-chained audit log. Optional forwarding to attache's evidence ledger through its Append API: **done** in part 3b ([ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change), [ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable)).
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

### Phase B status

**State on 2026-11-02: parts 1, 2a, 2b, 3a and 3b are merged. Phase B is not done, and the service gate does not pass yet** (its end-to-end check needs the Console). v0.2.0 is not tagged. attache and texc-symphony stay on `v0.1.0`.

Done:

| Work | State | Where |
|---|---|---|
| Public errors made opaque, for v0.2.0 | Done | [ADR-0017](DECISIONS.md#adr-0017-opaque-public-errors-for-the-crates-that-touch-the-outside-world), [MIGRATION-0.2.md](MIGRATION-0.2.md) |
| `tutelad`: config, the API port (HTTP and gRPC), the ops port, metrics, JSON logs, graceful shutdown, bearer tokens through `tutela-sdk`, `tutelad migrate`, `deploy/` | Done | [ADR-0018](DECISIONS.md#adr-0018-tutelad-the-stack-the-two-ports-and-the-config) |
| Tenants with row-level security: `FORCE`, a non-owner role, the tenant only from the verified token with `SET LOCAL`, `check_isolation` | Done | [ADR-0019](DECISIONS.md#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked) |
| Bindings and groups store with a per-tenant revision; assignment expiry with a revision bump | Done | [ADR-0020](DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry) |
| Evaluation API: `POST /access/v1/evaluation`, `/access/v1/evaluations`, gRPC `tutela.authz.v1`, per-tenant snapshots with a revision lease | Done | [ADR-0021](DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease) |
| Search: `/access/v1/search/resource`, `/access/v1/search/subject` | Done | [ADR-0022](DECISIONS.md#adr-0022-the-searches-live-next-to-the-evaluator) |
| Permission map, `POST /v1/authz/permissions` with ETag and 304 | Done | [ADR-0023](DECISIONS.md#adr-0023-the-permission-map-and-a-tag-that-covers-the-answer) |
| `write_check` over the API, moves and links across scopes | Done | [ADR-0025](DECISIONS.md#adr-0025-moves-and-links-in-write_check) |
| Model versioning: a tenant's own numbered versions, rollback as a new publish | Done | [ADR-0026](DECISIONS.md#adr-0026-a-tenant-owns-its-model-versions) |
| Impact report: who gains or loses what, bounded, never "no impact" when cut short | Done | [ADR-0027](DECISIONS.md#adr-0027-the-impact-report) |
| Explain and simulate, behind `read_audit` on the resource | Done | [ADR-0028](DECISIONS.md#adr-0028-explain-and-simulate-need-read_audit-on-the-resource) |
| Two-person publish, optional per tenant; a proposal goes stale when its impact report would change | Done | [ADR-0029](DECISIONS.md#adr-0029-two-person-publish) |
| `tutelad`'s own issuer: signing keys sealed by `tutela-vault`, the JWKS without a token, rotation with pre-publication, a `kid` deny-list, tenants made at runtime trusted through the directory; `TUTELA_MASTER_KEY`, `TUTELA_KEY_PEPPER` and `TUTELA_ISSUER` required at start-up | Done (part 3a) | [ADR-0030](DECISIONS.md#adr-0030-tutelads-own-issuer-signing-keys-the-jwks-and-paths-without-a-token) |
| Token exchange (RFC 8693) at `POST /oauth2/token`: an external issuer's token for a Tutela access token, the tenant from the trust list, just-in-time provisioning by `(iss, sub)`, each external token once; own tokens for another audience; a raised `epoch` or a disabled principal refused on the API | Done (part 3a) | [ADR-0031](DECISIONS.md#adr-0031-token-exchange-the-tenant-from-the-trust-list-a-person-from-iss-sub) |
| Admin tokens: `aud=tutela-admin` from token exchange, for a person after step-up (`TUTELA_ADMIN_ACR`), at most 300 s; the model routes, explain and simulate take them from a person and a `tutela-authz` token from a service (a pipeline); every other route refuses them | Done (part 3a) | [ADR-0032](DECISIONS.md#adr-0032-admin-tokens-a-person-steps-up-a-pipeline-keeps-its-service-token) |
| Delegated agent tokens (RFC 8693, `act`, `typ: agent+jwt`) from token exchange, only for `delegation_aware` audiences, at most 4 actors, an agent registered and enabled in the tenant (an access token of an agent, or attache's JWT-SVID on `/ns/<ns>/svc/<service>`), 60 to 120 s; on in `verifier_config`; a disabled agent or person stops them | Done (part 3a) | [ADR-0033](DECISIONS.md#adr-0033-delegated-agent-tokens-from-token-exchange) |
| Local hash-chained audit log: one chain per tenant in the change's transaction, `seq` from 1 with no gap, append-only in the database, a verifier that finds the first broken link; records for every token issued or refused, provisioning, publishes and their refusals, proposals, the two-person setting, impact, explain, simulate, write checks, the expiry sweep and signing keys; `details` added to audit.v1 | Done (part 3b) | [ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change) |
| Transactional outbox: events in the change's transaction, numbered per tenant in commit order with no gap, a stable id; `permissions.changed`, `model.published`, `user.created`, `session.revoked`, `principal.disabled`, `user.disabled` and the new `principal.enabled`; a one-line hook for part 3c's org lifecycle events | Done (part 3b) | [ADR-0035](DECISIONS.md#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order) |
| Webhook delivery from the outbox: Standard Webhooks signatures (the spec's test vector passes), `tutela-safenet` at registration (DNS answer included) and at each send, a lease so two replicas never send one event at once, order per subject, retries with backoff and jitter for 24 hours, then dead and sent again by hand, secret rotation with an overlap, secrets sealed by `tutela-vault`. Registration is a function; its route is part 3c's | Done (part 3b) | [ADR-0036](DECISIONS.md#adr-0036-webhooks-delivered-from-the-outbox-registered-by-part-3c) |
| SSE `GET /v1/events` for a service of the tenant: events, the `kid` deny-list (`denied_kids`) and revision changes (`rev`) pushed, resume by `Last-Event-ID` with `reset`, one feed per tenant per replica, bounded streams (count, age, buffer), ended on revocation and shutdown; `tutela_sdk::events` applies them to a verifier | Done (part 3b) | [ADR-0037](DECISIONS.md#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded) |
| Signed bundles at `GET /v1/authz/bundle` for a service with `read_audit` at every org: the tenant's data and active model, `typ: tutela-bundle+jwt`, signed with `KeyRing::signer()`, `exp` no later than the first expiry in it; `tutela_sdk` verifies them against the same JWKS (a denied `kid` refused) and `OfflinePdp` answers from them until `exp`, refusing an older, changed, other-tenant or newer-format bundle | Done (part 3b) | [ADR-0038](DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp) |
| Forwarding of audit records to attache's evidence ledger through its acknowledged Append API, off unless `TUTELA_LEDGER_URL` is set: each record signed by the deployment's Ed25519 producer key over its body, marked shipped only on acknowledgement, one replica per chain at a time, resuming after the last acknowledged `seq`; nothing changed in attache | Done (part 3b) | [ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable) |

Not started:

| Work | Part | Note |
|---|---|---|
| `tutela apply` against `tutelad`, `tutela apps create`, `tutela keys rotate` | 4 | `tutela apply` calls `POST /v1/models/publish`, per tenant. |
| `tutela.admin.v1`, agent principal management, org lifecycle events, soft-delete of tenants, the route that registers webhooks | 3c | `grant_service` gives no write on `tenant` yet. The store calls for agents and revocation exist (part 3a); webhooks' store and delivery exist (part 3b). See [Notes for part 3c](#notes-for-part-3c). |
| A test of token exchange against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87)) | open | No image could be pulled; tested against a local signer of Keycloak-shaped tokens. |
| Client authentication at the token endpoint | 4 | With apps (`tutela apps create`): bind `azp` to the client (ADR-0031). |
| Tutela Console and embeddable admin components | 4 | |
| Helm chart and bootstrap job; the OCI image ([#49](https://github.com/f8fvwgzc/tutela/issues/49)) | 4 | The chart must set the values in `deploy/tutelad.env`, including `RUST_BACKTRACE=1` and `RUST_LIB_BACKTRACE=0`. |
| OTLP export of traces | open | Logs carry the `traceparent` trace id today. |

The service gate:

| Check | State |
|---|---|
| A query with no tenant set returns zero rows | **Passes** on a real Postgres (`crates/tutelad/tests/rls.rs`) |
| A cross-tenant read fails at RLS, even with an injected code bug | **Passes**, with a control that shows the same request leaks when RLS is off |
| Group and path closure p99 | **Passes** the 5 ms threshold going up: 1.44 ms, 1.46 ms at 32 levels, 0.67 ms for a path. Going down (`scopes_below`) is 11 ms, not gated ([ADR-0020](DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry)) |
| 2+ replicas | **Passes**: two real `tutelad` processes on one Postgres answer together, share a sweep (one expiry, one revision), and one keeps serving when the other stops (`crates/tutelad/tests/ha.rs`) |
| Bundle expiry | **Passes.** A replica's snapshot stops at its age limit and at `next_expiry`, also during an outage, and fails closed (`crates/tutelad/tests/ha.rs`). A signed bundle's `exp` is never later than the first assignment in it that expires, and a product's `OfflinePdp` answers from it with `tutelad` stopped until `exp`, then answers nothing; an expired, older, changed, denied-`kid` or newer-format bundle is refused (`crates/tutelad/tests/bundle.rs`, [ADR-0038](DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp)). The offline test stops the in-process service; it is not a second process |
| A revoked role takes effect within the documented delay | **Passes on replicas**: documented at most 1.5 s, measured p50 0.61 s, worst 1.010 s over 60 rounds under steady traffic. The test fails above 1.5 s. A replica cut off from the database stops at the age limit of the action, also tested ([PERMISSION-MODEL.md 16.1](PERMISSION-MODEL.md#161-how-long-until-a-revocation-takes-effect)) |
| Sign-in, the permission map and runtime role editing, end to end | **Not built.** The service parts exist: a Keycloak-shaped sign-in becomes a Tutela token by token exchange, which the check API and the permission map accept (part 3a, `crates/tutelad/tests/exchange.rs`), and a person with a stepped-up admin token edits the tenant's model (ADR-0026, ADR-0032). The Console (part 4) and a test against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87)) are missing |

#### Notes for part 2b

Part 2b is done; these notes stay for what they say about the code.

Read these with [ADR-0021](DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease), [ADR-0022](DECISIONS.md#adr-0022-the-searches-live-next-to-the-evaluator), [ADR-0023](DECISIONS.md#adr-0023-the-permission-map-and-a-tag-that-covers-the-answer) and [ADR-0024](DECISIONS.md#adr-0024-signed-bundles-wait-for-part-3).

- **Crate layout.** `crates/tutelad` is a library and a thin binary. `api` has the routers, `config` the settings, `db` the pool, `tenant` the tenant, `expiry` the sweep, `telemetry` logs and metrics, and `server` the listeners and shutdown. `authz` holds the decision APIs: `mod.rs` (who may ask, the revision floor, evaluation), `search.rs`, `permissions.rs`, `wire.rs` (the JSON types), and `http.rs` and `grpc.rs`, which only adapt. `cache` holds the tenant snapshots. Tests run the real `Server` on port 0; `tests/common/mod.rs` has the Postgres harness, a signing issuer and a seeded `World`. `tests/ha.rs` runs the real binary.
- **Adding an operation.** Write one function in `authz` over `wire` types, then a route in `api::api_router` and a method in `grpc.rs`. Never put a decision in an adapter.
- **How tenant data is loaded and cached.** `TenantCache::view(tenant, need)` gives a `View`, and `View::for_class(class)` gives the `Snapshot`. A snapshot is immutable: a `Pdp` for one tenant, its `ScopePathSnapshot`, the model and its digest. `read_tenant` reads the data and then the manifest in one transaction, after the revision's share lock, so the two always match. One request at a time per tenant reads the database, and a build runs on a blocking thread. `at_least_revision` and the token's `rev` force a read past the lease.
- **How replicas learn of a change.** A lease, `TUTELA_REVISION_CHECK_MS`. There is no push between replicas. A change needs nothing but its revision bump: any write through the store reaches every replica. **So never change tenant data without a bump.** Expiry is the one exception, and the snapshot's `next_expiry` deadline covers it.
- **Hooking in `write_check`.** Add `authz::write_check` over a new wire type, and call `Pdp::write_check` on `view.for_class(ActionClass::Write)` or stricter. Use `ActionClass::of` with `manage_access` when a `grants_access` field changes. `may_ask` applies as it does to the others. Moves: `Pdp::write_check` refuses `new_path` today. The boundary rules are in `boundary_rule`, and `ScopePaths` is on the snapshot.
- **Hooking in a model publish.** `tutela_store::publish_manifest` writes the manifest and bumps every tenant in one transaction, so the cache needs no change: the next check sees the revision and loads the new manifest, compiled once by digest. `grant_service` gives no write on `app_manifest` yet. `publish_manifest` takes an advisory lock, then one row lock per tenant, so keep it out of a request's transaction with a tenant in it. For a model per tenant, replace `applied_manifest` in `read_tenant`, keep it after the revision lock, and make `TenantCache::model` hold more than one digest. The ETag uses `Snapshot::model_digest`; keep that the digest of what was compiled.
- **Explain and simulate.** A `Decision` already carries `rule_ids` and `reason`. Simulate needs a `Pdp` built from a candidate model: `Pdp::new()` and `load` are cheap beside the read, and the snapshot is never to be changed for it.
- **The ETag covers the answer** because of expiry. A new input to a map must reach `body.canonical()` or the answer, or a 304 will hide it.
- **Search names only what is certain.** A new filter op must be added to `search::Test`; the compiler makes that match exhaustive on purpose.
- **How the revision works.** `tenant_rev` goes up in the same transaction as every change, and a write locks that row first. The exception is expiry, which has two halves: a read drops a row past its expiry at once, and the sweep bumps the revision up to `TUTELA_EXPIRY_SWEEP_SECS` later. So two loads at one revision can differ, in the narrowing direction only.
- **How a request gets its tenant.** A handler takes a `Tenant`, or calls `Tenant::of` on the verified `Identity`. Do not add a way to make a `Tenant` from a key. A background job gets a narrow crate-private method on `Conn`, as the sweep does.
- **A write reads the whole tenant** (about 48 ms at the benchmark's size, ADR-0014 item 4). Plan bulk work around it.
- **A SQL `ScopePaths::below` would not use the GIN index** under row-level security. The in-memory `ScopePathSnapshot` is fine.
- **Secrets.** Nothing reads `TUTELA_MASTER_KEY` or `TUTELA_KEY_PEPPER` yet. The part that adds signing keys or API keys must make them required at start-up (TM-22).
- **Upgrades.** Old replicas stop answering when a migration lands (ADR-0018 item 5). The deploy order is `tutelad migrate`, then new replicas at once.
- **`make` is the gate.** Run it as its own command and read its exit code before a merge; a background job's "exit 0" is the shell's, not `make`'s. `tests/*.rs` need `#![cfg(test)]`, or clippy denies `unwrap` in helpers there.

#### Notes for part 3

Part 3a is done; these notes stay for what they say about the code. The notes for part 3b follow.

Read these with [ADR-0025](DECISIONS.md#adr-0025-moves-and-links-in-write_check) to [ADR-0029](DECISIONS.md#adr-0029-two-person-publish).

- **New code.** `authz/write.rs` (`write_check`), `authz/explain.rs` (explain, simulate), and `models/` (`mod.rs` the operations, `wire.rs`, `http.rs`). `tutela-pdp` has `moves.rs`, `impact.rs` (the before/after comparison, shared by moves and the report) and `explain.rs`. `tutela-store` has `models.rs`, `proposals.rs` and `approval.rs` (the token, moved from the CLI). `crates/tutelad/mutants/mutants.py` plants bugs in the service; it is not part of `make`.
- **The model is per tenant now** (ADR-0026). `read_tenant` reads `tutela_store::active_model`: the tenant's own newest version, else the app's manifest. `TenantCache` keeps 32 compiled models by digest. **A signed bundle must carry the tenant's active model**, not `app_manifest`, and its tag the digest of what was compiled.
- **The audience.** The model routes, explain and simulate take a `tutela-authz` token today, with admin keys at every org (or `read_audit` on the resource). CONTRACTS.md 4.4 and TM-01 want `aud=tutela-admin` with step-up MFA for the Console. When token exchange issues it, accept it on these routes and check `acr`; decide whether `tutela-authz` tokens keep working for `tutela apply` in a pipeline.
- **Delegated tokens.** When `verifier_config` turns them on, nothing more is needed here: `models::principal` refuses them for every model call, explain and simulate, and `write_check` evaluates the chain (a delegated approver never counts). `tests/two_person.rs` already runs a replica with them on.
- **What the audit log must record** (one `audit.v1` record each, in the same transaction as the change where there is one):
  - `write_check`: every deny, with the denied fields; every move verdict with `left`, `entered`, `looser`, `complete`, `approve_at` and `approved_by`; every link deny.
  - `POST /v1/models/publish` and an approval: the version, the revision, the author, the approvers (principal and approval key id), the class, `restores`, and the impact report's digest. A refused publish too (`approval_required`, `two_person_required`).
  - Proposals: proposed, approved, rejected, and closed as stale with the reason. `PUT /v1/models/settings`: on, off asked, off.
  - `explain`, `simulate` and `POST /v1/models/impact`: who asked about whom. They read other people's access.
  - `set_boundary` and `move_scope` in the store: the product's admin calls, with the scope.
- **Events.** `tutela.model.published.v1 {rev}` for a tenant publish and an approved proposal, from `publish_tenant_model` and `publish_proposal`, in their transactions. `tutela.permissions.changed.v1 {rev}` for `set_boundary` and `move_scope`. A proposal and a setting change no access; if the Console needs to hear of them, add event types (CONTRACTS.md 8, additive).
- **`tutela.admin.v1`.** The model routes are HTTP only; give them gRPC methods there. `set_boundary` needs an admin route that checks `manage_boundaries` on the scope.
- **The publish API for `tutela apply` (part 4):** `POST /v1/models/impact {source}` gives `version`, `from`, `to`, `class`, `diff` and the report; then `POST /v1/models/publish {source, expected_version, approval}`. With two-person on, `POST /v1/models/proposals` and a second person's `POST …/approve`. A token for `tutelad` needs `tutela approve --tenant <tid>`. The error codes are in CONTRACTS.md 7.9.
- **Open limits**, each in its ADR: a type that stopped being a container can hold rows the model does not show (moves, ADR-0025); `restricted_links` and `ai_reach` are not read; a tenant cannot go back to following the app's manifest (ADR-0026); a large tenant with a changed role held by a group of everyone reaches the report's bound (ADR-0027); proposals have no expiry (ADR-0029).

#### Notes for part 3b

Part 3b is done; these notes stay for what they say about the code. The notes for part 3c follow.

Read these with [ADR-0030](DECISIONS.md#adr-0030-tutelads-own-issuer-signing-keys-the-jwks-and-paths-without-a-token) to [ADR-0033](DECISIONS.md#adr-0033-delegated-agent-tokens-from-token-exchange) and CONTRACTS.md 4.8.

- **New code in part 3a.** `tutelad`: `keys.rs` (the `KeyRing`, the `Signer` trait, `OwnJwks`, the refresh job), `exchange.rs` (`Audiences`, the token endpoint, admin and delegated tokens), `revocation.rs` (the per-tenant book of raised epochs and disabled principals, and the middleware in `api.rs` that refuses such tokens with step `epoch`), `Tenant::exchanged`. `api.rs` has three routers: the public paths (`PUBLIC_PATHS`, no token), the admin routes (their own token check, `admin_auth`), and the rest (`AuthLayer`). `tutela-store`: `signing_keys.rs` and `principals.rs`, migrations 6 and 7. Mutants T01 to T23 are in `crates/tutelad/mutants/mutants.py`.
- **The key store** (`tutela_store::signing_keys`, for `tutela keys rotate` in part 4): `rotate_signing_key(tx, vault, tutelad::keys::rotation_times(TUTELA_JWKS_CACHE_SECS))`, `deny_signing_key(tx, vault, kid)`, `ensure_signing_key`, `rewrap_signing_keys`, `signing_keys`. A replica reads the table every `TUTELA_KEY_REFRESH_SECS`. Rotation is started by an operator; there is no timer.
- **Signing bundles.** Sign with `KeyRing::signer()` (the `Signer` trait), not a new key store. A bundle verifier reads the same JWKS. Keep the bundle's `kid` on the deny-list rules, and decide whether bundles need their own `typ`.
- **The `kid` deny-list over SSE** (TM-15): `KeyRing::denied()` is the list to push; `Verifier::forget_jwks` is the forced refetch a receiver runs.
- **Events to emit** (CONTRACTS.md 8), in the transaction of the change: `tutela.session.revoked.v1` from `revoke_sessions` and `tutela.principal.disabled.v1` from `set_disabled`, each with the new `epoch`, so an SDK's `EpochBook` refuses old tokens (CONTRACTS.md 4.2 step 9). Until they exist, a product waits for the token to expire. Provisioning bumps no revision and needs no event.
- **What the audit log must record for tokens** (one `audit.v1` record each; never a token, never an e-mail):
  - every token issued: the kind (`access`, `admin`, `delegated`), its `jti`, the principal, the tenant, the audience, `azp`, `exp`; for an external subject, the upstream issuer; for a delegated token, the whole `act` chain, `run_id` and `node_id`;
  - every refused exchange: the kind and the refusal's `reason` (`Refusal::reason`: `replayed`, `expired`, `disabled`, `epoch`, `step_up`, `actor_unknown`, `actor_disabled`, `actor_tenant`, `workload`, `chain`, a verifier step, ...), the upstream issuer, and the principal when it is known;
  - just-in-time provisioning: the new principal and its upstream `(iss, sub)`;
  - `revoke_sessions`, `set_disabled` (on and off) and `register_agent`, with the new epoch and, once the admin API exists, who asked;
  - a token refused on the API for an old epoch or a disabled principal or actor (step `epoch`): a security event;
  - signing keys: a first key, a rotation (the next `kid`, `signs_from`, the previous `kid` and `retire_at`), a denial (the `kid` and its replacement), a re-wrap (how many).
  The token endpoint has no transaction at a refusal; write those records in their own.
- **The revocation book** reads each active tenant every `TUTELA_REVISION_CHECK_MS`, beside the snapshot's own read. When SSE or a push exists, it can drop the lease. Neither it nor the tenant cache evicts a tenant: the directory bounds them now, not the trust file.
- **Open from part 3a:** client authentication at the token endpoint (apps, part 4); `cnf` binding of delegated tokens; the `org` claim (membership is not modeled); one `ses_` per exchange; a timer for key rotation; a real Keycloak test ([#87](https://github.com/f8fvwgzc/tutela/issues/87)).

#### Notes for part 3c

Part 3b is done. Read these with [ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change) to [ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable).

- **New code in part 3b.** `tutelad`: `audit.rs` (`Record`, `write`, `write_alone`, the reserved actor `audit::SYSTEM`), `events.rs` (the CloudEvent envelope), `webhooks.rs` (the relay, `register`, `sign`), `stream.rs` (`GET /v1/events`, the `Hub`), `bundle.rs` (`GET /v1/authz/bundle`), `ledger.rs` (the forwarder). `tutela-store`: `audit.rs` (the chains, the verifier, forwarding state), `events.rs` (the outbox, `OutboxEvent`, `emit`), `webhooks.rs`; migrations 8 to 11. `tutela-sdk`: `events` (feed a verifier from events) and `bundle` (`verify_bundle`, `OfflinePdp`). `tutela-contracts`: `jcs`, `AuditDraft`, `details`. `tutela-safenet`: `Client::check`. Mutants A01–A12, E01–E07, W01–W08, X01–X08, B01–B08 and L01–L03 are in `crates/tutelad/mutants/mutants.py`, every one caught; the script is not part of `make`, the tests that catch them are.
- **How to audit a new operation.** Build `audit::Record::new(tenant, actor, "tutela_<thing>:<verb>", ("tutela_<thing>", id))`, end it with `.allowed(rev)`, `.denied(rev, reason)` or `.failed(rev, reason)`, add ids and numbers with `.detail(k, v)` (never a token, a secret, an e-mail or a field value), and call `audit::write(state, &tx, records)` **last** in the change's transaction, just before the commit: it locks the chain's head until then. A refusal or a read with no transaction calls `audit::write_alone` before it answers. Add a label to `audit::audit_label` for a new `tutela_*` type. The actor of the admin routes is `audit::actor_of(&identity)`.
- **What part 3c must record** (the store calls take no actor, so the route records them): `register_agent` (the agent, its workload), `set_disabled` on and off and `revoke_sessions` (the principal and the new epoch, which the store returns), `set_boundary` and `move_scope` (the scope and the rule), org lifecycle, user deletion, webhook registration, rotation, disabling and `redeliver`, with **who asked**.
- **How to add an event.** Each `tutela_store::OutboxEvent` variant is one line in the change's transaction: `tutela_store::emit(&tx, tenant, OutboxEvent::OrgCreated { org })`. `OrgCreated`, `OrgUpdated`, `OrgDeleted { org, purge_after }` and `UserDeleted` exist; `insert` is the crate-private form the store's own writes use. A new type is a variant, its `parts` (subject, org, data) and its `EventType` constant in `tutela-contracts` (CONTRACTS.md 8.3, additive). Every data write already emits `permissions.changed`; `revoke_sessions`, `set_disabled` and provisioning emit theirs.
- **Webhook registration is part 3c's route** (ADR-0036 item 9): a person with a stepped-up admin token, or a service with its `tutela-authz` token, holding `read_audit` **and** `manage_access` at every org of the tenant (`models::admin` with both keys), in `tutela.admin.v1` and its HTTP admin routes. Build it on `tutelad::webhooks::register(tx, vault, relay_client, url, types, by)` (it checks the URL and its DNS answer with `tutela-safenet`), `tutela_store::webhooks::{rotate_webhook_secret, disable_webhook, webhooks, deliveries, redeliver}`. Show the secret once. Audit each call.
- **The SSE contract** (CONTRACTS.md 8.6, ADR-0037): services only; messages `id`/`event`/`data`; control messages `denied_kids`, `rev`, `reset` with no `id`; resume by `Last-Event-ID`; bounded by `TUTELA_SSE_*`. A new event type reaches streams with no change here. If the Console needs events about one person, add a filter per principal; do not open the stream to people.
- **The bundle format** (CONTRACTS.md 7.12, ADR-0038): `typ: tutela-bundle+jwt`, claims `iss`, `tid`, `tenant_iss`, `rev`, `iat`, `exp`, `jti`, `format: 1`, `model {digest, source}`, `data` (`TenantData` JSON), `paths`. A change to the format is `format: 2` beside 1; readers refuse a higher one. Who pulls: a service with `read_audit` at every org; part 4's apps may narrow it to a registered audience.
- **Tenant soft-delete** must keep the tenant's audit chain (append-only, never deleted) and stop its feeds and relays when the tenant leaves the directory. Erasure of personal data inside audit bodies (`upstream_sub`, actor ids) is still open (TM-20).
- **Open from part 3b:** a timer that verifies each chain and alerts on a broken link; the Console's view of dead webhook deliveries; per-principal SSE; `traceparent`, `request_id` and `ip` in audit records (left empty today); the relay and the forwarder visit every tenant of the directory each tick, which wants an index of tenants with work once tenants are many.

#### Notes for part 3c and part 4

- **`tutela.admin.v1`** must expose `register_agent` (with the workload SPIFFE id on `/ns/<ns>/svc/<service>`), `set_disabled` and `revoke_sessions`: attache creates, quarantines and enables agents through it. Give its gRPC methods the admin audience rule of ADR-0032, or make them services-only.
- **The Console** gets a person's admin token by token exchange after step-up (`audience=tutela-admin`; `TUTELA_ADMIN_ACR` set to what Keycloak's step-up gives), and calls the admin routes with it. A pipeline (`tutela apply`) uses a service account's `tutela-authz` token.
- **`tutela keys rotate`** calls the key store above with the vault from `TUTELA_MASTER_KEY`.

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
