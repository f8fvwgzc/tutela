# Tutela roadmap

Status: **pre-alpha**. `v0.1.0` is a pre-release of the Rust crates in library mode. Parts 1, 2a, 2b, 3a, 3b and 3c of Phase B are merged: the `tutelad` service, tenant isolation, the bindings store, the check API, the permission map, the replica checks, `write_check` with moves and links, model versions per tenant, the impact report, explain and simulate, two-person publish, the service's own issuer with token exchange, admin and delegated tokens, the local audit log, events with webhooks and SSE, signed bundles, and the admin API `tutela.admin.v1` with agent principals, the lifecycle of tenants, orgs and people, and webhook registration. Nothing is usable in production yet. See [Phase B status](#phase-b-status).

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
| 10 | JS and Python SDKs | `@f8fvwgzc/tutela-react` (`<Can>`, `<Field>`, `<Protect>`, `useCan`), `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js`, `tutela-py`. Shared test vectors so Rust, TypeScript and Python give the same answers. **Partly built in Phase B, part 4b1:** the workspace, `@f8fvwgzc/tutela-js` (the client of `tutelad`) and the admin side of `@f8fvwgzc/tutela-react` with `useCan` ([JS-SDK.md](JS-SDK.md)). `<Can>`, `<Field>`, `<Protect>`, the library-mode map, `tutela-node`, `tutela-py` and the shared test vectors are not. |
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
| Items 10–11: the JS and Python SDKs and the template product (Keycloak sign-in, `<Can>`, `<Field>`) | the admin side of the JS SDKs is built (Phase B, part 4b1); the rest not started |
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
- CLI: `tutela apply` against `tutelad` (adds the impact report and approvals; still refuses a widening diff without an approval token), `tutela apps create`, `tutela keys rotate`: **done** in part 4a ([ADR-0046](DECISIONS.md#adr-0046-the-cli-against-tutelad-apply-with-the-impact-report-apps-and-keys-through-the-key-store)).
- Webhooks (transactional outbox, Standard Webhooks signatures) and SSE `/v1/events`: **done** in part 3b ([ADR-0035](DECISIONS.md#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order) to [ADR-0037](DECISIONS.md#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded)); registering one is a route of the admin API since part 3c.
- Local hash-chained audit log. Optional forwarding to attache's evidence ledger through its Append API: **done** in part 3b ([ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change), [ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable)).
- **Token-exchange service**: accepts the Keycloak token and issues a short-lived Tutela access token, with just-in-time user provisioning. Apps with client authentication and `client_credentials`: **done** in part 4a ([ADR-0044](DECISIONS.md#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated)).
- **Delegated agent tokens** (RFC 8693, `act` claim, `typ: agent+jwt`, only for `delegation_aware` audiences). Not optional.
- Org lifecycle events (`tutela.org.created|updated|deleted.v1`, `tutela.user.deleted.v1`, ...): **done** in part 3c, with soft delete and a purge of tenants and orgs ([ADR-0041](DECISIONS.md#adr-0041-the-lifecycle-of-tenants-orgs-and-people-the-operator-makes-a-tenant-soft-delete-with-a-grace-a-purge-that-keeps-the-audit-chain)).
- Admin API `tutela.admin.v1` over gRPC and HTTP: **done** in part 3c for agent principals, people, the model, `PutResourceTypes`, boundary rules, tenants, orgs and webhooks ([ADR-0040](DECISIONS.md#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org)); scopes, role assignments and groups in part 4a ([#107](https://github.com/f8fvwgzc/tutela/issues/107), [ADR-0043](DECISIONS.md#adr-0043-scopes-assignments-and-groups-over-the-admin-api-checked-on-the-data-they-change)).
- Tutela Console, plus embeddable admin components (RoleEditor, MembersTable, permission matrix) using a separate `aud=tutela-admin` token. The components and the client they use: **done** in part 4b1 ([ADR-0048](DECISIONS.md#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice), [ADR-0049](DECISIONS.md#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people), [JS-SDK.md](JS-SDK.md)); the Console, served by `tutelad`: **done** in part 4b2 ([ADR-0050](DECISIONS.md#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start), [ADR-0052](DECISIONS.md#adr-0052-the-console-a-vite-app-on-the-sdks-sign-in-by-code-with-pkce-the-permission-map-asked-again-every-half-second)).
- A Helm bootstrap job that creates client credentials and webhook secrets before other charts start: **done** in part 4c ([ADR-0056](DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing)), with the chart and the OCI image ([ADR-0055](DECISIONS.md#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release)).

**Exit criteria.**

- Sign-in, the UI permission map and runtime role editing pass end to end.
- A cross-tenant read fails at RLS even with an injected code bug.
- A revoked role takes effect within the documented delay.
- 2+ replicas run.
- The service gate passes.

### Phase B status

**State on 2026-11-07: every part (1, 2a, 2b, 3a, 3b, 3c, 4a, 4b1, 4b2 and 4c) is merged, and `v0.2.0` is tagged as a pre-release.** Every item of the work list is built and every exit check passes **as far as this repo can check it**: locally, by `make` (GitHub Actions cannot run), the end-to-end check in a real browser against a test provider shaped like Keycloak 26, and the chart in a kind cluster by hand. **Not done:** publishing the image, the chart and the npm packages (a release step for the owner); OTLP traces. **Since `v0.2.0`:** token exchange and the browser check also pass against a real Keycloak 26.8.1 ([#87](https://github.com/f8fvwgzc/tutela/issues/87), `make keycloak`), which made the chart's Console client give one audience. attache and texc-symphony stay on `v0.1.0` until they bump ([#44](https://github.com/f8fvwgzc/tutela/issues/44), [Notes for after Phase B](#notes-for-after-phase-b)).

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
| `tutela.admin.v1` over gRPC and its HTTP admin routes, one code path, the admin token rule on both: agent principals (register with a workload on attache's path, list, read, disable and enable, revoke sessions), `PutResourceTypes` as a proposal, `set_boundary` with `manage_boundaries` on the scope, and the model routes as gRPC methods; every change and every refusal audited with who asked | Done (part 3c) | [ADR-0040](DECISIONS.md#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org), CONTRACTS.md 7.13 |
| The lifecycle of tenants, orgs and people: the operator makes a tenant with its first org and owners (`tutelad tenant create`, `restore`); its owner names and soft-deletes it; orgs made, renamed, soft-deleted and restored; people deleted; a purge after `TUTELA_PURGE_GRACE_SECS` that keeps the audit chain; `tutela.org.created|updated|deleted.v1` and `tutela.user.deleted.v1` | Done (part 3c) | [ADR-0041](DECISIONS.md#adr-0041-the-lifecycle-of-tenants-orgs-and-people-the-operator-makes-a-tenant-soft-delete-with-a-grace-a-purge-that-keeps-the-audit-chain), CONTRACTS.md 7.13.5 |
| Webhooks over the admin API: register (the URL and its DNS answer checked), list, rotate with an overlap, disable, list deliveries and send a dead one again; `read_audit` and `manage_access` at every org; a secret shown once | Done (part 3c) | [ADR-0036](DECISIONS.md#adr-0036-webhooks-delivered-from-the-outbox-registered-by-part-3c) item 9, CONTRACTS.md 7.13.6 |
| The audit log's leftovers: every chain walked on a timer (`TUTELA_AUDIT_VERIFY_SECS`), a broken link reported as an error log and `tutelad_audit_chains_broken`; `request_id`, `trace_id` and `span_id` in each record of a request; the two-process bundle test | Done (part 3c) | [ADR-0042](DECISIONS.md#adr-0042-the-audit-logs-leftovers-a-chain-check-on-a-timer-the-callers-trace-in-each-record) |
| Forwarding of audit records to attache's evidence ledger through its acknowledged Append API, off unless `TUTELA_LEDGER_URL` is set: each record signed by the deployment's Ed25519 producer key over its body, marked shipped only on acknowledgement, one replica per chain at a time, resuming after the last acknowledged `seq`; nothing changed in attache | Done (part 3b) | [ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable) |
| Scopes, role assignments and groups over `tutela.admin.v1` and its HTTP routes: register, move (behind `write_check`'s verdict, on the data it writes), delete and the private flag of scopes; assign, end and remove roles; groups and their members; the roles and types of the model; pages with `next_after`. Every binding change, a removal too, is held to the narrow-only rule before and after (`tutela_pdp::grant_excess`), under the tenant's write lock | Done (part 4a, [#107](https://github.com/f8fvwgzc/tutela/issues/107)) | [ADR-0043](DECISIONS.md#adr-0043-scopes-assignments-and-groups-over-the-admin-api-checked-on-the-data-they-change), CONTRACTS.md 7.13.7 |
| Apps and client authentication: an app per tenant with a service account and a client secret (an API key, stored as SHA-256(pepper ‖ key), shown once), made by the tenant's owner (`POST /v1/admin/apps`) or the operator (`tutelad apps create`); rotation with an overlap; disabling; `client_credentials`; `azp` bound to the client that authenticated, and an exchange with no client authentication open to public clients only | Done (part 4a, [#118](https://github.com/f8fvwgzc/tutela/issues/118)) | [ADR-0044](DECISIONS.md#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated), CONTRACTS.md 4.9, 7.13.8 |
| The audit producer key sealed in the database by `tutela-vault` instead of `TUTELA_AUDIT_KEY` in the environment: imported once from it, made at start otherwise, rotated with every old key kept so a record it signed still verifies, re-wrapped with the signing keys | Done (part 4a) | [ADR-0045](DECISIONS.md#adr-0045-the-audit-producer-key-sealed-in-the-database-rotated-with-its-old-keys-kept), CONTRACTS.md 9.4 |
| The JavaScript workspace in `sdk/` (pnpm, TypeScript strict, Biome, vitest), checked by `make js` inside `make`; plain `cargo build`/`cargo test` need no node | Done (part 4b1, [#126](https://github.com/f8fvwgzc/tutela/issues/126)) | [ADR-0047](DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make) |
| `@f8fvwgzc/tutela-js`: the browser token flow (one upstream token exchanged once for a `tutela-authz` and an admin token, step-up as a typed error and a state, renewal, tokens in memory only), a service mode, every route the Console calls with typed errors, pages, the revision of a write, the permission map with ETag/304 and `can`, a 503 retry that never repeats a create; tested against a real `tutelad` | Done (part 4b1, [#136](https://github.com/f8fvwgzc/tutela/issues/136)) | [ADR-0048](DECISIONS.md#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice), [JS-SDK.md](JS-SDK.md) |
| `@f8fvwgzc/tutela-react`: `TutelaProvider` and hooks, `MembersTable`, `RoleEditor`, `PermissionMatrix`, `ErrorNotice`; one scoped stylesheet with light and dark themes; axe-checked | Done (part 4b1, [#138](https://github.com/f8fvwgzc/tutela/issues/138)) | [ADR-0049](DECISIONS.md#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people), [JS-SDK.md](JS-SDK.md) |
| `GET /v1/models/active` (`GetActiveModel`): the active model's text, also at version 0, for a role change made in a UI | Done (part 4b1, [#132](https://github.com/f8fvwgzc/tutela/issues/132)) | CONTRACTS.md 7.9 |
| `grant_excess` holds a group change that makes an `in_group` condition hold to the narrow-only rule (found by the property test) | Done (part 4b1, [#127](https://github.com/f8fvwgzc/tutela/issues/127)) | CONTRACTS.md 7.13.7 |
| The CLI against `tutelad`: `tutela apply --server` (the diff and the impact report from `POST /v1/models/impact`, a widening change refused without an approval token before anything is sent, a publish with `expected_version` or a proposal when two-person publish is on), `tutela apps create | list | rotate | disable` (a secret printed once), `tutela keys list | rotate [--audit] | deny | rewrap` through the key stores with the vault of `TUTELA_MASTER_KEY`; library mode unchanged; tested against a real `tutelad` on a real Postgres | Done (part 4a, [#122](https://github.com/f8fvwgzc/tutela/issues/122)) | [ADR-0046](DECISIONS.md#adr-0046-the-cli-against-tutelad-apply-with-the-impact-report-apps-and-keys-through-the-key-store) |
| Serving the Tutela Console from `tutelad`: under `/console/` on the API port, from `TUTELA_CONSOLE_DIR` read once at start, exact paths with no token, a page fallback only under `/console/`, a strict CSP, `nosniff` and `Referrer-Policy: no-referrer`, the realm and client id from the configuration (`/console/config.json`) | Done (part 4b2, [#142](https://github.com/f8fvwgzc/tutela/issues/142)) | [ADR-0050](DECISIONS.md#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start), CONTRACTS.md 7.11 |
| A test OpenID provider shaped like Keycloak 26 (`crates/tutela-test-idp`): discovery, an authorization form with and without MFA, the code flow with PKCE S256, refresh, an RS256 JWKS; loopback only, a dev-dependency, never in `tutelad` | Done (part 4b2, [#144](https://github.com/f8fvwgzc/tutela/issues/144)) | [ADR-0051](DECISIONS.md#adr-0051-a-test-openid-provider-shaped-like-keycloak-a-dev-only-crate-on-loopback) |
| The Tutela Console (`console/`): sign-in by code with PKCE S256 as a public client, tokens in memory, the step-up banner, the rail from the permission map asked again every 500 ms, and every page of the notes for part 4b (scopes with `MembersTable`, roles with `PermissionMatrix` and `RoleEditor`, model history, groups, people and agents, apps, webhooks, tenant and orgs, explain and simulate); `searchResources` in `tutela-js`; a resource search for `org` names orgs (it failed with 503) | Done (part 4b2, [#146](https://github.com/f8fvwgzc/tutela/issues/146)) | [ADR-0052](DECISIONS.md#adr-0052-the-console-a-vite-app-on-the-sdks-sign-in-by-code-with-pkce-the-permission-map-asked-again-every-half-second), [JS-SDK.md](JS-SDK.md#the-console) |
| The exit check in a real browser (`make js-e2e`, part of `make`): Playwright's Chromium against a real `tutelad` on a real Postgres and the test provider | Done (part 4b2, [#149](https://github.com/f8fvwgzc/tutela/issues/149)) | [ADR-0053](DECISIONS.md#adr-0053-the-exit-check-in-a-real-browser-playwrights-chromium-a-real-tutelad-and-the-test-provider-run-by-make) |
| CORS for embedded components on another origin: `TUTELA_CORS_ORIGINS`, exact origins, off by default, never `*` or credentials, a listed origin's preflight answered without a token | Done (part 4b2, [#135](https://github.com/f8fvwgzc/tutela/issues/135)) | [ADR-0054](DECISIONS.md#adr-0054-cors-exact-origins-from-configuration-off-by-default-never-credentials), CONTRACTS.md 7.11 |
| The OCI image: a `Dockerfile` (node 22.12 builds the Console, Rust 1.99.0 builds `tutelad`), a distroless non-root runtime with no shell, the Console in `/srv/tutela/console`, base images pinned by digest, OCI labels, no `HEALTHCHECK`; `make image-lint` (hadolint). Built and run locally (linux/arm64, 62 MB); not pushed | Done (part 4c, [#49](https://github.com/f8fvwgzc/tutela/issues/49)) | [ADR-0055](DECISIONS.md#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release) |
| The Helm chart `deploy/helm/tutela`: 2+ replicas, probes, a non-root read-only pod, Service, optional Ingress, PodDisruptionBudget, NetworkPolicies, every setting of `deploy/tutelad.env` and the Console's, the trust file, secrets by reference; the Console's Keycloak client as a partial-import file; `make helm`. Run in a kind cluster by hand (two pods ready, TLS to Postgres with a private CA); not pushed | Done (part 4c, [#158](https://github.com/f8fvwgzc/tutela/issues/158)) | [ADR-0056](DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing) |
| The bootstrap job, `tutelad bootstrap` as a pre-install and pre-upgrade hook: migrate, the tenant with the id the values name and its first owners, each product's app with its secret in a Kubernetes Secret, the app's roles, webhooks; only what is missing, a lost Secret healed by rotation; `tutelad tenant new-id` | Done (part 4c, [#158](https://github.com/f8fvwgzc/tutela/issues/158)) | [ADR-0056](DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing), CONTRACTS.md 7.13.9 |
| The flaky `ha.rs` port race: a test's `tutelad` binds port 0 itself and says where | Done (part 4c, [#147](https://github.com/f8fvwgzc/tutela/issues/147)) | `crates/tutelad/tests/common` |
| `v0.2.0`, a pre-release: every crate and both npm packages at 0.2.0, MIGRATION-0.2.md, CHANGELOG.md | Done (part 4c) | [MIGRATION-0.2.md](MIGRATION-0.2.md), [CHANGELOG.md](../CHANGELOG.md) |
| A test against a real Keycloak 26.8.1 (pinned by digest, dev mode on loopback): a realm with the step-up browser flow and the chart's Console client imported from its partial-import JSON; real tokens from Keycloak's own login and OTP pages exchanged at `POST /oauth2/token` (step-up, refusals, once only, one person per `(iss, sub)`, key rotation); the browser check signing in at Keycloak; `make keycloak` with `TUTELA_REQUIRE_KEYCLOAK=1`. It found that the chart's client gave two audiences (`account`); the client now has no full scope | Done (after Phase B, [#87](https://github.com/f8fvwgzc/tutela/issues/87)) | [ADR-0057](DECISIONS.md#adr-0057-a-real-keycloak-26-in-the-tests-a-pinned-image-a-realm-made-from-the-chart-and-a-client-without-full-scope) |

Not started:

| Work | Part | Note |
|---|---|---|
| Publishing: the image to `ghcr.io/f8fvwgzc/tutelad`, the chart to `oci://ghcr.io/f8fvwgzc/charts`, the npm packages | owner | The commands are in ADR-0055 item 8 and ADR-0056 item 14. |
| The JavaScript toolchain bump of Dependabot #153 (node above 22.12, the pinned Chromium, TypeScript 7, vitest 5) | open | [#156](https://github.com/f8fvwgzc/tutela/issues/156) |
| OTLP export of traces | open | Logs and audit records carry the caller's `traceparent` trace and span ids today. |

The service gate:

| Check | State |
|---|---|
| A query with no tenant set returns zero rows | **Passes** on a real Postgres (`crates/tutelad/tests/rls.rs`) |
| A cross-tenant read fails at RLS, even with an injected code bug | **Passes**, with a control that shows the same request leaks when RLS is off |
| Group and path closure p99 | **Passes** the 5 ms threshold going up: 1.44 ms, 1.46 ms at 32 levels, 0.67 ms for a path. Going down (`scopes_below`) is 11 ms, not gated ([ADR-0020](DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry)) |
| 2+ replicas | **Passes**: two real `tutelad` processes on one Postgres answer together, share a sweep (one expiry, one revision), and one keeps serving when the other stops (`crates/tutelad/tests/ha.rs`). The Helm chart runs two pods by default (refuses fewer); in a kind cluster both became ready and the Service kept answering while one was deleted (part 4c, by hand, not in `make`) |
| Bundle expiry | **Passes.** A replica's snapshot stops at its age limit and at `next_expiry`, also during an outage, and fails closed (`crates/tutelad/tests/ha.rs`). A signed bundle's `exp` is never later than the first assignment in it that expires, and a product's `OfflinePdp` answers from it with `tutelad` stopped until `exp`, then answers nothing; an expired, older, changed, denied-`kid` or newer-format bundle is refused (`crates/tutelad/tests/bundle.rs`, [ADR-0038](DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp)). `crates/tutelad/tests/ha.rs` also runs the shipped binary as a separate process, stops it, and the product's `OfflinePdp` answers from the bundle on the wall clock until `exp`, then nothing (ADR-0042) |
| A revoked role takes effect within the documented delay | **Passes on replicas**: documented at most 1.5 s, measured p50 0.61 s, worst 1.010 s over 60 rounds under steady traffic. The test fails above 1.5 s. A replica cut off from the database stops at the age limit of the action, also tested ([PERMISSION-MODEL.md 16.1](PERMISSION-MODEL.md#161-how-long-until-a-revocation-takes-effect)) |
| Sign-in, the permission map and runtime role editing, end to end | **Passes in a real browser** (part 4b2, `crates/tutelad/tests/console_e2e.rs` running `console/e2e/exit-check.spec.ts` in Playwright's Chromium, in `make`): an owner signs in to the Console with MFA through a provider shaped like Keycloak 26, the rail shows the pages the permission map allows, the owner gives and removes a role in `MembersTable`, and a second person's Console shows the change within the documented 1.5 s (measured 285 to 795 ms in the runs of part 4b2) and no admin action they do not hold; the owner edits a role in the permission matrix, the RoleEditor shows the impact sentence, and the publish is a new model version; no token is in cookies, `localStorage`, `sessionStorage` or IndexedDB (TM-06); an admin token six minutes old and a sign-in without step-up are refused; no CSP violation. **Passes against a real Keycloak 26.8.1 as well** (`make keycloak` with `TUTELA_REQUIRE_KEYCLOAK=1`, [#87](https://github.com/f8fvwgzc/tutela/issues/87), [ADR-0057](DECISIONS.md#adr-0057-a-real-keycloak-26-in-the-tests-a-pinned-image-a-realm-made-from-the-chart-and-a-client-without-full-scope)): the same spec, the people signing in at Keycloak's own login and OTP pages through the chart's Console client, after real Keycloak tokens were exchanged, refused without step-up, refused when used twice or for another audience or realm, and accepted after a realm key rotation |

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

Part 3c is done; these notes stay for what they say about the code. The notes for part 4 follow. Read these with [ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change) to [ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable).

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

Done in part 3c: `tutela.admin.v1` exposes `RegisterAgent` (with the workload's SPIFFE id on `/ns/<ns>/svc/<service>`), `SetDisabled` and `RevokeSessions` under the admin token rule of ADR-0032 (ADR-0040). The rest of these notes moved to the notes for part 4.

- **`tutela keys rotate`** calls the key store of the notes for part 3b with the vault from `TUTELA_MASTER_KEY`.

#### Notes for after Phase B

Part 4c is done, and with it every part of Phase B: the OCI image ([ADR-0055](DECISIONS.md#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release)), the Helm chart and its bootstrap job ([ADR-0056](DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing)) and the `v0.2.0` pre-release ([CHANGELOG.md](../CHANGELOG.md)). These notes are for the next jobs.

- **attache and texc-symphony bump from `v0.1.0` to `v0.2.0`** ([#44](https://github.com/f8fvwgzc/tutela/issues/44)). In library mode, which both use today ([MIGRATION-0.2.md, the short list](MIGRATION-0.2.md#the-short-list-for-a-v010-user)):
  1. `tag = "v0.2.0"` for every Tutela crate (the crates now say `version = "0.2.0"`).
  2. Branch on `kind()` of the opaque errors; print causes with `tutela_contracts::error_chain` at the sites MIGRATION-0.2.md lists (attache `services/embassy/src/authz.rs`, texc-symphony `crates/symphony-server/src/tutela.rs`); one tenant per `tutela-store` transaction; `AuditEventV1 { details: None, .. }`; `provision_user` returns `(PrincipalState, bool)`.
  3. Run `tutela migrate` as the owner (migrations 3 to 14), then `grant_service`; every store write now emits an outbox event: prune them (`prune_events`) or read them (`events_after`).
  4. Each repo's own gates, with a real Postgres.
- **When they move to the service** (optional, a larger step; each item is in MIGRATION-0.2.md under "when they bump"):
  - both: an app per product and tenant, made by the chart's bootstrap job (`apps:` in its values; the product reads `client_id`, `client_secret`, `tenant`, `issuer` and `token_url` from its Secret, CONTRACTS.md 7.13.9) or by `tutela apps create`; `client_credentials` for their own token; `tutelad`'s issuer in their `tutela-sdk` trust list (`<TUTELA_ISSUER>/.well-known/jwks.json`, ES256); events from SSE `GET /v1/events` or a webhook (the job can register it);
  - attache: its app's service account with `manage_agents` at every org (`owner` at the org); agents through `RegisterAgent`, quarantine through `SetDisabled`; the embassy's issuer in `tutelad`'s trust file with `workloads = true`; for ledger forwarding, `tutelad`'s producer key in `ledger.producers`;
  - texc-symphony: its pipeline's app with `manage_access`, `manage_fields` and `read_audit` at every org; `tutela apply --server`; `symphony` as an `[[audience]]` with `delegation_aware = true`, delegation on in its verifier.
- **Done since `v0.2.0`:** the test against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87), [ADR-0057](DECISIONS.md#adr-0057-a-real-keycloak-26-in-the-tests-a-pinned-image-a-realm-made-from-the-chart-and-a-client-without-full-scope)): the chart's Console client imports into Keycloak 26.8.1 and works there after one fix (no full scope, so one audience); the realm's step-up browser flow stays the realm admin's step, now written out in JS-SDK.md.
- **Still open**:
  - publishing the image, the chart and the npm packages from the tag (the owner; ADR-0055 item 8, ADR-0056 item 14); an amd64 image build was not run; the Ingress was not exercised (no controller in kind);
  - the JavaScript toolchain bump that Dependabot #153 asked for ([#156](https://github.com/f8fvwgzc/tutela/issues/156));
  - OTLP export of traces;
  - from earlier notes, each in its ADR: a granter with conditions taken at its lowest (ADR-0043 item 3), bundles not narrowed to an app (ADR-0044 item 11), `TUTELA_KEY_PEPPER_PREVIOUS` (ADR-0044 item 10), private-key JWT client authentication, `cnf` binding of delegated tokens, erasing personal data inside audit bodies (TM-20); for the Console: access requests after `not_held`, "which roles may I give here", the audit log over the API, a view of sessions, names of people.
- **Next phases:** C (an own login server, optional) and D (hardening), below.

#### Notes for part 4c

Part 4b2 is done: the Console is served by `tutelad` (ADR-0050), the Console app (ADR-0052), the test provider (ADR-0051) and the exit check in a real browser (ADR-0053). Part 4c builds the Helm chart with its bootstrap job, the OCI image ([#49](https://github.com/f8fvwgzc/tutela/issues/49)) and the v0.2.0 tag.

- **New code in part 4b2.** `crates/tutelad/src/console.rs` (the files, the headers, `config.json`), `Config::console`, `api::api_router`'s Console branch; `crates/tutela-test-idp` (library and binary); `console/` (`src/oidc.ts` sign-in, `src/access.ts` the permission map and the rail, `src/pages/*`, `test/`, `e2e/exit-check.spec.ts`, `playwright.config.ts`); `tutela-js` `searchResources`; `tutela-pdp` search names orgs; `crates/tutelad/tests/console.rs`, `console_e2e.rs`; `make js-e2e`.
- **What the image must copy.** The built Console: `console/dist` (`index.html`, `favicon.svg`, `assets/*`), made by `pnpm install --frozen-lockfile && pnpm -r run build` with node 22.12+ and pnpm 10.18 in a build stage. Copy it to a directory of the image (for example `/srv/tutela/console`) and set `TUTELA_CONSOLE_DIR` to it. The files are read once at start: a new Console is a new image. Nothing else of `console/` is needed at run time, and the runtime image needs no node.
- **Every setting the Helm chart must set for the Console** (besides `deploy/tutelad.env`):
  - `TUTELA_CONSOLE_DIR` (the directory above), `TUTELA_CONSOLE_ISSUER` (the realm's issuer, written exactly as the trust file's `iss`) and `TUTELA_CONSOLE_CLIENT_ID` (the Console's public client). With `TUTELA_CONSOLE_DIR` unset the Console is off.
  - `TUTELA_CORS_ORIGINS` only for products that embed the components on their own origin without a proxy (exact `https` origins; ADR-0054); the Console needs none.
  - `TUTELA_ADMIN_ACR`: required with the Console (start-up fails without it); its first value is what the Console asks for at sign-in, so it must be the name of the realm's MFA level.
  - The trust file's `[[issuer]]` for the realm: `external = true`, `allow_typ_jwt = true` (Keycloak's access tokens are `typ: JWT`), `algs = ["RS256"]` (Keycloak's default), `tenants = ["<tid>"]` (one), its `jwks_uri`; `private_hosts` when Keycloak is on a private network.
  - `TUTELA_AUDIENCE` (default `tutela-authz`), which the realm's audience mapper must add. `TUTELA_REVISION_CHECK_MS` stays at most 1000 for the 1.5 s delay the Console shows changes within.
  - The ingress routes `/console/` (and `/console`) to the API port with the other public paths, over https, and must not add or loosen a Content-Security-Policy; dev mode stays off (an `https` realm). A CDN in front may cache `assets/` for a year (`immutable`) but never `index.html` or `config.json`.
- **What the bootstrap job must create for the Console's Keycloak client** (JS-SDK.md, "Configure Keycloak for it"): a public client (`publicClient: true`), standard flow only (no implicit flow, no direct access grants), PKCE `S256` required (`pkce.code.challenge.method`), redirect URI `https://<host>/console/callback`, web origin `https://<host>`, post-logout redirect URI `https://<host>/console/`, an audience mapper adding `TUTELA_AUDIENCE` to the access token, and the realm's ACR-to-LoA mapping with the MFA level named as `TUTELA_ADMIN_ACR` and a browser flow that asks for OTP at that level. The first owner is the Keycloak user given to `tutelad tenant create --admin-upstream <iss>=<sub>`; the job prints the Console's URL.
- **Still missing for the Console:**
  - a test against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87)): the check runs against the test provider (done after Phase B, ADR-0057);
  - names of people: Tutela keeps none, so the Console shows principal ids (the signed-in person's own name comes from the realm's ID token);
  - a route for access requests after `not_held`, "which roles may I give here", a read of the audit log over the API, a view of a person's sessions (as in the notes for part 4b2);
  - a person with roles only below an org sees just the overview: the Console finds scopes from orgs;
  - an open Console tab asks the permission map twice a second per org it shows (a hidden tab does not); server-sent events for browsers would be quieter (ADR-0037 keeps them for services).
- **Dependabot** pull requests: #130 and #131 were merged in part 4c; #153 (which replaced #133) was closed red, see [#156](https://github.com/f8fvwgzc/tutela/issues/156).

#### Notes for part 4b2

Part 4b1 is done: the JavaScript workspace and its gate ([ADR-0047](DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make)), `@f8fvwgzc/tutela-js` ([ADR-0048](DECISIONS.md#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice)) and `@f8fvwgzc/tutela-react` ([ADR-0049](DECISIONS.md#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people)). Part 4b2 builds the Tutela Console on them, serves it from `tutelad`, and runs the end-to-end exit check in a real browser. The guide is [JS-SDK.md](JS-SDK.md).

- **New code in part 4b1.** `sdk/js/src`: `client.ts` (`TutelaClient`, every route), `auth.ts` (`BrowserSession`, `serviceAuth`, `payload`), `http.ts` (`Transport`: timeout, problems, the 503 retry), `errors.ts`, `permissions.ts` (`PermissionMap`, `PermissionStore`), `model.ts` (`permissionMatrix`, `setRoleGrants`), `types.ts`. `sdk/react/src`: `context.tsx`, `hooks.ts`, `MembersTable.tsx`, `RoleEditor.tsx`, `PermissionMatrix.tsx`, `ErrorNotice.tsx`, `cells.tsx`, `theme.ts`; `sdk/react/styles/tutela.css`. Server: `GET /v1/models/active` and `GetActiveModel` ([#132](https://github.com/f8fvwgzc/tutela/issues/132)); `grant_excess` holds a group change that makes an `in_group` condition hold ([#127](https://github.com/f8fvwgzc/tutela/issues/127)). Tests: `crates/tutelad/tests/js_client.rs` makes the world and runs `sdk/js/test-integration` against a real `tutelad`. Gates: `make js` (part of `make`).
- **The package API the Console should use.**
  - One `TutelaClient` per signed-in person: `new TutelaClient({ baseUrl: "", auth: { kind: "browser", getUpstreamToken } })` (an empty base is the page's own origin). `getUpstreamToken(reason)` must give a token the session has not sent before; with keycloak-js, `await kc.updateToken(-1); return kc.token`. `client.session.state` / `subscribe` drive the sign-in banner (`step-up-required` asks for MFA, then `session.stepUp()`); `session.signOut()` on sign-out.
  - `<TutelaProvider client>` at the root; pages use `MembersTable` (scope pages), `PermissionMatrix editable` with `onReview` feeding `RoleEditor roleKey draft` (roles page), and `ErrorNotice` for every other call. Each typed error's meaning is in JS-SDK.md, Errors.
  - The other Console pages call the client directly: `scopes.list({under})` (the tree; `ancestors` is the `path` MembersTable needs), `groups.*`, `models.versions/version/proposals/approve/reject/settings`, `principals.*`, `agents.*`, `apps.*` (show a secret once, never keep it), `webhooks.*` (dead deliveries: `deliveries(id, {state: "dead"})`, `redeliver`), `tenant.*`, `orgs.*`, `explain`, `simulate`.
  - `useCan(action, resource)` after `usePermissionMap(resource, actions)` decides what a page shows; the server decides what happens.
- **How the Console should be served and signed into** (decide in an ADR of part 4b2; this is the plan part 4b1 leaves):
  - Served by `tutelad` on the API port under one prefix (for example `/console/`), from a directory set by configuration (for example `TUTELA_CONSOLE_DIR`), so `cargo build` still needs no node; the OCI image of part 4c copies the built Console there. Same origin as the API: no CORS needed, and `credentials: "omit"` stays.
  - The Console is a `console/` member of the pnpm workspace, built by a bundler (Vite) into static files; `make js` builds and tests it.
  - Static files need no token (like the JWKS paths, ADR-0030): list the exact paths. Send a strict Content-Security-Policy (`default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' <the Keycloak origin>; frame-ancestors 'none'; base-uri 'none'`), `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. The components use no inline style or script, so this CSP needs no exception.
  - Sign-in: authorization code with PKCE (S256) at the tenant's Keycloak realm, as a public client whose access tokens have `aud = TUTELA_AUDIENCE` and, after MFA, an `acr` in `TUTELA_ADMIN_ACR`. The Console needs the realm URL and client id at start: serve them from `tutelad`'s configuration (a small JSON next to the files), never from the person. With one realm per deployment (ARCHITECTURE.md) that is one value.
  - The TM-06 test in a real browser: after sign-in and a role change, nothing in `document.cookie`, `localStorage`, `sessionStorage` or IndexedDB holds a token (jsdom already checks it, `sdk/js/test/storage.test.ts`); an admin token six minutes old is refused; a call without step-up is refused.
- **The end-to-end exit check** needs a test OIDC provider with an authorization endpoint, which the repo does not have (`exchange.rs` signs Keycloak-shaped tokens locally; a real Keycloak is [#87](https://github.com/f8fvwgzc/tutela/issues/87)). Docker image pulls hang on the owner's Mac, so a small in-repo provider (a test binary that serves `/authorize`, `/token` and a JWKS on loopback) may be the way. The browser: Playwright's Chromium, if its download works; otherwise a locally installed Chrome.
- **What part 4b1 found missing:**
  - CORS for a product page on another origin ([#135](https://github.com/f8fvwgzc/tutela/issues/135)); until then a product proxies `tutelad` on its origin (JS-SDK.md).
  - A route for access requests: `MembersTable`'s "Ask an admin who holds more" hands the request to the host (`onAskAdmin`).
  - "Which roles may I give here": the components offer every role and show `not_held`; a dry run of `grant_excess` per role is possible but not built.
  - Names: Tutela keeps no names of people or scopes. The Console shows principal ids (with the signed-in person's own name from Keycloak) unless a product passes `renderSubject`.
  - Still open from part 4b: a read of the audit log over the API, a view of a person's sessions, events per principal.
- **Decisions part 4b1 made** (each in its ADR): `sdk/js` and `sdk/react` in one pnpm workspace with Biome instead of ESLint (node 22.12), `tsc` without a bundler, exact pins and a week's release age (ADR-0047); one upstream token gives both the `tutela-authz` and the admin token (authz first, then admin from it), tokens in memory only with `credentials: "omit"`, a 503 retry that never repeats a create, the revision kept from writes only (ADR-0048); one scoped stylesheet with `--tutela-*` variables, the host names the people, `MembersTable` takes the scope's `path`, the RoleEditor's change built from `GET /v1/models/active` with `setRoleGrants` (ADR-0049).

#### Notes for part 4b

Part 4a is done. Part 4b builds the Console and the embeddable admin components (`@f8fvwgzc/tutela-js`, `@f8fvwgzc/tutela-react`: MembersTable, RoleEditor, the permission matrix) and the end-to-end exit check; part 4c the Helm chart with its bootstrap job, the OCI image ([#49](https://github.com/f8fvwgzc/tutela/issues/49)) and the v0.2.0 tag. Read these with [ADR-0043](DECISIONS.md#adr-0043-scopes-assignments-and-groups-over-the-admin-api-checked-on-the-data-they-change) to [ADR-0046](DECISIONS.md#adr-0046-the-cli-against-tutelad-apply-with-the-impact-report-apps-and-keys-through-the-key-store) and CONTRACTS.md 4.9, 7.9, 7.13.

- **New code in part 4a.** `tutela-pdp`: `grant.rs` (`grant_excess`, the narrow-only rule), `tests_grant.rs`. `tutela-store`: `apps.rs`, `audit_keys.rs`, `lock`, `group`, `group_page`, `group_member_page`, `scope_page`; migrations 13 (apps) and 14 (audit key). `tutelad`: `admin/locked.rs` (a change checked on the data it writes, under the tenant's write lock), `admin/bindings.rs`, `admin/scopes.rs`, `admin/apps.rs`, `apps.rs` (secrets and client authentication), `lifecycle::create_app`, `tutelad apps create`, `ledger::verify_record`. `tutela-cli`: `service.rs` (`apply --server`, `apps`), `keys.rs`. Mutants M01–M14, C01–C08, V01–V03 and P01–P04 are in `crates/tutelad/mutants/mutants.py`, every one caught; the script is not part of `make`, the tests that catch them are.
- **The token flow of a person in a browser** (the Console is a public client: it keeps no secret, ADR-0044 item 7):
  1. The person signs in at Keycloak with the authorization code flow and PKCE; the Console holds a Keycloak access token whose `aud` is `tutelad`'s `TUTELA_AUDIENCE` (`tutela-authz`) and whose `acr` is a step-up value (`TUTELA_ADMIN_ACR`) when the person did MFA.
  2. `POST /oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token=<keycloak token>`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `audience=tutela-admin`, and **no client authentication**. The answer is an admin token of at most 300 s for the person (`sub` found by `(iss, sub)`, the tenant from the trust list). Without step-up: `invalid_grant` with `step-up authentication is required`; ask Keycloak for MFA and try again. Each Keycloak token is exchanged once.
  3. Send `Authorization: Bearer <admin token>` to every admin route, HTTP or gRPC-web. Before it expires, get a fresh Keycloak token (a refresh at Keycloak, with step-up still valid) and exchange that: each Keycloak token is exchanged once, and an admin token never outlives the token it came from. Keep tokens in memory, never in storage.
  4. The Console's own permission map (what to show) is `POST /v1/authz/permissions` with a `tutela-authz` token from the same exchange (`audience=tutela-authz`): the admin token is refused on every route outside the admin API (401).
- **Every route the Console calls** (CONTRACTS.md 7.9, 7.13; "every org" is the key at each live org):

  | Page | Route (gRPC `tutela.admin.v1.Admin/`) | Needs |
  |---|---|---|
  | Tenant | `GET`/`PATCH`/`DELETE /v1/admin/tenant` | `read_audit` every org / every admin key |
  | Orgs | `GET`/`POST /v1/admin/orgs`, `PATCH`/`DELETE /v1/admin/orgs/{org}`, `POST …/restore` | as 7.13.5 |
  | Scopes tree | `GET /v1/admin/scopes?under=org:<id>` then `?under=<type>:<id>` (`ListScopes`), `PUT /v1/admin/scopes/private` (`SetPrivate`), `PUT /v1/admin/boundaries` (`SetBoundary`) | `read_audit` or `manage_access` on `under`; `manage_boundaries` on the scope |
  | Members of a scope (MembersTable) | `POST /v1/admin/assignments/list {scope}` (`ListAssignments`), `POST /v1/admin/assignments` (`Assign`), `PATCH`/`DELETE /v1/admin/assignments/{id}` (`SetAssignmentExpiry`, `Unassign`) | `read_audit` or `manage_access` there to look; `<type>:manage_access` there to change, and the narrow-only rule |
  | A person's access | `POST /v1/admin/assignments/list {subject}`, `POST /v1/authz/explain` | `read_audit` every org; `read_audit` on the resource |
  | Groups | `GET /v1/admin/groups?org=` (`ListGroups`), `POST /v1/admin/groups`, `DELETE /v1/admin/groups/{key}`, `GET`/`POST /v1/admin/groups/{key}/members`, `POST …/members/remove` | `read_audit` or `manage_access` on the org to look; `org:manage_access` to change |
  | Roles and the permission matrix (RoleEditor) | `GET /v1/admin/roles[?scope=]` (`ListRoles`) to show; a role change is a model change: `POST /v1/models/impact`, then `POST /v1/models/publish` or `/v1/models/proposals` with `expected_version`, and an approval token when it widens | `read_audit` every org (or on the scope) to show; `manage_access` and `manage_fields` every org to change |
  | Model history, proposals, two-person | `GET /v1/models`, `GET /v1/models/{version}`, `GET`/`PUT /v1/models/settings`, `GET /v1/models/proposals`, `POST …/approve`, `…/reject` | as 7.9 |
  | People and agents | `POST /v1/admin/principals/state`, `…/disabled`, `…/revoke-sessions`, `POST /v1/admin/users/delete`, `GET /v1/admin/agents` | as 7.13.1 |
  | Apps | `GET`/`POST /v1/admin/apps`, `POST /v1/admin/apps/{id}/rotate`, `…/disable` | every admin key every org; show a secret once |
  | Webhooks | `GET`/`POST /v1/admin/webhooks`, `…/rotate`, `…/disable`, `GET …/deliveries?state=dead`, `POST …/redeliver` | `read_audit` and `manage_access` every org |
  | Explain, simulate | `POST /v1/authz/explain`, `/v1/authz/simulate` | `read_audit` on the resource |

- **The shapes** (CONTRACTS.md 7.13.7): an assignment `{id, subject, role, scope{type,id}, granted_by?, created_at?, expires_at?}`; a group `{key, org, name, created_at?, members?}`; a member `user:usr_…` or `group:<key>`; a scope `{scope, ancestors[], private, moves_out?, moves_in?, on_looser?, links_from?}`; the roles answer `{version, roles[{key, label?, seeded?, levels{type: level}, field_levels{"type.field": level}, grants[], assignable_to[]}], types[{name, label?, parents[], container, starts_private, fields[{name, sensitivity, label?}], features[], actions[]}]}`. The **permission matrix** is roles × types: a cell is `levels[type]` (missing is `none`), a field row `field_levels["type.field"]` (missing: the item level, never above it), a custom action is in `grants` (`type:action`), an admin key is in `grants` (`type:manage_access`, ...). Pages are `{…, next_after?}`; pass it back as `after`.
- **What a page does with an answer.** 403 `forbidden`: hide what the person may not do. 403 `not_held`: the change would give someone more than the person holds; show the detail (counts only) and offer to ask an admin who holds more. 403 `move_refused`: show which scopes wait for an owner. 409: reload, the data moved. 503: retry after `Retry-After`. A change answers the new `rev`: send it as `at_least_revision` on the next check, so the page shows its own write.
- **What is not there yet for the Console:** a read of the audit log over the API (records are read through the store only); a view of a person's sessions (one `ses_` per exchange is not stored); "which roles may I grant here" (the RoleEditor can offer every role and show `not_held`; a dry run of `grant_excess` per role is possible but not built); events per principal over SSE (ADR-0037: services only).
- **For part 4c (Helm and the bootstrap job):** the job runs, as the owner role, `tutelad migrate`, then `tutelad tenant create --name … --admin-upstream <iss>=<sub>` (the first owner by their Keycloak account), then `tutelad apps create --tenant <tid> --name <product>` for each product chart, which prints `{client_id, principal, client_secret}` once: write the secret to a Kubernetes Secret the product's chart reads, and give the app's service account its roles (for example `owner` at the tenant's first org) with `tutela_store::assign` or the admin route. It needs `TUTELA_OWNER_DATABASE_URL`, `TUTELA_ISSUER`, `TUTELA_MASTER_KEY` and `TUTELA_KEY_PEPPER`. With forwarding on, the first replica makes the audit key; the job may print its public key for attache from `tutela keys list`. Webhook secrets come from `POST /v1/admin/webhooks` with an app's token. The chart sets every value in `deploy/tutelad.env`, without `TUTELA_AUDIT_KEY`.
- **Open, each in its ADR:** a granter with conditions is taken at its lowest (ADR-0043 item 3); bundles are not narrowed to an app (ADR-0044 item 11); `TUTELA_KEY_PEPPER_PREVIOUS` is still proposed (ADR-0044 item 10); private-key JWT client authentication; `cnf` binding of delegated tokens; erasing personal data inside audit bodies (TM-20); a test against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87)).

#### Notes for part 4

Part 4a is done; these notes stay for what they say about the code, and the notes for part 4b above replace their lists of routes and open items. Part 3c is done. Read these with [ADR-0040](DECISIONS.md#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org) to [ADR-0042](DECISIONS.md#adr-0042-the-audit-logs-leftovers-a-chain-check-on-a-timer-the-callers-trace-in-each-record) and CONTRACTS.md 7.9 and 7.13. Part 4 builds the Console, the CLI's commands against `tutelad`, apps and client authentication, the Helm chart with its bootstrap job, the OCI image, the end-to-end exit check and the v0.2.0 tag.

- **New code in part 3c.** `tutelad`: `admin/` (`mod.rs`: `guard`, `refused`, `store_problem`, `observed`; `principals.rs`, `boundaries.rs`, `types.rs`, `lifecycle.rs`, `webhooks.rs`, `wire.rs`, `http.rs`, `grpc.rs`), `lifecycle.rs` (the operator's `create_tenant`, `restore_tenant`, `connect_owner`, the purge's records), `expiry::purge`, `audit::check_chains`, `telemetry::RequestContext`. `tutela-store`: `lifecycle.rs`, migration 12, `agents`, `webhooks::webhook`, `webhooks::delivery_page`. The proto is `crates/tutela-contracts/proto/tutela/admin/v1/admin.proto`. Mutants D01–D08, G01–G09, H01–H05 and K01–K05 are in `crates/tutelad/mutants/mutants.py`, every one caught; the script is not part of `make`, the tests that catch them are.
- **Adding an admin operation.** One function in `tutelad::admin` over `admin::wire` types; a route in `api::api_router`'s `admin` router; a method in `admin.proto` and `admin/grpc.rs`. Start it with `admin::guard(state, id, &tenant, KEYS, "tutela_<thing>:<verb>", (type, id))`: it applies the admin token rule, checks the keys at every org on fresh data, and records a refusal. Write the change's record with `audit::write` last in its transaction. Count it with `admin::observed`.
- **The tokens.** Every admin route and every `tutela.admin.v1` method takes the same two (ADR-0032, ADR-0040):
  - **the Console** (a person): an admin token, `aud=tutela-admin`, from token exchange after step-up (`audience=tutela-admin`, `TUTELA_ADMIN_ACR` set to what Keycloak's step-up gives), at most 300 s: refresh it by exchanging again;
  - **a pipeline or a core** (`tutela apply`, attache, onto-intelli's adapter): its service account's `tutela-authz` token.
  A person's `tutela-authz` token, a service's admin token, an agent, a delegated token and an external token get 403 `forbidden` (gRPC `PERMISSION_DENIED`); no token or a bad one 401 (`UNAUTHENTICATED`). Every other route refuses an admin token with 401.
- **Every admin route and method**, with what it needs and answers (details and JSON in CONTRACTS.md 7.9 and 7.13). "Every org" means the admin key at each live org of the tenant; "all keys" is the six admin keys of MANIFEST.md 6 (the tenant's owner).

  | Route | gRPC `tutela.admin.v1.Admin/` | Needs | Answers |
  |---|---|---|---|
  | `GET /v1/models` | `ListModelVersions` | `read_audit` every org | active model and versions (`result_json`) |
  | `GET /v1/models/{version}` | `GetModelVersion` | `read_audit` every org | a version with its text |
  | `POST /v1/models/impact` | `ModelImpact` | `read_audit` every org | diff and impact report |
  | `POST /v1/models/publish` | `PublishModel` | `manage_access`, `manage_fields` every org | the new version |
  | `GET`/`PUT /v1/models/settings` | `GetModelSettings`/`PutModelSettings` | look / change | two-person setting |
  | `POST`/`GET /v1/models/proposals`, `GET …/{id}` | `ProposeModel`, `ListProposals`, `GetProposal` | change / look | proposals |
  | `POST …/{id}/approve`, `…/reject` | `ApproveProposal`, `RejectProposal` | change | a publish, or the closed proposal |
  | `POST /v1/admin/resource-types` | `PutResourceTypes` | `manage_access`, `manage_fields` every org | a proposal |
  | `POST /v1/admin/agents` | `RegisterAgent` | `manage_agents` every org | the agent's state |
  | `GET /v1/admin/agents` | `ListAgents` | `manage_agents` every org | a page of agents |
  | `POST /v1/admin/principals/state` | `GetPrincipal` | `manage_agents` (agent) or `manage_access` (person) every org | a principal's state |
  | `POST /v1/admin/principals/disabled` | `SetDisabled` | as above | the state with the new epoch and `rev` |
  | `POST /v1/admin/principals/revoke-sessions` | `RevokeSessions` | as above | the state with the new epoch and `rev` |
  | `POST /v1/admin/users/delete` | `DeleteUser` | `manage_access` every org | the state, disabled for good |
  | `PUT /v1/admin/boundaries` | `SetBoundary` | `<type>:manage_boundaries` on the scope | `{rev}` |
  | `GET`/`PATCH`/`DELETE /v1/admin/tenant` | `GetTenant`/`UpdateTenant`/`DeleteTenant` | `read_audit` every org / all keys / all keys | the tenant (`purge_after` after a delete) |
  | `GET`/`POST /v1/admin/orgs` | `ListOrgs`/`CreateOrg` | `read_audit` every org / all keys | orgs / the new org (the caller owns it) |
  | `PATCH`/`DELETE /v1/admin/orgs/{org}`, `POST …/restore` | `UpdateOrg`/`DeleteOrg`/`RestoreOrg` | `manage_access` on that org / all keys / all keys | the org |
  | `GET`/`POST /v1/admin/webhooks` | `ListWebhooks`/`RegisterWebhook` | `read_audit` and `manage_access` every org | webhooks / the webhook and its secret, once |
  | `POST /v1/admin/webhooks/{id}/rotate`, `…/disable` | `RotateWebhookSecret`, `DisableWebhook` | as above | the new secret, once / the webhook |
  | `GET /v1/admin/webhooks/{id}/deliveries`, `POST …/{seq}/redeliver` | `ListDeliveries`, `Redeliver` | as above | a page of deliveries / the delivery |
  | `POST /v1/authz/explain`, `/v1/authz/simulate` | (`tutela.authz.v1` `Explain`, `Simulate`: services only) | `read_audit` on the resource | explanation, simulation |

- **Error codes** of the admin API (problem documents, CONTRACTS.md 7.1; gRPC message `<code>: <text>`): 400 `invalid_request`, `invalid_manifest`, `app_mismatch`, `invalid_url` (`INVALID_ARGUMENT`); 401 `invalid_token` (`UNAUTHENTICATED`); 403 `forbidden`, `unknown_tenant`, `approval_required`, `two_person_required`, `same_person` (`PERMISSION_DENIED`); 404 `not_found` (`NOT_FOUND`); 409 `version_conflict`, `no_change`, `no_source`, `stale_proposal`, `not_open`, `busy`, `exists`, `not_additive`, `last_org` (`ABORTED`); 413/415 for a body too large or not JSON; 503 `unavailable`, `stale`, `no_data`, `expired` (`UNAVAILABLE`). A Console page reacts to 403 `forbidden` by hiding what the person may not do, to 409 by reloading, and to 503 by retrying.
- **Who makes a tenant: the operator, never the API** (ADR-0041). `tutelad tenant create --name … --admin <user:…|sa:…> --admin-upstream <iss>=<sub>` as the owner role, under `TUTELA_ISSUER`, prints `{tid, iss, org, owners, rev}`; then the trust file maps the external issuer to that `tid`. The Helm bootstrap job calls the same `tutelad::lifecycle::create_tenant`, with the first admin from its values, and writes the tid where the products' charts read it. The Console has no "new tenant" page for a tenant's admin; a deployment console for operators would need an operator identity Tutela does not have (TM-08).
- **How apps should attach to a tenant (the plan part 3c leaves; decided in part 4a by [ADR-0044](DECISIONS.md#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated), which follows this plan and leaves bundles as ADR-0038 has them):** an app (`tutela apps create`) belongs to **one tenant**, made by that tenant's owner (all admin keys at every org, like making an org) or by the operator for the bootstrap. Its client credentials authenticate at the token endpoint and bind `azp` (ADR-0031). Its service account (`sa:`) is the app's principal: it gets roles through ordinary assignments, never admin keys by default, and its `client_credentials` token has the tenant from the app's record, never from the request. An app's `audience` is registered per tenant (the manifest's `[app] audience`), and part 4 may narrow `GET /v1/authz/bundle` to an app of that audience (ADR-0038 item 2). Record each app operation in the tenant's audit chain with who asked, through `admin::guard`.
- **What the Console needs that is not built:** service-mode scopes, role assignments and groups (MembersTable, RoleEditor, the permission matrix) and a move behind `write_check` ([#107](https://github.com/f8fvwgzc/tutela/issues/107)); a read of the audit log over the API (records are read only through the store today); a view of a person's sessions (one `ses_` per exchange is not stored). `ListDeliveries` with `dead_only` is the dead-letter view ADR-0036 asked for.
- **Open, each in its ADR:** client authentication at the token endpoint and `cnf` binding (part 4); erasing personal data inside audit bodies (TM-20, ADR-0041 item 8); `ip` in audit records (ADR-0042 item 3); OTLP export; an incremental chain check for very long chains (ADR-0042); a test against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87)); the relay, the forwarder and the chain check visit every tenant each tick, which wants an index of tenants with work once tenants are many.

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
