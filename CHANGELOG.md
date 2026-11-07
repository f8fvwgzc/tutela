# Changelog

Each release is a git tag; depend on it by tag, never by path. What a consumer must change is in [docs/MIGRATION-0.2.md](docs/MIGRATION-0.2.md). The full record of decisions is [docs/DECISIONS.md](docs/DECISIONS.md).

## Unreleased

### Tested against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87), [ADR-0057](docs/DECISIONS.md#adr-0057-a-real-keycloak-26-in-the-tests-a-pinned-image-a-realm-made-from-the-chart-and-a-client-without-full-scope))
- `make keycloak` (`scripts/keycloak-check.mjs`, skipped unless `TUTELA_REQUIRE_KEYCLOAK=1`): Keycloak 26.8.1 pinned by digest, in dev mode on loopback; a realm with the step-up browser flow and the chart's Console client imported from its partial-import JSON. `crates/tutelad/tests/keycloak.rs` exchanges real Keycloak tokens at `POST /oauth2/token`; the Console's browser check runs against it too, signing in at Keycloak's own login and OTP pages.
- **Fixed: the Helm chart's Console client gave two audiences.** A person with the realm's default roles got `aud: ["tutela-authz", "account"]` (Keycloak's full scope), which `tutelad` refuses. The client now has `fullScopeAllowed: false`. If you imported the v0.2.0 client into a realm, turn "Full scope allowed" off on it (its dedicated client scope), or import the new file over it.
- JS-SDK.md, "Configure Keycloak for it": the steps that worked against Keycloak 26.8.1 (the browser flow's levels and max ages, `acr` and `amr` values, the hostname).
- `tutela-sdk`: a test with a captured Keycloak 26.8.1 JWKS and two of its tokens, run without Docker.

### The JavaScript toolchain ([#156](https://github.com/f8fvwgzc/tutela/issues/156), Dependabot #153, [ADR-0047](docs/DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make))
- **node 22.22.2 or later** (`engines`, `.nvmrc`, the image's node stage `node:22.22.2-bookworm-slim` pinned by digest), for `jsdom` 30. With nvm: `nvm install` in the repo.
- `typescript` 7.0.2, `vitest` 5.0.5, `jsdom` 30.1.3, `@biomejs/biome` 2.6.4 (Markdown left out of its files), React 19.3.1 in the Console and the tests (`tutela-react`'s peer range stays `^19.0.0`). No source change was needed.
- Not bumped: `@playwright/test` stays at 1.63.0, whose Chromium is build 1243 ([#163](https://github.com/f8fvwgzc/tutela/issues/163)); `@types/node` stays at 22.x, the node major that runs the tests.

## v0.2.0 (Phase B, the service): 2026-11-07

**Pre-release.** GitHub Actions did not run (account billing); every merge was gated by local `make` with a real Postgres (`TUTELA_REQUIRE_DATABASE=1`): fmt, clippy `-D warnings`, tests, doc, cargo-deny, cargo-audit, the JavaScript gates (build, tsc, Biome, vitest, the integration test against a real `tutelad`, the Console's browser check in Playwright's Chromium, `pnpm audit`, licences), hadolint on the `Dockerfile` and the Helm chart check.

```toml
tutela-contracts = { git = "ssh://git@github.com/f8fvwgzc/tutela.git", tag = "v0.2.0" }
```

### Breaking for v0.1.0 users
- Public errors are opaque structs with a `kind()` (`StoreError`, `SqlError`, `SafenetError`, `VaultError`); `From<tokio_postgres::Error>` is gone ([ADR-0017](docs/DECISIONS.md#adr-0017-opaque-public-errors-for-the-crates-that-touch-the-outside-world)).
- A `tutela-store` transaction belongs to one tenant (`TenantMismatch`).
- Migrations 3 to 14; every store write emits an outbox event; `AuditEventV1.details`, `provision_user` returning `(PrincipalState, bool)`, `TenantBundle.next_expiry`.
- The list and the code changes: [docs/MIGRATION-0.2.md](docs/MIGRATION-0.2.md).

### The service: `tutelad` (new crate)
- Two ports (API: HTTP and gRPC; ops: health, readiness, metrics), JSON logs, graceful shutdown, `tutelad migrate` as the owner role.
- Tenants under forced row-level security, the tenant only from the verified token; a cross-tenant read fails at RLS even with an injected bug.
- The check API (AuthZEN-shaped evaluation, evaluations, searches; gRPC `tutela.authz.v1`), the permission map with ETag/304, `write_check` with moves and links, signed bundles for offline checks.
- Model versions per tenant, the impact report, explain and simulate, two-person publish.
- Its own issuer: signing keys sealed by `tutela-vault`, a JWKS without a token, rotation and a `kid` deny-list. Token exchange (RFC 8693) with just-in-time provisioning; admin tokens after step-up; delegated agent tokens (`act`, `typ: agent+jwt`).
- Apps with hashed client secrets, `client_credentials`, `azp` bound to the authenticated client.
- The admin API `tutela.admin.v1` over HTTP and gRPC (agents, people, scopes, assignments, groups, the model, tenants, orgs, webhooks, apps), held to the narrow-only rule.
- A local hash-chained audit log per tenant, a transactional outbox, Standard Webhooks delivery, SSE `GET /v1/events`, forwarding to attache's evidence ledger with a sealed, rotatable producer key.
- The lifecycle of tenants, orgs and people: soft delete with a grace, a purge that keeps the audit chain.
- CORS for exact origins, off by default.

### The Console and the JavaScript SDKs (new)
- `@f8fvwgzc/tutela-js` (the browser token flow in memory, every admin route, typed errors) and `@f8fvwgzc/tutela-react` (`MembersTable`, `RoleEditor`, `PermissionMatrix`), version 0.2.0. Not published to a registry yet.
- The Tutela Console, served by `tutelad` under `/console/` with a strict CSP: sign-in by code with PKCE, the pages the permission map allows, role editing with the impact first.

### Deploy (new)
- The OCI image: a `Dockerfile` with the Console, a distroless non-root runtime, base images pinned by digest ([ADR-0055](docs/DECISIONS.md#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release)). Built and run locally (linux/arm64, 62 MB); **not pushed** to `ghcr.io/f8fvwgzc/tutelad`.
- The Helm chart `deploy/helm/tutela` with its bootstrap job (`tutelad bootstrap`: migrate, the tenant, each product's app and its Secret, roles, webhooks; only what is missing) and the Console's Keycloak client as an import file ([ADR-0056](docs/DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing)). Checked by `helm lint`, `helm template` and a manifest check in `make`, and by hand in a kind cluster; **not pushed** to `oci://ghcr.io/f8fvwgzc/charts`.

### Phase B's exit checks
- Sign-in, the permission map and runtime role editing, end to end: in a real browser against a test provider shaped like Keycloak 26 (`make js-e2e`).
- A cross-tenant read fails at RLS even with an injected code bug; a revoked role takes effect within the documented 1.5 s on replicas; 2+ replicas run (two `tutelad` processes on one Postgres in `make`; two pods in kind).

### Not in this release
- A test against a real Keycloak ([#87](https://github.com/f8fvwgzc/tutela/issues/87)); the realm's step-up flow is the realm admin's step.
- Published packages: crates, npm packages, the image and the chart are built from the tag by the owner.
- OTLP export of traces; the JavaScript toolchain bump of Dependabot #153 ([#156](https://github.com/f8fvwgzc/tutela/issues/156)).
- Phase C (own login server) and Phase D (hardening).

## v0.1.0 (Phase A, library mode): 2026-10-28

**Pre-release.** CI did not run (GitHub billing); every merge was gated by local `make`: fmt, clippy `-D warnings`, doc, tests (with Postgres), cargo-deny and cargo-audit. The crates carried version `0.0.0`.

```toml
tutela-contracts = { git = "ssh://git@github.com/f8fvwgzc/tutela.git", tag = "v0.1.0" }
```

### Crates
- **tutela-contracts**: wire types (ids, principals, claims, Decision, `audit.v1`, the event envelope).
- **tutela-pdp**: the model compiler for `tutela.resources.toml` (MANIFEST v1, the narrowing/neutral/widening diff) and the evaluator (`check`, `batch`, `list_filter`, `write_check`).
- **tutela-store**: the Postgres schema and migrations for library mode: forced row-level security, checked writes in the product's transaction, scope paths, published manifests (ADR-0014).
- **tutela-sdk**: the token verifier, an auth layer for axum and tonic, route guards, a decision cache, and the `list_filter` SQL adapter.
- **tutela-vault**: envelope encryption with a KMS trait.
- **tutela-safenet**: SSRF-safe outbound HTTP, on rustls with aws-lc-rs.

### CLI (`tutela`)
`init`, `check`, `codegen`, `migrate`, `apply` (a widening diff needs an Ed25519 approval token, ADR-0015), `approve`, `approvers keygen|add|list|revoke`.

### Not in this release
Fuzzing; the JS and Python SDKs and the template product; everything in Phase B (`tutelad`).
