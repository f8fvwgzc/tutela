# Tutela

Tutela is a self-hostable identity and permissions core, like Clerk or Auth0, for one developer's platform of products. It gives every product the same login, keys, roles and permission checks. It has its own backend service (`tutelad`), its own web UI (the Tutela Console) and packages that products install: Rust crates, npm packages and a Python package. Tenants define their own resource types and roles at runtime; nobody hard-codes roles in a product any more.

**The name.** Tutela was the Roman goddess of protection and guardianship. In Roman law, *tutela* is a guardian's legal power to act for someone else, which is exactly what delegation is when an AI agent acts for a person.

> **Status: pre-alpha.** `v0.1.0` is a pre-release of the Rust crates in library mode. The `tutelad` service exists and answers permission checks over HTTP and gRPC. Nothing here is usable in production yet. See [Status](#status).

## Is Tutela required?

The answer has three parts.

| Part | Required? | Why |
|------|-----------|-----|
| Tutela core packages (crates, npm, Python) | **Yes** | Every product needs login, keys, roles and permission checks. Today four different hard-coded role sets exist across the projects, and no tenant can define its own roles. |
| A running `tutelad` service | **Yes**, for runtime work | Needed for tenant-defined roles at runtime and for apps that are not written in Rust. |
| Tutela's own login server (OIDC provider) | **No**, optional | Keycloak 26.x (Apache-2.0) is the login server first, and it can stay for good. Tutela's own login server comes in Phase C, only if wanted. |

## The boundary rule

Tutela answers: "may this principal touch this data or resource?"
attache answers: "may this agent use this tool, host or model, and at what risk?"
onto-intelli keeps per-entity visibility inside graph traversal (called once per entity, in-process), fed by Tutela's permissions.
UI hiding is never security. Every server checks again.

**What Tutela never does:** store a product's records, decide an agent's tool, host or model use (attache does that), or run workload mTLS (attache owns SPIFFE).

## Packages it will publish

Nothing is published to a registry yet. Other repos depend on the Rust crates by the `v0.1.0` git tag. The phase column says when each package is planned.

| Kind | Name | What it does | Phase |
|------|------|--------------|-------|
| Rust crate | `tutela-contracts` | Wire types: ids, principals, token claims, the Decision object, `audit.v1`, the event envelope; the `tutela.authz.v1` and `tutela.admin.v1` protos (`proto/`) | Started in the first commit; grows in A; protos in B |
| Rust crate | `tutela-pdp` | Embedded decision engine: `check`, `batch`, `list_filter`, `write_check` | A |
| Rust crate | `tutela-sdk` | Token verifier, axum and tonic layers, decision cache | A |
| Rust crate | `tutela-store` | Postgres schema and migrations for bindings, field rules and groups (library mode and `tutelad`) | A |
| Rust crate | `tutela-vault` | Envelope encryption with a KMS trait | A |
| Rust crate | `tutela-safenet` | SSRF-safe outbound HTTP | A |
| npm | `@f8fvwgzc/tutela-react` | `<Can>`, `<Field>`, `<Protect>`, `useCan`; the embeddable admin parts (RoleEditor, MembersTable, permission matrix) | A (admin parts and `useCan`: built, B part 4b1) |
| npm | `@f8fvwgzc/tutela-node` | Server middleware and check client for Node | A |
| npm | `@f8fvwgzc/tutela-js` | Browser helper | A |
| Python | `tutela-py` (import `tutela`) | Token verifier, FastAPI dependency, check client | A |
| OCI image | `ghcr.io/f8fvwgzc/tutelad` | The service and the Tutela Console; from Phase C optionally also the OIDC provider | B |
| Helm chart | `oci://ghcr.io/f8fvwgzc/charts/tutela` | Self-hosting with 2+ replicas | B (hardened in D) |
| CLI | `tutela` | `init`, `apply` (library mode, or against `tutelad` with the impact report), `codegen`, `apps create`, `keys rotate` | A (`apps create` and `keys rotate` need `tutelad`: B) |

Delivery while the repo is private: Rust crates as git dependencies pinned to a release tag, npm packages on the GitHub Packages npm registry under the `@f8fvwgzc` scope, Python through git sources pinned to a tag. Every artifact of one release carries the same version.

## Quick look: how a product uses it

> **Planned API.** None of this works yet. Names and shapes may change during Phase A.

A product declares its resource types, roles and UI keys in `tutela.resources.toml`:

```toml
# tutela.resources.toml (format v1: docs/MANIFEST.md)
version = 1

[app]
name = "crm"

[types.project]
parent    = "org"                 # every resource has exactly one parent
container = true

[types.invoice]
parent = "project"

[types.invoice.actions]
approve = { needs = "write" }     # also needs the grant on the role
export  = { needs = "read" }

[types.invoice.fields]
number = { sensitivity = "internal" }
status = { sensitivity = "internal" }
amount = { sensitivity = "confidential" } # confidential and secret fields start at None

[roles.finance]
grants = { "project" = "read", "invoice" = "write", "invoice.amount" = "read", "invoice:approve" = true, "invoice:export" = true }

[[field_rules]]                   # amount starts hidden; open it for finance
field = "invoice.amount"
role  = "finance"
max   = "read"

[ui."invoices.approve_button"]
actions     = ["invoice:approve"]
routes      = ["POST /api/invoices/{id}/approve"]  # codegen writes the server guard too
when_denied = "disable"                            # show | disable | hide | readonly

[ui."invoices.export_button"]
actions     = ["invoice:export"]
routes      = ["POST /api/invoices/export"]
when_denied = "hide"
```

`tutela apply` shows the diff first and refuses a widening diff without an approval token. `tutela codegen` writes the React constants and the server route guards from the same entries.

In React:

```tsx
// Planned API (Phase A). Package: @f8fvwgzc/tutela-react
import { Can, Field } from "@f8fvwgzc/tutela-react";
import { ui } from "./generated/tutela"; // written by `tutela codegen`

export function InvoiceActions({ invoice }: { invoice: Invoice }) {
  const resource = { type: "invoice", id: invoice.id };
  return (
    <>
      <Field resource={resource} name="amount">{invoice.amount}</Field>
      <Can component={ui.INVOICES_APPROVE_BUTTON} resource={resource}>
        <button onClick={() => approve(invoice.id)}>Approve</button>
      </Can>
    </>
  );
}
```

This only changes what the user sees. The generated guard on `POST /api/invoices/{id}/approve` checks again on the server, and the server removes `amount` from the response when the user may not read it. The SDK refuses to start if a declared route has no guard. Full steps are in [docs/INTEGRATION.md](docs/INTEGRATION.md).

## Where Tutela sits

There are four independent core repos. Each has its own CI, releases and roadmap. Products install the cores' published packages and never copy core code.

```
Products        nexc-engine (Linear-style work tracker, the first product)
                later: CRM-, ERP/SAP- or Salesforce-like products
                        |  every product uses the four cores
Domain cores    onto-intelli            texc-symphony
                        |
AgentSecOps     attache  (repo f8fvwgzc/agent-sidecar)
                        |
Identity        Tutela   (depends on no other core)
```

| Core | Job |
|------|-----|
| **Tutela** | Identity and permissions: login, keys, roles, permission checks, its own service and UI. The lowest layer. |
| **attache** | AgentSecOps: agent sidecar and mesh (SPIFFE mTLS), guardrails, budgets, approvals, agent firewall, agent registry, agent runtime, model gateway, evidence ledger. |
| **onto-intelli** | Fully automated enterprise ontology: connectors, dynamic modeling, reasoning, knowledge and long-term agent memory, MCP data tools. |
| **texc-symphony** | The AI task executor: any task handled to completion, with any LLM provider, through a task API. |

Dependencies point down only: products → onto-intelli / texc-symphony → attache → Tutela. No cycles. A core uses another core only through that core's published client or contract packages. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

Phase A, Rust side: built, and tagged as the pre-release `v0.1.0` (items 1–9). Phase A is **not done**: fuzzing, the JS and Python SDKs and the template product are open. The list-query latency gate passes ([ADR-0016](docs/DECISIONS.md#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits)). Details: [ROADMAP.md, Phase A](docs/ROADMAP.md#phase-a-packages-library-mode).

Phase B: parts 1, 2a, 2b, 3a, 3b, 3c, 4a, 4b1 and 4b2 are merged: tenants, the bindings store, the check API over HTTP and gRPC, search, the permission map, two-replica checks with a measured revocation delay, `write_check` with moves and links, model versions per tenant with an impact report, explain and simulate, and two-person publish. Part 3a: `tutelad` has its own issuer, with signing keys sealed by `tutela-vault`, a JWKS that needs no token, rotation and a `kid` deny-list, and it refuses to start without its master key and pepper. It exchanges a Keycloak token for a Tutela token (RFC 8693) with just-in-time provisioning, and refuses tokens of a revoked session or a disabled person. Admin tokens (`aud=tutela-admin`) need step-up, and the model routes take them from a person. Delegated agent tokens (`typ: agent+jwt`, RFC 8693 `act`) are issued for `delegation_aware` audiences only and never decide more than the person and the agent each hold. Part 3a is done. Part 3b is done: a local hash-chained audit log records every token, publish, proposal, explain, simulate, write check, expiry and signing-key operation in the change's own transaction ([ADR-0034](docs/DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change)), and every change writes its event to a transactional outbox, numbered per tenant in commit order ([ADR-0035](docs/DECISIONS.md#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order)), which every replica delivers to webhooks with Standard Webhooks signatures, retries and a dead-letter state ([ADR-0036](docs/DECISIONS.md#adr-0036-webhooks-delivered-from-the-outbox-registered-by-part-3c); the route to register one came in part 3c), and streams to a product's service over SSE `GET /v1/events` with the `kid` deny-list and revision changes, which `tutela_sdk::events` applies to a verifier ([ADR-0037](docs/DECISIONS.md#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded)). Audit records can be forwarded, signed, to attache's evidence ledger ([ADR-0039](docs/DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable)). Signed bundles let a Rust product check offline from a tenant's data until their `exp` ([ADR-0038](docs/DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp)). Part 3c is done: the admin API `tutela.admin.v1`, over gRPC and HTTP with one code path, takes a person's stepped-up admin token or a service's own token; attache registers, quarantines and enables its agents through it, onto-intelli pushes its types as a proposal (`PutResourceTypes`), and the model routes, boundary rules and webhook registration (a secret shown once) are in it ([ADR-0040](docs/DECISIONS.md#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org)). The operator makes a tenant with `tutelad tenant create`; its owner soft-deletes it, and a purge after the grace removes its data but never its audit chain; orgs are made, deleted and restored, and people deleted ([ADR-0041](docs/DECISIONS.md#adr-0041-the-lifecycle-of-tenants-orgs-and-people-the-operator-makes-a-tenant-soft-delete-with-a-grace-a-purge-that-keeps-the-audit-chain)). Every chain is checked on a timer, and each audit record of a request names its request and trace ([ADR-0042](docs/DECISIONS.md#adr-0042-the-audit-logs-leftovers-a-chain-check-on-a-timer-the-callers-trace-in-each-record)). Part 4b1 is done: the JavaScript SDKs in `sdk/`, `@f8fvwgzc/tutela-js` (the browser token flow in memory, every admin route, typed errors) and `@f8fvwgzc/tutela-react` (`MembersTable`, `RoleEditor`, `PermissionMatrix`), checked by `make` and tested against a real `tutelad` ([JS-SDK.md](docs/JS-SDK.md)). Part 4b2 is done: the Tutela Console, served by `tutelad` under `/console/` with a strict Content-Security-Policy ([ADR-0050](docs/DECISIONS.md#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start)), signs a person in by the authorization code flow with PKCE, shows the pages their permission map allows and edits roles with the impact report first ([ADR-0052](docs/DECISIONS.md#adr-0052-the-console-a-vite-app-on-the-sdks-sign-in-by-code-with-pkce-the-permission-map-asked-again-every-half-second)); the Phase B exit check (sign-in, the permission map and runtime role editing) passes end to end in a real browser, in `make`, against a test provider shaped like Keycloak ([ADR-0053](docs/DECISIONS.md#adr-0053-the-exit-check-in-a-real-browser-playwrights-chromium-a-real-tutelad-and-the-test-provider-run-by-make)). Part 4c is done: the OCI image ([ADR-0055](docs/DECISIONS.md#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release)) and the Helm chart `deploy/helm/tutela` with its bootstrap job, which makes the tenant and each product's app and writes its secret to a Kubernetes Secret ([ADR-0056](docs/DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing)); both were built and run locally, in a kind cluster for the chart, and neither is pushed to a registry. Phase B is tagged as the pre-release `v0.2.0` ([CHANGELOG.md](CHANGELOG.md), [MIGRATION-0.2.md](docs/MIGRATION-0.2.md)): every item and exit check passes as far as this repo can check it. Since the tag, token exchange and the Console's sign-in also pass against a real Keycloak 26.8.1 (`make keycloak`, [#87](https://github.com/f8fvwgzc/tutela/issues/87)). GitHub Actions has not run (account billing), so every merge was gated by local `make`. Details: [ROADMAP.md, Phase B status](docs/ROADMAP.md#phase-b-status).

| Item | State |
|------|-------|
| Design docs in `docs/` | Kept current |
| `tutela-contracts` crate | Done (wire types and their format checks only; no I/O) |
| Blocking CI (fmt, clippy, tests, docs, cargo-deny, cargo-audit) | Written, but it has not run: local `make` is the gate |
| Week-1 spike with go/no-go numbers | Done: **go** ([ADR-0011](docs/DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator)) |
| Model language and compiler (`tutela-pdp`, module `model`; format in [docs/MANIFEST.md](docs/MANIFEST.md)) | Done (Phase A; [ADR-0012](docs/DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)) |
| Evaluator (`tutela-pdp`: `check`, `batch`, `list_filter`, `write_check`; [ADR-0013](docs/DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)) | Done (Phase A; [ADR-0013](docs/DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)) |
| `tutela-store` (Postgres schema, migrations, row-level security, checked writes; [ADR-0014](docs/DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)) | Done (Phase A) |
| `tutela` CLI: `init`, `check`, `migrate`, `apply` with approval tokens ([ADR-0015](docs/DECISIONS.md#adr-0015-approval-tokens-for-tutela-apply-in-library-mode)), `codegen` | Done (Phase A); the generated denied-route test comes with `tutela-sdk` |
| `tutela-safenet` (SSRF-safe outbound HTTP, THREAT-MODEL TM-18) | Done (Phase A) |
| `tutela-vault` (envelope encryption with a KMS trait) | Done (Phase A) |
| `tutela-sdk`: token verifier (CONTRACTS §4), auth layer for axum and tonic, route guards, decision cache, `list_filter` SQL adapter | Done (Phase A) |
| `tutelad`: the service binary with config, health, readiness, metrics, JSON logs, graceful shutdown and bearer-token checks on HTTP and gRPC ([ADR-0018](docs/DECISIONS.md#adr-0018-tutelad-the-stack-the-two-ports-and-the-config)) | Built (Phase B) |
| Bindings and groups store: reads, closures at query time, assignment expiry with a revision bump, and the sweep in `tutelad` ([ADR-0020](docs/DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry)) | Built (Phase B) |
| Tenant isolation in `tutelad`: forced row-level security, a non-owner role, the tenant only from the verified token, and the Service gate's two checks on a real Postgres ([ADR-0019](docs/DECISIONS.md#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked)) | Built (Phase B) |
| The check API in `tutelad`: evaluation, search and the permission map over HTTP and gRPC, from a snapshot per tenant that fails closed ([ADR-0021](docs/DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease), [ADR-0022](docs/DECISIONS.md#adr-0022-the-searches-live-next-to-the-evaluator), [ADR-0023](docs/DECISIONS.md#adr-0023-the-permission-map-and-a-tag-that-covers-the-answer)) | Done (Phase B). Nothing in production uses it yet |
| Two real `tutelad` processes on one Postgres: a revoked role stops within 1.5 s (worst measured 1.010 s), and a database outage fails closed | Tested (Phase B) |
| `tutelad`'s own issuer: signing keys sealed by `tutela-vault`, a JWKS, rotation and a `kid` deny-list; token exchange with just-in-time provisioning; admin tokens with step-up; delegated agent tokens ([ADR-0030](docs/DECISIONS.md#adr-0030-tutelads-own-issuer-signing-keys-the-jwks-and-paths-without-a-token) to [ADR-0033](docs/DECISIONS.md#adr-0033-delegated-agent-tokens-from-token-exchange)) | Built (Phase B, part 3a). Tested against a local signer of Keycloak-shaped tokens, and against a real Keycloak 26.8.1 (`make keycloak`, [#87](https://github.com/f8fvwgzc/tutela/issues/87), [ADR-0057](docs/DECISIONS.md#adr-0057-a-real-keycloak-26-in-the-tests-a-pinned-image-a-realm-made-from-the-chart-and-a-client-without-full-scope)) |
| `write_check` over the API, with moves and links across scopes checked against boundary rules and compared before and after ([ADR-0025](docs/DECISIONS.md#adr-0025-moves-and-links-in-write_check)) | Done (Phase B) |
| Model versions: each tenant's published models kept and numbered, with rollback as a new publish and widening refused without an approval token ([ADR-0026](docs/DECISIONS.md#adr-0026-a-tenant-owns-its-model-versions)) | Done (Phase B) |
| Impact report for a model change: who gains or loses what, from the tenant's own data ([ADR-0027](docs/DECISIONS.md#adr-0027-the-impact-report)) | Done (Phase B) |
| Explain and simulate over HTTP and gRPC, for whoever holds `read_audit` on the resource ([ADR-0028](docs/DECISIONS.md#adr-0028-explain-and-simulate-need-read_audit-on-the-resource)) | Done (Phase B) |
| Two-person publish, optional per tenant: another principal approves, and a proposal goes stale when its impact report would change ([ADR-0029](docs/DECISIONS.md#adr-0029-two-person-publish)) | Done (Phase B) |
| Signed bundles for offline checks: `GET /v1/authz/bundle`, `Verifier::verify_bundle`, `OfflinePdp` ([ADR-0038](docs/DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp)) | Built (Phase B, part 3b) |
| Local hash-chained audit log, written with each change, append-only in the database, with a verifier ([ADR-0034](docs/DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change)), and optional signed forwarding to attache's evidence ledger ([ADR-0039](docs/DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable)) | Built (Phase B, part 3b) |
| Events: a transactional outbox in commit order, webhook delivery with Standard Webhooks signatures, retries and a dead-letter state, and SSE `GET /v1/events` with the `kid` deny-list and revision pushes ([ADR-0035](docs/DECISIONS.md#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order) to [ADR-0037](docs/DECISIONS.md#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded)). Registering a webhook is a route of the admin API (part 3c) | Built (Phase B, parts 3b and 3c) |
| Scopes, role assignments and groups over the admin API, every change held to the narrow-only rule before and after, a move behind `write_check` ([ADR-0043](docs/DECISIONS.md#adr-0043-scopes-assignments-and-groups-over-the-admin-api-checked-on-the-data-they-change)) | Done (Phase B, part 4a) |
| Apps: a client secret per app (an API key, stored hashed with the pepper, shown once), `client_credentials`, and `azp` bound to the client that authenticated ([ADR-0044](docs/DECISIONS.md#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated)) | Done (Phase B, part 4a) |
| The audit producer key sealed in the database and rotated with its old keys kept ([ADR-0045](docs/DECISIONS.md#adr-0045-the-audit-producer-key-sealed-in-the-database-rotated-with-its-old-keys-kept)) | Done (Phase B, part 4a) |
| `tutela apply` against `tutelad` with the impact report, `tutela apps`, `tutela keys` ([ADR-0046](docs/DECISIONS.md#adr-0046-the-cli-against-tutelad-apply-with-the-impact-report-apps-and-keys-through-the-key-store)) | Done (Phase B, part 4a) |
| The admin API `tutela.admin.v1` over gRPC and HTTP: agent principals, people, the model, `PutResourceTypes`, boundary rules, tenants and orgs with soft delete and purge, webhooks ([ADR-0040](docs/DECISIONS.md#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org) to [ADR-0042](docs/DECISIONS.md#adr-0042-the-audit-logs-leftovers-a-chain-check-on-a-timer-the-callers-trace-in-each-record)). Scopes, role assignments and groups over it are not built ([#107](https://github.com/f8fvwgzc/tutela/issues/107)) | Built (Phase B, part 3c) |
| The JavaScript SDKs: `@f8fvwgzc/tutela-js` and the admin components of `@f8fvwgzc/tutela-react` ([ADR-0047](docs/DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make) to [ADR-0049](docs/DECISIONS.md#adr-0049-tutela-react-embeddable-admin-components-scoped-css-variables-and-the-host-names-the-people), [docs/JS-SDK.md](docs/JS-SDK.md)) | Built (Phase B, part 4b1). Not published |
| The Tutela Console (`console/`), served by `tutelad` under `/console/`, and the exit check in a real browser ([ADR-0050](docs/DECISIONS.md#adr-0050-the-console-is-served-by-tutelad-under-console-from-files-read-at-start) to [ADR-0053](docs/DECISIONS.md#adr-0053-the-exit-check-in-a-real-browser-playwrights-chromium-a-real-tutelad-and-the-test-provider-run-by-make); how to run it: [docs/JS-SDK.md, The Console](docs/JS-SDK.md#the-console)) | Built (Phase B, part 4b2) |
| The OCI image (`Dockerfile`: the service and the Console, distroless, non-root) and the Helm chart `deploy/helm/tutela` with its bootstrap job (`tutelad bootstrap`) ([ADR-0055](docs/DECISIONS.md#adr-0055-the-oci-image-three-stages-a-distroless-runtime-the-console-on-and-publishing-left-to-a-release), [ADR-0056](docs/DECISIONS.md#adr-0056-the-helm-chart-and-its-bootstrap-job-a-pre-install-hook-that-makes-only-what-is-missing)) | Built and run locally (Phase B, part 4c); not pushed |
| Everything else | Planned, see [docs/ROADMAP.md](docs/ROADMAP.md) |

Phases: **A** packages and library mode, **B** `tutelad` service and Tutela Console, **C** own login server (optional), **D** hardening. Honest size for Tutela alone: about 35–45 person-weeks for one strong engineer.

## Build

You need Rust (the exact version is pinned in `rust-toolchain.toml`; rustup installs it), plus `cargo-deny` and `cargo-audit`, and node 22.22.2 or later (`.nvmrc`) with pnpm 10 for the JavaScript SDKs in `sdk/` ([ADR-0047](docs/DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make)):

```sh
cargo install --locked cargo-deny cargo-audit
```

Then:

```sh
make            # all gates: fmt check, clippy -D warnings, tests, docs, cargo-deny, cargo-audit, and `make js`
make js         # the JavaScript SDKs and the Console: build, typecheck, Biome, vitest, the browser check, pnpm audit, licences
make fmt        # format the code
make test       # tests only
make help       # list all targets
```

CI calls the same `make` targets, and every gate blocks the merge. When you add a dependency, run `make lint LOCKED=` once, then commit the new `Cargo.lock`. Rules for contributors and AI agents are in [AGENTS.md](AGENTS.md).

## Licence

The repo is under the MIT licence ([LICENSE](LICENSE)). The SDKs, crates and contracts will always stay permissive (MIT or Apache-2.0), because products link them in-process. The licence of `tutelad` itself is an open decision for the owner before Phase C or any public release (MIT, Apache-2.0, or AGPL/BSL with a commercial licence).

## Documents

| Document | What is in it |
|----------|---------------|
| [README.md](README.md) | This page |
| [AGENTS.md](AGENTS.md) | Rules for humans and AI coding agents in this repo |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability; security gates per phase |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Parts of Tutela and how they fit with the other cores |
| [docs/PERMISSION-MODEL.md](docs/PERMISSION-MODEL.md) | Levels, inheritance, field rules, agents and delegation |
| [docs/CONTRACTS.md](docs/CONTRACTS.md) | APIs, tokens, events and audit records |
| [docs/MANIFEST.md](docs/MANIFEST.md) | The `tutela.resources.toml` format and the model compiler |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Threats and how Tutela answers them |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | How cores and products adopt Tutela |
| [docs/JS-SDK.md](docs/JS-SDK.md) | The JavaScript SDKs: embedding the admin components, the token flow, the errors |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phases A–D, exit checks and sizes |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decisions made, and the ones still open |
| [docs/MIGRATION-0.2.md](docs/MIGRATION-0.2.md) | What breaks for a consumer at v0.2, and the change to make |
