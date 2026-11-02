# Tutela

Tutela is a self-hostable identity and permissions core, like Clerk or Auth0, for one developer's platform of products. It gives every product the same login, keys, roles and permission checks. It has its own backend service (`tutelad`), its own web UI (the Tutela Console) and packages that products install: Rust crates, npm packages and a Python package. Tenants define their own resource types and roles at runtime; nobody hard-codes roles in a product any more.

**The name.** Tutela was the Roman goddess of protection and guardianship. In Roman law, *tutela* is a guardian's legal power to act for someone else, which is exactly what delegation is when an AI agent acts for a person.

> **Status: pre-alpha.** The first commit has only the design docs, the `tutela-contracts` crate and CI. Nothing here is usable in production yet. See [Status](#status).

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

Nothing is published yet. The phase column says when each package is planned.

| Kind | Name | What it does | Phase |
|------|------|--------------|-------|
| Rust crate | `tutela-contracts` | Wire types: ids, principals, token claims, the Decision object, `audit.v1`, the event envelope; later the `tutela.authz.v1` and `tutela.admin.v1` protos | Started in the first commit; grows in A; protos in B |
| Rust crate | `tutela-pdp` | Embedded decision engine: `check`, `batch`, `list_filter`, `write_check` | A |
| Rust crate | `tutela-sdk` | Token verifier, axum and tonic layers, decision cache | A |
| Rust crate | `tutela-store` | Postgres schema and migrations for bindings, field rules and groups (library mode and `tutelad`) | A |
| Rust crate | `tutela-vault` | Envelope encryption with a KMS trait | A |
| Rust crate | `tutela-safenet` | SSRF-safe outbound HTTP | A |
| npm | `@f8fvwgzc/tutela-react` | `<Can>`, `<Field>`, `<Protect>`, `useCan`; later the embeddable admin parts (RoleEditor, MembersTable, permission matrix) | A (admin parts B) |
| npm | `@f8fvwgzc/tutela-node` | Server middleware and check client for Node | A |
| npm | `@f8fvwgzc/tutela-js` | Browser helper | A |
| Python | `tutela-py` (import `tutela`) | Token verifier, FastAPI dependency, check client | A |
| OCI image | `ghcr.io/f8fvwgzc/tutelad` | The service and the Tutela Console; from Phase C optionally also the OIDC provider | B |
| Helm chart | `oci://ghcr.io/f8fvwgzc/charts/tutela` | Self-hosting with 2+ replicas | B (hardened in D) |
| CLI | `tutela` | `init`, `apply`, `codegen`, `apps create`, `keys rotate` | A (`apps create` and `keys rotate` need `tutelad`: B) |

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

Phase A, Rust side: built (items 1–9). Phase A is **not done**: fuzzing, the JS and Python SDKs, the template product and v0.1 are open. The list-query latency gate passes ([ADR-0016](docs/DECISIONS.md#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits)). Details: [ROADMAP.md, Phase A](docs/ROADMAP.md#phase-a-packages-library-mode).

| Item | State |
|------|-------|
| Design docs in `docs/` | In the first commit |
| `tutela-contracts` crate | In the first commit (wire types and their format checks only; no I/O) |
| Blocking CI (fmt, clippy, tests, docs, cargo-deny, cargo-audit) | In the first commit |
| Week-1 spike with go/no-go numbers | Done: **go** ([ADR-0011](docs/DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator)) |
| Model language and compiler (`tutela-pdp`, module `model`; format in [docs/MANIFEST.md](docs/MANIFEST.md)) | Done (Phase A; [ADR-0012](docs/DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)) |
| Evaluator (`tutela-pdp`: `check`, `batch`, `list_filter`, `write_check`; [ADR-0013](docs/DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)) | Done (Phase A; [ADR-0013](docs/DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)) |
| `tutela-store` (Postgres schema, migrations, row-level security, checked writes; [ADR-0014](docs/DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)) | Done (Phase A) |
| `tutela` CLI: `init`, `check`, `migrate`, `apply` with approval tokens ([ADR-0015](docs/DECISIONS.md#adr-0015-approval-tokens-for-tutela-apply-in-library-mode)), `codegen` | Done (Phase A); the generated denied-route test comes with `tutela-sdk` |
| `tutela-safenet` (SSRF-safe outbound HTTP, THREAT-MODEL TM-18) | Done (Phase A) |
| `tutela-vault` (envelope encryption with a KMS trait) | Done (Phase A) |
| `tutela-sdk`: token verifier (CONTRACTS §4), auth layer for axum and tonic, route guards, decision cache, `list_filter` SQL adapter | Done (Phase A); the list-query gate benchmark is [#22](https://github.com/f8fvwgzc/tutela/issues/22) |
| `tutelad`: the service binary with config, health, readiness, metrics, JSON logs, graceful shutdown and bearer-token checks on HTTP and gRPC ([ADR-0018](docs/DECISIONS.md#adr-0018-tutelad-the-stack-the-two-ports-and-the-config)) | Built (Phase B). It serves no permission API yet. |
| Bindings and groups store: reads, closures at query time, assignment expiry with a revision bump, and the sweep in `tutelad` ([ADR-0020](docs/DECISIONS.md#adr-0020-the-bindings-store-closures-at-read-time-and-assignment-expiry)) | Built (Phase B) |
| Tenant isolation in `tutelad`: forced row-level security, a non-owner role, the tenant only from the verified token, and the Service gate's two checks on a real Postgres ([ADR-0019](docs/DECISIONS.md#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked)) | Built (Phase B) |
| Everything else | Planned, see [docs/ROADMAP.md](docs/ROADMAP.md) |

Phases: **A** packages and library mode, **B** `tutelad` service and Tutela Console, **C** own login server (optional), **D** hardening. Honest size for Tutela alone: about 35–45 person-weeks for one strong engineer.

## Build

You need Rust (the exact version is pinned in `rust-toolchain.toml`; rustup installs it), plus `cargo-deny` and `cargo-audit`:

```sh
cargo install --locked cargo-deny cargo-audit
```

Then:

```sh
make            # all gates: fmt check, clippy -D warnings, tests, docs, cargo-deny, cargo-audit
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
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phases A–D, exit checks and sizes |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decisions made, and the ones still open |
| [docs/MIGRATION-0.2.md](docs/MIGRATION-0.2.md) | What breaks for a consumer at v0.2, and the change to make |
