# AGENTS.md

Rules for everyone who changes this repo: the owner, other humans and AI coding agents (Claude Code, Codex and others). Read this file and [README.md](README.md) before you change anything.

Tutela is security code. A small mistake here can give one tenant another tenant's data. Work slowly where it matters and prove each change with a test.

## 1. Core rules

| Rule | Detail |
|------|--------|
| No merge on red CI | `cargo fmt`, `clippy -D warnings`, tests, `cargo-deny` and `cargo-audit` all block. There is no "fix it later". |
| `unsafe` is forbidden | The workspace sets `unsafe_code = "forbid"`. Do not add `#[allow]` to get around it. |
| No `unwrap`, `expect`, `panic!`, `todo!` outside tests | The workspace lints deny them (plus `unimplemented!` and `dbg!`). `clippy.toml` allows them in tests only. Return a typed error instead. |
| Auth changes get a human review and a regression test | See [section 4](#4-auth-related-changes). An AI agent may write the change, but a human must review it before merge. |
| `docs/` is the source of truth for contracts | Change the docs and the code in the same commit. See [section 3](#3-docs-are-the-contract). |
| Commit identity is repo-local | `git config --local user.name f8fvwgzc`. Do not change the global git config. |
| Never commit secrets | Test values only. `.env` files are ignored; only `.env.example` may be committed. |
| Tutela depends on no other core | Never add attache, onto-intelli, texc-symphony or nexc-engine as a dependency. They depend on Tutela, not the other way. |
| Permissive licences | Tutela's crates, SDKs and contracts stay MIT or Apache-2.0, because products link them in-process. `deny.toml` lists the licences allowed for dependencies (permissive ones, plus MPL-2.0 for `webauthn-rs`). |
| One TLS stack | rustls on aws-lc-rs. `openssl`, `openssl-sys` and `native-tls` are banned in `deny.toml`. |

### Extra rules for AI agents

- Do only the task you were given. Do not edit files outside it, and do not "clean up" other code on the way.
- Use the exact names from the docs: `tutelad`, `tutela`, `tutela-pdp`, `tutela.authz.v1`, `TUTELA_*`. Do not invent new names for existing things.
- Run `make` before you say a change is done. If a gate fails, fix the cause. Do not weaken a lint, skip a test, or add an advisory ignore to make CI green.
- If the docs and the code disagree, stop and say so. Do not pick one quietly.
- Mark unfinished or future work with its phase (A, B, C, D). Never write that something works when it does not.
- Write docs in plain, simple English with short sentences. The owner is not a native English speaker.

## 2. Repo layout

Today only the parts marked **now** exist. Everything else is planned. Paths of planned parts may still change.

```
tutela/
├── Cargo.toml               workspace; lints forbid unsafe, unwrap, expect, panic, todo   now
├── Makefile                 the gates; CI calls the same targets                          now
├── deny.toml                licences, bans, sources for cargo-deny                        now
├── .github/workflows/ci.yml blocking CI                                                   now
├── docs/                    the contract source of truth                                  now
├── crates/
│   ├── tutela-contracts/    wire types: ids, claims, Decision, audit.v1, event envelope   now (wire types)
│   │                        (protos tutela.authz.v1, tutela.admin.v1: B)
│   ├── tutela-pdp/          model compiler for tutela.resources.toml                      now (compiler)
│   │                        embedded decision engine: check, batch, list_filter,          now (evaluator)
│   │                        write_check
│   ├── tutela-store/        Postgres schema and migrations: bindings, field rules, groups now
│   ├── tutela-sdk/          token verifier, axum and tonic layers, decision cache, SQL   now
│   ├── tutela-vault/        envelope encryption with a KMS trait                          now
│   ├── tutela-safenet/      SSRF-safe outbound HTTP                                       now
│   ├── tutela-cli/          the `tutela` CLI: init, check, codegen, migrate, apply,       now
│   │                        approvals (apps, keys: B)
│   └── tutelad/             the service; serves the Tutela Console                        B
├── sdk/
│   ├── react/               @f8fvwgzc/tutela-react                                        A
│   ├── node/                @f8fvwgzc/tutela-node                                         A
│   ├── js/                  @f8fvwgzc/tutela-js                                           A
│   └── python/              tutela-py (import name `tutela`)                              A
├── console/                 Tutela Console web UI                                         B
└── templates/product/       a template product that uses Tutela                          A
```

What each crate does is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 3. Docs are the contract

The files in `docs/` are the source of truth for every contract: APIs, proto packages, token claims, event types, the `audit.v1` record, the permission model and the manifest format.

- If you change a contract, change [docs/CONTRACTS.md](docs/CONTRACTS.md) (or the doc that owns it) and the code **in the same commit**.
- Wire contracts are additive only: add fields, never rename or remove them in a `v1`. A breaking change needs a new version (`v2`) and an entry in [docs/DECISIONS.md](docs/DECISIONS.md).
- A new decision, or a change to an old one, goes into [docs/DECISIONS.md](docs/DECISIONS.md).
- Permission rules live in [docs/PERMISSION-MODEL.md](docs/PERMISSION-MODEL.md). Code follows the doc, not the other way.

| Doc | Owns |
|-----|------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Parts, crate jobs, where Tutela sits |
| [docs/PERMISSION-MODEL.md](docs/PERMISSION-MODEL.md) | Levels, inheritance, field rules, delegation |
| [docs/CONTRACTS.md](docs/CONTRACTS.md) | APIs, protos, claims, events, audit |
| [docs/MANIFEST.md](docs/MANIFEST.md) | The `tutela.resources.toml` format, compiler checks, diff classes |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Threats and answers |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | How cores and products adopt Tutela |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phases and exit checks |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decisions, open questions |

## 4. Auth-related changes

A change is auth-related if it touches any of these:

- the decision engine (`tutela-pdp`), list filters or field masks;
- token checks, claims, keys, JWKS, sessions or delegation (`tutela-sdk`, `tutelad`);
- tenant isolation: row-level security, `SET LOCAL`, migrations in `tutela-store`;
- secrets and encryption (`tutela-vault`), outbound HTTP (`tutela-safenet`);
- the permission parts of `tutela-contracts`, the manifest, codegen or route guards.

For these changes:

1. Add a regression test that fails without the change.
2. Get a human review before merge. An AI review alone is not enough.
3. Keep the property tests green: no cross-tenant grant, no widening, delegation ≤ person AND agent, `list_filter` returns the same rows that `check` allows.

## 5. Running the gates

You need Rust (pinned in `rust-toolchain.toml`), `cargo-deny` and `cargo-audit`:

```sh
cargo install --locked cargo-deny cargo-audit
```

| Command | What it runs | CI job |
|---------|--------------|--------|
| `make` (same as `make all`) | every gate below | all jobs |
| `make fmt-check` | `cargo fmt --all -- --check` | lint |
| `make lint` | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | lint |
| `make doc` | `cargo doc` with `-D warnings` | lint |
| `make test` | `cargo test --workspace --all-features --locked` | test |
| `make deny` | `cargo deny check` (licences, bans, sources, advisories) | supply-chain |
| `make audit` | `cargo audit --deny warnings` | supply-chain |
| `make fmt` | formats the code (not a gate) | none |

Notes:

- Run `make` before every commit and every pull request.
- `tutela-store`'s tests need a Postgres. Set `TUTELA_TEST_DATABASE_URL` to a key=value connection string for a role that may create roles and databases, for example `host=127.0.0.1 port=5432 user=postgres password=postgres dbname=postgres`. Without it they print `skipped` and pass; CI sets `TUTELA_REQUIRE_DATABASE=1`, so there a missing database fails.
- The gates run with `--locked`. When you add a dependency, run `make lint LOCKED=` once, then commit the new `Cargo.lock` with the change.
- An advisory ignore in `deny.toml` needs an id, a reason and a review date.
- The later phases add more gates (fuzzing, property tests, latency numbers, RLS tests, conformance). They are listed in [SECURITY.md](SECURITY.md).

## 6. Never do

- **Never commit secrets.** No real keys, tokens, passwords or master keys. Test values only.
- **Never use `unwrap`, `expect`, `panic!` or `todo!` outside tests.** Return an error.
- **Never trust a UI-only check.** Hiding a button is not security. Every server route checks again.
- **Never filter lists by loading rows and then dropping some.** Filter inside SQL with `list_filter`. Load-then-drop leaks counts and page sizes.
- **Never put permission lists in tokens.** Tokens carry identity and a revision (`rev`), not grants.
- Never read a resource's path or attributes from the request body. Load them on the server by id.
- Never log tokens or personal data, and never put them in URLs or span attributes.
- Never key an account by e-mail. Accounts are keyed by `(iss, sub)`.
- Never let anyone grant a permission they do not hold. Delegation only narrows.
- Never run `DROP SCHEMA ... CASCADE` on tenant data. Tenants are soft-deleted with a grace period.
