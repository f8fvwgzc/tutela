# Security policy

Tutela is identity and permissions code, so security reports are welcome and important. This page says how to report a problem, which versions get fixes, and which security gates each phase must pass before it ships.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report it privately:

1. Use GitHub private vulnerability reporting on [`f8fvwgzc/tutela`](https://github.com/f8fvwgzc/tutela): open the **Security** tab and choose **Report a vulnerability**.
2. The repo is private today. If you cannot see that button, contact the owner, [@f8fvwgzc](https://github.com/f8fvwgzc), privately on GitHub and ask for a private channel. Do not put the details in a public place.

Please include:

- what is affected (crate, package, `tutelad`, Tutela Console, CLI) and the commit or version;
- the steps to reproduce, or a small proof of concept;
- what an attacker gains (for example: reads another tenant's data, widens a role, an agent gets more than the person);
- whether you want credit when the fix is published.

This is a one-person project. Replies and fixes are best effort. We will agree on a disclosure date with you, and we will not publish details before a fix is ready.

Please test only on your own deployment with test data. Do not test against systems or data that are not yours.

### Scope

| In scope | Not in scope (report upstream) |
|----------|--------------------------------|
| `tutela-*` crates, `tutelad`, Tutela Console, `tutela` CLI | Keycloak itself: report to the Keycloak project |
| `@f8fvwgzc/tutela-react`, `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js`, `tutela-py` | attache, onto-intelli, texc-symphony, nexc-engine: report in their own repos |
| The contracts and docs in this repo (a design flaw counts) | Third-party libraries: report to the library, and tell us if Tutela is affected |

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (0.0.x, pre-alpha) | No. Do not run it in production. |
| Any release | None yet. No release has been tagged. |

Tutela is pre-alpha. The first commit has only the design docs, `tutela-contracts` and CI. When releases start, this table will list which versions get security fixes. Releases will be tagged and signed (from v0.1, the end of Phase A).

## Security gates per phase

A phase is not done, and nothing from it ships, until its gate passes. Gates add up: each phase keeps every earlier gate. Phases are described in [docs/ROADMAP.md](docs/ROADMAP.md).

### Always (from the first commit)

| Gate | How it is checked |
|------|-------------------|
| No merge on red CI | `cargo fmt`, `clippy -D warnings`, tests, docs, `cargo-deny`, `cargo-audit` all block (see [AGENTS.md](AGENTS.md)) |
| No `unsafe` | `unsafe_code = "forbid"` in the workspace |
| No `unwrap`, `expect`, `panic!`, `todo!` outside tests | Workspace clippy lints |
| Allowed licences only (permissive, plus MPL-2.0), one TLS stack, known sources only | `deny.toml` |
| Every auth-related change gets a human review and a regression test | Review rule in [AGENTS.md](AGENTS.md) |
| No secrets in the repo | Test values only; `.env` files are ignored |

### Phase A: packages and library mode (library gate)

| Gate | Pass condition |
|------|----------------|
| Week-1 spike (go/no-go) | `check` p99 < 1 ms with a large per-tenant model; closure p99 measured at depth 32 with big groups; `list_filter` correct on 100k rows |
| Property tests | No cross-tenant grant. No widening. Delegation ≤ person AND agent. `list_filter` returns exactly the rows that `check()` allows (differential test). |
| Fuzzing | Fuzz tests run on the inputs Tutela parses and compiles: the manifest and the model compiler, tokens, and the SQL filter compiler |
| Latency | The spike's p99 numbers still hold for the released packages. The list query in Postgres has p99 under 100 ms at the `list_filter` limits on the reference machine (table size fixed by ROADMAP Phase A item 6), and its statement timeout fails closed ([ADR-0011](docs/DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F2). |
| Release | v0.1 tagged and signed |

### Phase B: `tutelad` and Tutela Console (service gate)

| Gate | Pass condition |
|------|----------------|
| Tenant isolation (RLS) | A cross-tenant read fails at row-level security even with an injected code bug. A query with no tenant set returns zero rows. `FORCE ROW LEVEL SECURITY` on every table; app roles never own tables. |
| Closure | Group and hierarchy closure stays correct and inside its latency budget |
| Revocation | A revoked role takes effect within the documented delay |
| Stale data | The decision engine refuses a lower revision than it has seen and refuses expired bundles (reads return 503, never a stale allow) |
| High availability | 2+ `tutelad` replicas |
| End to end | Sign-in, UI permission map and runtime role editing pass end to end |

### Phase C: own login server, optional (before anyone uses it)

| Gate | Pass condition |
|------|----------------|
| Conformance | OpenID Foundation Basic OP and Config OP conformance tests run in CI and pass |
| Fuzzing | The login server's endpoints are fuzzed |
| External review | An external security review is done and its findings are fixed |
| Key-restore drill | Signing keys are restored from backup in a drill |
| Swap test | Switching from Keycloak to `tutelad` is a config change only |

### Phase D: hardening

| Gate | Pass condition |
|------|----------------|
| Webhooks | Webhook delivery hardened (signatures, retries, dedupe) |
| Load and soak | Load and soak tests pass |
| Backups | Backup and restore drills pass |
| Deploy | The Helm chart and compose files are finished and tested |

## More detail

- Threats and how Tutela answers them: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- The permission rules the tests check: [docs/PERMISSION-MODEL.md](docs/PERMISSION-MODEL.md)
- Tokens, claims and audit records: [docs/CONTRACTS.md](docs/CONTRACTS.md)
- Overview: [README.md](README.md)
