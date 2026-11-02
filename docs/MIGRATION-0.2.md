# Migrating to Tutela v0.2

v0.2.0 is not tagged yet. attache and texc-symphony stay pinned to `v0.1.0` until they choose to bump. This note lists what breaks for a consumer, and the change to make. The reasons are in [ADR-0017](DECISIONS.md#adr-0017-opaque-public-errors-for-the-crates-that-touch-the-outside-world).

Other docs: [README](../README.md) · [DECISIONS](DECISIONS.md) · [ROADMAP](ROADMAP.md)

## Public errors are opaque

`StoreError`, `SqlError`, `SafenetError` and `VaultError` were enums with public variants. They are now structs with private fields. Branch on `kind()`.

```rust
// Before
match e {
    StoreError::NotFound(what) => not_found(what),
    StoreError::Db(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => retry(),
    other => return Err(other.into()),
}

// After
match e.kind() {
    StoreErrorKind::NotFound => not_found(e.detail().unwrap_or("row")),
    StoreErrorKind::Database if e.sqlstate() == Some("40001") => retry(),
    _ => return Err(e.into()),
}
```

Each kind enum is `#[non_exhaustive]`, so a `match` needs a `_` arm.

### `tutela_store::StoreError`

| Before | After |
|---|---|
| `StoreError::Db(e)` | `kind() == StoreErrorKind::Database`; `sqlstate()` gives the code as text |
| `StoreError::SchemaTooNew(v)` | `StoreErrorKind::SchemaTooNew`; the version is in the text |
| `StoreError::UnknownTenant` | `StoreErrorKind::UnknownTenant` |
| `StoreError::NotFound(s)`, `Exists(s)`, `Invalid(s)`, `Corrupt(s)` | The kind of the same name; `detail()` gives `s` |
| `StoreError::Refused(load_error)` | `StoreErrorKind::Refused`; `refusal()` gives `&LoadError` |
| `StoreError::RevOutOfRange` | `StoreErrorKind::RevOutOfRange` |
| `impl From<tokio_postgres::Error> for StoreError` | Gone. `?` on a driver error no longer gives a `StoreError`. Use your own error type for your own statements and for `commit`. |

`impl From<LoadError> for StoreError` stays.

### `tutela_sdk::sql::SqlError`

| Before | After |
|---|---|
| `SqlError::Column(name)`, `UnmappedField(name)` | `SqlErrorKind::Column`, `UnmappedField`; the name is in the text |
| `SqlError::Unsupported` | `SqlErrorKind::Unsupported` |
| `SqlError::Query(e)` | `SqlErrorKind::Query`; `sqlstate()` gives the code (`57014` for a statement timeout) |
| `impl From<tokio_postgres::Error> for SqlError` | Gone |

### `tutela_safenet::SafenetError`

| Before | After |
|---|---|
| `SafenetError::Url(s)`, `Header(s)` | `SafenetErrorKind::Url`, `Header`; the rule is in the text |
| `SafenetError::NotPublic { host }`, `NoAddress { host }` | The kind of the same name; `host()` gives the host |
| `SafenetError::TooLarge { limit }` | `SafenetErrorKind::TooLarge`; `limit()` gives the limit |
| `SafenetError::Timeout` | `SafenetErrorKind::Timeout` |
| `SafenetError::Http(text)` | `SafenetErrorKind::Http`. The text is now `the request failed`, and the reason is in `source()`. The chain holds no part of the URL. |
| `SafenetError::Http` from a TLS setup failure | `SafenetErrorKind::Setup` |

### `tutela_vault::VaultError`

| Before | After |
|---|---|
| `VaultError::Decrypt`, `Malformed`, `NoMasterKey`, ... | The kind of the same name in `VaultErrorKind` |
| `VaultError::UnknownKey(id)` | `VaultErrorKind::UnknownKey`; `key()` gives the id |
| `VaultError::BadMasterKey(name)` | `VaultErrorKind::BadMasterKey`; `variable()` gives the name |
| `VaultError::Kms(text)` | `VaultErrorKind::Kms`; the backend's error is in `source()` |
| `derive(Clone, PartialEq, Eq)` | Gone. Compare `kind()`. |

A [`Kms`](../crates/tutela-vault/src/lib.rs) backend outside this repo builds its errors with `VaultError::kms(cause)`, `VaultError::unknown_key(id)` and `VaultError::decrypt()`. The cause must not hold key material.

## Print the whole chain

An error's own text leaves its cause out. `{e}` prints `invalid name`, and the reason sits in `source()`. Every Tutela error works this way since #37 and #39. `{e:#}` does not help: it walks the chain of an `anyhow::Error`, and a `thiserror` type ignores it.

Wrap the error in `anyhow::Error`, or call the helper:

```rust
tracing::warn!(error = %tutela_contracts::error_chain(&e), "...");
```

Sites to change at the bump ([#44](https://github.com/f8fvwgzc/tutela/issues/44)). Search again then: this list was made from the worktrees of both repos.

| Repo | File | Error |
|---|---|---|
| attache | `services/embassy/src/authz.rs` (`ResourceId::parse`, `ActionKey::parse`) | `KeyError` |
| texc-symphony | `crates/symphony-server/src/tutela.rs` (`TenantId` in `verifier_config`) | `IdError` |

A `SafenetError` of kind `Http` also needs the chain now: its own text no longer holds the reason.

## A transaction belongs to one tenant

`tutela_store` calls now refuse a second tenant in one transaction, with `StoreErrorKind::TenantMismatch`. Before, a call with another tenant's key switched the transaction to that tenant, so a bug that passed the wrong key read the wrong tenant's rows. Use one transaction per tenant. `publish_manifest` still spans every tenant, and leaves none entered.

`tutela_store::enter` is public, for a caller that runs its own statements. `check_isolation` and `grant_service` are new; a product in library mode can use them for its runtime role.

## The bindings store

- Run `tutela migrate`: migration 3 adds two indexes.
- A role assignment with `expires_at` used to be ignored. It now counts until that time. Nothing in the store wrote `expires_at` before, so this only affects a row you wrote yourself.
- `TenantBundle` has a new field, `next_expiry`. This view of the tenant is good until then: load again at that time.
- In library mode nothing sweeps for you. Call `tutela_store::expire_assignments` on a timer, in a transaction per tenant, if you use `assign_until`. Until you do, an expired assignment already does not count, but the revision does not move.

## Other changes

- `tutela_contracts::error_chain` is new and public.
- Workload examples use attache's path, `/ns/<namespace>/svc/<service>` ([CONTRACTS.md 1.4](CONTRACTS.md#14-workload-principals-spiffe)). Nothing in the parser changed.

## `tutelad`'s own issuer (part 3a)

These matter to whoever runs `tutelad`, and to a product that verifies its tokens.

- **New required variables.** `tutelad` does not start without `TUTELA_ISSUER` (its own issuer, a public https URL), `TUTELA_MASTER_KEY` (32 bytes) and `TUTELA_KEY_PEPPER` (32 bytes or more, not the master key), each as base64 or hex. `deploy/compose.yaml` asks for them. `TUTELA_ISSUER` must not be an issuer of the trust file.
- **Run `tutelad migrate`.** Migration 6 adds `tutela.signing_key`, and `grant_service` gives the service role read, add and update on it.
- **The JWKS** is at `<TUTELA_ISSUER>/.well-known/jwks.json` on the API port, with no token. To accept `tutelad`'s tokens, add its issuer to your `tutela-sdk` trust list with that `jwks_uri`, `algs = ["ES256"]`, and the tenants you serve.
- **Additive in `tutela-contracts`:** `TrustList::insert_directory` and `TrustList::is_directory`. Only a service that checks every tenant against its own directory uses them; a product never does. `TrustList` gained a private field, so nothing that builds one changes.
- **Additive in `tutela-sdk`:** `Verifier::forget_jwks(jwks_uri)`, the forced refetch of an emergency rotation.
- **New in `tutela-store`:** the signing-key API (`rotate_signing_key`, `deny_signing_key`, `ensure_signing_key`, `rewrap_signing_keys`, `signing_keys`), and a dependency on `tutela-vault`.

## Token exchange (part 3a)

- **Run `tutelad migrate`.** Migration 7 adds `tutela.principal`, `tutela.upstream_account` and `tutela.exchanged_token`, each with forced row-level security.
- **`POST /oauth2/token`** exchanges a Keycloak token (or any `external` issuer's) for a Tutela token of `TUTELA_ISSUER` ([CONTRACTS.md 4.8](CONTRACTS.md#48-token-exchange-phase-b-built)). The tenant is the one the trust file maps the realm to, and it must be in `tutelad`'s directory under `TUTELA_ISSUER`. The person is a new `user:usr_…` the first time, found by the realm's `(iss, sub)` after that.
- **The trust file** may list `[[audience]]` entries (`name`, `delegation_aware`): the audiences token exchange issues for, besides `TUTELA_AUDIENCE`. `tutela-admin` is not allowed there.
- **For attache and texc-symphony, when they bump:** a token from `tutelad` has `iss = TUTELA_ISSUER`. Add that issuer to the `tutela-sdk` trust list with `jwks_uri = <TUTELA_ISSUER>/.well-known/jwks.json` and `algs = ["ES256"]`, with the tenants you serve, and register your audience (`symphony`, ...) in `tutelad`'s trust file. A person's token from Keycloak is exchanged once; for another audience, exchange the Tutela token. Nothing changes in `tutela-sdk`'s verifier for these tokens.
- **New in `tutela-store`:** `provision_user`, `principal_state`, `revoke_sessions`, `set_disabled`, `register_agent`, `agent_for_workload`, `revocations`, `note_exchange`.

## Admin tokens (part 3a)

- **A person on the admin routes** (`/v1/models…`, `POST /v1/authz/explain`, `POST /v1/authz/simulate`) now sends an admin token, `aud=tutela-admin`, from token exchange after step-up. A person's `tutela-authz` token gets 403 there. A service account keeps its `tutela-authz` token (`tutela apply` in a pipeline).
- **`TUTELA_ADMIN_ACR`**: the `acr` values your IdP gives after step-up MFA, comma-separated. Unset, no admin token is issued. Set it to what Keycloak's step-up gives (an ACR-to-LoA mapping or a client policy).
- **gRPC `Explain` and `Simulate`** are for services only.

## Delegated agent tokens (part 3a)

- **`tutelad` issues them** by token exchange with an `actor_token` ([CONTRACTS.md 4.8](CONTRACTS.md#48-token-exchange-phase-b-built), [ADR-0033](DECISIONS.md#adr-0033-delegated-agent-tokens-from-token-exchange)), and accepts them on its own API: `verifier_config` now has delegation on.
- **For attache, when it bumps:** register each agent in its tenant (`tutela_store::register_agent`, with the workload's SPIFFE id on `/ns/<namespace>/svc/<service>` for a workload agent; `tutela.admin.v1` gives this an API in part 3c). Ask for a delegated token with the person's token as `subject_token`, the agent's token as `actor_token` (an access token of the agent from an issuer `tutelad` trusts, or the embassy's JWT-SVID, its issuer marked `workloads = true` in `tutelad`'s trust file), the target `audience`, `run_id`, `node_id` and `cap`. Quarantine is `set_disabled` on the agent: its tokens stop at the next exchange and on `tutelad` within a second; products learn of it from `tutela.principal.disabled.v1` (part 3b).
- **For texc-symphony, when it bumps:** turn delegation on in the `tutela-sdk` verifier (`delegation: true`, `delegation_aware: true`), and register `symphony` in `tutelad`'s trust file as `[[audience]] name = "symphony"`, `delegation_aware = true`. For the next hop, exchange the delegated token you received for the next audience (no `actor_token`); never forward it.
- **`IssuerEntry` in the trust file** has a new key, `workloads` (only with `external = true`). `TUTELA_DELEGATED_TTL_SECS` (60 to 120, default 90) and `TUTELA_TOKEN_TTL_SECS` (60 to 600, default 300) are new and optional.


## The audit log (part 3b)

- **Migration 8** adds `tutela.audit_head` and `tutela.audit_record`, the local hash-chained audit log ([ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change)). Run `tutela migrate` (or `tutelad migrate`) as the owner, then `grant_service` again: the service role gets `SELECT, INSERT` on records and never `UPDATE` or `DELETE`. `check_isolation` now fails when a runtime role may change the log, or when its triggers are switched off.
- **`tutela-contracts`:** `AuditEventV1` has a new optional field, `details`, so a struct literal needs `details: None`. New: `AuditDraft` (a record before its `seq` and signature), `AuditEventV1::signing_bytes` and `from_body`, `Details`, and `tutela_contracts::jcs` (RFC 8785 for the values Tutela signs). `AuditError` has two new variants (`Details`, `Canonical`); it is `#[non_exhaustive]`.
- **`tutela-store`:** `provision_user` now returns `(PrincipalState, bool)`, the `bool` being `true` when this call made the person. New: `append_audit`, `audit_records`, `verify_audit_chain`, and the same for the deployment's own chain.
- **In library mode** (attache, texc-symphony when they bump): nothing is written to the log for you. Record your own admin calls with `tutela_store::append_audit` in the same transaction, last, just before the commit.
