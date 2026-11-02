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
