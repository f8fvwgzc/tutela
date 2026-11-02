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
- **For attache, when it bumps:** register each agent in its tenant through the admin API (part 3c, below), with the workload's SPIFFE id on `/ns/<namespace>/svc/<service>` for a workload agent. Ask for a delegated token with the person's token as `subject_token`, the agent's token as `actor_token` (an access token of the agent from an issuer `tutelad` trusts, or the embassy's JWT-SVID, its issuer marked `workloads = true` in `tutelad`'s trust file), the target `audience`, `run_id`, `node_id` and `cap`. Quarantine is `SetDisabled` on the agent (part 3c, below): its tokens stop at the next exchange and on `tutelad` within a second; products learn of it from `tutela.principal.disabled.v1` (part 3b).
- **For texc-symphony, when it bumps:** turn delegation on in the `tutela-sdk` verifier (`delegation: true`, `delegation_aware: true`), and register `symphony` in `tutelad`'s trust file as `[[audience]] name = "symphony"`, `delegation_aware = true`. For the next hop, exchange the delegated token you received for the next audience (no `actor_token`); never forward it.
- **`IssuerEntry` in the trust file** has a new key, `workloads` (only with `external = true`). `TUTELA_DELEGATED_TTL_SECS` (60 to 120, default 90) and `TUTELA_TOKEN_TTL_SECS` (60 to 600, default 300) are new and optional.


## The audit log (part 3b)

- **Migration 8** adds `tutela.audit_head` and `tutela.audit_record`, the local hash-chained audit log ([ADR-0034](DECISIONS.md#adr-0034-the-local-audit-log-one-chain-per-tenant-written-with-the-change)). Run `tutela migrate` (or `tutelad migrate`) as the owner, then `grant_service` again: the service role gets `SELECT, INSERT` on records and never `UPDATE` or `DELETE`. `check_isolation` now fails when a runtime role may change the log, or when its triggers are switched off.
- **`tutela-contracts`:** `AuditEventV1` has a new optional field, `details`, so a struct literal needs `details: None`. New: `AuditDraft` (a record before its `seq` and signature), `AuditEventV1::signing_bytes` and `from_body`, `Details`, and `tutela_contracts::jcs` (RFC 8785 for the values Tutela signs). `AuditError` has two new variants (`Details`, `Canonical`); it is `#[non_exhaustive]`.
- **`tutela-store`:** `provision_user` now returns `(PrincipalState, bool)`, the `bool` being `true` when this call made the person. New: `append_audit`, `audit_records`, `verify_audit_chain`, and the same for the deployment's own chain.
- **In library mode** (attache, texc-symphony when they bump): nothing is written to the log for you. Record your own admin calls with `tutela_store::append_audit` in the same transaction, last, just before the commit.

## Events (part 3b)

- **Migration 9** adds `tutela.event`, the transactional outbox, and a column `event_seq` on `tutela.tenant_rev` ([ADR-0035](DECISIONS.md#adr-0035-the-outbox-events-numbered-per-tenant-in-commit-order)). Run `grant_service` again: the service role gets `SELECT, INSERT, DELETE` on events, never `UPDATE`.
- **Every store write now writes an event** in your transaction: `tutela.permissions.changed.v1` for a data write and `expire_assignments`, `tutela.model.published.v1` for a publish, `tutela.user.created.v1`, `tutela.session.revoked.v1`, `tutela.principal.disabled.v1`, `tutela.user.disabled.v1` and the new `tutela.principal.enabled.v1`. In library mode nothing delivers them: read them with `tutela_store::events_after`, or prune them with `tutela_store::prune_events` (for example daily, older than a week).
- **A first sign-in now waits for a write in progress** in its tenant: provisioning takes the tenant's revision row to number its event.
- **`tutela-contracts`:** `EventType::PRINCIPAL_ENABLED` and `PrincipalEnabledData`. An SDK that feeds `EpochBook` from events should call `set_disabled(p, false)` on it.
- **`tutela-store`:** `emit`, `OutboxEvent`, `StoredEvent`, `events_after`, `event_cursor`, `events_now`, `prune_events`.

## Webhooks (part 3b)

- **Migration 10** adds `tutela.webhook` and `tutela.webhook_delivery` ([ADR-0036](DECISIONS.md#adr-0036-webhooks-delivered-from-the-outbox-registered-by-part-3c)). Run `grant_service` again.
- **New settings:** `TUTELA_WEBHOOK_POLL_MS` (default 1000; `0` turns delivery off on a replica) and `TUTELA_EVENT_RETENTION_SECS` (default 604800, at least 172800). `deploy/tutelad.env` has both.
- **Registering a webhook** is `POST /v1/admin/webhooks` (`RegisterWebhook`) since part 3c (CONTRACTS.md 7.13.6), with a token that holds `read_audit` and `manage_access` at every org. Keep the `secret` of the answer: it is never shown again. Rotate it with `POST /v1/admin/webhooks/{id}/rotate`; both secrets sign during the overlap.
- **A receiver** (attache, texc-symphony, a product) checks `webhook-signature` in constant time over `<webhook-id>.<webhook-timestamp>.<body>` with the decoded `whsec_` secret, refuses a timestamp more than 5 minutes off, dedupes by `webhook-id`, and answers 2xx at once. During a rotation the header holds two signatures; accept either.
- **`tutela-safenet`:** `Client::check(url)` checks a URL and its DNS answer without a request.
- **`tutela-store`** (part 3c): `webhooks::webhook` (one webhook), `webhooks::delivery_page` (a page of deliveries, the dead ones only if asked) and `webhooks::MAX_DELIVERY_PAGE`.

## Event stream (part 3b)

- **`GET /v1/events`** ([ADR-0037](DECISIONS.md#adr-0037-the-event-stream-services-only-one-feed-per-tenant-bounded), CONTRACTS.md 8.6): a product backend listens with its service token (`sa` or `key`) and feeds its `tutela-sdk` verifier: `tutela_sdk::events::apply_event` for each event, `tutela_sdk::events::apply_denied_kids` for each `denied_kids` message. Reconnect with `Last-Event-ID` when a stream ends; reload on `reset`.
- **For texc-symphony and attache, when they bump:** listening is how a revoked session, a disabled person or a quarantined agent is refused at once instead of when its token expires.
- **New settings:** `TUTELA_EVENTS_POLL_MS` (default 500), `TUTELA_SSE_MAX_STREAMS` (1000), `TUTELA_SSE_MAX_SECS` (900), `TUTELA_SSE_BUFFER` (256).
- **`tutela-sdk`:** new module `events`.

## Signed bundles (part 3b)

- **`GET /v1/authz/bundle`** ([ADR-0038](DECISIONS.md#adr-0038-signed-bundles-a-service-with-read_audit-everywhere-its-own-typ-and-no-skew-at-exp), CONTRACTS.md 7.12): a Rust product that wants to check offline gives its service account `read_audit` at every org of its tenant, pulls a bundle below its `exp` (or when SSE says `rev` moved), verifies it with `Verifier::verify_bundle` and loads it into a `tutela_sdk::bundle::OfflinePdp`. Its trust list must allow `TUTELA_ISSUER` for its tenant id.
- **New setting:** `TUTELA_BUNDLE_TTL_SECS` (default 300, 1 to 3600).
- **`tutela-pdp`:** `TenantData`, `Binding`, `Group`, `Member`, `Subject`, `ScopeFieldRule`, `BoundaryRule`, `MoveRule`, `OnLooser`, `LinksFrom`, `PathEntry`, `RoleKey`, `GroupKey` and `AppName` implement `Serialize` and `Deserialize`.
- **`tutela-store`:** `ScopePathSnapshot::entries`.
- **`tutela-sdk`:** new module `bundle`, and `Verifier::verify_bundle`.

## Forwarding to attache's evidence ledger (part 3b)

- **Migration 11** adds `tutela.audit_forward`. Run `grant_service` again.
- **Off unless configured.** Set `TUTELA_LEDGER_URL` (attache's `.../api/v1/ledger/append`), `TUTELA_LEDGER_TOKEN` (the `att_` token of an `auth.tokens` entry) and `TUTELA_AUDIT_KEY` (a 32-byte Ed25519 seed, base64, the same on every replica) ([ADR-0039](DECISIONS.md#adr-0039-forwarding-to-attaches-evidence-ledger-signed-acknowledged-resumable)).
- **For attache's operator:** add `tutelad` to `ledger.producers` with that token and the public key `tutelad` logs at start (`public_key`, standard base64). Nothing else changes in attache.

## The admin API, `tutela.admin.v1` (part 3c)

- **One API over HTTP and gRPC** ([CONTRACTS.md 7.13](CONTRACTS.md#713-admin-api-tutelaadminv1), [ADR-0040](DECISIONS.md#adr-0040-tutelaadminv1-one-code-path-the-admin-token-rule-on-grpc-and-keys-at-every-org)). gRPC service `tutela.admin.v1.Admin`, proto in `crates/tutela-contracts/proto/tutela/admin/v1/admin.proto`. A service calls it with its `tutela-authz` token; a person with an admin token after step-up.
- **For attache, when it bumps:** give attache's service account the admin key `manage_agents` at every org of each tenant it serves (for example the seeded `owner` role, or a role of your own that holds `"org:manage_agents" = true`, assigned at each org). Then:
  - **create** an agent with `RegisterAgent {workload}` (`POST /v1/admin/agents`), with the SPIFFE id `spiffe://<trust domain>/ns/<namespace>/svc/<service>` of the workload it runs as. `tutelad` answers the new `agent:agt_<uuidv7>`; keep it beside attache's own agent id. After a lost answer, `ListAgents {workload}` finds it again (a second registration of the same workload is 409 `exists`);
  - **quarantine** it with `SetDisabled {principal, disabled: true}`, and **enable** it again with `disabled: false`. Disabling raises its epoch: tokens it held stay refused after it is enabled, so ask for new ones;
  - read it with `GetPrincipal`.
- **For texc-symphony:** nothing changes. Its pipeline (`tutela apply`, part 4) uses the model routes with its service token, over HTTP or gRPC.
- **For onto-intelli, when it adopts Tutela:** push types with `PutResourceTypes` (`POST /v1/admin/resource-types`). Its service account needs `manage_access` and `manage_fields` at every org. The answer is a proposal: a tenant admin approves it.
- **`tutela-store`:** new `agents` (a page of a tenant's agents) and `MAX_AGENT_PAGE`.

## The lifecycle of tenants, orgs and people (part 3c)

- **Migration 12** adds the lifecycle columns to `tutela.tenant`, `tutela.org` and `tutela.principal`, row-level security on the directory for updates, and lets a tenant's purge delete its model versions ([ADR-0041](DECISIONS.md#adr-0041-the-lifecycle-of-tenants-orgs-and-people-the-operator-makes-a-tenant-soft-delete-with-a-grace-a-purge-that-keeps-the-audit-chain)). Run `tutela migrate` (or `tutelad migrate`) as the owner, then `grant_service` again: the service role gets `UPDATE (name, deleted_at, purge_after, purged_at)` on the directory, never `INSERT` or `DELETE`. `check_isolation` now fails when a runtime role may add or remove tenants.
- **Making a tenant** is the operator's: `tutelad tenant create --name <name> --admin <user:… or sa:…> --admin-upstream <iss>=<sub>` with `TUTELA_OWNER_DATABASE_URL` and `TUTELA_ISSUER`. It prints the new `tid`. Then map your external issuer to it in `tutelad`'s trust file. `tutelad tenant restore <tid>` undoes a soft delete before the purge.
- **New setting:** `TUTELA_PURGE_GRACE_SECS` (default 2592000, 30 days; at least 3600). `deploy/tutelad.env` has it.
- **`tutela-store`, in library mode too:**
  - `enter` refuses a soft-deleted tenant (`UnknownTenant`), unless the transaction entered it before; `tenants` leaves it out. `audit_records` and `verify_audit_chain` still read its chain.
  - The load leaves out a soft-deleted org and everything under it, and a write under it is `NotFound`.
  - `set_disabled(.., false)` on a deleted person is `Invalid`: it is never enabled again.
  - New module `lifecycle`: `tenant_info`, `set_tenant_name`, `delete_tenant`, `restore_tenant`, `due_tenant_purges`, `purge_tenant`, `orgs`, `org`, `set_org_name`, `delete_org`, `restore_org`, `due_org_purges`, `purge_org`, `delete_user`, `TenantInfo`, `OrgInfo`.
- **For attache and texc-symphony, when they bump:** listen for `tutela.org.deleted.v1` (remove your container for the org at `purge_after`, or hide it at once) and `tutela.user.deleted.v1` (delete or pseudonymise your copies of the person). A soft-deleted tenant answers 403 `unknown_tenant` and sends no more events.

## The audit log's leftovers (part 3c)

- **New setting:** `TUTELA_AUDIT_VERIFY_SECS` (default 3600; `0` off): every replica walks every audit chain this often ([ADR-0042](DECISIONS.md#adr-0042-the-audit-logs-leftovers-a-chain-check-on-a-timer-the-callers-trace-in-each-record)). Alert on `tutelad_audit_chains_broken` above 0.
- **Audit records** of a request now carry `request_id`, and `trace_id` and `span_id` when the caller sent a `traceparent`. attache's ledger and any reader of audit.v1 already accept these fields; `ip` stays empty.


## Scopes, role assignments and groups over the admin API (part 4a)

- **New routes and methods** ([CONTRACTS.md 7.13.7](CONTRACTS.md#7137-scopes-role-assignments-and-groups), [ADR-0043](DECISIONS.md#adr-0043-scopes-assignments-and-groups-over-the-admin-api-checked-on-the-data-they-change)): a product in service mode registers, moves and deletes its scopes, assigns roles and manages groups through `tutelad`, as library mode calls `tutela-store`. Its service account needs the keys each route names (for example `write` on the parent to register a scope, `manage_access` on a scope to assign there).
- **Narrow-only:** a change that gives anyone more than the caller holds at the same place is refused with 403 `not_held`, a removal that uncovers wider access too. A service account with the seeded `owner` role at each org it serves may give anything in those orgs.
- **A move** is refused unless `write_check`'s verdict allows it for the caller (403 `move_refused`, naming the scopes that wait for an owner).
- **`tutela-store`:** new `lock` (the tenant's revision row, for update), `group`, `group_page`, `group_member_page`, `scope_page`, `GroupSummary`, `ScopeInfo`. **`tutela-pdp`:** new `grant_excess`.

## Apps and client authentication (part 4a)

- **Migration 13** adds `tutela.app_directory`, `tutela.app` and `tutela.app_secret`, and lets a service account have an epoch ([ADR-0044](DECISIONS.md#adr-0044-apps-one-tenant-each-a-hashed-client-secret-and-azp-bound-to-the-client-that-authenticated)). Run `tutelad migrate` as the owner, then `grant_service` again (`tutelad migrate` does both).
- **What attache and texc-symphony do to authenticate as an app, when they bump:**
  1. The tenant's owner makes one app per product and tenant: `tutela apps create --name attache` with an admin token (or `POST /v1/admin/apps`), or the operator at bootstrap: `tutelad apps create --tenant <tid> --name attache`. Keep the printed `client_id` and `client_secret` in the product's secret store: the secret is shown once.
  2. The owner gives the app's service account (`principal` in the answer) the roles the product needs, with `POST /v1/admin/assignments`: attache needs `manage_agents` at every org (for example `owner` at each org); texc-symphony's pipeline needs `manage_access` and `manage_fields` at every org to publish the model, and `read_audit` to see the impact report.
  3. The product asks `POST /oauth2/token` with `grant_type=client_credentials` and its client id and secret (HTTP Basic, or `client_id` and `client_secret` in the form) for its own `tutela-authz` token, and again before it expires (`expires_in`, at most `TUTELA_TOKEN_TTL_SECS`). This replaces a service token from Keycloak exchanged at `tutelad`.
  4. When it exchanges its users' tokens, it authenticates too: the issued token's `azp` is then its client id, and a token whose `azp` is its client id can be exchanged by it only.
  5. To rotate: `tutela apps rotate` (or `POST /v1/admin/apps/{id}/rotate {overlap_secs}`) gives a new secret; deploy it within the overlap (default one hour). To revoke: `POST /v1/admin/apps/{id}/disable`; its tokens stop within `TUTELA_REVISION_CHECK_MS`.
- **A browser app** (the Console) does not authenticate: an exchange with no client authentication still works, keeps the sign-in's `azp`, and may not name an app.
- **`tutela-store`:** new `apps` items: `create_app`, `app`, `apps`, `app_secret`, `app_tenant`, `rotate_app_secret`, `disable_app`, `AppInfo`, `SecretHash`, `StoredSecret`. `set_disabled` and `revoke_sessions` take a service account too.

## The audit producer key, sealed (part 4a)

- **Migration 14** adds `tutela.audit_key` ([ADR-0045](DECISIONS.md#adr-0045-the-audit-producer-key-sealed-in-the-database-rotated-with-its-old-keys-kept)). Run `tutelad migrate` (it runs `grant_service` too: the runtime role may read, add and update audit keys, never delete one).
- **For an operator who forwards to attache's ledger:** keep `TUTELA_AUDIT_KEY` set for the first start of this version. `tutelad` seals that seed into the database (`tutela_audit_key:import` in the deployment's chain) and forwards with the same key, so attache needs no change. Then remove `TUTELA_AUDIT_KEY` from the secret store: the stored key wins, and a different seed in the environment is ignored with a warning. Without `TUTELA_AUDIT_KEY` a new key is made at the first start; give attache the `key_id` and public key `tutelad` logs.
- **Rotation:** add the new public key to attache's `ledger.producers[].keys` first, keep the old one, then `tutela keys rotate --audit`. Records already in the ledger keep verifying with the old key, which the database keeps.
- **`tutelad::ledger`:** `LedgerConfig.key` is now `import: Option<…>`; `Forwarder::new` takes the vault; `key_id()` and `public_key()` became `producer()`; new `verify_record`. **`tutela-store`:** new `AuditKey`, `Ensured`, `audit_key_id`, `audit_keys`, `signing_audit_key`, `ensure_audit_key`, `rotate_audit_key`, `rewrap_audit_keys`.

