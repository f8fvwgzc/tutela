//! Apps over the admin API (CONTRACTS.md 7.13.8, ADR-0044).
//!
//! **Who may ask:** every admin key at every org ([`TENANT_KEYS`]): the
//! tenant's owner, as for making an org. An app's credentials let a product
//! speak for the tenant with a service account, so nobody less may make
//! one. The operator makes the first ones for the bootstrap
//! (`tutelad apps create`, [`crate::lifecycle`]).
//!
//! A client secret is shown once: in the answer of `create` and `rotate`.
//! Records name the key's id and display prefix, never the secret.

use std::time::{Duration, SystemTime};

use tutela_contracts::audit::Actor;
use tutela_sdk::Identity;
use tutela_store::AppInfo;

use super::lifecycle::TENANT_KEYS;
use super::wire::{AppOut, AppSecretOut, AppsOut, NameBody, RotateBody};
use super::{guard, required, store_problem};
use crate::api::{AppState, Problem};
use crate::apps::{DEFAULT_OVERLAP_SECS, MAX_OVERLAP_SECS, is_client_id, new_secret};
use crate::audit::{self, Record};
use crate::tenant::Tenant;

fn invalid(detail: &str) -> Problem {
    Problem::invalid("invalid_request", detail.to_owned())
}

fn not_found() -> Problem {
    Problem::new(
        axum::http::StatusCode::NOT_FOUND,
        "not_found",
        "no such app in this tenant",
    )
}

impl AppOut {
    /// The answer for a stored app.
    #[must_use]
    pub fn of(a: &AppInfo) -> Self {
        use crate::models::wire::time;
        Self {
            client_id: a.id.clone(),
            name: a.name.clone(),
            principal: a.principal.to_string(),
            created_by: a.created_by.clone(),
            created_at: time(a.created_at),
            disabled_at: a.disabled_at.and_then(time),
        }
    }
}

fn secret_failed(_: crate::apps::SecretError) -> Problem {
    tracing::error!("no client secret could be made");
    Problem::stale("unavailable")
}

/// `POST /v1/admin/apps {name}`: a new app of the caller's tenant, its
/// service account and its first client secret.
///
/// # Errors
///
/// A [`Problem`]: 400 for a bad name, 403 without every admin key at every
/// org.
pub async fn create(
    state: &AppState,
    id: &Identity,
    body: NameBody,
) -> Result<AppSecretOut, Problem> {
    let tenant = Tenant::of(id);
    let name = required(body.name, "name")?;
    let action = "tutela_app:create";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_app", "new"),
    )
    .await?;
    let (pepper, version) = state.pepper();
    let (secret, hash) = new_secret(pepper, version).map_err(secret_failed)?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let app = tutela_store::create_app(&tx, tenant.key(), &name, &by.to_string(), &hash)
        .await
        .map_err(store_problem)?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_app", &app.id),
            )
            .allowed(rev)
            .detail("app", app.id.clone())
            .detail("principal", app.principal.to_string())
            .detail("key_id", hash.key_id.clone())
            .detail("prefix", format!("tut_sk_{}", hash.prefix)),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!(app = %app.id, "an app was made");
    Ok(AppSecretOut {
        app: AppOut::of(&app),
        client_secret: secret.to_string(),
    })
}

/// `GET /v1/admin/apps`: the tenant's apps, oldest first. Never a secret.
///
/// # Errors
///
/// A [`Problem`]: 403 without every admin key at every org.
pub async fn list(state: &AppState, id: &Identity) -> Result<AppsOut, Problem> {
    let tenant = Tenant::of(id);
    guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        "tutela_app:read",
        ("tutela_app", "*"),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let apps = tutela_store::apps(&tx, tenant.key()).await?;
    tx.commit().await?;
    Ok(AppsOut {
        apps: apps.iter().map(AppOut::of).collect(),
    })
}

/// `POST /v1/admin/apps/{id}/rotate {overlap_secs?}`: a new client secret,
/// shown this once. Every secret the app had keeps working for
/// `overlap_secs` (default 3600, at most 604800), so the app can move.
///
/// # Errors
///
/// A [`Problem`]: 400 for an overlap over the limit, 404 for an app that is
/// not there or is disabled, 403 as for [`create`].
pub async fn rotate(
    state: &AppState,
    id: &Identity,
    app: &str,
    body: RotateBody,
) -> Result<AppSecretOut, Problem> {
    let tenant = Tenant::of(id);
    if !is_client_id(app) {
        return Err(not_found());
    }
    let overlap = body.overlap_secs.unwrap_or(DEFAULT_OVERLAP_SECS);
    if overlap > MAX_OVERLAP_SECS {
        return Err(invalid("`overlap_secs` is at most 604800"));
    }
    let action = "tutela_app:rotate";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_app", app),
    )
    .await?;
    let (pepper, version) = state.pepper();
    let (secret, hash) = new_secret(pepper, version).map_err(secret_failed)?;
    let until = SystemTime::now() + Duration::from_secs(overlap);
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let found =
        tutela_store::rotate_app_secret(&tx, tenant.key(), app, &hash, until, &by.to_string())
            .await
            .map_err(|e| match e.kind() {
                tutela_store::StoreErrorKind::NotFound => not_found(),
                _ => store_problem(e),
            })?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(tenant.key(), Actor::new(by), action, ("tutela_app", app))
                .allowed(rev)
                .detail("app", app)
                .detail("key_id", hash.key_id.clone())
                .detail("prefix", format!("tut_sk_{}", hash.prefix))
                .detail("overlap_secs", overlap),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!(app, "an app's client secret was rotated");
    Ok(AppSecretOut {
        app: AppOut::of(&found),
        client_secret: secret.to_string(),
    })
}

/// `POST /v1/admin/apps/{id}/disable`: every secret stops now, and the
/// app's service account is disabled with a raised epoch, so the tokens it
/// holds are refused on `tutelad`'s API within `TUTELA_REVISION_CHECK_MS`
/// and products hear `tutela.principal.disabled.v1`.
///
/// # Errors
///
/// A [`Problem`]: 404 for an app that is not there or is disabled, 403 as
/// for [`create`].
pub async fn disable(state: &AppState, id: &Identity, app: &str) -> Result<AppOut, Problem> {
    let tenant = Tenant::of(id);
    if !is_client_id(app) {
        return Err(not_found());
    }
    let action = "tutela_app:disable";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_app", app),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let (found, epoch) = tutela_store::disable_app(&tx, tenant.key(), app)
        .await
        .map_err(|e| match e.kind() {
            tutela_store::StoreErrorKind::NotFound => not_found(),
            _ => store_problem(e),
        })?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(tenant.key(), Actor::new(by), action, ("tutela_app", app))
                .allowed(rev)
                .detail("app", app)
                .detail("principal", found.principal.to_string())
                .detail("epoch", epoch)
                .detail("rev", rev),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!(app, "an app was disabled");
    let mut out = AppOut::of(&found);
    if out.disabled_at.is_none() {
        out.disabled_at = crate::models::wire::time(SystemTime::now());
    }
    Ok(out)
}
