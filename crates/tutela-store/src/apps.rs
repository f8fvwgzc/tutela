//! Apps and their client secrets (ADR-0044, CONTRACTS.md 4.9, 5).
//!
//! An app belongs to one tenant. Its client id is `app_<uuidv7>`, and its
//! principal is a service account of the tenant, which holds what ordinary
//! assignments give it. Its client secrets are API keys (`tut_sk_…`),
//! stored only as their hash: the caller hashes with the pepper
//! (`TUTELA_KEY_PEPPER`) and this module never sees a secret.
//!
//! `app_directory` maps a client id to its tenant, so the token endpoint can
//! enter the right tenant before it reads anything of it.

use std::time::SystemTime;

use tokio_postgres::Transaction;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{TenantId, TenantKey};

use crate::{DbResult as _, StoreError, enter, uuid7};

/// One app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppInfo {
    /// Its client id, `app_<uuidv7>`.
    pub id: String,
    /// Its display name.
    pub name: String,
    /// Its service account.
    pub principal: Principal,
    /// Who made it.
    pub created_by: String,
    /// When it was made.
    pub created_at: SystemTime,
    /// When it was disabled.
    pub disabled_at: Option<SystemTime>,
}

/// A client secret's hash, made by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretHash {
    /// The key's id, `key_<uuidv7>`.
    pub key_id: String,
    /// The 8 characters that find the key (CONTRACTS.md 5.1).
    pub prefix: String,
    /// SHA-256(pepper || key), 64 lowercase hex characters.
    pub hash: String,
    /// The version of the pepper it was hashed with.
    pub pepper_version: u32,
}

/// A stored secret that still works.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSecret {
    /// The app it belongs to.
    pub app_id: String,
    /// Its hash.
    pub hash: SecretHash,
    /// When it stops working, if it does.
    pub expires_at: Option<SystemTime>,
}

const APP: &str = "id, name, principal, created_by, created_at, disabled_at";

fn app_row(r: &tokio_postgres::Row) -> Result<AppInfo, StoreError> {
    Ok(AppInfo {
        id: r.try_get(0).db()?,
        name: r.try_get(1).db()?,
        principal: r
            .try_get::<_, &str>(2)
            .db()?
            .parse()
            .map_err(|_| StoreError::corrupt("app principal"))?,
        created_by: r.try_get(3).db()?,
        created_at: r.try_get(4).db()?,
        disabled_at: r.try_get(5).db()?,
    })
}

fn version(v: u32) -> Result<i32, StoreError> {
    i32::try_from(v).map_err(|_| StoreError::invalid("a pepper version is at most 2^31 - 1"))
}

async fn add_secret(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    app: &str,
    secret: &SecretHash,
    by: &str,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO tutela.app_secret (tenant_id, app_id, key_id, prefix, hash, pepper_version, \
         created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &tenant.tid.to_string(),
            &app,
            &secret.key_id,
            &secret.prefix,
            &secret.hash,
            &version(secret.pepper_version)?,
            &by,
        ],
    )
    .await
    .map_err(|e| {
        if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
            StoreError::exists("a key with this prefix")
        } else {
            StoreError::from(crate::Repr::Db(e))
        }
    })?;
    Ok(())
}

/// Makes an app of `tenant` with its service account and its first client
/// secret. The service account gets a principal row at epoch 0, so the
/// app's disabling can raise it. No revision moves: with no assignment the
/// app holds nothing.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a name that is empty,
/// over 200 characters or holds a control character,
/// [`Exists`](crate::StoreErrorKind::Exists) for a prefix in use (draw
/// another), or a database error.
pub async fn create_app(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    name: &str,
    by: &str,
    secret: &SecretHash,
) -> Result<AppInfo, StoreError> {
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return Err(StoreError::invalid(
            "an app name is 1 to 200 characters with no control character",
        ));
    }
    enter(tx, tenant).await?;
    let id = format!("app_{}", uuid7()?);
    let principal: Principal = format!("sa:sa_{}", uuid7()?)
        .parse()
        .map_err(|_| StoreError::corrupt("service account"))?;
    let tid = tenant.tid.to_string();
    tx.execute(
        "INSERT INTO tutela.app_directory (app_id, tenant_id) VALUES ($1, $2)",
        &[&id, &tid],
    )
    .await
    .db()?;
    tx.execute(
        "INSERT INTO tutela.principal (tenant_id, principal) VALUES ($1, $2)",
        &[&tid, &principal.to_string()],
    )
    .await
    .db()?;
    let row = tx
        .query_one(
            &format!(
                "INSERT INTO tutela.app (tenant_id, id, name, principal, created_by) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING {APP}"
            ),
            &[&tid, &id, &name, &principal.to_string(), &by],
        )
        .await
        .db()?;
    add_secret(tx, tenant, &id, secret, by).await?;
    app_row(&row)
}

/// The tenant an app belongs to, from the directory. It needs no tenant:
/// the directory holds no tenant data.
///
/// # Errors
///
/// [`Corrupt`](crate::StoreErrorKind::Corrupt) or a database error.
pub async fn app_tenant(tx: &Transaction<'_>, app: &str) -> Result<Option<TenantKey>, StoreError> {
    let Some(r) = tx
        .query_opt(
            "SELECT d.tenant_id, t.iss FROM tutela.app_directory d \
             JOIN tutela.tenant t ON t.tenant_id = d.tenant_id \
             WHERE d.app_id = $1 AND t.deleted_at IS NULL",
            &[&app],
        )
        .await
        .db()?
    else {
        return Ok(None);
    };
    let tid: TenantId = r
        .try_get::<_, &str>(0)
        .db()?
        .parse()
        .map_err(|_| StoreError::corrupt("tenant id"))?;
    let iss = r
        .try_get::<_, &str>(1)
        .db()?
        .parse()
        .map_err(|_| StoreError::corrupt("issuer"))?;
    Ok(Some(TenantKey::new(iss, tid)))
}

/// One app of `tenant`.
///
/// # Errors
///
/// A database error.
pub async fn app(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
) -> Result<Option<AppInfo>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        &format!("SELECT {APP} FROM tutela.app WHERE tenant_id = $1 AND id = $2"),
        &[&tenant.tid.to_string(), &id],
    )
    .await
    .db()?
    .as_ref()
    .map(app_row)
    .transpose()
}

/// The apps of `tenant`, oldest first.
///
/// # Errors
///
/// A database error.
pub async fn apps(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<Vec<AppInfo>, StoreError> {
    enter(tx, tenant).await?;
    tx.query(
        &format!("SELECT {APP} FROM tutela.app WHERE tenant_id = $1 ORDER BY created_at, id"),
        &[&tenant.tid.to_string()],
    )
    .await
    .db()?
    .iter()
    .map(app_row)
    .collect()
}

/// The secret with `prefix`, while it still works and its app is enabled.
///
/// # Errors
///
/// A database error.
pub async fn app_secret(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    prefix: &str,
) -> Result<Option<StoredSecret>, StoreError> {
    enter(tx, tenant).await?;
    let Some(r) = tx
        .query_opt(
            "SELECT s.app_id, s.key_id, s.prefix, s.hash, s.pepper_version, s.expires_at \
             FROM tutela.app_secret s JOIN tutela.app a \
             ON a.tenant_id = s.tenant_id AND a.id = s.app_id \
             WHERE s.tenant_id = $1 AND s.prefix = $2 AND a.disabled_at IS NULL \
             AND (s.expires_at IS NULL OR s.expires_at > clock_timestamp())",
            &[&tenant.tid.to_string(), &prefix],
        )
        .await
        .db()?
    else {
        return Ok(None);
    };
    let v: i32 = r.try_get(4).db()?;
    Ok(Some(StoredSecret {
        app_id: r.try_get(0).db()?,
        hash: SecretHash {
            key_id: r.try_get(1).db()?,
            prefix: r.try_get(2).db()?,
            hash: r.try_get(3).db()?,
            pepper_version: u32::try_from(v).map_err(|_| StoreError::corrupt("pepper version"))?,
        },
        expires_at: r.try_get(5).db()?,
    }))
}

/// Adds a new client secret to an app, and lets every secret it had work
/// until `old_until` at the latest (an overlap, CONTRACTS.md 10.4).
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an app that is not
/// there or is disabled, [`Exists`](crate::StoreErrorKind::Exists) for a
/// prefix in use, or a database error.
pub async fn rotate_app_secret(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    app: &str,
    secret: &SecretHash,
    old_until: SystemTime,
    by: &str,
) -> Result<AppInfo, StoreError> {
    let found = self::app(tx, tenant, app)
        .await?
        .filter(|a| a.disabled_at.is_none())
        .ok_or(StoreError::not_found("app"))?;
    tx.execute(
        "UPDATE tutela.app_secret SET expires_at = least(coalesce(expires_at, $3), $3) \
         WHERE tenant_id = $1 AND app_id = $2",
        &[&tenant.tid.to_string(), &app, &old_until],
    )
    .await
    .db()?;
    add_secret(tx, tenant, app, secret, by).await?;
    Ok(found)
}

/// Disables an app: every secret stops now, and its service account is
/// disabled with a raised epoch, so the tokens it holds are refused too.
/// Returns the app and the service account's new epoch.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an app that is not
/// there or is disabled already, or a database error.
pub async fn disable_app(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    app: &str,
) -> Result<(AppInfo, u64), StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let row = tx
        .query_opt(
            &format!(
                "UPDATE tutela.app SET disabled_at = now() WHERE tenant_id = $1 AND id = $2 \
                 AND disabled_at IS NULL RETURNING {APP}"
            ),
            &[&tid, &app],
        )
        .await
        .db()?
        .ok_or(StoreError::not_found("app"))?;
    let found = app_row(&row)?;
    tx.execute(
        "UPDATE tutela.app_secret SET expires_at = least(coalesce(expires_at, now()), now()) \
         WHERE tenant_id = $1 AND app_id = $2",
        &[&tid, &app],
    )
    .await
    .db()?;
    let epoch = crate::set_disabled(tx, tenant, &found.principal, true).await?;
    Ok((found, epoch))
}
