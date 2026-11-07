//! The lifecycle of tenants, orgs and people (ADR-0041): names, soft
//! deletion with a grace period, the purge after it, and deleting a person.
//!
//! - A **tenant** is made by the operator ([`crate::create_tenant`], as the
//!   owner role). Its owner may name it and soft-delete it
//!   ([`delete_tenant`]); from then on [`crate::enter`] refuses it, so it
//!   answers nothing, and [`crate::tenants`] leaves it out, so no job visits
//!   it. After `purge_after`, [`purge_tenant`] removes its data. Its audit
//!   chain is never removed.
//! - An **org** is made with [`crate::add_org`] and soft-deleted with
//!   [`delete_org`]: it leaves the tenant's decisions at once (the load
//!   leaves out the org and everything under it), and [`purge_org`] removes
//!   its data after `purge_after`. The org row stays, so its id is never
//!   reused.
//! - A **person** is deleted with [`delete_user`]: its assignments and
//!   memberships go, its link to an upstream account goes, and the principal
//!   stays disabled, so no token of it works again.

use std::time::{Duration, SystemTime};

use tokio_postgres::{Row, Transaction};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::{OrgId, TenantKey};

use crate::events::{OutboxEvent, insert};
use crate::write::principal_row;
use crate::{
    DbResult as _, Repr, StoreError, begin_write, enter, finish_write, parse_org, set_tenant,
};

/// The longest name of a tenant or an org, in characters.
pub const MAX_NAME: usize = 200;

/// The tables a tenant's purge empties, children first. The audit chain
/// (`audit_record`, `audit_head`, `audit_forward`), the revision row and the
/// directory row stay.
const PURGED: [&str; 18] = [
    "app_secret",
    "app",
    "webhook_delivery",
    "webhook",
    "event",
    "model_proposal",
    "model_revision",
    "tenant_setting",
    "exchanged_token",
    "upstream_account",
    "principal",
    "role_assignment",
    "field_rule",
    "boundary_rule",
    "scope_path",
    "group_member",
    "group",
    "org",
];

/// What the directory says of a tenant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenantInfo {
    /// The tenant key.
    pub key: TenantKey,
    /// Its display name.
    pub name: Option<String>,
    /// When it was made.
    pub created_at: SystemTime,
}

/// Where a tenant id stands in the directory, for the operator: whether it
/// is there under which issuer, and whether it is soft-deleted or purged.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirectoryEntry {
    /// The issuer it is under.
    pub iss: String,
    /// When it was soft-deleted.
    pub deleted_at: Option<SystemTime>,
    /// When its data was purged.
    pub purged_at: Option<SystemTime>,
}

/// The directory row of tenant id `tid`, in any state, or `None` when the id
/// was never used. It enters no tenant: the directory holds no tenant data
/// and every role reads it (ADR-0019).
///
/// # Errors
///
/// A database error.
pub async fn directory_entry(
    tx: &Transaction<'_>,
    tid: &tutela_contracts::tenant::TenantId,
) -> Result<Option<DirectoryEntry>, StoreError> {
    tx.query_opt(
        "SELECT iss, deleted_at, purged_at FROM tutela.tenant WHERE tenant_id = $1",
        &[&tid.to_string()],
    )
    .await
    .db()?
    .map(|r| {
        Ok(DirectoryEntry {
            iss: r.try_get(0).db()?,
            deleted_at: r.try_get(1).db()?,
            purged_at: r.try_get(2).db()?,
        })
    })
    .transpose()
}

/// One org of a tenant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OrgInfo {
    /// The org.
    pub org: OrgId,
    /// Its display name.
    pub name: Option<String>,
    /// When it was made.
    pub created_at: SystemTime,
    /// When it was soft-deleted.
    pub deleted_at: Option<SystemTime>,
    /// When its data is purged.
    pub purge_after: Option<SystemTime>,
    /// When its data was purged.
    pub purged_at: Option<SystemTime>,
}

/// A display name: 1 to [`MAX_NAME`] characters, no control character.
fn check_name(name: &str) -> Result<(), StoreError> {
    let n = name.chars().count();
    if n == 0 || n > MAX_NAME || name.chars().any(char::is_control) {
        return Err(StoreError::invalid(
            "a name is 1 to 200 characters with no control character",
        ));
    }
    Ok(())
}

fn secs(grace: Duration) -> f64 {
    grace.as_secs_f64()
}

/// The tenant's directory entry.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn tenant_info(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<TenantInfo, StoreError> {
    enter(tx, tenant).await?;
    let r = tx
        .query_one(
            "SELECT name, created_at FROM tutela.tenant WHERE tenant_id = $1",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?;
    Ok(TenantInfo {
        key: tenant.clone(),
        name: r.try_get(0).db()?,
        created_at: r.try_get(1).db()?,
    })
}

/// Names the tenant, or clears its name. Changes no decision, so no
/// revision moves.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a bad name,
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn set_tenant_name(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    name: Option<&str>,
) -> Result<(), StoreError> {
    if let Some(n) = name {
        check_name(n)?;
    }
    enter(tx, tenant).await?;
    let n = tx
        .execute(
            "UPDATE tutela.tenant SET name = $2 WHERE tenant_id = $1",
            &[&tenant.tid.to_string(), &name],
        )
        .await
        .db()?;
    if n != 1 {
        return Err(StoreError::unknown_tenant());
    }
    Ok(())
}

/// Soft-deletes the tenant: from the commit on, [`enter`] refuses it and
/// [`crate::tenants`] leaves it out. Its data is purged after the returned
/// time, `grace` from now on the database's clock. The caller's transaction
/// keeps the tenant until it ends, to write its audit record last.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn delete_tenant(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    grace: Duration,
) -> Result<SystemTime, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        "UPDATE tutela.tenant SET deleted_at = now(), \
         purge_after = now() + make_interval(secs => $2) \
         WHERE tenant_id = $1 AND deleted_at IS NULL RETURNING purge_after",
        &[&tenant.tid.to_string(), &secs(grace)],
    )
    .await
    .db()?
    .ok_or(StoreError::unknown_tenant())?
    .try_get(0)
    .db()
}

/// Undoes a soft delete before the purge. The operator's call: it runs as
/// the owner role, because the tenant is out of the directory. Returns
/// `false` when the tenant is not deleted, or already purged.
///
/// # Errors
///
/// A database error.
pub async fn restore_tenant(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<bool, StoreError> {
    let n = tx
        .execute(
            "UPDATE tutela.tenant SET deleted_at = NULL, purge_after = NULL \
             WHERE tenant_id = $1 AND iss = $2 AND deleted_at IS NOT NULL AND purged_at IS NULL",
            &[&tenant.tid.to_string(), &tenant.iss.as_str()],
        )
        .await
        .db()?;
    Ok(n == 1)
}

/// The soft-deleted tenants whose grace has passed and whose data is still
/// there.
///
/// # Errors
///
/// A database error.
pub async fn due_tenant_purges(tx: &Transaction<'_>) -> Result<Vec<TenantKey>, StoreError> {
    tx.query(
        "SELECT tenant_id, iss FROM tutela.tenant WHERE deleted_at IS NOT NULL \
         AND purge_after <= now() AND purged_at IS NULL ORDER BY tenant_id",
        &[],
    )
    .await
    .db()?
    .iter()
    .map(|r| {
        Ok(TenantKey::new(
            r.try_get::<_, &str>(1)
                .db()?
                .parse()
                .map_err(|_| StoreError::corrupt("issuer"))?,
            r.try_get::<_, &str>(0)
                .db()?
                .parse()
                .map_err(|_| StoreError::corrupt("tenant id"))?,
        ))
    })
    .collect()
}

/// Purges a soft-deleted tenant whose grace has passed: every row of its
/// tables but its audit chain, its revision row and its directory row,
/// which gets `purged_at`. Returns `false` when it is not due, or another
/// call purged it first (the directory row is locked until this ends).
///
/// # Errors
///
/// [`TenantMismatch`](crate::StoreErrorKind::TenantMismatch) when the
/// transaction entered another tenant, or a database error.
pub async fn purge_tenant(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<bool, StoreError> {
    let tid = tenant.tid.to_string();
    // Not `enter`: the tenant has left the directory for every request.
    let current: Option<String> = tx
        .query_one("SELECT current_setting('tutela.tenant_id', true)", &[])
        .await
        .db()?
        .try_get(0)
        .db()?;
    match current.filter(|c| !c.is_empty()) {
        Some(c) if c == tid => {}
        Some(_) => return Err(StoreError(Repr::TenantMismatch)),
        None => set_tenant(tx, &tenant.tid).await?,
    }
    let due = tx
        .query_opt(
            "UPDATE tutela.tenant SET purged_at = now() WHERE tenant_id = $1 AND iss = $2 \
             AND deleted_at IS NOT NULL AND purge_after <= now() AND purged_at IS NULL \
             RETURNING 1",
            &[&tid, &tenant.iss.as_str()],
        )
        .await
        .db()?;
    if due.is_none() {
        return Ok(false);
    }
    for table in PURGED {
        tx.execute(
            &format!("DELETE FROM tutela.\"{table}\" WHERE tenant_id = $1"),
            &[&tid],
        )
        .await
        .db()?;
    }
    Ok(true)
}

fn org_info(r: &Row) -> Result<OrgInfo, StoreError> {
    Ok(OrgInfo {
        org: parse_org(r.try_get(0).db()?)?,
        name: r.try_get(1).db()?,
        created_at: r.try_get(2).db()?,
        deleted_at: r.try_get(3).db()?,
        purge_after: r.try_get(4).db()?,
        purged_at: r.try_get(5).db()?,
    })
}

const ORG_COLUMNS: &str = "org_id, name, created_at, deleted_at, purge_after, purged_at";

/// The tenant's orgs, the deleted ones too, oldest first.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn orgs(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<Vec<OrgInfo>, StoreError> {
    enter(tx, tenant).await?;
    tx.query(
        &format!(
            "SELECT {ORG_COLUMNS} FROM tutela.org WHERE tenant_id = $1 ORDER BY created_at, org_id"
        ),
        &[&tenant.tid.to_string()],
    )
    .await
    .db()?
    .iter()
    .map(org_info)
    .collect()
}

/// One org of the tenant, deleted or not.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn org(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: &OrgId,
) -> Result<Option<OrgInfo>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        &format!("SELECT {ORG_COLUMNS} FROM tutela.org WHERE tenant_id = $1 AND org_id = $2"),
        &[&tenant.tid.to_string(), &org.to_string()],
    )
    .await
    .db()?
    .as_ref()
    .map(org_info)
    .transpose()
}

/// Names an org that is not deleted, or clears its name. No revision moves.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an org this tenant does
/// not have, or that is deleted, [`Invalid`](crate::StoreErrorKind::Invalid)
/// for a bad name, or a database error.
pub async fn set_org_name(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: &OrgId,
    name: Option<&str>,
) -> Result<(), StoreError> {
    if let Some(n) = name {
        check_name(n)?;
    }
    enter(tx, tenant).await?;
    let n = tx
        .execute(
            "UPDATE tutela.org SET name = $3 WHERE tenant_id = $1 AND org_id = $2 \
             AND deleted_at IS NULL",
            &[&tenant.tid.to_string(), &org.to_string(), &name],
        )
        .await
        .db()?;
    if n == 0 {
        return Err(StoreError::not_found("org"));
    }
    Ok(())
}

/// Soft-deletes an org: in this revision the load leaves it out, with every
/// registered scope under it and their assignments, field rules and
/// boundary rules. Returns when it is purged and the new revision. A
/// tenant keeps at least one org.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an org this tenant does
/// not have or that is deleted, [`Invalid`](crate::StoreErrorKind::Invalid)
/// for the last org, or a database error.
pub async fn delete_org(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: &OrgId,
    grace: Duration,
) -> Result<(SystemTime, u64), StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let live: i64 = tx
        .query_one(
            "SELECT count(*) FROM tutela.org WHERE tenant_id = $1 AND deleted_at IS NULL",
            &[&tid],
        )
        .await
        .db()?
        .try_get(0)
        .db()?;
    let purge_after: SystemTime = tx
        .query_opt(
            "UPDATE tutela.org SET deleted_at = now(), \
             purge_after = now() + make_interval(secs => $3) \
             WHERE tenant_id = $1 AND org_id = $2 AND deleted_at IS NULL RETURNING purge_after",
            &[&tid, &org.to_string(), &secs(grace)],
        )
        .await
        .db()?
        .ok_or(StoreError::not_found("org"))?
        .try_get(0)
        .db()?;
    if live <= 1 {
        return Err(StoreError::invalid("a tenant keeps at least one org"));
    }
    Ok((purge_after, finish_write(tx, tenant, rev).await?))
}

/// Brings back a soft-deleted org before its purge. Returns the new
/// revision.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) when the org is not deleted
/// or already purged, or a database error.
pub async fn restore_org(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: &OrgId,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let n = tx
        .execute(
            "UPDATE tutela.org SET deleted_at = NULL, purge_after = NULL \
             WHERE tenant_id = $1 AND org_id = $2 AND deleted_at IS NOT NULL AND purged_at IS NULL",
            &[&tenant.tid.to_string(), &org.to_string()],
        )
        .await
        .db()?;
    if n == 0 {
        return Err(StoreError::not_found("deleted org"));
    }
    finish_write(tx, tenant, rev).await
}

/// The tenant's deleted orgs whose grace has passed and whose data is still
/// there.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn due_org_purges(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Vec<OrgId>, StoreError> {
    enter(tx, tenant).await?;
    tx.query(
        "SELECT org_id FROM tutela.org WHERE tenant_id = $1 AND deleted_at IS NOT NULL \
         AND purge_after <= now() AND purged_at IS NULL ORDER BY org_id",
        &[&tenant.tid.to_string()],
    )
    .await
    .db()?
    .iter()
    .map(|r| parse_org(r.try_get(0).db()?))
    .collect()
}

/// Purges a deleted org whose grace has passed: its registered scopes and
/// their assignments, field rules and boundary rules, and the assignments at
/// the org itself. The org row stays with `purged_at`; its groups stay, as
/// a group may be assigned in another org. Returns the new revision, or
/// `None` when it is not due (the caller rolls back).
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn purge_org(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: &OrgId,
) -> Result<Option<u64>, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let due = tx
        .query_opt(
            "UPDATE tutela.org SET purged_at = now() WHERE tenant_id = $1 AND org_id = $2 \
             AND deleted_at IS NOT NULL AND purge_after <= now() AND purged_at IS NULL RETURNING 1",
            &[&tid, &org.to_string()],
        )
        .await
        .db()?;
    if due.is_none() {
        return Ok(None);
    }
    let tag = format!("org:{org}");
    let mut kinds = vec!["org".to_owned()];
    let mut ids = vec![org.to_string()];
    for r in tx
        .query(
            "SELECT scope_kind, scope_id FROM tutela.scope_path \
             WHERE tenant_id = $1 AND ancestors[cardinality(ancestors)] = $2",
            &[&tid, &tag],
        )
        .await
        .db()?
    {
        kinds.push(r.try_get(0).db()?);
        ids.push(r.try_get(1).db()?);
    }
    for table in [
        "role_assignment",
        "field_rule",
        "boundary_rule",
        "scope_path",
    ] {
        tx.execute(
            &format!(
                "DELETE FROM tutela.{table} WHERE tenant_id = $1 AND (scope_kind, scope_id) IN \
                 (SELECT * FROM unnest($2::text[], $3::text[]))"
            ),
            &[&tid, &kinds, &ids],
        )
        .await
        .db()?;
    }
    Ok(Some(finish_write(tx, tenant, rev).await?))
}

/// Deletes a person of the tenant: its assignments and group memberships go
/// in this revision, its link to its upstream account goes, and the
/// principal stays as a disabled row with a raised epoch, so no token of it
/// works again and it is never enabled. Emits `tutela.user.deleted.v1` and
/// `tutela.principal.disabled.v1`. Returns the new epoch and revision.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a principal that is not a
/// user, [`NotFound`](crate::StoreErrorKind::NotFound) for one deleted
/// already, or a database error.
pub async fn delete_user(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    user: &Principal,
) -> Result<(u64, u64), StoreError> {
    if user.kind() != PrincipalKind::User {
        return Err(StoreError::invalid("only a user is deleted here"));
    }
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let name = user.to_string();
    let gone = tx
        .query_opt(
            "SELECT 1 FROM tutela.principal WHERE tenant_id = $1 AND principal = $2 \
             AND deleted_at IS NOT NULL",
            &[&tid, &name],
        )
        .await
        .db()?;
    if gone.is_some() {
        return Err(StoreError::not_found("user"));
    }
    let (kind, id) = principal_row(user)?;
    tx.execute(
        "DELETE FROM tutela.role_assignment WHERE tenant_id = $1 \
         AND principal_kind = $2 AND principal_id = $3",
        &[&tid, &kind, &id],
    )
    .await
    .db()?;
    tx.execute(
        "DELETE FROM tutela.group_member WHERE tenant_id = $1 \
         AND member_kind = $2 AND member_id = $3",
        &[&tid, &kind, &id],
    )
    .await
    .db()?;
    tx.execute(
        "DELETE FROM tutela.upstream_account WHERE tenant_id = $1 AND principal = $2",
        &[&tid, &name],
    )
    .await
    .db()?;
    let epoch: i64 = tx
        .query_one(
            "INSERT INTO tutela.principal (tenant_id, principal, epoch, disabled_at, deleted_at) \
             VALUES ($1, $2, 1, now(), now()) \
             ON CONFLICT (tenant_id, principal) DO UPDATE \
             SET epoch = tutela.principal.epoch + 1, \
                 disabled_at = coalesce(tutela.principal.disabled_at, now()), \
                 deleted_at = now() \
             RETURNING epoch",
            &[&tid, &name],
        )
        .await
        .db()?
        .try_get(0)
        .db()?;
    let epoch = u64::try_from(epoch).map_err(|_| StoreError::corrupt("epoch"))?;
    for e in [
        OutboxEvent::UserDeleted { user: user.clone() },
        OutboxEvent::PrincipalDisabled {
            principal: user.clone(),
            epoch,
        },
    ] {
        insert(tx, &tenant.tid, &e).await?;
    }
    let rev = finish_write(tx, tenant, rev).await?;
    Ok((epoch, rev))
}
