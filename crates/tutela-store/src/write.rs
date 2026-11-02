//! Writes. Each one runs in the caller's transaction, bumps the tenant
//! revision first and checks the tenant data last (see the crate docs).
//! Each returns the new revision; the caller sends it as
//! `at_least_revision` on its next check.

use std::collections::BTreeSet;
use std::time::SystemTime;

use tokio_postgres::Transaction;
use tokio_postgres::types::ToSql;
use tutela_contracts::decision::RuleId;
use tutela_contracts::keys::FieldKey;
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, OrgId, TenantId, TenantKey};
use tutela_pdp::model::{GroupKey, RoleKey};
use tutela_pdp::{MAX_PATH, Member, PathEntry, Subject};

use crate::bindings::{Assignment, assignment_row};
use crate::{
    DbResult as _, StoreError, begin_write, entry_text, finish_write, new_rule_id, parse_entry,
    set_tenant, to_rev, uuid7,
};

/// The longest group name.
const MAX_GROUP_NAME: usize = 256;

/// Makes a new tenant for `iss`, with revision 0. The tenant id is new and
/// never reused.
///
/// # Errors
///
/// A database error.
pub async fn create_tenant(tx: &Transaction<'_>, iss: &Issuer) -> Result<TenantKey, StoreError> {
    let tid = TenantId::new(uuid7()?);
    tx.execute(
        "INSERT INTO tutela.tenant (tenant_id, iss) VALUES ($1, $2)",
        &[&tid.to_string(), &iss.as_str()],
    )
    .await
    .db()?;
    set_tenant(tx, &tid).await?;
    tx.execute(
        "INSERT INTO tutela.tenant_rev (tenant_id, rev) VALUES ($1, 0)",
        &[&tid.to_string()],
    )
    .await
    .db()?;
    Ok(TenantKey::new(iss.clone(), tid))
}

/// Adds a new org to the tenant. Returns the org id and the new revision.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn add_org(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<(OrgId, u64), StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let org = OrgId::new(uuid7()?);
    tx.execute(
        "INSERT INTO tutela.org (tenant_id, org_id) VALUES ($1, $2)",
        &[&tenant.tid.to_string(), &org.to_string()],
    )
    .await
    .db()?;
    Ok((org, finish_write(tx, tenant, rev).await?))
}

/// Assigns `role` to `subject` at `scope`. The scope is an org of the
/// tenant or a registered scope ([`put_scope`]). Returns the new
/// assignment id and the new revision.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unregistered scope
/// or an unknown group, [`Exists`](crate::StoreErrorKind::Exists) if the
/// subject already has an assignment at the scope (one per (subject,
/// scope)), [`Refused`](crate::StoreErrorKind::Refused) if the data would
/// break a rule, or a database error.
pub async fn assign(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    subject: &Subject,
    role: &RoleKey,
    scope: &PathEntry,
    granted_by: Option<&Principal>,
) -> Result<(RuleId, u64), StoreError> {
    insert_assignment(tx, tenant, subject, role, scope, granted_by, None).await
}

/// As [`assign`], for an assignment that ends at `expires_at`. It counts
/// until then. A sweep ([`expire_assignments`]) then removes it and bumps
/// the revision (ADR-0020).
///
/// # Errors
///
/// As [`assign`], and [`Invalid`](crate::StoreErrorKind::Invalid) for a time
/// that has passed by the database's clock.
pub async fn assign_until(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    subject: &Subject,
    role: &RoleKey,
    scope: &PathEntry,
    granted_by: Option<&Principal>,
    expires_at: SystemTime,
) -> Result<(RuleId, u64), StoreError> {
    insert_assignment(
        tx,
        tenant,
        subject,
        role,
        scope,
        granted_by,
        Some(expires_at),
    )
    .await
}

async fn insert_assignment(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    subject: &Subject,
    role: &RoleKey,
    scope: &PathEntry,
    granted_by: Option<&Principal>,
    expires_at: Option<SystemTime>,
) -> Result<(RuleId, u64), StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    require_future(tx, expires_at).await?;
    require_scope(tx, &tid, scope).await?;
    let (kind, id) = subject_row(tx, &tid, subject).await?;
    let same = "WHERE tenant_id = $1 AND principal_kind = $2 \
                AND principal_id = $3 AND scope_kind = $4 AND scope_id = $5";
    let row: [&(dyn ToSql + Sync); 5] = [
        &tid,
        &kind,
        &id,
        &scope.type_name.as_str(),
        &scope.id.as_str(),
    ];
    // A row past its expiry no longer counts, so it does not hold the place.
    tx.execute(
        &format!(
            "DELETE FROM tutela.role_assignment {same} \
             AND expires_at IS NOT NULL AND expires_at <= clock_timestamp()"
        ),
        &row,
    )
    .await
    .db()?;
    let taken = tx
        .query_opt(
            &format!("SELECT 1 FROM tutela.role_assignment {same}"),
            &row,
        )
        .await
        .db()?;
    if taken.is_some() {
        return Err(StoreError::exists(
            "an assignment for this subject at this scope",
        ));
    }
    let rule = new_rule_id("ra")?;
    tx.execute(
        "INSERT INTO tutela.role_assignment (tenant_id, id, principal_kind, principal_id, \
         scope_kind, scope_id, role_id, granted_by, expires_at, rev) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &tid,
            &rule.as_str(),
            &kind,
            &id,
            &scope.type_name.as_str(),
            &scope.id.as_str(),
            &role.as_str(),
            &granted_by.map(ToString::to_string),
            &expires_at,
            &db_rev(rev)?,
        ],
    )
    .await
    .db()?;
    Ok((rule, finish_write(tx, tenant, rev).await?))
}

/// Changes when an assignment ends, or with `None` makes it permanent.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an assignment that does
/// not exist or has already expired,
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a time that has passed,
/// or a database error.
pub async fn set_assignment_expiry(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &RuleId,
    expires_at: Option<SystemTime>,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    require_future(tx, expires_at).await?;
    let changed = tx
        .execute(
            "UPDATE tutela.role_assignment SET expires_at = $3, rev = $4 \
             WHERE tenant_id = $1 AND id = $2 \
             AND (expires_at IS NULL OR expires_at > clock_timestamp())",
            &[
                &tenant.tid.to_string(),
                &id.as_str(),
                &expires_at,
                &db_rev(rev)?,
            ],
        )
        .await
        .db()?;
    if changed == 0 {
        return Err(StoreError::not_found("assignment"));
    }
    finish_write(tx, tenant, rev).await
}

/// A time must be ahead of the database's clock.
async fn require_future(
    tx: &Transaction<'_>,
    expires_at: Option<SystemTime>,
) -> Result<(), StoreError> {
    let Some(at) = expires_at else {
        return Ok(());
    };
    let ahead: bool = tx
        .query_one("SELECT $1::timestamptz > clock_timestamp()", &[&at])
        .await
        .db()?
        .try_get(0)
        .db()?;
    if ahead {
        Ok(())
    } else {
        Err(StoreError::invalid("an expiry must be in the future"))
    }
}

/// What a sweep removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expired {
    /// The assignments that passed their expiry and are now gone.
    pub assignments: Vec<Assignment>,
    /// The new tenant revision.
    pub rev: u64,
}

/// Removes the assignments of `tenant` that are past their expiry, and bumps
/// the revision in the same transaction, so every cache at an older revision
/// reloads. Returns `None` when nothing has expired, with no bump.
///
/// Several replicas may run this at once: the second waits for the first on
/// the revision row, then finds nothing, so one expiry is one bump. It does
/// not run the load checks: taking a row out cannot break them, and a tenant
/// whose data no longer loads must still lose an expired grant.
///
/// `tutelad` runs this on a timer. A product in library mode calls it
/// itself; until then an expired assignment already does not count, but the
/// revision does not move.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn expire_assignments(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Option<Expired>, StoreError> {
    crate::enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    // The usual answer is no. Find that out without taking a lock.
    let due: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM tutela.role_assignment WHERE tenant_id = $1 \
             AND expires_at IS NOT NULL AND expires_at <= clock_timestamp())",
            &[&tid],
        )
        .await
        .db()?
        .try_get(0)
        .db()?;
    if !due {
        return Ok(None);
    }
    tx.query_opt(
        "SELECT 1 FROM tutela.tenant_rev WHERE tenant_id = $1 FOR UPDATE",
        &[&tid],
    )
    .await
    .db()?
    .ok_or(StoreError::corrupt("tenant revision row"))?;
    let gone = tx
        .query(
            "WITH gone AS (DELETE FROM tutela.role_assignment a WHERE a.tenant_id = $1 \
             AND a.expires_at IS NOT NULL AND a.expires_at <= clock_timestamp() \
             RETURNING a.*) \
             SELECT a.id, a.principal_kind, a.principal_id, a.scope_kind, a.scope_id, \
             a.role_id, a.granted_by, a.created_at, a.expires_at, a.rev, g.key \
             FROM gone a LEFT JOIN tutela.\"group\" g ON a.principal_kind = 'group' \
             AND g.tenant_id = a.tenant_id AND g.id = a.principal_id ORDER BY a.id",
            &[&tid],
        )
        .await
        .db()?;
    if gone.is_empty() {
        return Ok(None);
    }
    let rev = tx
        .query_opt(
            "UPDATE tutela.tenant_rev SET rev = rev + 1 WHERE tenant_id = $1 RETURNING rev",
            &[&tid],
        )
        .await
        .db()?
        .ok_or(StoreError::corrupt("tenant revision row"))?
        .try_get(0)
        .db()?;
    Ok(Some(Expired {
        assignments: gone.iter().map(assignment_row).collect::<Result<_, _>>()?,
        rev: to_rev(rev)?,
    }))
}

/// Removes a principal from a tenant: its assignments and its group
/// memberships go in one revision (PERMISSION-MODEL.md 6.4). Call it in the
/// transaction that deletes the principal.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) when the principal has
/// neither, or a database error.
pub async fn remove_principal(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    who: &Principal,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let (kind, id) = principal_row(who)?;
    let assignments = tx
        .execute(
            "DELETE FROM tutela.role_assignment WHERE tenant_id = $1 \
             AND principal_kind = $2 AND principal_id = $3",
            &[&tid, &kind, &id],
        )
        .await
        .db()?;
    let memberships = tx
        .execute(
            "DELETE FROM tutela.group_member WHERE tenant_id = $1 \
             AND member_kind = $2 AND member_id = $3",
            &[&tid, &kind, &id],
        )
        .await
        .db()?;
    if assignments + memberships == 0 {
        return Err(StoreError::not_found("principal"));
    }
    finish_write(tx, tenant, rev).await
}

/// Removes a role assignment.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) or a database error.
pub async fn unassign(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &RuleId,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let gone = tx
        .execute(
            "DELETE FROM tutela.role_assignment WHERE tenant_id = $1 AND id = $2",
            &[&tenant.tid.to_string(), &id.as_str()],
        )
        .await
        .db()?;
    if gone == 0 {
        return Err(StoreError::not_found("assignment"));
    }
    finish_write(tx, tenant, rev).await
}

/// Makes a group in an org of the tenant. Group keys are unique in the
/// tenant (ADR-0013).
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an org of another tenant,
/// [`Exists`](crate::StoreErrorKind::Exists) for a key in use,
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a name over 256 characters
/// or with control characters, or a database error.
pub async fn create_group(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: &OrgId,
    key: &GroupKey,
    name: &str,
) -> Result<u64, StoreError> {
    if name.chars().count() > MAX_GROUP_NAME || name.chars().any(char::is_control) {
        return Err(StoreError::invalid(
            "a group name is at most 256 characters with no control characters",
        ));
    }
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    if tx
        .query_opt(
            "SELECT 1 FROM tutela.org WHERE tenant_id = $1 AND org_id = $2",
            &[&tid, &org.to_string()],
        )
        .await
        .db()?
        .is_none()
    {
        return Err(StoreError::not_found("org"));
    }
    if group_id(tx, &tid, key).await?.is_some() {
        return Err(StoreError::exists("a group with this key"));
    }
    let id = format!("grp_{}", uuid7()?);
    tx.execute(
        "INSERT INTO tutela.\"group\" (tenant_id, id, org_id, key, name) \
         VALUES ($1, $2, $3, $4, $5)",
        &[&tid, &id, &org.to_string(), &key.as_str(), &name],
    )
    .await
    .db()?;
    finish_write(tx, tenant, rev).await
}

/// Adds a direct member to a group: a principal or another group.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unknown group,
/// [`Exists`](crate::StoreErrorKind::Exists) if it is already a member,
/// [`Refused`](crate::StoreErrorKind::Refused) for a cycle, nesting deeper than
/// 32 or a closure over the limits, or a database error.
pub async fn add_member(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    group: &GroupKey,
    member: &Member,
    added_by: Option<&Principal>,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let gid = group_id(tx, &tid, group)
        .await?
        .ok_or(StoreError::not_found("group"))?;
    let (kind, id) = member_row(tx, &tid, member).await?;
    if tx
        .query_opt(
            "SELECT 1 FROM tutela.group_member WHERE tenant_id = $1 AND group_id = $2 \
             AND member_kind = $3 AND member_id = $4",
            &[&tid, &gid, &kind, &id],
        )
        .await
        .db()?
        .is_some()
    {
        return Err(StoreError::exists("this member of the group"));
    }
    tx.execute(
        "INSERT INTO tutela.group_member (tenant_id, group_id, member_kind, member_id, added_by) \
         VALUES ($1, $2, $3, $4, $5)",
        &[&tid, &gid, &kind, &id, &added_by.map(ToString::to_string)],
    )
    .await
    .db()?;
    finish_write(tx, tenant, rev).await
}

/// Removes a direct member from a group.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) or a database error.
pub async fn remove_member(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    group: &GroupKey,
    member: &Member,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let gid = group_id(tx, &tid, group)
        .await?
        .ok_or(StoreError::not_found("group"))?;
    let (kind, id) = member_row(tx, &tid, member).await?;
    let gone = tx
        .execute(
            "DELETE FROM tutela.group_member WHERE tenant_id = $1 AND group_id = $2 \
             AND member_kind = $3 AND member_id = $4",
            &[&tid, &gid, &kind, &id],
        )
        .await
        .db()?;
    if gone == 0 {
        return Err(StoreError::not_found("member"));
    }
    finish_write(tx, tenant, rev).await
}

/// Deletes a group, with its assignments, its members and its places in
/// other groups, in one revision. A condition that names the group is then
/// false (an unknown group fails closed).
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) or a database error.
pub async fn delete_group(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    group: &GroupKey,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let gid = group_id(tx, &tid, group)
        .await?
        .ok_or(StoreError::not_found("group"))?;
    tx.execute(
        "DELETE FROM tutela.role_assignment WHERE tenant_id = $1 AND principal_kind = 'group' \
         AND principal_id = $2",
        &[&tid, &gid],
    )
    .await
    .db()?;
    tx.execute(
        "DELETE FROM tutela.group_member WHERE tenant_id = $1 AND member_kind = 'group' \
         AND member_id = $2",
        &[&tid, &gid],
    )
    .await
    .db()?;
    tx.execute(
        "DELETE FROM tutela.\"group\" WHERE tenant_id = $1 AND id = $2",
        &[&tid, &gid],
    )
    .await
    .db()?;
    finish_write(tx, tenant, rev).await
}

/// Registers a scope of the product's tree: its ancestors (nearest first,
/// ending at an org of the tenant) and whether it is private. The private
/// flag is written in the same transaction as the scope and the revision
/// bump (ADR-0013), so a scope is never open, even for a moment, when it
/// should be private. Call it in the transaction that makes the scope in the
/// product's own tables, with the private flag from the type's `starts`.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a path that breaks a rule or
/// disagrees with a registered ancestor,
/// [`Exists`](crate::StoreErrorKind::Exists) if the scope is registered, or a
/// database error.
pub async fn put_scope(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
    ancestors: &[PathEntry],
    private: bool,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    check_path(tx, &tid, scope, ancestors).await?;
    if path_of(tx, &tid, scope).await?.is_some() {
        return Err(StoreError::exists("a registered scope"));
    }
    let texts: Vec<String> = ancestors.iter().map(entry_text).collect();
    tx.execute(
        "INSERT INTO tutela.scope_path (tenant_id, scope_kind, scope_id, ancestors) \
         VALUES ($1, $2, $3, $4)",
        &[&tid, &scope.type_name.as_str(), &scope.id.as_str(), &texts],
    )
    .await
    .db()?;
    if private {
        write_private(tx, &tid, scope, true, rev).await?;
    }
    finish_write(tx, tenant, rev).await
}

/// Sets or clears the private flag of a registered scope.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unregistered scope, or
/// a database error.
pub async fn set_private(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
    private: bool,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    require_scope(tx, &tid, scope).await?;
    if scope.is_org() {
        return Err(StoreError::invalid("an org is never private"));
    }
    write_private(tx, &tid, scope, private, rev).await?;
    finish_write(tx, tenant, rev).await
}

/// Moves a registered scope under new ancestors. The scope and every
/// registered scope below it get their new paths in the caller's
/// transaction, with the revision bump, so `list_filter` sees the move at
/// once. Call it in the transaction that changes the parent in the
/// product's own tables.
///
/// This only keeps the paths current. Whether the move is allowed is the
/// product's check; `Pdp::write_check` refuses moves until boundary rules
/// exist (ADR-0014).
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unregistered scope,
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a path that breaks a rule,
/// puts the scope under itself, or makes a path below it longer than 32, or a
/// database error.
pub async fn move_scope(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
    ancestors: &[PathEntry],
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    if scope.is_org() {
        return Err(StoreError::invalid("an org has no parent"));
    }
    require_scope(tx, &tid, scope).await?;
    check_path(tx, &tid, scope, ancestors).await?;
    let me = entry_text(scope);
    // A scope below keeps its path up to and including this scope (`pos`
    // entries) and gets the new ancestors after it, so its new length is
    // `pos + ancestors.len()`. Check the longest before writing.
    let longest = tx
        .query_one(
            "SELECT coalesce(max(array_position(ancestors, $2)), 0)::bigint \
             FROM tutela.scope_path WHERE tenant_id = $1 AND $2 = ANY(ancestors)",
            &[&tid, &me],
        )
        .await
        .db()?
        .try_get::<_, i64>(0)
        .db()?;
    let longest = usize::try_from(longest).map_err(|_| StoreError::corrupt("path length"))?;
    if longest + ancestors.len() > MAX_PATH {
        return Err(StoreError::invalid(
            "after the move a scope below would have more than 32 ancestors",
        ));
    }
    let texts: Vec<String> = ancestors.iter().map(entry_text).collect();
    tx.execute(
        "UPDATE tutela.scope_path SET ancestors = ancestors[1:array_position(ancestors, $2)] || $3::text[] \
         WHERE tenant_id = $1 AND $2 = ANY(ancestors)",
        &[&tid, &me, &texts],
    )
    .await.db()?;
    tx.execute(
        "UPDATE tutela.scope_path SET ancestors = $4 \
         WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3",
        &[&tid, &scope.type_name.as_str(), &scope.id.as_str(), &texts],
    )
    .await
    .db()?;
    finish_write(tx, tenant, rev).await
}

/// Deletes a registered scope and every registered scope below it, with
/// their assignments, field rules, private flags and paths, in one
/// revision (ADR-0013: a deleted scope leaves the tenant data in the same
/// revision). Call it in the transaction that deletes the product's rows.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unregistered scope, or
/// a database error.
pub async fn delete_scope(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    if scope.is_org() {
        return Err(StoreError::invalid(
            "an org is not deleted through the store",
        ));
    }
    require_scope(tx, &tid, scope).await?;
    let me = entry_text(scope);
    let mut kinds = vec![scope.type_name.to_string()];
    let mut ids = vec![scope.id.to_string()];
    for r in tx
        .query(
            "SELECT scope_kind, scope_id FROM tutela.scope_path \
             WHERE tenant_id = $1 AND $2 = ANY(ancestors)",
            &[&tid, &me],
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
    finish_write(tx, tenant, rev).await
}

/// Sets the cap of `field` for `role` (or all roles) at a registered scope,
/// replacing any rule for the same (scope, field, role). The new rule gets a
/// new id. Org-root rules come from the manifest, never from here.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) at an org root,
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unregistered scope, or
/// a database error.
pub async fn put_field_rule(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
    field: &FieldKey,
    role: Option<&RoleKey>,
    max: Level,
    created_by: Option<&Principal>,
) -> Result<(RuleId, u64), StoreError> {
    if scope.is_org() {
        return Err(StoreError::invalid(
            "org-root field rules come from the manifest",
        ));
    }
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    require_scope(tx, &tid, scope).await?;
    let role_text = role.map(RoleKey::as_str);
    tx.execute(
        "DELETE FROM tutela.field_rule WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3 \
         AND field_key = $4 AND coalesce(role_id, '') = coalesce($5, '')",
        &[
            &tid,
            &scope.type_name.as_str(),
            &scope.id.as_str(),
            &field.to_string(),
            &role_text,
        ],
    )
    .await
    .db()?;
    let rule = new_rule_id("fr")?;
    tx.execute(
        "INSERT INTO tutela.field_rule (tenant_id, id, scope_kind, scope_id, item_type, field_key, \
         role_id, max_level, created_by, rev) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &tid,
            &rule.as_str(),
            &scope.type_name.as_str(),
            &scope.id.as_str(),
            &field.resource_type().as_str(),
            &field.to_string(),
            &role_text,
            &max.as_str(),
            &created_by.map(ToString::to_string),
            &db_rev(rev)?,
        ],
    )
    .await
    .db()?;
    Ok((rule, finish_write(tx, tenant, rev).await?))
}

/// Deletes a field rule.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) or a database error.
pub async fn delete_field_rule(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &RuleId,
) -> Result<u64, StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let gone = tx
        .execute(
            "DELETE FROM tutela.field_rule WHERE tenant_id = $1 AND id = $2",
            &[&tenant.tid.to_string(), &id.as_str()],
        )
        .await
        .db()?;
    if gone == 0 {
        return Err(StoreError::not_found("field rule"));
    }
    finish_write(tx, tenant, rev).await
}

// ---------- helpers ----------

fn db_rev(rev: u64) -> Result<i64, StoreError> {
    i64::try_from(rev).map_err(|_| StoreError::rev_out_of_range())
}

async fn write_private(
    tx: &Transaction<'_>,
    tid: &str,
    scope: &PathEntry,
    private: bool,
    rev: u64,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO tutela.boundary_rule (tenant_id, scope_kind, scope_id, private, rev) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, scope_kind, scope_id) \
         DO UPDATE SET private = excluded.private, rev = excluded.rev",
        &[
            &tid,
            &scope.type_name.as_str(),
            &scope.id.as_str(),
            &private,
            &db_rev(rev)?,
        ],
    )
    .await
    .db()?;
    Ok(())
}

/// The registered path of a scope, if any.
async fn path_of(
    tx: &Transaction<'_>,
    tid: &str,
    scope: &PathEntry,
) -> Result<Option<Vec<PathEntry>>, StoreError> {
    let Some(row) = tx
        .query_opt(
            "SELECT ancestors FROM tutela.scope_path \
             WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3",
            &[&tid, &scope.type_name.as_str(), &scope.id.as_str()],
        )
        .await
        .db()?
    else {
        return Ok(None);
    };
    let texts: Vec<&str> = row.try_get(0).db()?;
    texts
        .into_iter()
        .map(parse_entry)
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// An org of this tenant, or a registered scope.
async fn require_scope(
    tx: &Transaction<'_>,
    tid: &str,
    scope: &PathEntry,
) -> Result<(), StoreError> {
    if scope.is_org() {
        let org = scope
            .org_id()
            .ok_or(StoreError::invalid("an org scope needs an org id"))?;
        let found = tx
            .query_opt(
                "SELECT 1 FROM tutela.org WHERE tenant_id = $1 AND org_id = $2",
                &[&tid, &org.to_string()],
            )
            .await
            .db()?;
        return found.map(|_| ()).ok_or(StoreError::not_found("org"));
    }
    path_of(tx, tid, scope)
        .await?
        .map(|_| ())
        .ok_or(StoreError::not_found("registered scope"))
}

/// The rules of a scope path (CONTRACTS.md 6.5): 1 to 32 entries, nearest
/// first; the last is an org of this tenant and no other entry is an org; no
/// entry twice and not the scope itself; and every registered ancestor has
/// exactly the rest of this path as its own path.
async fn check_path(
    tx: &Transaction<'_>,
    tid: &str,
    scope: &PathEntry,
    ancestors: &[PathEntry],
) -> Result<(), StoreError> {
    if scope.is_org() {
        return Err(StoreError::invalid("an org is not a registered scope"));
    }
    let Some((last, rest)) = ancestors.split_last() else {
        return Err(StoreError::invalid("a path ends at an org"));
    };
    if ancestors.len() > MAX_PATH {
        return Err(StoreError::invalid("a path has at most 32 entries"));
    }
    if !last.is_org() || rest.iter().any(PathEntry::is_org) {
        return Err(StoreError::invalid("a path ends at an org, and only there"));
    }
    let mut seen = BTreeSet::from([scope]);
    if !ancestors.iter().all(|e| seen.insert(e)) {
        return Err(StoreError::invalid(
            "a path holds no entry twice and not the scope itself",
        ));
    }
    require_scope(tx, tid, last).await?;
    for (i, a) in rest.iter().enumerate() {
        if let Some(theirs) = path_of(tx, tid, a).await? {
            let ours = ancestors.get(i + 1..).unwrap_or_default();
            if theirs != ours {
                return Err(StoreError::invalid(
                    "the path disagrees with a registered ancestor's path",
                ));
            }
            if theirs.contains(scope) {
                return Err(StoreError::invalid("a scope cannot sit under itself"));
            }
        }
    }
    Ok(())
}

pub(crate) async fn group_id(
    tx: &Transaction<'_>,
    tid: &str,
    key: &GroupKey,
) -> Result<Option<String>, StoreError> {
    tx.query_opt(
        "SELECT id FROM tutela.\"group\" WHERE tenant_id = $1 AND key = $2",
        &[&tid, &key.as_str()],
    )
    .await
    .db()?
    .map(|r| r.try_get(0))
    .transpose()
    .db()
}

/// (kind, id) of a principal, as stored.
pub(crate) fn principal_row(p: &Principal) -> Result<(String, String), StoreError> {
    let text = p.to_string();
    let (kind, id) = text
        .split_once(':')
        .ok_or(StoreError::corrupt("principal"))?;
    Ok((kind.to_owned(), id.to_owned()))
}

pub(crate) async fn subject_row(
    tx: &Transaction<'_>,
    tid: &str,
    subject: &Subject,
) -> Result<(String, String), StoreError> {
    match subject {
        Subject::Principal(p) => principal_row(p),
        Subject::Group(k) => Ok((
            "group".to_owned(),
            group_id(tx, tid, k)
                .await?
                .ok_or(StoreError::not_found("group"))?,
        )),
    }
}

async fn member_row(
    tx: &Transaction<'_>,
    tid: &str,
    member: &Member,
) -> Result<(String, String), StoreError> {
    match member {
        Member::Principal(p) => principal_row(p),
        Member::Group(k) => Ok((
            "group".to_owned(),
            group_id(tx, tid, k)
                .await?
                .ok_or(StoreError::not_found("member group"))?,
        )),
    }
}
