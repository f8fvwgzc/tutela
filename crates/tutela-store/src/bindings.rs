//! Reading role assignments and groups, and the group and path closures.
//!
//! The closures are computed at read time (ADR-0020): a group closure is a
//! recursive query over `group_member`, and a path is one read of
//! `scope_path`. There is no closure table to keep current.

use std::collections::BTreeSet;
use std::time::SystemTime;

use tokio_postgres::Transaction;
use tokio_postgres::types::ToSql;
use tutela_contracts::decision::RuleId;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{OrgId, TenantId, TenantKey};
use tutela_pdp::model::{GroupKey, RoleKey};
use tutela_pdp::{Member, PathEntry, Subject};

use crate::load::principal;
use crate::write::{group_id, principal_row, subject_row};
use crate::{DbResult as _, StoreError, enter, entry, entry_text, parse_entry, parse_org, to_rev};

/// The most rows one page of [`assignments`] returns.
pub const MAX_PAGE: usize = 1000;

/// One role assignment, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Its id.
    pub id: RuleId,
    /// Who it is for.
    pub subject: Subject,
    /// The role.
    pub role: RoleKey,
    /// Where it applies.
    pub scope: PathEntry,
    /// Who granted it.
    pub granted_by: Option<Principal>,
    /// When it was made.
    pub created_at: SystemTime,
    /// When it ends, if it does.
    pub expires_at: Option<SystemTime>,
    /// The tenant revision it was made at.
    pub rev: u64,
}

/// One group, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    /// The key, unique in the tenant.
    pub key: GroupKey,
    /// The org it belongs to.
    pub org: OrgId,
    /// The display name.
    pub name: String,
    /// When it was made.
    pub created_at: SystemTime,
}

/// What [`assignments`] returns. Everything is optional; a page is ordered
/// by id, so `after` is the last id of the page before.
#[derive(Clone, Copy, Debug, Default)]
pub struct AssignmentQuery<'a> {
    /// Only this subject.
    pub subject: Option<&'a Subject>,
    /// Only at this scope.
    pub scope: Option<&'a PathEntry>,
    /// Only ids after this one.
    pub after: Option<&'a RuleId>,
    /// The page size: at most [`MAX_PAGE`], which is also the default.
    pub limit: Option<usize>,
}

/// The columns of an [`Assignment`], with the group's key for a group.
const ASSIGNMENT: &str = "a.id, a.principal_kind, a.principal_id, a.scope_kind, a.scope_id, \
     a.role_id, a.granted_by, a.created_at, a.expires_at, a.rev, g.key";

/// The rows of [`ASSIGNMENT`] that still count: not past their expiry.
const LIVE: &str = "(a.expires_at IS NULL OR a.expires_at > clock_timestamp())";

/// An assignment row from the columns of [`ASSIGNMENT`].
pub(crate) fn assignment_row(r: &tokio_postgres::Row) -> Result<Assignment, StoreError> {
    let kind: &str = r.try_get(1).db()?;
    let id: &str = r.try_get(2).db()?;
    let subject = if kind == "group" {
        let key: Option<&str> = r.try_get(10).db()?;
        let key = key.ok_or(StoreError::corrupt("assigned group"))?;
        Subject::Group(GroupKey::parse(key).map_err(|_| StoreError::corrupt("group key"))?)
    } else {
        Subject::Principal(principal(kind, id)?)
    };
    let granted: Option<&str> = r.try_get(6).db()?;
    Ok(Assignment {
        id: r
            .try_get::<_, &str>(0)
            .db()?
            .parse()
            .map_err(|_| StoreError::corrupt("assignment id"))?,
        subject,
        role: RoleKey::parse(r.try_get(5).db()?).map_err(|_| StoreError::corrupt("role"))?,
        scope: entry(r.try_get(3).db()?, r.try_get(4).db()?)?,
        granted_by: granted
            .map(str::parse)
            .transpose()
            .map_err(|_| StoreError::corrupt("granted by"))?,
        created_at: r.try_get(7).db()?,
        expires_at: r.try_get(8).db()?,
        rev: to_rev(r.try_get(9).db()?)?,
    })
}

/// The assignments that still count, ordered by id, one page at a time. An
/// assignment past its expiry is not returned, even before
/// [`expire_assignments`](crate::expire_assignments) has removed it.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unknown group
/// subject, [`Invalid`](crate::StoreErrorKind::Invalid) for a limit over
/// [`MAX_PAGE`] or of 0, or a database error.
pub async fn assignments(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    query: &AssignmentQuery<'_>,
) -> Result<Vec<Assignment>, StoreError> {
    enter(tx, tenant).await?;
    let limit = query.limit.unwrap_or(MAX_PAGE);
    if limit == 0 || limit > MAX_PAGE {
        return Err(StoreError::invalid("a page is 1 to 1000 rows"));
    }
    let limit =
        i64::try_from(limit).map_err(|_| StoreError::invalid("a page is 1 to 1000 rows"))?;
    let tid = tenant.tid.to_string();
    let subject = match query.subject {
        Some(s) => Some(subject_row(tx, &tid, s).await?),
        None => None,
    };
    let (kind, id) = subject.map_or((None, None), |(k, i)| (Some(k), Some(i)));
    let (scope_kind, scope_id) = query.scope.map_or((None, None), |s| {
        (Some(s.type_name.as_str()), Some(s.id.as_str()))
    });
    let after = query.after.map(RuleId::as_str);
    let sql = format!(
        "SELECT {ASSIGNMENT} FROM tutela.role_assignment a \
         LEFT JOIN tutela.\"group\" g ON a.principal_kind = 'group' \
         AND g.tenant_id = a.tenant_id AND g.id = a.principal_id \
         WHERE a.tenant_id = $1 AND {LIVE} \
         AND ($2::text IS NULL OR (a.principal_kind = $2 AND a.principal_id = $3)) \
         AND ($4::text IS NULL OR (a.scope_kind = $4 AND a.scope_id = $5)) \
         AND ($6::text IS NULL OR a.id > $6) \
         ORDER BY a.id LIMIT $7"
    );
    let params: [&(dyn ToSql + Sync); 7] =
        [&tid, &kind, &id, &scope_kind, &scope_id, &after, &limit];
    tx.query(&sql, &params)
        .await
        .db()?
        .iter()
        .map(assignment_row)
        .collect()
}

/// One assignment by id, while it still counts.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) or a database error.
pub async fn assignment(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &RuleId,
) -> Result<Assignment, StoreError> {
    enter(tx, tenant).await?;
    let sql = format!(
        "SELECT {ASSIGNMENT} FROM tutela.role_assignment a \
         LEFT JOIN tutela.\"group\" g ON a.principal_kind = 'group' \
         AND g.tenant_id = a.tenant_id AND g.id = a.principal_id \
         WHERE a.tenant_id = $1 AND a.id = $2 AND {LIVE}"
    );
    let row = tx
        .query_opt(&sql, &[&tenant.tid.to_string(), &id.as_str()])
        .await
        .db()?
        .ok_or(StoreError::not_found("assignment"))?;
    assignment_row(&row)
}

/// Every assignment that applies to `who`: its own, and those of every group
/// it is in, directly or through other groups.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn assignments_for(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    who: &Principal,
) -> Result<Vec<Assignment>, StoreError> {
    enter(tx, tenant).await?;
    let (kind, id) = principal_row(who)?;
    let sql = format!(
        "WITH RECURSIVE up(group_id) AS ({UP}) \
         SELECT {ASSIGNMENT} FROM tutela.role_assignment a \
         LEFT JOIN tutela.\"group\" g ON a.principal_kind = 'group' \
         AND g.tenant_id = a.tenant_id AND g.id = a.principal_id \
         WHERE a.tenant_id = $1 AND {LIVE} AND ((a.principal_kind = $2 AND a.principal_id = $3) \
         OR (a.principal_kind = 'group' AND a.principal_id IN (SELECT group_id FROM up))) \
         ORDER BY a.id"
    );
    tx.query(&sql, &[&tenant.tid.to_string(), &kind, &id])
        .await
        .db()?
        .iter()
        .map(assignment_row)
        .collect()
}

/// The groups of a tenant, ordered by key.
///
/// # Errors
///
/// A database error.
pub async fn groups(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Vec<GroupInfo>, StoreError> {
    enter(tx, tenant).await?;
    tx.query(
        "SELECT key, org_id, name, created_at FROM tutela.\"group\" \
         WHERE tenant_id = $1 ORDER BY key",
        &[&tenant.tid.to_string()],
    )
    .await
    .db()?
    .iter()
    .map(|r| {
        Ok(GroupInfo {
            key: GroupKey::parse(r.try_get(0).db()?)
                .map_err(|_| StoreError::corrupt("group key"))?,
            org: parse_org(r.try_get(1).db()?)?,
            name: r.try_get(2).db()?,
            created_at: r.try_get(3).db()?,
        })
    })
    .collect()
}

/// The direct members of a group.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unknown group, or a
/// database error.
pub async fn group_members(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    group: &GroupKey,
) -> Result<Vec<Member>, StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let gid = group_id(tx, &tid, group)
        .await?
        .ok_or(StoreError::not_found("group"))?;
    tx.query(
        "SELECT m.member_kind, m.member_id, g.key FROM tutela.group_member m \
         LEFT JOIN tutela.\"group\" g ON m.member_kind = 'group' \
         AND g.tenant_id = m.tenant_id AND g.id = m.member_id \
         WHERE m.tenant_id = $1 AND m.group_id = $2 ORDER BY m.member_kind, m.member_id",
        &[&tid, &gid],
    )
    .await
    .db()?
    .iter()
    .map(|r| {
        let kind: &str = r.try_get(0).db()?;
        if kind == "group" {
            let key: Option<&str> = r.try_get(2).db()?;
            let key = key.ok_or(StoreError::corrupt("member group"))?;
            Ok(Member::Group(
                GroupKey::parse(key).map_err(|_| StoreError::corrupt("group key"))?,
            ))
        } else {
            Ok(Member::Principal(principal(kind, r.try_get(1).db()?)?))
        }
    })
    .collect()
}

/// The start of the walk up the group tree from `($2, $3)`. It needs `$1`,
/// the tenant. `UNION` ends a walk even if a cycle got into the table.
const UP: &str = "SELECT group_id FROM tutela.group_member \
     WHERE tenant_id = $1 AND member_kind = $2 AND member_id = $3 \
     UNION \
     SELECT m.group_id FROM tutela.group_member m JOIN up ON m.member_id = up.group_id \
     WHERE m.tenant_id = $1 AND m.member_kind = 'group'";

/// The group closure, up: every group `who` is in, directly or through
/// other groups.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn groups_of(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    who: &Principal,
) -> Result<BTreeSet<GroupKey>, StoreError> {
    enter(tx, tenant).await?;
    let (kind, id) = principal_row(who)?;
    let sql = format!(
        "WITH RECURSIVE up(group_id) AS ({UP}) \
         SELECT g.key FROM up JOIN tutela.\"group\" g \
         ON g.tenant_id = $1 AND g.id = up.group_id"
    );
    tx.query(&sql, &[&tenant.tid.to_string(), &kind, &id])
        .await
        .db()?
        .iter()
        .map(|r| GroupKey::parse(r.try_get(0).db()?).map_err(|_| StoreError::corrupt("group key")))
        .collect()
}

/// The group closure, down: every principal in a group, directly or through
/// other groups.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unknown group, or a
/// database error.
pub async fn members_of(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    group: &GroupKey,
) -> Result<BTreeSet<Principal>, StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let gid = group_id(tx, &tid, group)
        .await?
        .ok_or(StoreError::not_found("group"))?;
    tx.query(
        "WITH RECURSIVE down(kind, id) AS ( \
           SELECT member_kind, member_id FROM tutela.group_member \
           WHERE tenant_id = $1 AND group_id = $2 \
           UNION \
           SELECT m.member_kind, m.member_id FROM tutela.group_member m \
           JOIN down ON down.kind = 'group' AND m.group_id = down.id \
           WHERE m.tenant_id = $1) \
         SELECT kind, id FROM down WHERE kind <> 'group'",
        &[&tid, &gid],
    )
    .await
    .db()?
    .iter()
    .map(|r| principal(r.try_get(0).db()?, r.try_get(1).db()?))
    .collect()
}

/// The path closure, up: the ancestors of a registered scope, nearest
/// first, ending at its org. `None` for a scope that is not registered.
///
/// # Errors
///
/// [`Corrupt`](crate::StoreErrorKind::Corrupt) for a stored path that does
/// not parse, or a database error.
pub async fn ancestors(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
) -> Result<Option<Vec<PathEntry>>, StoreError> {
    enter(tx, tenant).await?;
    let Some(row) = tx
        .query_opt(
            "SELECT ancestors FROM tutela.scope_path \
             WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3",
            &[
                &tenant.tid.to_string(),
                &scope.type_name.as_str(),
                &scope.id.as_str(),
            ],
        )
        .await
        .db()?
    else {
        return Ok(None);
    };
    let path: Vec<&str> = row.try_get(0).db()?;
    path.into_iter()
        .map(parse_entry)
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// The path closure, down: every registered scope below `scope`, which may
/// be an org.
///
/// # Errors
///
/// A database error.
pub async fn scopes_below(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    scope: &PathEntry,
) -> Result<Vec<PathEntry>, StoreError> {
    enter(tx, tenant).await?;
    tx.query(
        "SELECT scope_kind, scope_id FROM tutela.scope_path \
         WHERE tenant_id = $1 AND $2 = ANY(ancestors) ORDER BY scope_kind, scope_id",
        &[&tenant.tid.to_string(), &entry_text(scope)],
    )
    .await
    .db()?
    .iter()
    .map(|r| entry(r.try_get(0).db()?, r.try_get(1).db()?))
    .collect()
}

/// The tenants in the directory. It holds no tenant data, so this needs no
/// tenant. A job that serves every tenant enters each one in turn, in its
/// own transaction (ADR-0014).
///
/// # Errors
///
/// [`Corrupt`](crate::StoreErrorKind::Corrupt) or a database error.
pub async fn tenants(tx: &Transaction<'_>) -> Result<Vec<TenantKey>, StoreError> {
    tx.query(
        "SELECT tenant_id, iss FROM tutela.tenant WHERE deleted_at IS NULL ORDER BY tenant_id",
        &[],
    )
    .await
    .db()?
    .iter()
    .map(|r| {
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
        Ok(TenantKey::new(iss, tid))
    })
    .collect()
}

/// One group with the number of its direct members, for a page of groups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSummary {
    /// The group.
    pub group: GroupInfo,
    /// How many direct members it has: principals and groups.
    pub members: u64,
}

/// One page of the tenant's groups, by key, the number of direct members
/// with each; only the groups of `org` when it is given. `after` is the
/// last key of the page before.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a limit over
/// [`MAX_PAGE`] or of 0, or a database error.
pub async fn group_page(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    org: Option<&OrgId>,
    after: Option<&GroupKey>,
    limit: usize,
) -> Result<Vec<GroupSummary>, StoreError> {
    enter(tx, tenant).await?;
    let limit = page_limit(limit)?;
    let org = org.map(ToString::to_string);
    let after = after.map(GroupKey::as_str);
    tx.query(
        "SELECT g.key, g.org_id, g.name, g.created_at, \
         (SELECT count(*) FROM tutela.group_member m \
          WHERE m.tenant_id = g.tenant_id AND m.group_id = g.id) \
         FROM tutela.\"group\" g WHERE g.tenant_id = $1 \
         AND ($2::text IS NULL OR g.org_id = $2) AND ($3::text IS NULL OR g.key > $3) \
         ORDER BY g.key LIMIT $4",
        &[&tenant.tid.to_string(), &org, &after, &limit],
    )
    .await
    .db()?
    .iter()
    .map(|r| {
        let members: i64 = r.try_get(4).db()?;
        Ok(GroupSummary {
            group: GroupInfo {
                key: GroupKey::parse(r.try_get(0).db()?)
                    .map_err(|_| StoreError::corrupt("group key"))?,
                org: parse_org(r.try_get(1).db()?)?,
                name: r.try_get(2).db()?,
                created_at: r.try_get(3).db()?,
            },
            members: u64::try_from(members).map_err(|_| StoreError::corrupt("member count"))?,
        })
    })
    .collect()
}

/// One group by key.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) or a database error.
pub async fn group(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    key: &GroupKey,
) -> Result<GroupInfo, StoreError> {
    enter(tx, tenant).await?;
    let r = tx
        .query_opt(
            "SELECT key, org_id, name, created_at FROM tutela.\"group\" \
             WHERE tenant_id = $1 AND key = $2",
            &[&tenant.tid.to_string(), &key.as_str()],
        )
        .await
        .db()?
        .ok_or(StoreError::not_found("group"))?;
    Ok(GroupInfo {
        key: GroupKey::parse(r.try_get(0).db()?).map_err(|_| StoreError::corrupt("group key"))?,
        org: parse_org(r.try_get(1).db()?)?,
        name: r.try_get(2).db()?,
        created_at: r.try_get(3).db()?,
    })
}

/// One page of a group's direct members, by their text (`user:usr_…`,
/// `group:<key>`, ...); `after` is the text of the last member of the page
/// before.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unknown group,
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a limit over [`MAX_PAGE`]
/// or of 0, or a database error.
pub async fn group_member_page(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    group: &GroupKey,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<Member>, StoreError> {
    enter(tx, tenant).await?;
    let limit = page_limit(limit)?;
    let tid = tenant.tid.to_string();
    let gid = group_id(tx, &tid, group)
        .await?
        .ok_or(StoreError::not_found("group"))?;
    tx.query(
        "SELECT * FROM (SELECT m.member_kind, m.member_id, g.key, \
         CASE WHEN m.member_kind = 'group' THEN 'group:' || g.key \
         ELSE m.member_kind || ':' || m.member_id END AS label \
         FROM tutela.group_member m \
         LEFT JOIN tutela.\"group\" g ON m.member_kind = 'group' \
         AND g.tenant_id = m.tenant_id AND g.id = m.member_id \
         WHERE m.tenant_id = $1 AND m.group_id = $2) x \
         WHERE ($3::text IS NULL OR x.label COLLATE \"C\" > $3) \
         ORDER BY x.label COLLATE \"C\" LIMIT $4",
        &[&tid, &gid, &after, &limit],
    )
    .await
    .db()?
    .iter()
    .map(|r| {
        let kind: &str = r.try_get(0).db()?;
        if kind == "group" {
            let key: Option<&str> = r.try_get(2).db()?;
            let key = key.ok_or(StoreError::corrupt("member group"))?;
            Ok(Member::Group(
                GroupKey::parse(key).map_err(|_| StoreError::corrupt("group key"))?,
            ))
        } else {
            Ok(Member::Principal(principal(kind, r.try_get(1).db()?)?))
        }
    })
    .collect()
}

/// One registered scope, as the admin API shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeInfo {
    /// The scope.
    pub scope: PathEntry,
    /// Its ancestors, nearest first, ending at its org.
    pub ancestors: Vec<PathEntry>,
    /// `true` when it stops inheritance from above.
    pub private: bool,
    /// Its move and link rules.
    pub boundary: tutela_pdp::BoundaryRule,
}

/// One page of the registered scopes below `under` (an org or a registered
/// scope), by `type:id`, with their paths, private flags and rules. `after`
/// is the last scope of the page before. A scope of a deleted org is not
/// shown.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a limit over [`MAX_PAGE`]
/// or of 0, [`Corrupt`](crate::StoreErrorKind::Corrupt) for a stored value
/// that does not parse, or a database error.
pub async fn scope_page(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    under: &PathEntry,
    after: Option<&PathEntry>,
    limit: usize,
) -> Result<Vec<ScopeInfo>, StoreError> {
    enter(tx, tenant).await?;
    let limit = page_limit(limit)?;
    let after = after.map(entry_text);
    let rows = tx
        .query(
            "SELECT p.scope_kind, p.scope_id, p.ancestors, coalesce(b.private, false), \
             b.moves_out, b.moves_in, b.on_looser, b.links_from \
             FROM tutela.scope_path p LEFT JOIN tutela.boundary_rule b \
             ON b.tenant_id = p.tenant_id AND b.scope_kind = p.scope_kind \
             AND b.scope_id = p.scope_id \
             JOIN tutela.org o ON o.tenant_id = p.tenant_id \
             AND 'org:' || o.org_id = p.ancestors[array_length(p.ancestors, 1)] \
             AND o.deleted_at IS NULL \
             WHERE p.tenant_id = $1 AND $2 = ANY(p.ancestors) \
             AND ($3::text IS NULL OR (p.scope_kind || ':' || p.scope_id) COLLATE \"C\" > $3) \
             ORDER BY (p.scope_kind || ':' || p.scope_id) COLLATE \"C\" LIMIT $4",
            &[&tenant.tid.to_string(), &entry_text(under), &after, &limit],
        )
        .await
        .db()?;
    rows.iter()
        .map(|r| {
            let path: Vec<&str> = r.try_get(2).db()?;
            let rule = |i: usize| -> Result<Option<String>, StoreError> { r.try_get(i).db() };
            Ok(ScopeInfo {
                scope: entry(r.try_get(0).db()?, r.try_get(1).db()?)?,
                ancestors: path
                    .into_iter()
                    .map(parse_entry)
                    .collect::<Result<_, _>>()?,
                private: r.try_get(3).db()?,
                boundary: crate::load::boundary_of(
                    rule(4)?.as_deref(),
                    rule(5)?.as_deref(),
                    rule(6)?.as_deref(),
                    rule(7)?.as_deref(),
                )?,
            })
        })
        .collect()
}

fn page_limit(limit: usize) -> Result<i64, StoreError> {
    if limit == 0 || limit > MAX_PAGE {
        return Err(StoreError::invalid("a page is 1 to 1000 rows"));
    }
    i64::try_from(limit).map_err(|_| StoreError::invalid("a page is 1 to 1000 rows"))
}
