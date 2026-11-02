//! Reading a tenant: its revision, [`TenantData`] and scope paths.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use tokio_postgres::Transaction;
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::{GroupKey, RoleKey};
use tutela_pdp::{
    Binding, Group, Member, PathEntry, ScopeFieldRule, ScopePathError, ScopePaths, Subject,
    TenantData,
};

use crate::{DbResult as _, StoreError, enter, entry, parse_entry, parse_org, to_rev};

/// A tenant at one revision: what [`tutela_pdp::Pdp::load`] needs, and the
/// scope paths for [`tutela_pdp::Pdp::list_filter`].
#[derive(Clone, Debug)]
pub struct TenantBundle {
    /// The tenant revision this view was read at.
    pub rev: u64,
    /// The tenant data.
    pub data: TenantData,
    /// The scope paths, read in the same view.
    pub paths: ScopePathSnapshot,
}

/// The registered scope paths of one tenant at one revision. It answers
/// only for its own tenant, and only for registered scopes; anything else is
/// [`ScopePathError::NotFound`], so `list_filter` fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopePathSnapshot {
    tenant: TenantKey,
    paths: HashMap<PathEntry, Vec<PathEntry>>,
}

impl ScopePathSnapshot {
    /// The number of registered scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// `true` if no scope is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

impl ScopePaths for ScopePathSnapshot {
    fn ancestors(
        &self,
        tenant: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        if *tenant != self.tenant {
            return Err(ScopePathError::NotFound);
        }
        self.paths
            .get(scope)
            .cloned()
            .ok_or(ScopePathError::NotFound)
    }

    /// Complete by construction: every registered scope of the tenant whose
    /// path holds one of `scopes`.
    fn below(
        &self,
        tenant: &TenantKey,
        scopes: &[PathEntry],
    ) -> Option<Result<Vec<PathEntry>, ScopePathError>> {
        if *tenant != self.tenant {
            return Some(Err(ScopePathError::NotFound));
        }
        Some(Ok(self
            .paths
            .iter()
            .filter(|(_, path)| path.iter().any(|a| scopes.contains(a)))
            .map(|(s, _)| s.clone())
            .collect()))
    }
}

/// The tenant's current revision.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) for an unknown (iss,
/// tid), or a database error.
pub async fn rev(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<u64, StoreError> {
    enter(tx, tenant).await?;
    read_rev(tx, tenant, false).await
}

/// Reads a tenant in one consistent view. It first takes a share lock on
/// the tenant's revision row, so it waits for a write in progress and no
/// write commits until the caller's transaction ends.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), a database error,
/// or [`Corrupt`](crate::StoreErrorKind::Corrupt) if a stored value does not
/// parse.
pub async fn load(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<TenantBundle, StoreError> {
    enter(tx, tenant).await?;
    let rev = read_rev(tx, tenant, true).await?;
    let data = tenant_data(tx, tenant).await?;
    let paths = scope_paths(tx, tenant).await?;
    Ok(TenantBundle { rev, data, paths })
}

async fn read_rev(tx: &Transaction<'_>, tenant: &TenantKey, lock: bool) -> Result<u64, StoreError> {
    let sql = if lock {
        "SELECT rev FROM tutela.tenant_rev WHERE tenant_id = $1 FOR SHARE"
    } else {
        "SELECT rev FROM tutela.tenant_rev WHERE tenant_id = $1"
    };
    let row = tx
        .query_opt(sql, &[&tenant.tid.to_string()])
        .await
        .db()?
        .ok_or(StoreError::corrupt("tenant revision row"))?;
    to_rev(row.try_get(0).db()?)
}

/// The tenant data. The caller has entered the tenant. Every query names the
/// tenant as well, on top of row-level security.
pub(crate) async fn tenant_data(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<TenantData, StoreError> {
    let tid = tenant.tid.to_string();
    let mut data = TenantData::default();

    for r in tx
        .query(
            "SELECT org_id FROM tutela.org WHERE tenant_id = $1",
            &[&tid],
        )
        .await
        .db()?
    {
        data.orgs.insert(parse_org(r.try_get(0).db()?)?);
    }

    // Groups: ids to keys, then the members.
    let mut keys: BTreeMap<String, GroupKey> = BTreeMap::new();
    for r in tx
        .query(
            "SELECT id, key FROM tutela.\"group\" WHERE tenant_id = $1 ORDER BY id",
            &[&tid],
        )
        .await
        .db()?
    {
        let key =
            GroupKey::parse(r.try_get(1).db()?).map_err(|_| StoreError::corrupt("group key"))?;
        keys.insert(r.try_get(0).db()?, key);
    }
    let mut members: BTreeMap<String, Vec<Member>> = BTreeMap::new();
    for r in tx
        .query(
            "SELECT group_id, member_kind, member_id FROM tutela.group_member \
             WHERE tenant_id = $1 ORDER BY group_id, member_kind, member_id",
            &[&tid],
        )
        .await
        .db()?
    {
        let group: String = r.try_get(0).db()?;
        let kind: &str = r.try_get(1).db()?;
        let id: &str = r.try_get(2).db()?;
        let m = if kind == "group" {
            Member::Group(
                keys.get(id)
                    .cloned()
                    .ok_or(StoreError::corrupt("member group"))?,
            )
        } else {
            Member::Principal(principal(kind, id)?)
        };
        members.entry(group).or_default().push(m);
    }
    data.groups = keys
        .iter()
        .map(|(id, key)| Group {
            key: key.clone(),
            members: members.remove(id).unwrap_or_default(),
        })
        .collect();

    // Assignments with an expiry are not read: expiry needs a revision bump
    // when it passes, which comes with Phase B (ADR-0014). Ignoring them
    // fails closed.
    for r in tx
        .query(
            "SELECT id, principal_kind, principal_id, scope_kind, scope_id, role_id \
             FROM tutela.role_assignment WHERE tenant_id = $1 AND expires_at IS NULL \
             ORDER BY created_at, id",
            &[&tid],
        )
        .await
        .db()?
    {
        let kind: &str = r.try_get(1).db()?;
        let id: &str = r.try_get(2).db()?;
        let subject = if kind == "group" {
            Subject::Group(
                keys.get(id)
                    .cloned()
                    .ok_or(StoreError::corrupt("assigned group"))?,
            )
        } else {
            Subject::Principal(principal(kind, id)?)
        };
        data.bindings.push(Binding {
            id: r
                .try_get::<_, &str>(0)
                .db()?
                .parse()
                .map_err(|_| StoreError::corrupt("assignment id"))?,
            subject,
            role: RoleKey::parse(r.try_get(5).db()?).map_err(|_| StoreError::corrupt("role"))?,
            scope: entry(r.try_get(3).db()?, r.try_get(4).db()?)?,
        });
    }

    let mut private = BTreeSet::new();
    for r in tx
        .query(
            "SELECT scope_kind, scope_id FROM tutela.boundary_rule \
             WHERE tenant_id = $1 AND private",
            &[&tid],
        )
        .await
        .db()?
    {
        private.insert(entry(r.try_get(0).db()?, r.try_get(1).db()?)?);
    }
    data.private_scopes = private;

    for r in tx
        .query(
            "SELECT id, scope_kind, scope_id, field_key, role_id, max_level \
             FROM tutela.field_rule WHERE tenant_id = $1 ORDER BY created_at, id",
            &[&tid],
        )
        .await
        .db()?
    {
        let role: Option<&str> = r.try_get(4).db()?;
        data.field_rules.push(ScopeFieldRule {
            id: r
                .try_get::<_, &str>(0)
                .db()?
                .parse()
                .map_err(|_| StoreError::corrupt("field rule id"))?,
            scope: entry(r.try_get(1).db()?, r.try_get(2).db()?)?,
            field: r
                .try_get::<_, &str>(3)
                .db()?
                .parse()
                .map_err(|_| StoreError::corrupt("field key"))?,
            role: role
                .map(RoleKey::parse)
                .transpose()
                .map_err(|_| StoreError::corrupt("role"))?,
            max: r
                .try_get::<_, &str>(5)
                .db()?
                .parse::<Level>()
                .map_err(|_| StoreError::corrupt("level"))?,
        });
    }
    Ok(data)
}

async fn scope_paths(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<ScopePathSnapshot, StoreError> {
    let mut paths = HashMap::new();
    for r in tx
        .query(
            "SELECT scope_kind, scope_id, ancestors FROM tutela.scope_path WHERE tenant_id = $1",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?
    {
        let ancestors: Vec<&str> = r.try_get(2).db()?;
        let path = ancestors
            .into_iter()
            .map(parse_entry)
            .collect::<Result<Vec<_>, _>>()?;
        paths.insert(entry(r.try_get(0).db()?, r.try_get(1).db()?)?, path);
    }
    Ok(ScopePathSnapshot {
        tenant: tenant.clone(),
        paths,
    })
}

/// A principal from its stored kind and id.
pub(crate) fn principal(kind: &str, id: &str) -> Result<Principal, StoreError> {
    format!("{kind}:{id}")
        .parse()
        .map_err(|_| StoreError::corrupt("principal"))
}
