//! Reading a tenant: its revision, [`TenantData`] and scope paths.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::SystemTime;

use tokio_postgres::Transaction;
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::{GroupKey, RoleKey};
use tutela_pdp::{
    Binding, BoundaryRule, Group, LinksFrom, Member, MoveRule, OnLooser, PathEntry, ScopeFieldRule,
    ScopePathError, ScopePaths, Subject, TenantData,
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
    /// The earliest expiry among the assignments in `data`. This view is
    /// good until then: a cache must load again at this time, because the
    /// revision goes up only when a sweep runs (ADR-0020).
    pub next_expiry: Option<SystemTime>,
    /// The database's clock when this view was read. Measure `next_expiry`
    /// from here, not from a local clock that may disagree with it.
    pub read_at: SystemTime,
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
    /// A snapshot of `tenant` with no scope. It answers
    /// [`ScopePathError::NotFound`] for everything.
    #[must_use]
    pub fn empty(tenant: TenantKey) -> Self {
        Self {
            tenant,
            paths: HashMap::new(),
        }
    }

    /// Every registered scope and its ancestors, nearest first, in no
    /// order: what a signed bundle carries (ADR-0038).
    pub fn entries(&self) -> impl Iterator<Item = (&PathEntry, &Vec<PathEntry>)> {
        self.paths.iter()
    }

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
        // A filter can name thousands of scopes, and this runs over every
        // registered path.
        let scopes: HashSet<&PathEntry> = scopes.iter().collect();
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
    let gone = deleted_scopes(tx, tenant).await?;
    let (data, next_expiry) = tenant_view(tx, tenant, &gone).await?;
    let paths = scope_paths(tx, tenant, &gone).await?;
    let read_at = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .db()?
        .try_get(0)
        .db()?;
    Ok(TenantBundle {
        rev,
        data,
        paths,
        next_expiry,
        read_at,
    })
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
    let gone = deleted_scopes(tx, tenant).await?;
    Ok(tenant_view(tx, tenant, &gone).await?.0)
}

/// The scopes of the tenant's soft-deleted orgs (ADR-0041): each such org,
/// and every registered scope whose path ends at it. They are out of every
/// decision from the revision that deleted the org: the load leaves out
/// their assignments, field rules, boundary rules and paths.
async fn deleted_scopes(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<HashSet<(String, String)>, StoreError> {
    let tid = tenant.tid.to_string();
    let orgs: Vec<String> = tx
        .query(
            "SELECT org_id FROM tutela.org WHERE tenant_id = $1 AND deleted_at IS NOT NULL",
            &[&tid],
        )
        .await
        .db()?
        .iter()
        .map(|r| r.try_get(0))
        .collect::<Result<_, _>>()
        .db()?;
    let mut gone = HashSet::new();
    if orgs.is_empty() {
        return Ok(gone);
    }
    let tags: Vec<String> = orgs.iter().map(|o| format!("org:{o}")).collect();
    for r in tx
        .query(
            "SELECT scope_kind, scope_id FROM tutela.scope_path \
             WHERE tenant_id = $1 AND ancestors[cardinality(ancestors)] = ANY($2)",
            &[&tid, &tags],
        )
        .await
        .db()?
    {
        gone.insert((r.try_get(0).db()?, r.try_get(1).db()?));
    }
    gone.extend(orgs.into_iter().map(|o| ("org".to_owned(), o)));
    Ok(gone)
}

/// `true` for a scope of a soft-deleted org.
fn is_gone(gone: &HashSet<(String, String)>, kind: &str, id: &str) -> bool {
    !gone.is_empty() && gone.contains(&(kind.to_owned(), id.to_owned()))
}

/// The tenant data, and the earliest expiry in it, without what `gone`
/// names.
async fn tenant_view(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    gone: &HashSet<(String, String)>,
) -> Result<(TenantData, Option<SystemTime>), StoreError> {
    let tid = tenant.tid.to_string();
    let mut data = TenantData::default();

    for r in tx
        .query(
            "SELECT org_id FROM tutela.org WHERE tenant_id = $1 AND deleted_at IS NULL",
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

    // An assignment past its expiry does not count, even before a sweep has
    // removed it and bumped the revision. Ignoring it fails closed.
    let mut next_expiry: Option<SystemTime> = None;
    for r in tx
        .query(
            "SELECT id, principal_kind, principal_id, scope_kind, scope_id, role_id, expires_at \
             FROM tutela.role_assignment WHERE tenant_id = $1 \
             AND (expires_at IS NULL OR expires_at > clock_timestamp()) \
             ORDER BY created_at, id",
            &[&tid],
        )
        .await
        .db()?
    {
        if is_gone(gone, r.try_get(3).db()?, r.try_get(4).db()?) {
            continue;
        }
        let expires: Option<SystemTime> = r.try_get(6).db()?;
        next_expiry = match (next_expiry, expires) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
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
    let mut boundaries = BTreeMap::new();
    for r in tx
        .query(
            "SELECT scope_kind, scope_id, private, moves_out, moves_in, on_looser, links_from \
             FROM tutela.boundary_rule WHERE tenant_id = $1",
            &[&tid],
        )
        .await
        .db()?
    {
        if is_gone(gone, r.try_get(0).db()?, r.try_get(1).db()?) {
            continue;
        }
        let scope = entry(r.try_get(0).db()?, r.try_get(1).db()?)?;
        if r.try_get::<_, bool>(2).db()? {
            private.insert(scope.clone());
        }
        let rule = BoundaryRule {
            moves_out: move_rule(r.try_get(3).db()?)?,
            moves_in: move_rule(r.try_get(4).db()?)?,
            on_looser: on_looser(r.try_get(5).db()?)?,
            links_from: links_from(r.try_get(6).db()?)?,
        };
        if rule != BoundaryRule::default() {
            boundaries.insert(scope, rule);
        }
    }
    data.private_scopes = private;
    data.boundaries = boundaries;

    for r in tx
        .query(
            "SELECT id, scope_kind, scope_id, field_key, role_id, max_level \
             FROM tutela.field_rule WHERE tenant_id = $1 ORDER BY created_at, id",
            &[&tid],
        )
        .await
        .db()?
    {
        if is_gone(gone, r.try_get(1).db()?, r.try_get(2).db()?) {
            continue;
        }
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
    Ok((data, next_expiry))
}

fn move_rule(text: Option<&str>) -> Result<Option<MoveRule>, StoreError> {
    text.map(|t| match t {
        "members" => Ok(MoveRule::Members),
        "owners" => Ok(MoveRule::Owners),
        "none" => Ok(MoveRule::Nobody),
        _ => Err(StoreError::corrupt("move rule")),
    })
    .transpose()
}

fn on_looser(text: Option<&str>) -> Result<Option<OnLooser>, StoreError> {
    text.map(|t| match t {
        "approve" => Ok(OnLooser::Approve),
        "block" => Ok(OnLooser::Block),
        _ => Err(StoreError::corrupt("on_looser")),
    })
    .transpose()
}

fn links_from(text: Option<&str>) -> Result<Option<LinksFrom>, StoreError> {
    text.map(|t| match t {
        "any" => Ok(LinksFrom::Any),
        "team" => Ok(LinksFrom::Team),
        "none" => Ok(LinksFrom::Nobody),
        _ => Err(StoreError::corrupt("links_from")),
    })
    .transpose()
}

async fn scope_paths(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    gone: &HashSet<(String, String)>,
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
        if is_gone(gone, r.try_get(0).db()?, r.try_get(1).db()?) {
            continue;
        }
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
