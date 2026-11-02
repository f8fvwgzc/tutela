//! A tenant's model versions (ADR-0026).
//!
//! Every published model is a kept, numbered row of `model_revision`. A
//! tenant that has published a model of its own follows the newest row; one
//! that has not follows the app's manifest ([`crate::applied_manifest`]). So
//! one tenant's publish changes that tenant only: it writes inside the
//! tenant's row-level security and bumps that tenant's revision, and it never
//! touches `app_manifest`.
//!
//! A row is never changed. A rollback is a new version with the old text.

use std::time::SystemTime;

use tokio_postgres::{Row, Transaction};
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::{AppName, Class};

use crate::manifest::class_text;
use crate::proposals::require_one_person;
use crate::{DbResult as _, StoreError, applied_manifest, begin_write, digest, enter, to_rev};

/// The most versions in one page.
pub const MAX_VERSION_PAGE: usize = 100;

/// The model a tenant runs on now.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActiveModel {
    /// The manifest text.
    pub source: String,
    /// SHA-256 of the text, lowercase hex.
    pub digest: String,
    /// The tenant's newest version number; 0 when it has none yet. A publish
    /// names this as its `expected`.
    pub version: i64,
    /// `true` when the tenant published this model itself, `false` when it
    /// follows the app's manifest.
    pub own: bool,
}

/// One published version.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModelVersion {
    /// The number, from 1, per tenant.
    pub version: i64,
    /// The tenant revision it was published at.
    pub rev: u64,
    /// SHA-256 of the text.
    pub digest: String,
    /// `narrowing`, `neutral` or `widening`.
    pub class: String,
    /// The diff, one change per line.
    pub diff: String,
    /// The impact report, as stored by the publisher.
    pub impact: Option<String>,
    /// Who published it.
    pub author: Option<String>,
    /// Who approved it.
    pub approvers: Vec<String>,
    /// `app` or `tenant`.
    pub origin: String,
    /// The version this one copies, for a rollback.
    pub restores: Option<i64>,
    /// When.
    pub published_at: Option<SystemTime>,
    /// The text. `None` in a listing, and for a version from before
    /// migration 4 that is not the current manifest.
    pub source: Option<String>,
}

/// A tenant's own model to publish.
#[derive(Clone, Debug)]
pub struct TenantPublish<'a> {
    /// The app. A schema holds one.
    pub app: &'a AppName,
    /// The new text. The caller has compiled it.
    pub source: &'a str,
    /// The version the caller compared against: [`ActiveModel::version`].
    pub expected: i64,
    /// The class of the diff.
    pub class: Class,
    /// The diff as text, one change per line.
    pub diff: &'a str,
    /// The impact report.
    pub impact: Option<&'a str>,
    /// Who publishes it.
    pub author: Option<&'a str>,
    /// Who approved it.
    pub approvers: &'a [String],
    /// The version this one copies, for a rollback.
    pub restores: Option<i64>,
}

/// The model `tenant` runs on now. Call it after [`crate::load`], in the same
/// transaction: the revision's share lock then keeps the two together.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant),
/// [`Invalid`](crate::StoreErrorKind::Invalid) when the schema holds two apps,
/// [`Corrupt`](crate::StoreErrorKind::Corrupt) for a tenant row with no text,
/// or a database error. `None` when the tenant has no model of its own and
/// the app has no manifest.
pub async fn active_model(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Option<ActiveModel>, StoreError> {
    enter(tx, tenant).await?;
    let head = tx
        .query_opt(
            "SELECT version, origin, source, bundle_digest FROM tutela.model_revision \
             WHERE tenant_id = $1 ORDER BY version DESC LIMIT 1",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?;
    let version = head
        .as_ref()
        .map(|r| r.try_get::<_, i64>(0))
        .transpose()
        .db()?
        .unwrap_or(0);
    if let Some(r) = &head
        && r.try_get::<_, &str>(1).db()? == "tenant"
    {
        return Ok(Some(ActiveModel {
            source: r
                .try_get::<_, Option<String>>(2)
                .db()?
                .ok_or(StoreError::corrupt("a tenant model with no text"))?,
            digest: r.try_get(3).db()?,
            version,
            own: true,
        }));
    }
    Ok(applied_manifest(tx).await?.map(|m| ActiveModel {
        source: m.source,
        digest: m.digest,
        version,
        own: false,
    }))
}

fn to_version(r: &Row, with_source: bool) -> Result<ModelVersion, StoreError> {
    Ok(ModelVersion {
        version: r.try_get(0).db()?,
        rev: to_rev(r.try_get(1).db()?)?,
        digest: r.try_get(2).db()?,
        class: r.try_get(3).db()?,
        diff: r.try_get(4).db()?,
        impact: r.try_get(5).db()?,
        author: r.try_get(6).db()?,
        approvers: r.try_get(7).db()?,
        origin: r.try_get(8).db()?,
        restores: r.try_get(9).db()?,
        published_at: r.try_get(10).db()?,
        source: if with_source {
            r.try_get(11).db()?
        } else {
            None
        },
    })
}

const COLUMNS: &str = "version, rev, bundle_digest, class, diff, impact, author, approvers, \
                       origin, restores, published_at";

/// A page of `tenant`'s versions, newest first, below `before`. At most
/// [`MAX_VERSION_PAGE`]. The text is left out.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn model_versions(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    before: Option<i64>,
    limit: usize,
) -> Result<Vec<ModelVersion>, StoreError> {
    enter(tx, tenant).await?;
    let limit = i64::try_from(limit.clamp(1, MAX_VERSION_PAGE)).unwrap_or(1);
    tx.query(
        &format!(
            "SELECT {COLUMNS} FROM tutela.model_revision WHERE tenant_id = $1 \
             AND version < $2 ORDER BY version DESC LIMIT $3"
        ),
        &[&tenant.tid.to_string(), &before.unwrap_or(i64::MAX), &limit],
    )
    .await
    .db()?
    .iter()
    .map(|r| to_version(r, false))
    .collect()
}

/// One version of `tenant`, with its text.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn model_version(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    version: i64,
) -> Result<Option<ModelVersion>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        &format!(
            "SELECT {COLUMNS}, source FROM tutela.model_revision \
             WHERE tenant_id = $1 AND version = $2"
        ),
        &[&tenant.tid.to_string(), &version],
    )
    .await
    .db()?
    .map(|r| to_version(&r, true))
    .transpose()
}

/// Publishes a tenant's own model as a new version, and bumps that tenant's
/// revision in the same transaction. Returns the version and the revision.
/// No other tenant changes, and neither does the app's manifest. A tenant
/// that had no version gets two: the manifest it ran on, then this one.
///
/// The caller compiles the text, compares it with the active model and
/// decides whether the change may go in: a widening change needs an approval
/// token (ADR-0015). This function only stores the result.
///
/// # Errors
///
/// [`Exists`](crate::StoreErrorKind::Exists) if the newest version is not
/// `expected` (another publish came first),
/// [`TwoPerson`](crate::StoreErrorKind::TwoPerson) while the tenant publishes
/// only through approved proposals, or a database error.
pub async fn publish_tenant_model(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    p: &TenantPublish<'_>,
) -> Result<(i64, u64), StoreError> {
    let rev = begin_write(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    require_one_person(tx, &tid).await?;
    let version = insert_version(tx, &tid, rev, p).await?;
    crate::events::insert(
        tx,
        &tenant.tid,
        &crate::events::OutboxEvent::ModelPublished { rev },
    )
    .await?;
    Ok((version, rev))
}

/// Writes a version at revision `rev`, which the caller's write took. The
/// newest version must be `p.expected`.
pub(crate) async fn insert_version(
    tx: &Transaction<'_>,
    tid: &str,
    rev: u64,
    p: &TenantPublish<'_>,
) -> Result<i64, StoreError> {
    let tid = tid.to_owned();
    let head: i64 = tx
        .query_one(
            "SELECT coalesce(max(version), 0) FROM tutela.model_revision WHERE tenant_id = $1",
            &[&tid],
        )
        .await
        .db()?
        .try_get(0)
        .db()?;
    if head != p.expected {
        return Err(StoreError::exists("a newer model; compare again"));
    }
    let db_rev = i64::try_from(rev).map_err(|_| StoreError::rev_out_of_range())?;
    // A tenant made after the last app publish has no row yet. What it ran on
    // is what came before, so it goes into the history first.
    let mut version = head.saturating_add(1);
    if head == 0
        && let Some(base) = applied_manifest(tx).await?
    {
        tx.execute(
            "INSERT INTO tutela.model_revision (tenant_id, rev, parent_rev, app, diff, class, \
             state, published_at, bundle_digest, version, source) \
             VALUES ($1, $2, $3, $4, '', 'neutral', 'published', now(), $5, 1, $6)",
            &[
                &tid,
                &(db_rev - 1),
                &(db_rev - 2).max(0),
                &p.app.as_str(),
                &base.digest,
                &base.source,
            ],
        )
        .await
        .db()?;
        version = 2;
    }
    tx.execute(
        "INSERT INTO tutela.model_revision (tenant_id, rev, parent_rev, app, author, approvers, \
         diff, class, impact, state, published_at, bundle_digest, version, source, origin, \
         restores) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'published', now(), $10, $11, \
         $12, 'tenant', $13)",
        &[
            &tid,
            &db_rev,
            &(db_rev - 1),
            &p.app.as_str(),
            &p.author,
            &p.approvers,
            &p.diff,
            &class_text(p.class),
            &p.impact,
            &digest(p.source),
            &version,
            &p.source,
            &p.restores,
        ],
    )
    .await
    .db()?;
    Ok(version)
}
