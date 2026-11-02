//! Two-person publish, optional per tenant (ADR-0029).
//!
//! A proposal holds a model change and what its proposer saw. Another person
//! approves it, and it publishes as a version in the same transaction. The
//! database refuses a published proposal whose approver is its proposer, so
//! a bug above cannot let one person do both.

use std::time::SystemTime;

use tokio_postgres::{Row, Transaction};
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::{AppName, Class};

use crate::manifest::class_text;
use crate::models::{TenantPublish, insert_version};
use crate::{DbResult as _, Repr, StoreError, begin_write, enter, to_rev, uuid7};

/// The most proposals in one page.
pub const MAX_PROPOSAL_PAGE: usize = 100;

/// Whether a tenant publishes through two people.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TwoPerson {
    /// On: a model is published only through an approved proposal.
    pub on: bool,
    /// Who asked to turn it off. It stays on until a second person agrees.
    pub off_requested_by: Option<String>,
}

/// A proposal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proposal {
    /// `mpr_<uuidv7>`.
    pub id: String,
    /// `proposed`, `published`, `rejected` or `stale`.
    pub state: String,
    /// The new text. `None` in a listing.
    pub source: Option<String>,
    /// SHA-256 of the new text.
    pub digest: String,
    /// The version it was compared against.
    pub base_version: i64,
    /// The digest of that version.
    pub base_digest: String,
    /// The version it copies, for a rollback.
    pub restores: Option<i64>,
    /// `narrowing`, `neutral` or `widening`.
    pub class: String,
    /// The diff.
    pub diff: String,
    /// The impact report the proposer saw.
    pub impact: String,
    /// Its digest.
    pub impact_digest: String,
    /// `false` when that report stopped at its bound.
    pub impact_complete: bool,
    /// The tenant revision the report was made at.
    pub rev: u64,
    /// Who proposed it.
    pub proposed_by: String,
    /// Who approved, rejected or withdrew it.
    pub decided_by: Option<String>,
    /// The version it became.
    pub version: Option<i64>,
    /// When it was made.
    pub created_at: SystemTime,
    /// When it was decided.
    pub decided_at: Option<SystemTime>,
}

/// A proposal to store.
#[derive(Clone, Debug)]
pub struct NewProposal<'a> {
    /// The app.
    pub app: &'a AppName,
    /// The new text. The caller has compiled it.
    pub source: &'a str,
    /// The version it was compared against.
    pub base_version: i64,
    /// That version's digest.
    pub base_digest: &'a str,
    /// The version it copies, for a rollback.
    pub restores: Option<i64>,
    /// The class of the diff.
    pub class: Class,
    /// The diff.
    pub diff: &'a str,
    /// The impact report.
    pub impact: &'a str,
    /// Its digest.
    pub impact_digest: &'a str,
    /// Whether it is complete.
    pub impact_complete: bool,
    /// The tenant revision it was made at.
    pub rev: u64,
    /// Who proposes it.
    pub proposed_by: &'a str,
}

const COLUMNS: &str = "id, state, digest, base_version, base_digest, restores, class, diff, \
                       impact, impact_digest, impact_complete, rev, proposed_by, decided_by, \
                       version, created_at, decided_at";

fn to_proposal(r: &Row, source: bool) -> Result<Proposal, StoreError> {
    Ok(Proposal {
        id: r.try_get(0).db()?,
        state: r.try_get(1).db()?,
        digest: r.try_get(2).db()?,
        base_version: r.try_get(3).db()?,
        base_digest: r.try_get(4).db()?,
        restores: r.try_get(5).db()?,
        class: r.try_get(6).db()?,
        diff: r.try_get(7).db()?,
        impact: r.try_get(8).db()?,
        impact_digest: r.try_get(9).db()?,
        impact_complete: r.try_get(10).db()?,
        rev: to_rev(r.try_get(11).db()?)?,
        proposed_by: r.try_get(12).db()?,
        decided_by: r.try_get(13).db()?,
        version: r.try_get(14).db()?,
        created_at: r.try_get(15).db()?,
        decided_at: r.try_get(16).db()?,
        source: if source { r.try_get(17).db()? } else { None },
    })
}

fn db_rev(rev: u64) -> Result<i64, StoreError> {
    i64::try_from(rev).map_err(|_| StoreError::rev_out_of_range())
}

/// The tenant's two-person setting. Off when never set.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn two_person(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<TwoPerson, StoreError> {
    enter(tx, tenant).await?;
    Ok(tx
        .query_opt(
            "SELECT two_person, off_requested_by FROM tutela.tenant_setting WHERE tenant_id = $1",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?
        .map(|r| {
            Ok::<_, StoreError>(TwoPerson {
                on: r.try_get(0).db()?,
                off_requested_by: r.try_get(1).db()?,
            })
        })
        .transpose()?
        .unwrap_or_default())
}

/// Turns two-person publish on, or asks to turn it off. On takes one person.
/// Off takes two: the first call records who asks, and a call by someone
/// else turns it off. The caller has checked the right to change the model.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn set_two_person(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    on: bool,
    by: &str,
) -> Result<TwoPerson, StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    tx.execute(
        "INSERT INTO tutela.tenant_setting (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&tid],
    )
    .await
    .db()?;
    let row = tx
        .query_one(
            "SELECT two_person, off_requested_by FROM tutela.tenant_setting \
             WHERE tenant_id = $1 FOR UPDATE",
            &[&tid],
        )
        .await
        .db()?;
    let now = TwoPerson {
        on: row.try_get(0).db()?,
        off_requested_by: row.try_get(1).db()?,
    };
    let next = match (on, now.on, now.off_requested_by.as_deref()) {
        (true, _, _) => TwoPerson {
            on: true,
            off_requested_by: None,
        },
        (false, false, _) => now,
        (false, true, Some(first)) if first != by => TwoPerson {
            on: false,
            off_requested_by: None,
        },
        (false, true, _) => TwoPerson {
            on: true,
            off_requested_by: Some(by.to_owned()),
        },
    };
    tx.execute(
        "UPDATE tutela.tenant_setting SET two_person = $2, off_requested_by = $3, \
         changed_by = $4, changed_at = now() WHERE tenant_id = $1",
        &[&tid, &next.on, &next.off_requested_by, &by],
    )
    .await
    .db()?;
    Ok(next)
}

/// Stores a proposal. It changes nobody's access, so the revision stays.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn propose(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    p: &NewProposal<'_>,
) -> Result<String, StoreError> {
    enter(tx, tenant).await?;
    let id = format!("mpr_{}", uuid7()?);
    tx.execute(
        "INSERT INTO tutela.model_proposal (tenant_id, id, app, source, digest, base_version, \
         base_digest, restores, class, diff, impact, impact_digest, impact_complete, rev, \
         proposed_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        &[
            &tenant.tid.to_string(),
            &id,
            &p.app.as_str(),
            &p.source,
            &crate::digest(p.source),
            &p.base_version,
            &p.base_digest,
            &p.restores,
            &class_text(p.class),
            &p.diff,
            &p.impact,
            &p.impact_digest,
            &p.impact_complete,
            &db_rev(p.rev)?,
            &p.proposed_by,
        ],
    )
    .await
    .db()?;
    Ok(id)
}

/// One proposal, with its text.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn proposal(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
) -> Result<Option<Proposal>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        &format!(
            "SELECT {COLUMNS}, source FROM tutela.model_proposal \
             WHERE tenant_id = $1 AND id = $2"
        ),
        &[&tenant.tid.to_string(), &id],
    )
    .await
    .db()?
    .map(|r| to_proposal(&r, true))
    .transpose()
}

/// The newest proposals, at most [`MAX_PROPOSAL_PAGE`], without their text.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant) or a database error.
pub async fn proposals(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Vec<Proposal>, StoreError> {
    enter(tx, tenant).await?;
    let limit = i64::try_from(MAX_PROPOSAL_PAGE).unwrap_or(100);
    tx.query(
        &format!(
            "SELECT {COLUMNS} FROM tutela.model_proposal WHERE tenant_id = $1 \
             ORDER BY created_at DESC, id DESC LIMIT $2"
        ),
        &[&tenant.tid.to_string(), &limit],
    )
    .await
    .db()?
    .iter()
    .map(|r| to_proposal(r, false))
    .collect()
}

/// Ends an open proposal as `rejected` or `stale`.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) when no open proposal has
/// this id, or a database error.
pub async fn close_proposal(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
    stale: bool,
    by: Option<&str>,
) -> Result<(), StoreError> {
    enter(tx, tenant).await?;
    let state = if stale { "stale" } else { "rejected" };
    let n = tx
        .execute(
            "UPDATE tutela.model_proposal SET state = $3, decided_by = $4, decided_at = now() \
             WHERE tenant_id = $1 AND id = $2 AND state = 'proposed'",
            &[&tenant.tid.to_string(), &id, &state, &by],
        )
        .await
        .db()?;
    if n == 0 {
        return Err(StoreError::not_found("an open proposal"));
    }
    Ok(())
}

/// Publishes an open proposal as a new version, approved by `by`, and bumps
/// the tenant's revision, in one transaction. `rev` is the revision the
/// caller checked the proposal against: if the tenant moved since, nothing
/// is written, and the caller checks again.
///
/// # Errors
///
/// [`Exists`](crate::StoreErrorKind::Exists) when the tenant or its model
/// moved, [`NotFound`](crate::StoreErrorKind::NotFound) when the proposal is
/// not open, [`Invalid`](crate::StoreErrorKind::Invalid) when `by` proposed
/// it, or a database error.
pub async fn publish_proposal(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
    by: &str,
    approvers: &[String],
    rev: u64,
) -> Result<(i64, u64), StoreError> {
    let new_rev = begin_write(tx, tenant).await?;
    if new_rev != rev.saturating_add(1) {
        return Err(StoreError::exists("the tenant moved; check again"));
    }
    let tid = tenant.tid.to_string();
    let row = tx
        .query_opt(
            "SELECT app, source, base_version, restores, class, diff, impact, proposed_by \
             FROM tutela.model_proposal WHERE tenant_id = $1 AND id = $2 AND state = 'proposed' \
             FOR UPDATE",
            &[&tid, &id],
        )
        .await
        .db()?
        .ok_or(StoreError::not_found("an open proposal"))?;
    let proposed_by: String = row.try_get(7).db()?;
    if proposed_by == by {
        return Err(StoreError::invalid("the proposer cannot approve"));
    }
    let app = AppName::parse(row.try_get(0).db()?).map_err(|_| StoreError::corrupt("app"))?;
    let class = match row.try_get::<_, &str>(4).db()? {
        "narrowing" => Class::Narrowing,
        "widening" => Class::Widening,
        _ => Class::Neutral,
    };
    let source: String = row.try_get(1).db()?;
    let diff: String = row.try_get(5).db()?;
    let impact: String = row.try_get(6).db()?;
    let mut approved: Vec<String> = vec![by.to_owned()];
    approved.extend(approvers.iter().cloned());
    let version = insert_version(
        tx,
        &tid,
        new_rev,
        &TenantPublish {
            app: &app,
            source: &source,
            expected: row.try_get(2).db()?,
            class,
            diff: &diff,
            impact: Some(&impact),
            author: Some(&proposed_by),
            approvers: &approved,
            restores: row.try_get(3).db()?,
        },
    )
    .await?;
    tx.execute(
        "UPDATE tutela.model_proposal SET state = 'published', decided_by = $3, \
         decided_at = now(), version = $4 WHERE tenant_id = $1 AND id = $2",
        &[&tid, &id, &by, &version],
    )
    .await
    .db()?;
    Ok((version, new_rev))
}

/// Refuses a publish that bypasses a proposal while two-person is on.
pub(crate) async fn require_one_person(tx: &Transaction<'_>, tid: &str) -> Result<(), StoreError> {
    let on: bool = tx
        .query_opt(
            "SELECT two_person FROM tutela.tenant_setting WHERE tenant_id = $1",
            &[&tid],
        )
        .await
        .db()?
        .map(|r| r.try_get(0))
        .transpose()
        .db()?
        .unwrap_or(false);
    if on {
        return Err(StoreError(Repr::TwoPerson));
    }
    Ok(())
}
