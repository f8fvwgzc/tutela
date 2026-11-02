//! The local hash-chained audit log (CONTRACTS.md 9.4, THREAT-MODEL.md TM-20,
//! ADR-0034).
//!
//! Each tenant has one chain. [`append_audit`] writes records in the caller's
//! transaction, the one of the change they describe, so a rolled-back change
//! leaves no record and a committed one always has its record. A refusal
//! that has no transaction of its own gets one from the caller.
//!
//! - A record is stored as its canonical body: the audit.v1 JSON with the
//!   chain's `seq` and without `signature` ([`AuditDraft::body`]). The
//!   producer signs exactly these bytes when it forwards the record
//!   (CONTRACTS.md 9.3), so `seq` counts per (service, tenant) from 1 with no
//!   gap.
//! - `hash = SHA-256("tutela-audit-chain-v1\n" + prev_hash + "\n" + body)`
//!   in lowercase hex ([`chain_hash`]); the first record's `prev_hash` is
//!   [`GENESIS`].
//! - Writers lock the chain's head row, so two writers in one tenant make
//!   one chain, in commit order. Append last in a transaction: the lock is
//!   held until it ends.
//! - UPDATE, DELETE and TRUNCATE are refused by the database for every role
//!   (migration 8); [`verify_audit_chain`] finds a gap or an edited record.
//!
//! The deployment's own records (its signing keys) have a chain of their own
//! under [`DEPLOYMENT_TENANT`], a tenant id that is never in the directory.

use sha2::{Digest as _, Sha256};
use tokio_postgres::Transaction;
use tutela_contracts::audit::AuditDraft;
use tutela_contracts::tenant::{TenantId, TenantKey};

use crate::{DbResult as _, StoreError, enter, set_tenant};

/// The `prev_hash` of a chain's first record.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The tenant id of the deployment's own chain. It is never in the tenant
/// directory, so no token can enter it.
pub const DEPLOYMENT_TENANT: &str = "ten_00000000-0000-7000-8000-000000000000";

/// The most records [`audit_records`] returns at once.
pub const MAX_AUDIT_PAGE: usize = 1000;

/// The deployment's tenant id, [`DEPLOYMENT_TENANT`].
///
/// # Errors
///
/// Never in practice: the constant parses.
pub fn deployment_tenant() -> Result<TenantId, StoreError> {
    DEPLOYMENT_TENANT
        .parse()
        .map_err(|_| StoreError::corrupt("deployment tenant id"))
}

/// One stored record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuditEntry {
    /// The position in the chain, also the record's `seq`.
    pub seq: u64,
    /// The record id.
    pub id: String,
    /// The canonical body: the audit.v1 JSON without `signature`.
    pub body: String,
    /// The hash of the record before it, or [`GENESIS`].
    pub prev_hash: String,
    /// This record's hash.
    pub hash: String,
}

/// `SHA-256("tutela-audit-chain-v1\n" + prev_hash + "\n" + body)` in lowercase
/// hex.
#[must_use]
pub fn chain_hash(prev_hash: &str, body: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tutela-audit-chain-v1\n");
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(body.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Appends `drafts` to `tenant`'s chain, in order, in the caller's
/// transaction. Returns their `seq`s.
///
/// Call it last in the transaction: it locks the chain's head until the
/// transaction ends.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a draft of another tenant
/// or one that breaks an audit.v1 rule,
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn append_audit(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    drafts: &[AuditDraft],
) -> Result<Vec<u64>, StoreError> {
    enter(tx, tenant).await?;
    append(tx, &tenant.tid, drafts).await
}

/// Appends `drafts` to the deployment's own chain ([`DEPLOYMENT_TENANT`]),
/// in a transaction that has entered no tenant: records about the
/// deployment, such as its signing keys.
///
/// # Errors
///
/// [`TenantMismatch`](crate::StoreErrorKind::TenantMismatch) when the
/// transaction has entered a tenant, [`Invalid`](crate::StoreErrorKind::Invalid)
/// for a draft whose tenant is not the deployment's, or a database error.
pub async fn append_deployment_audit(
    tx: &Transaction<'_>,
    drafts: &[AuditDraft],
) -> Result<Vec<u64>, StoreError> {
    let tid = enter_deployment(tx).await?;
    append(tx, &tid, drafts).await
}

/// Sets the deployment's chain as the transaction's tenant, unless it has
/// entered another one.
async fn enter_deployment(tx: &Transaction<'_>) -> Result<TenantId, StoreError> {
    let tid = deployment_tenant()?;
    let current: Option<String> = tx
        .query_one("SELECT current_setting('tutela.tenant_id', true)", &[])
        .await
        .db()?
        .try_get(0)
        .db()?;
    match current.filter(|c| !c.is_empty()) {
        Some(c) if c == DEPLOYMENT_TENANT => {}
        Some(_) => return Err(StoreError(crate::Repr::TenantMismatch)),
        None => set_tenant(tx, &tid).await?,
    }
    Ok(tid)
}

async fn append(
    tx: &Transaction<'_>,
    tid: &TenantId,
    drafts: &[AuditDraft],
) -> Result<Vec<u64>, StoreError> {
    if drafts.is_empty() {
        return Ok(Vec::new());
    }
    if drafts.iter().any(|d| d.tenant.tid != *tid) {
        return Err(StoreError::invalid(
            "an audit record belongs to the chain of its own tenant",
        ));
    }
    let t = tid.to_string();
    tx.execute(
        "INSERT INTO tutela.audit_head (tenant_id, seq, hash) VALUES ($1, 0, $2) \
         ON CONFLICT DO NOTHING",
        &[&t, &GENESIS],
    )
    .await
    .db()?;
    let head = tx
        .query_one(
            "SELECT seq, hash FROM tutela.audit_head WHERE tenant_id = $1 FOR UPDATE",
            &[&t],
        )
        .await
        .db()?;
    let mut seq = u64::try_from(head.try_get::<_, i64>(0).db()?)
        .map_err(|_| StoreError::corrupt("audit head"))?;
    let mut prev: String = head.try_get(1).db()?;
    let mut out = Vec::with_capacity(drafts.len());
    for draft in drafts {
        seq += 1;
        let body = draft
            .body(seq)
            .map_err(|_| StoreError::invalid("the audit record breaks an audit.v1 rule"))?;
        let hash = chain_hash(&prev, &body);
        tx.execute(
            "INSERT INTO tutela.audit_record (tenant_id, seq, id, body, prev_hash, hash) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &t,
                &i64::try_from(seq).map_err(|_| StoreError::rev_out_of_range())?,
                &draft.id.to_string(),
                &body,
                &prev,
                &hash,
            ],
        )
        .await
        .db()?;
        out.push(seq);
        prev = hash;
    }
    tx.execute(
        "UPDATE tutela.audit_head SET seq = $2, hash = $3 WHERE tenant_id = $1",
        &[
            &t,
            &i64::try_from(seq).map_err(|_| StoreError::rev_out_of_range())?,
            &prev,
        ],
    )
    .await
    .db()?;
    Ok(out)
}

/// Up to `limit` (at most [`MAX_AUDIT_PAGE`]) records of `tenant` after
/// `after`, in chain order.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn audit_records(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    after: u64,
    limit: usize,
) -> Result<Vec<AuditEntry>, StoreError> {
    enter(tx, tenant).await?;
    page(tx, &tenant.tid, after, limit).await
}

/// [`audit_records`] of the deployment's own chain.
///
/// # Errors
///
/// As [`append_deployment_audit`].
pub async fn deployment_audit_records(
    tx: &Transaction<'_>,
    after: u64,
    limit: usize,
) -> Result<Vec<AuditEntry>, StoreError> {
    let tid = enter_deployment(tx).await?;
    page(tx, &tid, after, limit).await
}

async fn page(
    tx: &Transaction<'_>,
    tid: &TenantId,
    after: u64,
    limit: usize,
) -> Result<Vec<AuditEntry>, StoreError> {
    let limit = i64::try_from(limit.clamp(1, MAX_AUDIT_PAGE))
        .map_err(|_| StoreError::invalid("a page size"))?;
    let after = i64::try_from(after).map_err(|_| StoreError::invalid("an audit position"))?;
    let rows = tx
        .query(
            "SELECT seq, id, body, prev_hash, hash FROM tutela.audit_record \
             WHERE tenant_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
            &[&tid.to_string(), &after, &limit],
        )
        .await
        .db()?;
    rows.iter()
        .map(|r| {
            Ok(AuditEntry {
                seq: u64::try_from(r.try_get::<_, i64>(0).db()?)
                    .map_err(|_| StoreError::corrupt("audit seq"))?,
                id: r.try_get(1).db()?,
                body: r.try_get(2).db()?,
                prev_hash: r.try_get(3).db()?,
                hash: r.try_get(4).db()?,
            })
        })
        .collect()
}

/// What is wrong at the first broken link.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ChainProblem {
    /// A record is missing: the chain jumps past this `seq`.
    Gap,
    /// The record's `prev_hash` is not the hash of the record before it.
    PrevHash,
    /// The record's hash does not match its body: the record was changed.
    Hash,
    /// The body does not parse, or its `seq` or tenant is not its row's.
    Body,
    /// The head says the chain is longer than its records: the last ones
    /// are gone.
    Head,
}

/// The first broken link of a chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BrokenLink {
    /// The `seq` where the chain breaks: the record that is wrong, or the
    /// first one missing.
    pub seq: u64,
    /// What is wrong there.
    pub problem: ChainProblem,
}

/// What [`verify_audit_chain`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainReport {
    /// Records checked, up to the first broken link.
    pub checked: u64,
    /// The head's `seq`.
    pub head: u64,
    /// The first broken link; `None` when the whole chain holds.
    pub broken: Option<BrokenLink>,
}

impl ChainReport {
    /// `true` when the whole chain holds.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        self.broken.is_none()
    }
}

/// Walks `tenant`'s chain from the first record and reports the first broken
/// link: a missing record, a record whose hash or `prev_hash` does not hold,
/// a body that is not its row's, or a head past the last record.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error. A broken chain is a report, not an error.
pub async fn verify_audit_chain(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<ChainReport, StoreError> {
    enter(tx, tenant).await?;
    verify(tx, &tenant.tid).await
}

/// [`verify_audit_chain`] of the deployment's own chain.
///
/// # Errors
///
/// As [`append_deployment_audit`].
pub async fn verify_deployment_audit_chain(
    tx: &Transaction<'_>,
) -> Result<ChainReport, StoreError> {
    let tid = enter_deployment(tx).await?;
    verify(tx, &tid).await
}

async fn verify(tx: &Transaction<'_>, tid: &TenantId) -> Result<ChainReport, StoreError> {
    let t = tid.to_string();
    let head = tx
        .query_opt(
            "SELECT seq, hash FROM tutela.audit_head WHERE tenant_id = $1",
            &[&t],
        )
        .await
        .db()?;
    let (head_seq, head_hash) = match head {
        Some(r) => (
            u64::try_from(r.try_get::<_, i64>(0).db()?)
                .map_err(|_| StoreError::corrupt("audit head"))?,
            r.try_get::<_, String>(1).db()?,
        ),
        None => (0, GENESIS.to_owned()),
    };
    let broken = |seq, problem| BrokenLink { seq, problem };
    let mut report = ChainReport {
        checked: 0,
        head: head_seq,
        broken: None,
    };
    let mut prev = GENESIS.to_owned();
    let mut last = 0u64;
    loop {
        let entries = page(tx, tid, last, MAX_AUDIT_PAGE).await?;
        if entries.is_empty() {
            break;
        }
        for e in entries {
            let expected = last + 1;
            let problem = if e.seq != expected {
                report.broken = Some(broken(expected, ChainProblem::Gap));
                return Ok(report);
            } else if e.prev_hash != prev {
                Some(ChainProblem::PrevHash)
            } else if chain_hash(&e.prev_hash, &e.body) != e.hash {
                Some(ChainProblem::Hash)
            } else if !body_is_its_rows(&e.body, e.seq, &t) {
                Some(ChainProblem::Body)
            } else {
                None
            };
            if let Some(problem) = problem {
                report.broken = Some(broken(e.seq, problem));
                return Ok(report);
            }
            report.checked += 1;
            prev = e.hash;
            last = e.seq;
        }
    }
    if last != head_seq || (head_seq > 0 && prev != head_hash) {
        report.broken = Some(broken(last + 1, ChainProblem::Head));
    }
    Ok(report)
}

/// The body is a JSON object whose `seq` and `tenant.tid` are its row's.
fn body_is_its_rows(body: &str, seq: u64, tid: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    v.get("seq").and_then(serde_json::Value::as_u64) == Some(seq)
        && v.get("tenant")
            .and_then(|t| t.get("tid"))
            .and_then(serde_json::Value::as_str)
            == Some(tid)
        && v.get("schema").and_then(serde_json::Value::as_str) == Some("audit.v1")
}
