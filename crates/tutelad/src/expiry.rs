//! The expiry sweep (ADR-0020): on a timer, each tenant in turn loses its
//! assignments that are past their expiry, and its revision goes up, so
//! every cache at an older revision reloads.
//!
//! The sweep enters each tenant the way a request does. Row-level security
//! hides the rows of every other tenant, so there is no way to ask for all
//! expired rows at once, and there should not be one (ADR-0014). Several
//! replicas may sweep at once; one expiry still makes one revision.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use tutela_contracts::audit::{Actor, AuditDraft};
use tutela_contracts::tenant::{Issuer, TenantKey};
use tutela_pdp::Subject;

use crate::audit::{BuildError, Record, system};
use crate::db::{Db, DbError};
use crate::telemetry::Metrics;

/// The audit records of one sweep of `tenant` (ADR-0034): one per removed
/// assignment, by `tutelad` itself, at the new revision.
///
/// # Errors
///
/// A record that cannot be built: a bug.
pub(crate) fn records(
    tenant: &TenantKey,
    gone: &tutela_store::Expired,
) -> Result<Vec<AuditDraft>, BuildError> {
    let actor = Actor::new(system()?);
    gone.assignments
        .iter()
        .map(|a| {
            let subject = match &a.subject {
                Subject::Principal(p) => p.to_string(),
                Subject::Group(g) => format!("group:{g}"),
            };
            Record::new(
                tenant,
                actor.clone(),
                "tutela_assignment:expire",
                ("tutela_assignment", a.id.as_str()),
            )
            .allowed(gone.rev)
            .rules(std::slice::from_ref(&a.id))
            .detail("subject", subject)
            .detail("role", a.role.as_str())
            .detail("scope", format!("{}:{}", a.scope.type_name, a.scope.id))
            .build()
        })
        .collect()
}

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sweep {
    /// Tenants looked at.
    pub tenants: usize,
    /// Tenants whose revision went up.
    pub bumped: usize,
    /// Assignments removed.
    pub expired: usize,
    /// Tenants that failed. The others still ran.
    pub failed: usize,
}

/// One sweep over every tenant. A failure in one tenant does not stop the
/// others.
///
/// # Errors
///
/// When no connection can be had, or the tenants cannot be listed.
pub async fn sweep(db: &Db, metrics: &Metrics) -> Result<Sweep, DbError> {
    let mut conn = db.conn().await?;
    let tenants = conn.tenants().await?;
    let mut out = Sweep {
        tenants: tenants.len(),
        ..Sweep::default()
    };
    for tenant in &tenants {
        match conn.expire(tenant).await {
            Ok(None) => {}
            Ok(Some(gone)) => {
                out.bumped += 1;
                out.expired += gone.assignments.len();
                metrics.add_expired(gone.assignments.len());
                tracing::info!(
                    tid = %tenant.tid,
                    rev = gone.rev,
                    assignments = gone.assignments.len(),
                    "assignments expired"
                );
            }
            Err(e) => {
                out.failed += 1;
                tracing::error!(
                    tid = %tenant.tid,
                    error = %e,
                    kind = ?e.store_kind(),
                    sqlstate = e.sqlstate(),
                    "an expiry sweep failed for one tenant"
                );
            }
        }
    }
    Ok(out)
}

/// What one purge did (ADR-0041).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Purge {
    /// Soft-deleted tenants whose data was removed.
    pub tenants: usize,
    /// Soft-deleted orgs whose data was removed.
    pub orgs: usize,
    /// Tenants whose purge failed. The others still ran.
    pub failed: usize,
}

/// One purge: every soft-deleted tenant and org whose grace has passed
/// loses its data; audit chains stay. A tenant's purge is also recorded in
/// the deployment's own chain, whose tenant key names `own`. Several
/// replicas may purge at once; a tenant is purged once.
///
/// # Errors
///
/// When no connection can be had, or the tenants cannot be listed.
pub async fn purge(db: &Db, metrics: &Metrics, own: &Issuer) -> Result<Purge, DbError> {
    let mut conn = db.conn().await?;
    let mut out = Purge::default();
    for key in conn.due_tenant_purges().await? {
        match conn.purge_tenant(&key).await {
            Ok(false) => {}
            Ok(true) => {
                out.tenants += 1;
                metrics.count_purge("tenant", true);
                tracing::info!(tid = %key.tid, "a soft-deleted tenant was purged");
                let record = crate::lifecycle::deployment_record(
                    own,
                    "tutela_tenant:purge",
                    &key,
                    Actor::new(system()?),
                )?;
                if let Err(e) = conn.deployment_records(vec![record]).await {
                    metrics.count_audit("write", "error");
                    tracing::error!(error = %e, "a purge could not be recorded in the deployment's chain");
                }
            }
            Err(e) => {
                out.failed += 1;
                metrics.count_purge("tenant", false);
                tracing::error!(tid = %key.tid, error = %e, kind = ?e.store_kind(), "a tenant's purge failed");
            }
        }
    }
    for key in conn.tenants().await? {
        match conn.purge_orgs(&key).await {
            Ok(n) => {
                out.orgs += n;
                for _ in 0..n {
                    metrics.count_purge("org", true);
                }
            }
            Err(e) => {
                out.failed += 1;
                metrics.count_purge("org", false);
                tracing::error!(tid = %key.tid, error = %e, kind = ?e.store_kind(), "an org's purge failed");
            }
        }
    }
    Ok(out)
}

/// Sweeps, then purges, every `every` until `stop` turns true.
pub async fn run(
    db: Db,
    metrics: Arc<Metrics>,
    every: Duration,
    own: Issuer,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        match sweep(&db, &metrics).await {
            Ok(s) => metrics.count_sweep(s.failed == 0),
            Err(e) => {
                metrics.count_sweep(false);
                tracing::warn!(error = %e, "an expiry sweep did not run");
            }
        }
        if let Err(e) = purge(&db, &metrics, &own).await {
            tracing::warn!(error = %e, "a purge did not run");
        }
    }
}
