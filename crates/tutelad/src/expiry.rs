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

use crate::db::{Db, DbError};
use crate::telemetry::Metrics;

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

/// Sweeps every `every` until `stop` turns true.
pub async fn run(db: Db, metrics: Arc<Metrics>, every: Duration, mut stop: watch::Receiver<bool>) {
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
    }
}
