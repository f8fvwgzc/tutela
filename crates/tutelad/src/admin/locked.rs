//! A change of tenant data, checked on the data it changes (ADR-0043).
//!
//! The change runs in one transaction that first locks the tenant's
//! revision row, as a write does, and reads the tenant. The caller's keys
//! are checked on that read, the store writes, the tenant is read again in
//! the same transaction, and the narrow-only rule compares the two: nobody
//! may get more than the caller holds (PERMISSION-MODEL.md 7.1 step 6). No
//! other write can come between the check and the commit.

use std::sync::Arc;

use axum::http::StatusCode;
use tutela_contracts::decision::Decision;
use tutela_contracts::keys::ActionKey;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::Model;
use tutela_pdp::{Attrs, CheckRequest, ImpactReport, PathEntry, Pdp, ResourceRef, ScopePaths};
use tutela_store::TenantBundle;

use crate::api::{AppState, Problem};
use crate::authz::pdp_problem;
use crate::db::TenantTx;

/// The tenant as the change found it, under the write lock.
pub(crate) struct Before {
    /// Its data and paths.
    pub bundle: TenantBundle,
    /// Its active model, compiled.
    pub model: Arc<Model>,
    /// An evaluator over both.
    pub pdp: Pdp,
}

fn unavailable() -> Problem {
    Problem::stale("unavailable")
}

async fn build(
    tenant: TenantKey,
    rev: u64,
    model: Arc<Model>,
    data: tutela_pdp::TenantData,
) -> Result<Pdp, Problem> {
    tokio::task::spawn_blocking(move || {
        let mut pdp = Pdp::new();
        pdp.load(tenant, rev, model, data).map(|()| pdp)
    })
    .await
    .map_err(|_| unavailable())?
    .map_err(|e| {
        tracing::warn!(error = %e, "a tenant's data did not load for an admin change");
        unavailable()
    })
}

/// Locks the tenant for a change in `tx` and reads it.
///
/// # Errors
///
/// A 503, or 403 `unknown_tenant`.
pub(crate) async fn read(state: &AppState, tx: &TenantTx<'_>) -> Result<Before, Problem> {
    let tenant = tx.tenant().clone();
    tutela_store::lock(tx, &tenant).await?;
    let bundle = tutela_store::load(tx, &tenant).await?;
    let active = tutela_store::active_model(tx, &tenant)
        .await?
        .ok_or_else(|| Problem::stale("no_data"))?;
    let model = state
        .cache
        .compiled(active.source, &active.digest)
        .await
        .map_err(Problem::from)?;
    let pdp = build(tenant, bundle.rev, Arc::clone(&model), bundle.data.clone()).await?;
    Ok(Before { bundle, model, pdp })
}

/// `before` without one assignment: the base a change compares against when
/// it gives that assignment again, for longer (ADR-0043 item 4).
///
/// # Errors
///
/// A 503.
pub(crate) async fn without(
    before: Before,
    tenant: &TenantKey,
    rule: &tutela_contracts::decision::RuleId,
) -> Result<Before, Problem> {
    let mut data = before.bundle.data.clone();
    data.bindings.retain(|b| b.id != *rule);
    let pdp = build(
        tenant.clone(),
        before.bundle.rev,
        Arc::clone(&before.model),
        data,
    )
    .await?;
    Ok(Before { pdp, ..before })
}

/// 404 for a scope that is neither an org of the tenant nor registered.
pub(crate) fn no_scope() -> Problem {
    Problem::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such registered scope",
    )
}

/// The path the store holds for `scope`: none for an org.
pub(crate) fn path(
    before: &Before,
    tenant: &TenantKey,
    scope: &PathEntry,
) -> Result<Vec<PathEntry>, Problem> {
    if scope.is_org() {
        let org = scope.org_id().ok_or_else(no_scope)?;
        return if before.bundle.data.orgs.contains(&org) {
            Ok(Vec::new())
        } else {
            Err(no_scope())
        };
    }
    before
        .bundle
        .paths
        .ancestors(tenant, scope)
        .map_err(|_| no_scope())
}

/// Whether `who` may do `action` (an action name: `manage_access`, `write`,
/// ...) on `scope`, before the change, at the path the store holds for it.
/// Conditions on the scope's type count as false: Tutela does not have a
/// scope's field values, so the answer can only be too strict.
///
/// # Errors
///
/// 404 for an unknown scope, 400 for a type the model does not have, or a
/// 503.
pub(crate) fn decide(
    before: &Before,
    tenant: &TenantKey,
    who: &Principal,
    scope: &PathEntry,
    action: &str,
) -> Result<Decision, Problem> {
    let path = path(before, tenant, scope)?;
    let key =
        ActionKey::parse(&format!("{}:{action}", scope.type_name)).map_err(|_| unavailable())?;
    before
        .pdp
        .check(&CheckRequest {
            tenant: tenant.clone(),
            subject: who.clone(),
            actors: Vec::new(),
            action: key,
            resource: ResourceRef {
                type_name: scope.type_name.clone(),
                id: scope.id.clone(),
                path,
                attrs: Attrs::new(),
            },
            fields: Some(Vec::new()),
            at_least_revision: None,
        })
        .map_err(|e| pdp_problem(&e))
}

/// What the change made in `tx` gives beyond what `who` held before it
/// (PERMISSION-MODEL.md 7.1 step 6). Reads the tenant again in `tx`.
///
/// # Errors
///
/// A 503.
pub(crate) async fn excess(
    state: &AppState,
    tx: &TenantTx<'_>,
    before: Before,
    who: &Principal,
) -> Result<ImpactReport, Problem> {
    let tenant = tx.tenant().clone();
    let after = tutela_store::load(tx, &tenant).await?;
    let after_pdp = build(
        tenant.clone(),
        after.rev,
        Arc::clone(&before.model),
        after.data,
    )
    .await?;
    let (who, limit, paths) = (who.clone(), state.impact_work, after.paths);
    tokio::task::spawn_blocking(move || {
        tutela_pdp::grant_excess(&before.pdp, &after_pdp, &tenant, &paths, &who, limit)
    })
    .await
    .map_err(|_| unavailable())?
    .map_err(|e| pdp_problem(&e))
}

/// The most lines a refusal's detail names.
const SHOWN: usize = 5;

/// 403 `not_held`: the change would give someone what the caller does not
/// hold. The detail says what in plain words, with counts, never with a
/// principal (CONTRACTS.md 9.5).
pub(crate) fn not_held(r: &ImpactReport) -> Problem {
    let mut detail = r
        .summary()
        .into_iter()
        .take(SHOWN)
        .collect::<Vec<_>>()
        .join("; ");
    if r.lines.len() > SHOWN {
        detail.push_str(&format!("; and {} more", r.lines.len() - SHOWN));
    }
    if !r.complete {
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        detail.push_str("the check reached its bound before it could rule out more");
    }
    Problem {
        detail: Some(detail),
        ..Problem::new(
            StatusCode::FORBIDDEN,
            "not_held",
            "the change would give someone what the caller does not hold",
        )
    }
}
