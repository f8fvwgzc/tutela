//! `POST /v1/authz/write-check`: per-field verdicts for a write, and the
//! verdicts on a move and on new links (CONTRACTS.md 6.7, 7.8; ADR-0025).

use tutela_contracts::decision::Effect;
use tutela_pdp::WriteCheckRequest;
use tutela_sdk::Identity;

use super::wire::{WriteAsk, WriteCheckBody, WriteCheckResult, WriteContext};
use super::{floor, is_service, may_ask, pdp_problem, view};
use crate::api::{AppState, Problem};
use crate::cache::ActionClass;
use crate::telemetry::Outcome;
use crate::tenant::Tenant;

/// The class of a write. A move can rest on `approve_move`, and a
/// `grants_access` field needs `manage_access`: both are admin keys, so they
/// need data that has just been checked.
fn class(view: &crate::cache::View, ask: &WriteAsk) -> ActionClass {
    let def = view.model().types().get(&ask.resource.type_name);
    let guarded = ask.new_attrs.keys().any(|f| {
        def.and_then(|d| d.fields.get(f))
            .is_some_and(|f| f.grants_access)
    });
    if guarded || ask.new_path.is_some() {
        ActionClass::Admin
    } else {
        ActionClass::Write
    }
}

/// `POST /v1/authz/write-check`.
///
/// `approved_by` says who agreed to a move in the product's own flow. Only a
/// service may name them: it already speaks for its users. A person who asks
/// about itself gets no `gains`, because those name other principals.
///
/// # Errors
///
/// A [`Problem`]. An error is never an allow.
pub async fn write_check(
    state: &AppState,
    id: &Identity,
    body: WriteCheckBody,
) -> Result<WriteCheckResult, Problem> {
    const OP: &str = "write_check";
    let tenant = Tenant::of(id);
    let ask = WriteAsk::parse(body)?;
    may_ask(id, &ask.subject, &ask.actors)?;
    let service = is_service(id);
    if !ask.approved_by.is_empty() && !service {
        return Err(Problem::forbidden());
    }
    let need = floor(id, ask.at_least);
    let view = view(state, OP, &tenant, need).await?;
    let snapshot = view.for_class(class(&view, &ask)).map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        Problem::from(e)
    })?;
    let req = WriteCheckRequest {
        tenant: tenant.key().clone(),
        subject: ask.subject,
        actors: ask.actors,
        resource: ask.resource,
        new_attrs: ask.new_attrs,
        new_path: ask.new_path,
        new_links: ask.new_links,
        approved_by: ask.approved_by,
        at_least_revision: need,
    };
    let mut decision = snapshot.pdp.write_check(&req).map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        pdp_problem(&e)
    })?;
    if !service && let Some(m) = decision.moved.as_mut() {
        m.gains.clear();
    }
    let allowed = decision.effect == Effect::Allow;
    let outcome = if allowed {
        Outcome::Allow
    } else {
        Outcome::Deny
    };
    state.metrics.count_decision(OP, outcome);
    tracing::debug!(
        op = OP,
        outcome = outcome.as_str(),
        rev = decision.rev,
        "decided"
    );
    Ok(WriteCheckResult {
        decision: allowed,
        context: WriteContext { tutela: decision },
    })
}
