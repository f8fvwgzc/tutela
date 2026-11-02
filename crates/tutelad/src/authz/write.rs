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

fn entries(path: &[tutela_pdp::PathEntry]) -> Vec<String> {
    path.iter()
        .map(|e| format!("{}:{}", e.type_name, e.id))
        .collect()
}

/// The record of a write check (ADR-0034): every deny with the denied
/// fields, every move verdict, and every link deny. A write that only
/// changes allowed fields has none.
fn write_record(
    tenant: &Tenant,
    id: &Identity,
    subject: &tutela_contracts::principal::Principal,
    resource: &tutela_pdp::ResourceRef,
    approved_by: &[String],
    d: &tutela_pdp::WriteDecision,
) -> Option<crate::audit::Record> {
    let denied_fields: Vec<String> = d
        .fields
        .iter()
        .filter(|f| f.effect == Effect::Deny)
        .map(|f| f.field.to_string())
        .collect();
    let denied_links: Vec<String> = d
        .links
        .iter()
        .filter(|l| l.effect == Effect::Deny)
        .map(|l| format!("{}:{}", l.target.type_name, l.target.id))
        .collect();
    if d.effect == Effect::Allow && d.moved.is_none() && denied_links.is_empty() {
        return None;
    }
    let actor = crate::audit::actor_of(id)?;
    let reason = d
        .fields
        .iter()
        .find(|f| f.effect == Effect::Deny)
        .map(|f| f.reason.to_string())
        .or_else(|| {
            d.moved
                .as_ref()
                .filter(|m| m.effect == Effect::Deny)
                .map(|m| m.reason.to_string())
        })
        .or_else(|| {
            d.links
                .iter()
                .find(|l| l.effect == Effect::Deny)
                .map(|l| l.reason.to_string())
        })
        .unwrap_or_else(|| "not_allowed".to_owned());
    let mut rules: Vec<tutela_contracts::decision::RuleId> = d
        .fields
        .iter()
        .flat_map(|f| f.rule_ids.iter().cloned())
        .chain(d.moved.iter().flat_map(|m| m.rule_ids.iter().cloned()))
        .chain(d.links.iter().flat_map(|l| l.rule_ids.iter().cloned()))
        .collect();
    rules.sort();
    rules.dedup();
    let record = crate::audit::Record::new(
        tenant.key(),
        actor,
        &format!("{}:write", resource.type_name),
        (resource.type_name.as_str(), resource.id.as_str()),
    )
    .rules(&rules)
    .detail("subject", subject.to_string())
    .detail(
        "denied_fields",
        (!denied_fields.is_empty()).then_some(denied_fields),
    )
    .detail(
        "denied_links",
        (!denied_links.is_empty()).then_some(denied_links),
    );
    let record = match &d.moved {
        Some(m) => record.detail(
            "move",
            serde_json::json!({
                "outcome": m.outcome,
                "left": entries(&m.left),
                "entered": entries(&m.entered),
                "looser": m.looser,
                "complete": m.complete,
                "approve_at": entries(&m.approve_at),
                "approved_by": approved_by,
            }),
        ),
        None => record,
    };
    Some(if d.effect == Effect::Allow {
        record.allowed(d.rev)
    } else {
        record.denied(d.rev, &reason)
    })
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
    let req_subject = ask.subject.clone();
    let req_resource = ask.resource.clone();
    let approved_by: Vec<String> = ask.approved_by.iter().map(ToString::to_string).collect();
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
    if let Some(record) = write_record(
        &tenant,
        id,
        &req_subject,
        &req_resource,
        &approved_by,
        &decision,
    ) {
        crate::audit::write_alone(state, &tenant, vec![record]).await?;
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
