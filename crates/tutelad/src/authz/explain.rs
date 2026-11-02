//! `POST /v1/authz/explain` and `POST /v1/authz/simulate` (CONTRACTS.md
//! 7.10, ADR-0028).
//!
//! Both show why an answer is what it is, and so the model and other
//! principals' assignments. So the caller's own principal needs the admin key
//! `<type>:read_audit` on the resource (PERMISSION-MODEL.md 5.3: org admins
//! for everything, scope owners for their own scope), on data that has just
//! been checked. A check needs nothing like it. An agent never holds an admin
//! key, and a delegated or an external token never passes one on.
//!
//! The path is the caller's word, so every registered scope on it must have
//! the path the store holds: otherwise a caller could put a resource under a
//! scope it owns and read the assignments of another.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tutela_contracts::decision::Decision;
use tutela_contracts::keys::ActionKey;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::{GroupKey, Model, RoleKey};
use tutela_pdp::{
    Binding, CheckRequest, Explanation, PathEntry, Pdp, ResourceRef, ScopePaths, Subject,
};
use tutela_sdk::Identity;
use tutela_store::ScopePathSnapshot;

use super::wire::{Ask, Entry, EvaluationBody, Invalid};
use super::{floor, pdp_problem, view};
use crate::api::{AppState, Problem};
use crate::cache::{ActionClass, Snapshot};
use crate::models;
use crate::telemetry::Outcome;
use crate::tenant::Tenant;

/// The most what-if assignments in one simulation.
pub const MAX_WHAT_IF: usize = 100;

/// Every registered scope on the path, and the resource itself if it is one,
/// must have the path the store holds.
fn verify_path(
    paths: &ScopePathSnapshot,
    tenant: &TenantKey,
    r: &ResourceRef,
) -> Result<(), Problem> {
    let this = PathEntry::new(r.type_name.clone(), r.id.clone());
    for (i, e) in core::iter::once(&this).chain(&r.path).enumerate() {
        if e.is_org() {
            break;
        }
        let rest = r.path.get(i..).unwrap_or_default();
        if paths
            .ancestors(tenant, e)
            .is_ok_and(|stored| stored != rest)
        {
            return Err(Problem::invalid(
                "invalid_request",
                "the path is not the one the store holds for a scope on it".to_owned(),
            ));
        }
    }
    Ok(())
}

/// May this token's own principal see why an answer on `resource` is what
/// it is?
fn may_explain(
    snapshot: &Snapshot,
    tenant: &TenantKey,
    id: &Identity,
    resource: &ResourceRef,
    need: Option<u64>,
) -> Result<(), Problem> {
    let who = models::principal(id).ok_or_else(Problem::forbidden)?;
    verify_path(&snapshot.paths, tenant, resource)?;
    let action = ActionKey::parse(&format!("{}:read_audit", resource.type_name))
        .map_err(|_| Problem::forbidden())?;
    let decision = snapshot
        .pdp
        .check(&CheckRequest {
            tenant: tenant.clone(),
            subject: who.clone(),
            actors: Vec::new(),
            action,
            resource: resource.clone(),
            fields: Some(Vec::new()),
            at_least_revision: need,
        })
        .map_err(|e| pdp_problem(&e))?;
    if decision.is_allowed() {
        Ok(())
    } else {
        Err(Problem::forbidden())
    }
}

fn counted<T>(state: &AppState, op: &'static str, r: Result<T, Problem>) -> Result<T, Problem> {
    if r.is_err() {
        state.metrics.count_decision(op, Outcome::Error);
    }
    r
}

fn outcome(allowed: bool) -> Outcome {
    if allowed {
        Outcome::Allow
    } else {
        Outcome::Deny
    }
}

/// `context` of an explanation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ExplainContext {
    /// The decision, the walks and the rules.
    pub tutela: Explanation,
}

/// The answer of `POST /v1/authz/explain`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ExplainResult {
    /// `true` exactly when the decision allows.
    pub decision: bool,
    /// The details.
    pub context: ExplainContext,
}

/// `POST /v1/authz/explain`.
///
/// # Errors
///
/// A [`Problem`]. 403 for a caller without `read_audit` on the resource.
pub async fn explain(
    state: &AppState,
    id: &Identity,
    body: EvaluationBody,
) -> Result<ExplainResult, Problem> {
    const OP: &str = "explain";
    let r = async {
        let tenant = Tenant::of(id);
        let ask = Ask::parse(body)?;
        let need = floor(id, ask.at_least);
        let view = view(state, OP, &tenant, need).await?;
        let snapshot = view.for_class(ActionClass::Admin)?;
        may_explain(snapshot, tenant.key(), id, &ask.resource, need)?;
        let e = snapshot
            .pdp
            .explain(&ask.request(tenant.key().clone(), need))
            .map_err(|e| pdp_problem(&e))?;
        Ok(ExplainResult {
            decision: e.decision.is_allowed(),
            context: ExplainContext { tutela: e },
        })
    }
    .await;
    let r = counted(state, OP, r)?;
    state.metrics.count_decision(OP, outcome(r.decision));
    Ok(r)
}

/// One assignment that is not there, for a simulation.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct WhatIf {
    /// A principal string, or `group:<key>`.
    pub subject: String,
    /// The role.
    pub role: String,
    /// Where.
    pub scope: Entry,
}

/// What a simulation changes. Every part is optional.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Candidate {
    /// A candidate manifest.
    pub source: Option<String>,
    /// Or a kept version.
    pub restore: Option<i64>,
    /// Assignments to add.
    pub add: Option<Vec<WhatIf>>,
    /// Assignment ids to take away.
    pub remove: Option<Vec<String>>,
}

/// The body of `POST /v1/authz/simulate`: an evaluation, and a candidate.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SimulateBody {
    /// The question, as for `POST /access/v1/evaluation`.
    #[serde(flatten)]
    pub evaluation: EvaluationBody,
    /// What to change.
    pub candidate: Option<Candidate>,
}

/// One answer of a simulation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Answer {
    /// `true` exactly when the decision allows.
    pub decision: bool,
    /// The details.
    pub context: AnswerContext,
}

/// `context` of one answer.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AnswerContext {
    /// The decision.
    pub tutela: Decision,
}

impl Answer {
    fn of(d: Decision) -> Self {
        Self {
            decision: d.is_allowed(),
            context: AnswerContext { tutela: d },
        }
    }
}

/// The answer of `POST /v1/authz/simulate`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SimulateResult {
    /// What the candidate would answer.
    pub decision: bool,
    /// Its details.
    pub context: AnswerContext,
    /// What the tenant answers now, from the same read.
    pub current: Answer,
    /// `true` when the two decisions differ in any field.
    pub changed: bool,
}

fn what_if(data: &mut tutela_pdp::TenantData, c: &Candidate) -> Result<(), Invalid> {
    let add = c.add.as_deref().unwrap_or_default();
    if add.len() > MAX_WHAT_IF {
        return Err(Invalid("a simulation adds at most 100 assignments"));
    }
    for id in c.remove.as_deref().unwrap_or_default() {
        let before = data.bindings.len();
        data.bindings.retain(|b| b.id.as_str() != id);
        if data.bindings.len() == before {
            return Err(Invalid(
                "`remove` names an assignment this tenant does not have",
            ));
        }
    }
    for (i, w) in add.iter().enumerate() {
        let subject = match w.subject.strip_prefix("group:") {
            Some(g) => Subject::Group(
                GroupKey::parse(g).map_err(|_| Invalid("a what-if group is not a group key"))?,
            ),
            None => Subject::Principal(
                w.subject
                    .parse()
                    .map_err(|_| Invalid("a what-if subject is not a principal"))?,
            ),
        };
        let scope = super::wire::path(std::slice::from_ref(&w.scope))?
            .pop()
            .ok_or(Invalid("a what-if scope is missing"))?;
        data.bindings.push(Binding {
            id: format!("whatif_{i}")
                .parse()
                .map_err(|_| Invalid("a what-if id"))?,
            subject,
            role: RoleKey::parse(&w.role)
                .map_err(|_| Invalid("a what-if role is not a role key"))?,
            scope,
        });
    }
    Ok(())
}

/// `POST /v1/authz/simulate`: what a candidate model, or assignments that
/// are not there, would answer. Nothing is written, and no snapshot changes:
/// two evaluators are built from one fresh read.
///
/// # Errors
///
/// A [`Problem`]. 403 for a caller without `read_audit` on the resource.
pub async fn simulate(
    state: &AppState,
    id: &Identity,
    body: SimulateBody,
) -> Result<SimulateResult, Problem> {
    const OP: &str = "simulate";
    let r = async {
        let tenant = Tenant::of(id);
        let ask = Ask::parse(body.evaluation)?;
        let need = floor(id, ask.at_least);
        {
            let view = view(state, OP, &tenant, need).await?;
            let snapshot = view.for_class(ActionClass::Admin)?;
            may_explain(snapshot, tenant.key(), id, &ask.resource, need)?;
        }
        let c = body.candidate.unwrap_or_default();
        let model: Option<Arc<Model>> = if c.source.is_some() || c.restore.is_some() {
            let (text, _) =
                models::candidate_text(state, &tenant, c.source.clone(), c.restore).await?;
            Some(Arc::new(models::compile(text).await?))
        } else {
            None
        };
        let now = models::current(state, &tenant).await?;
        if need.is_some_and(|n| now.bundle.rev < n) {
            return Err(Problem::stale("stale"));
        }
        let mut data = now.bundle.data.clone();
        what_if(&mut data, &c)?;
        let key = tenant.key().clone();
        let (rev, current, active) = (now.bundle.rev, now.bundle.data.clone(), now.model);
        let candidate = model.unwrap_or_else(|| Arc::clone(&active));
        let req = ask.request(key.clone(), None);
        let answers = tokio::task::spawn_blocking(move || {
            let mut before = Pdp::new();
            before
                .load(key.clone(), rev, active, current)
                .map_err(|e| Problem::invalid("invalid_request", e.to_string()))?;
            let mut after = Pdp::new();
            after
                .load(key, rev, candidate, data)
                .map_err(|e| Problem::invalid("invalid_request", e.to_string()))?;
            let d0 = before.check(&req).map_err(|e| pdp_problem(&e))?;
            let d1 = after.check(&req).map_err(|e| pdp_problem(&e))?;
            Ok::<_, Problem>((d0, d1))
        })
        .await
        .map_err(|_| Problem::stale("unavailable"))??;
        let (d0, d1) = answers;
        Ok(SimulateResult {
            decision: d1.is_allowed(),
            changed: d0 != d1,
            context: AnswerContext { tutela: d1 },
            current: Answer::of(d0),
        })
    }
    .await;
    let r = counted(state, OP, r)?;
    state.metrics.count_decision(OP, outcome(r.decision));
    Ok(r)
}
