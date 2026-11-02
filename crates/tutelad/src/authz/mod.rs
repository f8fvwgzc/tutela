//! The permission decision APIs (CONTRACTS.md 7, ADR-0021).
//!
//! One code path: HTTP ([`http`]) and gRPC ([`grpc`]) only turn their own
//! messages into the types of [`wire`] and call the functions here, so the
//! two cannot disagree. Every function takes the verified [`Identity`]. The
//! tenant comes from it and from nowhere else.
//!
//! Logs here never hold a subject or a resource. The metric labels hold the
//! operation and the outcome only.

pub mod grpc;
pub mod http;
mod search;
pub mod wire;

pub use search::{search_resource, search_subject};

use axum::http::StatusCode;
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_pdp::PdpError;
use tutela_sdk::Identity;

use crate::api::{AppState, Problem};
use crate::cache::{ActionClass, Refused, View};
use crate::telemetry::Outcome;
use crate::tenant::Tenant;
use wire::{
    Ask, EvaluationBody, EvaluationResult, EvaluationsBody, EvaluationsResult, Invalid, ItemError,
};

/// The most items in one batch (CONTRACTS.md 7.3).
pub const MAX_EVALUATIONS: usize = 200;

/// May this token ask about this subject?
///
/// A service (`sa`, `key`) asks about anyone in its tenant. A person or an
/// agent asks about itself only, or one principal's token would read
/// another's permissions. A delegated token asks about its own person and
/// its own chain, in full: dropping the chain would turn "the overlap" into
/// "the person alone". An external token has no principal until token
/// exchange exists, so it cannot ask.
fn may_ask(id: &Identity, subject: &Principal, actors: &[Principal]) -> Result<(), Problem> {
    let allowed = match id {
        Identity::Access(c) => {
            matches!(
                c.sub.kind(),
                PrincipalKind::ServiceAccount | PrincipalKind::Key
            ) || (c.sub == *subject && actors.is_empty())
        }
        Identity::Delegated(c) => c.sub == *subject && c.act.chain().into_iter().eq(actors.iter()),
        _ => false,
    };
    allowed.then_some(()).ok_or_else(Problem::forbidden)
}

/// May this token list who holds a permission? That is a question about
/// many principals, so a service only.
fn may_list_subjects(id: &Identity) -> Result<(), Problem> {
    let service = matches!(
        id,
        Identity::Access(c) if matches!(
            c.sub.kind(),
            PrincipalKind::ServiceAccount | PrincipalKind::Key
        )
    );
    service.then_some(()).ok_or_else(Problem::forbidden)
}

/// The lowest revision that may answer: what the caller asked for, and the
/// token's `rev` (CONTRACTS.md 4.2).
fn floor(id: &Identity, asked: Option<u64>) -> Option<u64> {
    let token = match id {
        Identity::Access(c) => Some(c.rev),
        Identity::Delegated(c) => Some(c.rev),
        _ => None,
    };
    token.max(asked)
}

impl From<Invalid> for Problem {
    fn from(e: Invalid) -> Self {
        Self::invalid("invalid_request", e.0.to_owned())
    }
}

/// Fails closed. An unknown tenant is the caller's to fix; the rest is 503
/// with `Retry-After`.
impl From<Refused> for Problem {
    fn from(e: Refused) -> Self {
        match e {
            Refused::UnknownTenant(e) => e.into(),
            Refused::NoData => Self::stale("no_data"),
            Refused::Expired => Self::stale("expired"),
            Refused::Stale { .. } => Self::stale("stale"),
            Refused::Poisoned => Self::stale("unavailable"),
        }
    }
}

/// CONTRACTS.md 6.8: the bundle errors and a scope that cannot be placed are
/// 503, the rest 400. The detail is the evaluator's own short text, which
/// holds no field values.
fn pdp_problem(e: &PdpError) -> Problem {
    match e {
        PdpError::StaleBundle { .. } => Problem::stale("stale"),
        PdpError::ExpiredBundle => Problem::stale("expired"),
        PdpError::NoBundle => Problem::stale("no_data"),
        PdpError::UnsupportedBundle => Problem::stale("unavailable"),
        PdpError::UnknownType(_) | PdpError::UnknownAction(_) => {
            Problem::invalid("unknown_key", e.to_string())
        }
        // The tenant's scopes cannot be placed. Its text names a scope.
        PdpError::ScopePath { .. } => Problem::stale("unavailable"),
        PdpError::FilterTooLarge(_) => Problem::invalid("filter_too_large", e.to_string()),
        _ => Problem::invalid("invalid_request", e.to_string()),
    }
}

fn count(state: &AppState, op: &'static str, result: &EvaluationResult) {
    let outcome = match (&result.context.tutela, result.decision) {
        (None, _) => Outcome::Error,
        (Some(_), true) => Outcome::Allow,
        (Some(_), false) => Outcome::Deny,
    };
    state.metrics.count_decision(op, outcome);
    tracing::debug!(
        op,
        outcome = outcome.as_str(),
        rev = result.context.tutela.as_ref().map(|d| d.rev),
        reason = result.context.tutela.as_ref().map(|d| d.reason.code()),
        "decided"
    );
}

/// The view for `need`, counting a refusal as an error outcome.
async fn view(
    state: &AppState,
    op: &'static str,
    tenant: &Tenant,
    need: Option<u64>,
) -> Result<View, Problem> {
    state.cache.view(tenant, need).await.map_err(|e| {
        state.metrics.count_decision(op, Outcome::Error);
        tracing::warn!(op, reason = %e, "no answer: failing closed");
        e.into()
    })
}

/// `POST /access/v1/evaluation`.
///
/// # Errors
///
/// A [`Problem`]. An error is never an allow.
pub async fn evaluate(
    state: &AppState,
    id: &Identity,
    body: EvaluationBody,
) -> Result<EvaluationResult, Problem> {
    const OP: &str = "evaluation";
    let tenant = Tenant::of(id);
    let ask = Ask::parse(body)?;
    may_ask(id, &ask.subject, &ask.actors)?;
    let need = floor(id, ask.at_least);
    let view = view(state, OP, &tenant, need).await?;
    let snapshot = view
        .for_class(ActionClass::of(view.model(), &ask.action))
        .map_err(|e| {
            state.metrics.count_decision(OP, Outcome::Error);
            Problem::from(e)
        })?;
    let decision = snapshot
        .pdp
        .check(&ask.request(tenant.key().clone(), need))
        .map_err(|e| {
            state.metrics.count_decision(OP, Outcome::Error);
            pdp_problem(&e)
        })?;
    let result = EvaluationResult::of(decision);
    count(state, OP, &result);
    Ok(result)
}

/// `options.evaluations_semantic`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Semantic {
    ExecuteAll,
    DenyOnFirstDeny,
    PermitOnFirstPermit,
}

impl Semantic {
    fn parse(body: &EvaluationsBody) -> Result<Self, Problem> {
        let text = body
            .options
            .as_ref()
            .and_then(|o| o.evaluations_semantic.as_deref());
        match text {
            None | Some("execute_all") => Ok(Self::ExecuteAll),
            Some("deny_on_first_deny") => Ok(Self::DenyOnFirstDeny),
            Some("permit_on_first_permit") => Ok(Self::PermitOnFirstPermit),
            Some(_) => Err(Invalid("`options.evaluations_semantic` is not known").into()),
        }
    }

    const fn stops_at(self, result: &EvaluationResult) -> bool {
        match self {
            Self::ExecuteAll => false,
            Self::DenyOnFirstDeny => !result.decision,
            Self::PermitOnFirstPermit => result.decision,
        }
    }
}

/// `POST /access/v1/evaluations`.
///
/// One view answers the whole batch, so its results share a revision.
/// A bad item gets its own error and never an allow; other items still run
/// (AuthZEN 1.0 section 7). The answers that fail the whole call are the
/// ones about the call: too many items, a question this token may not ask,
/// and no data to decide on.
///
/// # Errors
///
/// A [`Problem`].
pub async fn evaluations(
    state: &AppState,
    id: &Identity,
    mut body: EvaluationsBody,
) -> Result<EvaluationsResult, Problem> {
    const OP: &str = "evaluations";
    let semantic = Semantic::parse(&body)?;
    let items = body.evaluations.take().unwrap_or_default();
    if items.is_empty() {
        let result = evaluate(state, id, body.defaults()).await?;
        return Ok(EvaluationsResult::One(result));
    }
    if items.len() > MAX_EVALUATIONS {
        return Err(Problem::invalid(
            "too_many_items",
            format!("a batch holds at most {MAX_EVALUATIONS} items"),
        ));
    }
    let defaults = body.defaults();
    let asks: Vec<Result<Ask, Invalid>> = items
        .into_iter()
        .map(|item| Ask::parse(item.or(&defaults)))
        .collect();
    // Every question is judged before any is answered.
    for ask in asks.iter().flatten() {
        may_ask(id, &ask.subject, &ask.actors)?;
    }
    let need = asks
        .iter()
        .flatten()
        .fold(floor(id, None), |n, a| n.max(a.at_least));
    let tenant = Tenant::of(id);
    let view = view(state, OP, &tenant, need).await?;
    let class = asks.iter().flatten().fold(ActionClass::Read, |c, a| {
        c.stricter(ActionClass::of(view.model(), &a.action))
    });
    let snapshot = view.for_class(class).map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        Problem::from(e)
    })?;

    let mut results = Vec::with_capacity(asks.len());
    for ask in asks {
        let result = match ask {
            Err(e) => EvaluationResult::failed(ItemError {
                status: StatusCode::BAD_REQUEST.as_u16(),
                message: e.0.to_owned(),
            }),
            Ok(ask) => match snapshot.pdp.check(&ask.request(tenant.key().clone(), need)) {
                Ok(decision) => EvaluationResult::of(decision),
                Err(e) => {
                    let problem = pdp_problem(&e);
                    if problem.status.is_server_error() {
                        state.metrics.count_decision(OP, Outcome::Error);
                        return Err(problem);
                    }
                    EvaluationResult::failed(ItemError {
                        status: problem.status.as_u16(),
                        message: e.to_string(),
                    })
                }
            },
        };
        count(state, OP, &result);
        let stop = semantic.stops_at(&result);
        results.push(result);
        if stop {
            break;
        }
    }
    Ok(EvaluationsResult::Many {
        evaluations: results,
    })
}

#[cfg(test)]
mod tests {
    use tutela_contracts::claims::{Actor, DelegatedClaims};
    use tutela_contracts::tenant::TenantKey;
    use tutela_sdk::ExternalToken;

    use super::*;

    const USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
    const OTHER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7082";
    const AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";

    fn p(s: &str) -> Principal {
        s.parse().unwrap()
    }

    fn external() -> Identity {
        Identity::External(ExternalToken {
            tenant: TenantKey::new(
                "https://auth.example.test".parse().unwrap(),
                "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".parse().unwrap(),
            ),
            sub: USER.to_owned(),
            azp: None,
            exp: 0,
        })
    }

    fn delegated() -> Identity {
        let claims = serde_json::json!({
            "iss": "https://auth.example.test",
            "sub": USER,
            "aud": "tutela-authz",
            "azp": "crm-web",
            "exp": 1_000, "iat": 900, "nbf": 900,
            "jti": "0193a1b2-c3d4-7123-8456-789abcdef012",
            "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
            "epoch": 0, "rev": 4,
            "act": {"sub": AGENT},
            "cap": {},
            "run_id": "run-1",
        });
        let parsed: Result<DelegatedClaims, _> = serde_json::from_value(claims);
        Identity::Delegated(Box::new(parsed.unwrap()))
    }

    #[test]
    fn tm09_a_delegated_token_cannot_shed_its_agent() {
        let id = delegated();
        let actor: Vec<Principal> = Actor::new(p(AGENT)).chain().into_iter().cloned().collect();
        assert!(may_ask(&id, &p(USER), &actor).is_ok());
        // Without the chain the answer would be the person's alone.
        assert!(may_ask(&id, &p(USER), &[]).is_err());
        assert!(may_ask(&id, &p(OTHER), &actor).is_err());
        assert_eq!(floor(&id, Some(2)), Some(4));
        assert_eq!(floor(&id, Some(9)), Some(9));
    }

    #[test]
    fn an_external_token_has_no_principal_yet_so_it_cannot_ask() {
        assert!(may_ask(&external(), &p(USER), &[]).is_err());
        assert_eq!(floor(&external(), Some(9)), Some(9));
    }
}
