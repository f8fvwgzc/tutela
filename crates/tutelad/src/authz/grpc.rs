//! `tutela.authz.v1` (CONTRACTS.md 7.6): thin adapters over [`crate::authz`].
//! Each call turns its messages into the types of [`super::wire`], so it
//! runs the same code as HTTP.

use tonic::{Code, Request, Response, Status};
use tutela_contracts::claims::Actor;
use tutela_contracts::decision::{Decision, Obligation};
use tutela_sdk::Identity;

use super::wire;
use crate::api::{AppState, Problem};

/// The generated messages and services.
#[allow(
    missing_docs,
    unreachable_pub,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
pub mod pb {
    tonic::include_proto!("tutela.authz.v1");
}

use pb::authz_server::Authz;

/// The gRPC service.
#[derive(Clone, Debug)]
pub struct AuthzService {
    state: AppState,
}

impl AuthzService {
    /// A service over `state`.
    #[must_use]
    pub const fn new(state: AppState) -> Self {
        Self { state }
    }

    /// The server, ready to add to the routes.
    #[must_use]
    pub fn server(state: AppState) -> pb::authz_server::AuthzServer<Self> {
        pb::authz_server::AuthzServer::new(Self::new(state))
    }
}

impl From<Problem> for Status {
    fn from(p: Problem) -> Self {
        let code = match p.status.as_u16() {
            400 | 413 | 415 => Code::InvalidArgument,
            401 => Code::Unauthenticated,
            403 => Code::PermissionDenied,
            404 => Code::NotFound,
            _ => Code::Unavailable,
        };
        let text = p.detail.unwrap_or_else(|| p.title.to_owned());
        Self::new(code, format!("{}: {text}", p.code))
    }
}

/// The verified identity. `AuthLayer` ran first, so a request with none
/// never gets here; if one does, it is refused.
fn identity<T>(req: &Request<T>) -> Result<Identity, Status> {
    req.extensions()
        .get::<Identity>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("a valid bearer token is required"))
}

fn actor(a: pb::Actor) -> Result<Actor, Status> {
    let sub = a
        .sub
        .parse()
        .map_err(|_| Status::invalid_argument("invalid_request: an actor is not a principal"))?;
    Ok(Actor {
        sub,
        act: a.act.map(|n| actor(*n).map(Box::new)).transpose()?,
    })
}

fn subject(s: pb::Subject) -> Result<wire::Subject, Status> {
    Ok(wire::Subject {
        kind: s.r#type,
        id: (!s.id.is_empty()).then_some(s.id),
        properties: s
            .act
            .map(actor)
            .transpose()?
            .map(|a| wire::SubjectProperties { act: Some(a) }),
    })
}

fn attr(v: pb::AttrValue) -> serde_json::Value {
    use pb::attr_value::Value;
    match v.value {
        None | Some(Value::NullValue(_)) => serde_json::Value::Null,
        Some(Value::StringValue(s)) => s.into(),
        Some(Value::IntegerValue(i)) => i.into(),
        Some(Value::BooleanValue(b)) => b.into(),
        Some(Value::StringsValue(l)) => l.values.into(),
    }
}

fn resource(r: pb::Resource) -> wire::Resource {
    wire::Resource {
        kind: r.r#type,
        id: (!r.id.is_empty()).then_some(r.id),
        properties: Some(wire::ResourceProperties {
            path: Some(
                r.path
                    .into_iter()
                    .map(|e| wire::Entry {
                        kind: e.r#type,
                        id: e.id,
                    })
                    .collect(),
            ),
            attrs: Some(r.attrs.into_iter().map(|(k, v)| (k, attr(v))).collect()),
        }),
    }
}

fn context(c: pb::Context) -> wire::Context {
    wire::Context {
        fields: c.fields.map(|f| f.values),
        at_least_revision: c.at_least_revision,
    }
}

fn evaluation(r: pb::EvaluationRequest) -> Result<wire::EvaluationBody, Status> {
    Ok(wire::EvaluationBody {
        subject: r.subject.map(subject).transpose()?,
        action: r.action.map(|a| wire::Action { name: a.name }),
        resource: r.resource.map(resource),
        context: r.context.map(context),
    })
}

fn obligation(o: &Obligation) -> pb::Obligation {
    let mut out = pb::Obligation {
        kind: o.kind().to_owned(),
        ..pb::Obligation::default()
    };
    match o {
        Obligation::Audit {
            on_behalf_of,
            reason_required,
        } => {
            out.on_behalf_of = on_behalf_of
                .as_ref()
                .map_or_else(String::new, ToString::to_string);
            out.reason_required = *reason_required;
        }
        Obligation::Label { value } => out.value = value.to_string(),
        Obligation::Restricted { fields } => {
            out.fields = fields.iter().map(ToString::to_string).collect();
        }
        _ => {}
    }
    out
}

fn decision(d: Decision) -> pb::Decision {
    pb::Decision {
        effect: d.effect.as_str().to_owned(),
        level: d.level.to_string(),
        field_mask: Some(pb::FieldMask {
            read: d
                .field_mask
                .read()
                .iter()
                .map(ToString::to_string)
                .collect(),
            write: d
                .field_mask
                .write()
                .iter()
                .map(ToString::to_string)
                .collect(),
        }),
        rule_ids: d.rule_ids.iter().map(ToString::to_string).collect(),
        reason: d.reason.as_str().to_owned(),
        rev: d.rev,
        obligations: d.obligations.iter().map(obligation).collect(),
    }
}

fn result(r: wire::EvaluationResult) -> pb::Evaluation {
    pb::Evaluation {
        decision: r.decision,
        context: Some(pb::EvaluationContext {
            tutela: r.context.tutela.map(decision),
            error: r.context.error.map(|e| pb::ItemError {
                status: u32::from(e.status),
                message: e.message,
            }),
        }),
    }
}

fn search(r: pb::SearchRequest) -> Result<wire::SearchBody, Status> {
    Ok(wire::SearchBody {
        subject: r.subject.map(subject).transpose()?,
        action: r.action.map(|a| wire::Action { name: a.name }),
        resource: r.resource.map(resource),
        context: r.context.map(context),
        page: r.page.map(|p| wire::Page {
            token: (!p.token.is_empty()).then_some(p.token),
            limit: Some(u64::from(p.limit)),
        }),
    })
}

fn page(p: wire::PageOut) -> pb::PageResponse {
    pb::PageResponse {
        next_token: p.next_token,
        count: u32::try_from(p.count).unwrap_or(u32::MAX),
    }
}

#[tonic::async_trait]
impl Authz for AuthzService {
    async fn evaluate(
        &self,
        req: Request<pb::EvaluationRequest>,
    ) -> Result<Response<pb::Evaluation>, Status> {
        let id = identity(&req)?;
        let body = evaluation(req.into_inner())?;
        let out = super::evaluate(&self.state, &id, body).await?;
        Ok(Response::new(result(out)))
    }

    async fn evaluations(
        &self,
        req: Request<pb::EvaluationsRequest>,
    ) -> Result<Response<pb::EvaluationsResponse>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = wire::EvaluationsBody {
            subject: r.subject.map(subject).transpose()?,
            action: r.action.map(|a| wire::Action { name: a.name }),
            resource: r.resource.map(resource),
            context: r.context.map(context),
            evaluations: Some(
                r.evaluations
                    .into_iter()
                    .map(evaluation)
                    .collect::<Result<_, _>>()?,
            ),
            options: r.options.map(|o| wire::Options {
                evaluations_semantic: Some(o.evaluations_semantic),
            }),
        };
        let out = match super::evaluations(&self.state, &id, body).await? {
            wire::EvaluationsResult::One(one) => vec![result(one)],
            wire::EvaluationsResult::Many { evaluations } => {
                evaluations.into_iter().map(result).collect()
            }
        };
        Ok(Response::new(pb::EvaluationsResponse { evaluations: out }))
    }

    async fn search_resource(
        &self,
        req: Request<pb::SearchRequest>,
    ) -> Result<Response<pb::SearchResourceResponse>, Status> {
        let id = identity(&req)?;
        let out = super::search_resource(&self.state, &id, search(req.into_inner())?).await?;
        let filter_json = serde_json::to_string(&out.context.tutela.filter)
            .map_err(|_| Status::unavailable("unavailable: the filter cannot be written"))?;
        Ok(Response::new(pb::SearchResourceResponse {
            results: out
                .results
                .into_iter()
                .map(|e| pb::PathEntry {
                    r#type: e.kind,
                    id: e.id,
                })
                .collect(),
            page: Some(page(out.page)),
            filter_json,
            rev: out.context.tutela.rev,
        }))
    }

    async fn search_subject(
        &self,
        req: Request<pb::SearchRequest>,
    ) -> Result<Response<pb::SearchSubjectResponse>, Status> {
        let id = identity(&req)?;
        let out = super::search_subject(&self.state, &id, search(req.into_inner())?).await?;
        Ok(Response::new(pb::SearchSubjectResponse {
            results: out
                .results
                .into_iter()
                .map(|s| pb::Subject {
                    r#type: s.kind,
                    id: s.id,
                    act: None,
                })
                .collect(),
            page: Some(page(out.page)),
            rev: out.context.tutela.rev,
        }))
    }
}
