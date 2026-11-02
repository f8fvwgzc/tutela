//! `tutela.admin.v1` (CONTRACTS.md 7.13): thin adapters over
//! [`crate::admin`] and [`crate::models`]. Each method turns its message
//! into the body of its HTTP route and runs the same function, so the two
//! never answer differently. Reports go back as the route's JSON text.

use serde::Serialize;
use tonic::{Request, Response, Status};

use super::observed;
use super::wire::{
    AgentsQuery, BoundaryBody, PrincipalBody, PrincipalOut, RegisterAgentBody, ResourceTypesBody,
    ScopeRef, SetDisabledBody,
};
use crate::api::AppState;
use crate::authz::grpc::identity;
use crate::models::http::MODEL_BODY_LIMIT;
use crate::models::wire::{ApproveBody, PublishBody, SettingsBody};

/// The generated messages and services.
#[allow(
    missing_docs,
    unreachable_pub,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
pub mod pb {
    tonic::include_proto!("tutela.admin.v1");
}

use pb::admin_server::Admin;

/// The gRPC path of every method: the admin token check applies to it
/// (`api::api_router`).
pub const PATH_PREFIX: &str = "/tutela.admin.v1.Admin/";

/// The gRPC service.
#[derive(Clone, Debug)]
pub struct AdminService {
    state: AppState,
}

impl AdminService {
    /// The server, ready to add to the routes. A message may be as large as
    /// a model's HTTP body.
    #[must_use]
    pub fn server(state: AppState) -> pb::admin_server::AdminServer<Self> {
        pb::admin_server::AdminServer::new(Self { state })
            .max_decoding_message_size(MODEL_BODY_LIMIT)
            .max_encoding_message_size(MODEL_BODY_LIMIT)
    }
}

/// The JSON answer of a route, as text.
fn json<T: Serialize>(v: &T) -> Result<Response<pb::JsonResult>, Status> {
    serde_json::to_string(v)
        .map(|result_json| Response::new(pb::JsonResult { result_json }))
        .map_err(|_| Status::unavailable("unavailable: the answer cannot be written"))
}

fn state_of(p: PrincipalOut) -> pb::PrincipalState {
    pb::PrincipalState {
        principal: p.principal,
        epoch: p.epoch,
        disabled: p.disabled,
        workload: p.workload.unwrap_or_default(),
        rev: p.rev.unwrap_or(0),
    }
}

fn some(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn change(r: pb::ModelChangeRequest) -> PublishBody {
    PublishBody {
        source: r.source,
        restore: r.restore,
        expected_version: r.expected_version,
        approval: r.approval,
    }
}

#[tonic::async_trait]
impl Admin for AdminService {
    async fn register_agent(
        &self,
        req: Request<pb::RegisterAgentRequest>,
    ) -> Result<Response<pb::PrincipalState>, Status> {
        let id = identity(&req)?;
        let body = RegisterAgentBody {
            workload: some(req.into_inner().workload),
        };
        let out = super::principals::register_agent(&self.state, &id, body).await;
        Ok(Response::new(state_of(observed(
            &self.state,
            "register_agent",
            out,
        )?)))
    }

    async fn list_agents(
        &self,
        req: Request<pb::ListAgentsRequest>,
    ) -> Result<Response<pb::ListAgentsResponse>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let q = AgentsQuery {
            after: some(r.after),
            limit: (r.limit > 0).then(|| usize::try_from(r.limit).unwrap_or(usize::MAX)),
            workload: some(r.workload),
        };
        let out = observed(
            &self.state,
            "list_agents",
            super::principals::agents(&self.state, &id, q).await,
        )?;
        Ok(Response::new(pb::ListAgentsResponse {
            agents: out.agents.into_iter().map(state_of).collect(),
            next_after: out.next_after.unwrap_or_default(),
        }))
    }

    async fn get_principal(
        &self,
        req: Request<pb::PrincipalRequest>,
    ) -> Result<Response<pb::PrincipalState>, Status> {
        let id = identity(&req)?;
        let body = PrincipalBody {
            principal: some(req.into_inner().principal),
        };
        let out = super::principals::principal(&self.state, &id, body).await;
        Ok(Response::new(state_of(observed(
            &self.state,
            "get_principal",
            out,
        )?)))
    }

    async fn set_disabled(
        &self,
        req: Request<pb::SetDisabledRequest>,
    ) -> Result<Response<pb::PrincipalState>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = SetDisabledBody {
            principal: some(r.principal),
            disabled: Some(r.disabled),
        };
        let out = super::principals::set_disabled(&self.state, &id, body).await;
        Ok(Response::new(state_of(observed(
            &self.state,
            "set_disabled",
            out,
        )?)))
    }

    async fn revoke_sessions(
        &self,
        req: Request<pb::PrincipalRequest>,
    ) -> Result<Response<pb::PrincipalState>, Status> {
        let id = identity(&req)?;
        let body = PrincipalBody {
            principal: some(req.into_inner().principal),
        };
        let out = super::principals::revoke_sessions(&self.state, &id, body).await;
        Ok(Response::new(state_of(observed(
            &self.state,
            "revoke_sessions",
            out,
        )?)))
    }

    async fn list_model_versions(
        &self,
        req: Request<pb::ListModelVersionsRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let limit = r.limit.map(|l| usize::try_from(l).unwrap_or(usize::MAX));
        let out = crate::models::versions(&self.state, &id, r.before, limit).await;
        json(&crate::models::observed(&self.state, "versions", out)?)
    }

    async fn get_model_version(
        &self,
        req: Request<pb::GetModelVersionRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let version = req.into_inner().version;
        let out = crate::models::version(&self.state, &id, version).await;
        json(&crate::models::observed(&self.state, "version", out)?)
    }

    async fn model_impact(
        &self,
        req: Request<pb::ModelChangeRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let out = crate::models::impact(&self.state, &id, change(req.into_inner())).await;
        json(&crate::models::observed(&self.state, "impact", out)?)
    }

    async fn publish_model(
        &self,
        req: Request<pb::ModelChangeRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let out = crate::models::publish(&self.state, &id, change(req.into_inner())).await;
        json(&crate::models::observed(&self.state, "publish", out)?)
    }

    async fn get_model_settings(
        &self,
        req: Request<pb::GetModelSettingsRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let out = crate::models::settings(&self.state, &id).await;
        json(&crate::models::observed(&self.state, "settings", out)?)
    }

    async fn put_model_settings(
        &self,
        req: Request<pb::PutModelSettingsRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let body = SettingsBody {
            two_person: Some(req.into_inner().two_person),
        };
        let out = crate::models::set_settings(&self.state, &id, body).await;
        json(&crate::models::observed(&self.state, "set_settings", out)?)
    }

    async fn propose_model(
        &self,
        req: Request<pb::ModelChangeRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let out = crate::models::propose(&self.state, &id, change(req.into_inner())).await;
        json(&crate::models::observed(&self.state, "propose", out)?)
    }

    async fn list_proposals(
        &self,
        req: Request<pb::ListProposalsRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let out = crate::models::proposals(&self.state, &id).await;
        json(&crate::models::observed(&self.state, "proposals", out)?)
    }

    async fn get_proposal(
        &self,
        req: Request<pb::ProposalRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let pid = req.into_inner().id;
        let out = crate::models::proposal(&self.state, &id, &pid).await;
        json(&crate::models::observed(&self.state, "proposal", out)?)
    }

    async fn approve_proposal(
        &self,
        req: Request<pb::ApproveProposalRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = ApproveBody {
            approval: r.approval,
        };
        let out = crate::models::approve(&self.state, &id, &r.id, body).await;
        json(&crate::models::observed(&self.state, "approve", out)?)
    }

    async fn reject_proposal(
        &self,
        req: Request<pb::ProposalRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let pid = req.into_inner().id;
        let out = crate::models::reject(&self.state, &id, &pid).await;
        json(&crate::models::observed(&self.state, "reject", out)?)
    }

    async fn put_resource_types(
        &self,
        req: Request<pb::PutResourceTypesRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let types = serde_json::from_str(&r.types_json).map_err(|_| {
            Status::invalid_argument("invalid_request: `types_json` is not a JSON object")
        })?;
        let body = ResourceTypesBody {
            types: Some(types),
            expected_version: r.expected_version,
        };
        let out = super::types::put_resource_types(&self.state, &id, body).await;
        json(&observed(&self.state, "put_resource_types", out)?)
    }

    async fn set_boundary(
        &self,
        req: Request<pb::SetBoundaryRequest>,
    ) -> Result<Response<pb::RevResponse>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = BoundaryBody {
            scope: r.scope.map(|s| ScopeRef {
                kind: s.r#type,
                id: s.id,
            }),
            moves_out: some(r.moves_out),
            moves_in: some(r.moves_in),
            on_looser: some(r.on_looser),
            links_from: some(r.links_from),
        };
        let out = super::boundaries::set_boundary(&self.state, &id, body).await;
        let rev = observed(&self.state, "set_boundary", out)?.rev;
        Ok(Response::new(pb::RevResponse { rev }))
    }
}
