//! `tutela.admin.v1` (CONTRACTS.md 7.13): thin adapters over
//! [`crate::admin`] and [`crate::models`]. Each method turns its message
//! into the body of its HTTP route and runs the same function, so the two
//! never answer differently. Reports go back as the route's JSON text.

use serde::Serialize;
use tonic::{Request, Response, Status};

use super::observed;
use super::wire::{
    AgentsQuery, AssignBody, AssignmentsQuery, BoundaryBody, DeliveriesQuery, DeliveryOut,
    ExpiryBody, GroupBody, GroupsQuery, MemberBody, MembersQuery, MoveScopeBody, NameBody, OrgOut,
    PrincipalBody, PrincipalOut, PrivateBody, PutScopeBody, RegisterAgentBody, RegisterWebhookBody,
    ResourceTypesBody, RolesQuery, RotateBody, ScopeBody, ScopeRef, ScopesQuery, SetDisabledBody,
    TenantOut, WebhookOut, WebhookSecretOut,
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

fn tenant_state(t: TenantOut) -> pb::TenantState {
    pb::TenantState {
        tid: t.tid,
        iss: t.iss,
        name: t.name.unwrap_or_default(),
        created_at: t.created_at.unwrap_or_default(),
        purge_after: t.purge_after.unwrap_or_default(),
    }
}

fn org_state(o: OrgOut) -> pb::OrgState {
    pb::OrgState {
        org: o.org,
        name: o.name.unwrap_or_default(),
        created_at: o.created_at.unwrap_or_default(),
        deleted_at: o.deleted_at.unwrap_or_default(),
        purge_after: o.purge_after.unwrap_or_default(),
        purged_at: o.purged_at.unwrap_or_default(),
        rev: o.rev.unwrap_or(0),
    }
}

fn webhook(w: WebhookOut) -> pb::Webhook {
    pb::Webhook {
        id: w.id,
        url: w.url,
        types: w.types,
        disabled: w.disabled,
        created_by: w.created_by,
    }
}

fn with_secret(w: WebhookSecretOut) -> pb::WebhookSecret {
    pb::WebhookSecret {
        webhook: Some(webhook(w.webhook)),
        secret: w.secret,
    }
}

fn delivery(d: DeliveryOut) -> pb::Delivery {
    pb::Delivery {
        webhook: d.webhook,
        seq: d.seq,
        state: d.state,
        attempts: d.attempts,
        last_status: d.last_status.map_or(0, u32::from),
        last_error: d.last_error.unwrap_or_default(),
    }
}

fn some(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn scope_ref(s: Option<pb::PathEntry>) -> Option<ScopeRef> {
    s.map(|s| ScopeRef {
        kind: s.r#type,
        id: s.id,
    })
}

fn limit(n: u32) -> Option<usize> {
    (n != 0).then(|| usize::try_from(n).unwrap_or(usize::MAX))
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

    async fn get_tenant(
        &self,
        req: Request<pb::GetTenantRequest>,
    ) -> Result<Response<pb::TenantState>, Status> {
        let id = identity(&req)?;
        let out = super::lifecycle::tenant(&self.state, &id).await;
        Ok(Response::new(tenant_state(observed(
            &self.state,
            "get_tenant",
            out,
        )?)))
    }

    async fn update_tenant(
        &self,
        req: Request<pb::UpdateTenantRequest>,
    ) -> Result<Response<pb::TenantState>, Status> {
        let id = identity(&req)?;
        let body = NameBody {
            name: some(req.into_inner().name),
        };
        let out = super::lifecycle::update_tenant(&self.state, &id, body).await;
        Ok(Response::new(tenant_state(observed(
            &self.state,
            "update_tenant",
            out,
        )?)))
    }

    async fn delete_tenant(
        &self,
        req: Request<pb::DeleteTenantRequest>,
    ) -> Result<Response<pb::TenantState>, Status> {
        let id = identity(&req)?;
        let out = super::lifecycle::delete_tenant(&self.state, &id).await;
        Ok(Response::new(tenant_state(observed(
            &self.state,
            "delete_tenant",
            out,
        )?)))
    }

    async fn list_orgs(
        &self,
        req: Request<pb::ListOrgsRequest>,
    ) -> Result<Response<pb::ListOrgsResponse>, Status> {
        let id = identity(&req)?;
        let out = observed(
            &self.state,
            "list_orgs",
            super::lifecycle::orgs(&self.state, &id).await,
        )?;
        Ok(Response::new(pb::ListOrgsResponse {
            orgs: out.orgs.into_iter().map(org_state).collect(),
        }))
    }

    async fn create_org(
        &self,
        req: Request<pb::CreateOrgRequest>,
    ) -> Result<Response<pb::OrgState>, Status> {
        let id = identity(&req)?;
        let body = NameBody {
            name: some(req.into_inner().name),
        };
        let out = super::lifecycle::create_org(&self.state, &id, body).await;
        Ok(Response::new(org_state(observed(
            &self.state,
            "create_org",
            out,
        )?)))
    }

    async fn update_org(
        &self,
        req: Request<pb::UpdateOrgRequest>,
    ) -> Result<Response<pb::OrgState>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = NameBody { name: some(r.name) };
        let out = super::lifecycle::update_org(&self.state, &id, &r.org, body).await;
        Ok(Response::new(org_state(observed(
            &self.state,
            "update_org",
            out,
        )?)))
    }

    async fn delete_org(
        &self,
        req: Request<pb::OrgRequest>,
    ) -> Result<Response<pb::OrgState>, Status> {
        let id = identity(&req)?;
        let org = req.into_inner().org;
        let out = super::lifecycle::delete_org(&self.state, &id, &org).await;
        Ok(Response::new(org_state(observed(
            &self.state,
            "delete_org",
            out,
        )?)))
    }

    async fn restore_org(
        &self,
        req: Request<pb::OrgRequest>,
    ) -> Result<Response<pb::OrgState>, Status> {
        let id = identity(&req)?;
        let org = req.into_inner().org;
        let out = super::lifecycle::restore_org(&self.state, &id, &org).await;
        Ok(Response::new(org_state(observed(
            &self.state,
            "restore_org",
            out,
        )?)))
    }

    async fn delete_user(
        &self,
        req: Request<pb::PrincipalRequest>,
    ) -> Result<Response<pb::PrincipalState>, Status> {
        let id = identity(&req)?;
        let body = PrincipalBody {
            principal: some(req.into_inner().principal),
        };
        let out = super::lifecycle::delete_user(&self.state, &id, body).await;
        Ok(Response::new(state_of(observed(
            &self.state,
            "delete_user",
            out,
        )?)))
    }

    async fn register_webhook(
        &self,
        req: Request<pb::RegisterWebhookRequest>,
    ) -> Result<Response<pb::WebhookSecret>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = RegisterWebhookBody {
            url: some(r.url),
            types: Some(r.types),
        };
        let out = super::webhooks::register(&self.state, &id, body).await;
        Ok(Response::new(with_secret(observed(
            &self.state,
            "register_webhook",
            out,
        )?)))
    }

    async fn list_webhooks(
        &self,
        req: Request<pb::ListWebhooksRequest>,
    ) -> Result<Response<pb::ListWebhooksResponse>, Status> {
        let id = identity(&req)?;
        let out = observed(
            &self.state,
            "list_webhooks",
            super::webhooks::list(&self.state, &id).await,
        )?;
        Ok(Response::new(pb::ListWebhooksResponse {
            webhooks: out.webhooks.into_iter().map(webhook).collect(),
        }))
    }

    async fn rotate_webhook_secret(
        &self,
        req: Request<pb::RotateWebhookSecretRequest>,
    ) -> Result<Response<pb::WebhookSecret>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = RotateBody {
            overlap_secs: r.overlap_secs,
        };
        let out = super::webhooks::rotate(&self.state, &id, &r.id, body).await;
        Ok(Response::new(with_secret(observed(
            &self.state,
            "rotate_webhook",
            out,
        )?)))
    }

    async fn disable_webhook(
        &self,
        req: Request<pb::WebhookRequest>,
    ) -> Result<Response<pb::Webhook>, Status> {
        let id = identity(&req)?;
        let wid = req.into_inner().id;
        let out = super::webhooks::disable(&self.state, &id, &wid).await;
        Ok(Response::new(webhook(observed(
            &self.state,
            "disable_webhook",
            out,
        )?)))
    }

    async fn list_deliveries(
        &self,
        req: Request<pb::ListDeliveriesRequest>,
    ) -> Result<Response<pb::ListDeliveriesResponse>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let q = DeliveriesQuery {
            state: r.dead_only.then(|| "dead".to_owned()),
            after: Some(r.after),
            limit: (r.limit > 0).then(|| usize::try_from(r.limit).unwrap_or(usize::MAX)),
        };
        let out = observed(
            &self.state,
            "list_deliveries",
            super::webhooks::deliveries(&self.state, &id, &r.id, q).await,
        )?;
        Ok(Response::new(pb::ListDeliveriesResponse {
            deliveries: out.deliveries.into_iter().map(delivery).collect(),
            next_after: out.next_after.unwrap_or(0),
        }))
    }

    async fn redeliver(
        &self,
        req: Request<pb::RedeliverRequest>,
    ) -> Result<Response<pb::Delivery>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let out = super::webhooks::redeliver(&self.state, &id, &r.id, r.seq).await;
        Ok(Response::new(delivery(observed(
            &self.state,
            "redeliver",
            out,
        )?)))
    }

    async fn list_scopes(
        &self,
        req: Request<pb::ListScopesRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let q = ScopesQuery {
            under: some(r.under),
            after: some(r.after),
            limit: limit(r.limit),
        };
        let out = super::scopes::list(&self.state, &id, q).await;
        json(&observed(&self.state, "list_scopes", out)?)
    }

    async fn put_scope(
        &self,
        req: Request<pb::PutScopeRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = PutScopeBody {
            scope: scope_ref(r.scope),
            parent: scope_ref(r.parent),
            private: r.private,
        };
        let out = super::scopes::put(&self.state, &id, body).await;
        json(&observed(&self.state, "put_scope", out)?)
    }

    async fn move_scope(
        &self,
        req: Request<pb::MoveScopeRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = MoveScopeBody {
            scope: scope_ref(r.scope),
            parent: scope_ref(r.parent),
            approved_by: (!r.approved_by.is_empty()).then_some(r.approved_by),
        };
        let out = super::scopes::move_scope(&self.state, &id, body).await;
        json(&observed(&self.state, "move_scope", out)?)
    }

    async fn delete_scope(
        &self,
        req: Request<pb::ScopeRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let body = ScopeBody {
            scope: scope_ref(req.into_inner().scope),
        };
        let out = super::scopes::delete(&self.state, &id, body).await;
        json(&observed(&self.state, "delete_scope", out)?)
    }

    async fn set_private(
        &self,
        req: Request<pb::SetPrivateRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = PrivateBody {
            scope: scope_ref(r.scope),
            private: Some(r.private),
        };
        let out = super::scopes::set_private(&self.state, &id, body).await;
        json(&observed(&self.state, "set_private", out)?)
    }

    async fn list_assignments(
        &self,
        req: Request<pb::ListAssignmentsRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let q = AssignmentsQuery {
            scope: scope_ref(r.scope),
            subject: some(r.subject),
            after: some(r.after),
            limit: limit(r.limit),
        };
        let out = super::bindings::assignments(&self.state, &id, q).await;
        json(&observed(&self.state, "list_assignments", out)?)
    }

    async fn assign(
        &self,
        req: Request<pb::AssignRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = AssignBody {
            subject: some(r.subject),
            role: some(r.role),
            scope: scope_ref(r.scope),
            expires_at: some(r.expires_at),
        };
        let out = super::bindings::assign(&self.state, &id, body).await;
        json(&observed(&self.state, "assign", out)?)
    }

    async fn set_assignment_expiry(
        &self,
        req: Request<pb::SetAssignmentExpiryRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = ExpiryBody {
            expires_at: Some(r.expires_at),
        };
        let out = super::bindings::set_expiry(&self.state, &id, &r.id, body).await;
        json(&observed(&self.state, "set_assignment_expiry", out)?)
    }

    async fn unassign(
        &self,
        req: Request<pb::AssignmentRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let out = super::bindings::unassign(&self.state, &id, &r.id).await;
        json(&observed(&self.state, "unassign", out)?)
    }

    async fn list_groups(
        &self,
        req: Request<pb::ListGroupsRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let q = GroupsQuery {
            org: some(r.org),
            after: some(r.after),
            limit: limit(r.limit),
        };
        let out = super::bindings::groups(&self.state, &id, q).await;
        json(&observed(&self.state, "list_groups", out)?)
    }

    async fn create_group(
        &self,
        req: Request<pb::CreateGroupRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = GroupBody {
            org: some(r.org),
            key: some(r.key),
            name: some(r.name),
        };
        let out = super::bindings::create_group(&self.state, &id, body).await;
        json(&observed(&self.state, "create_group", out)?)
    }

    async fn delete_group(
        &self,
        req: Request<pb::GroupRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let out = super::bindings::delete_group(&self.state, &id, &r.key).await;
        json(&observed(&self.state, "delete_group", out)?)
    }

    async fn list_group_members(
        &self,
        req: Request<pb::ListGroupMembersRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let q = MembersQuery {
            after: some(r.after),
            limit: limit(r.limit),
        };
        let out = super::bindings::members(&self.state, &id, &r.key, q).await;
        json(&observed(&self.state, "list_members", out)?)
    }

    async fn add_group_member(
        &self,
        req: Request<pb::GroupMemberRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = MemberBody {
            member: some(r.member),
        };
        let out = super::bindings::change_member(&self.state, &id, &r.key, body, true).await;
        json(&observed(&self.state, "add_member", out)?)
    }

    async fn remove_group_member(
        &self,
        req: Request<pb::GroupMemberRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let r = req.into_inner();
        let body = MemberBody {
            member: some(r.member),
        };
        let out = super::bindings::change_member(&self.state, &id, &r.key, body, false).await;
        json(&observed(&self.state, "remove_member", out)?)
    }

    async fn list_roles(
        &self,
        req: Request<pb::ListRolesRequest>,
    ) -> Result<Response<pb::JsonResult>, Status> {
        let id = identity(&req)?;
        let q = RolesQuery {
            scope: some(req.into_inner().scope),
        };
        let out = super::bindings::roles(&self.state, &id, q).await;
        json(&observed(&self.state, "list_roles", out)?)
    }
}
