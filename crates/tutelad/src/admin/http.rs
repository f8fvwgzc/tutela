//! The HTTP side of the admin API: thin adapters over [`crate::admin`].

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use tutela_sdk::Identity;

use super::observed;
use super::wire::{
    AgentsOut, AgentsQuery, AssignBody, AssignmentChangeOut, AssignmentsOut, AssignmentsQuery,
    BoundaryBody, DeliveriesOut, DeliveriesQuery, DeliveryOut, ExpiryBody, GroupBody, GroupOut,
    GroupsOut, GroupsQuery, MemberBody, MembersOut, MembersQuery, MoveScopeBody, NameBody, OrgOut,
    OrgsOut, PrincipalBody, PrincipalOut, PrivateBody, PutScopeBody, RegisterAgentBody,
    RegisterWebhookBody, ResourceTypesBody, RevOut, RolesOut, RolesQuery, RotateBody, ScopeBody,
    ScopeChangeOut, ScopesOut, ScopesQuery, SetDisabledBody, TenantOut, WebhookOut,
    WebhookSecretOut, WebhooksOut,
};
use crate::api::{AppState, Problem};
use crate::authz::http::Body;
use crate::models::wire::ProposalOut;

/// `POST /v1/admin/agents`.
pub async fn register_agent(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<RegisterAgentBody>,
) -> Result<Json<PrincipalOut>, Problem> {
    let out = super::principals::register_agent(&state, &id, body).await;
    observed(&state, "register_agent", out).map(Json)
}

/// `GET /v1/admin/agents`.
pub async fn agents(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Query(q): Query<AgentsQuery>,
) -> Result<Json<AgentsOut>, Problem> {
    let out = super::principals::agents(&state, &id, q).await;
    observed(&state, "list_agents", out).map(Json)
}

/// `POST /v1/admin/principals/state`.
pub async fn principal(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<PrincipalBody>,
) -> Result<Json<PrincipalOut>, Problem> {
    let out = super::principals::principal(&state, &id, body).await;
    observed(&state, "get_principal", out).map(Json)
}

/// `POST /v1/admin/principals/disabled`.
pub async fn set_disabled(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<SetDisabledBody>,
) -> Result<Json<PrincipalOut>, Problem> {
    let out = super::principals::set_disabled(&state, &id, body).await;
    observed(&state, "set_disabled", out).map(Json)
}

/// `POST /v1/admin/principals/revoke-sessions`.
pub async fn revoke_sessions(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<PrincipalBody>,
) -> Result<Json<PrincipalOut>, Problem> {
    let out = super::principals::revoke_sessions(&state, &id, body).await;
    observed(&state, "revoke_sessions", out).map(Json)
}

/// `PUT /v1/admin/boundaries`.
pub async fn set_boundary(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<BoundaryBody>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::boundaries::set_boundary(&state, &id, body).await;
    observed(&state, "set_boundary", out).map(Json)
}

/// `POST /v1/admin/resource-types`.
pub async fn put_resource_types(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<ResourceTypesBody>,
) -> Result<Json<ProposalOut>, Problem> {
    let out = super::types::put_resource_types(&state, &id, body).await;
    observed(&state, "put_resource_types", out).map(Json)
}

/// `GET /v1/admin/tenant`.
pub async fn tenant(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
) -> Result<Json<TenantOut>, Problem> {
    let out = super::lifecycle::tenant(&state, &id).await;
    observed(&state, "get_tenant", out).map(Json)
}

/// `PATCH /v1/admin/tenant`.
pub async fn update_tenant(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<NameBody>,
) -> Result<Json<TenantOut>, Problem> {
    let out = super::lifecycle::update_tenant(&state, &id, body).await;
    observed(&state, "update_tenant", out).map(Json)
}

/// `DELETE /v1/admin/tenant`.
pub async fn delete_tenant(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
) -> Result<Json<TenantOut>, Problem> {
    let out = super::lifecycle::delete_tenant(&state, &id).await;
    observed(&state, "delete_tenant", out).map(Json)
}

/// `GET /v1/admin/orgs`.
pub async fn orgs(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
) -> Result<Json<OrgsOut>, Problem> {
    let out = super::lifecycle::orgs(&state, &id).await;
    observed(&state, "list_orgs", out).map(Json)
}

/// `POST /v1/admin/orgs`.
pub async fn create_org(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<NameBody>,
) -> Result<Json<OrgOut>, Problem> {
    let out = super::lifecycle::create_org(&state, &id, body).await;
    observed(&state, "create_org", out).map(Json)
}

/// `PATCH /v1/admin/orgs/{org}`.
pub async fn update_org(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(org): Path<String>,
    Body(body): Body<NameBody>,
) -> Result<Json<OrgOut>, Problem> {
    let out = super::lifecycle::update_org(&state, &id, &org, body).await;
    observed(&state, "update_org", out).map(Json)
}

/// `DELETE /v1/admin/orgs/{org}`.
pub async fn delete_org(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(org): Path<String>,
) -> Result<Json<OrgOut>, Problem> {
    let out = super::lifecycle::delete_org(&state, &id, &org).await;
    observed(&state, "delete_org", out).map(Json)
}

/// `POST /v1/admin/orgs/{org}/restore`.
pub async fn restore_org(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(org): Path<String>,
) -> Result<Json<OrgOut>, Problem> {
    let out = super::lifecycle::restore_org(&state, &id, &org).await;
    observed(&state, "restore_org", out).map(Json)
}

/// `POST /v1/admin/users/delete`.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<PrincipalBody>,
) -> Result<Json<PrincipalOut>, Problem> {
    let out = super::lifecycle::delete_user(&state, &id, body).await;
    observed(&state, "delete_user", out).map(Json)
}

/// `POST /v1/admin/webhooks`.
pub async fn register_webhook(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<RegisterWebhookBody>,
) -> Result<Json<WebhookSecretOut>, Problem> {
    let out = super::webhooks::register(&state, &id, body).await;
    observed(&state, "register_webhook", out).map(Json)
}

/// `GET /v1/admin/webhooks`.
pub async fn webhooks(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
) -> Result<Json<WebhooksOut>, Problem> {
    let out = super::webhooks::list(&state, &id).await;
    observed(&state, "list_webhooks", out).map(Json)
}

/// `POST /v1/admin/webhooks/{id}/rotate`.
pub async fn rotate_webhook(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(wid): Path<String>,
    Body(body): Body<RotateBody>,
) -> Result<Json<WebhookSecretOut>, Problem> {
    let out = super::webhooks::rotate(&state, &id, &wid, body).await;
    observed(&state, "rotate_webhook", out).map(Json)
}

/// `POST /v1/admin/webhooks/{id}/disable`.
pub async fn disable_webhook(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(wid): Path<String>,
) -> Result<Json<WebhookOut>, Problem> {
    let out = super::webhooks::disable(&state, &id, &wid).await;
    observed(&state, "disable_webhook", out).map(Json)
}

/// `GET /v1/admin/webhooks/{id}/deliveries`.
pub async fn deliveries(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(wid): Path<String>,
    Query(q): Query<DeliveriesQuery>,
) -> Result<Json<DeliveriesOut>, Problem> {
    let out = super::webhooks::deliveries(&state, &id, &wid, q).await;
    observed(&state, "list_deliveries", out).map(Json)
}

/// `POST /v1/admin/webhooks/{id}/deliveries/{seq}/redeliver`.
pub async fn redeliver(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path((wid, seq)): Path<(String, u64)>,
) -> Result<Json<DeliveryOut>, Problem> {
    let out = super::webhooks::redeliver(&state, &id, &wid, seq).await;
    observed(&state, "redeliver", out).map(Json)
}

// ---------- Scopes, role assignments and groups (CONTRACTS.md 7.13.7) ----------

/// `GET /v1/admin/scopes`.
pub async fn scopes(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Query(q): Query<ScopesQuery>,
) -> Result<Json<ScopesOut>, Problem> {
    let out = super::scopes::list(&state, &id, q).await;
    observed(&state, "list_scopes", out).map(Json)
}

/// `POST /v1/admin/scopes`.
pub async fn put_scope(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<PutScopeBody>,
) -> Result<Json<ScopeChangeOut>, Problem> {
    let out = super::scopes::put(&state, &id, body).await;
    observed(&state, "put_scope", out).map(Json)
}

/// `POST /v1/admin/scopes/move`.
pub async fn move_scope(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<MoveScopeBody>,
) -> Result<Json<ScopeChangeOut>, Problem> {
    let out = super::scopes::move_scope(&state, &id, body).await;
    observed(&state, "move_scope", out).map(Json)
}

/// `POST /v1/admin/scopes/delete`.
pub async fn delete_scope(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<ScopeBody>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::scopes::delete(&state, &id, body).await;
    observed(&state, "delete_scope", out).map(Json)
}

/// `PUT /v1/admin/scopes/private`.
pub async fn set_private(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<PrivateBody>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::scopes::set_private(&state, &id, body).await;
    observed(&state, "set_private", out).map(Json)
}

/// `POST /v1/admin/assignments/list`.
pub async fn assignments(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<AssignmentsQuery>,
) -> Result<Json<AssignmentsOut>, Problem> {
    let out = super::bindings::assignments(&state, &id, body).await;
    observed(&state, "list_assignments", out).map(Json)
}

/// `POST /v1/admin/assignments`.
pub async fn assign(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<AssignBody>,
) -> Result<Json<AssignmentChangeOut>, Problem> {
    let out = super::bindings::assign(&state, &id, body).await;
    observed(&state, "assign", out).map(Json)
}

/// `PATCH /v1/admin/assignments/{id}`.
pub async fn set_expiry(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(aid): Path<String>,
    Body(body): Body<ExpiryBody>,
) -> Result<Json<AssignmentChangeOut>, Problem> {
    let out = super::bindings::set_expiry(&state, &id, &aid, body).await;
    observed(&state, "set_assignment_expiry", out).map(Json)
}

/// `DELETE /v1/admin/assignments/{id}`.
pub async fn unassign(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(aid): Path<String>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::bindings::unassign(&state, &id, &aid).await;
    observed(&state, "unassign", out).map(Json)
}

/// `GET /v1/admin/groups`.
pub async fn groups(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Query(q): Query<GroupsQuery>,
) -> Result<Json<GroupsOut>, Problem> {
    let out = super::bindings::groups(&state, &id, q).await;
    observed(&state, "list_groups", out).map(Json)
}

/// `POST /v1/admin/groups`.
pub async fn create_group(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<GroupBody>,
) -> Result<Json<GroupOut>, Problem> {
    let out = super::bindings::create_group(&state, &id, body).await;
    observed(&state, "create_group", out).map(Json)
}

/// `DELETE /v1/admin/groups/{key}`.
pub async fn delete_group(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(key): Path<String>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::bindings::delete_group(&state, &id, &key).await;
    observed(&state, "delete_group", out).map(Json)
}

/// `GET /v1/admin/groups/{key}/members`.
pub async fn members(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(key): Path<String>,
    Query(q): Query<MembersQuery>,
) -> Result<Json<MembersOut>, Problem> {
    let out = super::bindings::members(&state, &id, &key, q).await;
    observed(&state, "list_members", out).map(Json)
}

/// `POST /v1/admin/groups/{key}/members`.
pub async fn add_member(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(key): Path<String>,
    Body(body): Body<MemberBody>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::bindings::change_member(&state, &id, &key, body, true).await;
    observed(&state, "add_member", out).map(Json)
}

/// `POST /v1/admin/groups/{key}/members/remove`.
pub async fn remove_member(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(key): Path<String>,
    Body(body): Body<MemberBody>,
) -> Result<Json<RevOut>, Problem> {
    let out = super::bindings::change_member(&state, &id, &key, body, false).await;
    observed(&state, "remove_member", out).map(Json)
}

/// `GET /v1/admin/roles`.
pub async fn roles(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Query(q): Query<RolesQuery>,
) -> Result<Json<RolesOut>, Problem> {
    let out = super::bindings::roles(&state, &id, q).await;
    observed(&state, "list_roles", out).map(Json)
}
