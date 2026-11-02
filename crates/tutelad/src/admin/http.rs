//! The HTTP side of the admin API: thin adapters over [`crate::admin`].

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use tutela_sdk::Identity;

use super::observed;
use super::wire::{
    AgentsOut, AgentsQuery, BoundaryBody, DeliveriesOut, DeliveriesQuery, DeliveryOut, NameBody,
    OrgOut, OrgsOut, PrincipalBody, PrincipalOut, RegisterAgentBody, RegisterWebhookBody,
    ResourceTypesBody, RevOut, RotateBody, SetDisabledBody, TenantOut, WebhookOut,
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
