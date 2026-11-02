//! The HTTP side of the admin API: thin adapters over [`crate::admin`].

use axum::Json;
use axum::extract::{Extension, Query, State};
use tutela_sdk::Identity;

use super::observed;
use super::wire::{
    AgentsOut, AgentsQuery, BoundaryBody, PrincipalBody, PrincipalOut, RegisterAgentBody,
    ResourceTypesBody, RevOut, SetDisabledBody,
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
