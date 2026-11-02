//! The HTTP side of the model API: thin adapters over [`crate::models`].

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use serde::Deserialize;
use tutela_sdk::Identity;

use super::observed;
use super::wire::{PublishBody, PublishResult, VersionOut, VersionsOut};
use crate::api::{AppState, Problem};
use crate::authz::http::Body;

/// The most a manifest can be, after JSON escaping: MANIFEST.md 11 allows
/// 4 MiB of text.
pub const MODEL_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// `POST /v1/models/publish`.
pub async fn publish(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<PublishBody>,
) -> Result<Json<PublishResult>, Problem> {
    observed(&state, "publish", super::publish(&state, &id, body).await).map(Json)
}

/// The query of `GET /v1/models`.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
pub struct Page {
    /// The `next_before` of the page before.
    pub before: Option<i64>,
    /// How many. At most 100.
    pub limit: Option<usize>,
}

/// `GET /v1/models`.
pub async fn versions(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Query(page): Query<Page>,
) -> Result<Json<VersionsOut>, Problem> {
    let out = super::versions(&state, &id, page.before, page.limit).await;
    observed(&state, "versions", out).map(Json)
}

/// `GET /v1/models/{version}`.
pub async fn version(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Path(version): Path<i64>,
) -> Result<Json<VersionOut>, Problem> {
    observed(
        &state,
        "version",
        super::version(&state, &id, version).await,
    )
    .map(Json)
}
