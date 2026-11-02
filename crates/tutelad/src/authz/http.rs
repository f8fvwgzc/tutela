//! The HTTP side of the check API: thin adapters over [`crate::authz`].

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tutela_sdk::Identity;

use super::wire::{
    EvaluationBody, EvaluationResult, EvaluationsBody, EvaluationsResult, PermissionsBody,
    ResourceResults, SearchBody, SubjectResults, WriteCheckBody, WriteCheckResult,
};
use crate::api::{AppState, Problem};

/// A JSON body. A bad one is a problem document that says nothing about the
/// body's content: serde's messages quote the input.
pub struct Body<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = Problem;

    async fn from_request(req: Request, state: &S) -> Result<Self, Problem> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(body)) => Ok(Self(body)),
            Err(e) => Err(rejected(&e)),
        }
    }
}

fn rejected(e: &JsonRejection) -> Problem {
    let (status, title) = match e.status() {
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the body must be application/json",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => (StatusCode::PAYLOAD_TOO_LARGE, "the body is too large"),
        // CONTRACTS.md 7.1 has one status for a bad request: axum's 422 too.
        _ => (StatusCode::BAD_REQUEST, "the body is not a valid request"),
    };
    Problem::new(status, "invalid_request", title)
}

/// `POST /access/v1/evaluation`.
pub async fn evaluation(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<EvaluationBody>,
) -> Result<Json<EvaluationResult>, Problem> {
    super::evaluate(&state, &id, body).await.map(Json)
}

/// `POST /access/v1/evaluations`.
pub async fn evaluations(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<EvaluationsBody>,
) -> Result<Json<EvaluationsResult>, Problem> {
    super::evaluations(&state, &id, body).await.map(Json)
}

/// `POST /access/v1/search/resource`.
pub async fn search_resource(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<SearchBody>,
) -> Result<Json<ResourceResults>, Problem> {
    super::search_resource(&state, &id, body).await.map(Json)
}

/// `POST /access/v1/search/subject`.
pub async fn search_subject(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<SearchBody>,
) -> Result<Json<SubjectResults>, Problem> {
    super::search_subject(&state, &id, body).await.map(Json)
}

/// `POST /v1/authz/permissions`. The answer is 304 with no body when
/// `If-None-Match` names the current tag.
pub async fn permissions(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    headers: HeaderMap,
    Body(body): Body<PermissionsBody>,
) -> Result<Response, Problem> {
    let sent = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    let out = super::permissions(&state, &id, body, sent).await?;
    let etag = HeaderValue::from_str(&out.etag).map_err(|_| Problem::stale("unavailable"))?;
    let mut res = match out.map {
        Some(map) => Json(map).into_response(),
        None => StatusCode::NOT_MODIFIED.into_response(),
    };
    res.headers_mut().insert(header::ETAG, etag);
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    Ok(res)
}

/// `POST /v1/authz/write-check`.
pub async fn write_check(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<WriteCheckBody>,
) -> Result<Json<WriteCheckResult>, Problem> {
    super::write_check(&state, &id, body).await.map(Json)
}

/// `POST /v1/authz/explain`.
pub async fn explain(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<EvaluationBody>,
) -> Result<Json<super::ExplainResult>, Problem> {
    super::explain(&state, &id, body).await.map(Json)
}

/// `POST /v1/authz/simulate`.
pub async fn simulate(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Body(body): Body<super::SimulateBody>,
) -> Result<Json<super::SimulateResult>, Problem> {
    super::simulate(&state, &id, body).await.map(Json)
}

/// The AuthZEN metadata (section 9).
#[derive(Debug, Serialize)]
pub struct Metadata {
    policy_decision_point: String,
    access_evaluation_endpoint: String,
    access_evaluations_endpoint: String,
    search_subject_endpoint: String,
    search_resource_endpoint: String,
}

/// `GET /.well-known/authzen-configuration`. Behind the token check, like
/// the rest of this port (ADR-0018). The address is the one the caller
/// used.
pub async fn metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Metadata>, Problem> {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Problem::invalid("invalid_request", "no Host header".to_owned()))?;
    let scheme = if state.dev_mode { "http" } else { "https" };
    let base = format!("{scheme}://{host}");
    Ok(Json(Metadata {
        access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
        access_evaluations_endpoint: format!("{base}/access/v1/evaluations"),
        search_subject_endpoint: format!("{base}/access/v1/search/subject"),
        search_resource_endpoint: format!("{base}/access/v1/search/resource"),
        policy_decision_point: base,
    }))
}
