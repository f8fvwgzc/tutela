//! The two routers: the API port, where every request needs a token, and the
//! ops port, with health, readiness and metrics.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Extension, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use serde::Serialize;
use tower::ServiceExt as _;
use tower_http::timeout::TimeoutLayer;
use tutela_sdk::Identity;
use tutela_sdk::Verifier;
use tutela_sdk::http::{AuthLayer, Protocol};
use tutela_store::{StoreError, StoreErrorKind};

use crate::authz;
use crate::cache::TenantCache;
use crate::db::{Db, DbError};
use crate::models;
use crate::telemetry::{Metrics, observe};
use crate::tenant::Tenant;

/// How long `/readyz` waits for the database.
const READY_TIMEOUT: Duration = Duration::from_secs(2);

/// What every handler can reach.
#[derive(Clone, Debug)]
pub struct AppState {
    /// The token verifier.
    pub verifier: Arc<Verifier>,
    /// The database.
    pub db: Db,
    /// What decisions are made from.
    pub cache: Arc<TenantCache>,
    /// The metrics.
    pub metrics: Arc<Metrics>,
    /// Set when a shutdown starts, so readiness fails first.
    pub stopping: Arc<AtomicBool>,
    /// `TUTELA_DEV_MODE`.
    pub dev_mode: bool,
    /// `TUTELA_IMPACT_MAX_WORK`.
    pub impact_work: usize,
}

/// An error answer: `application/problem+json` (RFC 9457, CONTRACTS.md 7.1).
/// The detail never holds secrets or personal data.
#[derive(Clone, Debug)]
pub struct Problem {
    /// The status.
    pub status: StatusCode,
    /// The code in `urn:tutela:problem:<code>`.
    pub code: &'static str,
    /// A short title.
    pub title: &'static str,
    /// Short English about this request. No secrets, no personal data.
    pub detail: Option<String>,
    /// `Retry-After`, in seconds.
    pub retry_after: Option<u32>,
}

impl Problem {
    /// A problem with no detail.
    #[must_use]
    pub const fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        Self {
            status,
            code,
            title,
            detail: None,
            retry_after: None,
        }
    }

    /// 400: the request is wrong.
    #[must_use]
    pub fn invalid(code: &'static str, detail: String) -> Self {
        Self {
            detail: Some(detail),
            ..Self::new(StatusCode::BAD_REQUEST, code, "the request is not valid")
        }
    }

    /// 403: this token may not ask this question.
    #[must_use]
    pub const fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this caller may not ask this question",
        )
    }

    /// 503: no data fit to answer from. Never a hidden allow: the caller
    /// fails closed.
    #[must_use]
    pub fn stale(code: &'static str) -> Self {
        Self {
            retry_after: Some(1),
            ..Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                code,
                "the service cannot answer now",
            )
        }
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({
            "type": format!("urn:tutela:problem:{}", self.code),
            "title": self.title,
            "status": self.status.as_u16(),
        });
        if let Some(detail) = self.detail {
            body["detail"] = detail.into();
        }
        let mut res = (
            self.status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            )],
            body.to_string(),
        )
            .into_response();
        if let Some(secs) = self.retry_after {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}

impl From<DbError> for Problem {
    /// An unknown tenant is the caller's to fix. Anything else fails closed
    /// with the same 503. The log gets the kind and the SQLSTATE only: the
    /// server's message may hold a value from a row.
    fn from(e: DbError) -> Self {
        if e.store_kind() == Some(StoreErrorKind::UnknownTenant) {
            return Self::new(
                StatusCode::FORBIDDEN,
                "unknown_tenant",
                "this tenant is not known here",
            );
        }
        tracing::error!(
            error = %e,
            kind = ?e.store_kind(),
            sqlstate = e.sqlstate(),
            "a database call failed"
        );
        Self::stale("unavailable")
    }
}

impl From<StoreError> for Problem {
    fn from(e: StoreError) -> Self {
        DbError::from(e).into()
    }
}

/// The answer of `GET /v1/whoami` (CONTRACTS.md 7.7).
#[derive(Debug, Serialize)]
struct WhoAmI {
    iss: String,
    tid: String,
    sub: String,
    kind: &'static str,
    rev: u64,
}

/// The subject and kind of a token. `None` for a kind this build does not
/// know: `Identity` is non-exhaustive.
fn subject(id: &Identity) -> Option<(String, &'static str)> {
    match id {
        Identity::Access(c) => Some((c.sub.to_string(), "access")),
        Identity::Delegated(c) => Some((c.sub.to_string(), "delegated")),
        Identity::External(t) => Some((t.sub.clone(), "external")),
        _ => None,
    }
}

async fn whoami(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    tenant: Tenant,
) -> Result<Json<WhoAmI>, Problem> {
    let (sub, kind) = subject(&id).ok_or_else(invalid_token)?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    tx.commit().await?;
    Ok(Json(WhoAmI {
        iss: tenant.key().iss.to_string(),
        tid: tenant.key().tid.to_string(),
        sub,
        kind,
        rev,
    }))
}

async fn not_found() -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "not_found", "no such route")
}

/// 401.
#[must_use]
pub(crate) const fn invalid_token() -> Problem {
    Problem::new(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "a valid bearer token is required",
    )
}

/// `AuthLayer` answers 401 with an empty body. Clients of the HTTP API get
/// the same answer as `application/problem+json`, still with nothing about
/// the failed step.
async fn problem_for_401(res: Response) -> Response {
    if res.status() != StatusCode::UNAUTHORIZED {
        return res;
    }
    let (mut parts, _) = res.into_parts();
    let (problem, body) = invalid_token().into_response().into_parts();
    parts.headers.extend(problem.headers);
    Response::from_parts(parts, body)
}

/// The API port: HTTP and gRPC on one listener. Every request, also to an
/// unknown path, goes through the token check first, so this port says
/// nothing to a caller without a token. `grpc` holds the gRPC services.
pub fn api_router(state: &AppState, grpc: Router, request_timeout: Duration) -> Router {
    let timeout = TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, request_timeout);
    let http = Router::new()
        .route("/v1/whoami", get(whoami))
        .route("/access/v1/evaluation", post(authz::http::evaluation))
        .route("/access/v1/evaluations", post(authz::http::evaluations))
        .route(
            "/access/v1/search/resource",
            post(authz::http::search_resource),
        )
        .route(
            "/access/v1/search/subject",
            post(authz::http::search_subject),
        )
        .route("/v1/authz/permissions", post(authz::http::permissions))
        .route("/v1/authz/write-check", post(authz::http::write_check))
        .route("/v1/authz/explain", post(authz::http::explain))
        .route(
            "/v1/authz/simulate",
            post(authz::http::simulate)
                .layer(DefaultBodyLimit::max(models::http::MODEL_BODY_LIMIT)),
        )
        .route("/v1/models", get(models::http::versions))
        .route("/v1/models/{version}", get(models::http::version))
        .route(
            "/v1/models/impact",
            post(models::http::impact).layer(DefaultBodyLimit::max(models::http::MODEL_BODY_LIMIT)),
        )
        .route(
            "/v1/models/publish",
            post(models::http::publish)
                .layer(DefaultBodyLimit::max(models::http::MODEL_BODY_LIMIT)),
        )
        .route(
            "/.well-known/authzen-configuration",
            get(authz::http::metadata),
        )
        .fallback(not_found)
        .with_state(state.clone())
        .layer(timeout)
        .layer(AuthLayer::new(Arc::clone(&state.verifier), Protocol::Http))
        .layer(middleware::map_response(problem_for_401))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            observe,
        ));
    let grpc = grpc
        .layer(AuthLayer::new(Arc::clone(&state.verifier), Protocol::Grpc))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            observe,
        ));
    Router::new().fallback(move |req: Request| {
        let target = if is_grpc(&req) { &grpc } else { &http }.clone();
        target.oneshot(req)
    })
}

fn is_grpc(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/grpc"))
}

/// The ops port: no token. Keep it out of the public load balancer.
pub fn ops_router(state: &AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state.clone())
}

/// Liveness: the process answers. It never reads the database, so a
/// database outage does not restart every replica.
async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

#[derive(Debug, Serialize)]
struct Readiness {
    status: &'static str,
    database: &'static str,
    stopping: bool,
}

/// Readiness: this replica should get traffic. The body says which check
/// failed; the log says why.
async fn readyz(State(state): State<AppState>) -> Response {
    let stopping = state.stopping.load(Ordering::SeqCst);
    let database = match tokio::time::timeout(READY_TIMEOUT, state.db.check_ready()).await {
        Ok(Ok(())) => "ok",
        Ok(Err(e)) => {
            // Its own text only: a cause may hold a value from the server.
            tracing::warn!(reason = %e, "not ready");
            "failed"
        }
        Err(_) => {
            tracing::warn!("not ready: the database did not answer in time");
            "timeout"
        }
    };
    let ready = database == "ok" && !stopping;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = Readiness {
        status: if ready { "ready" } else { "not_ready" },
        database,
        stopping,
    };
    (status, Json(body)).into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    let (size, available) = state.db.sizes();
    state.metrics.set_pool(size, available);
    match state.metrics.render() {
        Ok(text) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            )],
            text,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
