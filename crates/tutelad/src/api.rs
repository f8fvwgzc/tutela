//! The two routers: the API port, where every request needs a token, and the
//! ops port, with health, readiness and metrics.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Extension, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router, middleware};
use serde::Serialize;
use tower::ServiceExt as _;
use tower_http::timeout::TimeoutLayer;
use tutela_contracts::claims::Audience;
use tutela_sdk::Verifier;
use tutela_sdk::http::{AuthLayer, Protocol};
use tutela_sdk::{Identity, Step};
use tutela_store::{StoreError, StoreErrorKind};

use crate::admin;
use crate::authz;
use crate::cache::TenantCache;
use crate::db::{Db, DbError};
use crate::exchange::{self, Audiences};
use crate::keys::{self, KeyRing};
use crate::models;
use crate::revocation::{Refusal, Revocations};
use crate::telemetry::{Metrics, observe};
use crate::tenant::Tenant;

/// How long `/readyz` waits for the database.
const READY_TIMEOUT: Duration = Duration::from_secs(2);

/// What every handler can reach.
#[derive(Clone, Debug)]
pub struct AppState {
    /// The token verifier.
    pub verifier: Arc<Verifier>,
    /// The service's own signing keys (ADR-0030).
    pub keys: Arc<KeyRing>,
    /// The audiences token exchange issues for (ADR-0031).
    pub audiences: Arc<Audiences>,
    /// Raised epochs and disabled principals, per tenant.
    pub revocations: Arc<Revocations>,
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
    /// The event streams of this replica (`GET /v1/events`).
    pub events: Arc<crate::stream::Hub>,
    /// `TUTELA_BUNDLE_TTL_SECS`: the longest a signed bundle lasts.
    pub bundle_ttl: Duration,
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
    // The admin routes take a `tutela-admin` token from a person, or a
    // `tutela-authz` token from a service (ADR-0032).
    let admin = Router::new()
        .route("/v1/authz/explain", post(authz::http::explain))
        .route(
            "/v1/authz/simulate",
            post(authz::http::simulate)
                .layer(DefaultBodyLimit::max(models::http::MODEL_BODY_LIMIT)),
        )
        .route("/v1/models", get(models::http::versions))
        .route("/v1/models/{version}", get(models::http::version))
        .route(
            "/v1/models/settings",
            get(models::http::settings).put(models::http::set_settings),
        )
        .route(
            "/v1/models/proposals",
            get(models::http::proposals)
                .post(models::http::propose)
                .layer(DefaultBodyLimit::max(models::http::MODEL_BODY_LIMIT)),
        )
        .route("/v1/models/proposals/{id}", get(models::http::proposal))
        .route(
            "/v1/models/proposals/{id}/approve",
            post(models::http::approve),
        )
        .route(
            "/v1/models/proposals/{id}/reject",
            post(models::http::reject),
        )
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
            "/v1/admin/agents",
            get(admin::http::agents).post(admin::http::register_agent),
        )
        .route("/v1/admin/principals/state", post(admin::http::principal))
        .route(
            "/v1/admin/principals/disabled",
            post(admin::http::set_disabled),
        )
        .route(
            "/v1/admin/principals/revoke-sessions",
            post(admin::http::revoke_sessions),
        )
        .route("/v1/admin/boundaries", put(admin::http::set_boundary))
        .route(
            "/v1/admin/resource-types",
            post(admin::http::put_resource_types)
                .layer(DefaultBodyLimit::max(models::http::MODEL_BODY_LIMIT)),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), current_http))
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth));
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
        .route("/v1/events", get(crate::stream::events))
        .route(crate::bundle::BUNDLE_PATH, get(crate::bundle::bundle))
        .route(
            "/.well-known/authzen-configuration",
            get(authz::http::metadata),
        )
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), current_http))
        .layer(AuthLayer::new(Arc::clone(&state.verifier), Protocol::Http))
        .merge(admin)
        .with_state(state.clone())
        .layer(timeout)
        .layer(middleware::map_response(problem_for_401))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            observe,
        ));
    let grpc = grpc
        .layer(middleware::from_fn_with_state(state.clone(), current_grpc))
        .layer(AuthLayer::new(Arc::clone(&state.verifier), Protocol::Grpc))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            observe,
        ));
    // `tutela.admin.v1` takes the tokens the admin routes take (ADR-0032,
    // ADR-0040), so its methods have the admin token check of HTTP.
    let admin_grpc = tonic::service::Routes::new(admin::grpc::AdminService::server(state.clone()))
        .prepare()
        .into_axum_router()
        .layer(middleware::from_fn_with_state(state.clone(), current_grpc))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_grpc,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            observe,
        ));
    let public = public_router(state, request_timeout);
    Router::new().fallback(move |req: Request| {
        let target = if is_public(&req) {
            &public
        } else if is_grpc(&req) && req.uri().path().starts_with(admin::grpc::PATH_PREFIX) {
            &admin_grpc
        } else if is_grpc(&req) {
            &grpc
        } else {
            &http
        }
        .clone();
        target.oneshot(req)
    })
}

/// A verified token whose subject's epoch was raised, or whose subject or
/// actor is disabled, is refused like any token that fails a step: 401,
/// with the step `epoch` for the log (CONTRACTS.md 4.2 step 9).
async fn current_http(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(id) = req.extensions().get::<Identity>().cloned() else {
        return next.run(req).await;
    };
    match state.revocations.check(&id).await {
        Ok(()) => next.run(req).await,
        Err(Refusal::Revoked) => {
            let mut res = invalid_token().into_response();
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
            res.extensions_mut().insert(Step::Epoch);
            res
        }
        Err(Refusal::Problem(p)) => p.into_response(),
    }
}

/// The token check of the admin routes: an admin token (`aud=tutela-admin`)
/// goes to the admin verifier, any other to the main one, which checks
/// everything else as on every route. A refusal is the same 401 as
/// `AuthLayer`'s, with the step for the log.
async fn admin_auth(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match admin_identity(&state, bearer(req.headers())).await {
        Ok(id) => {
            req.extensions_mut().insert(id);
            next.run(req).await
        }
        Err(step) => {
            let mut res = invalid_token().into_response();
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
            if let Some(step) = step {
                res.extensions_mut().insert(step);
            }
            res
        }
    }
}

/// [`admin_auth`] for `tutela.admin.v1`: a refusal is `unauthenticated`
/// (`grpc-status: 16`), with the step for the log, as `AuthLayer` answers.
async fn admin_auth_grpc(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match admin_identity(&state, bearer(req.headers())).await {
        Ok(id) => {
            req.extensions_mut().insert(id);
            next.run(req).await
        }
        Err(step) => {
            let mut res = Response::new(axum::body::Body::empty());
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/grpc"),
            );
            res.headers_mut()
                .insert("grpc-status", HeaderValue::from_static("16"));
            if let Some(step) = step {
                res.extensions_mut().insert(step);
            }
            res
        }
    }
}

/// The verified identity of an admin request: an admin token goes to the
/// admin verifier, any other to the main one. `Err` names the failed step,
/// when there is one.
async fn admin_identity(state: &AppState, token: Option<String>) -> Result<Identity, Option<Step>> {
    let token = token.ok_or(None)?;
    let admin = exchange::peek_audience(&token).as_deref() == Some(Audience::TUTELA_ADMIN.as_str());
    let verifier = if admin {
        state.audiences.admin_verifier()
    } else {
        &state.verifier
    };
    verifier.verify(&token).await.map_err(|e| Some(e.step()))
}

/// The token of exactly one `Authorization: Bearer` header, as `AuthLayer`
/// reads it.
fn bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let v = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.contains(' '))
        .then(|| token.to_owned())
}

/// [`current_http`] for gRPC: `unauthenticated`, `permission_denied` or
/// `unavailable`, in the headers. gRPC health needs a token but no
/// database, and says nothing about anyone, so it is not held here.
async fn current_grpc(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/grpc.health.v1.Health/") {
        return next.run(req).await;
    }
    let Some(id) = req.extensions().get::<Identity>().cloned() else {
        return next.run(req).await;
    };
    let code = match state.revocations.check(&id).await {
        Ok(()) => return next.run(req).await,
        Err(Refusal::Revoked) => "16",
        Err(Refusal::Problem(p)) if p.status == StatusCode::FORBIDDEN => "7",
        Err(Refusal::Problem(_)) => "14",
    };
    let mut res = Response::new(axum::body::Body::empty());
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    res.headers_mut()
        .insert("grpc-status", HeaderValue::from_static(code));
    if code == "16" {
        res.extensions_mut().insert(Step::Epoch);
    }
    res
}

/// The paths of the API port that need no token: what a verifier or a client
/// must reach before it has one (ADR-0030). Exact paths only, so an unknown
/// path still says nothing without a token.
pub const PUBLIC_PATHS: [&str; 3] = [
    keys::JWKS_PATH,
    exchange::TOKEN_PATH,
    exchange::METADATA_PATH,
];

fn is_public(req: &Request) -> bool {
    PUBLIC_PATHS.contains(&req.uri().path())
}

/// The routes of [`PUBLIC_PATHS`]. Each one checks what it is sent itself.
fn public_router(state: &AppState, request_timeout: Duration) -> Router {
    let timeout = TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, request_timeout);
    Router::new()
        .route(keys::JWKS_PATH, get(keys::jwks))
        .route(
            exchange::TOKEN_PATH,
            post(exchange::token).layer(DefaultBodyLimit::max(exchange::BODY_LIMIT)),
        )
        .route(exchange::METADATA_PATH, get(exchange::metadata))
        .fallback(not_found)
        .with_state(state.clone())
        .layer(timeout)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            observe,
        ))
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
    state.metrics.set_open_streams(state.events.open_streams());
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
