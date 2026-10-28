//! The auth layer and route guards for HTTP and gRPC services (axum and
//! tonic are both tower services over `http`), PERMISSION-MODEL.md 14.1.
//!
//! - [`AuthLayer`] verifies the bearer token and puts the [`Identity`] in
//!   the request extensions. A refusal is 401 (HTTP) or `grpc-status: 16`
//!   (gRPC), and says nothing about the failed step.
//! - [`Guards`] holds one guard per route the manifest declares (the
//!   `ROUTES` table from `tutela codegen`). [`Guards::check_complete`]
//!   fails when a declared route has no guard, so the service refuses to
//!   start. [`GuardLayer`] runs the guard of each declared route; a
//!   declared route without a guard, or a request without an identity, is
//!   403.
//! - [`assert_routes_deny`] calls every declared route as a denied
//!   principal and expects 403: the test `tutela codegen` asks for.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use http::{HeaderValue, Method, Request, Response, StatusCode};
use tower_layer::Layer;
use tower_service::Service;

use crate::{Identity, Verifier};

/// A boxed future of a service response.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How a refusal is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    /// HTTP: 401 with `WWW-Authenticate: Bearer error="invalid_token"`.
    Http,
    /// gRPC: HTTP 200 with `grpc-status: 16` (unauthenticated) or `7`
    /// (permission denied).
    Grpc,
}

fn refusal<B: Default>(protocol: Protocol, status: StatusCode) -> Response<B> {
    let mut r = Response::new(B::default());
    match protocol {
        Protocol::Http => {
            *r.status_mut() = status;
            if status == StatusCode::UNAUTHORIZED {
                r.headers_mut().insert(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
            }
        }
        Protocol::Grpc => {
            let code = if status == StatusCode::UNAUTHORIZED {
                "16"
            } else {
                "7"
            };
            r.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/grpc"),
            );
            r.headers_mut()
                .insert("grpc-status", HeaderValue::from_static(code));
        }
    }
    r
}

/// The token of exactly one `Authorization: Bearer` header.
fn bearer<B>(req: &Request<B>) -> Option<String> {
    let mut values = req.headers().get_all(http::header::AUTHORIZATION).iter();
    let v = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.contains(' '))
        .then(|| token.to_owned())
}

/// Verifies the bearer token of every request.
#[derive(Clone, Debug)]
pub struct AuthLayer {
    verifier: Arc<Verifier>,
    protocol: Protocol,
}

impl AuthLayer {
    /// A layer over `verifier`, answering refusals for `protocol`.
    #[must_use]
    pub const fn new(verifier: Arc<Verifier>, protocol: Protocol) -> Self {
        Self { verifier, protocol }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            verifier: Arc::clone(&self.verifier),
            protocol: self.protocol,
        }
    }
}

/// The service of [`AuthLayer`].
#[derive(Clone, Debug)]
pub struct AuthService<S> {
    inner: S,
    verifier: Arc<Verifier>,
    protocol: Protocol,
}

impl<S, B, R> Service<Request<B>> for AuthService<S>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
    R: Default,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response<R>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // The inner service that was polled ready serves this request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let verifier = Arc::clone(&self.verifier);
        let protocol = self.protocol;
        Box::pin(async move {
            let Some(token) = bearer(&req) else {
                return Ok(refusal(protocol, StatusCode::UNAUTHORIZED));
            };
            match verifier.verify(&token).await {
                Ok(id) => {
                    req.extensions_mut().insert(id);
                    inner.call(req).await
                }
                Err(_) => Ok(refusal(protocol, StatusCode::UNAUTHORIZED)),
            }
        })
    }
}

/// The values of a route's `{name}` placeholders.
pub type Params = HashMap<String, String>;

/// Decides whether an identity may call one declared route. The product
/// loads the resource **server-side** by the ids in `params` (never from the
/// request body) and asks the PDP.
pub trait Guard: Send + Sync + 'static {
    /// `true` to let the request through.
    fn allow(&self, id: Identity, params: Params) -> BoxFuture<bool>;
}

impl<F, Fut> Guard for F
where
    F: Fn(Identity, Params) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    fn allow(&self, id: Identity, params: Params) -> BoxFuture<bool> {
        Box::pin(self(id, params))
    }
}

/// A route pattern: `METHOD /a/{id}/b`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Pattern {
    method: Method,
    segments: Vec<String>,
}

impl Pattern {
    fn parse(method: &str, path: &str) -> Option<Self> {
        let method = Method::from_bytes(method.as_bytes()).ok()?;
        let path = path.strip_prefix('/')?;
        Some(Self {
            method,
            segments: path.split('/').map(str::to_owned).collect(),
        })
    }

    /// The placeholders' values if `method` and `path` match.
    fn matches(&self, method: &Method, path: &str) -> Option<Params> {
        if *method != self.method {
            return None;
        }
        let parts: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
        if parts.len() != self.segments.len() {
            return None;
        }
        let mut params = Params::new();
        for (seg, part) in self.segments.iter().zip(parts) {
            match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) if !part.is_empty() => {
                    params.insert(name.to_owned(), part.to_owned());
                }
                Some(_) => return None,
                None if seg == part => {}
                None => return None,
            }
        }
        Some(params)
    }

    fn sample_path(&self) -> String {
        let segs: Vec<&str> = self
            .segments
            .iter()
            .map(|s| if s.starts_with('{') { "x" } else { s.as_str() })
            .collect();
        format!("/{}", segs.join("/"))
    }
}

/// One guard per declared route.
#[derive(Clone, Default)]
pub struct Guards {
    routes: Vec<(Pattern, Option<Arc<dyn Guard>>)>,
}

impl std::fmt::Debug for Guards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guards")
            .field("routes", &self.routes.len())
            .finish()
    }
}

/// Why the guards are not complete.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("declared routes without a guard: {}", .0.join(", "))]
pub struct Unguarded(pub Vec<String>);

impl Guards {
    /// The declared routes, as `(method, path)` pairs (from the codegen
    /// `ROUTES` table). A pair that does not parse is kept as unguarded, so
    /// [`Guards::check_complete`] reports it.
    #[must_use]
    pub fn declared<'a>(routes: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let routes = routes
            .into_iter()
            .map(|(m, p)| {
                let pattern = Pattern::parse(m, p).unwrap_or(Pattern {
                    method: Method::GET,
                    segments: vec![format!("<bad route {m} {p}>")],
                });
                (pattern, None)
            })
            .collect();
        Self { routes }
    }

    /// Sets the guard of a declared route.
    ///
    /// # Errors
    ///
    /// The route text, when it is not declared.
    pub fn protect(mut self, method: &str, path: &str, guard: impl Guard) -> Result<Self, String> {
        let want = Pattern::parse(method, path).ok_or_else(|| format!("{method} {path}"))?;
        let slot = self
            .routes
            .iter_mut()
            .find(|(p, _)| *p == want)
            .ok_or_else(|| format!("{method} {path} is not a declared route"))?;
        slot.1 = Some(Arc::new(guard));
        Ok(self)
    }

    /// Fails when a declared route has no guard: call it at start-up and
    /// refuse to serve on an error.
    ///
    /// # Errors
    ///
    /// [`Unguarded`] with every route that has no guard.
    pub fn check_complete(&self) -> Result<(), Unguarded> {
        let missing: Vec<String> = self
            .routes
            .iter()
            .filter(|(_, g)| g.is_none())
            .map(|(p, _)| format!("{} /{}", p.method, p.segments.join("/")))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Unguarded(missing))
        }
    }

    /// The guard and parameters for a request, if the route is declared.
    /// The guard is `None` when the declared route has none.
    fn find(&self, method: &Method, path: &str) -> Option<(Option<Arc<dyn Guard>>, Params)> {
        self.routes
            .iter()
            .find_map(|(p, g)| p.matches(method, path).map(|params| (g.clone(), params)))
    }
}

/// Runs the guard of each declared route. Put it inside [`AuthLayer`].
#[derive(Clone, Debug)]
pub struct GuardLayer {
    guards: Arc<Guards>,
    protocol: Protocol,
}

impl GuardLayer {
    /// A layer over `guards`.
    #[must_use]
    pub fn new(guards: Guards, protocol: Protocol) -> Self {
        Self {
            guards: Arc::new(guards),
            protocol,
        }
    }
}

impl<S> Layer<S> for GuardLayer {
    type Service = GuardService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        GuardService {
            inner,
            guards: Arc::clone(&self.guards),
            protocol: self.protocol,
        }
    }
}

/// The service of [`GuardLayer`].
#[derive(Clone, Debug)]
pub struct GuardService<S> {
    inner: S,
    guards: Arc<Guards>,
    protocol: Protocol,
}

impl<S, B, R> Service<Request<B>> for GuardService<S>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
    R: Default,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response<R>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let found = self.guards.find(req.method(), req.uri().path());
        let id = req.extensions().get::<Identity>().cloned();
        let protocol = self.protocol;
        Box::pin(async move {
            let Some((guard, params)) = found else {
                // Not a declared route: the handler checks for itself.
                return inner.call(req).await;
            };
            let allowed = match (guard, id) {
                (Some(g), Some(id)) => g.allow(id, params).await,
                _ => false,
            };
            if allowed {
                inner.call(req).await
            } else {
                Ok(refusal(protocol, StatusCode::FORBIDDEN))
            }
        })
    }
}

/// Calls every declared route once on `service` with `token` (a principal
/// that may do none of them) and returns the routes that did **not**
/// answer 403. Placeholders are filled with `x`. Use it in a test with the
/// service's real router.
pub async fn assert_routes_deny<'a, S, R>(
    mut service: S,
    routes: impl IntoIterator<Item = (&'a str, &'a str)>,
    token: &str,
) -> Vec<String>
where
    S: Service<Request<String>, Response = Response<R>>,
{
    let mut not_denied = Vec::new();
    for (m, p) in routes {
        let Some(pattern) = Pattern::parse(m, p) else {
            not_denied.push(format!("{m} {p} (does not parse)"));
            continue;
        };
        let req = Request::builder()
            .method(pattern.method.clone())
            .uri(pattern.sample_path())
            .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(String::new());
        let status = match req {
            Ok(req) => {
                let ready = std::future::poll_fn(|cx| service.poll_ready(cx)).await;
                match ready {
                    Ok(()) => service.call(req).await.ok().map(|r| r.status()),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        };
        if status != Some(StatusCode::FORBIDDEN) {
            not_denied.push(format!("{m} {p} -> {status:?}"));
        }
    }
    not_denied
}
