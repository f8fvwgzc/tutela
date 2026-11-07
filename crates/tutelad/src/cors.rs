//! CORS for the HTTP API, off unless `TUTELA_CORS_ORIGINS` names exact
//! origins (ADR-0054): a product page on another origin then calls
//! `tutelad` with `@f8fvwgzc/tutela-js` without a proxy.
//!
//! - Only an `Origin` of the list gets CORS headers, and the answer names
//!   that origin, never `*`.
//! - No `Access-Control-Allow-Credentials`, ever: the browser client sends
//!   its token in `Authorization` with `credentials: "omit"`, so no cookie
//!   of the page's origin reaches `tutelad`.
//! - A preflight (`OPTIONS` with `Access-Control-Request-Method`) from a
//!   listed origin is answered here, without a token: it holds no data. Any
//!   other `OPTIONS` goes on to the token check as before.
//! - The Console's paths (`/console/`) and gRPC are left alone.

use std::sync::Arc;

use anyhow::{Context as _, ensure};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

/// The headers a page may send.
const ALLOW_HEADERS: &str = "authorization, content-type, if-none-match, x-request-id, traceparent";
/// The methods of the HTTP API.
const ALLOW_METHODS: &str = "GET, POST, PUT, PATCH, DELETE";
/// The headers a page may read besides the safe ones.
const EXPOSE_HEADERS: &str = "etag, retry-after, x-request-id, www-authenticate";
/// How long a browser may keep a preflight's answer, in seconds.
const MAX_AGE: &str = "600";

/// The origins of `TUTELA_CORS_ORIGINS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cors {
    origins: Vec<String>,
}

impl Cors {
    /// Parses a comma-separated list of exact origins.
    ///
    /// # Errors
    ///
    /// A wildcard, an origin with a path, a query, credentials or a trailing
    /// slash, or `http` outside dev mode on loopback.
    pub fn parse(text: &str, dev_mode: bool) -> anyhow::Result<Self> {
        let mut origins = Vec::new();
        for o in text.split(',').map(str::trim).filter(|o| !o.is_empty()) {
            ensure!(
                o != "*" && o != "null",
                "TUTELA_CORS_ORIGINS names exact origins: no `*` and no `null`"
            );
            let (scheme, host) = o
                .split_once("://")
                .with_context(|| format!("TUTELA_CORS_ORIGINS: {o:?} is not an origin"))?;
            ensure!(
                !host.is_empty()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
                    && !host.starts_with('.')
                    && !host.contains('*'),
                "TUTELA_CORS_ORIGINS: {o:?} must be scheme://host[:port], with no path"
            );
            let loopback = {
                let name = host.rsplit_once(':').map_or(host, |(h, p)| {
                    if p.bytes().all(|b| b.is_ascii_digit()) {
                        h
                    } else {
                        host
                    }
                });
                name == "localhost" || name == "127.0.0.1" || name == "[::1]"
            };
            ensure!(
                scheme == "https" || (scheme == "http" && dev_mode && loopback),
                "TUTELA_CORS_ORIGINS: {o:?} must be https (http only on loopback in dev mode)"
            );
            let o = o.to_ascii_lowercase();
            if !origins.contains(&o) {
                origins.push(o);
            }
        }
        Ok(Self { origins })
    }

    /// Whether CORS is on.
    #[must_use]
    pub fn is_on(&self) -> bool {
        !self.origins.is_empty()
    }

    /// The listed origin a request comes from, as sent.
    fn allowed(&self, headers: &HeaderMap) -> Option<HeaderValue> {
        let origin = headers.get(header::ORIGIN)?;
        let text = origin.to_str().ok()?;
        self.origins
            .iter()
            .any(|o| o.eq_ignore_ascii_case(text))
            .then(|| origin.clone())
    }
}

fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/grpc"))
}

fn vary(h: &mut HeaderMap, value: &'static str) {
    h.append(header::VARY, HeaderValue::from_static(value));
}

/// The middleware: answers a listed origin's preflight, and adds the
/// headers to every answer to a listed origin.
pub async fn layer(State(cors): State<Arc<Cors>>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if !cors.is_on() || crate::console::owns(path) || is_grpc(req.headers()) {
        return next.run(req).await;
    }
    let Some(origin) = cors.allowed(req.headers()) else {
        let mut res = next.run(req).await;
        vary(res.headers_mut(), "origin");
        return res;
    };
    if req.method() == Method::OPTIONS
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::NO_CONTENT;
        let h = res.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(ALLOW_METHODS),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(ALLOW_HEADERS),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(MAX_AGE),
        );
        vary(
            h,
            "origin, access-control-request-method, access-control-request-headers",
        );
        return res;
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSE_HEADERS),
    );
    vary(h, "origin");
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_origins_only() {
        let c = Cors::parse(
            "https://app.example.com, https://crm.example.com:8443",
            false,
        )
        .unwrap();
        assert!(c.is_on());
        assert!(!Cors::parse("", false).unwrap().is_on());
        for bad in [
            "*",
            "null",
            "https://*.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://user@app.example.com",
            "app.example.com",
            "http://app.example.com",
            "ftp://app.example.com",
        ] {
            assert!(Cors::parse(bad, false).is_err(), "{bad}");
        }
        // http only on loopback, only in dev mode.
        assert!(Cors::parse("http://127.0.0.1:5173", false).is_err());
        assert!(Cors::parse("http://127.0.0.1:5173", true).is_ok());
        assert!(Cors::parse("http://localhost:5173", true).is_ok());
        assert!(Cors::parse("http://app.example.com", true).is_err());
    }

    #[test]
    fn an_origin_matches_exactly() {
        let c = Cors::parse("https://app.example.com", false).unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example.com"),
        );
        assert!(c.allowed(&h).is_some());
        for other in [
            "https://app.example.com.evil.test",
            "https://evil.app.example.com",
            "http://app.example.com",
            "https://app.example.com:444",
            "null",
        ] {
            h.insert(header::ORIGIN, HeaderValue::from_static(other));
            assert!(c.allowed(&h).is_none(), "{other}");
        }
    }
}
