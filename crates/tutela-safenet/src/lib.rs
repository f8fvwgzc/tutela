//! SSRF-safe outbound HTTP for Tutela (`tutela-safenet`), Phase A
//! (THREAT-MODEL.md TM-18). Ported from the design of onto-intelli
//! `crates/onto-control/src/net.rs` and `crates/onto-intelli/src/net.rs`
//! (MIT).
//!
//! A [`Client`] reaches only public addresses:
//!
//! - [`check_url`] runs before each request: `https` only (`http` only to
//!   loopback in dev mode), no credentials in the URL, and an IP literal
//!   host must be allowed as written. The URL parser has already turned
//!   decimal, hex and octal forms (`2130706433`, `0x7f.1`) into the address
//!   they mean.
//! - A host name is resolved **once**, inside the client's own resolver.
//!   Every address is checked, and the connection uses exactly those
//!   addresses, so a name that changes its answer after a check cannot slip
//!   through (DNS rebinding).
//! - Redirects are never followed and no proxy is used. Connect and total
//!   timeouts are set, and the response body has a size limit.
//! - An operator may allow named private hosts (for example an internal
//!   Keycloak) in [`Policy::allow_private_host`]. There is no switch that
//!   allows every private address.
//!
//! TLS is rustls on aws-lc-rs, with the platform's root certificates.
//! Errors never contain a URL's credentials or a response body.

mod ip;

use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

pub use ip::public_ip;
pub use reqwest::Url;

/// The default total timeout of one request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// The default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The default largest response body: 1 MiB.
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;

/// Why a request was refused or failed. The texts never hold a URL's
/// credentials or a response body.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SafenetError {
    /// The URL breaks a rule; the text says which.
    #[error("refused URL: {0}")]
    Url(&'static str),
    /// The host is, or resolves to, an address that is not allowed.
    #[error("refused: {host} is not a public address")]
    NotPublic {
        /// The host as written in the URL.
        host: String,
    },
    /// The host has no addresses.
    #[error("{host} does not resolve")]
    NoAddress {
        /// The host as written in the URL.
        host: String,
    },
    /// A header that the caller may not set.
    #[error("refused header: {0}")]
    Header(&'static str),
    /// The response body is larger than the limit.
    #[error("the response body is larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// The request took longer than the timeout.
    #[error("the request timed out")]
    Timeout,
    /// Connecting, TLS or HTTP failed.
    #[error("the request failed: {0}")]
    Http(String),
}

impl SafenetError {
    fn from_reqwest(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            return Self::Timeout;
        }
        // The resolver's own refusal travels as the error source.
        let mut source = std::error::Error::source(&e);
        while let Some(s) = source {
            if let Some(refused) = s.downcast_ref::<Refused>() {
                return refused.0.clone().into_error();
            }
            source = s.source();
        }
        Self::Http(e.without_url().to_string())
    }
}

/// What outbound requests may reach.
#[derive(Clone, Debug)]
pub struct Policy {
    dev_loopback: bool,
    private_hosts: BTreeSet<String>,
    timeout: Duration,
    connect_timeout: Duration,
    max_body: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            dev_loopback: false,
            private_hosts: BTreeSet::new(),
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
        }
    }
}

impl Policy {
    /// The production policy: public addresses over `https` only.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Dev mode: `http` and `https` to loopback (`localhost`, `127.0.0.0/8`,
    /// `::1`) are allowed too. Never use it in production.
    #[must_use]
    pub const fn dev_loopback(mut self) -> Self {
        self.dev_loopback = true;
        self
    }

    /// Allows one named host to resolve to private addresses (an internal
    /// service needed on purpose). The name is matched exactly, ignoring
    /// case. `https` is still required.
    ///
    /// # Errors
    ///
    /// [`SafenetError::Url`] for an empty name or one with characters a host
    /// name cannot have.
    pub fn allow_private_host(mut self, host: &str) -> Result<Self, SafenetError> {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let ok = !h.is_empty()
            && h.len() <= 253
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':'));
        if !ok {
            return Err(SafenetError::Url(
                "an allowed private host is a plain host name or IP",
            ));
        }
        self.private_hosts.insert(h);
        Ok(self)
    }

    /// The total timeout of one request.
    #[must_use]
    pub const fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// The connect timeout.
    #[must_use]
    pub const fn connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = t;
        self
    }

    /// The largest response body read.
    #[must_use]
    pub const fn max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    fn private_ok(&self, host: &str) -> bool {
        self.private_hosts
            .contains(host.trim_end_matches('.').to_ascii_lowercase().as_str())
    }

    /// `true` if `host` may connect to `ip` under this policy.
    fn allows(&self, host: &str, ip: IpAddr) -> bool {
        public_ip(ip)
            || (self.dev_loopback && ip.is_loopback())
            || (self.private_ok(host) && !ip.is_unspecified() && !ip.is_multicast())
    }
}

/// `true` for `localhost` and its subdomains.
fn is_localhost(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

/// Checks a URL against `policy` before a request. Returns the parsed URL.
///
/// # Errors
///
/// [`SafenetError::Url`] for a URL that breaks a rule, or
/// [`SafenetError::NotPublic`] for an IP literal that is not allowed.
pub fn check_url(raw: &str, policy: &Policy) -> Result<Url, SafenetError> {
    let url = Url::parse(raw.trim()).map_err(|_| SafenetError::Url("the URL does not parse"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SafenetError::Url("a URL may not carry credentials"));
    }
    let host = url.host().ok_or(SafenetError::Url("the URL has no host"))?;
    let (ip, name) = match host {
        url::Host::Ipv4(v4) => (Some(IpAddr::V4(v4)), v4.to_string()),
        url::Host::Ipv6(v6) => (Some(IpAddr::V6(v6)), v6.to_string()),
        url::Host::Domain(d) => (None, d.to_owned()),
    };
    let loopback = ip.map_or_else(|| is_localhost(&name), |a| a.is_loopback());
    match url.scheme() {
        "https" => {}
        "http" if policy.dev_loopback && loopback => {}
        "http" => {
            return Err(SafenetError::Url(
                "http is allowed only to loopback in dev mode",
            ));
        }
        _ => return Err(SafenetError::Url("the scheme must be https")),
    }
    if let Some(ip) = ip
        && !policy.allows(&name, ip)
    {
        return Err(SafenetError::NotPublic { host: name });
    }
    if ip.is_none() && is_localhost(&name) && !policy.dev_loopback {
        return Err(SafenetError::NotPublic { host: name });
    }
    Ok(url)
}

/// A resolver refusal, carried through reqwest to [`SafenetError`].
#[derive(Debug)]
struct Refused(RefusedKind);

#[derive(Clone, Debug)]
enum RefusedKind {
    NotPublic(String),
    NoAddress(String),
}

impl RefusedKind {
    fn into_error(self) -> SafenetError {
        match self {
            Self::NotPublic(host) => SafenetError::NotPublic { host },
            Self::NoAddress(host) => SafenetError::NoAddress { host },
        }
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            RefusedKind::NotPublic(h) => write!(f, "{h} is not a public address"),
            RefusedKind::NoAddress(h) => write!(f, "{h} does not resolve"),
        }
    }
}

impl std::error::Error for Refused {}

/// Looks up the addresses of a host name. The system resolver in
/// production; tests give their own.
pub trait Lookup: Send + Sync + 'static {
    /// The addresses of `host`.
    fn lookup(&self, host: String)
    -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
}

/// The system resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

/// The client's resolver: one lookup, every address checked, and exactly
/// those addresses returned for the connection.
struct Guard {
    lookup: Arc<dyn Lookup>,
    policy: Arc<Policy>,
}

impl Guard {
    async fn checked(
        lookup: Arc<dyn Lookup>,
        policy: Arc<Policy>,
        host: String,
    ) -> Result<Vec<IpAddr>, Refused> {
        let addrs = lookup
            .lookup(host.clone())
            .await
            .map_err(|_| Refused(RefusedKind::NoAddress(host.clone())))?;
        if addrs.is_empty() {
            return Err(Refused(RefusedKind::NoAddress(host)));
        }
        // `localhost` must stay on this machine, also in dev mode.
        let must_loop = is_localhost(&host);
        if addrs
            .iter()
            .any(|ip| !policy.allows(&host, *ip) || (must_loop && !ip.is_loopback()))
        {
            return Err(Refused(RefusedKind::NotPublic(host)));
        }
        Ok(addrs)
    }
}

impl Resolve for Guard {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = Arc::clone(&self.lookup);
        let policy = Arc::clone(&self.policy);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = Self::checked(lookup, policy, host)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0))) as Addrs)
        })
    }
}

/// A response: status, headers and a body read up to the size limit. A
/// redirect is returned as is, never followed.
#[derive(Clone, Debug)]
pub struct Response {
    /// The HTTP status code.
    pub status: u16,
    /// The response headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A header value as text, if present and visible ASCII.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// `true` for a 2xx status.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Header names a caller may not set: the client sets them, or they would
/// leak context to outside hosts.
const RESERVED_HEADERS: [&str; 8] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "baggage",
    "upgrade",
];

/// The SSRF-safe HTTP client.
#[derive(Clone, Debug)]
pub struct Client {
    http: reqwest::Client,
    policy: Arc<Policy>,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard").finish_non_exhaustive()
    }
}

impl Client {
    /// A client with the system resolver.
    ///
    /// # Errors
    ///
    /// [`SafenetError::Http`] if the TLS setup fails.
    pub fn new(policy: Policy) -> Result<Self, SafenetError> {
        Self::with_lookup(policy, Arc::new(SystemLookup))
    }

    /// A client with its own resolver (for tests and for an operator's own
    /// DNS).
    ///
    /// # Errors
    ///
    /// [`SafenetError::Http`] if the TLS setup fails.
    pub fn with_lookup(policy: Policy, lookup: Arc<dyn Lookup>) -> Result<Self, SafenetError> {
        let policy = Arc::new(policy);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(!policy.dev_loopback)
            .timeout(policy.timeout)
            .connect_timeout(policy.connect_timeout)
            .user_agent(concat!("tutela-safenet/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(Guard {
                lookup,
                policy: Arc::clone(&policy),
            }))
            .build()
            .map_err(|e| SafenetError::Http(e.to_string()))?;
        Ok(Self { http, policy })
    }

    /// `GET url`.
    ///
    /// # Errors
    ///
    /// The [`SafenetError`] that says why it was refused or failed.
    pub async fn get(&self, url: &str) -> Result<Response, SafenetError> {
        let url = check_url(url, &self.policy)?;
        self.send(self.http.get(url)).await
    }

    /// `POST url` with a body and extra headers.
    ///
    /// # Errors
    ///
    /// [`SafenetError::Header`] for a header the caller may not set, or the
    /// [`SafenetError`] that says why it was refused or failed.
    pub async fn post(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> Result<Response, SafenetError> {
        let url = check_url(url, &self.policy)?;
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            let name = HeaderName::from_bytes(k.trim().as_bytes())
                .map_err(|_| SafenetError::Header("not a valid header name"))?;
            if RESERVED_HEADERS.contains(&name.as_str()) {
                return Err(SafenetError::Header(
                    "this header is set by the client or never sent",
                ));
            }
            let value = HeaderValue::from_str(v)
                .map_err(|_| SafenetError::Header("not a valid header value"))?;
            map.append(name, value);
        }
        let content_type = HeaderValue::from_str(content_type)
            .map_err(|_| SafenetError::Header("not a valid content type"))?;
        map.insert(reqwest::header::CONTENT_TYPE, content_type);
        self.send(self.http.post(url).headers(map).body(body)).await
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Response, SafenetError> {
        let limit = self.policy.max_body;
        let mut resp = req.send().await.map_err(SafenetError::from_reqwest)?;
        if resp
            .content_length()
            .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > limit))
        {
            return Err(SafenetError::TooLarge { limit });
        }
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(SafenetError::from_reqwest)? {
            if body.len() + chunk.len() > limit {
                return Err(SafenetError::TooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests;
