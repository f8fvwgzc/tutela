//! Structured logs and metrics.
//!
//! Logs and metrics never hold tokens or personal data (THREAT-MODEL.md
//! TM-17): a request is logged by its route pattern, not its URL, and only
//! ids and kinds go in fields. Metric labels never hold a tenant.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context as _, anyhow};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use tracing::Instrument as _;
use tracing_subscriber::EnvFilter;
use tutela_sdk::Step;

/// Installs the JSON log writer on stdout. Called once, by the binary.
///
/// # Errors
///
/// A bad filter, or a second call.
pub fn init_logs(filter: &str) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_env_filter(EnvFilter::try_new(filter).context("TUTELA_LOG is not valid")?)
        .try_init()
        .map_err(|e| anyhow!("installing the log writer: {e}"))
}

/// The trace id of a W3C `traceparent` header, if it is well formed.
fn trace_id(traceparent: &HeaderValue) -> Option<&str> {
    let text = traceparent.to_str().ok()?;
    let mut parts = text.split('-');
    let (version, trace, parent, flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let hex = |s: &str, len: usize| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let ok = hex(version, 2)
        && version != "ff"
        && hex(trace, 32)
        && trace != "0".repeat(32)
        && hex(parent, 16)
        && parent != "0".repeat(16)
        && hex(flags, 2);
    ok.then_some(trace)
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    method: String,
    route: String,
    status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteLabels {
    route: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RefusalLabels {
    step: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SweepLabels {
    result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DecisionLabels {
    operation: String,
    outcome: String,
}

/// How one question ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
    /// No decision: the caller fails closed.
    Error,
}

impl Outcome {
    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }
}

/// The id of a request: the caller's own, so that it can follow the request
/// (AuthZEN 1.0 section 10.1.3), when it is short visible ASCII. Otherwise
/// a new one.
fn request_id(sent: Option<&HeaderValue>) -> String {
    sent.and_then(|v| v.to_str().ok())
        .filter(|s| (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic()))
        .map_or_else(|| uuid::Uuid::now_v7().to_string(), str::to_owned)
}

/// Latency buckets from 1 ms to about 16 s.
fn latency_histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.001, 2.0, 15))
}

/// The service's metrics, in the Prometheus text format at `/metrics`.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    requests: Family<RequestLabels, Counter>,
    latency: Family<RouteLabels, Histogram, fn() -> Histogram>,
    refusals: Family<RefusalLabels, Counter>,
    pool_size: Gauge,
    pool_available: Gauge,
    expired: Counter,
    sweeps: Family<SweepLabels, Counter>,
    decisions: Family<DecisionLabels, Counter>,
    revision_checks: Family<SweepLabels, Counter>,
    tenant_loads: Family<SweepLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Empty metrics.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("tutelad");
        let requests = Family::<RequestLabels, Counter>::default();
        registry.register(
            "http_requests",
            "Requests served on the API port",
            requests.clone(),
        );
        let latency: Family<RouteLabels, Histogram, fn() -> Histogram> =
            Family::new_with_constructor(latency_histogram);
        registry.register(
            "http_request_duration_seconds",
            "Time to answer a request on the API port",
            latency.clone(),
        );
        let refusals = Family::<RefusalLabels, Counter>::default();
        registry.register(
            "auth_refusals",
            "Requests refused with 401, by verification step",
            refusals.clone(),
        );
        let pool_size = Gauge::default();
        registry.register(
            "db_pool_connections",
            "Connections held by the pool",
            pool_size.clone(),
        );
        let pool_available = Gauge::default();
        registry.register(
            "db_pool_available",
            "Idle connections in the pool",
            pool_available.clone(),
        );
        let expired = Counter::default();
        registry.register(
            "assignments_expired",
            "Role assignments removed because they expired",
            expired.clone(),
        );
        let sweeps = Family::<SweepLabels, Counter>::default();
        registry.register("expiry_sweeps", "Expiry sweeps, by result", sweeps.clone());
        let decisions = Family::<DecisionLabels, Counter>::default();
        registry.register(
            "decisions",
            "Permission questions, by operation and outcome",
            decisions.clone(),
        );
        let revision_checks = Family::<SweepLabels, Counter>::default();
        registry.register(
            "revision_checks",
            "Checks of a tenant's revision against the database, by result",
            revision_checks.clone(),
        );
        let tenant_loads = Family::<SweepLabels, Counter>::default();
        registry.register(
            "tenant_loads",
            "Whole-tenant loads from the database, by result",
            tenant_loads.clone(),
        );
        Self {
            registry,
            requests,
            latency,
            refusals,
            pool_size,
            pool_available,
            expired,
            sweeps,
            decisions,
            revision_checks,
            tenant_loads,
        }
    }

    /// Counts one question.
    pub fn count_decision(&self, operation: &'static str, outcome: Outcome) {
        self.decisions
            .get_or_create(&DecisionLabels {
                operation: operation.to_owned(),
                outcome: outcome.as_str().to_owned(),
            })
            .inc();
    }

    /// Counts one revision check.
    pub fn count_revision_check(&self, ok: bool) {
        count_result(&self.revision_checks, ok);
    }

    /// Counts one tenant load.
    pub fn count_tenant_load(&self, ok: bool) {
        count_result(&self.tenant_loads, ok);
    }

    /// Counts assignments the sweep removed.
    pub fn add_expired(&self, n: usize) {
        self.expired.inc_by(u64::try_from(n).unwrap_or(u64::MAX));
    }

    /// Counts one sweep.
    pub fn count_sweep(&self, ok: bool) {
        count_result(&self.sweeps, ok);
    }

    /// Records the pool's sizes, read at scrape time.
    pub fn set_pool(&self, size: usize, available: usize) {
        self.pool_size.set(i64::try_from(size).unwrap_or(i64::MAX));
        self.pool_available
            .set(i64::try_from(available).unwrap_or(i64::MAX));
    }

    /// The text exposition.
    ///
    /// # Errors
    ///
    /// When encoding fails.
    pub fn render(&self) -> Result<String, std::fmt::Error> {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &self.registry)?;
        Ok(out)
    }
}

fn count_result(family: &Family<SweepLabels, Counter>, ok: bool) {
    let result = if ok { "ok" } else { "failed" };
    family
        .get_or_create(&SweepLabels {
            result: result.to_owned(),
        })
        .inc();
}

/// Logs and counts each request on the API port, and gives it a request id.
pub async fn observe(State(metrics): State<Arc<Metrics>>, req: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().to_string();
    // The pattern, never the URL: a URL may hold ids.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let request_id = request_id(req.headers().get("x-request-id"));
    let trace = req.headers().get("traceparent").and_then(trace_id);
    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        trace_id = trace,
        method = %method,
        route = %route,
        tid = tracing::field::Empty,
    );
    let mut res = next.run(req).instrument(span.clone()).await;

    let status = res.status();
    let step = (status == StatusCode::UNAUTHORIZED).then(|| {
        res.extensions()
            .get::<Step>()
            .map_or("missing", |s| s.as_str())
    });
    if let Some(step) = step {
        metrics
            .refusals
            .get_or_create(&RefusalLabels {
                step: step.to_owned(),
            })
            .inc();
    }
    metrics
        .requests
        .get_or_create(&RequestLabels {
            method,
            route: route.clone(),
            status: status.as_u16(),
        })
        .inc();
    let elapsed = started.elapsed();
    metrics
        .latency
        .get_or_create(&RouteLabels { route })
        .observe(elapsed.as_secs_f64());
    span.in_scope(|| {
        tracing::info!(
            status = status.as_u16(),
            latency_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            refused_at = step,
            "request served"
        );
    });
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_well_formed_traceparent_gives_a_trace_id() {
        let id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let good = format!("00-{id}-00f067aa0ba902b7-01");
        let v = HeaderValue::from_str(&good).unwrap();
        assert_eq!(trace_id(&v), Some(id));
        for bad in [
            "",
            "00-short-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-<script>alert(1)</script>7b34da6-00f067aa0ba902b7-01",
        ] {
            assert_eq!(
                trace_id(&HeaderValue::from_str(bad).unwrap()),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_request_id_is_echoed_only_when_it_is_short_visible_ascii() {
        let good = HeaderValue::from_static("abc-123");
        assert_eq!(request_id(Some(&good)), "abc-123");
        let long = HeaderValue::from_str(&"a".repeat(129)).unwrap();
        for bad in [long, HeaderValue::from_static("has space")] {
            assert_ne!(request_id(Some(&bad)), bad.to_str().unwrap());
        }
        assert!(!request_id(None).is_empty());
    }

    #[test]
    fn decisions_are_counted_by_operation_and_outcome_only() {
        let m = Metrics::new();
        m.count_decision("evaluation", Outcome::Deny);
        let text = m.render().unwrap();
        assert!(
            text.contains("tutelad_decisions_total{operation=\"evaluation\",outcome=\"deny\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn metrics_render_in_the_text_format() {
        let m = Metrics::new();
        m.set_pool(3, 1);
        let text = m.render().unwrap();
        assert!(text.contains("tutelad_db_pool_connections 3"), "{text}");
        assert!(text.contains("tutelad_db_pool_available 1"), "{text}");
    }
}
