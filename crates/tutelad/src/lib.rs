//! The Tutela service (`tutelad`), Phase B.
//!
//! A library plus a thin binary, so the tests run the same service as
//! production. See `docs/ARCHITECTURE.md` and ADR-0018.
//!
//! - [`config`]: `TUTELA_*` variables and the trust file.
//! - [`console`]: the Tutela Console's files, under `/console/` (ADR-0050).
//! - [`cors`]: CORS for listed origins, off by default (ADR-0054).
//! - [`api`]: the API port (HTTP and gRPC on one listener, every request
//!   behind [`tutela_sdk::http::AuthLayer`]) and the ops port (`/healthz`,
//!   `/readyz`, `/metrics`).
//! - [`admin`]: the admin API, `tutela.admin.v1` and its HTTP routes.
//! - [`apps`]: apps, their client secrets, and client authentication at
//!   the token endpoint.
//! - [`authz`]: the permission decision APIs, one code path for HTTP and gRPC.
//! - [`bundle`]: signed bundles of a tenant's data, for offline checks.
//! - [`cache`]: the tenant data decisions are made from, and how it stays
//!   current.
//! - [`tenant`]: how a request gets its tenant, from the verified token only.
//! - [`db`]: the connection pool, and [`db::Conn::begin`], the one way to
//!   run a query as a tenant.
//! - [`expiry`]: the timer that removes expired assignments and bumps the
//!   revision.
//! - [`keys`]: the service's own issuer: its signing keys and its JWKS.
//! - [`ledger`]: forwarding audit records to attache's evidence ledger.
//! - [`lifecycle`]: making and restoring a tenant (the operator's), and the
//!   purge after a soft delete.
//! - [`events`]: the CloudEvents envelope of the outbox's events.
//! - [`exchange`]: token exchange (RFC 8693) at `POST /oauth2/token`.
//! - [`revocation`]: raised epochs and disabled principals, per tenant.
//! - [`audit`]: the records `tutelad` writes to the local audit log.
//! - [`telemetry`]: JSON logs and Prometheus metrics.
//! - [`webhooks`]: delivery of the outbox's events to webhooks.
//! - [`stream`]: `GET /v1/events`, a tenant's events as Server-Sent Events.
//! - [`server`]: the two listeners and the graceful shutdown.

pub mod admin;
pub mod api;
pub mod apps;
pub mod audit;
pub mod authz;
pub mod bundle;
pub mod cache;
pub mod config;
pub mod console;
pub mod cors;
pub mod db;
pub mod events;
pub mod exchange;
pub mod expiry;
pub mod keys;
pub mod ledger;
pub mod lifecycle;
pub mod models;
pub mod revocation;
pub mod server;
pub mod stream;
pub mod telemetry;
pub mod tenant;
pub mod webhooks;

pub use config::Config;
pub use server::{Server, run};
