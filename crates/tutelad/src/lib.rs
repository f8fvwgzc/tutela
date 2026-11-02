//! The Tutela service (`tutelad`), Phase B.
//!
//! A library plus a thin binary, so the tests run the same service as
//! production. See `docs/ARCHITECTURE.md` and ADR-0018.
//!
//! - [`config`]: `TUTELA_*` variables and the trust file.
//! - [`api`]: the API port (HTTP and gRPC on one listener, every request
//!   behind [`tutela_sdk::http::AuthLayer`]) and the ops port (`/healthz`,
//!   `/readyz`, `/metrics`).
//! - [`tenant`]: how a request gets its tenant, from the verified token only.
//! - [`db`]: the connection pool, and [`db::Conn::begin`], the one way to
//!   run a query as a tenant.
//! - [`expiry`]: the timer that removes expired assignments and bumps the
//!   revision.
//! - [`telemetry`]: JSON logs and Prometheus metrics.
//! - [`server`]: the two listeners and the graceful shutdown.

pub mod api;
pub mod config;
pub mod db;
pub mod expiry;
pub mod server;
pub mod telemetry;
pub mod tenant;

pub use config::Config;
pub use server::{Server, run};
