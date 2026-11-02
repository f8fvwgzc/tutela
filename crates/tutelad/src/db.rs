//! The connection pool.
//!
//! `tutelad` connects as a role that owns nothing; migrations run as the
//! owner (THREAT-MODEL.md TM-14). A connection goes back through
//! [`RecyclingMethod::Clean`], so `RESET ALL` runs on every reuse: even a
//! session-level setting left by a bug does not reach the next request.

use std::time::Duration;

use anyhow::{Context as _, anyhow};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tutela_store::tokio_postgres::NoTls;
use tutela_store::{StoreError, Transport};

/// How long a request waits for a connection, and for a new one to open.
const POOL_WAIT: Duration = Duration::from_secs(5);
/// Set on every connection, so one bad query cannot hold a connection.
const SESSION_OPTIONS: &str =
    "-c statement_timeout=5000 -c idle_in_transaction_session_timeout=10000";

/// The database, as `tutelad` reaches it.
#[derive(Clone, Debug)]
pub struct Db {
    pool: Pool,
}

/// Why the service is not ready to use the database.
#[derive(Debug, thiserror::Error)]
pub enum NotReady {
    /// No connection could be had.
    #[error("no database connection")]
    Connection(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A statement failed.
    #[error("the schema could not be read")]
    Schema(#[source] StoreError),
    /// The schema is not the one this build knows. An old binary never
    /// runs on a newer schema (ADR-0014).
    #[error("the schema is at migration {have}, this build needs {need}")]
    SchemaVersion {
        /// The newest migration in the database.
        have: i32,
        /// The newest migration this build knows.
        need: i32,
    },
}

impl Db {
    /// A pool over `url`. It connects on first use, so a database that is
    /// down at start-up shows as "not ready", not as a crash.
    ///
    /// # Errors
    ///
    /// A URL that does not parse, a remote host without TLS, or a failed TLS
    /// setup. The text never holds the URL.
    pub fn connect(url: &str, size: usize) -> anyhow::Result<Self> {
        let (mut pg, transport) = tutela_store::database_config(url)
            .map_err(|e| anyhow!(e.detail().unwrap_or("TUTELA_DATABASE_URL is not valid")))?;
        pg.application_name("tutelad");
        let options = pg.get_options().map_or_else(
            || SESSION_OPTIONS.to_owned(),
            |o| format!("{o} {SESSION_OPTIONS}"),
        );
        pg.options(options);
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Clean,
        };
        let manager = match transport {
            Transport::Local => Manager::from_config(pg, NoTls, manager_config),
            Transport::Tls => {
                let tls = tutela_safenet::tls_client_config().context("setting up database TLS")?;
                Manager::from_config(
                    pg,
                    tokio_postgres_rustls::MakeRustlsConnect::new(tls),
                    manager_config,
                )
            }
        };
        let pool = Pool::builder(manager)
            .max_size(size)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(POOL_WAIT))
            .create_timeout(Some(POOL_WAIT))
            .recycle_timeout(Some(POOL_WAIT))
            .build()
            .context("building the connection pool")?;
        Ok(Self { pool })
    }

    /// Connections held, and how many of them are idle.
    #[must_use]
    pub fn sizes(&self) -> (usize, usize) {
        let s = self.pool.status();
        (s.size, s.available)
    }

    /// Checks that a connection works and that the schema is the one this
    /// build knows.
    ///
    /// # Errors
    ///
    /// A [`NotReady`] that says why.
    pub async fn check_ready(&self) -> Result<(), NotReady> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| NotReady::Connection(Box::new(e)))?;
        let have = tutela_store::applied_migration(&client)
            .await
            .map_err(NotReady::Schema)?;
        let need = tutela_store::latest_migration();
        if have == need {
            Ok(())
        } else {
            Err(NotReady::SchemaVersion { have, need })
        }
    }
}
