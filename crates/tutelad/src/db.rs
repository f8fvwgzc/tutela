//! The connection pool, and the one way to run a query as a tenant.
//!
//! `tutelad` connects as a role that owns nothing; migrations run as the
//! owner (THREAT-MODEL.md TM-14). A connection goes back through
//! [`RecyclingMethod::Clean`], so `RESET ALL` runs on every reuse: even a
//! session-level setting left by a bug does not reach the next request.
//!
//! [`Db::conn`] gives a [`Conn`], which has no query methods. A handler
//! reaches the database through [`Conn::begin`], which takes a [`Tenant`]:
//!
//! ```no_run
//! # async fn f(db: tutelad::db::Db, tenant: tutelad::tenant::Tenant)
//! # -> Result<u64, tutelad::db::DbError> {
//! let mut conn = db.conn().await?;
//! let tx = conn.begin(&tenant).await?;
//! let rev = tutela_store::rev(&tx, tenant.key()).await?;
//! tx.commit().await?;
//! # Ok(rev) }
//! ```

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use tutela_contracts::tenant::TenantKey;
use tutela_store::tokio_postgres::{self, NoTls};
use tutela_store::{StoreError, StoreErrorKind, Transport};

use crate::tenant::Tenant;

/// How long a request waits for a connection, and for a new one to open.
const POOL_WAIT: Duration = Duration::from_secs(5);
/// Set on every connection, so one bad query cannot hold a connection.
const SESSION_OPTIONS: &str =
    "-c statement_timeout=5000 -c idle_in_transaction_session_timeout=10000";

/// The database, as `tutelad` reaches it.
#[derive(Clone, Debug)]
pub struct Db {
    pool: Pool,
    /// [`tutela_store::check_isolation`] passed. A query waits for this.
    isolated: Arc<AtomicBool>,
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
    /// The role or the schema does not isolate tenants.
    #[error("tenant isolation is not in force")]
    Isolation(#[source] StoreError),
    /// A connection from the pool still has a tenant set. This is a bug.
    #[error("a pooled connection still has tenant {0} set")]
    TenantLeft(String),
}

impl NotReady {
    /// `true` when the role or the schema does not isolate tenants: the
    /// service must not start.
    #[must_use]
    pub const fn is_unsafe(&self) -> bool {
        matches!(self, Self::Isolation(_) | Self::TenantLeft(_))
    }
}

/// Why a query could not run. The answer to the caller is the same for
/// everything here except an unknown tenant: fail closed, say nothing.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// The service is not ready to use the database.
    #[error("the database is not usable")]
    NotReady(#[from] NotReady),
    /// The driver failed.
    #[error("database error")]
    Driver(#[source] tokio_postgres::Error),
    /// A store call failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Driver(e)
    }
}

impl DbError {
    /// The store's kind, when a store call failed.
    #[must_use]
    pub const fn store_kind(&self) -> Option<StoreErrorKind> {
        match self {
            Self::Store(e) => Some(e.kind()),
            _ => None,
        }
    }

    /// The SQLSTATE, when the server sent one. Safe to log: unlike the
    /// server's message, it never holds a value.
    #[must_use]
    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            Self::Driver(e) => e.code().map(tokio_postgres::error::SqlState::code),
            Self::Store(e) => e.sqlstate(),
            Self::NotReady(_) => None,
        }
    }
}

/// A connection from the pool, with no tenant yet. It has no query methods.
#[derive(Debug)]
pub struct Conn(Object);

impl Conn {
    /// Starts a transaction as `tenant`. Everything in it sees that tenant's
    /// rows only. The setting ends with the transaction, on commit, on
    /// rollback or on drop.
    ///
    /// # Errors
    ///
    /// [`StoreErrorKind::UnknownTenant`] for a tenant that is not in the
    /// directory, or a database error.
    pub async fn begin(&mut self, tenant: &Tenant) -> Result<TenantTx<'_>, DbError> {
        let tx = self.0.transaction().await?;
        tutela_store::enter(&tx, tenant.key()).await?;
        Ok(TenantTx {
            tx,
            tenant: tenant.key().clone(),
        })
    }
}

impl Conn {
    /// The tenants in the directory, for a job that serves all of them.
    pub(crate) async fn tenants(&mut self) -> Result<Vec<TenantKey>, DbError> {
        let tx = self.0.transaction().await?;
        let tenants = tutela_store::tenants(&tx).await?;
        tx.commit().await?;
        Ok(tenants)
    }

    /// One tenant's expiry sweep, in its own transaction. A job has no token
    /// to take a [`Tenant`] from, so this does the one thing it needs, and
    /// a handler cannot reach it.
    pub(crate) async fn expire(
        &mut self,
        tenant: &TenantKey,
    ) -> Result<Option<tutela_store::Expired>, DbError> {
        let tx = self.0.transaction().await?;
        let gone = tutela_store::expire_assignments(&tx, tenant).await?;
        tx.commit().await?;
        Ok(gone)
    }
}

/// A transaction inside one tenant. It reads as a
/// [`tokio_postgres::Transaction`], so store calls take `&tx`. Dropping it
/// rolls back.
#[derive(Debug)]
pub struct TenantTx<'c> {
    tx: deadpool_postgres::Transaction<'c>,
    tenant: TenantKey,
}

impl<'c> Deref for TenantTx<'c> {
    type Target = tokio_postgres::Transaction<'c>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl TenantTx<'_> {
    /// The tenant this transaction belongs to.
    #[must_use]
    pub const fn tenant(&self) -> &TenantKey {
        &self.tenant
    }

    /// Commits.
    ///
    /// # Errors
    ///
    /// A database error. Nothing stays.
    pub async fn commit(self) -> Result<(), DbError> {
        Ok(self.tx.commit().await?)
    }
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
        Ok(Self {
            pool,
            isolated: Arc::default(),
        })
    }

    /// A connection, once the role and the schema are known to isolate
    /// tenants.
    ///
    /// # Errors
    ///
    /// [`NotReady`] when there is no connection, or when isolation is not in
    /// force.
    pub async fn conn(&self) -> Result<Conn, DbError> {
        if !self.isolated.load(Ordering::Acquire) {
            self.check_ready().await?;
        }
        Ok(Conn(self.object().await?))
    }

    async fn object(&self) -> Result<Object, NotReady> {
        self.pool
            .get()
            .await
            .map_err(|e| NotReady::Connection(Box::new(e)))
    }

    /// Runs the migrations and gives `service_role` its grants. Call it on a
    /// pool of the **owner** role; `tutelad migrate` does.
    ///
    /// # Errors
    ///
    /// When a connection, a migration or a grant fails.
    pub async fn migrate(&self, service_role: &str) -> anyhow::Result<Vec<i32>> {
        let mut client = self.object().await?;
        client
            .batch_execute("SET statement_timeout = 0")
            .await
            .context("clearing the statement timeout")?;
        let applied = tutela_store::migrate(&mut client)
            .await
            .context("running the migrations")?;
        tutela_store::grant_service(&mut client, service_role)
            .await
            .context("granting the service role")?;
        Ok(applied)
    }

    /// Connections held, and how many of them are idle.
    #[must_use]
    pub fn sizes(&self) -> (usize, usize) {
        let s = self.pool.status();
        (s.size, s.available)
    }

    /// Checks that a connection works, that the schema is the one this build
    /// knows, and that the role and the schema isolate tenants. A failed
    /// isolation check stops every query until a later check passes.
    ///
    /// # Errors
    ///
    /// A [`NotReady`] that says why.
    pub async fn check_ready(&self) -> Result<(), NotReady> {
        let client = self.object().await?;
        let isolation = tutela_store::check_isolation(&client).await;
        self.isolated.store(isolation.is_ok(), Ordering::Release);
        isolation.map_err(|e| match e.kind() {
            StoreErrorKind::Isolation => NotReady::Isolation(e),
            _ => NotReady::Schema(e),
        })?;
        let have = tutela_store::applied_migration(&client)
            .await
            .map_err(NotReady::Schema)?;
        let need = tutela_store::latest_migration();
        if have != need {
            return Err(NotReady::SchemaVersion { have, need });
        }
        if let Some(leftover) = leftover(&client).await? {
            self.isolated.store(false, Ordering::Release);
            return Err(NotReady::TenantLeft(leftover));
        }
        Ok(())
    }

    /// The tenant set on a connection fresh from the pool. It is always
    /// `None`: `SET LOCAL` ends with the transaction, and recycling clears
    /// the rest. Readiness watches it.
    ///
    /// # Errors
    ///
    /// [`NotReady`] when there is no connection.
    pub async fn leftover_tenant(&self) -> Result<Option<String>, NotReady> {
        leftover(&*self.object().await?).await
    }
}

async fn leftover(client: &tokio_postgres::Client) -> Result<Option<String>, NotReady> {
    client
        .query_one("SELECT current_setting('tutela.tenant_id', true)", &[])
        .await
        .and_then(|r| r.try_get::<_, Option<String>>(0))
        .map(|t| t.filter(|t| !t.is_empty()))
        .map_err(|e| NotReady::Connection(Box::new(e)))
}
