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
    /// The last [`Db::check_ready`] passed. A query waits for this.
    checked: Arc<AtomicBool>,
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
    /// An audit record could not be built. A bug; nothing commits.
    #[error("an audit record could not be built")]
    Audit(#[from] crate::audit::BuildError),
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
            Self::NotReady(_) | Self::Audit(_) => None,
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
    /// The tenant an app belongs to, from the app directory, which holds no
    /// tenant data: the token endpoint enters it to read the app's secret.
    pub(crate) async fn app_tenant(&mut self, app: &str) -> Result<Option<TenantKey>, DbError> {
        let tx = self.0.transaction().await?;
        let key = tutela_store::app_tenant(&tx, app).await?;
        tx.commit().await?;
        Ok(key)
    }

    /// The tenants in the directory, for a job that serves all of them.
    pub(crate) async fn tenants(&mut self) -> Result<Vec<TenantKey>, DbError> {
        let tx = self.0.transaction().await?;
        let tenants = tutela_store::tenants(&tx).await?;
        tx.commit().await?;
        Ok(tenants)
    }

    /// One tenant's expiry sweep, in its own transaction, with an audit
    /// record for each assignment it removed. A job has no token to take a
    /// [`Tenant`] from, so this does the one thing it needs, and a handler
    /// cannot reach it.
    pub(crate) async fn expire(
        &mut self,
        tenant: &TenantKey,
    ) -> Result<Option<tutela_store::Expired>, DbError> {
        let tx = self.0.transaction().await?;
        let gone = tutela_store::expire_assignments(&tx, tenant).await?;
        if let Some(g) = &gone {
            let drafts = crate::expiry::records(tenant, g)?;
            tutela_store::append_audit(&tx, tenant, &drafts).await?;
        }
        tx.commit().await?;
        Ok(gone)
    }
}

impl Conn {
    /// The soft-deleted tenants whose grace has passed (ADR-0041).
    pub(crate) async fn due_tenant_purges(&mut self) -> Result<Vec<TenantKey>, DbError> {
        let tx = self.0.transaction().await?;
        let due = tutela_store::due_tenant_purges(&tx).await?;
        tx.commit().await?;
        Ok(due)
    }

    /// Purges one soft-deleted tenant whose grace has passed, in a
    /// transaction of its own, with its record last in the tenant's own
    /// chain, which stays. `false` when it is not due, or another replica
    /// purged it first.
    pub(crate) async fn purge_tenant(&mut self, key: &TenantKey) -> Result<bool, DbError> {
        let tx = self.0.transaction().await?;
        if !tutela_store::purge_tenant(&tx, key).await? {
            return Ok(false);
        }
        tutela_store::append_audit(&tx, key, &crate::lifecycle::purge_records(key)?).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Purges the deleted orgs of one tenant whose grace has passed, each in
    /// a transaction of its own with its record. Returns how many.
    pub(crate) async fn purge_orgs(&mut self, key: &TenantKey) -> Result<usize, DbError> {
        let tx = self.0.transaction().await?;
        let due = tutela_store::due_org_purges(&tx, key).await?;
        tx.commit().await?;
        let mut done = 0;
        for org in due {
            let tx = self.0.transaction().await?;
            if let Some(rev) = tutela_store::purge_org(&tx, key, &org).await? {
                let drafts = crate::lifecycle::org_purge_records(key, &org, rev)?;
                tutela_store::append_audit(&tx, key, &drafts).await?;
                tx.commit().await?;
                done += 1;
            }
        }
        Ok(done)
    }

    /// Walks one tenant's audit chain (ADR-0034), in a read transaction of
    /// its own, and reports the first broken link.
    pub(crate) async fn verify_chain(
        &mut self,
        key: &TenantKey,
    ) -> Result<tutela_store::ChainReport, DbError> {
        let tx = self.0.transaction().await?;
        let report = tutela_store::verify_audit_chain(&tx, key).await?;
        tx.commit().await?;
        Ok(report)
    }

    /// [`Conn::verify_chain`] of the deployment's own chain.
    pub(crate) async fn verify_deployment_chain(
        &mut self,
    ) -> Result<tutela_store::ChainReport, DbError> {
        let tx = self.0.transaction().await?;
        let report = tutela_store::verify_deployment_audit_chain(&tx).await?;
        tx.commit().await?;
        Ok(report)
    }

    /// Writes `records` to the deployment's own chain, in a transaction of
    /// their own.
    pub(crate) async fn deployment_records(
        &mut self,
        records: Vec<crate::audit::Record>,
    ) -> Result<(), DbError> {
        let tx = self.0.transaction().await?;
        deployment_audit(&tx, records).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl Conn {
    /// The signing keys, in a transaction of their own: they are the
    /// deployment's, not a tenant's (ADR-0030). With no key that may sign,
    /// one is made; a key sealed under a previous master key is re-wrapped.
    /// Both are recorded in the deployment's audit chain (ADR-0034), whose
    /// tenant key names the service's own issuer `iss`.
    pub(crate) async fn signing_keys(
        &mut self,
        vault: &tutela_vault::Vault,
        iss: &tutela_contracts::tenant::Issuer,
    ) -> Result<tutela_store::KeySet, DbError> {
        let tx = self.0.transaction().await?;
        let mut set = tutela_store::signing_keys(&tx).await?;
        let mut records = Vec::new();
        if set.signing(set.now).is_none() {
            if let Some(kid) = tutela_store::ensure_signing_key(&tx, vault).await? {
                records.push(key_record(iss, "create", &kid)?.detail("kid", kid));
            }
            set = tutela_store::signing_keys(&tx).await?;
        }
        let current = vault.current_key();
        if set
            .keys
            .iter()
            .any(|k| vault.key_of(&k.sealed).is_ok_and(|id| id != current))
        {
            let n = tutela_store::rewrap_signing_keys(&tx, vault).await?;
            records.push(key_record(iss, "rewrap", "all")?.detail("rewrapped", n));
            set = tutela_store::signing_keys(&tx).await?;
        }
        deployment_audit(&tx, records).await?;
        tx.commit().await?;
        Ok(set)
    }

    /// Makes sure an audit producer key signs (ADR-0045): the stored one, or
    /// `import` (`TUTELA_AUDIT_KEY` from before) sealed, or a new one, with
    /// its record in the deployment's audit chain, in one transaction.
    pub(crate) async fn audit_key(
        &mut self,
        vault: &tutela_vault::Vault,
        iss: &tutela_contracts::tenant::Issuer,
        import: Option<&[u8]>,
    ) -> Result<tutela_store::Ensured, DbError> {
        let tx = self.0.transaction().await?;
        let ensured = tutela_store::ensure_audit_key(&tx, vault, import).await?;
        let record = match &ensured {
            tutela_store::Ensured::Kept { .. } => None,
            tutela_store::Ensured::Imported(kid) => {
                Some(audit_key_record(iss, "import", kid)?.detail("kid", kid.clone()))
            }
            tutela_store::Ensured::Made(kid) => {
                Some(audit_key_record(iss, "create", kid)?.detail("kid", kid.clone()))
            }
        };
        deployment_audit(&tx, record.into_iter().collect()).await?;
        tx.commit().await?;
        Ok(ensured)
    }

    /// The audit producer key that signs now.
    pub(crate) async fn signing_audit_key(
        &mut self,
    ) -> Result<Option<tutela_store::AuditKey>, DbError> {
        let tx = self.0.transaction().await?;
        let key = tutela_store::signing_audit_key(&tx).await?;
        tx.commit().await?;
        Ok(key)
    }

    /// Rotates the signing key (`tutela_store::rotate_signing_key`), with its
    /// record in the deployment's audit chain, in one transaction.
    pub(crate) async fn rotate_signing_key(
        &mut self,
        vault: &tutela_vault::Vault,
        iss: &tutela_contracts::tenant::Issuer,
        times: tutela_store::KeyTimes,
    ) -> Result<tutela_store::Rotation, DbError> {
        let tx = self.0.transaction().await?;
        let r = tutela_store::rotate_signing_key(&tx, vault, times).await?;
        if r.made {
            let millis = |t: std::time::SystemTime| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            };
            let record = key_record(iss, "rotate", &r.next)?
                .detail("next", r.next.clone())
                .detail("signs_from_ms", millis(r.signs_from))
                .detail("previous", r.previous.as_ref().map(|(k, _)| k.clone()))
                .detail("retire_at_ms", r.previous.as_ref().map(|(_, t)| millis(*t)));
            deployment_audit(&tx, vec![record]).await?;
        }
        tx.commit().await?;
        Ok(r)
    }

    /// Denies a signing key (`tutela_store::deny_signing_key`), with its
    /// record in the deployment's audit chain, in one transaction.
    pub(crate) async fn deny_signing_key(
        &mut self,
        vault: &tutela_vault::Vault,
        iss: &tutela_contracts::tenant::Issuer,
        kid: &str,
    ) -> Result<Option<String>, DbError> {
        let tx = self.0.transaction().await?;
        let replacement = tutela_store::deny_signing_key(&tx, vault, kid).await?;
        let record = key_record(iss, "deny", kid)?
            .detail("kid", kid)
            .detail("replacement", replacement.clone());
        deployment_audit(&tx, vec![record]).await?;
        tx.commit().await?;
        Ok(replacement)
    }
}

impl Conn {
    /// One tenant's webhook work, in a transaction of its own that ends
    /// before anything is sent: hand new events to its webhooks, prune what
    /// is past `retention`, and claim due deliveries for `replica`.
    pub(crate) async fn webhook_claims(
        &mut self,
        tenant: &TenantKey,
        vault: &tutela_vault::Vault,
        replica: &str,
        settings: &crate::webhooks::Settings,
        handed: &mut u64,
    ) -> Result<Vec<tutela_store::webhooks::Claimed>, DbError> {
        let tx = self.0.transaction().await?;
        *handed += tutela_store::webhooks::fan_out(&tx, tenant).await?;
        let before = std::time::SystemTime::now()
            .checked_sub(settings.retention)
            .unwrap_or(std::time::UNIX_EPOCH);
        tutela_store::webhooks::prune(&tx, tenant, before).await?;
        let claimed = tutela_store::webhooks::claim_deliveries(
            &tx,
            tenant,
            vault,
            replica,
            settings.lease,
            settings.batch,
        )
        .await?;
        tx.commit().await?;
        Ok(claimed)
    }

    /// Records how a replica's attempt ended, in a transaction of its own.
    pub(crate) async fn webhook_finish(
        &mut self,
        tenant: &TenantKey,
        replica: &str,
        webhook: &str,
        seq: u64,
        how: &tutela_store::webhooks::Attempt,
    ) -> Result<bool, DbError> {
        let tx = self.0.transaction().await?;
        let held = tutela_store::webhooks::finish_delivery(&tx, tenant, replica, webhook, seq, how)
            .await?;
        tx.commit().await?;
        Ok(held)
    }
}

impl Conn {
    /// Claims `chain` for forwarding and reads up to `batch` records past
    /// what the ledger acknowledged, in a transaction of its own. `None`
    /// when another replica holds the chain.
    pub(crate) async fn forward_claim(
        &mut self,
        chain: &tutela_store::audit::Chain,
        replica: &str,
        lease: Duration,
        batch: usize,
    ) -> Result<Option<Vec<tutela_store::AuditEntry>>, DbError> {
        let tx = self.0.transaction().await?;
        let Some(after) = tutela_store::audit::claim_forward(&tx, chain, replica, lease).await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let entries = tutela_store::audit::chain_records(&tx, chain, after, batch).await?;
        tx.commit().await?;
        Ok(Some(entries))
    }

    /// Ends a forwarding claim, with how far the ledger acknowledged.
    pub(crate) async fn forward_done(
        &mut self,
        chain: &tutela_store::audit::Chain,
        replica: &str,
        acked: Option<u64>,
    ) -> Result<bool, DbError> {
        let tx = self.0.transaction().await?;
        let held = tutela_store::audit::finish_forward(&tx, chain, replica, acked).await?;
        tx.commit().await?;
        Ok(held)
    }
}

/// A record about the deployment's signing keys, by `tutelad` itself.
fn key_record(
    iss: &tutela_contracts::tenant::Issuer,
    verb: &str,
    kid: &str,
) -> Result<crate::audit::Record, crate::audit::BuildError> {
    let tid = tutela_store::audit::deployment_tenant()
        .map_err(|_| crate::audit::BuildError::new("deployment tenant"))?;
    Ok(crate::audit::Record::new(
        &TenantKey::new(iss.clone(), tid),
        tutela_contracts::audit::Actor::new(crate::audit::system()?),
        &format!("tutela_signing_key:{verb}"),
        ("tutela_signing_key", kid),
    )
    .allowed(0))
}

fn audit_key_record(
    iss: &tutela_contracts::tenant::Issuer,
    verb: &str,
    kid: &str,
) -> Result<crate::audit::Record, crate::audit::BuildError> {
    let tid = tutela_store::audit::deployment_tenant()
        .map_err(|_| crate::audit::BuildError::new("deployment tenant"))?;
    Ok(crate::audit::Record::new(
        &TenantKey::new(iss.clone(), tid),
        tutela_contracts::audit::Actor::new(crate::audit::system()?),
        &format!("tutela_audit_key:{verb}"),
        ("tutela_audit_key", kid),
    )
    .allowed(0))
}

async fn deployment_audit(
    tx: &tokio_postgres::Transaction<'_>,
    records: Vec<crate::audit::Record>,
) -> Result<(), DbError> {
    if records.is_empty() {
        return Ok(());
    }
    let drafts = records
        .into_iter()
        .map(crate::audit::Record::build)
        .collect::<Result<Vec<_>, _>>()?;
    tutela_store::append_deployment_audit(tx, &drafts).await?;
    Ok(())
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
            checked: Arc::default(),
        })
    }

    /// A connection, while [`Db::check_ready`] passes. Until a check has
    /// passed, this runs one first.
    ///
    /// # Errors
    ///
    /// [`NotReady`] when there is no connection, or when a check fails.
    pub async fn conn(&self) -> Result<Conn, DbError> {
        if !self.checked.load(Ordering::Acquire) {
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

    /// Checks that a connection works, that the role and the schema isolate
    /// tenants, that the schema is the one this build knows, and that a
    /// fresh connection has no tenant set. Queries run only while this
    /// passes: readiness calls it, so a failure stops them too.
    ///
    /// # Errors
    ///
    /// A [`NotReady`] that says why.
    pub async fn check_ready(&self) -> Result<(), NotReady> {
        let client = self.object().await?;
        let result = checks(&client).await;
        self.checked.store(result.is_ok(), Ordering::Release);
        result
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

async fn checks(client: &tokio_postgres::Client) -> Result<(), NotReady> {
    tutela_store::check_isolation(client)
        .await
        .map_err(|e| match e.kind() {
            StoreErrorKind::Isolation => NotReady::Isolation(e),
            _ => NotReady::Schema(e),
        })?;
    let have = tutela_store::applied_migration(client)
        .await
        .map_err(NotReady::Schema)?;
    let need = tutela_store::latest_migration();
    if have != need {
        return Err(NotReady::SchemaVersion { have, need });
    }
    match leftover(client).await? {
        Some(tenant) => Err(NotReady::TenantLeft(tenant)),
        None => Ok(()),
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
