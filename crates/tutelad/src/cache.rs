//! The tenant cache: what a replica answers from (ADR-0021).
//!
//! Each tenant has one immutable [`Snapshot`]: its compiled model, a [`Pdp`]
//! loaded with its data at one revision, and its scope paths. A request reads
//! the snapshot in memory, so its cost does not grow with the data.
//!
//! **How a replica learns that a revision moved.** A snapshot is trusted for
//! `check_every` after it was last checked against the database. The first
//! request after that reads the tenant's revision, one request at a time per
//! tenant, while the others wait. A new revision loads a new snapshot. So a
//! change that committed reaches every replica within `check_every`, plus the
//! time of that read, and an idle tenant costs nothing.
//!
//! **Failing closed.** The checks below never turn into an allow:
//!
//! - No snapshot and no database: an error.
//! - The database does not answer: a snapshot may still be used until the
//!   max age of the action's class ([`ActionClass`]). The age counts from
//!   before the last good read, so it never flatters the snapshot. Past it,
//!   an error.
//! - A snapshot stops being true at `next_expiry`, also when the revision has
//!   not moved (ADR-0020). Past it, the snapshot is never used. The deadline
//!   is measured from the database's clock on this process's monotonic
//!   clock, so a replica whose clock is behind does not hold on to an
//!   expired assignment.
//! - A revision below the one seen is refused, and so is a snapshot below
//!   `at_least_revision` or the token's `rev`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Mutex;
use tokio::time::timeout;
use tutela_contracts::keys::{ActionKey, BuiltinAction};
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::{Model, is_admin_key};
use tutela_pdp::{LoadError, Pdp};
use tutela_store::{ScopePathSnapshot, StoreErrorKind, StoredManifest, TenantBundle};

use crate::db::{Db, DbError};
use crate::telemetry::Metrics;
use crate::tenant::Tenant;

/// How long a request waits for the revision read. A database that takes
/// longer counts as down for this check.
const CHECK_TIMEOUT: Duration = Duration::from_secs(1);
/// How long a load may take. It reads the whole tenant.
const LOAD_TIMEOUT: Duration = Duration::from_secs(10);
/// After a failed check, requests do not try the database for this long.
/// They answer at once from what they have, or fail, so an outage does not
/// queue every request behind a timeout.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(1);

/// The limits of the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `TUTELA_REVISION_CHECK_MS`: how long a snapshot is trusted without a
    /// new read. This is the delay of a revocation in normal running.
    /// `0` reads the revision on every request.
    pub check_every: Duration,
    /// `TUTELA_MAX_AGE_READ_SECS`: the max age of a snapshot for
    /// [`ActionClass::Read`] while the database does not answer.
    pub max_age_read: Duration,
    /// `TUTELA_MAX_AGE_WRITE_SECS`: the same for [`ActionClass::Write`].
    pub max_age_write: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            check_every: Duration::from_secs(1),
            max_age_read: Duration::from_secs(60),
            max_age_write: Duration::from_secs(10),
        }
    }
}

/// How stale an answer may be (PERMISSION-MODEL.md 16). Writes and admin
/// actions fail closed sooner than reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionClass {
    /// The built-in `read`.
    Read,
    /// Any other action.
    Write,
    /// Admin keys and owner-only actions: revocation-sensitive. Never
    /// answered from a snapshot that could not be checked.
    Admin,
}

impl ActionClass {
    /// The class of `action`. An action the model does not know is
    /// [`ActionClass::Read`]: the evaluator refuses it anyway.
    #[must_use]
    pub fn of(model: &Model, action: &ActionKey) -> Self {
        if is_admin_key(action.action()) {
            return Self::Admin;
        }
        if action.as_builtin() == Some(BuiltinAction::Read) {
            return Self::Read;
        }
        let def = model
            .types()
            .get(action.resource_type())
            .and_then(|t| t.actions.get(action.action()));
        match def {
            Some(d) if d.needs == tutela_contracts::keys::ActionRequirement::OwnerOnly => {
                Self::Admin
            }
            Some(_) => Self::Write,
            None if action.as_builtin().is_some() => Self::Write,
            None => Self::Read,
        }
    }

    /// The stricter of two classes.
    #[must_use]
    pub const fn stricter(self, other: Self) -> Self {
        match (self, other) {
            (Self::Admin, _) | (_, Self::Admin) => Self::Admin,
            (Self::Write, _) | (_, Self::Write) => Self::Write,
            (Self::Read, Self::Read) => Self::Read,
        }
    }
}

/// Why no answer can be given. Every one of these fails closed.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    /// This tenant is not in the directory. The caller gets 403.
    #[error("unknown tenant")]
    UnknownTenant(#[source] DbError),
    /// No snapshot, and none can be loaded.
    #[error("no data is loaded for this tenant")]
    NoData,
    /// The snapshot is past its age limit or its `next_expiry`.
    #[error("the data has expired")]
    Expired,
    /// The database is behind the revision the caller needs.
    #[error("the loaded revision {have} is below the needed revision {need}")]
    Stale {
        /// The revision in hand.
        have: u64,
        /// The revision needed.
        need: u64,
    },
    /// The cache's own lock was poisoned by a panic.
    #[error("the cache is unavailable")]
    Poisoned,
}

/// Why a check of the database failed. It is logged, never sent.
#[derive(Debug, thiserror::Error)]
enum CheckError {
    #[error("the database did not answer in time")]
    Timeout,
    #[error("a database call failed")]
    Db(#[from] DbError),
    #[error("this schema holds no manifest")]
    NoManifest,
    #[error("the stored manifest does not compile")]
    BadManifest,
    #[error("the tenant data does not load")]
    BadData(#[source] LoadError),
    #[error("the revision went from {seen} down to {got}")]
    WentBack { seen: u64, got: u64 },
    #[error("a build task failed")]
    Task,
}

/// One tenant at one revision. It never changes.
pub struct Snapshot {
    /// The tenant revision.
    pub rev: u64,
    /// The evaluator, holding this tenant only. One tenant's bad data or a
    /// lookup bug cannot reach another's.
    pub pdp: Pdp,
    /// The scope paths, for `list_filter`.
    pub paths: ScopePathSnapshot,
    /// The compiled model.
    pub model: Arc<Model>,
    /// SHA-256 of the manifest the model came from, lowercase hex.
    pub model_digest: String,
    /// When the earliest assignment in this view expires.
    valid_until: Option<Instant>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("rev", &self.rev)
            .field("model_digest", &self.model_digest)
            .finish_non_exhaustive()
    }
}

impl Snapshot {
    fn valid(&self, now: Instant) -> bool {
        self.valid_until.is_none_or(|until| now < until)
    }
}

#[derive(Clone)]
struct Current {
    snapshot: Arc<Snapshot>,
    /// Taken before the read that last proved this snapshot current.
    verified: Instant,
}

/// One tenant's place in the cache.
#[derive(Default)]
struct Slot {
    current: RwLock<Option<Current>>,
    /// Held during a check, so one request at a time reads the database for
    /// this tenant. It holds the time before which no check should start.
    gate: Mutex<Option<Instant>>,
}

impl Slot {
    fn get(&self) -> Result<Option<Current>, Refused> {
        self.current
            .read()
            .map(|c| c.clone())
            .map_err(|_| Refused::Poisoned)
    }

    fn set(&self, current: Current) -> Result<(), Refused> {
        *self.current.write().map_err(|_| Refused::Poisoned)? = Some(current);
        Ok(())
    }
}

/// A snapshot in hand, and how far past its check it is.
#[derive(Debug)]
pub struct View {
    snapshot: Arc<Snapshot>,
    /// How old the last good check is. Zero unless the database failed.
    stale_for: Duration,
    limits: Limits,
}

impl View {
    /// The snapshot, for an action of `class`. All actions of a request go
    /// through this, with the strictest class among them.
    ///
    /// # Errors
    ///
    /// [`Refused::Expired`] when the snapshot is too old for this class.
    pub fn for_class(&self, class: ActionClass) -> Result<&Snapshot, Refused> {
        let limit = match class {
            ActionClass::Read => self.limits.max_age_read,
            ActionClass::Write => self.limits.max_age_write,
            ActionClass::Admin => Duration::ZERO,
        };
        if self.stale_for > limit {
            return Err(Refused::Expired);
        }
        Ok(&self.snapshot)
    }

    /// As [`View::for_class`], for work on another thread.
    ///
    /// # Errors
    ///
    /// [`Refused::Expired`] when the snapshot is too old for this class.
    pub fn shared_for_class(&self, class: ActionClass) -> Result<Arc<Snapshot>, Refused> {
        self.for_class(class)?;
        Ok(Arc::clone(&self.snapshot))
    }

    /// The model, to work out a request's class.
    #[must_use]
    pub fn model(&self) -> &Model {
        &self.snapshot.model
    }
}

/// The snapshots of this replica, one per tenant. The trust file bounds the
/// tenants that can reach it.
pub struct TenantCache {
    db: Db,
    limits: Limits,
    metrics: Arc<Metrics>,
    slots: RwLock<HashMap<TenantKey, Arc<Slot>>>,
    /// The last compiled model, by digest. One schema holds one manifest
    /// (ADR-0014 item 7), and a manifest can take seconds to compile.
    model: Mutex<Option<(String, Arc<Model>)>>,
}

impl std::fmt::Debug for TenantCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantCache")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl TenantCache {
    /// An empty cache.
    #[must_use]
    pub fn new(db: Db, limits: Limits, metrics: Arc<Metrics>) -> Self {
        Self {
            db,
            limits,
            metrics,
            slots: RwLock::default(),
            model: Mutex::new(None),
        }
    }

    fn slot(&self, key: &TenantKey) -> Result<Arc<Slot>, Refused> {
        if let Some(slot) = self
            .slots
            .read()
            .map_err(|_| Refused::Poisoned)?
            .get(key)
            .cloned()
        {
            return Ok(slot);
        }
        let mut slots = self.slots.write().map_err(|_| Refused::Poisoned)?;
        Ok(Arc::clone(slots.entry(key.clone()).or_default()))
    }

    fn usable(&self, c: &Current, need: Option<u64>, now: Instant) -> bool {
        now.saturating_duration_since(c.verified) < self.limits.check_every
            && c.snapshot.valid(now)
            && need.is_none_or(|n| c.snapshot.rev >= n)
    }

    fn fresh(&self, c: Current) -> View {
        View {
            snapshot: c.snapshot,
            stale_for: Duration::ZERO,
            limits: self.limits,
        }
    }

    /// The tenant's view at revision `need` or later, checked against the
    /// database if its time has come.
    ///
    /// # Errors
    ///
    /// [`Refused`]: the caller fails closed.
    pub async fn view(&self, tenant: &Tenant, need: Option<u64>) -> Result<View, Refused> {
        let slot = self.slot(tenant.key())?;
        if let Some(c) = slot.get()?
            && self.usable(&c, need, Instant::now())
        {
            return Ok(self.fresh(c));
        }
        let Ok(mut gate) = timeout(CHECK_TIMEOUT, slot.gate.lock()).await else {
            return self.stale(&slot, need);
        };
        // The request that held the gate may have done this work.
        let now = Instant::now();
        if let Some(c) = slot.get()?
            && self.usable(&c, need, now)
        {
            return Ok(self.fresh(c));
        }
        if gate.is_some_and(|until| now < until) {
            return self.stale(&slot, need);
        }
        match self.check(tenant, &slot).await {
            Ok(c) => {
                *gate = None;
                self.metrics.count_revision_check(true);
                let have = c.snapshot.rev;
                match need {
                    Some(need) if have < need => Err(Refused::Stale { have, need }),
                    _ => Ok(self.fresh(c)),
                }
            }
            Err(CheckError::Db(e)) if e.store_kind() == Some(StoreErrorKind::UnknownTenant) => {
                Err(Refused::UnknownTenant(e))
            }
            Err(e) => {
                *gate = Some(Instant::now() + RETRY_AFTER_FAILURE);
                self.metrics.count_revision_check(false);
                tracing::warn!(
                    tid = %tenant.key().tid,
                    error = %e,
                    "the tenant could not be checked against the database"
                );
                self.stale(&slot, need)
            }
        }
    }

    /// The database gave no answer. What is in hand may still serve, up to
    /// the longest max age; [`View::for_class`] applies the class's own.
    fn stale(&self, slot: &Slot, need: Option<u64>) -> Result<View, Refused> {
        let Some(c) = slot.get()? else {
            return Err(Refused::NoData);
        };
        let now = Instant::now();
        if !c.snapshot.valid(now) {
            return Err(Refused::Expired);
        }
        if let Some(need) = need
            && c.snapshot.rev < need
        {
            return Err(Refused::Stale {
                have: c.snapshot.rev,
                need,
            });
        }
        let stale_for = now.saturating_duration_since(c.verified);
        if stale_for > self.limits.max_age_read {
            return Err(Refused::Expired);
        }
        Ok(View {
            snapshot: c.snapshot,
            stale_for,
            limits: self.limits,
        })
    }

    /// Reads the revision, and loads a new snapshot if it moved or if the
    /// snapshot in hand has passed its expiry.
    async fn check(&self, tenant: &Tenant, slot: &Slot) -> Result<Current, CheckError> {
        // Before the read: a change that commits during it is not proved
        // absent, so the trust counts from here.
        let started = Instant::now();
        let rev = timeout(CHECK_TIMEOUT, self.read_rev(tenant))
            .await
            .map_err(|_| CheckError::Timeout)??;
        let current = slot.get().ok().flatten();
        if let Some(c) = current {
            if rev < c.snapshot.rev {
                return Err(CheckError::WentBack {
                    seen: c.snapshot.rev,
                    got: rev,
                });
            }
            if rev == c.snapshot.rev && c.snapshot.valid(started) {
                let c = Current {
                    verified: started,
                    ..c
                };
                slot.set(c.clone()).map_err(|_| CheckError::Task)?;
                return Ok(c);
            }
        }
        let snapshot = Arc::new(self.load(tenant).await?);
        if let Some(c) = slot.get().ok().flatten()
            && snapshot.rev < c.snapshot.rev
        {
            return Err(CheckError::WentBack {
                seen: c.snapshot.rev,
                got: snapshot.rev,
            });
        }
        let c = Current {
            snapshot,
            verified: started,
        };
        slot.set(c.clone()).map_err(|_| CheckError::Task)?;
        Ok(c)
    }

    async fn read_rev(&self, tenant: &Tenant) -> Result<u64, DbError> {
        let mut conn = self.db.conn().await?;
        let tx = conn.begin(tenant).await?;
        let rev = tutela_store::rev(&tx, tenant.key()).await?;
        tx.commit().await?;
        Ok(rev)
    }

    async fn load(&self, tenant: &Tenant) -> Result<Snapshot, CheckError> {
        let started = Instant::now();
        let read = timeout(LOAD_TIMEOUT, self.read_tenant(tenant))
            .await
            .map_err(|_| CheckError::Timeout);
        let loaded = read.and_then(|r| r);
        self.metrics.count_tenant_load(loaded.is_ok());
        let (bundle, manifest) = loaded?;
        let model = self.compiled(manifest.source, &manifest.digest).await?;
        let TenantBundle {
            rev,
            data,
            paths,
            next_expiry,
            read_at,
        } = bundle;
        let key = tenant.key().clone();
        let for_pdp = Arc::clone(&model);
        // The index of a large tenant takes real time.
        let pdp = tokio::task::spawn_blocking(move || {
            let mut pdp = Pdp::new();
            pdp.load(key, rev, for_pdp, data).map(|()| pdp)
        })
        .await
        .map_err(|_| CheckError::Task)?
        .map_err(CheckError::BadData)?;
        Ok(Snapshot {
            rev,
            pdp,
            paths,
            model,
            model_digest: manifest.digest,
            valid_until: deadline(started, next_expiry, read_at),
        })
    }

    /// The tenant and the manifest, in one view. The manifest is read after
    /// the revision lock: `publish_manifest` writes it and bumps the
    /// revision in one transaction, so a view never pairs a new revision
    /// with an old model.
    async fn read_tenant(
        &self,
        tenant: &Tenant,
    ) -> Result<(TenantBundle, StoredManifest), CheckError> {
        let mut conn = self.db.conn().await?;
        let tx = conn.begin(tenant).await?;
        let bundle = tutela_store::load(&tx, tenant.key())
            .await
            .map_err(DbError::from)?;
        let manifest = tutela_store::applied_manifest(&tx)
            .await
            .map_err(DbError::from)?
            .ok_or(CheckError::NoManifest)?;
        tx.commit().await?;
        Ok((bundle, manifest))
    }

    async fn compiled(&self, source: String, digest: &str) -> Result<Arc<Model>, CheckError> {
        let mut last = self.model.lock().await;
        if let Some((d, m)) = last.as_ref()
            && d == digest
        {
            return Ok(Arc::clone(m));
        }
        // The compiler blocks while it runs on its own thread.
        let model = tokio::task::spawn_blocking(move || Model::from_toml(&source))
            .await
            .map_err(|_| CheckError::Task)?
            .map_err(|_| CheckError::BadManifest)?;
        let model = Arc::new(model);
        *last = Some((digest.to_owned(), Arc::clone(&model)));
        Ok(model)
    }
}

/// When a view read at `read_at` on the database's clock stops being true,
/// on this process's monotonic clock. `started` is before the read, so the
/// deadline can only be early. A deadline too far off to compute is the same
/// as none.
fn deadline(
    started: Instant,
    next_expiry: Option<SystemTime>,
    read_at: SystemTime,
) -> Option<Instant> {
    let next = next_expiry?;
    let left = next.duration_since(read_at).unwrap_or(Duration::ZERO);
    started.checked_add(left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_comes_from_the_database_clock_and_never_late() {
        let started = Instant::now();
        let read_at = SystemTime::now();
        assert_eq!(deadline(started, None, read_at), None);
        let in_ten = read_at + Duration::from_secs(10);
        assert_eq!(
            deadline(started, Some(in_ten), read_at),
            Some(started + Duration::from_secs(10))
        );
        // Already past on the database's clock, whatever this clock says.
        let past = read_at - Duration::from_secs(1);
        assert_eq!(deadline(started, Some(past), read_at), Some(started));
    }

    fn view(stale_for: Duration, limits: Limits) -> View {
        let model = Model::from_toml("version = 1\n[app]\nname = \"crm\"\n").unwrap();
        View {
            snapshot: Arc::new(Snapshot {
                rev: 1,
                pdp: Pdp::new(),
                paths: tutela_store_paths(),
                model: Arc::new(model),
                model_digest: String::new(),
                valid_until: None,
            }),
            stale_for,
            limits,
        }
    }

    fn tutela_store_paths() -> ScopePathSnapshot {
        ScopePathSnapshot::empty(TenantKey::new(
            "https://auth.example.test".parse().unwrap(),
            "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".parse().unwrap(),
        ))
    }

    #[test]
    fn tm13_writes_and_admin_actions_fail_closed_sooner_than_reads() {
        let limits = Limits::default();
        let at = |secs| view(Duration::from_secs(secs), limits);
        assert!(at(5).for_class(ActionClass::Read).is_ok());
        assert!(at(5).for_class(ActionClass::Write).is_ok());
        assert!(at(5).for_class(ActionClass::Admin).is_err());
        assert!(at(30).for_class(ActionClass::Read).is_ok());
        assert!(at(30).for_class(ActionClass::Write).is_err());
        assert!(at(61).for_class(ActionClass::Read).is_err());
        assert!(at(0).for_class(ActionClass::Admin).is_ok());
    }

    #[test]
    fn the_strictest_class_of_a_request_wins() {
        use ActionClass::{Admin, Read, Write};
        assert_eq!(Read.stricter(Write), Write);
        assert_eq!(Write.stricter(Read), Write);
        assert_eq!(Read.stricter(Admin), Admin);
        assert_eq!(Admin.stricter(Write), Admin);
        assert_eq!(Read.stricter(Read), Read);
    }
}
