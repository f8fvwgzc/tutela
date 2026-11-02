//! Raised epochs and disabled principals: what makes a valid signature not
//! enough (CONTRACTS.md 4.2 step 9, ADR-0031).
//!
//! `tutelad` holds the truth in `tutela.principal`, so it does not wait for
//! events as a product's SDK does. Each tenant has a [`Book`] of the
//! principals that refuse something, read again after
//! `TUTELA_REVISION_CHECK_MS`, like the tenant's snapshot (ADR-0021). So a
//! revoked session or a disabled principal stops being accepted on every
//! replica within that time plus one read.
//!
//! Failing closed is the snapshot's: with no database, a book may serve until
//! `TUTELA_MAX_AGE_READ_SECS` after it was last read, and then nothing is
//! answered; with no book and no database, nothing is answered.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::time::timeout;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_sdk::Identity;
use tutela_store::StoreErrorKind;

use crate::api::Problem;
use crate::cache::Limits;
use crate::db::{Db, DbError};
use crate::tenant::Tenant;

/// How long a request waits for the read.
const CHECK_TIMEOUT: Duration = Duration::from_secs(1);
/// After a failed read, requests do not try the database for this long.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(1);

/// One tenant's principals that refuse something.
#[derive(Debug, Default)]
pub struct Book {
    /// The newest epoch and the disabled flag, per principal.
    entries: HashMap<Principal, (u64, bool)>,
}

impl Book {
    /// `epoch` is current for `p`, and `p` is not disabled. A principal the
    /// book does not name is current at any epoch.
    #[must_use]
    pub fn current(&self, p: &Principal, epoch: u64) -> bool {
        self.entries
            .get(p)
            .is_none_or(|&(newest, disabled)| !disabled && epoch >= newest)
    }

    /// `p` is disabled.
    #[must_use]
    pub fn disabled(&self, p: &Principal) -> bool {
        self.entries.get(p).is_some_and(|&(_, disabled)| disabled)
    }
}

/// Why a verified token is refused or cannot be judged.
#[derive(Debug)]
pub enum Refusal {
    /// A raised epoch, or a disabled principal or actor: 401, as any token
    /// that fails a step.
    Revoked,
    /// No answer: the [`Problem`] says why.
    Problem(Problem),
}

#[derive(Default)]
struct Slot {
    current: RwLock<Option<(Arc<Book>, Instant)>>,
    gate: Mutex<Option<Instant>>,
}

/// The books of this replica, one per tenant that a token reached.
pub struct Revocations {
    db: Db,
    limits: Limits,
    slots: RwLock<HashMap<TenantKey, Arc<Slot>>>,
}

impl std::fmt::Debug for Revocations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revocations").finish_non_exhaustive()
    }
}

impl Revocations {
    /// No book yet.
    #[must_use]
    pub fn new(db: Db, limits: Limits) -> Self {
        Self {
            db,
            limits,
            slots: RwLock::default(),
        }
    }

    /// Checks a verified token: its subject's epoch is current, and neither
    /// the subject nor any actor is disabled. A token of an external issuer
    /// has no principal here and passes; it cannot ask anything anyway.
    ///
    /// # Errors
    ///
    /// [`Refusal::Revoked`], or the [`Problem`] of a book that cannot be had.
    pub async fn check(&self, id: &Identity) -> Result<(), Refusal> {
        let (sub, epoch, actors) = match id {
            Identity::Access(c) => (&c.sub, c.epoch, Vec::new()),
            Identity::Delegated(c) => (&c.sub, c.epoch, c.act.chain()),
            _ => return Ok(()),
        };
        let book = self.book(&Tenant::of(id)).await.map_err(Refusal::Problem)?;
        if book.current(sub, epoch) && !actors.iter().any(|a| book.disabled(a)) {
            Ok(())
        } else {
            Err(Refusal::Revoked)
        }
    }

    fn slot(&self, key: &TenantKey) -> Result<Arc<Slot>, Problem> {
        if let Some(s) = self
            .slots
            .read()
            .map_err(|_| Problem::stale("unavailable"))?
            .get(key)
        {
            return Ok(Arc::clone(s));
        }
        let mut slots = self
            .slots
            .write()
            .map_err(|_| Problem::stale("unavailable"))?;
        Ok(Arc::clone(slots.entry(key.clone()).or_default()))
    }

    fn held(slot: &Slot) -> Result<Option<(Arc<Book>, Instant)>, Problem> {
        slot.current
            .read()
            .map(|c| c.clone())
            .map_err(|_| Problem::stale("unavailable"))
    }

    /// The tenant's book, read again when its time has come.
    ///
    /// # Errors
    ///
    /// 403 `unknown_tenant`, or 503 `no_data` or `expired` when the database
    /// gives no answer and nothing in hand may serve.
    pub async fn book(&self, tenant: &Tenant) -> Result<Arc<Book>, Problem> {
        let slot = self.slot(tenant.key())?;
        let fresh = |c: &Option<(Arc<Book>, Instant)>| {
            c.as_ref()
                .filter(|(_, at)| at.elapsed() < self.limits.check_every)
                .map(|(b, _)| Arc::clone(b))
        };
        if let Some(b) = fresh(&Self::held(&slot)?) {
            return Ok(b);
        }
        let Ok(mut gate) = timeout(CHECK_TIMEOUT, slot.gate.lock()).await else {
            return self.stale(&slot);
        };
        if let Some(b) = fresh(&Self::held(&slot)?) {
            return Ok(b);
        }
        if gate.is_some_and(|until| Instant::now() < until) {
            return self.stale(&slot);
        }
        let started = Instant::now();
        match timeout(CHECK_TIMEOUT, self.read(tenant)).await {
            Ok(Ok(book)) => {
                *gate = None;
                let book = Arc::new(book);
                if let Ok(mut c) = slot.current.write() {
                    *c = Some((Arc::clone(&book), started));
                }
                Ok(book)
            }
            Ok(Err(e)) if e.store_kind() == Some(StoreErrorKind::UnknownTenant) => {
                Err(Problem::from(e))
            }
            // A role or a schema that does not isolate tenants is not an
            // outage: nothing in hand serves, as no query runs.
            Ok(Err(e)) if matches!(&e, DbError::NotReady(n) if n.is_unsafe()) => {
                Err(Problem::from(e))
            }
            failed => {
                *gate = Some(Instant::now() + RETRY_AFTER_FAILURE);
                if let Ok(Err(e)) = failed {
                    tracing::warn!(error = %e, "the revocations could not be read");
                }
                self.stale(&slot)
            }
        }
    }

    /// What is in hand, while it is younger than the read age limit.
    fn stale(&self, slot: &Slot) -> Result<Arc<Book>, Problem> {
        match Self::held(slot)? {
            None => Err(Problem::stale("no_data")),
            Some((b, at)) if at.elapsed() <= self.limits.max_age_read => Ok(b),
            Some(_) => Err(Problem::stale("expired")),
        }
    }

    async fn read(&self, tenant: &Tenant) -> Result<Book, DbError> {
        let mut conn = self.db.conn().await?;
        let tx = conn.begin(tenant).await?;
        let r = tutela_store::revocations(&tx, tenant.key()).await?;
        tx.commit().await?;
        Ok(Book {
            entries: r
                .entries
                .into_iter()
                .map(|s| (s.principal, (s.epoch, s.disabled)))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Principal {
        s.parse().unwrap()
    }

    #[test]
    fn a_raised_epoch_or_a_disabled_principal_refuses_and_others_pass() {
        let user = p("user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081");
        let off = p("agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102");
        let other = p("user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7082");
        let book = Book {
            entries: [(user.clone(), (2, false)), (off.clone(), (1, true))]
                .into_iter()
                .collect(),
        };
        assert!(!book.current(&user, 1));
        assert!(book.current(&user, 2) && book.current(&user, 3));
        assert!(!book.current(&off, 5) && book.disabled(&off));
        assert!(book.current(&other, 0) && !book.disabled(&other));
    }
}
