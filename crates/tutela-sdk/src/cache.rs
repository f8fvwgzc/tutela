//! A decision cache in front of [`Pdp::check`] (ADR-0013 #14).
//!
//! A decision is cached under the tenant's loaded revision and the whole
//! request, so a newer bundle never answers from an older one. On top of
//! that, **every** [`CachedPdp::load`] clears the cache: a reload at the
//! same revision (a retry) may carry other data. Errors are never cached.
//! The cache is bounded; when full it is cleared.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use tutela_contracts::decision::Decision;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::Model;
use tutela_pdp::{CheckRequest, LoadError, Pdp, PdpError, TenantData};

/// Why a cached check failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// The PDP refused or failed the check.
    #[error(transparent)]
    Pdp(#[from] PdpError),
    /// The PDP refused the bundle.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// A lock was poisoned by a panic elsewhere: fail closed.
    #[error("the decision cache is unavailable")]
    Poisoned,
}

/// A [`Pdp`] with a decision cache for `check`.
pub struct CachedPdp {
    pdp: RwLock<Pdp>,
    cache: Mutex<HashMap<String, Decision>>,
    capacity: usize,
}

impl std::fmt::Debug for CachedPdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedPdp")
            .field("cached", &self.cached())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl CachedPdp {
    /// An empty PDP whose cache holds at most `capacity` decisions.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            pdp: RwLock::new(Pdp::new()),
            cache: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Loads a tenant bundle ([`Pdp::load`]) and clears the cache.
    ///
    /// # Errors
    ///
    /// [`CacheError::Load`] as [`Pdp::load`] (the old bundle and the cache
    /// stay), or [`CacheError::Poisoned`].
    pub fn load(
        &self,
        tenant: TenantKey,
        rev: u64,
        model: Arc<Model>,
        data: TenantData,
    ) -> Result<(), CacheError> {
        let mut pdp = self.pdp.write().map_err(|_| CacheError::Poisoned)?;
        pdp.load(tenant, rev, model, data)?;
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
        Ok(())
    }

    /// [`Pdp::check`], answered from the cache when it can be.
    ///
    /// # Errors
    ///
    /// [`CacheError::Pdp`] as [`Pdp::check`], or [`CacheError::Poisoned`].
    pub fn check(&self, req: &CheckRequest) -> Result<Decision, CacheError> {
        let pdp = self.pdp.read().map_err(|_| CacheError::Poisoned)?;
        let Some(rev) = pdp.rev(&req.tenant) else {
            return Ok(pdp.check(req)?);
        };
        let key = format!("{rev}\u{1f}{req:?}");
        if let Some(d) = self
            .cache
            .lock()
            .map_err(|_| CacheError::Poisoned)?
            .get(&key)
        {
            return Ok(d.clone());
        }
        let d = pdp.check(req)?;
        let mut c = self.cache.lock().map_err(|_| CacheError::Poisoned)?;
        if c.len() >= self.capacity {
            c.clear();
        }
        c.insert(key, d.clone());
        Ok(d)
    }

    /// The number of cached decisions.
    #[must_use]
    pub fn cached(&self) -> usize {
        self.cache.lock().map_or(0, |c| c.len())
    }

    /// Runs `f` with the PDP, for the calls that are not cached (`batch`,
    /// `list_filter`, `write_check`).
    ///
    /// # Errors
    ///
    /// [`CacheError::Poisoned`].
    pub fn with<R>(&self, f: impl FnOnce(&Pdp) -> R) -> Result<R, CacheError> {
        self.pdp
            .read()
            .map(|p| f(&p))
            .map_err(|_| CacheError::Poisoned)
    }
}
