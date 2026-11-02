//! `tutelad`'s own issuer: its signing keys in memory, the JWKS it
//! publishes, and the [`Signer`] tokens are signed with (ADR-0030,
//! THREAT-MODEL.md TM-15).
//!
//! The keys live in `tutela.signing_key`, each private key sealed by
//! `tutela-vault` under `TUTELA_MASTER_KEY` ([`mod@tutela_store::signing_keys`]).
//! A [`KeyRing`] opens them in memory and reads the table again every
//! `TUTELA_KEY_REFRESH_SECS`, so a rotation or a denial made by another
//! replica, or by `tutela keys rotate` (part 4), reaches every replica within
//! that time. A rotation publishes the next key at least twice the JWKS cache
//! time before it signs, so no verifier meets a `kid` it has not seen.
//!
//! A private key is never logged, and never leaves the process: signing goes
//! through the [`Signer`] trait, so a KMS or HSM backend (Phase C) changes no
//! call site.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use tokio::sync::watch;
use tutela_contracts::claims::{CLOCK_SKEW_SECS, MAX_ACCESS_TOKEN_LIFETIME_SECS};
use tutela_contracts::tenant::Issuer;
use tutela_sdk::JwksSource;
use tutela_store::{KeySet, KeyTimes};
use tutela_vault::Vault;

use crate::api::AppState;
use crate::db::{Db, DbError};

/// The path of the JWKS on the API port. It needs no token.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Why a key operation failed. The texts name `kid`s at most, never key
/// material.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The database failed.
    #[error("the signing keys could not be read")]
    Db(#[from] DbError),
    /// A stored key does not open with this master key, or does not parse.
    #[error("signing key {0} cannot be used")]
    Unusable(String),
    /// No key may sign now: none has been loaded yet.
    #[error("no signing key is loaded")]
    NoKey,
    /// The signature could not be made.
    #[error("signing failed")]
    Sign,
}

/// Signs tokens. A local key today; a KMS or HSM behind the same trait
/// later, where the private key never leaves the device (TM-15).
pub trait Signer: Send + Sync {
    /// The key's id: its RFC 7638 thumbprint.
    fn kid(&self) -> &str;
    /// The JOSE algorithm.
    fn alg(&self) -> &'static str;
    /// The signature over `message`, in the JOSE form.
    ///
    /// # Errors
    ///
    /// [`KeyError::Sign`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// A P-256 key held in this process.
struct LocalSigner {
    kid: String,
    pair: EcdsaKeyPair,
}

impl Signer for LocalSigner {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn alg(&self) -> &'static str {
        tutela_store::signing_keys::ALG
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| KeyError::Sign)
    }
}

/// One loaded key.
struct Live {
    signs_from: SystemTime,
    retire_at: Option<SystemTime>,
    signer: Arc<LocalSigner>,
}

/// The key set at one load.
struct Ring {
    /// The database's clock at the load, and this process's clock then: key
    /// times are the database's, so "now" is counted from the load.
    db_now: SystemTime,
    at: Instant,
    keys: Vec<Live>,
    denied: Vec<String>,
    jwks: Arc<[u8]>,
}

impl Ring {
    fn empty() -> Self {
        Self {
            db_now: SystemTime::now(),
            at: Instant::now(),
            keys: Vec::new(),
            denied: Vec::new(),
            jwks: Arc::from(&br#"{"keys":[]}"#[..]),
        }
    }

    fn now(&self) -> SystemTime {
        self.db_now + self.at.elapsed()
    }
}

/// The issuer's keys, in memory. Cheap to read; [`KeyRing::refresh`] loads
/// them again.
pub struct KeyRing {
    iss: Issuer,
    jwks_url: String,
    vault: Vault,
    times: KeyTimes,
    cache_secs: u64,
    ring: RwLock<Arc<Ring>>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("iss", &self.iss)
            .field("times", &self.times)
            .finish_non_exhaustive()
    }
}

/// The JWKS document.
#[derive(Serialize)]
struct Jwks {
    keys: Vec<serde_json::Value>,
}

impl KeyRing {
    /// A ring with no key yet, for issuer `iss`, sealing with `vault`.
    /// `jwks_cache` is how long verifiers keep the JWKS: a rotation publishes
    /// the next key twice that long before it signs.
    #[must_use]
    pub fn new(iss: Issuer, vault: Vault, jwks_cache: Duration) -> Self {
        Self {
            jwks_url: jwks_url(&iss),
            iss,
            vault,
            times: rotation_times(jwks_cache),
            cache_secs: jwks_cache.as_secs(),
            ring: RwLock::new(Arc::new(Ring::empty())),
        }
    }

    /// The issuer.
    #[must_use]
    pub const fn iss(&self) -> &Issuer {
        &self.iss
    }

    /// Where the JWKS is published.
    #[must_use]
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    /// The times a rotation uses (for `tutela keys rotate`).
    #[must_use]
    pub const fn times(&self) -> KeyTimes {
        self.times
    }

    /// The vault the keys are sealed with.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    fn current(&self) -> Arc<Ring> {
        self.ring
            .read()
            .map_or_else(|_| Arc::new(Ring::empty()), |r| Arc::clone(&r))
    }

    /// The JWKS document: every published key, the next one included.
    #[must_use]
    pub fn jwks(&self) -> Arc<[u8]> {
        Arc::clone(&self.current().jwks)
    }

    /// The denied `kid`s.
    #[must_use]
    pub fn denied(&self) -> Vec<String> {
        self.current().denied.clone()
    }

    /// The `kid`s published now, oldest first.
    #[must_use]
    pub fn published(&self) -> Vec<String> {
        let ring = self.current();
        let now = ring.now();
        ring.keys
            .iter()
            .filter(|k| k.retire_at.is_none_or(|r| now < r))
            .map(|k| k.signer.kid.clone())
            .collect()
    }

    /// The key that signs now: the latest whose time has come.
    ///
    /// # Errors
    ///
    /// [`KeyError::NoKey`] before a key is loaded.
    pub fn signer(&self) -> Result<Arc<dyn Signer>, KeyError> {
        let ring = self.current();
        let now = ring.now();
        ring.keys
            .iter()
            .filter(|k| k.signs_from <= now && k.retire_at.is_none_or(|r| now < r))
            .max_by_key(|k| k.signs_from)
            .map(|k| Arc::clone(&k.signer) as Arc<dyn Signer>)
            .ok_or(KeyError::NoKey)
    }

    /// A signed JWT with header `typ` and `claims`.
    ///
    /// # Errors
    ///
    /// [`KeyError::NoKey`] or [`KeyError::Sign`].
    pub fn sign_jwt(&self, typ: &str, claims: &impl Serialize) -> Result<String, KeyError> {
        let signer = self.signer()?;
        let header = serde_json::json!({"typ": typ, "alg": signer.alg(), "kid": signer.kid()});
        let payload = serde_json::to_vec(claims).map_err(|_| KeyError::Sign)?;
        let message = format!("{}.{}", B64.encode(header.to_string()), B64.encode(payload));
        let signature = signer.sign(message.as_bytes())?;
        Ok(format!("{message}.{}", B64.encode(signature)))
    }

    /// Loads the keys again. A deployment with no key that may sign gets
    /// one, under a lock, so replicas that start together make one key. A key
    /// sealed under `TUTELA_MASTER_KEY_PREVIOUS` is re-wrapped to the current
    /// master key on the way.
    ///
    /// # Errors
    ///
    /// [`KeyError::Db`] or [`KeyError::Unusable`]. The keys in hand stay.
    pub async fn refresh(&self, db: &Db) -> Result<(), KeyError> {
        let mut conn = db.conn().await?;
        let set = conn.signing_keys(&self.vault).await?;
        let mut keys = Vec::with_capacity(set.keys.len());
        let mut jwks = Vec::with_capacity(set.keys.len());
        for k in &set.keys {
            let pkcs8 = k
                .open(&self.vault)
                .map_err(|_| KeyError::Unusable(k.kid.clone()))?;
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
                .map_err(|_| KeyError::Unusable(k.kid.clone()))?;
            let jwk: serde_json::Value = serde_json::from_str(&k.public_jwk)
                .map_err(|_| KeyError::Unusable(k.kid.clone()))?;
            jwks.push(jwk);
            keys.push(Live {
                signs_from: k.signs_from,
                retire_at: k.retire_at,
                signer: Arc::new(LocalSigner {
                    kid: k.kid.clone(),
                    pair,
                }),
            });
        }
        let body = serde_json::to_vec(&Jwks { keys: jwks })
            .map_err(|_| KeyError::Unusable("jwks".to_owned()))?;
        let KeySet { now, denied, .. } = set;
        let ring = Arc::new(Ring {
            db_now: now,
            at: Instant::now(),
            keys,
            denied,
            jwks: Arc::from(body),
        });
        if let Ok(mut slot) = self.ring.write() {
            *slot = ring;
        }
        Ok(())
    }
}

/// `<iss>/.well-known/jwks.json`.
#[must_use]
pub fn jwks_url(iss: &Issuer) -> String {
    format!("{}{JWKS_PATH}", iss.as_str())
}

/// The rotation times for a JWKS cache time: publish twice the cache time
/// ahead; keep a key until the longest access token it signed has expired,
/// plus the clock skew (CONTRACTS.md 10.4).
#[must_use]
pub const fn rotation_times(jwks_cache: Duration) -> KeyTimes {
    KeyTimes {
        lead: Duration::from_secs(jwks_cache.as_secs().saturating_mul(2)),
        keep: Duration::from_secs(MAX_ACCESS_TOKEN_LIFETIME_SECS + CLOCK_SKEW_SECS),
    }
}

/// The verifier's JWKS source: this issuer's own keys from memory, and
/// every other issuer's through `other` (`tutela-safenet`). `tutelad` never
/// fetches its own JWKS over the network.
pub struct OwnJwks {
    ring: Arc<KeyRing>,
    other: Arc<dyn JwksSource>,
}

impl OwnJwks {
    /// Over `ring`, with `other` for every other issuer.
    #[must_use]
    pub fn new(ring: Arc<KeyRing>, other: Arc<dyn JwksSource>) -> Self {
        Self { ring, other }
    }
}

impl JwksSource for OwnJwks {
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> {
        if url == self.ring.jwks_url() {
            let body = self.ring.jwks().to_vec();
            return Box::pin(async move { Some(body) });
        }
        self.other.fetch(url)
    }
}

/// One refresh, and every verifier's deny-list after it. A denied `kid` is
/// refused at once on this replica, even when a verifier has it cached.
///
/// # Errors
///
/// As [`KeyRing::refresh`].
pub async fn refresh(state: &AppState) -> Result<(), KeyError> {
    let ring = &state.keys;
    let before = ring.published();
    let result = ring.refresh(&state.db).await;
    state.metrics.count_key_refresh(result.is_ok());
    let after = ring.published();
    let verifiers = std::iter::once(&state.verifier).chain(state.audiences.verifiers());
    for verifier in verifiers {
        for kid in ring.denied() {
            verifier.deny_kid(&kid);
        }
        if after != before {
            // A key that signs at once (the first, or one after a denial)
            // must not wait for the verifier's refetch limit.
            verifier.forget_jwks(ring.jwks_url()).await;
        }
    }
    state.metrics.set_published_keys(after.len());
    result
}

/// Refreshes the keys every `every` until `stop` says so. A failure keeps
/// the keys in hand and is logged; a missing key shows up as 503 where a
/// token is needed, never as a token signed with a guess.
pub async fn run(state: AppState, every: Duration, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        if let Err(e) = refresh(&state).await {
            tracing::warn!(error = %e, "the signing keys could not be refreshed");
        }
    }
}

/// `GET /.well-known/jwks.json`: the published keys, the next one included.
/// It needs no token. Verifiers may cache it for `TUTELA_JWKS_CACHE_SECS`.
pub async fn jwks(State(state): State<AppState>) -> Response {
    let body = state.keys.jwks().to_vec();
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/jwk-set+json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_str(&format!("public, max-age={}", state.keys.cache_secs))
                    .unwrap_or(HeaderValue::from_static("no-store")),
            ),
        ],
        body,
    )
        .into_response()
}
