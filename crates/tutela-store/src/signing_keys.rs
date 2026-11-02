//! `tutelad`'s token signing keys (ADR-0030, THREAT-MODEL.md TM-15).
//!
//! The key set belongs to the deployment, not to a tenant (per-tenant keys
//! are Phase C), so these calls take no tenant and the table has no
//! row-level security. The service role may read, add and update keys, never
//! delete them.
//!
//! A private key leaves this module only as a [`tutela_vault`] envelope,
//! sealed under the master key for the purpose [`PURPOSE`] and the key's
//! `kid`. It is never stored, returned or logged in plain text; a caller
//! that must sign opens it with [`StoredKey::open`].
//!
//! **Times.** Every time is the database's clock, so replicas agree.
//!
//! - A key is in the JWKS from the moment it is made until `retire_at`,
//!   unless it is denied.
//! - It signs from `signs_from`. The signing key is the one with the latest
//!   `signs_from` that has come, among the keys that are not denied or
//!   retired.
//! - [`rotate_signing_key`] makes the next key with `signs_from` at
//!   [`KeyTimes::lead`] from now, at least twice the JWKS cache time, and
//!   retires the key that signs now at [`KeyTimes::keep`] after the switch:
//!   the longest token life plus the clock skew.
//! - [`deny_signing_key`] takes a key out of the JWKS at once and puts its
//!   `kid` on the deny-list for good. If it was the signing key, a pending
//!   next key signs at once, or a new one is made.
//!
//! `tutela keys rotate` (part 4) calls [`rotate_signing_key`] and
//! [`deny_signing_key`]; `tutelad` calls [`ensure_signing_key`] and
//! [`signing_keys`].

use std::time::{Duration, SystemTime};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};
use tokio_postgres::{Row, Transaction};
use tutela_vault::{Kms, Vault};
use zeroize::Zeroizing;

use crate::{DbResult as _, StoreError};

/// The `tutela-vault` purpose of a sealed signing key.
pub const PURPOSE: &str = "signing_key";

/// The one algorithm `tutelad` signs with (CONTRACTS.md 4.1: ES256 is the
/// default).
pub const ALG: &str = "ES256";

/// One lock id for every caller that changes the key set
/// (`pg_advisory_xact_lock`), so two replicas never both make a first key.
const LOCK_ID: i64 = 0x7475_7465_6c61_0006;

/// When a rotation publishes and retires keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyTimes {
    /// How long the next key is published before it signs: at least twice
    /// the JWKS cache time (CONTRACTS.md 10.4).
    pub lead: Duration,
    /// How long a key stays published after it stopped signing: the longest
    /// token life plus the clock skew.
    pub keep: Duration,
}

/// One stored key. The private key is in [`StoredKey::sealed`] only.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// The RFC 7638 thumbprint of the public key.
    pub kid: String,
    /// `ES256`.
    pub alg: String,
    /// The public JWK, as JSON text, with `kid`, `alg` and `use`.
    pub public_jwk: String,
    /// The private key, sealed by `tutela-vault`.
    pub sealed: Vec<u8>,
    /// When it starts to sign.
    pub signs_from: SystemTime,
    /// When it leaves the JWKS.
    pub retire_at: Option<SystemTime>,
    /// When it was denied.
    pub denied_at: Option<SystemTime>,
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKey")
            .field("kid", &self.kid)
            .field("signs_from", &self.signs_from)
            .field("retire_at", &self.retire_at)
            .field("denied_at", &self.denied_at)
            .finish_non_exhaustive()
    }
}

impl StoredKey {
    /// The private key as PKCS#8, opened with `vault`. The bytes are wiped
    /// when dropped.
    ///
    /// # Errors
    ///
    /// [`Invalid`](crate::StoreErrorKind::Invalid) when the vault cannot open
    /// it: another master key, or a blob that was changed.
    pub fn open<K: Kms>(&self, vault: &Vault<K>) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        vault
            .open(PURPOSE, self.kid.as_bytes(), &self.sealed)
            .map_err(|_| StoreError::invalid("the signing key does not open with this master key"))
    }

    /// `true` while it is in the JWKS at `now`.
    #[must_use]
    pub fn published(&self, now: SystemTime) -> bool {
        self.denied_at.is_none() && self.retire_at.is_none_or(|r| now < r)
    }

    /// `true` if it may sign at `now`: published, and its time has come.
    #[must_use]
    pub fn may_sign(&self, now: SystemTime) -> bool {
        self.published(now) && self.signs_from <= now
    }
}

/// The key set at one moment of the database's clock.
#[derive(Clone, Debug)]
pub struct KeySet {
    /// The database's clock when it was read.
    pub now: SystemTime,
    /// Every key that is published now or still to sign, oldest first.
    pub keys: Vec<StoredKey>,
    /// Every denied `kid`.
    pub denied: Vec<String>,
}

impl KeySet {
    /// The key that signs at `now`: the latest `signs_from` that has come.
    #[must_use]
    pub fn signing(&self, now: SystemTime) -> Option<&StoredKey> {
        self.keys
            .iter()
            .filter(|k| k.may_sign(now))
            .max_by_key(|k| k.signs_from)
    }
}

/// What a rotation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// The next key.
    pub next: String,
    /// When it starts to sign.
    pub signs_from: SystemTime,
    /// `false` when a next key was already waiting: no key was made.
    pub made: bool,
    /// The key that signs until then, and when it leaves the JWKS.
    pub previous: Option<(String, SystemTime)>,
}

/// The RFC 7638 thumbprint of a P-256 public key given as `x` and `y`.
#[must_use]
pub fn thumbprint(x: &str, y: &str) -> String {
    let json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    B64.encode(Sha256::digest(json.as_bytes()))
}

/// A new key: its `kid`, public JWK and sealed private key. The PKCS#8
/// bytes are wiped when this returns.
fn new_key<K: Kms>(vault: &Vault<K>) -> Result<(String, String, Vec<u8>), StoreError> {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map_err(|_| StoreError::corrupt("a new signing key"))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .map_err(|_| StoreError::corrupt("a new signing key"))?;
    let point = pair.public_key().as_ref();
    let (Some(x), Some(y)) = (point.get(1..33), point.get(33..65)) else {
        return Err(StoreError::corrupt("a new signing key"));
    };
    let (x, y) = (B64.encode(x), B64.encode(y));
    let kid = thumbprint(&x, &y);
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "kid": kid, "alg": ALG, "use": "sig",
    })
    .to_string();
    let sealed = vault
        .seal(PURPOSE, kid.as_bytes(), pkcs8.as_ref())
        .map_err(|_| StoreError::invalid("the signing key could not be sealed"))?;
    Ok((kid, jwk, sealed))
}

async fn lock(tx: &Transaction<'_>) -> Result<SystemTime, StoreError> {
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&LOCK_ID])
        .await
        .db()?;
    db_now(tx).await
}

async fn db_now(tx: &Transaction<'_>) -> Result<SystemTime, StoreError> {
    tx.query_one("SELECT clock_timestamp()", &[])
        .await
        .db()?
        .try_get(0)
        .db()
}

fn row(r: &Row) -> Result<StoredKey, StoreError> {
    Ok(StoredKey {
        kid: r.try_get(0).db()?,
        alg: r.try_get(1).db()?,
        public_jwk: r.try_get(2).db()?,
        sealed: r.try_get(3).db()?,
        signs_from: r.try_get(4).db()?,
        retire_at: r.try_get(5).db()?,
        denied_at: r.try_get(6).db()?,
    })
}

const COLUMNS: &str = "kid, alg, public_jwk, sealed, signs_from, retire_at, denied_at";

async fn insert(
    tx: &Transaction<'_>,
    vault: &Vault<impl Kms>,
    signs_from: SystemTime,
) -> Result<String, StoreError> {
    let (kid, jwk, sealed) = new_key(vault)?;
    tx.execute(
        "INSERT INTO tutela.signing_key (kid, alg, public_jwk, sealed, signs_from) \
         VALUES ($1, $2, $3, $4, $5)",
        &[&kid, &ALG, &jwk, &sealed, &signs_from],
    )
    .await
    .db()?;
    Ok(kid)
}

/// The key set now: every key that is published or still to sign, and the
/// deny-list.
///
/// # Errors
///
/// A database error, or [`Corrupt`](crate::StoreErrorKind::Corrupt) for a
/// row that does not parse.
pub async fn signing_keys(tx: &Transaction<'_>) -> Result<KeySet, StoreError> {
    let now = db_now(tx).await?;
    let rows = tx
        .query(
            &format!(
                "SELECT {COLUMNS} FROM tutela.signing_key \
                 WHERE denied_at IS NULL AND (retire_at IS NULL OR retire_at > $1) \
                 ORDER BY signs_from, kid"
            ),
            &[&now],
        )
        .await
        .db()?;
    let keys = rows.iter().map(row).collect::<Result<Vec<_>, _>>()?;
    let denied = tx
        .query(
            "SELECT kid FROM tutela.signing_key WHERE denied_at IS NOT NULL ORDER BY kid",
            &[],
        )
        .await
        .db()?
        .iter()
        .map(|r| r.try_get(0).db())
        .collect::<Result<Vec<String>, _>>()?;
    Ok(KeySet { now, keys, denied })
}

/// Makes a key that signs at once when no key may sign now: the first start
/// of a deployment, or after the signing key was denied with no next key.
/// Returns the new `kid`, or `None` when a key signs already.
///
/// # Errors
///
/// A database or vault error.
pub async fn ensure_signing_key<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
) -> Result<Option<String>, StoreError> {
    let now = lock(tx).await?;
    let set = signing_keys(tx).await?;
    if set.signing(now).is_some() {
        return Ok(None);
    }
    // A pending next key is already published: it signs now rather than a
    // key that no cache has seen.
    if let Some(next) = set.keys.iter().find(|k| k.signs_from > now) {
        tx.execute(
            "UPDATE tutela.signing_key SET signs_from = $2 WHERE kid = $1",
            &[&next.kid, &now],
        )
        .await
        .db()?;
        return Ok(Some(next.kid.clone()));
    }
    insert(tx, vault, now).await.map(Some)
}

/// Starts a rotation: the next key is published now and signs at
/// `times.lead` from now; the key that signs now leaves the JWKS at
/// `times.keep` after that. A rotation that is already waiting is returned
/// as it is (`made` is `false`). With no signing key at all, the new key
/// signs at once.
///
/// # Errors
///
/// A database or vault error.
pub async fn rotate_signing_key<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
    times: KeyTimes,
) -> Result<Rotation, StoreError> {
    let now = lock(tx).await?;
    let set = signing_keys(tx).await?;
    if let Some(next) = set.keys.iter().find(|k| k.signs_from > now) {
        let previous = set
            .signing(now)
            .and_then(|k| k.retire_at.map(|r| (k.kid.clone(), r)));
        return Ok(Rotation {
            next: next.kid.clone(),
            signs_from: next.signs_from,
            made: false,
            previous,
        });
    }
    let Some(current) = set.signing(now) else {
        let kid = insert(tx, vault, now).await?;
        return Ok(Rotation {
            next: kid,
            signs_from: now,
            made: true,
            previous: None,
        });
    };
    let signs_from = now + times.lead;
    let retire_at = signs_from + times.keep;
    let kid = insert(tx, vault, signs_from).await?;
    // Every older key that has no end yet ends with this one.
    tx.execute(
        "UPDATE tutela.signing_key SET retire_at = $2 \
         WHERE retire_at IS NULL AND denied_at IS NULL AND kid <> $1",
        &[&kid, &retire_at],
    )
    .await
    .db()?;
    Ok(Rotation {
        next: kid,
        signs_from,
        made: true,
        previous: Some((current.kid.clone(), retire_at)),
    })
}

/// Denies a key: it leaves the JWKS at once, and its `kid` is on the
/// deny-list for good (TM-15, an emergency). If no key may sign after it,
/// a pending next key signs at once, or a new key is made; its `kid` is
/// returned.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for an unknown `kid`, or a
/// database or vault error.
pub async fn deny_signing_key<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
    kid: &str,
) -> Result<Option<String>, StoreError> {
    let now = lock(tx).await?;
    let found = tx
        .execute(
            "UPDATE tutela.signing_key SET denied_at = coalesce(denied_at, $2) WHERE kid = $1",
            &[&kid, &now],
        )
        .await
        .db()?;
    if found == 0 {
        return Err(StoreError::not_found("signing key"));
    }
    ensure_signing_key(tx, vault).await
}

/// Re-wraps every sealed key that a previous master key wrapped, after a
/// master-key rotation (CONTRACTS.md 10.4). The key itself does not change.
/// Returns how many were re-wrapped.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a key the vault cannot
/// open, or a database error.
pub async fn rewrap_signing_keys<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
) -> Result<usize, StoreError> {
    lock(tx).await?;
    let rows = tx
        .query(
            &format!("SELECT {COLUMNS} FROM tutela.signing_key WHERE denied_at IS NULL"),
            &[],
        )
        .await
        .db()?;
    let mut n = 0;
    for r in &rows {
        let k = row(r)?;
        let blob = vault
            .rewrap(PURPOSE, k.kid.as_bytes(), &k.sealed)
            .map_err(|_| {
                StoreError::invalid("the signing key does not open with this master key")
            })?;
        if let Some(blob) = blob {
            tx.execute(
                "UPDATE tutela.signing_key SET sealed = $2 WHERE kid = $1",
                &[&k.kid, &blob],
            )
            .await
            .db()?;
            n += 1;
        }
    }
    Ok(n)
}
