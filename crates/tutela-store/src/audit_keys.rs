//! The deployment's audit producer key, sealed (ADR-0045, CONTRACTS.md
//! 9.3).
//!
//! The Ed25519 key that signs the audit records `tutelad` forwards to
//! attache's evidence ledger. Its 32-byte seed is stored only as a
//! `tutela-vault` envelope, sealed under the master key for the purpose
//! [`PURPOSE`] and the key's `kid`. One key signs at a time; a rotation
//! retires it and makes the next. A retired key keeps its public key, and
//! no key is deleted (a trigger holds it), so every record a key signed
//! stays verifiable.

use std::time::SystemTime;

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};
use tokio_postgres::{Row, Transaction};
use tutela_vault::{Kms, Vault};
use zeroize::Zeroizing;

use crate::{DbResult as _, StoreError};

/// The `tutela-vault` purpose of a sealed audit key.
pub const PURPOSE: &str = "audit_key";

/// Serializes the changes to the audit keys.
const LOCK_ID: i64 = 0x7475_7465_6c61_6175;

/// The RFC 7638 thumbprint of an Ed25519 public key: `signature.key_id`.
#[must_use]
pub fn audit_key_id(public: &[u8]) -> String {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        B64.encode(public)
    );
    B64.encode(Sha256::digest(jwk.as_bytes()))
}

/// One audit key. The seed is in [`AuditKey::sealed`] only.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditKey {
    /// Its RFC 7638 thumbprint.
    pub kid: String,
    /// The 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
    /// The seed, sealed.
    pub sealed: Vec<u8>,
    /// `made` here, or `imported` from `TUTELA_AUDIT_KEY`.
    pub origin: String,
    /// When it was stored.
    pub created_at: SystemTime,
    /// When it stopped signing; `None` for the key that signs.
    pub retired_at: Option<SystemTime>,
}

impl std::fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditKey")
            .field("kid", &self.kid)
            .field("origin", &self.origin)
            .field("retired_at", &self.retired_at)
            .finish_non_exhaustive()
    }
}

impl AuditKey {
    /// The 32-byte seed, opened with `vault`. Wiped when dropped.
    ///
    /// # Errors
    ///
    /// [`Invalid`](crate::StoreErrorKind::Invalid) when the vault cannot open
    /// it: another master key, or a blob that was changed.
    pub fn open<K: Kms>(&self, vault: &Vault<K>) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        vault
            .open(PURPOSE, self.kid.as_bytes(), &self.sealed)
            .map_err(|_| StoreError::invalid("the audit key does not open with this master key"))
    }
}

impl AuditKey {
    /// The key pair, opened with `vault`, to sign with.
    ///
    /// # Errors
    ///
    /// As [`AuditKey::open`], and [`Corrupt`](crate::StoreErrorKind::Corrupt)
    /// for a seed that does not make this key's public key.
    pub fn pair<K: Kms>(&self, vault: &Vault<K>) -> Result<Ed25519KeyPair, StoreError> {
        let seed = self.open(vault)?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| StoreError::corrupt("audit key"))?;
        if pair.public_key().as_ref() == self.public_key.as_slice() {
            Ok(pair)
        } else {
            Err(StoreError::corrupt("audit key"))
        }
    }
}

const COLUMNS: &str = "kid, public_key, sealed, origin, created_at, retired_at";

fn row(r: &Row) -> Result<AuditKey, StoreError> {
    Ok(AuditKey {
        kid: r.try_get(0).db()?,
        public_key: r.try_get(1).db()?,
        sealed: r.try_get(2).db()?,
        origin: r.try_get(3).db()?,
        created_at: r.try_get(4).db()?,
        retired_at: r.try_get(5).db()?,
    })
}

async fn lock(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&LOCK_ID])
        .await
        .db()?;
    Ok(())
}

/// Every audit key, the retired ones too, oldest first: what verifies a
/// forwarded record.
///
/// # Errors
///
/// A database error.
pub async fn audit_keys(tx: &Transaction<'_>) -> Result<Vec<AuditKey>, StoreError> {
    tx.query(
        &format!("SELECT {COLUMNS} FROM tutela.audit_key ORDER BY created_at, kid"),
        &[],
    )
    .await
    .db()?
    .iter()
    .map(row)
    .collect()
}

/// The key that signs, if there is one.
///
/// # Errors
///
/// A database error.
pub async fn signing_audit_key(tx: &Transaction<'_>) -> Result<Option<AuditKey>, StoreError> {
    tx.query_opt(
        &format!("SELECT {COLUMNS} FROM tutela.audit_key WHERE retired_at IS NULL"),
        &[],
    )
    .await
    .db()?
    .as_ref()
    .map(row)
    .transpose()
}

async fn insert<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
    seed: &[u8],
    origin: &str,
) -> Result<String, StoreError> {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| StoreError::invalid("an audit key is a 32-byte Ed25519 seed"))?;
    let public = pair.public_key().as_ref().to_vec();
    let kid = audit_key_id(&public);
    let sealed = vault
        .seal(PURPOSE, kid.as_bytes(), seed)
        .map_err(|_| StoreError::invalid("the audit key could not be sealed"))?;
    tx.execute(
        "INSERT INTO tutela.audit_key (kid, alg, public_key, sealed, origin) \
         VALUES ($1, 'EdDSA', $2, $3, $4)",
        &[&kid, &public, &sealed, &origin],
    )
    .await
    .map_err(|e| {
        if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
            StoreError::exists("this audit key")
        } else {
            StoreError::from(crate::Repr::Db(e))
        }
    })?;
    Ok(kid)
}

fn new_seed() -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(seed.as_mut())
        .map_err(|_| StoreError::corrupt("a new audit key"))?;
    Ok(seed)
}

/// What [`ensure_audit_key`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ensured {
    /// A key signs already. `ignored` is `true` when an import was offered
    /// and is not that key: the stored key wins.
    Kept {
        /// The key that signs.
        kid: String,
        /// An offered import was not used.
        ignored: bool,
    },
    /// The offered seed (`TUTELA_AUDIT_KEY`) was sealed and signs now.
    Imported(String),
    /// A new key was made and signs now.
    Made(String),
}

/// Makes sure a key signs: the one there is; else `import`, the seed of
/// `TUTELA_AUDIT_KEY` from before this migration, sealed; else a new key.
/// A stored key always wins over the environment.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a seed that is not 32
/// bytes or a vault that cannot seal, or a database error.
pub async fn ensure_audit_key<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
    import: Option<&[u8]>,
) -> Result<Ensured, StoreError> {
    lock(tx).await?;
    if let Some(k) = signing_audit_key(tx).await? {
        let ignored = import.is_some_and(|seed| {
            Ed25519KeyPair::from_seed_unchecked(seed)
                .is_ok_and(|p| audit_key_id(p.public_key().as_ref()) != k.kid)
        });
        return Ok(Ensured::Kept {
            kid: k.kid,
            ignored,
        });
    }
    match import {
        Some(seed) => {
            // A key imported before and since retired is not brought back.
            let pair = Ed25519KeyPair::from_seed_unchecked(seed)
                .map_err(|_| StoreError::invalid("an audit key is a 32-byte Ed25519 seed"))?;
            let kid = audit_key_id(pair.public_key().as_ref());
            if audit_keys(tx).await?.iter().any(|k| k.kid == kid) {
                let seed = new_seed()?;
                return Ok(Ensured::Made(
                    insert(tx, vault, seed.as_ref(), "made").await?,
                ));
            }
            Ok(Ensured::Imported(
                insert(tx, vault, seed, "imported").await?,
            ))
        }
        None => {
            let seed = new_seed()?;
            Ok(Ensured::Made(
                insert(tx, vault, seed.as_ref(), "made").await?,
            ))
        }
    }
}

/// Retires the key that signs and makes the next. Returns the new `kid`
/// and the retired one. Records already forwarded stay verifiable with the
/// retired key's public key, which is kept.
///
/// # Errors
///
/// A database or vault error.
pub async fn rotate_audit_key<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
) -> Result<(String, Option<String>), StoreError> {
    lock(tx).await?;
    let old = tx
        .query_opt(
            "UPDATE tutela.audit_key SET retired_at = clock_timestamp() \
             WHERE retired_at IS NULL RETURNING kid",
            &[],
        )
        .await
        .db()?
        .map(|r| r.try_get::<_, String>(0))
        .transpose()
        .db()?;
    let seed = new_seed()?;
    let kid = insert(tx, vault, seed.as_ref(), "made").await?;
    Ok((kid, old))
}

/// Seals every audit key again under the current master key. Returns how
/// many changed.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a key the vault cannot
/// open, or a database error.
pub async fn rewrap_audit_keys<K: Kms>(
    tx: &Transaction<'_>,
    vault: &Vault<K>,
) -> Result<usize, StoreError> {
    lock(tx).await?;
    let mut n = 0;
    for k in audit_keys(tx).await? {
        let blob = vault
            .rewrap(PURPOSE, k.kid.as_bytes(), &k.sealed)
            .map_err(|_| StoreError::invalid("the audit key does not open with this master key"))?;
        if let Some(blob) = blob {
            tx.execute(
                "UPDATE tutela.audit_key SET sealed = $2 WHERE kid = $1",
                &[&k.kid, &blob],
            )
            .await
            .db()?;
            n += 1;
        }
    }
    Ok(n)
}
