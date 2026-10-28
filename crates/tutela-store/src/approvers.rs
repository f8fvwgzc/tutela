//! Approver keys for widening model changes in library mode (ADR-0015).
//!
//! The store keeps only public keys. A key id is `apk_` and the first 32 hex
//! digits of SHA-256 of the public key, so a signer can name its key without
//! asking the database.

use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;

use crate::StoreError;

/// The longest approver name.
const MAX_NAME: usize = 256;

/// One approver key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Approver {
    /// `apk_<32 hex>`.
    pub id: String,
    /// Who holds it (a display label).
    pub name: String,
    /// The Ed25519 public key.
    pub public_key: [u8; 32],
    /// `true` once revoked: it approves nothing.
    pub revoked: bool,
}

/// The key id of an Ed25519 public key.
#[must_use]
pub fn approver_id(public_key: &[u8; 32]) -> String {
    let d = Sha256::digest(public_key);
    let hex: String = d.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("apk_{hex}")
}

/// Registers an approver key. Returns its id.
///
/// # Errors
///
/// [`StoreError::Invalid`] for an empty name, one over 256 characters or one
/// with control characters; [`StoreError::Exists`] if the key is registered;
/// or a database error.
pub async fn add_approver(
    tx: &Transaction<'_>,
    name: &str,
    public_key: &[u8; 32],
) -> Result<String, StoreError> {
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(StoreError::Invalid(
            "an approver name is 1 to 256 characters with no control characters",
        ));
    }
    let id = approver_id(public_key);
    if approver(tx, &id).await?.is_some() {
        return Err(StoreError::Exists("this approver key"));
    }
    tx.execute(
        "INSERT INTO tutela.approver_key (id, name, public_key) VALUES ($1, $2, $3)",
        &[&id, &name, &public_key.as_slice()],
    )
    .await?;
    Ok(id)
}

/// Revokes an approver key. A revoked key approves nothing, also not a token
/// it signed before.
///
/// # Errors
///
/// [`StoreError::NotFound`] for an unknown or already revoked key, or a
/// database error.
pub async fn revoke_approver(tx: &Transaction<'_>, id: &str) -> Result<(), StoreError> {
    let n = tx
        .execute(
            "UPDATE tutela.approver_key SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
            &[&id],
        )
        .await?;
    if n == 0 {
        return Err(StoreError::NotFound("approver key"));
    }
    Ok(())
}

/// One approver key, if it exists (revoked or not).
///
/// # Errors
///
/// A database error, or [`StoreError::Corrupt`] for a bad stored key.
pub async fn approver(tx: &Transaction<'_>, id: &str) -> Result<Option<Approver>, StoreError> {
    let row = tx
        .query_opt(
            "SELECT id, name, public_key, revoked_at IS NOT NULL FROM tutela.approver_key \
             WHERE id = $1",
            &[&id],
        )
        .await?;
    row.map(|r| to_approver(&r)).transpose()
}

/// Every approver key, oldest first.
///
/// # Errors
///
/// A database error, or [`StoreError::Corrupt`] for a bad stored key.
pub async fn approvers(tx: &Transaction<'_>) -> Result<Vec<Approver>, StoreError> {
    tx.query(
        "SELECT id, name, public_key, revoked_at IS NOT NULL FROM tutela.approver_key \
         ORDER BY created_at, id",
        &[],
    )
    .await?
    .iter()
    .map(to_approver)
    .collect()
}

fn to_approver(r: &tokio_postgres::Row) -> Result<Approver, StoreError> {
    let key: &[u8] = r.try_get(2)?;
    Ok(Approver {
        id: r.try_get(0)?,
        name: r.try_get(1)?,
        public_key: key
            .try_into()
            .map_err(|_| StoreError::Corrupt("approver public key"))?,
        revoked: r.try_get(3)?,
    })
}
