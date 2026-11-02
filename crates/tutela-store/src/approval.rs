//! Approval tokens for widening model changes (ADR-0015, ADR-0026).
//!
//! A token is `tutela-approval-v1.<payload>.<signature>`, both base64url
//! without padding. The payload is JSON:
//! `{"app", "from", "to", "kid", "iat", "exp"}`, and `"tid"` when it approves
//! the change for one tenant. `from` and `to` are the SHA-256 digests of the
//! applied and the new manifest (`from` is `none` for a first apply). The diff
//! is a function of the two manifests, so the token approves exactly one diff.
//! The signature is Ed25519 over the ASCII bytes
//! `tutela-approval-v1.<payload>`.
//!
//! `tutela apply` in library mode changes the app's manifest, for every
//! tenant, and takes a token with no `tid`. `tutelad` changes one tenant's
//! model and takes a token for that tenant only: the same two manifests can
//! mean something else in another tenant.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::approver_id;

/// The token prefix, also the signature's domain separator.
pub const PREFIX: &str = "tutela-approval-v1";

/// The longest a token may live: 24 hours.
pub const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Clock skew allowed for `iat`.
const SKEW_SECS: u64 = 300;

/// `from` for an app with no applied manifest yet.
pub const NO_MANIFEST: &str = "none";

/// What a token approves.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// The app.
    pub app: String,
    /// The digest of the applied manifest, or [`NO_MANIFEST`].
    pub from: String,
    /// The digest of the new manifest.
    pub to: String,
    /// The approver key id (`apk_...`).
    pub kid: String,
    /// Issued at, Unix seconds.
    pub iat: u64,
    /// Expires at, Unix seconds.
    pub exp: u64,
    /// The one tenant it approves the change for. `None`: the app's manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<String>,
}

/// Why a token or a key was refused. The messages never contain the token
/// or the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// Not three parts, not base64url, not the expected JSON.
    #[error("the approval token is malformed")]
    Malformed,
    /// The signature does not match the payload and the key.
    #[error("the approval token's signature is not valid")]
    BadSignature,
    /// The key id is unknown to this database.
    #[error("the approval token names an unknown approver key")]
    UnknownKey,
    /// The key was revoked.
    #[error("the approval token's key is revoked")]
    RevokedKey,
    /// The token approves another app or another pair of manifests.
    #[error("the approval token approves a different change")]
    OtherChange,
    /// Expired, issued in the future, or living longer than 24 hours.
    #[error("the approval token is expired or its times are not valid")]
    Expired,
    /// A key file that is not ours.
    #[error("the key file is not a tutela approver key")]
    BadKeyFile,
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
}

/// Signs an approval.
///
/// # Errors
///
/// [`ApprovalError::Expired`] if `exp` is not after `iat` or the token would
/// live longer than 24 hours, [`ApprovalError::Malformed`] if the payload
/// does not serialize.
pub fn mint(key: &SigningKey, approval: &Approval) -> Result<String, ApprovalError> {
    if approval.exp <= approval.iat || approval.exp - approval.iat > MAX_LIFETIME_SECS {
        return Err(ApprovalError::Expired);
    }
    let json = serde_json::to_vec(approval).map_err(|_| ApprovalError::Malformed)?;
    let signed = format!("{PREFIX}.{}", B64.encode(json));
    let sig = key.sign(signed.as_bytes());
    Ok(format!("{signed}.{}", B64.encode(sig.to_bytes())))
}

/// Reads a token without checking its signature, to learn its key id.
///
/// # Errors
///
/// [`ApprovalError::Malformed`].
pub fn peek(token: &str) -> Result<Approval, ApprovalError> {
    let (_, approval, _) = split(token)?;
    Ok(approval)
}

/// Checks a token: the signature with `key`, the change it approves, the
/// tenant it is for (`None`: it must name no tenant), and its times against
/// `now` (Unix seconds).
///
/// # Errors
///
/// The [`ApprovalError`] that says why it was refused.
pub fn verify(
    token: &str,
    key: &[u8; 32],
    app: &str,
    from: &str,
    to: &str,
    tenant: Option<&str>,
    now: u64,
) -> Result<Approval, ApprovalError> {
    let (signed, approval, sig) = split(token)?;
    let vk = VerifyingKey::from_bytes(key).map_err(|_| ApprovalError::BadSignature)?;
    vk.verify_strict(signed.as_bytes(), &sig)
        .map_err(|_| ApprovalError::BadSignature)?;
    if approval.kid != approver_id(key) {
        return Err(ApprovalError::BadSignature);
    }
    if approval.app != app
        || approval.from != from
        || approval.to != to
        || approval.tid.as_deref() != tenant
    {
        return Err(ApprovalError::OtherChange);
    }
    if approval.exp <= approval.iat
        || approval.exp - approval.iat > MAX_LIFETIME_SECS
        || approval.iat > now.saturating_add(SKEW_SECS)
        || now >= approval.exp
    {
        return Err(ApprovalError::Expired);
    }
    Ok(approval)
}

fn split(token: &str) -> Result<(&str, Approval, Signature), ApprovalError> {
    let (signed, sig) = token.rsplit_once('.').ok_or(ApprovalError::Malformed)?;
    let (prefix, payload) = signed.split_once('.').ok_or(ApprovalError::Malformed)?;
    if prefix != PREFIX || payload.contains('.') {
        return Err(ApprovalError::Malformed);
    }
    let json = B64.decode(payload).map_err(|_| ApprovalError::Malformed)?;
    let approval: Approval = serde_json::from_slice(&json).map_err(|_| ApprovalError::Malformed)?;
    let sig = B64.decode(sig).map_err(|_| ApprovalError::Malformed)?;
    let sig: [u8; 64] = sig
        .as_slice()
        .try_into()
        .map_err(|_| ApprovalError::Malformed)?;
    Ok((signed, approval, Signature::from_bytes(&sig)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";

    #[test]
    fn tm08_a_token_for_one_tenant_approves_nothing_else() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let pk = key.verifying_key().to_bytes();
        let approval = |tid: Option<&str>| Approval {
            app: "crm".into(),
            from: "a".into(),
            to: "b".into(),
            kid: approver_id(&pk),
            iat: 1_000,
            exp: 2_000,
            tid: tid.map(str::to_owned),
        };
        let at = |t: &str, tid| verify(t, &pk, "crm", "a", "b", tid, 1_500);
        let bound = mint(&key, &approval(Some(TID))).unwrap();
        assert!(at(&bound, Some(TID)).is_ok());
        assert_eq!(at(&bound, Some("other")), Err(ApprovalError::OtherChange));
        assert_eq!(at(&bound, None), Err(ApprovalError::OtherChange));
        // A token for the whole app changes no single tenant's model.
        let open = mint(&key, &approval(None)).unwrap();
        assert!(at(&open, None).is_ok());
        assert_eq!(at(&open, Some(TID)), Err(ApprovalError::OtherChange));
    }
}
