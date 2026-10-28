//! Approval tokens for widening model changes in library mode (ADR-0015).
//!
//! A token is `tutela-approval-v1.<payload>.<signature>`, both base64url
//! without padding. The payload is JSON:
//! `{"app", "from", "to", "kid", "iat", "exp"}`. `from` and `to` are the
//! SHA-256 digests of the applied and the new manifest (`from` is `none` for
//! a first apply). The diff is a function of the two manifests, so the token
//! approves exactly one diff. The signature is Ed25519 over the ASCII bytes
//! `tutela-approval-v1.<payload>`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The token prefix, also the signature's domain separator.
pub const PREFIX: &str = "tutela-approval-v1";

/// The first line of a private key file.
pub const KEY_FILE_HEADER: &str = "tutela-approver-key-v1";

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

/// A new signing key from the system random source.
///
/// # Errors
///
/// [`ApprovalError::Random`].
pub fn generate() -> Result<SigningKey, ApprovalError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| ApprovalError::Random)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The text of a private key file.
#[must_use]
pub fn key_file_text(key: &SigningKey) -> Zeroizing<String> {
    let seed = Zeroizing::new(key.to_bytes());
    Zeroizing::new(format!(
        "{KEY_FILE_HEADER}\n{}\n",
        B64.encode(seed.as_ref())
    ))
}

/// Reads a private key file's text.
///
/// # Errors
///
/// [`ApprovalError::BadKeyFile`].
pub fn parse_key_file(text: &str) -> Result<SigningKey, ApprovalError> {
    let mut lines = text.lines();
    if lines.next() != Some(KEY_FILE_HEADER) {
        return Err(ApprovalError::BadKeyFile);
    }
    let body = lines.next().ok_or(ApprovalError::BadKeyFile)?;
    if lines.any(|l| !l.trim().is_empty()) {
        return Err(ApprovalError::BadKeyFile);
    }
    let raw = Zeroizing::new(
        B64.decode(body.trim())
            .map_err(|_| ApprovalError::BadKeyFile)?,
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        raw.as_slice()
            .try_into()
            .map_err(|_| ApprovalError::BadKeyFile)?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

/// A public key as text (base64url, 43 characters).
#[must_use]
pub fn public_key_text(key: &VerifyingKey) -> String {
    B64.encode(key.as_bytes())
}

/// Reads a public key text.
///
/// # Errors
///
/// [`ApprovalError::Malformed`].
pub fn parse_public_key(text: &str) -> Result<[u8; 32], ApprovalError> {
    let raw = B64
        .decode(text.trim())
        .map_err(|_| ApprovalError::Malformed)?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| ApprovalError::Malformed)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ApprovalError::Malformed)?;
    Ok(bytes)
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

/// Checks a token: the signature with `key`, the change it approves, and its
/// times against `now` (Unix seconds).
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
    now: u64,
) -> Result<Approval, ApprovalError> {
    let (signed, approval, sig) = split(token)?;
    let vk = VerifyingKey::from_bytes(key).map_err(|_| ApprovalError::BadSignature)?;
    vk.verify_strict(signed.as_bytes(), &sig)
        .map_err(|_| ApprovalError::BadSignature)?;
    if approval.kid != tutela_store::approver_id(key) {
        return Err(ApprovalError::BadSignature);
    }
    if approval.app != app || approval.from != from || approval.to != to {
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

    const APP: &str = "crm";
    const FROM: &str = NO_MANIFEST;
    const TO: &str = "aa";

    fn approval(kid: &str) -> Approval {
        Approval {
            app: APP.into(),
            from: FROM.into(),
            to: TO.into(),
            kid: kid.into(),
            iat: 1_000,
            exp: 4_600,
        }
    }

    fn key() -> (SigningKey, [u8; 32], String) {
        let k = generate().unwrap();
        let pk = k.verifying_key().to_bytes();
        let kid = tutela_store::approver_id(&pk);
        (k, pk, kid)
    }

    #[test]
    fn a_token_approves_exactly_its_change_until_it_expires() {
        let (k, pk, kid) = key();
        let t = mint(&k, &approval(&kid)).unwrap();
        assert!(t.starts_with("tutela-approval-v1."));
        assert_eq!(
            verify(&t, &pk, APP, FROM, TO, 2_000).unwrap(),
            approval(&kid)
        );
        assert_eq!(peek(&t).unwrap().kid, kid);
        for (app, from, to) in [("other", FROM, TO), (APP, "bb", TO), (APP, FROM, "bb")] {
            assert_eq!(
                verify(&t, &pk, app, from, to, 2_000),
                Err(ApprovalError::OtherChange)
            );
        }
        assert_eq!(
            verify(&t, &pk, APP, FROM, TO, 4_600),
            Err(ApprovalError::Expired)
        );
        // Issued more than 5 minutes in the future.
        assert_eq!(
            verify(&t, &pk, APP, FROM, TO, 600),
            Err(ApprovalError::Expired)
        );
    }

    #[test]
    fn another_key_or_a_changed_token_is_refused() {
        let (k, _, kid) = key();
        let (_, other_pk, _) = key();
        let t = mint(&k, &approval(&kid)).unwrap();
        assert_eq!(
            verify(&t, &other_pk, APP, FROM, TO, 2_000),
            Err(ApprovalError::BadSignature)
        );
        // A payload changed after signing (a later expiry).
        let mut longer = approval(&kid);
        longer.exp = 5_000;
        let forged = {
            let good = mint(&k, &approval(&kid)).unwrap();
            let sig = good.rsplit_once('.').unwrap().1.to_owned();
            let payload = B64.encode(serde_json::to_vec(&longer).unwrap());
            format!("{PREFIX}.{payload}.{sig}")
        };
        let (_, pk) = (0, k.verifying_key().to_bytes());
        assert_eq!(
            verify(&forged, &pk, APP, FROM, TO, 2_000),
            Err(ApprovalError::BadSignature)
        );
        // A token whose kid is not the signing key's id.
        let wrong = mint(&k, &approval("apk_00000000000000000000000000000000")).unwrap();
        assert_eq!(
            verify(&wrong, &pk, APP, FROM, TO, 2_000),
            Err(ApprovalError::BadSignature)
        );
        for bad in [
            "",
            "x",
            "tutela-approval-v1.e30",
            "other.e30.AAAA",
            &format!("{t}.x"),
        ] {
            assert_eq!(peek(bad), Err(ApprovalError::Malformed), "{bad}");
        }
    }

    #[test]
    fn tokens_live_at_most_a_day() {
        let (k, _, kid) = key();
        let mut a = approval(&kid);
        a.exp = a.iat + MAX_LIFETIME_SECS + 1;
        assert_eq!(mint(&k, &a), Err(ApprovalError::Expired));
        a.exp = a.iat;
        assert_eq!(mint(&k, &a), Err(ApprovalError::Expired));
    }

    #[test]
    fn key_files_round_trip_and_strangers_are_refused() {
        let k = generate().unwrap();
        let text = key_file_text(&k);
        let back = parse_key_file(&text).unwrap();
        assert_eq!(back.to_bytes(), k.to_bytes());
        for bad in [
            "",
            "tutela-approver-key-v1\n",
            "other\nAAAA\n",
            "tutela-approver-key-v1\nAAAA\n",
        ] {
            assert!(parse_key_file(bad).is_err(), "{bad:?}");
        }
        let pk = public_key_text(&k.verifying_key());
        assert_eq!(parse_public_key(&pk).unwrap(), k.verifying_key().to_bytes());
        assert!(parse_public_key("not a key").is_err());
    }
}
