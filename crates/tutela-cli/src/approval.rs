//! Approval tokens for widening model changes in library mode (ADR-0015).
//! The token itself is `tutela_store::approval`. This module keeps what only
//! an approver's machine needs: the key files.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
pub use tutela_store::approval::{
    Approval, ApprovalError, MAX_LIFETIME_SECS, NO_MANIFEST, PREFIX, mint, peek,
};
use zeroize::Zeroizing;

/// The first line of a private key file.
pub const KEY_FILE_HEADER: &str = "tutela-approver-key-v1";

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

/// Checks a token for the app's manifest: one that names no tenant.
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
    tutela_store::approval::verify(token, key, app, from, to, None, now)
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
            tid: None,
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
