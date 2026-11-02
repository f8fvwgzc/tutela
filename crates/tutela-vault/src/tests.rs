use std::sync::Mutex;

use super::*;

fn vault(k: u8, prev: Option<u8>) -> Vault {
    Vault::new(LocalKms::new([k; 32], prev.map(|p| [p; 32])))
}

const P: &str = "webhook_secret";
const CTX: &[u8] = b"ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b/wh_1";

/// The kind of a failed call.
fn kind<T>(r: Result<T, VaultError>) -> Option<VaultErrorKind> {
    r.err().map(|e| e.kind())
}

#[test]
fn a_secret_round_trips_and_opens_only_for_its_purpose_and_context() {
    let v = vault(1, None);
    let blob = v.seal(P, CTX, b"whsec_123").unwrap();
    assert_eq!(blob[0], VERSION);
    assert_eq!(v.key_of(&blob).unwrap(), v.current_key());
    assert_eq!(v.open(P, CTX, &blob).unwrap().as_slice(), b"whsec_123");
    // Two seals of one secret differ (fresh data key and nonces).
    assert_ne!(v.seal(P, CTX, b"whsec_123").unwrap(), blob);
    assert_eq!(
        kind(v.open("other_purpose", CTX, &blob)),
        Some(VaultErrorKind::Decrypt)
    );
    assert_eq!(
        kind(v.open(P, b"ten_other/wh_1", &blob)),
        Some(VaultErrorKind::Decrypt)
    );
    // Length prefixes: moving a byte between purpose and context fails.
    let a = v.seal("ab", b"c", b"x").unwrap();
    assert_eq!(kind(v.open("a", b"bc", &a)), Some(VaultErrorKind::Decrypt));
    // An empty secret is fine.
    let empty = v.seal(P, CTX, b"").unwrap();
    assert!(v.open(P, CTX, &empty).unwrap().is_empty());
}

#[test]
fn every_altered_byte_is_refused() {
    let v = vault(1, None);
    let blob = v.seal(P, CTX, b"whsec_123").unwrap();
    for i in 0..blob.len() {
        let mut bad = blob.clone();
        bad[i] ^= 0x40;
        assert!(v.open(P, CTX, &bad).is_err(), "byte {i}");
    }
    for n in [0, 1, 9, 11, 30, blob.len() - 1] {
        assert!(v.open(P, CTX, &blob[..n]).is_err(), "cut at {n}");
    }
    let mut longer = blob.clone();
    longer.push(0);
    assert!(v.open(P, CTX, &longer).is_err());
}

#[test]
fn tm15_rotation_keeps_old_blobs_open_and_rewraps_them() {
    let old = vault(1, None);
    let blob = old.seal(P, CTX, b"whsec_rotate").unwrap();
    let new = vault(2, Some(1));
    assert_eq!(new.open(P, CTX, &blob).unwrap().as_slice(), b"whsec_rotate");
    let rewrapped = new.rewrap(P, CTX, &blob).unwrap().unwrap();
    assert_eq!(new.key_of(&rewrapped).unwrap(), new.current_key());
    // The secret's ciphertext (the last part) is kept as it is.
    let tail = 12 + b"whsec_rotate".len() + 16;
    assert_eq!(
        rewrapped[rewrapped.len() - tail..],
        blob[blob.len() - tail..]
    );
    assert_eq!(new.rewrap(P, CTX, &rewrapped).unwrap(), None);
    // Without the previous key only the rewrapped blob opens, and the error
    // names the missing key.
    let only_new = vault(2, None);
    assert_eq!(
        only_new.open(P, CTX, &rewrapped).unwrap().as_slice(),
        b"whsec_rotate"
    );
    let e = only_new.open(P, CTX, &blob).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::UnknownKey);
    assert_eq!(e.key(), Some(old.current_key()));
    // A rewrap checks the binding too.
    assert!(new.rewrap("other_purpose", CTX, &blob).is_err());
    // The same key as current and previous counts once.
    let same = LocalKms::new([3; 32], Some([3; 32]));
    assert!(format!("{same:?}").contains("previous: None"));
}

#[test]
fn master_keys_come_from_the_environment_and_are_never_made_up() {
    assert_eq!(
        kind(LocalKms::from_values(None, Some("x"))),
        Some(VaultErrorKind::NoMasterKey)
    );
    assert_eq!(
        kind(LocalKms::from_values(Some("  "), None)),
        Some(VaultErrorKind::NoMasterKey)
    );
    let hex = "ab".repeat(32);
    let a = LocalKms::from_values(Some(&hex), None).unwrap();
    use base64::Engine as _;
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        let b = LocalKms::from_values(Some(&engine.encode([0xab; 32])), None).unwrap();
        assert_eq!(a.current(), b.current());
    }
    let bad = |current: &str, previous| {
        let e = LocalKms::from_values(Some(current), previous).unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::BadMasterKey);
        e.variable()
    };
    assert_eq!(bad("short", None), Some(MASTER_KEY_ENV));
    assert_eq!(bad(&hex, Some("bad")), Some(MASTER_KEY_PREVIOUS_ENV));
    // Debug shows key ids, never keys.
    let shown = format!("{a:?}");
    assert!(
        !shown.contains("ab, ab") && !shown.contains(&hex),
        "{shown}"
    );
}

#[test]
fn purposes_and_contexts_are_checked() {
    let v = vault(1, None);
    for bad in ["", "Upper", "a b", "x/y", &"a".repeat(65)] {
        assert_eq!(
            kind(v.seal(bad, CTX, b"s")),
            Some(VaultErrorKind::BadPurpose),
            "{bad:?}"
        );
    }
    assert_eq!(
        kind(v.seal(P, &vec![0; MAX_CONTEXT + 1], b"s")),
        Some(VaultErrorKind::ContextTooLong)
    );
    assert!(v.seal("a.b-c_9", &vec![0; MAX_CONTEXT], b"s").is_ok());
}

/// A KMS backend that keeps wrapped keys in memory and wraps by a XOR, to
/// show the trait is enough for another backend. Not secure; tests only.
struct FakeKms {
    calls: Mutex<usize>,
}

impl Kms for FakeKms {
    fn current(&self) -> KeyId {
        KeyId(*b"fake-kms")
    }
    fn wrap(&self, dek: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        *self.calls.lock().unwrap() += 1;
        let mut out: Vec<u8> = dek.iter().map(|b| b ^ 0x5a).collect();
        out.extend_from_slice(aad);
        Ok(out)
    }
    fn unwrap(
        &self,
        key: KeyId,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if key != self.current() {
            return Err(VaultError::unknown_key(key));
        }
        if wrapped.len() != 32 + aad.len() || &wrapped[32..] != aad {
            return Err(VaultError::decrypt());
        }
        let mut dek = Zeroizing::new([0u8; 32]);
        for (d, w) in dek.iter_mut().zip(wrapped) {
            *d = w ^ 0x5a;
        }
        Ok(dek)
    }
}

#[test]
fn another_kms_backend_works_through_the_trait() {
    let v = Vault::new(FakeKms {
        calls: Mutex::new(0),
    });
    let blob = v.seal(P, CTX, b"via kms").unwrap();
    assert_eq!(v.open(P, CTX, &blob).unwrap().as_slice(), b"via kms");
    assert_eq!(
        kind(v.open(P, b"other", &blob)),
        Some(VaultErrorKind::Decrypt)
    );
    assert_eq!(v.key_of(&blob).unwrap().to_string(), "66616b652d6b6d73");
}

/// A KMS whose backend fails, the way a cloud KMS does.
struct DownKms;

#[derive(Debug, thiserror::Error)]
#[error("the KMS endpoint refused the call")]
struct Down;

impl Kms for DownKms {
    fn current(&self) -> KeyId {
        KeyId(*b"down-kms")
    }
    fn wrap(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>, VaultError> {
        Err(VaultError::kms(Down))
    }
    fn unwrap(&self, _: KeyId, _: &[u8], _: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Err(VaultError::kms(Down))
    }
}

/// A backend's reason stays in `source()`; it is not flattened into text
/// (#43).
#[test]
fn a_kms_failure_keeps_its_cause_in_the_chain() {
    let e = Vault::new(DownKms).seal(P, CTX, b"s").unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Kms);
    assert_eq!(e.to_string(), "the KMS failed");
    let cause = std::error::Error::source(&e).unwrap();
    assert!(cause.is::<Down>());
    assert_eq!(cause.to_string(), "the KMS endpoint refused the call");
}

/// The envelope's two-byte length cannot hold a longer wrapped key.
#[test]
fn a_wrapped_key_over_the_envelope_limit_is_a_kms_failure() {
    struct Huge;
    impl Kms for Huge {
        fn current(&self) -> KeyId {
            KeyId(*b"hugekms!")
        }
        fn wrap(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>, VaultError> {
            Ok(vec![0; 70_000])
        }
        fn unwrap(&self, _: KeyId, _: &[u8], _: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
            Err(VaultError::decrypt())
        }
    }
    let e = Vault::new(Huge).seal(P, CTX, b"s").unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Kms);
    assert_eq!(
        std::error::Error::source(&e).unwrap().to_string(),
        "the wrapped key is over 64 KiB"
    );
}
