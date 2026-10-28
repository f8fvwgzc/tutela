//! Envelope encryption for Tutela's stored secrets (`tutela-vault`), Phase A.
//! Ported from the design of onto-intelli `crates/onto-control/src/vault.rs`
//! (MIT).
//!
//! Each secret gets its own random 256-bit data key (DEK). The secret is
//! sealed with AES-256-GCM under the DEK, and the DEK is wrapped by a
//! [`Kms`]: [`LocalKms`] (a master key from `TUTELA_MASTER_KEY`) or a
//! production KMS behind the same trait.
//!
//! ```text
//! blob = 0x01                         version
//!      ‖ key_id[8]                    the key that wrapped the DEK
//!      ‖ wlen[2] ‖ wrapped[wlen]      the wrapped DEK (big-endian length)
//!      ‖ nonce[12] ‖ AES-256-GCM(DEK, secret) ‖ tag[16]
//! ```
//!
//! Both the wrap and the seal are bound to a **purpose** (for example
//! `webhook_secret`) and a **context** (for example the tenant and the row
//! id) in the associated data, each length-prefixed, so no two inputs give
//! the same bytes. A blob opens only with its own purpose and context.
//!
//! Rotation (CONTRACTS.md 10): set the new `TUTELA_MASTER_KEY` and move the
//! old one to `TUTELA_MASTER_KEY_PREVIOUS`. Blobs under either key open;
//! new blobs use the new key; [`Vault::rewrap`] moves an old blob to the new
//! key without touching the secret's ciphertext.

use std::fmt;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

/// The envelope version this build writes.
pub const VERSION: u8 = 0x01;
/// The current master key.
pub const MASTER_KEY_ENV: &str = "TUTELA_MASTER_KEY";
/// The previous master key, during a rotation.
pub const MASTER_KEY_PREVIOUS_ENV: &str = "TUTELA_MASTER_KEY_PREVIOUS";
/// The longest context.
pub const MAX_CONTEXT: usize = 4096;

const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KEY_ID_LEN: usize = 8;
const DOMAIN: &[u8] = b"tutela-vault/v1";

/// Why sealing or opening failed. The texts name key ids only, never keys
/// or secrets.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// `TUTELA_MASTER_KEY` is not set. Tutela never makes one up.
    #[error("TUTELA_MASTER_KEY is not set; refusing to seal or open secrets")]
    NoMasterKey,
    /// A master key that is not 32 bytes.
    #[error("{0} must be 32 bytes, as base64 or 64 hex digits")]
    BadMasterKey(&'static str),
    /// A purpose that breaks the rule.
    #[error("a purpose is 1 to 64 characters of a-z, 0-9, `_`, `.` or `-`")]
    BadPurpose,
    /// A context over [`MAX_CONTEXT`] bytes.
    #[error("a context is at most 4096 bytes")]
    ContextTooLong,
    /// Not a version 1 envelope.
    #[error("the blob is not a version 1 envelope")]
    Malformed,
    /// The DEK was wrapped by a key this vault does not have.
    #[error("the blob's data key was wrapped by key {0}, which this vault does not have")]
    UnknownKey(KeyId),
    /// It does not authenticate: altered, or another purpose or context.
    #[error("the blob does not decrypt (altered, or sealed for another purpose or context)")]
    Decrypt,
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
    /// An AES-256-GCM operation failed (a size over its limits).
    #[error("the AES-256-GCM operation failed")]
    Crypto,
    /// A KMS backend failed.
    #[error("the KMS failed: {0}")]
    Kms(String),
}

/// The id of a key-encryption key: the first 8 bytes of SHA-256 of the key
/// for [`LocalKms`]; any stable 8 bytes for another backend.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub [u8; KEY_ID_LEN]);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

/// Wraps and unwraps data keys. [`LocalKms`] in development and small
/// self-hosts; a cloud KMS or an HSM in production, where the key-encryption
/// key never leaves the device. A backend that calls a network service
/// blocks in these calls; run them where blocking is allowed.
pub trait Kms: Send + Sync {
    /// The key that new data keys are wrapped with.
    fn current(&self) -> KeyId;

    /// Wraps `dek` under [`Kms::current`], bound to `aad`.
    ///
    /// # Errors
    ///
    /// The backend's error.
    fn wrap(&self, dek: &[u8; KEY_LEN], aad: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// Unwraps a data key that `key` wrapped, bound to `aad`.
    ///
    /// # Errors
    ///
    /// [`VaultError::UnknownKey`] for a key the backend does not have,
    /// [`VaultError::Decrypt`] if it does not authenticate.
    fn unwrap(
        &self,
        key: KeyId,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError>;
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, VaultError> {
    let mut buf = Zeroizing::new([0u8; N]);
    SystemRandom::new()
        .fill(buf.as_mut())
        .map_err(|_| VaultError::Random)?;
    Ok(buf)
}

fn aes(key: &[u8; KEY_LEN]) -> Result<LessSafeKey, VaultError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| VaultError::Crypto)
}

/// `nonce ‖ ciphertext ‖ tag`.
fn seal(key: &[u8; KEY_LEN], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, VaultError> {
    let nonce = random::<NONCE_LEN>()?;
    let mut buf = plain.to_vec();
    aes(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| VaultError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(nonce.as_ref());
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::Malformed);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| VaultError::Malformed)?;
    let mut buf = Zeroizing::new(ct.to_vec());
    let n = aes(key)?
        .open_in_place(nonce, Aad::from(aad), buf.as_mut())
        .map_err(|_| VaultError::Decrypt)?
        .len();
    buf.truncate(n);
    Ok(buf)
}

/// One key-encryption key of [`LocalKms`].
struct Kek {
    id: KeyId,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl Kek {
    fn new(key: [u8; KEY_LEN]) -> Self {
        let key = Zeroizing::new(key);
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key.as_ref());
        let mut id = [0u8; KEY_ID_LEN];
        for (slot, b) in id.iter_mut().zip(d.as_ref()) {
            *slot = *b;
        }
        Self { id: KeyId(id), key }
    }
}

/// The master key from the environment: `TUTELA_MASTER_KEY` wraps new data
/// keys; `TUTELA_MASTER_KEY_PREVIOUS`, during a rotation, still unwraps old
/// ones.
pub struct LocalKms {
    current: Kek,
    previous: Option<Kek>,
}

impl fmt::Debug for LocalKms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalKms")
            .field("current", &self.current.id)
            .field("previous", &self.previous.as_ref().map(|k| k.id))
            .finish()
    }
}

impl LocalKms {
    /// From raw 32-byte keys. A previous key equal to the current one is
    /// dropped.
    #[must_use]
    pub fn new(current: [u8; KEY_LEN], previous: Option<[u8; KEY_LEN]>) -> Self {
        let current = Kek::new(current);
        let previous = previous.map(Kek::new).filter(|p| p.id != current.id);
        Self { current, previous }
    }

    /// From `TUTELA_MASTER_KEY` and `TUTELA_MASTER_KEY_PREVIOUS`.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoMasterKey`] when `TUTELA_MASTER_KEY` is unset or
    /// empty, [`VaultError::BadMasterKey`] for a key that is not 32 bytes.
    pub fn from_env() -> Result<Self, VaultError> {
        let current = std::env::var(MASTER_KEY_ENV).ok().map(Zeroizing::new);
        let previous = std::env::var(MASTER_KEY_PREVIOUS_ENV)
            .ok()
            .map(Zeroizing::new);
        Self::from_values(
            current.as_ref().map(|s| s.as_str()),
            previous.as_ref().map(|s| s.as_str()),
        )
    }

    /// From the text of the two keys (base64 or 64 hex digits each).
    ///
    /// # Errors
    ///
    /// As [`LocalKms::from_env`].
    pub fn from_values(current: Option<&str>, previous: Option<&str>) -> Result<Self, VaultError> {
        fn present(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|v| !v.is_empty())
        }
        let current = present(current).ok_or(VaultError::NoMasterKey)?;
        let current = parse_key(current).ok_or(VaultError::BadMasterKey(MASTER_KEY_ENV))?;
        let previous = present(previous)
            .map(|p| parse_key(p).ok_or(VaultError::BadMasterKey(MASTER_KEY_PREVIOUS_ENV)))
            .transpose()?;
        Ok(Self::new(*current, previous.map(|p| *p)))
    }

    fn kek(&self, id: KeyId) -> Result<&Kek, VaultError> {
        [Some(&self.current), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|k| k.id == id)
            .ok_or(VaultError::UnknownKey(id))
    }
}

impl Kms for LocalKms {
    fn current(&self) -> KeyId {
        self.current.id
    }

    fn wrap(&self, dek: &[u8; KEY_LEN], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        seal(&self.current.key, aad, dek)
    }

    fn unwrap(
        &self,
        key: KeyId,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let plain = open(&self.kek(key)?.key, aad, wrapped)?;
        let mut dek = Zeroizing::new([0u8; KEY_LEN]);
        if plain.len() != KEY_LEN {
            return Err(VaultError::Decrypt);
        }
        dek.copy_from_slice(&plain);
        Ok(dek)
    }
}

/// A 32-byte key from 64 hex digits or base64 (standard or URL-safe, with
/// or without padding).
fn parse_key(v: &str) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    if v.len() == 2 * KEY_LEN && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(v.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        return Some(out);
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(raw) = engine.decode(v).map(Zeroizing::new)
            && raw.len() == KEY_LEN
        {
            out.copy_from_slice(&raw);
            return Some(out);
        }
    }
    None
}

/// The associated data: the domain, the role (`k` for the wrapped key, `d`
/// for the data), then the purpose and the context, each length-prefixed.
fn binding(role: u8, purpose: &str, context: &[u8]) -> Result<Vec<u8>, VaultError> {
    let ok = !purpose.is_empty()
        && purpose.len() <= 64
        && purpose.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        });
    if !ok {
        return Err(VaultError::BadPurpose);
    }
    if context.len() > MAX_CONTEXT {
        return Err(VaultError::ContextTooLong);
    }
    let plen = u16::try_from(purpose.len()).map_err(|_| VaultError::BadPurpose)?;
    let clen = u32::try_from(context.len()).map_err(|_| VaultError::ContextTooLong)?;
    let mut aad = Vec::with_capacity(DOMAIN.len() + 7 + purpose.len() + context.len());
    aad.extend_from_slice(DOMAIN);
    aad.push(role);
    aad.extend_from_slice(&plen.to_be_bytes());
    aad.extend_from_slice(purpose.as_bytes());
    aad.extend_from_slice(&clen.to_be_bytes());
    aad.extend_from_slice(context);
    Ok(aad)
}

/// The parts of a blob.
struct Parts<'a> {
    key: KeyId,
    wrapped: &'a [u8],
    data: &'a [u8],
}

fn parts(blob: &[u8]) -> Result<Parts<'_>, VaultError> {
    let (&version, rest) = blob.split_first().ok_or(VaultError::Malformed)?;
    if version != VERSION {
        return Err(VaultError::Malformed);
    }
    let (id, rest) = rest
        .split_at_checked(KEY_ID_LEN)
        .ok_or(VaultError::Malformed)?;
    let (len, rest) = rest.split_at_checked(2).ok_or(VaultError::Malformed)?;
    let len = usize::from(u16::from_be_bytes([
        *len.first().ok_or(VaultError::Malformed)?,
        *len.get(1).ok_or(VaultError::Malformed)?,
    ]));
    let (wrapped, data) = rest.split_at_checked(len).ok_or(VaultError::Malformed)?;
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::Malformed);
    }
    let mut key = [0u8; KEY_ID_LEN];
    key.copy_from_slice(id);
    Ok(Parts {
        key: KeyId(key),
        wrapped,
        data,
    })
}

fn header(key: KeyId, wrapped: &[u8]) -> Result<Vec<u8>, VaultError> {
    let len = u16::try_from(wrapped.len())
        .map_err(|_| VaultError::Kms("wrapped key over 64 KiB".into()))?;
    let mut out = Vec::with_capacity(1 + KEY_ID_LEN + 2 + wrapped.len());
    out.push(VERSION);
    out.extend_from_slice(&key.0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(wrapped);
    Ok(out)
}

/// Seals and opens secrets with a [`Kms`].
#[derive(Debug)]
pub struct Vault<K: Kms = LocalKms> {
    kms: K,
}

impl Vault<LocalKms> {
    /// A vault over the master key in the environment.
    ///
    /// # Errors
    ///
    /// As [`LocalKms::from_env`].
    pub fn from_env() -> Result<Self, VaultError> {
        LocalKms::from_env().map(Self::new)
    }
}

impl<K: Kms> Vault<K> {
    /// A vault over `kms`.
    pub const fn new(kms: K) -> Self {
        Self { kms }
    }

    /// The key new blobs are wrapped with.
    pub fn current_key(&self) -> KeyId {
        self.kms.current()
    }

    /// The key that wrapped this blob's data key.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`].
    pub fn key_of(&self, blob: &[u8]) -> Result<KeyId, VaultError> {
        parts(blob).map(|p| p.key)
    }

    /// Seals `secret` for `purpose` and `context` under the current key.
    ///
    /// # Errors
    ///
    /// [`VaultError::BadPurpose`], [`VaultError::ContextTooLong`], or a KMS
    /// or random-source error.
    pub fn seal(
        &self,
        purpose: &str,
        context: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let dek = random::<KEY_LEN>()?;
        let wrapped = self.kms.wrap(&dek, &binding(b'k', purpose, context)?)?;
        let mut blob = header(self.kms.current(), &wrapped)?;
        blob.extend_from_slice(&seal(&dek, &binding(b'd', purpose, context)?, secret)?);
        Ok(blob)
    }

    /// Opens a blob sealed for `purpose` and `context`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`], [`VaultError::UnknownKey`], or
    /// [`VaultError::Decrypt`] for an altered blob or another purpose or
    /// context.
    pub fn open(
        &self,
        purpose: &str,
        context: &[u8],
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let p = parts(blob)?;
        let dek = self
            .kms
            .unwrap(p.key, p.wrapped, &binding(b'k', purpose, context)?)?;
        open(&dek, &binding(b'd', purpose, context)?, p.data)
    }

    /// The blob with its data key wrapped under the current key; the
    /// secret's ciphertext is kept as it is. `None` when it already is.
    ///
    /// # Errors
    ///
    /// As [`Vault::open`].
    pub fn rewrap(
        &self,
        purpose: &str,
        context: &[u8],
        blob: &[u8],
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let p = parts(blob)?;
        if p.key == self.kms.current() {
            return Ok(None);
        }
        let aad = binding(b'k', purpose, context)?;
        let dek = self.kms.unwrap(p.key, p.wrapped, &aad)?;
        // The data must still open with this data key before it is kept.
        open(&dek, &binding(b'd', purpose, context)?, p.data)?;
        let wrapped = self.kms.wrap(&dek, &aad)?;
        let mut out = header(self.kms.current(), &wrapped)?;
        out.extend_from_slice(p.data);
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests;
