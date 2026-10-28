//! JSON Web Keys: parsing, the RFC 7638 thumbprint, signature checks, and
//! the per-issuer cache with its refetch rules (CONTRACTS.md 4.1,
//! THREAT-MODEL.md TM-15).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use tokio::sync::Mutex;

/// The signature algorithms Tutela accepts (CONTRACTS.md 4.1). `none` and
/// the `HS*` family never.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256 (the default).
    Es256,
    /// RSASSA-PKCS1-v1_5 with SHA-256, keys of 2048 bits or more.
    Rs256,
    /// Ed25519.
    EdDsa,
}

impl Alg {
    /// From the JOSE name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::Es256),
            "RS256" => Some(Self::Rs256),
            "EdDSA" => Some(Self::EdDsa),
            _ => None,
        }
    }

    /// The JOSE name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// A public key from a JWKS.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Key {
    /// P-256: the uncompressed point (65 bytes).
    P256 {
        point: Vec<u8>,
        x: String,
        y: String,
    },
    /// RSA: modulus and exponent, big-endian.
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
        n_b64: String,
        e_b64: String,
    },
    /// Ed25519: 32 bytes.
    Ed25519 { x: Vec<u8>, x_b64: String },
}

impl Key {
    /// The algorithm this key may verify.
    const fn alg(&self) -> Alg {
        match self {
            Self::P256 { .. } => Alg::Es256,
            Self::Rsa { .. } => Alg::Rs256,
            Self::Ed25519 { .. } => Alg::EdDsa,
        }
    }

    /// The RFC 7638 thumbprint: SHA-256 of the required members in
    /// lexicographic order, base64url.
    pub(crate) fn thumbprint(&self) -> String {
        let json = match self {
            Self::P256 { x, y, .. } => {
                format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            Self::Rsa { n_b64, e_b64, .. } => {
                format!(r#"{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}"#)
            }
            Self::Ed25519 { x_b64, .. } => {
                format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#)
            }
        };
        B64.encode(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            json.as_bytes(),
        ))
    }

    /// Checks `signature` over `message` with this key and `alg`. A key of
    /// another type never verifies (no algorithm confusion).
    pub(crate) fn verify(&self, alg: Alg, message: &[u8], signature: &[u8]) -> bool {
        if alg != self.alg() {
            return false;
        }
        match self {
            Self::P256 { point, .. } => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .is_ok(),
            Self::Ed25519 { x, .. } => UnparsedPublicKey::new(&ED25519, x)
                .verify(message, signature)
                .is_ok(),
            Self::Rsa { n, e, .. } => RsaPublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
        }
    }
}

#[derive(Deserialize)]
struct RawJwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

fn b64(s: Option<&String>) -> Option<Vec<u8>> {
    B64.decode(s?.as_bytes()).ok()
}

impl RawJwk {
    /// The key, or `None` for one that is not for signing, has no `kid`, or
    /// has a type, curve or size Tutela does not accept.
    fn key(&self) -> Option<(String, Key)> {
        let kid = self
            .kid
            .clone()
            .filter(|k| !k.is_empty() && k.len() <= 256)?;
        if self.use_.as_deref().is_some_and(|u| u != "sig") {
            return None;
        }
        let key = match (self.kty.as_str(), self.crv.as_deref()) {
            ("EC", Some("P-256")) => {
                let (xb, yb) = (b64(self.x.as_ref())?, b64(self.y.as_ref())?);
                if xb.len() != 32 || yb.len() != 32 {
                    return None;
                }
                let mut point = vec![0x04];
                point.extend_from_slice(&xb);
                point.extend_from_slice(&yb);
                Key::P256 {
                    point,
                    x: self.x.clone()?,
                    y: self.y.clone()?,
                }
            }
            ("OKP", Some("Ed25519")) => {
                let x = b64(self.x.as_ref())?;
                if x.len() != 32 {
                    return None;
                }
                Key::Ed25519 {
                    x,
                    x_b64: self.x.clone()?,
                }
            }
            ("RSA", None) => {
                let (n, e) = (b64(self.n.as_ref())?, b64(self.e.as_ref())?);
                if n.len() < 256 {
                    return None;
                }
                Key::Rsa {
                    n,
                    e,
                    n_b64: self.n.clone()?,
                    e_b64: self.e.clone()?,
                }
            }
            _ => return None,
        };
        if self
            .alg
            .as_deref()
            .is_some_and(|a| Alg::parse(a) != Some(key.alg()))
        {
            return None;
        }
        Some((kid, key))
    }
}

/// Parses a JWKS document. Keys Tutela does not accept are skipped; two
/// keys with one `kid` make the whole set invalid.
pub(crate) fn parse_jwks(body: &[u8]) -> Option<HashMap<String, Key>> {
    let raw: RawJwks = serde_json::from_slice(body).ok()?;
    let mut out = HashMap::new();
    for jwk in &raw.keys {
        if let Some((kid, key)) = jwk.key()
            && out.insert(kid, key).is_some()
        {
            return None;
        }
    }
    Some(out)
}

/// Where JWKS documents come from: `tutela-safenet` in production.
pub trait JwksSource: Send + Sync + 'static {
    /// The body of the document at `url`, or `None` when it cannot be
    /// fetched (any failure: refused URL, network, status, size).
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;
}

/// Fetches JWKS documents through `tutela-safenet` (https only, public
/// addresses only, no redirects, 64 KiB at most).
#[derive(Clone, Debug)]
pub struct SafenetSource {
    client: tutela_safenet::Client,
}

impl SafenetSource {
    /// Over `policy` (its body limit is lowered to 64 KiB).
    ///
    /// # Errors
    ///
    /// When the TLS setup fails.
    pub fn new(policy: tutela_safenet::Policy) -> Result<Self, tutela_safenet::SafenetError> {
        Ok(Self {
            client: tutela_safenet::Client::new(policy.max_body(64 * 1024))?,
        })
    }
}

impl JwksSource for SafenetSource {
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            client
                .get(&url)
                .await
                .ok()
                .filter(tutela_safenet::Response::is_success)
                .map(|r| r.body)
        })
    }
}

/// The cached keys of one issuer.
struct Cached {
    keys: HashMap<String, Key>,
    /// When `keys` were fetched.
    fetched_at: u64,
}

/// When the cache refreshes, refetches and gives up.
#[derive(Clone, Copy, Debug)]
pub struct CacheRules {
    /// Refresh the keys after this many seconds.
    pub ttl: u64,
    /// At most one fetch per issuer in this many seconds (an unknown `kid`
    /// cannot cause fetch storms).
    pub min_refetch: u64,
    /// If refreshing fails, keep using the cached keys until they are this
    /// old; then every token of the issuer fails.
    pub max_stale: u64,
}

impl Default for CacheRules {
    fn default() -> Self {
        Self {
            ttl: 300,
            min_refetch: 30,
            max_stale: 3600,
        }
    }
}

/// One issuer's slot: its cached keys, and when a fetch was last tried.
type Slot = (Option<Cached>, Option<u64>);

/// Per-issuer keys with the refetch rules.
pub(crate) struct KeyCache {
    source: Arc<dyn JwksSource>,
    rules: CacheRules,
    state: Mutex<HashMap<String, Slot>>,
}

impl KeyCache {
    pub(crate) fn new(source: Arc<dyn JwksSource>, rules: CacheRules) -> Self {
        Self {
            source,
            rules,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// The key `kid` of the issuer whose JWKS is at `url`, at time `now`.
    pub(crate) async fn key(&self, url: &str, kid: &str, now: u64) -> Option<Key> {
        let mut state = self.state.lock().await;
        let (cached, last_try) = state.entry(url.to_owned()).or_insert((None, None));
        let fresh = cached
            .as_ref()
            .is_some_and(|c| now.saturating_sub(c.fetched_at) < self.rules.ttl);
        let known = cached.as_ref().and_then(|c| c.keys.get(kid)).cloned();
        if fresh && known.is_some() {
            return known;
        }
        let may_fetch = last_try.is_none_or(|t| now.saturating_sub(t) >= self.rules.min_refetch);
        if may_fetch {
            *last_try = Some(now);
            if let Some(keys) = self
                .source
                .fetch(url.to_owned())
                .await
                .and_then(|b| parse_jwks(&b))
            {
                let key = keys.get(kid).cloned();
                *cached = Some(Cached {
                    keys,
                    fetched_at: now,
                });
                return key;
            }
        }
        // Not refreshed (failed or rate limited): use the cached key while it
        // is not too old.
        let usable = cached
            .as_ref()
            .is_some_and(|c| now.saturating_sub(c.fetched_at) < self.rules.max_stale);
        if usable { known } else { None }
    }
}
