//! Apps: their client secrets, and client authentication at the token
//! endpoint (ADR-0044, CONTRACTS.md 4.9, 5).
//!
//! An app belongs to one tenant. Its client id is `app_<uuidv7>`; its
//! principal is a service account of the tenant, which holds only what
//! ordinary assignments give it. A client secret is an API key of
//! CONTRACTS.md 5 (`tut_sk_<prefix>_<secret>`), shown once and stored as
//! SHA-256(pepper ‖ key) with the pepper's version (`TUTELA_KEY_PEPPER`):
//! never in plain text, never sealed, never derived from the master key.
//!
//! A client authenticates with HTTP Basic (`client_secret_basic`) or with
//! `client_id` and `client_secret` in the form (`client_secret_post`), never
//! both (RFC 6749 2.3.1). A bad id or secret is `invalid_client`, with one
//! text, after a hash computed either way, so the time says nothing of
//! which check failed (CONTRACTS.md 5.6).

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use tutela_contracts::apikey::{ApiKey, ApiKeyKind};
use tutela_contracts::tenant::TenantKey;
use tutela_store::{AppInfo, SecretHash};
use zeroize::Zeroizing;

use crate::api::AppState;
use crate::exchange::Refusal;
use crate::tenant::Tenant;

/// `TUTELA_KEY_PEPPER` and its version. `Debug` shows the version only.
pub struct Pepper {
    /// The pepper's bytes.
    pub bytes: Zeroizing<Vec<u8>>,
    /// `TUTELA_KEY_PEPPER_VERSION`.
    pub version: u32,
}

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pepper")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Pepper {
    /// The pepper of the service's secrets.
    #[must_use]
    pub fn of(secrets: &crate::config::Secrets) -> Self {
        let (bytes, version) = secrets.pepper();
        Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            version,
        }
    }
}

/// The default overlap of a rotation: the old secret keeps working this
/// long, in seconds.
pub const DEFAULT_OVERLAP_SECS: u64 = 3600;

/// The longest overlap of a rotation, in seconds (7 days).
pub const MAX_OVERLAP_SECS: u64 = 604_800;

/// A client id: `app_<uuidv7>`.
#[must_use]
pub fn is_client_id(s: &str) -> bool {
    s.strip_prefix("app_")
        .is_some_and(|u| tutela_contracts::id::Uuid7::parse(u).is_ok())
}

/// SHA-256(pepper ‖ key), lowercase hex (CONTRACTS.md 5.4).
#[must_use]
pub fn hash(pepper: &[u8], key: &str) -> String {
    let mut input = Zeroizing::new(Vec::with_capacity(pepper.len() + key.len()));
    input.extend_from_slice(pepper);
    input.extend_from_slice(key.as_bytes());
    let d = digest(&SHA256, &input);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a secret could not be made.
#[derive(Debug, thiserror::Error)]
#[error("a client secret could not be made")]
pub struct SecretError;

/// A new client secret, and what is stored of it. The secret is shown once,
/// to whoever asked; only the hash is kept.
///
/// # Errors
///
/// [`SecretError`] when the system's random source fails.
pub fn new_secret(
    pepper: &[u8],
    version: u32,
) -> Result<(Zeroizing<String>, SecretHash), SecretError> {
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let rng = SystemRandom::new();
    let mut raw = Zeroizing::new([0u8; 32]);
    rng.fill(raw.as_mut()).map_err(|_| SecretError)?;
    // 8 characters of a-z0-9, without a modulo bias: 252 is 7 × 36.
    let mut prefix = String::with_capacity(8);
    while prefix.len() < 8 {
        let mut b = [0u8; 16];
        rng.fill(&mut b).map_err(|_| SecretError)?;
        for x in b.iter().filter(|x| **x < 252) {
            if prefix.len() < 8 {
                prefix.push(char::from(ALPHABET[usize::from(*x % 36)]));
            }
        }
    }
    let secret = Zeroizing::new(format!(
        "tut_sk_{prefix}_{}",
        URL_SAFE_NO_PAD.encode(raw.as_ref())
    ));
    // The format of CONTRACTS.md 5.1, checked as a verifier will.
    ApiKey::parse(&secret).map_err(|_| SecretError)?;
    let id =
        tutela_contracts::id::Uuid7::from_uuid(uuid::Uuid::now_v7()).map_err(|_| SecretError)?;
    Ok((
        Zeroizing::new(secret.to_string()),
        SecretHash {
            key_id: format!("key_{id}"),
            prefix,
            hash: hash(pepper, &secret),
            pepper_version: version,
        },
    ))
}

/// The client credentials of a token request. No `Debug`: it holds a secret.
pub struct Credentials {
    /// The client id.
    pub id: String,
    /// The client secret.
    pub secret: Zeroizing<String>,
}

/// The credentials of `Authorization: Basic`, when the header is there.
/// The id and the secret of an app hold no character that needs the form
/// encoding of RFC 6749 2.3.1, so one that has `%` or `+` is refused.
///
/// # Errors
///
/// `invalid_client` for a header that does not parse.
pub fn basic(headers: &HeaderMap) -> Result<Option<Credentials>, Refusal> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let bad = || Refusal::client("basic");
    let text = value.to_str().map_err(|_| bad())?;
    let Some(b64) = text
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .map(|(_, rest)| rest.trim())
    else {
        return Err(bad());
    };
    let decoded = Zeroizing::new(STANDARD.decode(b64).map_err(|_| bad())?);
    let text = std::str::from_utf8(&decoded).map_err(|_| bad())?;
    let (id, secret) = text.split_once(':').ok_or_else(bad)?;
    if [id, secret].iter().any(|s| s.contains(['%', '+'])) {
        return Err(bad());
    }
    Ok(Some(Credentials {
        id: id.to_owned(),
        secret: Zeroizing::new(secret.to_owned()),
    }))
}

/// An app that authenticated, in its tenant.
pub struct Client {
    /// Its tenant, from the directory.
    pub tenant: Tenant,
    /// The app.
    pub app: AppInfo,
}

/// The app `creds` authenticate. Every failure is the same
/// `invalid_client`, after a hash: the reason goes to the log only.
///
/// # Errors
///
/// `invalid_client`, or `temporarily_unavailable` when the database fails.
pub async fn authenticate(state: &AppState, creds: &Credentials) -> Result<Client, Refusal> {
    let (pepper, version) = state.pepper();
    let key = ApiKey::parse(&creds.secret)
        .ok()
        .filter(|k| k.kind() == ApiKeyKind::Sk);
    // The hash is computed on every path, so a miss costs what a match does.
    let computed = hash(pepper, &creds.secret);
    let fail = |reason| Err(Refusal::client(reason));
    let Some(key) = key else {
        return fail("secret_format");
    };
    if !is_client_id(&creds.id) {
        return fail("client_id");
    }
    let mut conn = state.db.conn().await?;
    let Some(found) = conn.app_tenant(&creds.id).await? else {
        return fail("unknown_client");
    };
    if found.iss != *state.keys.iss() {
        return fail("client_issuer");
    }
    let tenant = Tenant::of_app(found);
    let tx = conn.begin(&tenant).await?;
    let secret = tutela_store::app_secret(&tx, tenant.key(), key.prefix().as_str()).await?;
    let app = tutela_store::app(&tx, tenant.key(), &creds.id).await?;
    tx.commit().await?;
    let Some(secret) = secret else {
        return fail("unknown_secret");
    };
    if secret.app_id != creds.id {
        return fail("other_app");
    }
    if secret.hash.pepper_version != version {
        tracing::warn!(
            stored = secret.hash.pepper_version,
            current = version,
            "a client secret was hashed with another pepper; rotate it"
        );
        return fail("pepper_version");
    }
    if verify_slices_are_equal(secret.hash.hash.as_bytes(), computed.as_bytes()).is_err() {
        return fail("secret");
    }
    match app {
        Some(app) if app.disabled_at.is_none() => Ok(Client { tenant, app }),
        _ => fail("disabled"),
    }
}

/// `true` when `id` names an app of `tenant`.
///
/// # Errors
///
/// A database error.
pub(crate) async fn registered(
    tx: &crate::db::TenantTx<'_>,
    tenant: &TenantKey,
    id: &str,
) -> Result<bool, tutela_store::StoreError> {
    if !is_client_id(id) {
        return Ok(false);
    }
    Ok(tutela_store::app(tx, tenant, id).await?.is_some())
}
