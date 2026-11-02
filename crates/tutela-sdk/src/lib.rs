//! Tutela's SDK for Rust services (`tutela-sdk`), Phase A: the token
//! verifier (CONTRACTS.md 4), and the auth layer and route guards for axum
//! and tonic services ([`http`]).
//!
//! [`Verifier::verify`] checks a bearer token offline, with a cached JWKS,
//! in the order of CONTRACTS.md 4.2:
//!
//! 1. size: at most 8 KiB;
//! 2. header: `typ`, `alg` from the configured allow-list, `kid`, and none
//!    of `jku`, `x5u`, `jwk`, `x5c`, `crit`;
//! 3. the issuer is configured; its JWKS comes through `tutela-safenet`;
//! 4. the signature (ES256, RS256 or EdDSA, with a key of that type only);
//! 5. to 8. the claims: one audience that is ours, the time rules, `(iss,
//!    tid)` on the trust list, the subject kind;
//! 9. `epoch` is current and the principal is not disabled;
//! 10. for `agent+jwt`: delegation is on, our audience is
//!     `delegation_aware`, no actor is disabled, and `cnf` matches the
//!     client certificate.
//!
//! Any failure is a [`AuthError`]: the caller answers 401 and says nothing
//! about the step. [`AuthError::step`] names the step for the log. Errors
//! never hold the token.

pub mod cache;
pub mod http;
mod jwks;
pub mod sql;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use tutela_contracts::claims::{
    AccessTokenClaims, Audience, AudienceClaim, CLOCK_SKEW_SECS, DelegatedClaims,
    MAX_ACCESS_TOKEN_LIFETIME_SECS, MAX_TOKEN_BYTES,
};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, TenantKey, TrustList};

pub use jwks::{Alg, CacheRules, JwksSource, SafenetSource};

/// The step that refused a token (CONTRACTS.md 4.2). For logs only: the
/// response is always the same 401.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Step {
    /// 1. Over 8 KiB.
    Size,
    /// 2. The header, or not a JWS at all.
    Header,
    /// 3. The issuer is not configured.
    Issuer,
    /// 3. No usable key: unknown or deny-listed `kid`, or the JWKS could
    ///    not be fetched.
    Key,
    /// 4. The signature.
    Signature,
    /// 5 to 8. The claims.
    Claims,
    /// 9. An old `epoch`, or a disabled principal.
    Epoch,
    /// 10. A delegation rule.
    Delegation,
}

impl Step {
    /// A short name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Header => "header",
            Self::Issuer => "issuer",
            Self::Key => "key",
            Self::Signature => "signature",
            Self::Claims => "claims",
            Self::Epoch => "epoch",
            Self::Delegation => "delegation",
        }
    }
}

/// A refused token: always 401 to the caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("the token is not valid")]
pub struct AuthError(Step);

impl AuthError {
    /// The step that refused it, for the log.
    #[must_use]
    pub const fn step(&self) -> Step {
        self.0
    }
}

const fn refuse(step: Step) -> AuthError {
    AuthError(step)
}

/// The verifier's clock, seconds since the Unix epoch.
pub trait Clock: Send + Sync + 'static {
    /// Now.
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// One trusted issuer.
#[derive(Clone, Debug)]
pub struct IssuerConfig {
    /// The exact `iss`.
    pub iss: Issuer,
    /// Its JWKS document (https; fetched through `tutela-safenet`).
    pub jwks_uri: String,
    /// The algorithms it may use: a subset of [`Alg`].
    pub algs: Vec<Alg>,
    /// An external issuer (CONTRACTS.md 4.6, for example Keycloak): its
    /// tokens are not in Tutela's format, `tid` comes from the trust list,
    /// and there is no `epoch` or `rev`.
    pub external: bool,
    /// For an external issuer only: accept `typ: JWT` as well as `at+jwt`.
    pub allow_typ_jwt: bool,
}

/// The verifier's settings.
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// This service's audience.
    pub audience: Audience,
    /// The issuers and the tenants each may speak for (CONTRACTS.md 1.6).
    pub trust: TrustList,
    /// The issuers' keys and rules.
    pub issuers: Vec<IssuerConfig>,
    /// Accept delegated (`agent+jwt`) tokens at all. Off by default.
    pub delegation: bool,
    /// This audience is registered `delegation_aware`.
    pub delegation_aware: bool,
    /// Key ids refused at once, even when cached (TM-15).
    pub denied_kids: HashSet<String>,
    /// When the JWKS cache refreshes and gives up.
    pub cache: CacheRules,
}

/// A verified token.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Identity {
    /// A Tutela access token (`at+jwt`).
    Access(Box<AccessTokenClaims>),
    /// A delegated token (`agent+jwt`): the person in `sub`, the agents in
    /// `act`.
    Delegated(Box<DelegatedClaims>),
    /// A token of an external issuer (CONTRACTS.md 4.6). `sub` is the
    /// issuer's own subject: map `(iss, sub)` to a Tutela principal, never
    /// the e-mail claim.
    External(ExternalToken),
}

impl Identity {
    /// The tenant key `(iss, tid)`.
    #[must_use]
    pub fn tenant(&self) -> TenantKey {
        match self {
            Self::Access(c) => c.tenant_key(),
            Self::Delegated(c) => c.tenant_key(),
            Self::External(t) => t.tenant.clone(),
        }
    }
}

/// The checked claims of an external issuer's token.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExternalToken {
    /// The tenant, from the trust list.
    pub tenant: TenantKey,
    /// The issuer's subject.
    pub sub: String,
    /// `azp`, when present.
    pub azp: Option<String>,
    /// `exp`.
    pub exp: u64,
}

/// Extra facts about the request that some checks need.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context<'a> {
    /// SHA-256 of the TLS client certificate (DER), for `cnf` (RFC 8705).
    pub client_cert_sha256: Option<&'a [u8; 32]>,
}

/// The newest epoch per principal and the disabled principals, learned from
/// `tutela.session.revoked.v1` and `tutela.principal.disabled.v1`.
#[derive(Debug, Default)]
pub struct EpochBook {
    newest: RwLock<HashMap<Principal, u64>>,
    disabled: RwLock<HashSet<Principal>>,
}

impl EpochBook {
    /// Records an epoch from an event. Older values never lower it.
    pub fn note(&self, p: &Principal, epoch: u64) {
        if let Ok(mut m) = self.newest.write() {
            let e = m.entry(p.clone()).or_insert(epoch);
            *e = (*e).max(epoch);
        }
    }

    /// Marks a principal disabled (or enabled again).
    pub fn set_disabled(&self, p: &Principal, disabled: bool) {
        if let Ok(mut s) = self.disabled.write() {
            if disabled {
                s.insert(p.clone());
            } else {
                s.remove(p);
            }
        }
    }

    /// `epoch` is current for `p`, and `p` is not disabled. A poisoned lock
    /// fails closed.
    fn current(&self, p: &Principal, epoch: u64) -> bool {
        let newest_ok = self
            .newest
            .read()
            .is_ok_and(|m| m.get(p).is_none_or(|&n| epoch >= n));
        newest_ok && !self.is_disabled(p)
    }

    fn is_disabled(&self, p: &Principal) -> bool {
        self.disabled.read().map_or(true, |s| s.contains(p))
    }
}

#[derive(Deserialize)]
struct Header {
    typ: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_json::Value>,
}

const FORBIDDEN_HEADERS: [&str; 5] = ["jku", "x5u", "jwk", "x5c", "crit"];

/// The kind of token the `typ` header names.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Access,
    Delegated,
    PlainJwt,
}

fn kind_of(typ: Option<&str>) -> Option<Kind> {
    let t = typ?.to_ascii_lowercase();
    match t.as_str() {
        "at+jwt" | "application/at+jwt" => Some(Kind::Access),
        "agent+jwt" => Some(Kind::Delegated),
        "jwt" => Some(Kind::PlainJwt),
        _ => None,
    }
}

#[derive(Deserialize)]
struct IssOnly {
    iss: String,
}

#[derive(Deserialize)]
struct ExternalClaims {
    iss: Issuer,
    sub: String,
    aud: AudienceClaim,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    azp: Option<String>,
}

/// Verifies bearer tokens.
pub struct Verifier {
    config: VerifierConfig,
    issuers: HashMap<String, IssuerConfig>,
    keys: jwks::KeyCache,
    clock: Arc<dyn Clock>,
    epochs: Arc<EpochBook>,
    denied: RwLock<HashSet<String>>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("audience", &self.config.audience)
            .field("issuers", &self.issuers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// A verifier that fetches JWKS through `tutela-safenet` with
    /// production rules, and uses the system clock.
    ///
    /// # Errors
    ///
    /// When the TLS setup of the JWKS client fails.
    pub fn new(config: VerifierConfig) -> Result<Self, tutela_safenet::SafenetError> {
        let source = SafenetSource::new(tutela_safenet::Policy::new())?;
        Ok(Self::with(config, Arc::new(source), Arc::new(SystemClock)))
    }

    /// A verifier with its own JWKS source and clock.
    #[must_use]
    pub fn with(
        config: VerifierConfig,
        source: Arc<dyn JwksSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let issuers = config
            .issuers
            .iter()
            .map(|i| (i.iss.as_str().to_owned(), i.clone()))
            .collect();
        let denied = RwLock::new(config.denied_kids.clone());
        Self {
            keys: jwks::KeyCache::new(source, config.cache),
            config,
            issuers,
            clock,
            epochs: Arc::new(EpochBook::default()),
            denied,
        }
    }

    /// The epoch book, to feed from events.
    #[must_use]
    pub fn epochs(&self) -> Arc<EpochBook> {
        Arc::clone(&self.epochs)
    }

    /// Deny-lists a `kid` at once (an emergency, TM-15).
    pub fn deny_kid(&self, kid: &str) {
        if let Ok(mut d) = self.denied.write() {
            d.insert(kid.to_owned());
        }
    }

    /// Forgets the cached JWKS at `jwks_uri`, so the next token of that
    /// issuer fetches it at once, past the refetch limit: the forced refetch
    /// of an emergency rotation (TM-15). Call it when the issuer's key set is
    /// known to have changed; it is not for a token's own request.
    pub async fn forget_jwks(&self, jwks_uri: &str) {
        self.keys.forget(jwks_uri).await;
    }

    /// Verifies a bearer token.
    ///
    /// # Errors
    ///
    /// An [`AuthError`] naming the failed step.
    pub async fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        self.verify_with(token, Context::default()).await
    }

    /// Verifies a bearer token with request facts (the client certificate).
    ///
    /// # Errors
    ///
    /// An [`AuthError`] naming the failed step.
    pub async fn verify_with(&self, token: &str, ctx: Context<'_>) -> Result<Identity, AuthError> {
        // 1. Size.
        if token.len() > MAX_TOKEN_BYTES {
            return Err(refuse(Step::Size));
        }
        // 2. Header.
        let mut parts = token.split('.');
        let (Some(h64), Some(p64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(refuse(Step::Header));
        };
        let header: Header = B64
            .decode(h64)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(refuse(Step::Header))?;
        if header
            .rest
            .keys()
            .any(|k| FORBIDDEN_HEADERS.contains(&k.as_str()))
        {
            return Err(refuse(Step::Header));
        }
        let kind = kind_of(header.typ.as_deref()).ok_or(refuse(Step::Header))?;
        let alg = header
            .alg
            .as_deref()
            .and_then(Alg::parse)
            .ok_or(refuse(Step::Header))?;
        let kid = header
            .kid
            .filter(|k| !k.is_empty() && k.len() <= 256)
            .ok_or(refuse(Step::Header))?;
        let payload = B64.decode(p64).map_err(|_| refuse(Step::Header))?;

        // 3. The issuer, from the payload before the signature is checked,
        //    only to pick the keys.
        let iss: IssOnly = serde_json::from_slice(&payload).map_err(|_| refuse(Step::Issuer))?;
        let issuer = self.issuers.get(&iss.iss).ok_or(refuse(Step::Issuer))?;
        if !issuer.algs.contains(&alg) {
            return Err(refuse(Step::Header));
        }
        let kind_ok = match kind {
            Kind::Access | Kind::Delegated => true,
            Kind::PlainJwt => issuer.external && issuer.allow_typ_jwt,
        };
        if !kind_ok || (issuer.external && kind == Kind::Delegated) {
            return Err(refuse(Step::Header));
        }
        if self.denied.read().map_or(true, |d| d.contains(&kid)) {
            return Err(refuse(Step::Key));
        }
        let now = self.clock.now();
        let key = self
            .keys
            .key(&issuer.jwks_uri, &kid, now)
            .await
            .ok_or(refuse(Step::Key))?;
        // Tutela's own issuers name keys by their thumbprint (4.1).
        if !issuer.external && key.thumbprint() != kid {
            return Err(refuse(Step::Key));
        }

        // 4. The signature.
        let signature = B64.decode(s64).map_err(|_| refuse(Step::Signature))?;
        let signed_len = h64.len() + 1 + p64.len();
        let signed = token.get(..signed_len).ok_or(refuse(Step::Signature))?;
        if !key.verify(alg, signed.as_bytes(), &signature) {
            return Err(refuse(Step::Signature));
        }

        // 5 to 10.
        if issuer.external {
            return self.external(&payload, now).map(Identity::External);
        }
        match kind {
            Kind::Access => {
                let c: AccessTokenClaims =
                    serde_json::from_slice(&payload).map_err(|_| refuse(Step::Claims))?;
                c.validate(now, &self.config.audience, &self.config.trust)
                    .map_err(|_| refuse(Step::Claims))?;
                if !self.epochs.current(&c.sub, c.epoch) {
                    return Err(refuse(Step::Epoch));
                }
                Ok(Identity::Access(Box::new(c)))
            }
            Kind::Delegated => {
                if !self.config.delegation || !self.config.delegation_aware {
                    return Err(refuse(Step::Delegation));
                }
                let c: DelegatedClaims =
                    serde_json::from_slice(&payload).map_err(|_| refuse(Step::Claims))?;
                c.validate(now, &self.config.audience, &self.config.trust)
                    .map_err(|_| refuse(Step::Claims))?;
                if !self.epochs.current(&c.sub, c.epoch) {
                    return Err(refuse(Step::Epoch));
                }
                if c.act
                    .chain()
                    .into_iter()
                    .any(|a| self.epochs.is_disabled(a))
                {
                    return Err(refuse(Step::Delegation));
                }
                if let Some(cnf) = &c.cnf {
                    let want = cnf.x5t_s256.as_str();
                    let have = ctx.client_cert_sha256.map(|d| B64.encode(d));
                    if have.as_deref() != Some(want) {
                        return Err(refuse(Step::Delegation));
                    }
                }
                Ok(Identity::Delegated(Box::new(c)))
            }
            Kind::PlainJwt => Err(refuse(Step::Header)),
        }
    }

    /// Steps 5 to 8 for an external issuer (CONTRACTS.md 4.6).
    fn external(&self, payload: &[u8], now: u64) -> Result<ExternalToken, AuthError> {
        let c: ExternalClaims =
            serde_json::from_slice(payload).map_err(|_| refuse(Step::Claims))?;
        let aud_ok = c.aud.single().is_some_and(|a| *a == self.config.audience);
        let nbf = c.nbf.unwrap_or(c.iat);
        let times_ok = now <= c.exp.saturating_add(CLOCK_SKEW_SECS)
            && now.saturating_add(CLOCK_SKEW_SECS) >= nbf
            && c.iat <= now.saturating_add(CLOCK_SKEW_SECS)
            && c.exp > c.iat
            && c.exp - c.iat <= MAX_ACCESS_TOKEN_LIFETIME_SECS
            && nbf <= c.exp;
        let azp_ok = c.azp.as_deref().is_none_or(|a| {
            !a.is_empty() && a.len() <= 255 && a.bytes().all(|b| (0x21..=0x7e).contains(&b))
        });
        let sub_ok = !c.sub.is_empty() && c.sub.len() <= 255;
        if !(aud_ok && times_ok && azp_ok && sub_ok) {
            return Err(refuse(Step::Claims));
        }
        // `tid` comes from the trust list, never from the token.
        let tid = *self
            .config
            .trust
            .sole_tenant(&c.iss)
            .ok_or(refuse(Step::Claims))?;
        Ok(ExternalToken {
            tenant: TenantKey::new(c.iss, tid),
            sub: c.sub,
            azp: c.azp,
            exp: c.exp,
        })
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_list;
