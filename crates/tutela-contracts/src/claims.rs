//! Access-token and delegated-token claims (CONTRACTS.md section 4).
//!
//! This module has the claim structs and [`AccessTokenClaims::validate`] /
//! [`DelegatedClaims::validate`], which check the claims. It does **not**
//! check signatures or JOSE headers: that is `tutela-sdk` (Phase A). The
//! `epoch` check (step 9 of 4.2) needs SDK state and is also in `tutela-sdk`.
//! The delegation switches (steps 1 and 2 of 4.5) and the `cnf` match
//! (step 5) need service config and the TLS connection; they are in
//! `tutela-sdk` too.

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::encoding::{Thumbprint, json_int};
use crate::id::{SessionId, Uuid7};
use crate::principal::{Principal, PrincipalKind};
use crate::tenant::{Issuer, OrgId, TenantId, TenantKey, TrustList};

/// The JOSE `typ` of an access token (RFC 9068). Verifiers also accept
/// `application/at+jwt`, case-insensitive (CONTRACTS.md 4.1).
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// The JOSE `typ` of a delegated (agent) token (CONTRACTS.md 4.5).
pub const DELEGATED_TOKEN_TYP: &str = "agent+jwt";

/// The clock-skew allowance for the time rules, in seconds.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// The longest lifetime (`exp − iat`) of an access token, in seconds.
pub const MAX_ACCESS_TOKEN_LIFETIME_SECS: u64 = 600;

/// The longest lifetime of a token with `aud = tutela-admin`, in seconds.
pub const MAX_ADMIN_TOKEN_LIFETIME_SECS: u64 = 300;

/// The longest lifetime of a delegated (`agent+jwt`) token, in seconds.
pub const MAX_DELEGATED_TOKEN_LIFETIME_SECS: u64 = 120;

/// The largest token a verifier reads, in bytes (8 KiB).
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// The most actors in an `act` chain.
pub const MAX_ACTOR_CHAIN: usize = 4;

/// The largest `cap` claim, in bytes of JSON.
pub const MAX_CAP_BYTES: usize = 4096;

/// Why a claim value has the wrong format.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimFormatError {
    /// An audience is not `[a-z][a-z0-9-]{0,62}`.
    #[error("an audience must match [a-z][a-z0-9-]{{0,62}}")]
    Audience,
    /// `azp` is not 1 to 255 visible ASCII characters.
    #[error("a client id must be 1 to 255 visible ASCII characters")]
    ClientId,
    /// `scope` is not scope tokens separated by single spaces (RFC 6749 3.3).
    #[error("a scope must be scope tokens separated by single spaces")]
    Scope,
    /// `run_id` or `node_id` is not 1 to 128 characters from
    /// `A-Z a-z 0-9 . _ : -`.
    #[error("a run or node id must be 1 to 128 characters from A-Z a-z 0-9 . _ : -")]
    RunId,
}

/// An audience: `[a-z][a-z0-9-]{0,62}`, for example `symphony`, `crm-api` or
/// `tutela-admin` (CONTRACTS.md 4.2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Audience(Cow<'static, str>);

impl Audience {
    /// `tutela-admin`: the Tutela Console and the embeddable admin components.
    /// Lifetime at most 300 s (CONTRACTS.md 4.4).
    pub const TUTELA_ADMIN: Self = Self(Cow::Borrowed("tutela-admin"));

    /// Parses an audience.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimFormatError::Audience`] when `s` breaks the grammar.
    pub fn parse(s: &str) -> Result<Self, ClaimFormatError> {
        if crate::text::is_service_name(s) {
            Ok(Self(Cow::Owned(s.to_owned())))
        } else {
            Err(ClaimFormatError::Audience)
        }
    }

    /// The audience text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Audience {
    type Err = ClaimFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(Audience, "an audience string");

/// The `aud` claim as it was on the wire: a JSON string, or an array.
///
/// Tutela writes a string. Readers also accept an array, but
/// [`AccessTokenClaims::validate`] accepts only exactly one audience; an
/// array with 0 or 2 or more elements is rejected there.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AudienceClaim(Vec<Audience>);

impl AudienceClaim {
    /// One audience. This is what Tutela writes.
    #[must_use]
    pub fn one(audience: Audience) -> Self {
        Self(vec![audience])
    }

    /// Every audience in the claim.
    #[must_use]
    pub fn as_slice(&self) -> &[Audience] {
        &self.0
    }

    /// The audience, if there is exactly one.
    #[must_use]
    pub fn single(&self) -> Option<&Audience> {
        match self.0.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

impl From<Audience> for AudienceClaim {
    fn from(audience: Audience) -> Self {
        Self::one(audience)
    }
}

impl Serialize for AudienceClaim {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0.as_slice() {
            [one] => one.serialize(serializer),
            many => many.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AudienceClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AudVisitor;

        impl<'de> serde::de::Visitor<'de> for AudVisitor {
            type Value = AudienceClaim;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an audience string or an array of audience strings")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Audience::parse(v)
                    .map(AudienceClaim::one)
                    .map_err(E::custom)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut all = Vec::new();
                while let Some(aud) = seq.next_element::<Audience>()? {
                    all.push(aud);
                }
                Ok(AudienceClaim(all))
            }
        }

        deserializer.deserialize_any(AudVisitor)
    }
}

/// Defines a validated string newtype for a claim.
macro_rules! claim_string {
    ($(#[$meta:meta])* $name:ident, $check:expr, $err:expr, $expecting:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name(String);

        impl $name {
            /// Parses the value.
            ///
            /// # Errors
            ///
            /// Returns a [`ClaimFormatError`] when `s` breaks the grammar.
            pub fn parse(s: &str) -> Result<Self, ClaimFormatError> {
                let check: fn(&str) -> bool = $check;
                if check(s) { Ok(Self(s.to_owned())) } else { Err($err) }
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ClaimFormatError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        string_serde!($name, $expecting);
    };
}

claim_string!(
    /// The `azp` claim: the client id of the app that got the token. 1 to 255
    /// visible ASCII characters (`%x21-7E`).
    ClientId,
    |s| crate::text::is_visible_ascii_str(s, 1, 255),
    ClaimFormatError::ClientId,
    "a client id string"
);

claim_string!(
    /// The `scope` claim: OAuth scope tokens separated by single spaces
    /// (RFC 6749 3.3). Scopes only narrow access; they never add it.
    Scope,
    is_scope,
    ClaimFormatError::Scope,
    "a scope string"
);

claim_string!(
    /// The `run_id` claim: the run this work belongs to. 1 to 128 characters
    /// from `A-Z a-z 0-9 . _ : -`. The format is owned by the caller.
    RunId,
    is_run_id,
    ClaimFormatError::RunId,
    "a run id string"
);

claim_string!(
    /// The `node_id` claim: the step inside the run. Same grammar as
    /// [`RunId`].
    NodeId,
    is_run_id,
    ClaimFormatError::RunId,
    "a node id string"
);

impl Scope {
    /// The scope tokens.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.0.split(' ')
    }
}

/// `scope-token *( SP scope-token )`, `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`.
fn is_scope(s: &str) -> bool {
    s.split(' ').all(|token| {
        !token.is_empty()
            && token
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
    })
}

/// 1 to 128 characters from `A-Z a-z 0-9 . _ : -`.
fn is_run_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// One link of the `act` chain (RFC 8693): the actor that acts now, and,
/// nested, the actor it acts for (CONTRACTS.md 4.5).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Actor {
    /// The acting principal. Must be an `agent`.
    pub sub: Principal,
    /// The actor this actor acts for, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<Actor>>,
}

impl Actor {
    /// One actor with no nested actor.
    #[must_use]
    pub const fn new(sub: Principal) -> Self {
        Self { sub, act: None }
    }

    /// The principals of the chain, the current actor first.
    #[must_use]
    pub fn chain(&self) -> Vec<&Principal> {
        let mut out = Vec::new();
        let mut next = Some(self);
        while let Some(actor) = next {
            out.push(&actor.sub);
            next = actor.act.as_deref();
        }
        out
    }

    /// Checks the chain: at most [`MAX_ACTOR_CHAIN`] actors, every one an
    /// `agent` principal.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimsError::ActorKind`] or [`ClaimsError::ActorChainTooLong`].
    pub fn check_chain(&self) -> Result<(), ClaimsError> {
        let mut count = 0usize;
        let mut next = Some(self);
        while let Some(actor) = next {
            count += 1;
            if count > MAX_ACTOR_CHAIN {
                return Err(ClaimsError::ActorChainTooLong);
            }
            let kind = actor.sub.kind();
            if kind != PrincipalKind::Agent {
                return Err(ClaimsError::ActorKind { kind });
            }
            next = actor.act.as_deref();
        }
        Ok(())
    }
}

/// The `cnf` claim: an mTLS binding (RFC 8705).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Confirmation {
    /// `x5t#S256`: the base64url SHA-256 of the client certificate.
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Thumbprint,
}

/// Why claims were rejected. Every variant names one verification step and
/// never holds the token or a claim value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimsError {
    /// `iss` is not on the trust list.
    #[error("the issuer is not trusted")]
    UntrustedIssuer,
    /// `aud` does not hold exactly one audience.
    #[error("the token must have exactly one audience, it has {count}")]
    AudienceCount {
        /// How many audiences the token has.
        count: usize,
    },
    /// `aud` is not the verifier's own audience.
    #[error("the token is for another audience")]
    WrongAudience,
    /// `now > exp + 60`.
    #[error("the token has expired")]
    Expired,
    /// `now + 60 < nbf`.
    #[error("the token is not valid yet")]
    NotYetValid,
    /// `iat > now + 60`.
    #[error("the token was issued in the future")]
    IssuedInFuture,
    /// `exp ≤ iat`.
    #[error("the token expires before it was issued")]
    NonPositiveLifetime,
    /// `nbf > exp`: the token is never valid.
    #[error("the token becomes valid after it expires")]
    NotBeforeAfterExpiry,
    /// An access token carries `act`: it is a delegated token sent as an
    /// access token.
    #[error("an access token must not carry `act`")]
    UnexpectedAct,
    /// `exp − iat` is above the limit.
    #[error("the token lives longer than {max} seconds")]
    LifetimeTooLong {
        /// The limit that applied, in seconds.
        max: u64,
    },
    /// The pair `(iss, tid)` is not on the trust list.
    #[error("the issuer may not speak for this tenant")]
    TenantNotTrusted,
    /// `sub` has a kind that is not allowed here.
    #[error("a token subject may not be of kind `{kind}`")]
    SubjectKind {
        /// The kind of `sub`.
        kind: PrincipalKind,
    },
    /// `sub` is a user but `sid` is missing.
    #[error("`sid` is required when the subject is a user")]
    MissingSid,
    /// `sid` is present but `sub` is not a user.
    #[error("`sid` must be absent when the subject is not a user")]
    UnexpectedSid,
    /// `sub` is a user but `amr` is missing or empty.
    #[error("a non-empty `amr` is required when the subject is a user")]
    MissingAmr,
    /// An actor in the `act` chain is not an agent.
    #[error("every actor must be an agent, found `{kind}`")]
    ActorKind {
        /// The kind of the bad actor.
        kind: PrincipalKind,
    },
    /// The `act` chain has more than 4 actors.
    #[error("the actor chain has more than 4 actors")]
    ActorChainTooLong,
    /// `cap` is larger than 4096 bytes of JSON.
    #[error("the `cap` claim is larger than 4096 bytes")]
    CapTooLarge,
}

/// The claims every Tutela token checks the same way.
struct CommonClaims<'a> {
    iss: &'a Issuer,
    aud: &'a AudienceClaim,
    exp: u64,
    iat: u64,
    nbf: u64,
    tid: &'a TenantId,
}

impl CommonClaims<'_> {
    /// Steps 3, 5, 6 and 7 of CONTRACTS.md 4.2, in that order.
    fn check(
        &self,
        now: u64,
        expected_aud: &Audience,
        trusted: &TrustList,
        max_lifetime: u64,
    ) -> Result<(), ClaimsError> {
        if !trusted.has_issuer(self.iss) {
            return Err(ClaimsError::UntrustedIssuer);
        }
        let aud = self.aud.single().ok_or(ClaimsError::AudienceCount {
            count: self.aud.as_slice().len(),
        })?;
        if aud != expected_aud {
            return Err(ClaimsError::WrongAudience);
        }
        check_times(now, self.exp, self.nbf, self.iat, max_lifetime)?;
        if !trusted.allows(self.iss, self.tid) {
            return Err(ClaimsError::TenantNotTrusted);
        }
        Ok(())
    }
}

/// The time rules of CONTRACTS.md 4.2, with the 60 s skew.
fn check_times(
    now: u64,
    exp: u64,
    nbf: u64,
    iat: u64,
    max_lifetime: u64,
) -> Result<(), ClaimsError> {
    if now > exp.saturating_add(CLOCK_SKEW_SECS) {
        return Err(ClaimsError::Expired);
    }
    if now.saturating_add(CLOCK_SKEW_SECS) < nbf {
        return Err(ClaimsError::NotYetValid);
    }
    if iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(ClaimsError::IssuedInFuture);
    }
    if exp <= iat {
        return Err(ClaimsError::NonPositiveLifetime);
    }
    if nbf > exp {
        return Err(ClaimsError::NotBeforeAfterExpiry);
    }
    if exp - iat > max_lifetime {
        return Err(ClaimsError::LifetimeTooLong { max: max_lifetime });
    }
    Ok(())
}

/// The lifetime limit for an audience: 300 s for `tutela-admin`, else
/// `default`.
fn lifetime_for(aud: &Audience, default: u64) -> u64 {
    if *aud == Audience::TUTELA_ADMIN {
        default.min(MAX_ADMIN_TOKEN_LIFETIME_SECS)
    } else {
        default
    }
}

/// The claims of a Tutela access token, `typ = at+jwt` (CONTRACTS.md 4.2).
///
/// Never holds permission lists, role lists, field masks, profile data or
/// secrets (4.7).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// The issuer. Part of the tenant key.
    pub iss: Issuer,
    /// The principal: kind `user`, `sa`, `key` or `agent`, never `workload`.
    pub sub: Principal,
    /// Exactly one audience.
    pub aud: AudienceClaim,
    /// The client id of the app that got the token.
    pub azp: ClientId,
    /// Expiry, NumericDate (seconds since the Unix epoch).
    #[serde(with = "json_int")]
    pub exp: u64,
    /// Issued at, NumericDate.
    #[serde(with = "json_int")]
    pub iat: u64,
    /// Not before, NumericDate. Tutela sets `nbf = iat`.
    #[serde(with = "json_int")]
    pub nbf: u64,
    /// The token id. Names a token in logs and revokes one token.
    pub jti: Uuid7,
    /// The session. Required for users, absent for other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    /// The tenant id. With `iss`, the tenant key.
    pub tid: TenantId,
    /// The active org. Added only after a membership check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgId>,
    /// The subject's session epoch.
    #[serde(with = "json_int")]
    pub epoch: u64,
    /// The tenant revision when the token was issued.
    #[serde(with = "json_int")]
    pub rev: u64,
    /// OAuth scopes. They only narrow access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// Authentication methods (RFC 8176). Required for users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authentication context class from the issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Never set by Tutela. It is read only so that [`Self::validate`] can
    /// refuse a delegated token sent as an access token (CONTRACTS.md 4.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
}

impl AccessTokenClaims {
    /// The tenant key `(iss, tid)`.
    #[must_use]
    pub fn tenant_key(&self) -> TenantKey {
        TenantKey::new(self.iss.clone(), self.tid)
    }

    /// Checks the claims (CONTRACTS.md 4.2, steps 3 and 5 to 8):
    ///
    /// 1. `iss` is on the trust list;
    /// 2. `aud` holds exactly one audience, equal to `expected_aud`;
    /// 3. the time rules with 60 s skew; lifetime at most 600 s, or 300 s
    ///    when the audience is `tutela-admin`;
    /// 4. the pair `(iss, tid)` is on the trust list;
    /// 5. `sub` is a `user`, `sa`, `key` or `agent`;
    /// 6. a user has `sid` and a non-empty `amr`; other kinds have no `sid`;
    /// 7. there is no `act` claim.
    ///
    /// `now` is the verifier's clock in seconds since the Unix epoch. This
    /// does **not** verify the signature, the header or the `epoch`.
    ///
    /// # Errors
    ///
    /// Returns the [`ClaimsError`] of the first failed step.
    pub fn validate(
        &self,
        now: u64,
        expected_aud: &Audience,
        trusted: &TrustList,
    ) -> Result<(), ClaimsError> {
        CommonClaims {
            iss: &self.iss,
            aud: &self.aud,
            exp: self.exp,
            iat: self.iat,
            nbf: self.nbf,
            tid: &self.tid,
        }
        .check(
            now,
            expected_aud,
            trusted,
            lifetime_for(expected_aud, MAX_ACCESS_TOKEN_LIFETIME_SECS),
        )?;
        match self.sub.kind() {
            PrincipalKind::User => {
                if self.sid.is_none() {
                    return Err(ClaimsError::MissingSid);
                }
                if self.amr.as_ref().is_none_or(Vec::is_empty) {
                    return Err(ClaimsError::MissingAmr);
                }
            }
            PrincipalKind::ServiceAccount | PrincipalKind::Key | PrincipalKind::Agent => {
                if self.sid.is_some() {
                    return Err(ClaimsError::UnexpectedSid);
                }
            }
            kind @ PrincipalKind::Workload => return Err(ClaimsError::SubjectKind { kind }),
        }
        if self.act.is_some() {
            return Err(ClaimsError::UnexpectedAct);
        }
        Ok(())
    }
}

/// The claims of a delegated (agent) token, `typ = agent+jwt`
/// (CONTRACTS.md 4.5). Issued by `tutelad` through RFC 8693 token exchange
/// (Phase B).
///
/// An SDK refuses `agent+jwt` unless delegation support is on in its config.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DelegatedClaims {
    /// The issuer. Part of the tenant key.
    pub iss: Issuer,
    /// The **person** (`user:usr_...`) who caused the work.
    pub sub: Principal,
    /// The agent that acts now, maybe with nested actors. At most 4 actors,
    /// every one an agent.
    pub act: Actor,
    /// attache's capability snapshot. Opaque to Tutela: copied, never read or
    /// widened. At most 4096 bytes as JSON.
    pub cap: serde_json::Map<String, serde_json::Value>,
    /// The run this work belongs to.
    pub run_id: RunId,
    /// The step inside the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    /// Exactly one audience, registered with `delegation_aware = true`.
    pub aud: AudienceClaim,
    /// The client id of the app that got the token.
    pub azp: ClientId,
    /// Expiry, NumericDate. The issuer picks a TTL of 60 to 120 s.
    #[serde(with = "json_int")]
    pub exp: u64,
    /// Issued at, NumericDate.
    #[serde(with = "json_int")]
    pub iat: u64,
    /// Not before, NumericDate.
    #[serde(with = "json_int")]
    pub nbf: u64,
    /// The token id.
    pub jti: Uuid7,
    /// The person's session, when there is one. Scheduled work has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    /// The tenant id.
    pub tid: TenantId,
    /// The active org.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgId>,
    /// The **person's** epoch.
    #[serde(with = "json_int")]
    pub epoch: u64,
    /// The tenant revision when the token was issued.
    #[serde(with = "json_int")]
    pub rev: u64,
    /// OAuth scopes. They only narrow access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// The person's authentication methods, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authentication context class from the issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// mTLS binding (RFC 8705). If present, the verifier checks the TLS
    /// client certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

impl DelegatedClaims {
    /// The tenant key `(iss, tid)`.
    #[must_use]
    pub fn tenant_key(&self) -> TenantKey {
        TenantKey::new(self.iss.clone(), self.tid)
    }

    /// The size of `cap` as compact JSON, in bytes.
    #[must_use]
    pub fn cap_size(&self) -> Option<usize> {
        serde_json::to_vec(&self.cap).ok().map(|v| v.len())
    }

    /// Checks the claims (CONTRACTS.md 4.2 and 4.5):
    ///
    /// 1. to 4. as [`AccessTokenClaims::validate`], with a lifetime of at most
    ///    120 s;
    /// 5. `sub` is a `user`;
    /// 6. `act` has at most 4 actors and every actor is an `agent`;
    /// 7. `cap` is at most 4096 bytes as JSON.
    ///
    /// This does **not** verify the signature, the header, the `epoch`, the
    /// delegation switches, disabled actors or `cnf` (`tutela-sdk`, Phase A).
    ///
    /// # Errors
    ///
    /// Returns the [`ClaimsError`] of the first failed step.
    pub fn validate(
        &self,
        now: u64,
        expected_aud: &Audience,
        trusted: &TrustList,
    ) -> Result<(), ClaimsError> {
        CommonClaims {
            iss: &self.iss,
            aud: &self.aud,
            exp: self.exp,
            iat: self.iat,
            nbf: self.nbf,
            tid: &self.tid,
        }
        .check(
            now,
            expected_aud,
            trusted,
            lifetime_for(expected_aud, MAX_DELEGATED_TOKEN_LIFETIME_SECS),
        )?;
        let kind = self.sub.kind();
        if kind != PrincipalKind::User {
            return Err(ClaimsError::SubjectKind { kind });
        }
        self.act.check_chain()?;
        // A map of JSON values always serializes; fail closed if it ever did not.
        match self.cap_size() {
            Some(size) if size <= MAX_CAP_BYTES => Ok(()),
            _ => Err(ClaimsError::CapTooLarge),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const ISS: &str = "https://auth.example.test";
    const TEN: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
    const USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
    const AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";
    const AGENT2: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809103";

    const ACCESS_DOC: &str = r#"{
      "iss": "https://auth.example.test",
      "sub": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081",
      "aud": "crm-api",
      "azp": "crm-web",
      "exp": 1792921200,
      "iat": 1792920600,
      "nbf": 1792920600,
      "jti": "0193a1b2-c3d4-7e99-8f00-a1b2c3d4e5f6",
      "sid": "ses_0193a1b2-c3d4-7123-8456-789abcdef012",
      "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
      "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
      "epoch": 3,
      "rev": 42,
      "scope": "openid invoices",
      "amr": ["pwd", "otp", "mfa"],
      "acr": "mfa"
    }"#;

    const DELEGATED_DOC: &str = r#"{
      "iss": "https://auth.example.test",
      "sub": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081",
      "act": { "sub": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" },
      "cap": { "snapshot": "<attache data, opaque to Tutela>" },
      "run_id": "run-2026-10-25-0001",
      "node_id": "review-step-2",
      "aud": "symphony",
      "azp": "attache-sidecar",
      "exp": 1792920750,
      "iat": 1792920660,
      "nbf": 1792920660,
      "jti": "0193a1b2-c3d4-7e99-8f00-a1b2c3d4e5f7",
      "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
      "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
      "epoch": 3,
      "rev": 42
    }"#;

    const IAT: u64 = 1_792_920_600;

    fn trust() -> TrustList {
        TrustList::new()
            .with(ISS.parse().unwrap(), TEN.parse().unwrap())
            .unwrap()
    }

    fn aud(s: &str) -> Audience {
        Audience::parse(s).unwrap()
    }

    fn access() -> AccessTokenClaims {
        serde_json::from_str(ACCESS_DOC).unwrap()
    }

    fn delegated() -> DelegatedClaims {
        serde_json::from_str(DELEGATED_DOC).unwrap()
    }

    fn access_with(patch: Value) -> AccessTokenClaims {
        let mut v: Value = serde_json::from_str(ACCESS_DOC).unwrap();
        for (k, val) in patch.as_object().unwrap() {
            if val.is_null() {
                v.as_object_mut().unwrap().remove(k);
            } else {
                v[k] = val.clone();
            }
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn access_token_with_act_is_refused() {
        let claims = access_with(json!({ "act": { "sub": AGENT } }));
        assert_eq!(
            claims.validate(IAT + 10, &aud("crm-api"), &trust()),
            Err(ClaimsError::UnexpectedAct)
        );
    }

    #[test]
    fn user_token_with_empty_amr_is_refused() {
        let claims = access_with(json!({ "amr": [] }));
        assert_eq!(
            claims.validate(IAT + 10, &aud("crm-api"), &trust()),
            Err(ClaimsError::MissingAmr)
        );
    }

    #[test]
    fn nbf_after_exp_is_refused() {
        // `exp` is IAT + 600 in the doc example.
        let claims = access_with(json!({ "nbf": IAT + 601 }));
        assert_eq!(
            claims.validate(IAT + 600, &aud("crm-api"), &trust()),
            Err(ClaimsError::NotBeforeAfterExpiry)
        );
    }

    #[test]
    fn access_doc_example_round_trips_exactly() {
        let claims = access();
        assert_eq!(claims.sub.kind(), PrincipalKind::User);
        assert_eq!(claims.aud.single().map(Audience::as_str), Some("crm-api"));
        assert_eq!(
            claims.scope.as_ref().unwrap().tokens().collect::<Vec<_>>(),
            ["openid", "invoices"]
        );
        assert_eq!(claims.tenant_key().tid.to_string(), TEN);
        let back = serde_json::to_value(&claims).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(ACCESS_DOC).unwrap());
        assert_eq!(claims.validate(IAT + 10, &aud("crm-api"), &trust()), Ok(()));
    }

    #[test]
    fn delegated_doc_example_round_trips_exactly() {
        let claims = delegated();
        assert_eq!(claims.act.chain().len(), 1);
        assert_eq!(claims.act.sub.to_string(), AGENT);
        let back = serde_json::to_value(&claims).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(DELEGATED_DOC).unwrap());
        assert_eq!(
            claims.validate(1_792_920_700, &aud("symphony"), &trust()),
            Ok(())
        );
    }

    #[test]
    fn audience_forms() {
        let one = access_with(json!({ "aud": ["crm-api"] }));
        assert_eq!(one.validate(IAT, &aud("crm-api"), &trust()), Ok(()));
        // Tutela writes the one-element array back as a string.
        assert_eq!(serde_json::to_value(&one.aud).unwrap(), json!("crm-api"));

        let two = access_with(json!({ "aud": ["crm-api", "onto"] }));
        assert_eq!(
            two.validate(IAT, &aud("crm-api"), &trust()),
            Err(ClaimsError::AudienceCount { count: 2 })
        );
        assert_eq!(
            serde_json::to_value(&two.aud).unwrap(),
            json!(["crm-api", "onto"])
        );
        let none = access_with(json!({ "aud": [] }));
        assert_eq!(
            none.validate(IAT, &aud("crm-api"), &trust()),
            Err(ClaimsError::AudienceCount { count: 0 })
        );
        let other = access_with(json!({ "aud": "onto" }));
        assert_eq!(
            other.validate(IAT, &aud("crm-api"), &trust()),
            Err(ClaimsError::WrongAudience)
        );

        let mut v: Value = serde_json::from_str(ACCESS_DOC).unwrap();
        for bad in [
            json!("Crm-Api"),
            json!(""),
            json!(1),
            json!(null),
            json!(["crm_api"]),
            json!({}),
        ] {
            v["aud"] = bad.clone();
            assert!(
                serde_json::from_value::<AccessTokenClaims>(v.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn issuer_and_tenant_must_be_trusted() {
        let claims = access();
        let a = aud("crm-api");
        let other_issuer = TrustList::new()
            .with(
                "https://other.example.test".parse().unwrap(),
                TEN.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(
            claims.validate(IAT, &a, &other_issuer),
            Err(ClaimsError::UntrustedIssuer)
        );
        assert_eq!(
            claims.validate(IAT, &a, &TrustList::new()),
            Err(ClaimsError::UntrustedIssuer)
        );

        // The issuer is trusted, but for another tenant only.
        let wrong_tenant = TrustList::new()
            .with(
                ISS.parse().unwrap(),
                "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(
            claims.validate(IAT, &a, &wrong_tenant),
            Err(ClaimsError::TenantNotTrusted)
        );

        // The tenant is trusted, but under another issuer.
        let shared = trust()
            .with(
                "https://other.example.test".parse().unwrap(),
                "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c".parse().unwrap(),
            )
            .unwrap();
        let mut other = access_with(json!({ "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c" }));
        assert_eq!(
            other.validate(IAT, &a, &shared),
            Err(ClaimsError::TenantNotTrusted)
        );
        other.iss = "https://other.example.test".parse().unwrap();
        assert_eq!(other.validate(IAT, &a, &shared), Ok(()));

        // Exact text: a trailing slash is another issuer.
        let mut slash = access();
        slash.iss = "https://auth.example.test/".parse().unwrap();
        assert_eq!(
            slash.validate(IAT, &a, &trust()),
            Err(ClaimsError::UntrustedIssuer)
        );
    }

    #[test]
    fn time_rules_and_skew_boundaries() {
        let a = aud("crm-api");
        let t = trust();
        let claims = access(); // iat = nbf = IAT, exp = IAT + 600
        let exp = IAT + 600;
        assert_eq!(claims.validate(exp, &a, &t), Ok(()));
        assert_eq!(claims.validate(exp + 60, &a, &t), Ok(()));
        assert_eq!(claims.validate(exp + 61, &a, &t), Err(ClaimsError::Expired));
        assert_eq!(claims.validate(u64::MAX, &a, &t), Err(ClaimsError::Expired));
        assert_eq!(claims.validate(IAT - 60, &a, &t), Ok(()));
        assert_eq!(
            claims.validate(IAT - 61, &a, &t),
            Err(ClaimsError::NotYetValid)
        );
        assert_eq!(claims.validate(0, &a, &t), Err(ClaimsError::NotYetValid));

        // nbf in the past, iat in the future: the iat rule applies on its own.
        let future_iat =
            access_with(json!({ "nbf": IAT - 100, "iat": IAT + 61, "exp": IAT + 200 }));
        assert_eq!(
            future_iat.validate(IAT, &a, &t),
            Err(ClaimsError::IssuedInFuture)
        );
        let edge_iat = access_with(json!({ "nbf": IAT - 100, "iat": IAT + 60, "exp": IAT + 200 }));
        assert_eq!(edge_iat.validate(IAT, &a, &t), Ok(()));

        let zero = access_with(json!({ "exp": IAT }));
        assert_eq!(
            zero.validate(IAT, &a, &t),
            Err(ClaimsError::NonPositiveLifetime)
        );
        let negative = access_with(json!({ "exp": IAT - 1, "nbf": IAT - 30 }));
        assert_eq!(
            negative.validate(IAT - 1, &a, &t),
            Err(ClaimsError::NonPositiveLifetime)
        );
        let long = access_with(json!({ "exp": IAT + 601 }));
        assert_eq!(
            long.validate(IAT, &a, &t),
            Err(ClaimsError::LifetimeTooLong { max: 600 })
        );
    }

    #[test]
    fn admin_audience_lifetime() {
        let t = trust();
        let admin = Audience::TUTELA_ADMIN;
        let ok = access_with(json!({ "aud": "tutela-admin", "exp": IAT + 300 }));
        assert_eq!(ok.validate(IAT, &admin, &t), Ok(()));
        let long = access_with(json!({ "aud": "tutela-admin", "exp": IAT + 301 }));
        assert_eq!(
            long.validate(IAT, &admin, &t),
            Err(ClaimsError::LifetimeTooLong { max: 300 })
        );
        assert_eq!(
            Audience::parse("tutela-admin").unwrap(),
            Audience::TUTELA_ADMIN
        );
        // A delegated token keeps its own, shorter limit for this audience.
        let base: Value = serde_json::from_str(DELEGATED_DOC).unwrap();
        let mut v = base;
        v["aud"] = json!("tutela-admin");
        v["exp"] = json!(1_792_920_660u64 + 121);
        let d: DelegatedClaims = serde_json::from_value(v).unwrap();
        assert_eq!(
            d.validate(1_792_920_700, &admin, &t),
            Err(ClaimsError::LifetimeTooLong { max: 120 })
        );
    }

    #[test]
    fn duplicate_audiences_are_two_audiences() {
        let dup = access_with(json!({ "aud": ["crm-api", "crm-api"] }));
        assert_eq!(dup.aud.single(), None);
        assert_eq!(
            dup.validate(IAT, &aud("crm-api"), &trust()),
            Err(ClaimsError::AudienceCount { count: 2 })
        );
    }

    #[test]
    fn steps_run_in_the_documented_order() {
        // An untrusted issuer is reported before a wrong audience or bad times
        // (CONTRACTS.md 4.2: step 3 before steps 5 and 6).
        let bad = access_with(json!({ "aud": "onto", "exp": IAT + 601 }));
        assert_eq!(
            bad.validate(IAT, &aud("crm-api"), &TrustList::new()),
            Err(ClaimsError::UntrustedIssuer)
        );
        // A wrong audience is reported before bad times (step 5 before 6).
        assert_eq!(
            bad.validate(IAT, &aud("crm-api"), &trust()),
            Err(ClaimsError::WrongAudience)
        );
        // Bad times are reported before an untrusted tenant (step 6 before 7).
        let mut other_tenant = access_with(json!({ "exp": IAT + 601 }));
        other_tenant.tid = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c".parse().unwrap();
        assert_eq!(
            other_tenant.validate(IAT, &aud("crm-api"), &trust()),
            Err(ClaimsError::LifetimeTooLong { max: 600 })
        );
    }

    #[test]
    fn dev_issuers_need_a_dev_trust_list() {
        let dev_iss: Issuer = "http://localhost:8080/realms/dev".parse().unwrap();
        let mut claims = access();
        claims.iss = dev_iss.clone();
        let a = aud("crm-api");
        assert_eq!(
            claims.validate(IAT, &a, &trust()),
            Err(ClaimsError::UntrustedIssuer)
        );
        let dev = TrustList::dev_mode()
            .with(dev_iss, TEN.parse().unwrap())
            .unwrap();
        assert_eq!(claims.validate(IAT, &a, &dev), Ok(()));
    }

    #[test]
    fn extreme_times_never_overflow() {
        // The struct fields are plain `u64`, so a caller can build values
        // outside the JSON range. The checks must not overflow or panic.
        let a = aud("crm-api");
        let t = trust();
        let mut c = access();
        c.iat = 0;
        c.nbf = 0;
        c.exp = 0;
        assert_eq!(c.validate(u64::MAX, &a, &t), Err(ClaimsError::Expired));
        assert_eq!(c.validate(0, &a, &t), Err(ClaimsError::NonPositiveLifetime));
        c.exp = u64::MAX;
        assert_eq!(
            c.validate(0, &a, &t),
            Err(ClaimsError::LifetimeTooLong { max: 600 })
        );
        c.iat = u64::MAX - 600;
        c.nbf = c.iat;
        assert_eq!(c.validate(0, &a, &t), Err(ClaimsError::NotYetValid));
        c.nbf = 0;
        assert_eq!(c.validate(0, &a, &t), Err(ClaimsError::IssuedInFuture));
        c.nbf = c.iat;
        assert_eq!(c.validate(u64::MAX, &a, &t), Ok(()));
        // Such a token cannot be written: integers stop at 2^53 - 1.
        assert!(serde_json::to_value(&c).is_err());
    }

    #[test]
    fn errors_never_hold_claim_values() {
        let claims = access();
        let a = aud("crm-api");
        let mut errors = vec![
            claims.validate(IAT, &a, &TrustList::new()).unwrap_err(),
            claims.validate(IAT, &aud("onto"), &trust()).unwrap_err(),
            claims.validate(u64::MAX, &a, &trust()).unwrap_err(),
        ];
        errors.push(
            access_with(json!({ "sid": null }))
                .validate(IAT, &a, &trust())
                .unwrap_err(),
        );
        for err in errors {
            let text = format!("{err} {err:?}");
            for value in [ISS, TEN, USER, "crm-api", "crm-web", "ses_", "0193a1b2"] {
                assert!(!text.contains(value), "{text} contains {value}");
            }
        }
    }

    #[test]
    fn subject_rules() {
        let a = aud("crm-api");
        let t = trust();
        let no_sid = access_with(json!({ "sid": null }));
        assert_eq!(no_sid.validate(IAT, &a, &t), Err(ClaimsError::MissingSid));
        let no_amr = access_with(json!({ "amr": null }));
        assert_eq!(no_amr.validate(IAT, &a, &t), Err(ClaimsError::MissingAmr));

        let sa = "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3";
        let key = "key:key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4";
        for sub in [sa, key, AGENT] {
            let ok = access_with(json!({ "sub": sub, "sid": null, "amr": null }));
            assert_eq!(ok.validate(IAT, &a, &t), Ok(()), "{sub}");
            let with_sid = access_with(json!({ "sub": sub }));
            assert_eq!(
                with_sid.validate(IAT, &a, &t),
                Err(ClaimsError::UnexpectedSid),
                "{sub}"
            );
        }
        let workload = access_with(json!({ "sub": "workload:spiffe://td/ns/x", "sid": null }));
        assert_eq!(
            workload.validate(IAT, &a, &t),
            Err(ClaimsError::SubjectKind {
                kind: PrincipalKind::Workload
            })
        );
        // A user token with `sid: null` is the same as a missing `sid`.
        let mut v: Value = serde_json::from_str(ACCESS_DOC).unwrap();
        v["sid"] = Value::Null;
        let parsed: AccessTokenClaims = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.sid, None);
    }

    #[test]
    fn required_claims_and_formats() {
        let base: Value = serde_json::from_str(ACCESS_DOC).unwrap();
        for k in [
            "iss", "sub", "aud", "azp", "exp", "iat", "nbf", "jti", "tid", "epoch", "rev",
        ] {
            let mut v = base.clone();
            v.as_object_mut().unwrap().remove(k);
            assert!(
                serde_json::from_value::<AccessTokenClaims>(v.clone()).is_err(),
                "missing {k}"
            );
            v[k] = Value::Null;
            assert!(
                serde_json::from_value::<AccessTokenClaims>(v).is_err(),
                "null {k}"
            );
        }
        let bad: &[(&str, Value)] = &[
            ("iss", json!("http://auth.example.test")),
            ("sub", json!("usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081")),
            ("azp", json!("crm web")),
            ("azp", json!("")),
            ("exp", json!(-1)),
            ("exp", json!(1.5)),
            ("exp", json!("1792921200")),
            ("rev", json!(9_007_199_254_740_992u64)),
            ("jti", json!("0193a1b2-c3d4-4e99-8f00-a1b2c3d4e5f6")),
            ("sid", json!("usr_0193a1b2-c3d4-7123-8456-789abcdef012")),
            ("tid", json!("org_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b")),
            ("org", json!("ten_0193a1b2-c3d4-7f00-9a00-000000000002")),
            ("scope", json!("openid  invoices")),
            ("scope", json!(" openid")),
            ("scope", json!("")),
            ("scope", json!("a\"b")),
            ("amr", json!("pwd")),
        ];
        for (k, val) in bad {
            let mut v = base.clone();
            v[*k] = val.clone();
            assert!(
                serde_json::from_value::<AccessTokenClaims>(v).is_err(),
                "{k} = {val}"
            );
        }
        // Unknown claims are ignored.
        let mut v = base.clone();
        v["permissions"] = json!(["ignored"]);
        let parsed: AccessTokenClaims = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, access());
    }

    #[test]
    fn delegated_rules() {
        let a = aud("symphony");
        let t = trust();
        let now = 1_792_920_700;
        let base: Value = serde_json::from_str(DELEGATED_DOC).unwrap();
        let with = |patch: Value| -> DelegatedClaims {
            let mut v = base.clone();
            for (k, val) in patch.as_object().unwrap() {
                v[k] = val.clone();
            }
            serde_json::from_value(v).unwrap()
        };

        let long = with(json!({ "exp": 1_792_920_660 + 121 }));
        assert_eq!(
            long.validate(now, &a, &t),
            Err(ClaimsError::LifetimeTooLong { max: 120 })
        );
        let edge = with(json!({ "exp": 1_792_920_660 + 120 }));
        assert_eq!(edge.validate(now, &a, &t), Ok(()));

        let not_user = with(json!({ "sub": AGENT }));
        assert_eq!(
            not_user.validate(now, &a, &t),
            Err(ClaimsError::SubjectKind {
                kind: PrincipalKind::Agent
            })
        );

        let user_actor = with(json!({ "act": { "sub": USER } }));
        assert_eq!(
            user_actor.validate(now, &a, &t),
            Err(ClaimsError::ActorKind {
                kind: PrincipalKind::User
            })
        );
        let nested_bad = with(
            json!({ "act": { "sub": AGENT, "act": { "sub": "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3" } } }),
        );
        assert_eq!(
            nested_bad.validate(now, &a, &t),
            Err(ClaimsError::ActorKind {
                kind: PrincipalKind::ServiceAccount
            })
        );

        let chain4 = with(
            json!({ "act": { "sub": AGENT, "act": { "sub": AGENT2, "act": { "sub": AGENT, "act": { "sub": AGENT2 } } } } }),
        );
        assert_eq!(chain4.validate(now, &a, &t), Ok(()));
        assert_eq!(chain4.act.chain().len(), 4);
        assert_eq!(chain4.act.chain()[1].to_string(), AGENT2);
        let chain5 = with(
            json!({ "act": { "sub": AGENT, "act": { "sub": AGENT2, "act": { "sub": AGENT, "act": { "sub": AGENT2, "act": { "sub": AGENT } } } } } }),
        );
        assert_eq!(
            chain5.validate(now, &a, &t),
            Err(ClaimsError::ActorChainTooLong)
        );

        let big = with(json!({ "cap": { "snapshot": "x".repeat(MAX_CAP_BYTES) } }));
        assert_eq!(big.validate(now, &a, &t), Err(ClaimsError::CapTooLarge));
        // `{"s":"…"}` is 8 bytes plus the string.
        let fits = with(json!({ "cap": { "s": "x".repeat(MAX_CAP_BYTES - 8) } }));
        assert_eq!(fits.cap_size(), Some(MAX_CAP_BYTES));
        assert_eq!(fits.validate(now, &a, &t), Ok(()));

        let wrong_aud = delegated();
        assert_eq!(
            wrong_aud.validate(now, &aud("crm-api"), &t),
            Err(ClaimsError::WrongAudience)
        );

        let with_cnf =
            with(json!({ "cnf": { "x5t#S256": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" } }));
        assert!(with_cnf.cnf.is_some());
        let json = serde_json::to_value(&with_cnf).unwrap();
        assert_eq!(
            json["cnf"]["x5t#S256"],
            json!("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        );

        for (k, bad) in [
            ("cap", json!("not an object")),
            ("cap", json!(null)),
            (
                "act",
                json!("agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102"),
            ),
            ("act", json!({})),
            ("run_id", json!("")),
            ("run_id", json!("run 1")),
            ("run_id", json!("x".repeat(129))),
            ("node_id", json!("step/2")),
            ("cnf", json!({ "x5t#S256": "short" })),
        ] {
            let mut v = base.clone();
            v[k] = bad.clone();
            assert!(
                serde_json::from_value::<DelegatedClaims>(v).is_err(),
                "{k} = {bad}"
            );
        }
        assert!(RunId::parse(&"A.b_c:d-9".repeat(14)).is_ok());
    }

    #[test]
    fn typ_constants() {
        assert_eq!(ACCESS_TOKEN_TYP, "at+jwt");
        assert_eq!(DELEGATED_TOKEN_TYP, "agent+jwt");
        assert_eq!(MAX_TOKEN_BYTES, 8192);
    }
}
