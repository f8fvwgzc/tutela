//! Token exchange (RFC 8693) at `POST /oauth2/token` (ADR-0031,
//! CONTRACTS.md 4.8).
//!
//! A trusted token comes in as `subject_token`; a short-lived Tutela access
//! token for one registered `audience` goes out, signed by the service's own
//! issuer ([`crate::keys`]).
//!
//! - **An external issuer's token** (Keycloak or any issuer of the trust
//!   file with `external = true`): the tenant is the one the trust file maps
//!   that issuer to, under this service's issuer, never one the request
//!   names. The person is found by the upstream `(iss, sub)` and made the
//!   first time (just-in-time provisioning), never by e-mail. Each such token
//!   is exchanged once.
//! - **A token of this service**: exchanged again for another audience. The
//!   new token never outlives it and never names another principal or
//!   tenant.
//! - **Any other issuer's token** is refused: its tenant is not this
//!   service's to issue for.
//!
//! Every refusal of the subject token is `invalid_grant`, and says nothing
//! of which check failed; the log names it, never the token. Metrics count
//! each request by the kind of token asked for and how it ended.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tutela_contracts::claims::{
    AccessTokenClaims, Audience, AudienceClaim, ClientId, MAX_ACCESS_TOKEN_LIFETIME_SECS, Scope,
};
use tutela_contracts::id::{SessionId, Uuid7};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TrustList;
use tutela_sdk::{
    CacheRules, Clock, ExternalToken, Identity, JwksSource, Verifier, VerifierConfig,
};
use tutela_store::StoreErrorKind;

use crate::api::AppState;
use crate::config::Config;
use crate::db::{DbError, TenantTx};
use crate::keys::{KeyError, KeyRing, OwnJwks};
use crate::tenant::Tenant;

/// The token endpoint. It needs no bearer token: the subject token is the
/// credential.
pub const TOKEN_PATH: &str = "/oauth2/token";
/// The authorization server metadata (RFC 8414).
pub const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
/// RFC 8693's grant type.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// An access token, as a token type.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// A JWT, as a token type.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
/// The longest request body: two tokens of 8 KiB and a `cap` of 4 KiB,
/// form-encoded.
pub const BODY_LIMIT: usize = 64 * 1024;
/// `amr` when the external issuer did not say how the person signed in.
/// It is never a step-up method.
pub const AMR_EXTERNAL: &str = "ext";

/// One audience `tutelad` issues tokens for.
#[derive(Debug)]
pub struct Registered {
    /// It accepts delegated (`agent+jwt`) tokens.
    pub delegation_aware: bool,
    /// The verifier for this service's own tokens of this audience, when
    /// they come back to be exchanged again. `None` for the service's own
    /// audience, which the main verifier checks.
    verifier: Option<Arc<Verifier>>,
}

/// The audiences `tutelad` issues for, and how.
#[derive(Debug)]
pub struct Audiences {
    own: Audience,
    entries: HashMap<Audience, Registered>,
    /// The own issuer, for the check of what is issued.
    trust: TrustList,
    /// `TUTELA_TOKEN_TTL_SECS`.
    token_ttl: Duration,
}

impl Audiences {
    /// From the config: the service's own audience, and the trust file's
    /// `[[audience]]` entries. A verifier per registered audience reads the
    /// service's own tokens of it from `ring`.
    #[must_use]
    pub fn new(
        config: &Config,
        ring: &Arc<KeyRing>,
        other: &Arc<dyn JwksSource>,
        clock: &Arc<dyn Clock>,
    ) -> Self {
        let mut trust = if config.dev_mode {
            TrustList::dev_mode()
        } else {
            TrustList::new()
        };
        if trust.insert_directory(config.issuer.clone()).is_err() {
            tracing::error!("the own issuer could not be trusted");
        }
        let own_issuer = config
            .verifier_config()
            .issuers
            .into_iter()
            .find(|i| i.iss == config.issuer);
        let mut entries = HashMap::new();
        entries.insert(
            config.audience.clone(),
            Registered {
                delegation_aware: false,
                verifier: None,
            },
        );
        for entry in &config.trust.audience {
            let verifier = own_issuer.as_ref().map(|i| {
                Arc::new(Verifier::with(
                    VerifierConfig {
                        audience: entry.name.clone(),
                        trust: trust.clone(),
                        issuers: vec![i.clone()],
                        delegation: entry.delegation_aware,
                        delegation_aware: entry.delegation_aware,
                        denied_kids: std::collections::HashSet::new(),
                        cache: CacheRules::default(),
                    },
                    Arc::new(OwnJwks::new(Arc::clone(ring), Arc::clone(other))),
                    Arc::clone(clock),
                ))
            });
            entries.insert(
                entry.name.clone(),
                Registered {
                    delegation_aware: entry.delegation_aware,
                    verifier,
                },
            );
        }
        Self {
            own: config.audience.clone(),
            entries,
            trust,
            token_ttl: config.token_ttl,
        }
    }

    /// The registered audience `aud`.
    #[must_use]
    pub fn get(&self, aud: &Audience) -> Option<&Registered> {
        self.entries.get(aud)
    }

    /// Every verifier of the service's own tokens by audience, for the
    /// key job's deny-list.
    pub fn verifiers(&self) -> impl Iterator<Item = &Arc<Verifier>> {
        self.entries.values().filter_map(|r| r.verifier.as_ref())
    }
}

// ---------- The wire ----------

/// The form of a token request (RFC 8693 2.1). It has no `Debug`: it holds
/// tokens. A parameter sent twice fails the parse (RFC 6749 3.2); one this
/// service does not know is ignored.
#[derive(Deserialize, Default)]
pub struct TokenRequest {
    grant_type: Option<String>,
    resource: Option<String>,
    audience: Option<String>,
    scope: Option<String>,
    requested_token_type: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    actor_token: Option<String>,
    actor_token_type: Option<String>,
}

/// A token response (RFC 8693 2.2.1).
#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// A refused request (RFC 6749 5.2, RFC 8693 2.2.2). The description is a
/// fixed text: never a token, a claim or a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    status: StatusCode,
    /// The OAuth error code, also the metric's outcome.
    pub error: &'static str,
    description: &'static str,
    /// For the log: which check refused, when it was the subject token.
    pub reason: &'static str,
}

impl Refusal {
    const fn new(error: &'static str, description: &'static str, reason: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error,
            description,
            reason,
        }
    }

    const fn request(description: &'static str) -> Self {
        Self::new("invalid_request", description, "request")
    }

    const fn target(description: &'static str) -> Self {
        Self::new("invalid_target", description, "audience")
    }

    /// The subject or actor token cannot be used. One text for every reason.
    const fn grant(reason: &'static str) -> Self {
        Self::new("invalid_grant", "the token cannot be exchanged", reason)
    }

    const fn unavailable(reason: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "temporarily_unavailable",
            description: "no token can be issued now",
            reason,
        }
    }
}

impl From<DbError> for Refusal {
    fn from(e: DbError) -> Self {
        if e.store_kind() == Some(StoreErrorKind::UnknownTenant) {
            return Self::grant("tenant");
        }
        tracing::error!(
            error = %e,
            kind = ?e.store_kind(),
            sqlstate = e.sqlstate(),
            "a database call failed during an exchange"
        );
        Self::unavailable("database")
    }
}

impl From<tutela_store::StoreError> for Refusal {
    fn from(e: tutela_store::StoreError) -> Self {
        DbError::from(e).into()
    }
}

impl From<KeyError> for Refusal {
    fn from(e: KeyError) -> Self {
        tracing::error!(error = %e, "no token could be signed");
        Self::unavailable("signing")
    }
}

fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.error,
            "error_description": self.description,
        });
        no_store((self.status, axum::Json(body)).into_response())
    }
}

// ---------- The exchange ----------

/// What kind of token was asked for: the metric's operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An access token.
    Access,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
        }
    }
}

/// The person or service a subject token stands for, in this service's
/// tenant.
struct Subject {
    principal: Principal,
    epoch: u64,
    sid: Option<SessionId>,
    amr: Option<Vec<String>>,
    acr: Option<String>,
    azp: ClientId,
    scope: Option<Scope>,
    /// The issued token never outlives this.
    exp: u64,
}

/// The claims of an external token that the SDK does not keep: they were
/// signed with the rest, and are read only after the signature passed.
#[derive(Deserialize)]
struct Upstream {
    jti: Option<String>,
    acr: Option<String>,
    amr: Option<Vec<String>>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The payload of a JWT, before or after its signature was checked. Before,
/// it only picks the verifier; nothing in it is trusted.
fn payload<T: for<'de> Deserialize<'de>>(token: &str) -> Option<T> {
    let p = token.split('.').nth(1)?;
    serde_json::from_slice(&B64.decode(p).ok()?).ok()
}

#[derive(Deserialize)]
struct AudOnly {
    aud: Option<serde_json::Value>,
}

/// The one audience a token names, unverified.
fn peek_audience(token: &str) -> Option<String> {
    match payload::<AudOnly>(token)?.aud? {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Array(a) if a.len() == 1 => a.first()?.as_str().map(str::to_owned),
        _ => None,
    }
}

fn visible(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Checks the token-type parameters.
fn token_type(t: Option<&str>) -> Result<(), Refusal> {
    match t {
        Some(ACCESS_TOKEN_TYPE | JWT_TOKEN_TYPE) => Ok(()),
        Some(_) => Err(Refusal::request(
            "a token type is an access token or a JWT; an ID token is never accepted",
        )),
        None => Err(Refusal::request("the token type is required")),
    }
}

/// Verifies the subject token with the verifier of the audience it names.
async fn verify(state: &AppState, token: &str) -> Result<Identity, Refusal> {
    let verifier = match peek_audience(token) {
        Some(a) if a == state.audiences.own.as_str() => Arc::clone(&state.verifier),
        Some(a) => a
            .parse::<Audience>()
            .ok()
            .and_then(|a| state.audiences.get(&a))
            .and_then(|r| r.verifier.clone())
            .ok_or(Refusal::grant("audience"))?,
        None => return Err(Refusal::grant("audience")),
    };
    verifier.verify(token).await.map_err(|e| {
        tracing::info!(step = e.step().as_str(), "a subject token failed a step");
        Refusal::grant(e.step().as_str())
    })
}

/// A person of an external issuer, provisioned in the tenant that issuer
/// logs people in for, under this service's issuer, in `tx`. The token is
/// noted in `tx`, so it is exchanged once; nothing of this stays unless the
/// caller commits after the new token is signed.
async fn external(tx: &TenantTx<'_>, t: &ExternalToken, token: &str) -> Result<Subject, Refusal> {
    let up: Upstream = payload(token).ok_or(Refusal::grant("claims"))?;
    let jti = up
        .jti
        .filter(|j| visible(j, 255))
        .ok_or(Refusal::grant("jti"))?;
    let acr = match up.acr {
        Some(a) if visible(&a, 64) => Some(a),
        Some(_) => return Err(Refusal::grant("acr")),
        None => None,
    };
    let amr = match up.amr {
        Some(m) if m.is_empty() => vec![AMR_EXTERNAL.to_owned()],
        Some(m) if m.len() <= 16 && m.iter().all(|v| visible(v, 32)) => m,
        Some(_) => return Err(Refusal::grant("amr")),
        None => vec![AMR_EXTERNAL.to_owned()],
    };
    let azp = t
        .azp
        .as_deref()
        .and_then(|a| ClientId::parse(a).ok())
        .ok_or(Refusal::grant("azp"))?;
    let key = tx.tenant();
    let expires = UNIX_EPOCH + Duration::from_secs(t.exp);
    if !tutela_store::note_exchange(tx, key, &t.tenant.iss, &jti, expires).await? {
        return Err(Refusal::grant("replayed"));
    }
    let person = tutela_store::provision_user(tx, key, &t.tenant.iss, &t.sub).await?;
    if person.disabled {
        return Err(Refusal::grant("disabled"));
    }
    let sid = format!("ses_{}", new_id()?)
        .parse()
        .map_err(|_| Refusal::unavailable("id"))?;
    Ok(Subject {
        principal: person.principal,
        epoch: person.epoch,
        sid: Some(sid),
        amr: Some(amr),
        acr,
        azp,
        scope: None,
        exp: t.exp,
    })
}

/// A token this service issued, for another audience. The principal's
/// epoch is read again in `tx`: a token issued before a revocation is
/// never exchanged.
async fn own(tx: &TenantTx<'_>, c: &AccessTokenClaims) -> Result<Subject, Refusal> {
    let known = tutela_store::principal_state(tx, tx.tenant(), &c.sub).await?;
    if known.is_some_and(|s| s.disabled || c.epoch < s.epoch) {
        return Err(Refusal::grant("epoch"));
    }
    Ok(Subject {
        principal: c.sub.clone(),
        epoch: c.epoch,
        sid: c.sid,
        amr: c.amr.clone(),
        acr: c.acr.clone(),
        azp: c.azp.clone(),
        scope: c.scope.clone(),
        exp: c.exp,
    })
}

fn new_id() -> Result<Uuid7, Refusal> {
    Uuid7::from_uuid(uuid::Uuid::now_v7()).map_err(|_| Refusal::unavailable("id"))
}

/// Scopes only narrow: every asked scope must be in the subject's, when it
/// has any.
fn scope(asked: Option<&str>, held: Option<&Scope>) -> Result<Option<Scope>, Refusal> {
    let invalid = Refusal::new("invalid_scope", "the scope is not valid here", "scope");
    let Some(asked) = asked else {
        return Ok(held.cloned());
    };
    let asked = Scope::parse(asked).map_err(|_| invalid)?;
    if let Some(held) = held
        && !asked.tokens().all(|t| held.tokens().any(|h| h == t))
    {
        return Err(invalid);
    }
    Ok(Some(asked))
}

/// What was issued.
pub struct Issued {
    response: TokenResponse,
    jti: Uuid7,
}

/// The exchange.
///
/// # Errors
///
/// A [`Refusal`]: what to answer, with the reason for the log.
pub async fn exchange(state: &AppState, req: TokenRequest) -> Result<Issued, Refusal> {
    match req.grant_type.as_deref() {
        Some(GRANT_TYPE) => {}
        Some(_) => {
            return Err(Refusal::new(
                "unsupported_grant_type",
                "only token exchange is served here",
                "grant",
            ));
        }
        None => return Err(Refusal::request("grant_type is required")),
    }
    if req.resource.is_some() {
        return Err(Refusal::target(
            "name the service with `audience`, not `resource`",
        ));
    }
    let audience: Audience = req
        .audience
        .as_deref()
        .ok_or(Refusal::request("audience is required"))?
        .parse()
        .map_err(|_| Refusal::target("the audience is not registered"))?;
    state
        .audiences
        .get(&audience)
        .ok_or(Refusal::target("the audience is not registered"))?;
    match req.requested_token_type.as_deref() {
        None | Some(ACCESS_TOKEN_TYPE | JWT_TOKEN_TYPE) => {}
        Some(_) => return Err(Refusal::request("only an access token can be issued")),
    }
    let subject_token = req
        .subject_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or(Refusal::request("subject_token is required"))?;
    token_type(req.subject_token_type.as_deref())?;
    if req.actor_token.is_some() || req.actor_token_type.is_some() {
        return Err(Refusal::request("delegation is not served yet"));
    }

    let id = verify(state, subject_token).await?;
    let tenant = match &id {
        Identity::External(t) => Tenant::exchanged(state.keys.iss(), t),
        Identity::Access(c) if c.iss == *state.keys.iss() => Tenant::of(&id),
        _ => return Err(Refusal::grant("issuer")),
    };
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let subject = match &id {
        Identity::External(t) => external(&tx, t, subject_token).await?,
        Identity::Access(c) => own(&tx, c).await?,
        _ => return Err(Refusal::grant("issuer")),
    };
    let scope = scope(req.scope.as_deref(), subject.scope.as_ref())?;

    let now = now_secs();
    let exp = subject.exp.min(
        now + state
            .audiences
            .token_ttl
            .as_secs()
            .min(MAX_ACCESS_TOKEN_LIFETIME_SECS),
    );
    if exp <= now {
        return Err(Refusal::grant("expired"));
    }
    let key = tenant.key();
    let rev = tutela_store::rev(&tx, key).await?;
    let user = subject.principal.kind() == tutela_contracts::principal::PrincipalKind::User;
    let claims = AccessTokenClaims {
        iss: key.iss.clone(),
        sub: subject.principal,
        aud: AudienceClaim::one(audience.clone()),
        azp: subject.azp,
        exp,
        iat: now,
        nbf: now,
        jti: new_id()?,
        sid: if user { subject.sid } else { None },
        tid: key.tid,
        org: None,
        epoch: subject.epoch,
        rev,
        scope: scope.clone(),
        amr: if user { subject.amr } else { None },
        acr: subject.acr,
        act: None,
    };
    // What is issued passes the checks every verifier runs.
    claims
        .validate(now, &audience, &state.audiences.trust)
        .map_err(|e| {
            tracing::error!(error = %e, "an issued token would not verify");
            Refusal::unavailable("claims")
        })?;
    let access_token = state.keys.sign_jwt("at+jwt", &claims)?;
    // Only now is the subject token used up and the person made.
    tx.commit().await?;
    Ok(Issued {
        jti: claims.jti,
        response: TokenResponse {
            access_token,
            issued_token_type: ACCESS_TOKEN_TYPE,
            token_type: "Bearer",
            expires_in: exp - now,
            scope: scope.map(|s| s.to_string()),
        },
    })
}

/// `POST /oauth2/token`: an `application/x-www-form-urlencoded` body
/// (RFC 6749 3.2).
pub async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let kind = Kind::Access;
    let form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';').next().is_some_and(|m| {
                m.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        });
    let parsed = if form {
        serde_urlencoded::from_bytes::<TokenRequest>(&body)
            .map_err(|_| Refusal::request("the form does not parse, or a parameter is repeated"))
    } else {
        Err(Refusal::request(
            "the body is application/x-www-form-urlencoded",
        ))
    };
    let result = match parsed {
        Ok(req) => exchange(&state, req).await,
        Err(e) => Err(e),
    };
    match result {
        Ok(issued) => {
            state.metrics.count_token(kind.as_str(), "issued");
            tracing::info!(op = kind.as_str(), jti = %issued.jti, "token issued");
            no_store((StatusCode::OK, axum::Json(issued.response)).into_response())
        }
        Err(refusal) => {
            state.metrics.count_token(kind.as_str(), refusal.error);
            tracing::info!(
                op = kind.as_str(),
                outcome = refusal.error,
                reason = refusal.reason,
                "token refused"
            );
            refusal.into_response()
        }
    }
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414): where the token
/// endpoint and the JWKS are.
pub async fn metadata(State(state): State<AppState>) -> Response {
    let iss = state.keys.iss().as_str();
    axum::Json(serde_json::json!({
        "issuer": iss,
        "token_endpoint": format!("{iss}{TOKEN_PATH}"),
        "jwks_uri": state.keys.jwks_url(),
        "grant_types_supported": [GRANT_TYPE],
        "token_endpoint_auth_methods_supported": ["none"],
        "response_types_supported": [],
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_only_narrow() {
        let held = Scope::parse("a b").unwrap();
        assert_eq!(scope(None, Some(&held)).unwrap(), Some(held.clone()));
        assert_eq!(
            scope(Some("a"), Some(&held)).unwrap().unwrap().as_str(),
            "a"
        );
        assert_eq!(
            scope(Some("a c"), Some(&held)).unwrap_err().error,
            "invalid_scope"
        );
        assert_eq!(
            scope(Some("a  b"), None).unwrap_err().error,
            "invalid_scope"
        );
        assert!(scope(Some("x"), None).is_ok());
    }

    #[test]
    fn the_audience_is_peeked_from_a_string_or_a_one_element_array() {
        let tok = |aud: serde_json::Value| {
            format!(
                "e30.{}.sig",
                B64.encode(serde_json::json!({ "aud": aud }).to_string())
            )
        };
        assert_eq!(peek_audience(&tok("a".into())).as_deref(), Some("a"));
        assert_eq!(
            peek_audience(&tok(serde_json::json!(["a"]))).as_deref(),
            Some("a")
        );
        assert_eq!(peek_audience(&tok(serde_json::json!(["a", "b"]))), None);
        assert_eq!(peek_audience("not a token"), None);
    }
}
