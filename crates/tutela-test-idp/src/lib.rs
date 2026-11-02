//! A test OpenID provider shaped like Keycloak 26, for Tutela's tests and a
//! local demo of the Tutela Console (ADR-0051). **Never** part of
//! `tutelad`: this crate is a dev-dependency of the tests and its own small
//! binary, and it listens on loopback only.
//!
//! It serves one realm at Keycloak's paths, under `/realms/<realm>`:
//!
//! - `/.well-known/openid-configuration`: OIDC discovery;
//! - `/protocol/openid-connect/auth`: the authorization endpoint, a small
//!   form that picks a test person and whether they did MFA (so the `acr`
//!   differs);
//! - `/protocol/openid-connect/token`: `authorization_code` with PKCE S256
//!   verified (a public client), and `refresh_token` with rotation;
//! - `/protocol/openid-connect/certs`: the JWKS (one RS256 key);
//! - `/protocol/openid-connect/logout`: ends the session.
//!
//! Access tokens look like Keycloak's: `typ: JWT`, RS256, `aud` the audience
//! it is set up with (Tutela's `TUTELA_AUDIENCE`, as Keycloak's audience
//! mapper gives), `azp` the client, a `jti`, `sid`, `acr` (`"mfa"` after
//! MFA, else `"1"`), `typ: Bearer`, `scope` and the profile claims.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow, ensure};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// How long an authorization code may be used.
const CODE_TTL: Duration = Duration::from_secs(60);
/// How long a refresh token lasts (Keycloak's SSO idle default).
const REFRESH_TTL: Duration = Duration::from_secs(1800);

/// A test person of the realm.
#[derive(Clone, Debug)]
pub struct Person {
    /// The realm's subject (`sub`), as Keycloak's user id.
    pub sub: String,
    /// The display name (`name`); also the label in the form.
    pub name: String,
}

impl Person {
    /// A person with subject `sub` and name `name`.
    #[must_use]
    pub fn new(sub: &str, name: &str) -> Self {
        Self {
            sub: sub.to_owned(),
            name: name.to_owned(),
        }
    }

    fn username(&self) -> String {
        self.name.to_lowercase().replace(' ', ".")
    }
}

/// How the provider is set up.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Where it listens: a loopback address only.
    pub listen: SocketAddr,
    /// The realm's name, in its paths and its issuer.
    pub realm: String,
    /// The `aud` of access tokens: `tutelad`'s `TUTELA_AUDIENCE`.
    pub audience: String,
    /// The one public client.
    pub client_id: String,
    /// The client's redirect URIs, matched exactly.
    pub redirect_uris: Vec<String>,
    /// Where `logout` may send the browser back to, matched exactly.
    pub post_logout_redirect_uris: Vec<String>,
    /// The people of the realm.
    pub people: Vec<Person>,
    /// The `acr` after MFA (a step-up value of `TUTELA_ADMIN_ACR`).
    pub step_up_acr: String,
    /// The `acr` without MFA (Keycloak's `"1"`).
    pub plain_acr: String,
    /// The life of an access token (Keycloak's default is 300 s).
    pub access_ttl: Duration,
}

impl Settings {
    /// Settings for a realm `tutela` on `127.0.0.1` at any free port, with
    /// `audience`, the client `tutela-console` and no redirect URI yet.
    #[must_use]
    pub fn new(audience: &str) -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            realm: "tutela".to_owned(),
            audience: audience.to_owned(),
            client_id: "tutela-console".to_owned(),
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            people: Vec::new(),
            step_up_acr: "mfa".to_owned(),
            plain_acr: "1".to_owned(),
            access_ttl: Duration::from_secs(300),
        }
    }
}

/// A code waiting for the token endpoint.
#[derive(Clone, Debug)]
struct Grant {
    redirect_uri: String,
    challenge: String,
    nonce: Option<String>,
    sub: String,
    acr: String,
    scope: String,
    auth_time: u64,
    made: Instant,
}

/// A signed-in session, behind a refresh token.
#[derive(Clone, Debug)]
struct Session {
    sid: String,
    sub: String,
    acr: String,
    scope: String,
    auth_time: u64,
    made: Instant,
}

struct Realm {
    settings: Settings,
    issuer: String,
    key: KeyPair,
    kid: String,
    jwks: Value,
    codes: Mutex<HashMap<String, Grant>>,
    refresh: Mutex<HashMap<String, Session>>,
}

/// The running provider.
#[derive(Debug)]
pub struct Running {
    addr: SocketAddr,
    issuer: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Running {
    /// The address it listens on.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The realm's issuer: `http://<addr>/realms/<realm>`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The realm's JWKS URL (Keycloak's path).
    #[must_use]
    pub fn jwks_uri(&self) -> String {
        format!("{}/protocol/openid-connect/certs", self.issuer)
    }

    /// Stops it and waits.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}

/// Starts the provider.
///
/// # Errors
///
/// An address that is not loopback, a port that cannot be bound, or a key
/// that cannot be made.
pub async fn start(settings: Settings) -> anyhow::Result<Running> {
    ensure!(
        settings.listen.ip().is_loopback(),
        "the test OpenID provider listens on loopback only"
    );
    ensure!(
        !settings.realm.is_empty()
            && settings
                .realm
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "a realm name is letters, digits and '-'"
    );
    let listener = tokio::net::TcpListener::bind(settings.listen)
        .await
        .with_context(|| format!("binding {}", settings.listen))?;
    let addr = listener.local_addr()?;
    let issuer = format!("http://{addr}/realms/{}", settings.realm);
    let key = KeyPair::generate(KeySize::Rsa2048).map_err(|_| anyhow!("making an RSA key"))?;
    let n = B64.encode(key.public_key().modulus().big_endian_without_leading_zero());
    let e = B64.encode(
        key.public_key()
            .exponent()
            .big_endian_without_leading_zero(),
    );
    // RFC 7638 thumbprint, as a kid.
    let kid = B64.encode(digest(
        &SHA256,
        format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#).as_bytes(),
    ));
    let jwks = json!({"keys": [{
        "kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e,
    }]});
    let realm = Arc::new(Realm {
        issuer: issuer.clone(),
        key,
        kid,
        jwks,
        codes: Mutex::new(HashMap::new()),
        refresh: Mutex::new(HashMap::new()),
        settings,
    });
    let base = format!("/realms/{}", realm.settings.realm);
    let app = Router::new()
        .route(
            &format!("{base}/.well-known/openid-configuration"),
            get(discovery),
        )
        .route(
            &format!("{base}/protocol/openid-connect/auth"),
            get(authorize_form).post(authorize),
        )
        .route(
            &format!("{base}/protocol/openid-connect/token"),
            axum::routing::post(token).options(preflight),
        )
        .route(&format!("{base}/protocol/openid-connect/certs"), get(certs))
        .route(
            &format!("{base}/protocol/openid-connect/logout"),
            get(logout),
        )
        .with_state(realm);
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await;
    });
    Ok(Running {
        addr,
        issuer,
        stop,
        task,
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn random() -> String {
    let mut b = [0_u8; 32];
    // The system source does not fail on the platforms the tests run on;
    // a zero buffer would still be refused by nothing, so log it.
    if SystemRandom::new().fill(&mut b).is_err() {
        eprintln!("tutela-test-idp: the random source failed");
    }
    B64.encode(b)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

impl Realm {
    fn sign(&self, header_typ: &str, claims: &Value) -> Result<String, StatusCode> {
        let header = json!({"alg": "RS256", "typ": header_typ, "kid": self.kid});
        let msg = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let mut sig = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                msg.as_bytes(),
                &mut sig,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(format!("{msg}.{}", B64.encode(sig)))
    }

    fn person(&self, sub: &str) -> Option<&Person> {
        self.settings.people.iter().find(|p| p.sub == sub)
    }

    /// The origins of the client's redirect URIs: Keycloak's web origins.
    fn allowed_origin(&self, headers: &HeaderMap) -> Option<HeaderValue> {
        let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
        self.settings
            .redirect_uris
            .iter()
            .any(|u| origin_of(u) == Some(origin))
            .then(|| HeaderValue::from_str(origin).ok())
            .flatten()
    }

    /// The tokens of a session: access, ID and a new refresh token.
    fn tokens(&self, s: &Session, nonce: Option<&str>) -> Result<Value, StatusCode> {
        let now = now();
        let person = self.person(&s.sub).ok_or(StatusCode::BAD_REQUEST)?;
        let ttl = self.settings.access_ttl.as_secs();
        let origins: Vec<&str> = self
            .settings
            .redirect_uris
            .iter()
            .filter_map(|u| origin_of(u))
            .collect();
        let access = json!({
            "exp": now + ttl, "iat": now, "auth_time": s.auth_time,
            "jti": format!("onrtac:{}", uuid::Uuid::now_v7()),
            "iss": self.issuer, "aud": self.settings.audience, "sub": s.sub,
            "typ": "Bearer", "azp": self.settings.client_id, "sid": s.sid,
            "acr": s.acr, "allowed-origins": origins,
            "realm_access": {"roles": ["default-roles-tutela", "offline_access", "uma_authorization"]},
            "scope": s.scope, "email_verified": true, "name": person.name,
            "preferred_username": person.username(),
            "email": format!("{}@example.test", person.username()),
        });
        let mut id = json!({
            "exp": now + ttl, "iat": now, "auth_time": s.auth_time,
            "jti": format!("onrtid:{}", uuid::Uuid::now_v7()),
            "iss": self.issuer, "aud": self.settings.client_id, "sub": s.sub,
            "typ": "ID", "azp": self.settings.client_id, "sid": s.sid, "acr": s.acr,
            "name": person.name, "preferred_username": person.username(),
        });
        if let (Some(n), Some(obj)) = (nonce, id.as_object_mut()) {
            obj.insert("nonce".to_owned(), Value::from(n));
        }
        let refresh = random();
        self.refresh
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .insert(refresh.clone(), s.clone());
        Ok(json!({
            "access_token": self.sign("JWT", &access)?,
            "expires_in": ttl,
            "refresh_expires_in": REFRESH_TTL.as_secs(),
            "refresh_token": refresh,
            "token_type": "Bearer",
            "id_token": self.sign("JWT", &id)?,
            "not-before-policy": 0,
            "session_state": s.sid,
            "scope": s.scope,
        }))
    }
}

/// `scheme://host:port` of a URL.
fn origin_of(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find('/').map_or(url.len(), |i| scheme.len() + 3 + i);
    url.get(..end)
}

async fn discovery(State(r): State<Arc<Realm>>, headers: HeaderMap) -> Response {
    let i = &r.issuer;
    let body = json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/protocol/openid-connect/auth"),
        "token_endpoint": format!("{i}/protocol/openid-connect/token"),
        "jwks_uri": format!("{i}/protocol/openid-connect/certs"),
        "end_session_endpoint": format!("{i}/protocol/openid-connect/logout"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "acr_values_supported": [r.settings.plain_acr, r.settings.step_up_acr],
        "scopes_supported": ["openid", "profile", "email"],
        "authorization_response_iss_parameter_supported": true,
    });
    with_cors(&r, &headers, Json(body).into_response())
}

async fn certs(State(r): State<Arc<Realm>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        r.jwks.to_string(),
    )
        .into_response()
}

fn with_cors(r: &Realm, headers: &HeaderMap, mut res: Response) -> Response {
    if let Some(origin) = r.allowed_origin(headers) {
        let h = res.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        h.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    res
}

async fn preflight(State(r): State<Arc<Realm>>, headers: HeaderMap) -> Response {
    let mut res = with_cors(&r, &headers, StatusCode::NO_CONTENT.into_response());
    let h = res.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    res
}

/// The parameters of an authorization request.
#[derive(Debug, Default, Deserialize)]
struct AuthParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    acr_values: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    // The form's own fields.
    person: Option<String>,
    mfa: Option<String>,
}

/// An authorization error: shown on a page before the redirect URI is
/// known to be the client's, sent back to it after.
enum AuthError {
    Page(String),
    Redirect(String, &'static str, String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            Self::Page(text) => (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<!doctype html><title>Sign-in error</title><h1>Sign-in error</h1><p>{}</p>",
                    html_escape(&text)
                )),
            )
                .into_response(),
            Self::Redirect(uri, error, state) => {
                let q = serde_urlencoded::to_string([("error", error), ("state", &state)])
                    .unwrap_or_default();
                redirect(&format!("{uri}?{q}"))
            }
        }
    }
}

fn redirect(to: &str) -> Response {
    match HeaderValue::from_str(to) {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

fn pkce_ok(s: &str) -> bool {
    (43..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Checks an authorization request: the client and its exact redirect URI
/// first (else a page), then the rest (else back to the client).
fn check(r: &Realm, p: &AuthParams) -> Result<(String, String, String), AuthError> {
    if p.client_id.as_deref() != Some(r.settings.client_id.as_str()) {
        return Err(AuthError::Page("Client not found.".to_owned()));
    }
    let uri = p.redirect_uri.clone().unwrap_or_default();
    if !r.settings.redirect_uris.contains(&uri) {
        return Err(AuthError::Page(
            "Invalid parameter: redirect_uri".to_owned(),
        ));
    }
    let state = p.state.clone().unwrap_or_default();
    let fail = |e| Err(AuthError::Redirect(uri.clone(), e, state.clone()));
    if state.is_empty() {
        return fail("invalid_request");
    }
    if p.response_type.as_deref() != Some("code") {
        return fail("unsupported_response_type");
    }
    if !p
        .scope
        .as_deref()
        .unwrap_or_default()
        .split(' ')
        .any(|s| s == "openid")
    {
        return fail("invalid_scope");
    }
    if p.code_challenge_method.as_deref() != Some("S256")
        || !p
            .code_challenge
            .as_deref()
            .is_some_and(|c| c.len() == 43 && pkce_ok(c))
    {
        // PKCE S256 is required; `plain` is refused (TM-07).
        return fail("invalid_request");
    }
    Ok((uri, state, p.code_challenge.clone().unwrap_or_default()))
}

async fn authorize_form(State(r): State<Arc<Realm>>, Query(p): Query<AuthParams>) -> Response {
    if let Err(e) = check(&r, &p) {
        return e.into_response();
    }
    let hidden: String = [
        ("response_type", &p.response_type),
        ("client_id", &p.client_id),
        ("redirect_uri", &p.redirect_uri),
        ("scope", &p.scope),
        ("state", &p.state),
        ("nonce", &p.nonce),
        ("code_challenge", &p.code_challenge),
        ("code_challenge_method", &p.code_challenge_method),
    ]
    .iter()
    .filter_map(|(k, v)| {
        v.as_ref().map(|v| {
            format!(
                r#"<input type="hidden" name="{k}" value="{}">"#,
                html_escape(v)
            )
        })
    })
    .collect();
    let people: String = r
        .settings
        .people
        .iter()
        .enumerate()
        .map(|(i, person)| {
            format!(
                r#"<p><label><input type="radio" name="person" value="{}"{}> {}</label></p>"#,
                html_escape(&person.sub),
                if i == 0 { " checked" } else { "" },
                html_escape(&person.name)
            )
        })
        .collect();
    let asks_mfa = p
        .acr_values
        .as_deref()
        .unwrap_or_default()
        .split(' ')
        .any(|a| a == r.settings.step_up_acr);
    let page = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in to {realm}</title></head>
<body>
<main>
<h1>Sign in to {realm}</h1>
<p>Test OpenID provider. Pick a test person.</p>
<form method="post">
{hidden}
<fieldset><legend>Person</legend>
{people}
</fieldset>
<p><label><input type="checkbox" name="mfa" value="1"{mfa}> Use MFA (acr "{acr}")</label></p>
<p><button type="submit">Sign in</button></p>
</form>
</main>
</body></html>"#,
        realm = html_escape(&r.settings.realm),
        mfa = if asks_mfa { " checked" } else { "" },
        acr = html_escape(&r.settings.step_up_acr),
    );
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

async fn authorize(State(r): State<Arc<Realm>>, Form(p): Form<AuthParams>) -> Response {
    let (uri, state, challenge) = match check(&r, &p) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let Some(sub) = p.person.clone().filter(|s| r.person(s).is_some()) else {
        return AuthError::Redirect(uri, "access_denied", state).into_response();
    };
    let acr = if p.mfa.is_some() {
        r.settings.step_up_acr.clone()
    } else {
        r.settings.plain_acr.clone()
    };
    let code = random();
    let grant = Grant {
        redirect_uri: uri.clone(),
        challenge,
        nonce: p.nonce.clone(),
        sub,
        acr,
        scope: p.scope.clone().unwrap_or_default(),
        auth_time: now(),
        made: Instant::now(),
    };
    let Ok(mut codes) = r.codes.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    codes.insert(code.clone(), grant);
    drop(codes);
    let session_state = uuid::Uuid::now_v7().to_string();
    let q = serde_urlencoded::to_string([
        ("state", state.as_str()),
        ("session_state", session_state.as_str()),
        ("iss", r.issuer.as_str()),
        ("code", code.as_str()),
    ])
    .unwrap_or_default();
    let _ = (&p.prompt, &p.max_age);
    redirect(&format!("{uri}?{q}"))
}

/// The token endpoint's form.
#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

async fn token(
    State(r): State<Arc<Realm>>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Response {
    let res = token_answer(&r, f);
    with_cors(&r, &headers, res)
}

fn token_answer(r: &Realm, f: TokenForm) -> Response {
    if f.client_id.as_deref() != Some(r.settings.client_id.as_str()) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Invalid client or Invalid client credentials",
        );
    }
    let session = match f.grant_type.as_deref() {
        Some("authorization_code") => {
            // A code is used once: it is taken out before it is checked.
            let grant = r
                .codes
                .lock()
                .ok()
                .and_then(|mut c| f.code.as_deref().and_then(|code| c.remove(code)));
            let Some(g) = grant.filter(|g| g.made.elapsed() <= CODE_TTL) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Code not valid");
            };
            if f.redirect_uri.as_deref() != Some(g.redirect_uri.as_str()) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Incorrect redirect_uri",
                );
            }
            let verified = f.code_verifier.as_deref().is_some_and(|v| {
                pkce_ok(v) && B64.encode(digest(&SHA256, v.as_bytes())) == g.challenge
            });
            if !verified {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed: Code mismatch",
                );
            }
            let s = Session {
                sid: uuid::Uuid::now_v7().to_string(),
                sub: g.sub,
                acr: g.acr,
                scope: g.scope,
                auth_time: g.auth_time,
                made: Instant::now(),
            };
            return match r.tokens(&s, g.nonce.as_deref()) {
                Ok(t) => ([(header::CACHE_CONTROL, "no-store")], Json(t)).into_response(),
                Err(code) => code.into_response(),
            };
        }
        Some("refresh_token") => {
            // A refresh token is used once: the answer has the next one.
            let s = r
                .refresh
                .lock()
                .ok()
                .and_then(|mut m| f.refresh_token.as_deref().and_then(|t| m.remove(t)));
            match s.filter(|s| s.made.elapsed() <= REFRESH_TTL) {
                Some(s) => s,
                None => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Invalid refresh token",
                    );
                }
            }
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Unsupported grant_type",
            );
        }
    };
    match r.tokens(&session, None) {
        Ok(t) => ([(header::CACHE_CONTROL, "no-store")], Json(t)).into_response(),
        Err(code) => code.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct LogoutParams {
    post_logout_redirect_uri: Option<String>,
    client_id: Option<String>,
}

async fn logout(State(r): State<Arc<Realm>>, Query(p): Query<LogoutParams>) -> Response {
    let _ = &p.client_id;
    match p.post_logout_redirect_uri {
        Some(uri) if r.settings.post_logout_redirect_uris.contains(&uri) => redirect(&uri),
        Some(_) => AuthError::Page("Invalid redirect uri".to_owned()).into_response(),
        None => Html("<!doctype html><title>Signed out</title><p>You are signed out.</p>")
            .into_response(),
    }
}
