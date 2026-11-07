//! Token exchange against a real Keycloak 26 (#87, ADR-0057): real access
//! tokens, from sign-ins at Keycloak's own login and OTP pages, exchanged at
//! `POST /oauth2/token` of a real `tutelad` on a real Postgres that fetches
//! the realm's JWKS over HTTP through `tutela-safenet`.
//!
//! `scripts/keycloak-check.mjs` (`make keycloak`) starts the pinned Keycloak
//! image, makes the realm (the step-up browser flow, people with known TOTP
//! secrets), imports the Console's client from the Helm chart, and runs this
//! with `TUTELA_KEYCLOAK_FIXTURE` naming what it made. Without it the test
//! says it is skipped; the script fails instead when
//! `TUTELA_REQUIRE_KEYCLOAK=1` and Keycloak cannot run.
#![cfg(test)]

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_lc_rs::{digest, hmac, rand::SecureRandom as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutelad::config::TrustFile;

use common::{AUD, MANIFEST, OWN_ISS, USER, ask, now};

const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

fn fixture() -> Option<Value> {
    let Ok(path) = std::env::var("TUTELA_KEYCLOAK_FIXTURE") else {
        eprintln!(
            "skipped: `make keycloak` (TUTELA_REQUIRE_KEYCLOAK=1) runs this against Keycloak"
        );
        return None;
    };
    Some(serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
}

/// The header and the claims of a JWT, unverified: for the test's checks.
fn claims(token: &str) -> (Value, Value) {
    let mut parts = token.split('.');
    let mut part = || serde_json::from_slice(&B64.decode(parts.next().unwrap()).unwrap()).unwrap();
    (part(), part())
}

fn random_b64(n: usize) -> String {
    let mut b = vec![0u8; n];
    aws_lc_rs::rand::SystemRandom::new().fill(&mut b).unwrap();
    B64.encode(b)
}

/// RFC 6238 TOTP as Keycloak computes it: HMAC-SHA1 keyed with the secret's
/// bytes, 6 digits, 30 s steps.
fn totp(secret: &str, step: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret.as_bytes());
    let mac = hmac::sign(&key, &step.to_be_bytes());
    let h = mac.as_ref();
    let at = usize::from(h[19] & 0x0f);
    let bin = u32::from_be_bytes([h[at] & 0x7f, h[at + 1], h[at + 2], h[at + 3]]);
    format!("{:06}", bin % 1_000_000)
}

/// Keycloak refuses a code it accepted before (`otpPolicyCodeReusable` is
/// off): each code once, waiting for the next step when it was used.
static USED: Mutex<Option<HashSet<(String, u64)>>> = Mutex::new(None);

async fn fresh_code(secret: &str) -> String {
    loop {
        let step = now() / 30;
        let free = USED
            .lock()
            .unwrap()
            .get_or_insert_with(HashSet::new)
            .insert((secret.to_owned(), step));
        if free {
            return totp(secret, step);
        }
        tokio::time::sleep(Duration::from_secs(
            ((step + 1) * 30).saturating_sub(now()).max(1),
        ))
        .await;
    }
}

/// The tokens of a sign-in.
struct Tokens {
    access: String,
    refresh: String,
}

/// Keycloak over HTTP: a browser without JavaScript, for its login pages,
/// and its admin API.
struct Kc {
    f: Value,
    http: reqwest::Client,
}

/// A browser's cookies for one sign-in. Keycloak's cookies are `Secure`; a
/// browser sends them to loopback over http, and so does this.
#[derive(Default)]
struct Jar(HashMap<String, String>);

impl Jar {
    fn keep(&mut self, r: &reqwest::Response) {
        for c in r.headers().get_all("set-cookie") {
            let c = c.to_str().unwrap();
            let pair = c.split(';').next().unwrap();
            if let Some((k, v)) = pair.split_once('=') {
                self.0.insert(k.trim().to_owned(), v.to_owned());
            }
        }
    }

    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The `action` of the page's form that has an input `field`.
fn form_action(html: &str, field: &str) -> Option<String> {
    html.split("<form").skip(1).find_map(|f| {
        let f = f.split("</form>").next()?;
        if !f.contains(&format!("name=\"{field}\"")) {
            return None;
        }
        let at = f.find("action=\"")? + "action=\"".len();
        let end = f[at..].find('"')? + at;
        Some(f[at..end].replace("&amp;", "&"))
    })
}

impl Kc {
    fn new(f: Value) -> Self {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self { f, http }
    }

    fn person(&self, who: &str) -> &Value {
        &self.f["people"][who]
    }

    async fn get(&self, url: &str, jar: &mut Jar) -> reqwest::Response {
        let r = self
            .http
            .get(url)
            .header("cookie", jar.header())
            .send()
            .await
            .unwrap();
        jar.keep(&r);
        r
    }

    async fn post_form(
        &self,
        url: &str,
        jar: &mut Jar,
        form: &[(&str, &str)],
    ) -> reqwest::Response {
        let r = self
            .http
            .post(url)
            .header("cookie", jar.header())
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(form).unwrap())
            .send()
            .await
            .unwrap();
        jar.keep(&r);
        r
    }

    /// Signs `who` in at `issuer` through `client`'s authorization code
    /// flow with PKCE S256, filling Keycloak's own forms: the password, and
    /// the OTP when Keycloak asks for it. `acr` is the `acr_values` asked.
    async fn sign_in(&self, issuer: &str, client: &str, who: &str, acr: Option<&str>) -> Tokens {
        let p = self.person(who);
        let redirect = self.f["redirect_uri"].as_str().unwrap();
        let verifier = random_b64(32);
        let challenge = B64.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
        let state = random_b64(16);
        let mut q = vec![
            ("client_id", client),
            ("response_type", "code"),
            ("redirect_uri", redirect),
            ("scope", "openid"),
            ("state", &state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ];
        if let Some(acr) = acr {
            q.push(("acr_values", acr));
        }
        let mut jar = Jar::default();
        let mut r = self
            .get(
                &format!(
                    "{issuer}/protocol/openid-connect/auth?{}",
                    serde_urlencoded::to_string(&q).unwrap()
                ),
                &mut jar,
            )
            .await;
        let mut otp_tries = 0;
        let code = loop {
            if r.status().is_redirection() {
                let to = r.headers()["location"].to_str().unwrap().to_owned();
                if let Some(query) = to.strip_prefix(&format!("{redirect}?")) {
                    let back: HashMap<String, String> = serde_urlencoded::from_str(query).unwrap();
                    assert_eq!(back.get("state"), Some(&state));
                    break back.get("code").cloned().unwrap_or_else(|| {
                        panic!("Keycloak sent back no code: {query}");
                    });
                }
                r = self.get(&to, &mut jar).await;
                continue;
            }
            let status = r.status();
            let page = r.text().await.unwrap();
            if let Some(action) = form_action(&page, "username") {
                r = self
                    .post_form(
                        &action,
                        &mut jar,
                        &[
                            ("username", p["username"].as_str().unwrap()),
                            ("password", p["password"].as_str().unwrap()),
                            ("credentialId", ""),
                        ],
                    )
                    .await;
            } else if let Some(action) = form_action(&page, "otp") {
                otp_tries += 1;
                assert!(otp_tries <= 3, "Keycloak refused the OTP codes");
                let code = fresh_code(p["totp"].as_str().unwrap()).await;
                r = self.post_form(&action, &mut jar, &[("otp", &code)]).await;
            } else {
                panic!("an unexpected Keycloak page ({status}): {page:.600}");
            }
        };
        self.token_call(
            issuer,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect),
                ("client_id", client),
                ("code_verifier", &verifier),
            ],
        )
        .await
    }

    /// A new access token for the session of `t` (a new `jti`).
    async fn refresh(&self, issuer: &str, client: &str, t: &Tokens) -> Tokens {
        self.token_call(
            issuer,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &t.refresh),
                ("client_id", client),
            ],
        )
        .await
    }

    async fn token_call(&self, issuer: &str, form: &[(&str, &str)]) -> Tokens {
        let r = self
            .post_form(
                &format!("{issuer}/protocol/openid-connect/token"),
                &mut Jar::default(),
                form,
            )
            .await;
        let status = r.status();
        let body: Value = r.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "Keycloak's token endpoint: {body}");
        Tokens {
            access: body["access_token"].as_str().unwrap().to_owned(),
            refresh: body["refresh_token"].as_str().unwrap().to_owned(),
        }
    }

    /// An access token of Keycloak's admin (the master realm's `admin-cli`).
    async fn admin_token(&self) -> String {
        let r = self
            .post_form(
                &format!(
                    "{}/realms/master/protocol/openid-connect/token",
                    self.f["url"].as_str().unwrap()
                ),
                &mut Jar::default(),
                &[
                    ("grant_type", "password"),
                    ("client_id", "admin-cli"),
                    ("username", self.f["admin"]["username"].as_str().unwrap()),
                    ("password", self.f["admin"]["password"].as_str().unwrap()),
                ],
            )
            .await;
        let body: Value = r.json().await.unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// Calls the realm's admin API.
    async fn admin(&self, method: reqwest::Method, path: &str, body: Option<&Value>) -> Value {
        let url = format!(
            "{}{}{path}",
            self.f["url"].as_str().unwrap(),
            self.f["realm"]["admin_path"].as_str().unwrap()
        );
        let mut rq = self
            .http
            .request(method.clone(), &url)
            .bearer_auth(self.admin_token().await);
        if let Some(b) = body {
            rq = rq.json(b);
        }
        let r = rq.send().await.unwrap();
        let status = r.status();
        let text = r.text().await.unwrap();
        assert!(status.is_success(), "{method} {path}: {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }
}

/// `tutelad` with the realm as the one external issuer of tenant A.
struct Service {
    d: common::TestDb,
    s: common::Running,
    a: common::Seed,
}

impl Service {
    async fn start(f: &Value) -> Option<Self> {
        let mut d = common::migrated().await?;
        common::publish(&mut d.owner, MANIFEST, None).await;
        let a = common::seed_of(&mut d.owner, OWN_ISS, USER, "reader").await;
        let realm = f["realm"]["issuer"].as_str().unwrap();
        // As the chart writes it (ADR-0056): RS256, `typ: JWT` allowed.
        let trust = TrustFile::parse(
            &format!(
                "[[issuer]]\niss = \"{realm}\"\n\
                 jwks_uri = \"{realm}/protocol/openid-connect/certs\"\n\
                 algs = [\"RS256\"]\ntenants = [\"{}\"]\nexternal = true\nallow_typ_jwt = true\n",
                a.tid
            ),
            true,
        )
        .unwrap();
        let mut cfg = common::config(&d.service_url, trust);
        cfg.dev_mode = true;
        let jwks: Arc<dyn tutela_sdk::JwksSource> = Arc::new(cfg.jwks_source().unwrap());
        let state = common::state_with_jwks(&cfg, jwks, true);
        let s = common::start(&cfg, state).await;
        Some(Self { d, s, a })
    }

    async fn exchange(&self, subject: &str, audience: &str) -> (StatusCode, Value) {
        let r = common::http()
            .post(self.s.api_url("/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                serde_urlencoded::to_string([
                    ("grant_type", EXCHANGE),
                    ("subject_token", subject),
                    ("subject_token_type", ACCESS_TOKEN),
                    ("audience", audience),
                ])
                .unwrap(),
            )
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap())
    }

    async fn token(&self, subject: &str, audience: &str) -> String {
        let (status, body) = self.exchange(subject, audience).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// The error of a refused exchange: `invalid_grant` with the one text
    /// that says nothing about the check, unless it is the step-up refusal.
    async fn refused(&self, subject: &str, audience: &str) -> Value {
        let (status, body) = self.exchange(subject, audience).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body.to_string().contains(subject));
        body
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut rq = common::http()
            .request(method, self.s.api_url(path))
            .bearer_auth(token);
        if let Some(b) = body {
            rq = rq.json(b);
        }
        let r = rq.send().await.unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn assign(&mut self, who: &str, role: &str, at: &tutela_pdp::PathEntry) -> u64 {
        let tx = self.d.owner.transaction().await.unwrap();
        let (_, rev) = tutela_store::assign(
            &tx,
            &self.a.key,
            &tutela_pdp::Subject::Principal(who.parse().unwrap()),
            &tutela_pdp::model::RoleKey::parse(role).unwrap(),
            at,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        rev
    }
}

fn principal(token: &str) -> String {
    claims(token).1["sub"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_keycloak_tokens_are_exchanged_and_refused_as_documented() {
    let Some(f) = fixture() else { return };
    let Some(mut svc) = Service::start(&f).await else {
        return;
    };
    let kc = Kc::new(f.clone());
    let realm = f["realm"]["issuer"].as_str().unwrap();
    let console = f["realm"]["client_id"].as_str().unwrap();
    let step_up = f["step_up_acr"].as_str().unwrap();
    assert_eq!(
        step_up,
        common::STEP_UP,
        "TUTELA_ADMIN_ACR is the realm's MFA level"
    );

    // 1. A sign-in at the Console's client, as the chart makes it, without
    //    step-up: what Keycloak really puts in its access token.
    let plain = kc.sign_in(realm, console, "owner", None).await;
    let (h, c) = claims(&plain.access);
    println!("keycloak: access token header {h}");
    println!(
        "keycloak: claims {}",
        json!({
            "iss": c["iss"], "aud": c["aud"], "azp": c["azp"], "typ": c["typ"],
            "acr": c["acr"], "amr": c["amr"], "jti": c["jti"], "sid": c.get("sid").is_some(),
            "exp-iat": c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(),
            "nbf": c["nbf"], "scope": c["scope"],
        })
    );
    assert_eq!(h["typ"], "JWT", "Keycloak's access tokens are typ JWT");
    assert_eq!(h["alg"], "RS256");
    assert_eq!(
        c["iss"], realm,
        "the issuer is spelled as the trust file has it"
    );
    assert_eq!(
        c["aud"], AUD,
        "exactly one audience: the chart's client has no full scope"
    );
    assert_eq!(c["azp"], console);
    assert_eq!(
        c["acr"], "1",
        "Keycloak's level 1 has no name in the ACR-to-LoA map"
    );
    assert!(c.get("amr").is_none(), "no AMR mapper, no amr");
    assert_eq!(c["sub"], kc.person("owner")["sub"]);
    assert!(!c["jti"].as_str().unwrap().is_empty());
    let skew = c["iat"].as_u64().unwrap().abs_diff(now());
    assert!(skew <= 5, "Keycloak's clock is {skew} s off");

    // 2. The exchange gives a tutela-authz token for a person made just in
    //    time; the check API answers it.
    let (status, body) = svc.exchange(&plain.access, AUD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let authz = body["access_token"].as_str().unwrap().to_owned();
    let (h1, a1) = claims(&authz);
    assert_eq!(h1["typ"], "at+jwt");
    assert_eq!(a1["iss"], OWN_ISS);
    assert_eq!(a1["tid"], svc.a.tid);
    assert_eq!(a1["aud"], AUD);
    assert_eq!(a1["azp"], console);
    assert_eq!(a1["acr"], "1");
    assert_eq!(a1["amr"], json!(["ext"]), "Keycloak did not say how");
    assert!(a1["exp"].as_u64().unwrap() <= c["exp"].as_u64().unwrap());
    for never in ["email", "name", "preferred_username", "realm_access"] {
        assert!(a1.get(never).is_none(), "{never} copied into the token");
    }
    let me = principal(&authz);
    assert!(me.starts_with("user:usr_"), "{me}");
    let (status, body) = svc
        .call(
            reqwest::Method::POST,
            "/access/v1/evaluation",
            &authz,
            Some(&ask(&me, "invoice:read", &svc.a)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], false, "a new person holds nothing");
    let project = svc.a.project.clone();
    let rev = svc.assign(&me, "reader", &project).await;
    let mut asked = ask(&me, "invoice:read", &svc.a);
    asked["context"] = json!({ "at_least_revision": rev });
    let (status, body) = svc
        .call(
            reqwest::Method::POST,
            "/access/v1/evaluation",
            &authz,
            Some(&asked),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], true);

    // 3. No step-up, no admin token: the one refusal that says why.
    let body = svc.refused(&authz, "tutela-admin").await;
    assert_eq!(
        body,
        json!({"error": "invalid_grant", "error_description": "step-up authentication is required"})
    );

    // 4. A Keycloak token is exchanged once.
    let body = svc.refused(&plain.access, AUD).await;
    assert_eq!(body["error"], "invalid_grant");
    assert_ne!(
        body["error_description"],
        "step-up authentication is required"
    );

    // 5. A refreshed token (a new jti) of the same session: the same person.
    let again = kc.refresh(realm, console, &plain).await;
    let (_, r) = claims(&again.access);
    assert_ne!(r["jti"], c["jti"]);
    println!("keycloak: a refreshed token keeps acr {}", r["acr"]);
    assert_eq!(principal(&svc.token(&again.access, AUD).await), me);

    // 6. A sign-in with step-up: Keycloak's password form, then its OTP
    //    form; the acr is the MFA level's name; the admin token follows,
    //    as the Console gets it (authz first, then admin from it). The
    //    person owns the org first, so the new token's `rev` covers it.
    let org = svc.a.org.clone();
    svc.assign(&me, "owner", &org).await;
    let mfa = kc.sign_in(realm, console, "owner", Some(step_up)).await;
    let (_, m) = claims(&mfa.access);
    println!("keycloak: after OTP, acr {} amr {}", m["acr"], m["amr"]);
    assert_eq!(m["acr"], step_up);
    let authz2 = svc.token(&mfa.access, AUD).await;
    assert_eq!(principal(&authz2), me, "(iss, sub) maps to one person");
    let admin = svc.token(&authz2, "tutela-admin").await;
    let (_, ad) = claims(&admin);
    assert_eq!(ad["aud"], "tutela-admin");
    assert_eq!(ad["acr"], step_up);
    assert!(ad["exp"].as_u64().unwrap() - ad["iat"].as_u64().unwrap() <= 300);
    let (status, body) = svc
        .call(reqwest::Method::GET, "/v1/admin/tenant", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The tutela-authz token of the same person is no admin token.
    let (status, _) = svc
        .call(reqwest::Method::GET, "/v1/admin/tenant", &authz2, None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 7. Just-in-time provisioning made one person for (iss, sub).
    {
        let tx = svc.d.owner.transaction().await.unwrap();
        let (p, made) = tutela_store::provision_user(
            &tx,
            &svc.a.key,
            &realm.parse().unwrap(),
            kc.person("owner")["sub"].as_str().unwrap(),
        )
        .await
        .unwrap();
        assert!(!made, "the person was made twice");
        assert_eq!(p.principal.to_string(), me);
        tx.rollback().await.unwrap();
    }

    // 8. With the AMR mapper, Keycloak names the forms; tutelad copies
    //    them. Another person of the realm is another principal.
    let amr_client = f["amr_client"].as_str().unwrap();
    let t = kc.sign_in(realm, amr_client, "member", Some(step_up)).await;
    let (_, mc) = claims(&t.access);
    println!("keycloak: with the AMR mapper, amr {}", mc["amr"]);
    assert_eq!(mc["amr"], json!(["pwd", "otp"]));
    let member = svc.token(&t.access, AUD).await;
    let (_, mm) = claims(&member);
    assert_eq!(mm["amr"], json!(["pwd", "otp"]));
    assert_eq!(mm["azp"], amr_client);
    assert_ne!(principal(&member), me);

    // 9. Refused: another service's audience, two audiences (Keycloak's
    //    default full scope adds "account"), and another realm.
    let other = kc
        .sign_in(
            realm,
            f["other_api_client"].as_str().unwrap(),
            "owner",
            None,
        )
        .await;
    assert_eq!(claims(&other.access).1["aud"], "crm-api");
    assert_eq!(
        svc.refused(&other.access, AUD).await["error"],
        "invalid_grant"
    );
    let full = kc
        .sign_in(
            realm,
            f["full_scope_client"].as_str().unwrap(),
            "owner",
            None,
        )
        .await;
    let aud = claims(&full.access).1["aud"].clone();
    println!("keycloak: with full scope, aud {aud}");
    assert_eq!(aud, json!([AUD, "account"]));
    assert_eq!(
        svc.refused(&full.access, AUD).await["error"],
        "invalid_grant"
    );
    let elsewhere = &f["elsewhere"];
    let stranger = kc
        .sign_in(
            elsewhere["issuer"].as_str().unwrap(),
            elsewhere["client_id"].as_str().unwrap(),
            "stranger",
            None,
        )
        .await;
    assert_eq!(claims(&stranger.access).1["aud"], AUD);
    assert_eq!(
        svc.refused(&stranger.access, AUD).await["error"],
        "invalid_grant"
    );

    // 10. Key rotation at Keycloak: a new RS256 key of a higher priority
    //     signs the next tokens; tutelad fetches the JWKS again for the new
    //     kid (at most once per 30 s per issuer, CacheRules::min_refetch).
    let old_kid = h["kid"].as_str().unwrap().to_owned();
    let realm_id = kc.admin(reqwest::Method::GET, "", None).await["id"].clone();
    kc.admin(
        reqwest::Method::POST,
        "/components",
        Some(&json!({
            "name": "rotated-rs256",
            "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider",
            "parentId": realm_id,
            "config": {
                "priority": ["1000"], "keySize": ["2048"], "algorithm": ["RS256"],
                "active": ["true"], "enabled": ["true"],
            },
        })),
    )
    .await;
    let rotated = kc.refresh(realm, console, &mfa).await;
    let new_kid = claims(&rotated.access).0["kid"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_kid, old_kid, "Keycloak signs with the new key");
    let started = Instant::now();
    let token = loop {
        let (status, body) = svc.exchange(&rotated.access, AUD).await;
        if status == StatusCode::OK {
            break body["access_token"].as_str().unwrap().to_owned();
        }
        assert_eq!(body["error"], "invalid_grant", "{body}");
        assert!(
            started.elapsed() < Duration::from_secs(45),
            "the rotated key was not picked up"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    println!(
        "keycloak: a token of the rotated key was exchanged after {} s",
        started.elapsed().as_secs()
    );
    assert_eq!(principal(&token), me);

    // Every refusal and issue is in the tenant's audit chain.
    let records = common::audit_of(&mut svc.d.owner, &svc.a.key).await;
    assert!(records.iter().any(|r| r["outcome"] != "success"));
    assert!(records.iter().any(|r| r["outcome"] == "success"));

    svc.s.stop().await.unwrap();
    svc.d.finish().await;
}
