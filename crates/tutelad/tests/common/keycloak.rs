//! Keycloak for the tests that run against a real one (#87, ADR-0057):
//! `scripts/keycloak-check.mjs` starts it and writes a fixture file; these
//! helpers sign people in at its own login and OTP pages, as a browser
//! without JavaScript would, and call its admin API.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use aws_lc_rs::{digest, hmac, rand::SecureRandom as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::now;

/// The fixture `scripts/keycloak-check.mjs` wrote, from the variable `var`.
pub fn fixture(var: &str) -> Option<Value> {
    let path = std::env::var(var).ok()?;
    Some(serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
}

/// The header and the claims of a JWT, unverified: for the test's checks.
pub fn claims(token: &str) -> (Value, Value) {
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
pub fn totp(secret: &str, step: u64) -> String {
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

pub async fn fresh_code(secret: &str) -> String {
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
pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

/// Keycloak over HTTP: a browser without JavaScript, for its login pages,
/// and its admin API.
pub struct Kc {
    pub f: Value,
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
    pub fn new(f: Value) -> Self {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self { f, http }
    }

    pub fn person(&self, who: &str) -> &Value {
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
    pub async fn sign_in(
        &self,
        issuer: &str,
        client: &str,
        who: &str,
        acr: Option<&str>,
    ) -> Tokens {
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
    pub async fn refresh(&self, issuer: &str, client: &str, t: &Tokens) -> Tokens {
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
    pub async fn admin(&self, method: reqwest::Method, path: &str, body: Option<&Value>) -> Value {
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

    /// Lets the Console at `url` sign in with the realm's Console client:
    /// its callback, origin and post-logout URI, which the chart writes for
    /// the public https host.
    pub async fn allow_console(&self, url: &str) {
        let client_id = self.f["realm"]["client_id"].as_str().unwrap();
        let found = self
            .admin(
                reqwest::Method::GET,
                &format!("/clients?clientId={client_id}"),
                None,
            )
            .await;
        let mut client = found[0].clone();
        let id = client["id"].as_str().unwrap().to_owned();
        client["redirectUris"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("{url}/console/callback")));
        client["webOrigins"]
            .as_array_mut()
            .unwrap()
            .push(json!(url));
        client["attributes"]["post.logout.redirect.uris"] = json!(format!(
            "{}##{url}/console/",
            client["attributes"]["post.logout.redirect.uris"]
                .as_str()
                .unwrap()
        ));
        self.admin(
            reqwest::Method::PUT,
            &format!("/clients/{id}"),
            Some(&client),
        )
        .await;
    }
}
