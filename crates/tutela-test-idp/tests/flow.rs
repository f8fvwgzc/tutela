//! The test OpenID provider's authorization code flow with PKCE, refresh,
//! the JWKS and its refusals.
#![cfg(test)]

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use reqwest::{StatusCode, redirect::Policy};
use serde_json::Value;
use tutela_test_idp::{Person, Running, Settings};

const REDIRECT: &str = "http://127.0.0.1:9/console/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mJ92K9z1Ea0nIKKwSMnFoE3fWiZ4UTLJm5d6TJu4Mx9Oq3fXP2Q";

async fn idp() -> Running {
    let mut s = Settings::new("tutela-authz");
    s.redirect_uris = vec![REDIRECT.to_owned()];
    s.people = vec![
        Person::new("kc-owner", "Olivia Owner"),
        Person::new("kc-member", "Max Member"),
    ];
    tutela_test_idp::start(s).await.unwrap()
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .build()
        .unwrap()
}

fn challenge(v: &str) -> String {
    B64.encode(digest(&SHA256, v.as_bytes()))
}

fn auth_params(challenge: &str, method: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_owned()),
        ("client_id", "tutela-console".to_owned()),
        ("redirect_uri", REDIRECT.to_owned()),
        ("scope", "openid profile".to_owned()),
        ("state", "st-1".to_owned()),
        ("nonce", "n-1".to_owned()),
        ("code_challenge", challenge.to_owned()),
        ("code_challenge_method", method.to_owned()),
    ]
}

/// Picks `person` on the form, with or without MFA; answers the redirect.
async fn sign_in(i: &Running, person: &str, mfa: bool) -> reqwest::Response {
    let url = format!("{}/protocol/openid-connect/auth", i.issuer());
    let mut form = auth_params(&challenge(VERIFIER), "S256");
    form.push(("person", person.to_owned()));
    if mfa {
        form.push(("mfa", "1".to_owned()));
    }
    http()
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(serde_urlencoded::to_string(&form).unwrap())
        .send()
        .await
        .unwrap()
}

fn code_of(res: &reqwest::Response) -> String {
    assert_eq!(res.status(), StatusCode::FOUND);
    let loc = res.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with(REDIRECT), "{loc}");
    let q: Vec<(String, String)> =
        serde_urlencoded::from_str(loc.split_once('?').unwrap().1).unwrap();
    let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(get("state").as_deref(), Some("st-1"));
    assert!(get("iss").is_some(), "RFC 9207 iss");
    get("code").unwrap()
}

async fn token(i: &Running, form: &[(&str, &str)], origin: Option<&str>) -> reqwest::Response {
    let mut req = http()
        .post(format!("{}/protocol/openid-connect/token", i.issuer()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(serde_urlencoded::to_string(form).unwrap());
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    req.send().await.unwrap()
}

fn claims(jwt: &str) -> (Value, Value) {
    let mut parts = jwt.split('.');
    let h = serde_json::from_slice(&B64.decode(parts.next().unwrap()).unwrap()).unwrap();
    let c = serde_json::from_slice(&B64.decode(parts.next().unwrap()).unwrap()).unwrap();
    (h, c)
}

async fn verify(i: &Running, jwt: &str) {
    let jwks: Value = http()
        .get(i.jwks_uri())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let k = &jwks["keys"][0];
    let (h, _) = claims(jwt);
    assert_eq!(h["kid"], k["kid"]);
    let n = B64.decode(k["n"].as_str().unwrap()).unwrap();
    let e = B64.decode(k["e"].as_str().unwrap()).unwrap();
    let (msg, sig) = jwt.rsplit_once('.').unwrap();
    RsaPublicKeyComponents { n: &n, e: &e }
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            msg.as_bytes(),
            &B64.decode(sig).unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn the_code_flow_with_pkce_gives_keycloak_shaped_tokens() {
    let i = idp().await;
    let d: Value = http()
        .get(format!("{}/.well-known/openid-configuration", i.issuer()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(d["issuer"], i.issuer());
    assert_eq!(d["code_challenge_methods_supported"][0], "S256");

    // The form lists the people, and MFA is ticked when acr_values asks.
    let mut q = auth_params(&challenge(VERIFIER), "S256");
    q.push(("acr_values", "mfa".to_owned()));
    let page = http()
        .get(format!(
            "{}/protocol/openid-connect/auth?{}",
            i.issuer(),
            serde_urlencoded::to_string(&q).unwrap()
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Olivia Owner") && page.contains("Max Member"));
    assert!(page.contains(r#"name="mfa" value="1" checked"#), "{page}");

    let code = code_of(&sign_in(&i, "kc-owner", true).await);
    let origin = "http://127.0.0.1:9";
    let res = token(
        &i,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "tutela-console"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
        Some(origin),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["access-control-allow-origin"], origin);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let t: Value = res.json().await.unwrap();
    let access = t["access_token"].as_str().unwrap();
    verify(&i, access).await;
    let (h, c) = claims(access);
    assert_eq!(h["alg"], "RS256");
    assert_eq!(h["typ"], "JWT");
    assert_eq!(c["iss"], i.issuer());
    assert_eq!(c["aud"], "tutela-authz");
    assert_eq!(c["azp"], "tutela-console");
    assert_eq!(c["sub"], "kc-owner");
    assert_eq!(c["acr"], "mfa");
    assert_eq!(c["typ"], "Bearer");
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 300);
    assert!(c["jti"].as_str().is_some() && c["sid"].as_str().is_some());
    let (_, id) = claims(t["id_token"].as_str().unwrap());
    assert_eq!(id["nonce"], "n-1");
    assert_eq!(id["aud"], "tutela-console");

    // The code is used once.
    let again = token(
        &i,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "tutela-console"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);

    // Refresh gives a new access token and a new refresh token; the old
    // refresh token is spent.
    let rt = t["refresh_token"].as_str().unwrap().to_owned();
    let fresh: Value = token(
        &i,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "tutela-console"),
            ("refresh_token", &rt),
        ],
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    let (_, c2) = claims(fresh["access_token"].as_str().unwrap());
    assert_eq!(c2["acr"], "mfa");
    assert_ne!(c2["jti"], c["jti"]);
    assert_ne!(fresh["refresh_token"], t["refresh_token"]);
    let spent = token(
        &i,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "tutela-console"),
            ("refresh_token", &rt),
        ],
        None,
    )
    .await;
    assert_eq!(spent.status(), StatusCode::BAD_REQUEST);

    // Without MFA the acr is "1".
    let code = code_of(&sign_in(&i, "kc-member", false).await);
    let t: Value = token(
        &i,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "tutela-console"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    let (_, c) = claims(t["access_token"].as_str().unwrap());
    assert_eq!(c["acr"], "1");
    assert_eq!(c["sub"], "kc-member");
    i.stop().await;
}

#[tokio::test]
async fn refusals() {
    let i = idp().await;
    // A wrong verifier.
    let code = code_of(&sign_in(&i, "kc-owner", true).await);
    let res = token(
        &i,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "tutela-console"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            (
                "code_verifier",
                "wrong-verifier-wrong-verifier-wrong-verifier-0",
            ),
        ],
        Some("http://evil.example.test"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        !res.headers().contains_key("access-control-allow-origin"),
        "another origin gets no CORS answer"
    );
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["error"], "invalid_grant");

    // A redirect URI that is not the client's: a page, never a redirect.
    let mut q = auth_params(&challenge(VERIFIER), "S256");
    q[2].1 = "http://evil.example.test/cb".to_owned();
    let res = http()
        .get(format!(
            "{}/protocol/openid-connect/auth?{}",
            i.issuer(),
            serde_urlencoded::to_string(&q).unwrap()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(!res.headers().contains_key("location"));

    // `plain` PKCE, or none, goes back to the client as invalid_request.
    for method in ["plain", ""] {
        let q = auth_params(&challenge(VERIFIER), method);
        let res = http()
            .get(format!(
                "{}/protocol/openid-connect/auth?{}",
                i.issuer(),
                serde_urlencoded::to_string(&q).unwrap()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FOUND);
        let loc = res.headers()["location"].to_str().unwrap();
        assert!(loc.contains("error=invalid_request"), "{loc}");
        assert!(!loc.contains("code="), "{loc}");
    }

    // Another client id.
    let res = token(
        &i,
        &[("grant_type", "refresh_token"), ("client_id", "other")],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    i.stop().await;

    // Loopback only.
    let mut s = Settings::new("tutela-authz");
    s.listen = "0.0.0.0:0".parse().unwrap();
    assert!(tutela_test_idp::start(s).await.is_err());
}
