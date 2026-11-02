//! Token exchange (RFC 8693) through the real service, the real auth layer
//! and a real Postgres (ADR-0031). The external issuer is a local signer of
//! Keycloak-shaped tokens: a realm `iss`, `azp`, `sid`, `acr`, `typ: JWT`.
#![cfg(test)]

mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutelad::api::AppState;
use tutelad::config::TrustFile;

use common::{
    AUD, ISS, Issuer, MANIFEST, OWN_ISS, Running, Seed, TestDb, USER, ask, config, http, migrated,
    now, publish, seed_of, start, state,
};

/// A Keycloak realm that logs people in for tenant A.
const KC: &str = "https://kc.example.test/realms/acme";
/// A second realm for tenant A.
const KC_ALT: &str = "https://kc.example.test/realms/acme-partners";
/// A realm for tenant B.
const KC_B: &str = "https://kc.example.test/realms/beta";
/// A realm whose tenant is in the directory under the realm itself, the
/// Phase A way: not this service's to issue for.
const KC_OLD: &str = "https://kc.example.test/realms/legacy";

struct X {
    d: TestDb,
    st: AppState,
    s: Running,
    /// Signs for every issuer of the test: one key, served for each.
    issuer: Issuer,
    /// Tenant A, under the own issuer: USER is a reader on its project.
    a: Seed,
    /// Tenant B, under the own issuer.
    b: Seed,
    /// A tenant of the Tutela-format issuer ISS.
    foreign: TenantKey,
}

async fn x() -> Option<X> {
    x_with(|_| {}).await
}

async fn x_with(tune: impl FnOnce(&mut tutelad::Config)) -> Option<X> {
    let mut d = migrated().await?;
    publish(&mut d.owner, MANIFEST, None).await;
    let a = seed_of(&mut d.owner, OWN_ISS, USER, "reader").await;
    let b = seed_of(&mut d.owner, OWN_ISS, common::B_USER, "approver").await;
    let foreign = common::tenant_of(&mut d.owner, ISS).await;
    let old = common::tenant_of(&mut d.owner, KC_OLD).await;
    let ext = |iss: &str, tid: &str| {
        format!(
            "[[issuer]]\niss = \"{iss}\"\njwks_uri = \"{iss}/protocol/openid-connect/certs\"\n\
             algs = [\"ES256\"]\ntenants = [\"{tid}\"]\nexternal = true\nallow_typ_jwt = true\n"
        )
    };
    let file = format!(
        "[[issuer]]\niss = \"{ISS}\"\njwks_uri = \"{ISS}/jwks\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{}\"]\n{}{}{}{}\
         [[audience]]\nname = \"crm-api\"\n",
        foreign.tid,
        ext(KC, &a.tid),
        ext(KC_ALT, &a.tid),
        ext(KC_B, &b.tid),
        ext(KC_OLD, &old.tid.to_string()),
    );
    let trust = TrustFile::parse(&file, false).unwrap();
    let issuer = Issuer::new();
    let mut cfg = config(&d.service_url, trust);
    tune(&mut cfg);
    let st = state(&cfg, &issuer);
    let s = start(&cfg, st.clone()).await;
    Some(X {
        d,
        st,
        s,
        issuer,
        a,
        b,
        foreign,
    })
}

/// Claims of a Keycloak access token of `iss` for `sub`.
fn kc_claims(iss: &str, sub: &str) -> Value {
    let now = now();
    json!({
        "exp": now + 300, "iat": now, "auth_time": now - 5,
        "jti": uuid::Uuid::now_v7().to_string(),
        "iss": iss, "aud": AUD, "sub": sub, "typ": "Bearer",
        "azp": "crm-web", "sid": uuid::Uuid::now_v7().to_string(), "acr": "1",
        "scope": "openid email profile",
        "email": "alice@example.test", "email_verified": true,
        "preferred_username": "alice",
    })
}

impl X {
    fn kc(&self, iss: &str, sub: &str) -> String {
        self.kc_with(&kc_claims(iss, sub))
    }

    fn kc_with(&self, claims: &Value) -> String {
        self.issuer.sign_typed("JWT", claims)
    }

    async fn exchange_form(&self, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
        let r = http()
            .post(self.s.api_url("/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(pairs).unwrap())
            .send()
            .await
            .unwrap();
        let status = r.status();
        assert_eq!(r.headers()["cache-control"], "no-store");
        (status, r.json().await.unwrap())
    }

    async fn exchange(&self, subject: &str, audience: &str) -> (StatusCode, Value) {
        self.exchange_form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", subject),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", audience),
        ])
        .await
    }

    /// Exchanges and expects a token.
    async fn token(&self, subject: &str, audience: &str) -> String {
        let (status, body) = self.exchange(subject, audience).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn refused(&self, subject: &str, audience: &str) -> String {
        let (status, body) = self.exchange(subject, audience).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body.to_string().contains(subject));
        body["error"].as_str().unwrap().to_owned()
    }

    async fn get(&self, path: &str, token: &str) -> reqwest::Response {
        http()
            .get(self.s.api_url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        let r = http()
            .post(self.s.api_url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// Waits until `token` is refused on `/v1/whoami`: a revocation reaches
    /// a replica within `TUTELA_REVISION_CHECK_MS` plus one read.
    async fn until_refused(&self, token: &str) {
        let start = std::time::Instant::now();
        loop {
            if self.get("/v1/whoami", token).await.status() == StatusCode::UNAUTHORIZED {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_millis(2500),
                "the revoked token still works"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn store<T>(
        &mut self,
        f: impl AsyncFnOnce(&tutela_store::tokio_postgres::Transaction<'_>) -> T,
    ) -> T {
        let tx = self.d.owner.transaction().await.unwrap();
        let out = f(&tx).await;
        tx.commit().await.unwrap();
        out
    }

    async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }
}

fn claims(token: &str) -> (Value, Value) {
    let mut parts = token.split('.');
    let h = parts.next().unwrap();
    let p = parts.next().unwrap();
    (
        serde_json::from_slice(&B64.decode(h).unwrap()).unwrap(),
        serde_json::from_slice(&B64.decode(p).unwrap()).unwrap(),
    )
}

fn principal(token: &str) -> Principal {
    claims(token).1["sub"].as_str().unwrap().parse().unwrap()
}

/// The point of the exchange: the check API refuses the external token, and
/// accepts the exchanged one, for a person provisioned just in time.
#[tokio::test]
async fn the_check_api_accepts_the_exchanged_token_where_it_refused_the_external_one() {
    let Some(mut w) = x().await else { return };
    let external = w.kc(KC, "kc-user-1");
    let (status, _) = w
        .post(
            "/access/v1/evaluation",
            &external,
            &ask(USER, "invoice:read", &w.a),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = w.exchange(&external, AUD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(
        body["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    let expires_in = body["expires_in"].as_u64().unwrap();
    assert!((290..=300).contains(&expires_in), "{expires_in}");
    let token = body["access_token"].as_str().unwrap();
    let (header, c) = claims(token);
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["alg"], "ES256");
    assert!(
        w.st.keys
            .published()
            .contains(&header["kid"].as_str().unwrap().to_owned())
    );
    assert_eq!(c["iss"], OWN_ISS);
    assert_eq!(c["tid"], w.a.tid);
    assert_eq!(c["aud"], AUD);
    assert_eq!(c["azp"], "crm-web");
    assert_eq!(c["acr"], "1");
    assert_eq!(c["amr"], json!(["ext"]), "the realm did not say how");
    assert_eq!(c["epoch"], 0);
    assert!(c["sid"].as_str().unwrap().starts_with("ses_"));
    assert!(c["sub"].as_str().unwrap().starts_with("user:usr_"));
    assert_ne!(c["sub"], "kc-user-1");
    for never in ["email", "preferred_username", "act", "org"] {
        assert!(c.get(never).is_none(), "{never} in the token");
    }

    let who: Value = w.get("/v1/whoami", token).await.json().await.unwrap();
    assert_eq!(who["iss"], OWN_ISS);
    assert_eq!(who["sub"], c["sub"]);
    assert_eq!(who["kind"], "access");

    // A person asks about itself. It holds no role yet: a deny, not a 403.
    let me = principal(token);
    let (status, body) = w
        .post(
            "/access/v1/evaluation",
            token,
            &ask(&me.to_string(), "invoice:read", &w.a),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], false);
    // Give the provisioned person a role; the same token now gets an allow.
    let (a, project) = (w.a.key.clone(), w.a.project.clone());
    let rev = w
        .store(async |tx| {
            tutela_store::assign(
                tx,
                &a,
                &tutela_pdp::Subject::Principal(me.clone()),
                &tutela_pdp::model::RoleKey::parse("reader").unwrap(),
                &project,
                None,
            )
            .await
            .unwrap()
            .1
        })
        .await;
    let mut asked = ask(&me.to_string(), "invoice:read", &w.a);
    asked["context"] = json!({"at_least_revision": rev});
    let (status, body) = w.post("/access/v1/evaluation", token, &asked).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], true);
    // A person still asks about itself only.
    let (status, _) = w
        .post(
            "/access/v1/evaluation",
            token,
            &ask(USER, "invoice:read", &w.a),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    w.finish().await;
}

/// TM-05: the tenant comes from the trust list's mapping, never from the
/// token or the request, and an issuer never gets a tenant it may not
/// speak for.
#[tokio::test]
async fn tm05_an_issuer_cannot_name_a_tenant_it_may_not_speak_for() {
    let Some(w) = x().await else { return };
    // A realm token that names tenant B: the claim is ignored.
    let mut c = kc_claims(KC, "kc-user-2");
    c["tid"] = json!(w.b.tid);
    let t = w.token(&w.kc_with(&c), AUD).await;
    assert_eq!(claims(&t).1["tid"], w.a.tid);
    // A request that names tenant B: ignored too.
    let (status, body) = w
        .exchange_form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", &w.kc(KC, "kc-user-2")),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", AUD),
            ("tid", &w.b.tid),
            ("tenant", &w.b.tid),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        claims(body["access_token"].as_str().unwrap()).1["tid"],
        w.a.tid
    );

    // A Tutela-format issuer that names a tenant off its list.
    let off_list = w.issuer.token_of(ISS, common::SA, &w.b.tid, 0);
    assert_eq!(w.refused(&off_list, AUD).await, "invalid_grant");
    // The verifier itself refuses it, before any exchange rule.
    assert_eq!(
        w.get("/v1/whoami", &off_list).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // Its own tenant: still not this service's to issue for.
    let own_list = w
        .issuer
        .token_of(ISS, common::SA, &w.foreign.tid.to_string(), 0);
    assert_eq!(w.refused(&own_list, AUD).await, "invalid_grant");
    // A realm whose tenant is in the directory under the realm, not under
    // this service's issuer.
    assert_eq!(
        w.refused(&w.kc(KC_OLD, "kc-user-3"), AUD).await,
        "invalid_grant"
    );
    // Each realm gets its own tenant: B's realm, B's tenant.
    let tb = w.token(&w.kc(KC_B, "kc-user-2"), AUD).await;
    assert_eq!(claims(&tb).1["tid"], w.b.tid);
    w.finish().await;
}

/// An issuer the trust file does not name, and a known issuer's name with
/// another key, are refused the same way.
#[tokio::test]
async fn a_token_from_an_issuer_not_on_the_list_is_refused() {
    let Some(w) = x().await else { return };
    let evil = w.kc("https://evil.example.test/realms/acme", "kc-user-1");
    assert_eq!(w.refused(&evil, AUD).await, "invalid_grant");
    let forged = Issuer::new().sign_typed("JWT", &kc_claims(KC, "kc-user-1"));
    assert_eq!(w.refused(&forged, AUD).await, "invalid_grant");
    let metrics = http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(
            r#"tutelad_token_operations_total{operation="access",outcome="invalid_grant"} 2"#
        ),
        "{metrics}"
    );
    w.finish().await;
}

/// A subject token is exchanged once; an expired one, or one about to
/// expire inside the clock skew, never; one with no `jti` cannot be
/// tracked, so it is refused.
#[tokio::test]
async fn a_replayed_or_expired_subject_token_is_refused() {
    let Some(w) = x().await else { return };
    let once = w.kc(KC, "kc-user-1");
    w.token(&once, AUD).await;
    assert_eq!(w.refused(&once, AUD).await, "invalid_grant");
    assert_eq!(w.refused(&once, "crm-api").await, "invalid_grant");

    let now = now();
    let mut old = kc_claims(KC, "kc-user-1");
    old["iat"] = json!(now - 400);
    old["exp"] = json!(now - 100);
    assert_eq!(w.refused(&w.kc_with(&old), AUD).await, "invalid_grant");
    // Inside the skew a verifier still accepts it; nothing is issued from it.
    let mut ending = kc_claims(KC, "kc-user-1");
    ending["iat"] = json!(now - 300);
    ending["exp"] = json!(now - 10);
    assert_eq!(w.refused(&w.kc_with(&ending), AUD).await, "invalid_grant");
    let mut no_jti = kc_claims(KC, "kc-user-1");
    no_jti.as_object_mut().unwrap().remove("jti");
    assert_eq!(w.refused(&w.kc_with(&no_jti), AUD).await, "invalid_grant");
    // The issued token never outlives the subject token.
    let mut short = kc_claims(KC, "kc-user-1");
    short["exp"] = json!(now + 90);
    let t = w.token(&w.kc_with(&short), AUD).await;
    assert!(claims(&t).1["exp"].as_u64().unwrap() <= now + 90);
    w.finish().await;
}

/// A disabled person gets no token, and the tokens it holds stop working.
/// Enabled again, it gets tokens again, and the old ones stay dead.
#[tokio::test]
async fn a_disabled_user_gets_no_token_and_loses_the_ones_issued() {
    let Some(mut w) = x().await else { return };
    let t = w.token(&w.kc(KC, "kc-user-1"), AUD).await;
    assert_eq!(w.get("/v1/whoami", &t).await.status(), StatusCode::OK);
    let (a, me) = (w.a.key.clone(), principal(&t));
    w.store(async |tx| tutela_store::set_disabled(tx, &a, &me, true).await.unwrap())
        .await;
    assert_eq!(
        w.refused(&w.kc(KC, "kc-user-1"), AUD).await,
        "invalid_grant"
    );
    w.until_refused(&t).await;
    // Its own token, exchanged again: refused as well.
    assert_eq!(w.refused(&t, "crm-api").await, "invalid_grant");
    w.store(async |tx| {
        tutela_store::set_disabled(tx, &a, &me, false)
            .await
            .unwrap()
    })
    .await;
    let t2 = w.token(&w.kc(KC, "kc-user-1"), AUD).await;
    assert_eq!(principal(&t2), me);
    assert_eq!(claims(&t2).1["epoch"], 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(w.get("/v1/whoami", &t2).await.status(), StatusCode::OK);
    assert_eq!(
        w.get("/v1/whoami", &t).await.status(),
        StatusCode::UNAUTHORIZED
    );
    w.finish().await;
}

/// Revoking a person's sessions raises its epoch: every token issued before
/// is refused, and the next exchange carries the new epoch.
#[tokio::test]
async fn an_epoch_bump_revokes_issued_tokens() {
    let Some(mut w) = x().await else { return };
    let t = w.token(&w.kc(KC, "kc-user-1"), AUD).await;
    let crm = w.token(&t, "crm-api").await;
    let (a, me) = (w.a.key.clone(), principal(&t));
    let epoch = w
        .store(async |tx| tutela_store::revoke_sessions(tx, &a, &me).await.unwrap())
        .await;
    assert_eq!(epoch, 1);
    w.until_refused(&t).await;
    // Re-exchanging a revoked token gives nothing.
    assert_eq!(w.refused(&crm, AUD).await, "invalid_grant");
    let fresh = w.token(&w.kc(KC, "kc-user-1"), AUD).await;
    assert_eq!(claims(&fresh).1["epoch"], 1);
    assert_eq!(w.get("/v1/whoami", &fresh).await.status(), StatusCode::OK);
    w.finish().await;
}

/// TM-04: just-in-time provisioning keys on the upstream (iss, sub). Two
/// realms with the same subject and the same e-mail are two people; one
/// realm's subject is one person whatever its e-mail.
#[tokio::test]
async fn tm04_provisioning_keys_on_issuer_and_subject_never_email() {
    let Some(w) = x().await else { return };
    let one = principal(&w.token(&w.kc(KC, "same-sub"), AUD).await);
    let other_realm = principal(&w.token(&w.kc(KC_ALT, "same-sub"), AUD).await);
    assert_ne!(one, other_realm, "two realms, one e-mail: two accounts");
    let mut c = kc_claims(KC, "same-sub");
    c["email"] = json!("someone-else@example.test");
    assert_eq!(principal(&w.token(&w.kc_with(&c), AUD).await), one);
    let mut c = kc_claims(KC, "other-sub");
    c["email"] = json!("alice@example.test");
    assert_ne!(principal(&w.token(&w.kc_with(&c), AUD).await), one);
    w.finish().await;
}

/// A token of this service is exchanged for another registered audience:
/// same person, same tenant, never longer, scopes only narrower.
#[tokio::test]
async fn an_own_token_is_exchanged_for_another_audience_never_longer() {
    let Some(w) = x().await else { return };
    let t = w.token(&w.kc(KC, "kc-user-1"), AUD).await;
    let (status, body) = w
        .exchange_form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", &t),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("audience", "crm-api"),
            ("scope", "invoices"),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "invoices");
    let crm = body["access_token"].as_str().unwrap().to_owned();
    let (c0, c1) = (claims(&t).1, claims(&crm).1);
    assert_eq!(c1["aud"], "crm-api");
    assert_eq!(c1["sub"], c0["sub"]);
    assert_eq!(c1["tid"], c0["tid"]);
    assert_eq!(c1["sid"], c0["sid"]);
    assert!(c1["exp"].as_u64() <= c0["exp"].as_u64());
    // A crm-api token is not for this service's API.
    assert_eq!(
        w.get("/v1/whoami", &crm).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // Back to this service's audience: the scope cannot widen.
    let (status, body) = w
        .exchange_form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", &crm),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("audience", AUD),
            ("scope", "invoices reports"),
        ])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
    // An audience nobody registered.
    let (status, body) = w.exchange(&t, "billing").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
    w.finish().await;
}

/// Requests that are not a token exchange get the OAuth error for what is
/// wrong, and never echo a token.
#[tokio::test]
async fn the_token_endpoint_refuses_bad_requests() {
    let Some(w) = x().await else { return };
    let subject = w.kc(KC, "kc-user-1");
    let grant = (
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    let st = ("subject_token", subject.as_str());
    let stt = (
        "subject_token_type",
        "urn:ietf:params:oauth:token-type:access_token",
    );
    let aud = ("audience", AUD);
    for (pairs, error) in [
        (
            vec![("grant_type", "client_credentials"), st, stt, aud],
            "unsupported_grant_type",
        ),
        (vec![st, stt, aud], "invalid_request"),
        (vec![grant, st, stt], "invalid_request"),
        (
            vec![
                grant,
                st,
                stt,
                aud,
                ("resource", "https://crm.example.test"),
            ],
            "invalid_target",
        ),
        (vec![grant, st, aud], "invalid_request"),
        (
            vec![
                grant,
                st,
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:id_token",
                ),
                aud,
            ],
            "invalid_request",
        ),
        (
            vec![
                grant,
                st,
                stt,
                aud,
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                ),
            ],
            "invalid_request",
        ),
        (vec![grant, st, stt, aud, aud], "invalid_request"),
        (vec![grant, stt, aud], "invalid_request"),
    ] {
        let (status, body) = w.exchange_form(&pairs).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{pairs:?}");
        assert_eq!(body["error"], error, "{pairs:?}: {body}");
        assert!(!body.to_string().contains(&subject));
    }
    // JSON is not the form.
    let r = http()
        .post(w.s.api_url("/oauth2/token"))
        .json(&json!({"grant_type": grant.1, "subject_token": subject}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // Nothing above used the subject token up.
    w.token(&subject, AUD).await;
    w.finish().await;
}

/// The metadata names the token endpoint and the JWKS, without a token.
#[tokio::test]
async fn the_metadata_names_the_token_endpoint_and_the_jwks() {
    let Some(w) = x().await else { return };
    let m: Value = http()
        .get(w.s.api_url("/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["issuer"], OWN_ISS);
    assert_eq!(m["token_endpoint"], format!("{OWN_ISS}/oauth2/token"));
    assert_eq!(m["jwks_uri"], format!("{OWN_ISS}/.well-known/jwks.json"));
    assert_eq!(
        m["grant_types_supported"],
        json!(["urn:ietf:params:oauth:grant-type:token-exchange"])
    );
    w.finish().await;
}

/// Cross-tenant, through the real auth layer: a person of tenant A cannot
/// reach tenant B's resources with its exchanged token, and B's realm
/// cannot get it a token in A.
#[tokio::test]
async fn an_exchanged_token_stays_in_its_tenant() {
    let Some(mut w) = x().await else { return };
    let t = w.token(&w.kc(KC, "kc-user-1"), AUD).await;
    let me = principal(&t);
    // Give it a role in A, and ask about B's invoice: no role there.
    let (a, project) = (w.a.key.clone(), w.a.project.clone());
    let rev = w
        .store(async |tx| {
            tutela_store::assign(
                tx,
                &a,
                &tutela_pdp::Subject::Principal(me.clone()),
                &tutela_pdp::model::RoleKey::parse("reader").unwrap(),
                &project,
                None,
            )
            .await
            .unwrap()
            .1
        })
        .await;
    let mut in_b = ask(&me.to_string(), "invoice:read", &w.b);
    in_b["context"] = json!({"at_least_revision": rev});
    let (status, body) = w.post("/access/v1/evaluation", &t, &in_b).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], false);
    // The same upstream subject through B's realm is another person, in B.
    let tb = w.token(&w.kc(KC_B, "kc-user-1"), AUD).await;
    assert_ne!(principal(&tb), me);
    assert_eq!(claims(&tb).1["tid"], w.b.tid);
    // Disabling it in B does nothing to A's person.
    let (b, other) = (w.b.key.clone(), principal(&tb));
    w.store(async |tx| {
        tutela_store::set_disabled(tx, &b, &other, true)
            .await
            .unwrap()
    })
    .await;
    w.until_refused(&tb).await;
    assert_eq!(w.get("/v1/whoami", &t).await.status(), StatusCode::OK);
    w.finish().await;
}

/// ADR-0032, TM-06: an admin token is issued to a person whose sign-in
/// stepped up, for at most 300 s; to nobody else.
#[tokio::test]
async fn tm06_an_admin_token_is_for_a_person_after_step_up() {
    // Access tokens may live 600 s here; an admin token still lives 300 s.
    let Some(mut w) = x_with(|c| c.token_ttl = Duration::from_secs(600)).await else {
        return;
    };
    // No step-up: the one refusal that says why, so the Console asks for MFA.
    let (status, body) = w.exchange(&w.kc(KC, "kc-admin"), "tutela-admin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "step-up authentication is required"
    );

    // A realm token that lives 600 s: only the admin limit holds the new
    // token to 300 s.
    let mut c = kc_claims(KC, "kc-admin");
    c["acr"] = json!(common::STEP_UP);
    c["exp"] = json!(now() + 600);
    let admin = w.token(&w.kc_with(&c), "tutela-admin").await;
    let ac = claims(&admin).1;
    assert_eq!(ac["aud"], "tutela-admin");
    assert_eq!(ac["acr"], common::STEP_UP);
    assert!(ac["exp"].as_u64().unwrap() - ac["iat"].as_u64().unwrap() <= 300);
    // It is a person with no admin key yet: authenticated, refused.
    assert_eq!(
        w.get("/v1/models", &admin).await.status(),
        StatusCode::FORBIDDEN
    );
    let (a, org, me) = (w.a.key.clone(), w.a.org.clone(), principal(&admin));
    w.store(async |tx| {
        tutela_store::assign(
            tx,
            &a,
            &tutela_pdp::Subject::Principal(me.clone()),
            &tutela_pdp::model::RoleKey::parse("owner").unwrap(),
            &org,
            None,
        )
        .await
        .unwrap()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(w.get("/v1/models", &admin).await.status(), StatusCode::OK);
    // Not on a product route.
    assert_eq!(
        w.get("/v1/whoami", &admin).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // An own token that stepped up is exchanged for an admin token; one that
    // did not, never.
    c["jti"] = json!(uuid::Uuid::now_v7().to_string());
    let stepped = w.token(&w.kc_with(&c), AUD).await;
    w.token(&stepped, "tutela-admin").await;
    let plain = w.token(&w.kc(KC, "kc-admin"), AUD).await;
    assert_eq!(w.refused(&plain, "tutela-admin").await, "invalid_grant");
    // A service never gets one.
    let now = now();
    let sa =
        w.st.keys
            .sign_jwt(
                "at+jwt",
                &json!({
                    "iss": OWN_ISS, "sub": common::SA, "aud": AUD, "azp": "crm-api",
                    "exp": now + 300, "iat": now, "nbf": now,
                    "jti": uuid::Uuid::now_v7().to_string(),
                    "tid": w.a.tid, "epoch": 0, "rev": 0, "acr": common::STEP_UP,
                }),
            )
            .unwrap();
    assert_eq!(w.refused(&sa, "tutela-admin").await, "invalid_grant");
    let metrics = http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(r#"tutelad_token_operations_total{operation="admin",outcome="issued"} 2"#),
        "{metrics}"
    );
    w.finish().await;
}

/// With no step-up value configured, no admin token is issued at all.
#[tokio::test]
async fn tm22_no_step_up_configured_means_no_admin_token() {
    let Some(w) = x_with(|c| c.admin_acr.clear()).await else {
        return;
    };
    let mut c = kc_claims(KC, "kc-admin");
    c["acr"] = json!(common::STEP_UP);
    assert_eq!(
        w.refused(&w.kc_with(&c), "tutela-admin").await,
        "invalid_grant"
    );
    w.finish().await;
}

/// Every token issued, every just-in-time provisioning and every refusal
/// of a known tenant has its audit.v1 record (ADR-0034), with the token's
/// `jti` and never the token or an e-mail; a request whose tenant is not
/// known leaves nothing in any tenant's log.
#[tokio::test]
async fn tm20_every_token_issued_and_refused_has_its_record() {
    let Some(mut w) = x().await else { return };
    let kc = w.kc(KC, "kc-user-1");
    let t = w.token(&kc, AUD).await;
    let (_, c) = claims(&t);
    let me = c["sub"].as_str().unwrap().to_owned();
    let recs = common::audit_of(&mut w.d.owner, &w.a.key).await;
    assert_eq!(recs.len(), 2, "{recs:?}");
    let provision = &recs[0];
    assert_eq!(provision["action"], "tutela_principal:provision");
    assert_eq!(provision["actor"]["id"], me.as_str());
    assert_eq!(provision["details"]["upstream_iss"], KC);
    assert_eq!(provision["details"]["upstream_sub"], "kc-user-1");
    let issued = &recs[1];
    assert_eq!(issued["action"], "tutela_token:issue");
    assert_eq!(issued["outcome"], "success");
    assert_eq!(issued["service"], "tutelad");
    assert_eq!(issued["tenant"]["iss"], OWN_ISS);
    assert_eq!(issued["resource"]["id"], c["jti"]);
    assert_eq!(issued["details"]["jti"], c["jti"]);
    assert_eq!(issued["details"]["kind"], "access");
    assert_eq!(issued["details"]["principal"], me.as_str());
    assert_eq!(issued["details"]["aud"], AUD);
    assert_eq!(issued["details"]["azp"], "crm-web");
    assert_eq!(issued["details"]["exp"], c["exp"]);
    assert_eq!(issued["details"]["upstream_iss"], KC);

    // A replay is refused, and recorded with its reason and the upstream
    // issuer; the person is not known yet, so `tutelad` is the actor.
    assert_eq!(w.refused(&kc, AUD).await, "invalid_grant");
    // An own token for another audience: no upstream issuer, no new person.
    let other = w.token(&t, "crm-api").await;
    // A garbage token names no tenant: nothing is written anywhere.
    assert_eq!(w.refused("not.a.token", AUD).await, "invalid_grant");
    let recs = common::audit_of(&mut w.d.owner, &w.a.key).await;
    assert_eq!(recs.len(), 4, "{recs:?}");
    let replay = &recs[2];
    assert_eq!(replay["outcome"], "denied");
    assert_eq!(replay["decision"]["effect"], "deny");
    assert_eq!(replay["reason"], "replayed");
    assert_eq!(replay["details"]["reason"], "replayed");
    assert_eq!(replay["details"]["upstream_iss"], KC);
    assert_eq!(replay["actor"]["id"], tutelad::audit::SYSTEM);
    let again = &recs[3];
    assert_eq!(again["details"]["aud"], "crm-api");
    assert_eq!(again["details"]["jti"], claims(&other).1["jti"]);
    assert!(again["details"].get("upstream_iss").is_none());
    let text = serde_json::to_string(&recs).unwrap();
    for secret in [
        kc.as_str(),
        t.as_str(),
        other.as_str(),
        "alice@example.test",
    ] {
        assert!(!text.contains(secret));
    }
    // Tenant B's log has none of it.
    assert!(common::audit_of(&mut w.d.owner, &w.b.key).await.is_empty());
    w.finish().await;
}
