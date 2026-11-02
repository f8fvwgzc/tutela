//! `tutelad`'s own issuer: its signing keys, the JWKS, rotation, the `kid`
//! deny-list, and tenants made at runtime (ADR-0030, THREAT-MODEL.md TM-15).
#![cfg(test)]

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_store::KeyTimes;
use tutelad::api::AppState;

use common::{
    AUD, ISS, Issuer, MANIFEST, OWN_ISS, Running, SA, TestDb, config, http, migrated, now, publish,
    start, state, trust, vault,
};

/// A service with the test manifest, one tenant of the trust file, and the
/// state kept, so a test can make the key job run when it wants.
struct Own {
    d: TestDb,
    st: AppState,
    s: Running,
}

async fn own() -> Option<Own> {
    let mut d = migrated().await?;
    publish(&mut d.owner, MANIFEST, None).await;
    let fixed = common::tenant(&mut d.owner).await;
    let cfg = config(&d.service_url, trust(&[fixed.tid.to_string()]));
    let st = state(&cfg, &Issuer::new());
    let s = start(&cfg, st.clone()).await;
    Some(Own { d, st, s })
}

impl Own {
    /// What the key job does on its timer.
    async fn refresh(&self) {
        tutelad::keys::refresh(
            &self.st.keys,
            &self.st.verifier,
            &self.st.db,
            &self.st.metrics,
        )
        .await
        .unwrap();
    }

    async fn jwks(&self) -> (reqwest::header::HeaderMap, Vec<String>) {
        let r = http()
            .get(self.s.api_url("/.well-known/jwks.json"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let headers = r.headers().clone();
        let body: Value = r.json().await.unwrap();
        let kids = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| {
                assert_eq!(k["kty"], "EC");
                assert_eq!(k["crv"], "P-256");
                assert_eq!(k["alg"], "ES256");
                assert_eq!(k["use"], "sig");
                assert!(k.get("d").is_none(), "a private part in the JWKS");
                k["kid"].as_str().unwrap().to_owned()
            })
            .collect();
        (headers, kids)
    }

    /// A token of the service's own issuer for `sub` in `tid`.
    fn token(&self, sub: &str, tid: &str) -> String {
        let now = now();
        self.st
            .keys
            .sign_jwt(
                "at+jwt",
                &json!({
                    "iss": OWN_ISS, "sub": sub, "aud": AUD, "azp": "crm-web",
                    "exp": now + 300, "iat": now, "nbf": now,
                    "jti": uuid::Uuid::now_v7().to_string(),
                    "tid": tid, "epoch": 0, "rev": 0,
                }),
            )
            .unwrap()
    }

    async fn whoami(&self, token: &str) -> reqwest::Response {
        http()
            .get(self.s.api_url("/v1/whoami"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }

    async fn rotate(&mut self, times: KeyTimes) -> tutela_store::Rotation {
        let tx = self.d.owner.transaction().await.unwrap();
        let r = tutela_store::rotate_signing_key(&tx, &vault(), times)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        self.refresh().await;
        r
    }

    async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }
}

fn kid_of(token: &str) -> String {
    use base64::Engine as _;
    let header = token.split('.').next().unwrap();
    let header: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header)
            .unwrap(),
    )
    .unwrap();
    header["kid"].as_str().unwrap().to_owned()
}

/// The JWKS needs no token, is cacheable for the configured time, and a
/// rotation publishes the next key before it signs.
#[tokio::test]
async fn tm15_the_jwks_is_public_and_publishes_the_next_key_first() {
    let Some(mut w) = own().await else { return };
    let (headers, kids) = w.jwks().await;
    assert_eq!(headers["content-type"], "application/jwk-set+json");
    assert_eq!(headers["cache-control"], "public, max-age=300");
    assert_eq!(kids.len(), 1, "the first start makes one key");
    let first = kids[0].clone();

    // `tutela keys rotate` (part 4) calls this store function.
    let r = w
        .rotate(tutelad::keys::rotation_times(Duration::from_secs(300)))
        .await;
    assert!(r.made);
    assert_eq!(
        r.previous.as_ref().map(|p| p.0.clone()),
        Some(first.clone())
    );
    let (_, kids) = w.jwks().await;
    assert_eq!(kids, vec![first.clone(), r.next.clone()]);
    // The old key still signs: the next one is not in every cache yet.
    let t = common::tenant_of(&mut w.d.owner, OWN_ISS).await;
    let token = w.token(SA, &t.tid.to_string());
    assert_eq!(kid_of(&token), first);
    assert_eq!(w.whoami(&token).await.status(), StatusCode::OK);
    w.finish().await;
}

/// After the switch the next key signs, and a token the old key signed
/// still verifies until the old key leaves the JWKS.
#[tokio::test]
async fn tm15_a_token_of_the_previous_key_verifies_after_the_switch() {
    let Some(mut w) = own().await else { return };
    let t = common::tenant_of(&mut w.d.owner, OWN_ISS).await;
    let tid = t.tid.to_string();
    let old = w.token(SA, &tid);
    let r = w
        .rotate(KeyTimes {
            lead: Duration::ZERO,
            keep: Duration::from_secs(660),
        })
        .await;
    let new = w.token(SA, &tid);
    assert_eq!(kid_of(&new), r.next);
    assert_ne!(kid_of(&old), kid_of(&new));
    assert_eq!(w.whoami(&new).await.status(), StatusCode::OK);
    assert_eq!(w.whoami(&old).await.status(), StatusCode::OK);
    w.finish().await;
}

/// TM-15, the emergency: a denied `kid` is refused at once, also when the
/// verifier has it cached, it leaves the JWKS, and a new key signs.
#[tokio::test]
async fn tm15_a_denied_kid_is_refused_at_once() {
    let Some(mut w) = own().await else { return };
    let t = common::tenant_of(&mut w.d.owner, OWN_ISS).await;
    let tid = t.tid.to_string();
    let before = w.token(SA, &tid);
    // Verified once, so its key is in the verifier's cache.
    assert_eq!(w.whoami(&before).await.status(), StatusCode::OK);
    let kid = kid_of(&before);
    let tx = w.d.owner.transaction().await.unwrap();
    let replacement = tutela_store::deny_signing_key(&tx, &vault(), &kid)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    w.refresh().await;
    assert_eq!(w.whoami(&before).await.status(), StatusCode::UNAUTHORIZED);
    let (_, kids) = w.jwks().await;
    assert_eq!(kids, vec![replacement.clone()]);
    let after = w.token(SA, &tid);
    assert_eq!(kid_of(&after), replacement);
    assert_eq!(w.whoami(&after).await.status(), StatusCode::OK);
    w.finish().await;
}

/// A tenant made after the service started works through the service's own
/// issuer: the trust file never named it, and the directory decides. A
/// tenant the directory does not have under this issuer is refused, and so
/// is a token that claims the own issuer with another key.
#[tokio::test]
async fn a_tenant_made_at_runtime_is_trusted_through_the_own_issuer() {
    let Some(mut w) = own().await else { return };
    let t = common::tenant_of(&mut w.d.owner, OWN_ISS).await;
    let tid = t.tid.to_string();
    let r = w.whoami(&w.token(SA, &tid)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["iss"], OWN_ISS);
    assert_eq!(body["tid"], tid);

    // Not in the directory at all.
    let unknown = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f9999";
    let r = w.whoami(&w.token(SA, unknown)).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["type"], "urn:tutela:problem:unknown_tenant");

    // In the directory under the other issuer: (iss, tid) is the tenant
    // key, so the own issuer cannot speak for it (TM-05).
    let other = common::tenant_of(&mut w.d.owner, ISS).await;
    let r = w.whoami(&w.token(SA, &other.tid.to_string())).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // The own issuer's name with a key that is not the service's.
    let forged = Issuer::new().sign_claims(&json!({
        "iss": OWN_ISS, "sub": SA, "aud": AUD, "azp": "crm-web",
        "exp": now() + 300, "iat": now(), "nbf": now(),
        "jti": uuid::Uuid::now_v7().to_string(),
        "tid": tid, "epoch": 0, "rev": 0,
    }));
    assert_eq!(w.whoami(&forged).await.status(), StatusCode::UNAUTHORIZED);
    w.finish().await;
}

/// Two replicas that start on one empty key table make one key between
/// them, and both serve it.
#[tokio::test]
async fn replicas_that_start_together_make_one_key() {
    let Some(mut d) = migrated().await else {
        return;
    };
    publish(&mut d.owner, MANIFEST, None).await;
    let fixed = common::tenant(&mut d.owner).await;
    let cfg = config(&d.service_url, trust(&[fixed.tid.to_string()]));
    let (a, b) = (state(&cfg, &Issuer::new()), state(&cfg, &Issuer::new()));
    let (ra, rb) = tokio::join!(
        tutelad::keys::refresh(&a.keys, &a.verifier, &a.db, &a.metrics),
        tutelad::keys::refresh(&b.keys, &b.verifier, &b.db, &b.metrics),
    );
    ra.unwrap();
    rb.unwrap();
    assert_eq!(a.keys.published(), b.keys.published());
    assert_eq!(a.keys.published().len(), 1);
    d.finish().await;
}
