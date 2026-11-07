//! CORS on a running `tutelad` (ADR-0054): off by default; with
//! `TUTELA_CORS_ORIGINS`, a listed origin's preflight is answered without a
//! token, its answers name it (never `*`, never credentials), and any other
//! origin gets nothing.
#![cfg(test)]

mod common;

use reqwest::{Method, StatusCode};

use common::{Issuer, http};

const APP: &str = "https://app.example.test";

async fn preflight(url: &str, origin: &str) -> reqwest::Response {
    http()
        .request(Method::OPTIONS, url)
        .header("origin", origin)
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization, content-type",
        )
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cors_names_only_listed_origins_and_never_credentials() {
    let Some(d) = common::migrated().await else {
        return;
    };
    let issuer = Issuer::new();
    let tid = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".to_owned();

    // Off by default: a preflight is a request like any other, 401.
    let cfg = common::config(&d.service_url, common::trust(std::slice::from_ref(&tid)));
    assert!(!cfg.cors.is_on());
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;
    let r = preflight(&s.api_url("/v1/authz/permissions"), APP).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(!r.headers().contains_key("access-control-allow-origin"));
    s.stop().await.unwrap();

    let mut cfg = common::config(&d.service_url, common::trust(&[tid]));
    cfg.cors = tutelad::cors::Cors::parse(APP, false).unwrap();
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;

    // A listed origin's preflight: answered without a token.
    for path in [
        "/v1/authz/permissions",
        "/oauth2/token",
        "/v1/admin/assignments",
    ] {
        let r = preflight(&s.api_url(path), APP).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "{path}");
        let h = r.headers();
        assert_eq!(h["access-control-allow-origin"], APP);
        assert!(
            h["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .contains("POST")
        );
        let allowed = h["access-control-allow-headers"].to_str().unwrap();
        assert!(allowed.contains("authorization") && allowed.contains("if-none-match"));
        assert!(!h.contains_key("access-control-allow-credentials"));
    }

    // Its answers name it, and let it read the tag, Retry-After and the
    // request id; a refusal too, so the page can tell why.
    let r = http()
        .get(s.api_url("/v1/whoami"))
        .header("origin", APP)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r.headers()["access-control-allow-origin"], APP);
    let exposed = r.headers()["access-control-expose-headers"]
        .to_str()
        .unwrap();
    assert!(
        exposed.contains("etag")
            && exposed.contains("retry-after")
            && exposed.contains("x-request-id")
    );
    assert!(!r.headers().contains_key("access-control-allow-credentials"));
    let r = http()
        .get(s.api_url("/.well-known/jwks.json"))
        .header("origin", APP)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["access-control-allow-origin"], APP);

    // Another origin, or one that only looks like it, gets nothing, and its
    // preflight still needs a token.
    for other in [
        "https://evil.example.test",
        "https://app.example.test.evil.test",
        "http://app.example.test",
        "null",
    ] {
        let r = preflight(&s.api_url("/v1/authz/permissions"), other).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{other}");
        assert!(
            !r.headers().contains_key("access-control-allow-origin"),
            "{other}"
        );
        let r = http()
            .get(s.api_url("/v1/whoami"))
            .header("origin", other)
            .send()
            .await
            .unwrap();
        assert!(
            !r.headers().contains_key("access-control-allow-origin"),
            "{other}"
        );
    }

    // An OPTIONS that is not a preflight is not answered here.
    let r = http()
        .request(Method::OPTIONS, s.api_url("/v1/whoami"))
        .header("origin", APP)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    s.stop().await.unwrap();
    d.finish().await;
}
