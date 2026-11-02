//! The Tutela Console served by a running `tutelad` (ADR-0050): its paths
//! need no token and carry the security headers, every other path still
//! needs one, a traversal reaches nothing, and with no directory set
//! nothing is served.
#![cfg(test)]

mod common;

use std::path::PathBuf;

use reqwest::StatusCode;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tutelad::config::TrustFile;

use common::{Issuer, http};

const KC: &str = "https://kc.example.test/realms/acme";

/// A built Console, and a secret file next to it that no path may reach.
fn built() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tutela-console-it-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Tutela Console</title>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/index-4a5b6c.js"), "export {};").unwrap();
    std::fs::write(dir.with_extension("secret"), "SECRET").unwrap();
    dir
}

fn trust(tid: &str) -> TrustFile {
    TrustFile::parse(
        &format!(
            "[[issuer]]\niss = \"{KC}\"\njwks_uri = \"{KC}/protocol/openid-connect/certs\"\n\
             algs = [\"ES256\"]\ntenants = [\"{tid}\"]\nexternal = true\nallow_typ_jwt = true\n"
        ),
        false,
    )
    .unwrap()
}

/// One request written by hand, so no client tidies the path first.
async fn raw(addr: std::net::SocketAddr, path: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_console_is_served_without_a_token_and_nothing_else_is() {
    let Some(d) = common::migrated().await else {
        return;
    };
    let dir = built();
    let tid = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c";
    let mut cfg = common::config(&d.service_url, trust(tid));
    cfg.console = Some(
        tutelad::console::ConsoleConfig::from_values(
            dir.to_str().unwrap(),
            Some(KC),
            Some("tutela-console"),
            &cfg.admin_acr,
            cfg.audience.as_str(),
            &[KC.parse().unwrap()],
        )
        .unwrap(),
    );
    let issuer = Issuer::new();
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;
    let c = http();

    // The Console's paths: no token, the strict headers.
    for path in ["/console/", "/console/scopes", "/console/roles/"] {
        let r = c.get(s.api_url(path)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        let csp = r.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            csp.starts_with("default-src 'self'; script-src 'self'; style-src 'self';"),
            "{csp}"
        );
        assert!(
            csp.contains("connect-src 'self' https://kc.example.test;"),
            "{csp}"
        );
        assert!(
            csp.contains("frame-ancestors 'none'") && csp.contains("base-uri 'none'"),
            "{csp}"
        );
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        assert!(r.headers().contains_key("x-request-id"));
        assert!(
            r.text()
                .await
                .unwrap()
                .contains("<title>Tutela Console</title>")
        );
    }
    let r = c
        .get(s.api_url("/console/assets/index-4a5b6c.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
    let v: serde_json::Value = c
        .get(s.api_url("/console/config.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["issuer"], KC);
    assert_eq!(v["client_id"], "tutela-console");
    assert_eq!(v["step_up_acr"], common::STEP_UP);

    // Every other path still needs a token: the page fallback is the
    // Console's only, never the API's.
    for path in [
        "/v1/whoami",
        "/v1/admin/tenant",
        "/v1/scopes",
        "/consoles",
        "/v1/console/",
        "/index.html",
    ] {
        let r = c.get(s.api_url(path)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    // A POST to the Console is not a way in.
    let r = c
        .post(s.api_url("/console/config.json"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Traversals, sent as written: nothing outside the files read at start.
    for path in [
        "/console/../v1/whoami",
        "/console/..%2f..%2fCargo.toml",
        "/console/%2e%2e/%2e%2e/secret",
        "/console/assets/../../tutela-console-it.secret",
        "/console/assets/..%5c..%5csecret",
    ] {
        let out = raw(s.api, path).await;
        assert!(out.starts_with("HTTP/1.1 404"), "{path}: {out}");
        assert!(out.contains("x-content-type-options: nosniff"), "{out}");
        assert!(!out.contains("SECRET"), "{path}");
    }

    s.stop().await.unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(dir.with_extension("secret")).unwrap();

    // With no directory set, nothing is served: `/console/` is a path like
    // any other, behind the token check.
    let mut cfg = common::config(&d.service_url, trust(tid));
    cfg.console = None;
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;
    for path in ["/console/", "/console/config.json", "/console/scopes"] {
        let r = c.get(s.api_url(path)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert!(!r.headers().contains_key("content-security-policy"));
    }
    s.stop().await.unwrap();
    d.finish().await;
}
