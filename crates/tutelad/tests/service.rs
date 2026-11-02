//! The service end to end, over real sockets: the two ports, bearer tokens
//! on HTTP and gRPC, metrics, logs and the graceful shutdown.

#[cfg(test)]
mod common;

use std::time::Duration;

use common::{ISS, Issuer, USER, config, db, http, now, start, state, trust};
use reqwest::StatusCode;
use serde_json::Value;

const TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
const OTHER_TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c";
const AUD: &str = "tutela-authz";
/// No database behind this: most tests here never reach one.
const NO_DB: &str = "host=127.0.0.1 port=1 user=nobody dbname=nothing";

#[tokio::test]
async fn the_api_port_answers_nothing_without_a_token() {
    let issuer = Issuer::new();
    let cfg = config(NO_DB, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    // A known route, an unknown one, and the ops routes on the wrong port.
    for path in ["/v1/whoami", "/nothing/here", "/healthz", "/metrics"] {
        let r = c.get(s.api_url(path)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            r.headers()["www-authenticate"],
            "Bearer error=\"invalid_token\""
        );
        assert_eq!(r.headers()["content-type"], "application/problem+json");
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["type"], "urn:tutela:problem:invalid_token");
        assert_eq!(body["status"], 401);
    }
    s.stop().await.unwrap();
}

#[tokio::test]
async fn a_verified_token_gets_through_and_every_bad_one_gets_the_same_401() {
    let issuer = Issuer::new();
    let cfg = config(NO_DB, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let token = issuer.sign(ISS, TID, AUD, now());
    let r = c
        .get(s.api_url("/v1/whoami"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.headers().contains_key("x-request-id"));
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["iss"], ISS);
    assert_eq!(body["tid"], TID);
    assert_eq!(body["sub"], USER);
    assert_eq!(body["kind"], "access");

    // An unknown path behind a good token is a plain 404.
    let r = c
        .get(s.api_url("/nothing/here"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(r.headers()["content-type"], "application/problem+json");

    let other_key = Issuer::new().sign(ISS, TID, AUD, now());
    let bad = [
        issuer.sign(ISS, TID, "another-audience", now()),
        issuer.sign(ISS, OTHER_TID, AUD, now()),
        issuer.sign("https://evil.example.test", TID, AUD, now()),
        issuer.sign(ISS, TID, AUD, now() - 3600),
        other_key,
        "not-a-token".to_owned(),
    ];
    let mut bodies = Vec::new();
    for token in &bad {
        let r = c
            .get(s.api_url("/v1/whoami"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{token}");
        bodies.push(r.text().await.unwrap());
    }
    // The response says nothing about the failed step.
    bodies.dedup();
    assert_eq!(bodies.len(), 1, "{bodies:?}");

    // The steps are in the metrics, and no token is.
    let text = c
        .get(s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains(r#"tutelad_auth_refusals_total{step="key"} 1"#),
        "{text}"
    );
    assert!(
        text.contains(r#"tutelad_auth_refusals_total{step="claims"}"#),
        "{text}"
    );
    assert!(text.contains(r#"route="/v1/whoami""#), "{text}");
    assert!(!text.contains(&token), "a token reached the metrics");
    assert!(
        !text.contains("nothing/here"),
        "an unknown URL became a label"
    );
    assert!(!text.contains(TID), "a tenant became a label");
    s.stop().await.unwrap();
}

#[tokio::test]
async fn health_needs_no_database_and_readiness_does() {
    let issuer = Issuer::new();
    let cfg = config(NO_DB, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let r = c.get(s.ops_url("/healthz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = c.get(s.ops_url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["database"], "failed");
    s.stop().await.unwrap();
}

#[tokio::test]
async fn readiness_needs_the_schema_this_build_knows() {
    let Some(mut d) = db().await else { return };
    tutela_store::migrate(&mut d.owner).await.unwrap();
    d.owner
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA tutela TO {s}; \
             GRANT SELECT ON tutela.schema_migration TO {s};",
            s = common::SERVICE
        ))
        .await
        .unwrap();
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let r = c.get(s.ops_url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["status"], "ready");

    // A migration this build does not know: an old binary never runs on a
    // newer schema (ADR-0014).
    d.owner
        .batch_execute(
            "INSERT INTO tutela.schema_migration (version, name) VALUES (9999, 'future')",
        )
        .await
        .unwrap();
    let r = c.get(s.ops_url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    s.stop().await.unwrap();
    d.finish().await;
}

#[tokio::test]
async fn grpc_is_on_the_api_port_behind_the_same_token_check() {
    use tonic_health::pb::HealthCheckRequest;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::health_client::HealthClient;

    let issuer = Issuer::new();
    let cfg = config(NO_DB, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let channel = tonic::transport::Endpoint::from_shared(s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HealthClient::new(channel);

    let e = client
        .check(HealthCheckRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::Unauthenticated);

    let mut req = tonic::Request::new(HealthCheckRequest::default());
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", issuer.sign(ISS, TID, AUD, now()))
            .parse()
            .unwrap(),
    );
    let r = client.check(req).await.unwrap();
    assert_eq!(r.into_inner().status, ServingStatus::Serving as i32);
    s.stop().await.unwrap();
}

/// Readiness fails while requests still work, then a running request
/// finishes, then the service exits cleanly.
#[tokio::test]
async fn a_shutdown_fails_readiness_first_and_finishes_running_requests() {
    let issuer = Issuer::new();
    let mut cfg = config(NO_DB, trust(&[TID.to_owned()]));
    cfg.shutdown_drain = Duration::from_millis(600);
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let token = issuer.sign(ISS, TID, AUD, now());
    let (api, ops) = (s.api_url("/v1/whoami"), s.ops_url("/readyz"));
    let stopping = tokio::spawn(s.stop());

    // Inside the drain time.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let body: Value = c.get(&ops).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["stopping"], true);
    assert_eq!(body["status"], "not_ready");
    let r = c.get(&api).bearer_auth(&token).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    stopping.await.unwrap().unwrap();
    assert!(c.get(&api).bearer_auth(&token).send().await.is_err());
}

/// The real binary: it starts from the environment, logs JSON with no
/// token in it, and exits 0 on SIGTERM.
#[tokio::test]
async fn the_binary_serves_and_stops_on_sigterm() {
    use std::process::Stdio;

    use tokio::io::{AsyncBufReadExt as _, BufReader};

    let dir = std::env::temp_dir();
    let trust_path = dir.join(format!("tutelad-bin-{}.toml", std::process::id()));
    std::fs::write(
        &trust_path,
        format!(
            "[[issuer]]\niss = \"{ISS}\"\njwks_uri = \"{ISS}/jwks\"\nalgs = [\"ES256\"]\n\
             tenants = [\"{TID}\"]\n"
        ),
    )
    .unwrap();
    let free = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    };
    let (api, ops) = (free(), free());
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_tutelad"))
        .env_clear()
        .env("RUST_BACKTRACE", "1")
        .env("RUST_LIB_BACKTRACE", "0")
        .env("TUTELA_DATABASE_URL", NO_DB)
        .env("TUTELA_TRUST_FILE", &trust_path)
        .env("TUTELA_LISTEN", api.to_string())
        .env("TUTELA_OPS_LISTEN", ops.to_string())
        .env("TUTELA_SHUTDOWN_DRAIN_SECS", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let pid = child.id().unwrap().to_string();
    let c = http();
    let url = format!("http://{ops}/healthz");
    let mut up = false;
    for _ in 0..100 {
        if c.get(&url).send().await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "the binary did not start");

    // A token the service cannot verify (the JWKS host is not reachable).
    let token = Issuer::new().sign(ISS, TID, AUD, now());
    let r = c
        .get(format!("http://{api}/v1/whoami"))
        .bearer_auth(&token)
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let killed = tokio::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .await
        .unwrap();
    assert!(killed.success());
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("the binary did not stop on SIGTERM")
        .unwrap();
    assert_eq!(status.code(), Some(0));

    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut served = None;
    while let Some(line) = lines.next_line().await.unwrap() {
        assert!(!line.contains(&token), "a token reached the log: {line}");
        let v: Value = serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line}"));
        if v["message"] == "request served" {
            served = Some(v);
        }
    }
    let served = served.expect("the request was not logged");
    assert_eq!(served["status"], 401);
    assert_eq!(served["refused_at"], "key");
    assert_eq!(served["span"]["route"], "/v1/whoami");
    assert_eq!(
        served["span"]["trace_id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    std::fs::remove_file(trust_path).unwrap();
}

#[tokio::test]
async fn a_lost_database_does_not_fail_liveness() {
    let Some(d) = db().await else { return };
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    d.finish().await;
    assert_eq!(
        c.get(s.ops_url("/healthz")).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        c.get(s.ops_url("/readyz")).send().await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    s.stop().await.unwrap();
}
