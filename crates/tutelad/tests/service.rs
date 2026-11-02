//! The service end to end, over real sockets: the two ports, bearer tokens
//! on HTTP and gRPC, metrics, logs and the graceful shutdown.

#[cfg(test)]
mod common;

use std::time::Duration;

use common::{
    ISS, Issuer, SERVICE, USER, config, db, http, migrated, now, start, state, tenant, trust,
};
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
    let Some(mut d) = migrated().await else {
        return;
    };
    let t = tenant(&mut d.owner).await;
    let tid = t.tid.to_string();
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, trust(std::slice::from_ref(&tid)));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let token = issuer.sign(ISS, &tid, AUD, now());
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
    assert_eq!(body["tid"], tid);
    assert_eq!(body["sub"], USER);
    assert_eq!(body["kind"], "access");
    assert_eq!(body["rev"], 0);

    // An unknown path behind a good token is a plain 404.
    let r = c
        .get(s.api_url("/nothing/here"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(r.headers()["content-type"], "application/problem+json");

    let other_key = Issuer::new().sign(ISS, &tid, AUD, now());
    let bad = [
        issuer.sign(ISS, &tid, "another-audience", now()),
        issuer.sign(ISS, OTHER_TID, AUD, now()),
        issuer.sign("https://evil.example.test", &tid, AUD, now()),
        issuer.sign(ISS, &tid, AUD, now() - 3600),
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
    assert!(!text.contains(&tid), "a tenant became a label");
    s.stop().await.unwrap();
    d.finish().await;
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
    let Some(mut d) = migrated().await else {
        return;
    };
    let t = tenant(&mut d.owner).await;
    let tid = t.tid.to_string();
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, trust(std::slice::from_ref(&tid)));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let token = issuer.sign(ISS, &tid, AUD, now());
    let whoami = || {
        let req = c.get(s.api_url("/v1/whoami")).bearer_auth(&token);
        async move { req.send().await.unwrap().status() }
    };
    let r = c.get(s.ops_url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(whoami().await, StatusCode::OK);

    // A migration this build does not know: an old binary never runs on a
    // newer schema (ADR-0014). Readiness fails, and queries stop with it.
    d.owner
        .batch_execute(
            "INSERT INTO tutela.schema_migration (version, name) VALUES (9999, 'future')",
        )
        .await
        .unwrap();
    let r = c.get(s.ops_url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    for _ in 0..2 {
        assert_eq!(whoami().await, StatusCode::SERVICE_UNAVAILABLE);
    }

    // It recovers by itself when the check passes again.
    d.owner
        .batch_execute("DELETE FROM tutela.schema_migration WHERE version = 9999")
        .await
        .unwrap();
    assert_eq!(whoami().await, StatusCode::OK);
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
    let Some(mut d) = migrated().await else {
        return;
    };
    let t = tenant(&mut d.owner).await;
    let tid = t.tid.to_string();
    let issuer = Issuer::new();
    let mut cfg = config(&d.service_url, trust(std::slice::from_ref(&tid)));
    cfg.shutdown_drain = Duration::from_millis(600);
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let token = issuer.sign(ISS, &tid, AUD, now());
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
    d.finish().await;
}

/// The real binary, on free ports, with a trust file on disk.
struct Binary {
    child: tokio::process::Child,
    api: std::net::SocketAddr,
    trust_path: std::path::PathBuf,
}

impl Binary {
    /// Starts it, and waits for the ops port.
    async fn start(name: &str, trust: &str, database_url: &str, dev_mode: bool) -> Self {
        let trust_path =
            std::env::temp_dir().join(format!("tutelad-bin-{}-{name}.toml", std::process::id()));
        std::fs::write(&trust_path, trust).unwrap();
        let free = || {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
        };
        let (api, ops) = (free(), free());
        let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_tutelad"))
            .env_clear()
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .env("TUTELA_DATABASE_URL", database_url)
            .env("TUTELA_TRUST_FILE", &trust_path)
            .env("TUTELA_LISTEN", api.to_string())
            .env("TUTELA_OPS_LISTEN", ops.to_string())
            .env("TUTELA_SHUTDOWN_DRAIN_SECS", "0")
            .env("TUTELA_DEV_MODE", if dev_mode { "1" } else { "0" })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
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
        Self {
            child,
            api,
            trust_path,
        }
    }

    fn whoami(&self) -> String {
        format!("http://{}/v1/whoami", self.api)
    }

    /// Sends SIGTERM, expects exit 0, and returns the JSON log lines. No
    /// line may hold `secret`.
    async fn stop(mut self, secret: &str) -> Vec<Value> {
        use tokio::io::{AsyncBufReadExt as _, BufReader};

        let pid = self.child.id().unwrap().to_string();
        let killed = tokio::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .await
            .unwrap();
        assert!(killed.success());
        let status = tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .expect("the binary did not stop on SIGTERM")
            .unwrap();
        assert_eq!(status.code(), Some(0));
        std::fs::remove_file(&self.trust_path).unwrap();
        let mut lines = BufReader::new(self.child.stdout.take().unwrap()).lines();
        let mut out = Vec::new();
        while let Some(line) = lines.next_line().await.unwrap() {
            assert!(!line.contains(secret), "a token reached the log: {line}");
            out.push(serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line}")));
        }
        out
    }
}

/// The real binary: it starts from the environment, logs JSON with no
/// token in it, and exits 0 on SIGTERM.
#[tokio::test]
async fn the_binary_serves_and_stops_on_sigterm() {
    let trust = format!(
        "[[issuer]]\niss = \"{ISS}\"\njwks_uri = \"{ISS}/jwks\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{TID}\"]\n"
    );
    let bin = Binary::start("sigterm", &trust, NO_DB, false).await;
    // A token the service cannot verify (the JWKS host is not reachable).
    let token = Issuer::new().sign(ISS, TID, AUD, now());
    let r = http()
        .get(bin.whoami())
        .bearer_auth(&token)
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let logs = bin.stop(&token).await;
    let served = logs
        .iter()
        .find(|v| v["message"] == "request served")
        .expect("the request was not logged");
    assert_eq!(served["status"], 401);
    assert_eq!(served["refused_at"], "key");
    assert_eq!(served["span"]["route"], "/v1/whoami");
    assert_eq!(
        served["span"]["trace_id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
}

/// The whole path, with nothing in memory: the binary reads a trust file,
/// fetches the JWKS over a socket through `tutela-safenet`, verifies a real
/// token, enters the tenant on a real Postgres, and logs the tenant id.
#[tokio::test]
async fn the_binary_verifies_a_token_against_a_served_jwks() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let issuer = Issuer::new();
    let jwks = issuer.jwks();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let iss = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/jwks",
        axum::routing::get(move || {
            let body = jwks.clone();
            async move { body }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });

    let t = common::tenant_of(&mut d.owner, &iss).await;
    let tid = t.tid.to_string();
    let trust = format!(
        "[[issuer]]\niss = \"{iss}\"\njwks_uri = \"{iss}/jwks\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{tid}\"]\n"
    );
    let bin = Binary::start("jwks", &trust, &d.service_url, true).await;
    let token = issuer.sign(&iss, &tid, AUD, now());
    let r = http()
        .get(bin.whoami())
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["tid"], tid);
    assert_eq!(body["iss"], iss);
    assert_eq!(body["rev"], 0);

    let logs = bin.stop(&token).await;
    let served = logs
        .iter()
        .find(|v| v["message"] == "request served")
        .expect("the request was not logged");
    assert_eq!(served["status"], 200);
    assert_eq!(served["span"]["tid"], tid);
    d.finish().await;
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

/// The deploy step: as the owner, migrations and grants. Nothing else is
/// needed for the service to be ready.
#[tokio::test]
async fn tutelad_migrate_makes_the_schema_and_the_grants() {
    let Some(d) = db().await else { return };
    let run = |vars: Vec<(&'static str, String)>| {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_tutelad"));
        cmd.arg("migrate").env_clear().envs(vars);
        async move { cmd.output().await.unwrap() }
    };
    let out = run(vec![]).await;
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("TUTELA_OWNER_DATABASE_URL is not set"),
        "{err}"
    );

    let vars = vec![
        ("TUTELA_OWNER_DATABASE_URL", d.owner_url.clone()),
        ("TUTELA_SERVICE_ROLE", SERVICE.to_owned()),
    ];
    let out = run(vars.clone()).await;
    assert!(out.status.success(), "{out:?}");
    // It may run again.
    let out = run(vars).await;
    assert!(out.status.success(), "{out:?}");

    let issuer = Issuer::new();
    let cfg = config(&d.service_url, trust(&[TID.to_owned()]));
    let st = state(&cfg, &issuer);
    st.db.check_ready().await.unwrap();
    d.finish().await;
}

/// A token the trust list allows, for a tenant the directory does not have.
#[tokio::test]
async fn a_tenant_that_is_not_in_the_directory_is_refused() {
    let Some(d) = migrated().await else { return };
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, trust(&[TID.to_owned()]));
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let r = http()
        .get(s.api_url("/v1/whoami"))
        .bearer_auth(issuer.sign(ISS, TID, AUD, now()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["type"], "urn:tutela:problem:unknown_tenant");
    s.stop().await.unwrap();
    d.finish().await;
}
