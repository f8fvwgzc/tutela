//! Webhook registration over the admin API, through the real auth layer on
//! a real Postgres, with a real relay and receiver (CONTRACTS.md 7.13.6,
//! ADR-0036 item 9): who may register, a secret shown once, rotation,
//! disabling, dead deliveries sent again; HTTP and gRPC; two tenants.
#![cfg(test)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode as AxumStatus};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::OutboxEvent;
use tutela_store::tokio_postgres::Client;
use tutelad::admin::grpc::pb;
use tutelad::admin::grpc::pb::admin_client::AdminClient;
use tutelad::webhooks::{Relay, Settings};

use common::{OWN_ISS, SA, Seed, USER, World, audit_of, http, world_with};

const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b1";
const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b2";
/// Holds `read_audit` and not `manage_access`: looks, may not register.
const AUDITOR: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b4";

const AUDITOR_ROLE: &str = "\n[roles.auditor]\ngrants = { \"org:read_audit\" = true }\nassignable_to = [\"sa\", \"user\"]\n";

/// One delivery a receiver got: id, timestamp, signature, body.
type Got = (String, String, String, Vec<u8>);

#[derive(Clone, Default)]
struct Receiver {
    got: Arc<Mutex<Vec<Got>>>,
    fail: Arc<Mutex<bool>>,
}

async fn hook(
    State(r): State<Receiver>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> AxumStatus {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    r.got.lock().unwrap().push((
        h("webhook-id"),
        h("webhook-timestamp"),
        h("webhook-signature"),
        body.to_vec(),
    ));
    if *r.fail.lock().unwrap() {
        AxumStatus::INTERNAL_SERVER_ERROR
    } else {
        AxumStatus::NO_CONTENT
    }
}

async fn receiver() -> (Receiver, String) {
    let r = Receiver::default();
    let app = axum::Router::new()
        .route("/hook", post(hook))
        .with_state(r.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (r, format!("http://{addr}/hook?token=do-not-record"))
}

fn verifies(secret: &str, got: &Got) -> bool {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap())
        .unwrap();
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key);
    let mut msg = format!("{}.{}.", got.0, got.1).into_bytes();
    msg.extend_from_slice(&got.3);
    got.2.split(' ').any(|s| {
        s.strip_prefix("v1,")
            .and_then(|b| STANDARD.decode(b).ok())
            .is_some_and(|sig| aws_lc_rs::hmac::verify(&key, &msg, &sig).is_ok())
    })
}

async fn assign(owner: &mut Client, s: &Seed, who: &str, role: &str) {
    let tx = owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &s.key,
        &Subject::Principal(who.parse().unwrap()),
        &RoleKey::parse(role).unwrap(),
        &s.org,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// The world, with admins, and an auditor who may look but not change; in
/// dev mode a webhook may be registered on loopback.
async fn w(dev: bool) -> Option<World> {
    let mut w = world_with(|c| c.dev_mode = dev).await?;
    common::publish(
        &mut w.d.owner,
        &format!("{}{AUDITOR_ROLE}", common::MANIFEST),
        Some(1),
    )
    .await;
    for who in [(ADMIN, "owner"), (ADMIN_SA, "owner"), (AUDITOR, "auditor")] {
        assign(&mut w.d.owner, &w.a, who.0, who.1).await;
        assign(&mut w.d.owner, &w.b, who.0, who.1).await;
    }
    Some(w)
}

fn console(w: &World, who: &str, s: &Seed) -> String {
    w.issuer.console(who, &s.tid, 0)
}

async fn call(
    w: &World,
    method: reqwest::Method,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut r = http().request(method, w.s.api_url(path)).bearer_auth(token);
    if let Some(b) = body {
        r = r.json(b);
    }
    let res = r.send().await.unwrap();
    let status = res.status();
    let text = res.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

fn problem(v: &Value) -> &str {
    v["type"]
        .as_str()
        .and_then(|t| t.strip_prefix("urn:tutela:problem:"))
        .unwrap_or("")
}

async fn grpc(w: &World) -> AdminClient<tonic::transport::Channel> {
    let channel = tonic::transport::Endpoint::from_shared(w.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    AdminClient::new(channel)
}

fn with_token<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn relay(w: &World, give_up: Duration) -> Relay {
    Relay::new(
        tutelad::db::Db::connect(&w.d.service_url, 2).unwrap(),
        common::vault(),
        OWN_ISS.parse().unwrap(),
        tutela_safenet::Policy::new().dev_loopback(),
        "r1".to_owned(),
        Settings {
            lease: Duration::from_secs(5),
            first_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            give_up,
            timeout: Duration::from_secs(5),
            batch: 32,
            retention: Duration::from_secs(3600),
        },
        Arc::new(tutelad::telemetry::Metrics::new()),
    )
    .unwrap()
}

async fn emit(w: &mut World, rev: u64) {
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::emit(&tx, &w.a.key, OutboxEvent::ModelPublished { rev })
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn tm18_only_an_admin_with_both_keys_registers_and_only_a_public_url() {
    let Some(mut w) = w(false).await else { return };
    let body =
        json!({"url": "https://hooks.example.test/in", "types": ["tutela.model.published.v1"]});
    let mut g = grpc(&w).await;
    for (what, t) in [
        (
            "read_audit without manage_access",
            console(&w, AUDITOR, &w.a),
        ),
        ("a service with no key", console(&w, SA, &w.a)),
        ("a person's plain token", w.issuer.token(ADMIN, &w.a.tid, 0)),
        ("a person with no key", console(&w, USER, &w.a)),
    ] {
        let (status, v) = call(
            &w,
            reqwest::Method::POST,
            "/v1/admin/webhooks",
            &t,
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {v}");
        let (status, _) = call(&w, reqwest::Method::GET, "/v1/admin/webhooks", &t, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
        let e = g
            .register_webhook(with_token(
                &t,
                pb::RegisterWebhookRequest {
                    url: "https://hooks.example.test/in".into(),
                    types: vec![],
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::PermissionDenied, "{what}");
    }
    // Outside dev mode, a URL inside the network never registers (TM-18).
    let admin = console(&w, ADMIN_SA, &w.a);
    for url in [
        "http://127.0.0.1:9/hook",
        "https://127.0.0.1/hook",
        "https://10.0.0.7/hook",
        "https://169.254.169.254/latest",
        "https://user:pass@hooks.example.test/in",
    ] {
        let (status, v) = call(
            &w,
            reqwest::Method::POST,
            "/v1/admin/webhooks",
            &admin,
            Some(&json!({"url": url})),
        )
        .await;
        assert_eq!(
            (status, problem(&v)),
            (StatusCode::BAD_REQUEST, "invalid_url"),
            "{url}: {v}"
        );
    }
    let (status, _) = call(
        &w,
        reqwest::Method::POST,
        "/v1/admin/webhooks",
        &admin,
        Some(&json!({"url": "https://hooks.example.test/in", "types": ["not a type"]})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, v) = call(&w, reqwest::Method::GET, "/v1/admin/webhooks", &admin, None).await;
    assert!(v["webhooks"].as_array().unwrap().is_empty());
    // Each refusal is recorded: the keys, and a refused URL by its host only.
    let refused: Vec<Value> = common::audited(&mut w.d.owner, &w.a.key, "tutela_webhook:register")
        .await
        .into_iter()
        .filter(|r| r["outcome"] == "denied")
        .collect();
    assert!(
        refused
            .iter()
            .any(|r| r["actor"]["id"] == AUDITOR && r["reason"] == "forbidden")
    );
    assert!(
        refused
            .iter()
            .any(|r| r["reason"] == "invalid_url" && r["details"]["host"] == "10.0.0.7")
    );
    assert!(!refused.iter().any(|r| r.to_string().contains("user:pass")));
    w.finish().await;
}

#[tokio::test]
async fn tm19_a_secret_is_shown_once_and_signs_what_the_relay_sends() {
    let Some(mut w) = w(true).await else { return };
    let (r, url) = receiver().await;
    let admin = console(&w, ADMIN, &w.a);
    let (status, v) = call(
        &w,
        reqwest::Method::POST,
        "/v1/admin/webhooks",
        &admin,
        Some(&json!({"url": url, "types": ["tutela.model.published.v1"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let id = v["webhook"]["id"].as_str().unwrap().to_owned();
    let first = v["secret"].as_str().unwrap().to_owned();
    assert!(first.starts_with("whsec_"));
    assert_eq!(v["webhook"]["created_by"], ADMIN);

    // Never shown again: not in a list, not in the audit log, not in the
    // table, where it is sealed. The URL's query never reaches a record.
    let (_, list) = call(&w, reqwest::Method::GET, "/v1/admin/webhooks", &admin, None).await;
    assert_eq!(list["webhooks"][0]["id"], id.as_str());
    assert!(!list.to_string().contains("whsec_"), "{list}");
    let chain = audit_of(&mut w.d.owner, &w.a.key).await;
    let text = serde_json::to_string(&chain).unwrap();
    assert!(!text.contains(&first) && !text.contains("whsec_"));
    assert!(!text.contains("do-not-record"));
    let su = w.d.superuser().await;
    let sealed: Vec<u8> = su
        .query_one("SELECT secret FROM tutela.webhook WHERE id = $1", &[&id])
        .await
        .unwrap()
        .get(0);
    assert!(!String::from_utf8_lossy(&sealed).contains(first.trim_start_matches("whsec_")));

    // The relay signs with it.
    let relay = relay(&w, Duration::from_secs(3600));
    emit(&mut w, 41).await;
    relay.tick().await.unwrap();
    {
        let got = r.got.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert!(verifies(&first, &got[0]));
    }

    // Rotated over gRPC: a new secret, once; both sign during the overlap.
    let mut g = grpc(&w).await;
    let rotated = g
        .rotate_webhook_secret(with_token(
            &admin,
            pb::RotateWebhookSecretRequest {
                id: id.clone(),
                overlap_secs: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(rotated.secret, first);
    emit(&mut w, 42).await;
    relay.tick().await.unwrap();
    {
        let got = r.got.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert!(verifies(&first, &got[1]) && verifies(&rotated.secret, &got[1]));
    }
    let text = serde_json::to_string(&audit_of(&mut w.d.owner, &w.a.key).await).unwrap();
    assert!(!text.contains(&rotated.secret));

    // Another tenant's admin sees none of it.
    let b_admin = console(&w, ADMIN, &w.b);
    let (_, v) = call(
        &w,
        reqwest::Method::GET,
        "/v1/admin/webhooks",
        &b_admin,
        None,
    )
    .await;
    assert!(v["webhooks"].as_array().unwrap().is_empty());
    for (method, path) in [
        (
            reqwest::Method::POST,
            format!("/v1/admin/webhooks/{id}/rotate"),
        ),
        (
            reqwest::Method::POST,
            format!("/v1/admin/webhooks/{id}/disable"),
        ),
        (
            reqwest::Method::GET,
            format!("/v1/admin/webhooks/{id}/deliveries"),
        ),
        (
            reqwest::Method::POST,
            format!("/v1/admin/webhooks/{id}/deliveries/1/redeliver"),
        ),
    ] {
        let body = (method == reqwest::Method::POST).then(|| json!({}));
        let (status, v) = call(&w, method, &path, &b_admin, body.as_ref()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {v}");
    }

    // Disabled: nothing more is sent.
    let (status, v) = call(
        &w,
        reqwest::Method::POST,
        &format!("/v1/admin/webhooks/{id}/disable"),
        &admin,
        Some(&json!({})),
    )
    .await;
    assert_eq!(
        (status, v["disabled"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    emit(&mut w, 43).await;
    relay.tick().await.unwrap();
    assert_eq!(r.got.lock().unwrap().len(), 2);

    for action in [
        "tutela_webhook:register",
        "tutela_webhook:rotate",
        "tutela_webhook:disable",
    ] {
        let rec = common::audited(&mut w.d.owner, &w.a.key, action).await;
        let ok: Vec<&Value> = rec.iter().filter(|r| r["outcome"] == "success").collect();
        assert_eq!(ok.len(), 1, "{action}");
        assert_eq!(ok[0]["actor"]["id"], ADMIN, "{action}");
        assert_eq!(ok[0]["details"]["webhook"], id.as_str(), "{action}");
    }
    w.finish().await;
}

#[tokio::test]
async fn a_dead_delivery_is_listed_and_sent_again_by_hand() {
    let Some(mut w) = w(true).await else { return };
    let (r, url) = receiver().await;
    *r.fail.lock().unwrap() = true;
    let service = console(&w, ADMIN_SA, &w.a);
    let mut g = grpc(&w).await;
    let made = g
        .register_webhook(with_token(
            &service,
            pb::RegisterWebhookRequest { url, types: vec![] },
        ))
        .await
        .unwrap()
        .into_inner();
    let id = made.webhook.unwrap().id;
    assert!(made.secret.starts_with("whsec_"));
    let relay = relay(&w, Duration::ZERO);
    emit(&mut w, 51).await;
    let t = relay.tick().await.unwrap();
    assert_eq!(t.dead, 1, "{t:?}");

    let dead_path = format!("/v1/admin/webhooks/{id}/deliveries?state=dead");
    let (status, v) = call(&w, reqwest::Method::GET, &dead_path, &service, None).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let seq = v["deliveries"][0]["seq"].as_u64().unwrap();
    assert_eq!(v["deliveries"][0]["state"], "dead");
    assert_eq!(v["deliveries"][0]["last_status"], 500);
    let (status, _) = call(
        &w,
        reqwest::Method::GET,
        &format!("/v1/admin/webhooks/{id}/deliveries?state=pending"),
        &service,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Sent again over gRPC, then delivered.
    *r.fail.lock().unwrap() = false;
    let d = g
        .redeliver(with_token(
            &service,
            pb::RedeliverRequest {
                id: id.clone(),
                seq,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(d.state, "pending");
    let relay = self::relay(&w, Duration::from_secs(3600));
    relay.tick().await.unwrap();
    let list = g
        .list_deliveries(with_token(
            &service,
            pb::ListDeliveriesRequest {
                id: id.clone(),
                ..pb::ListDeliveriesRequest::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.deliveries[0].state, "delivered");
    // A delivery that is not dead is not sent again.
    let e = g
        .redeliver(with_token(
            &service,
            pb::RedeliverRequest {
                id: id.clone(),
                seq,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    let rec = common::audited(&mut w.d.owner, &w.a.key, "tutela_webhook:redeliver").await;
    assert_eq!(rec[0]["actor"]["id"], ADMIN_SA);
    assert_eq!(rec[0]["details"]["seq"], seq);
    w.finish().await;
}
