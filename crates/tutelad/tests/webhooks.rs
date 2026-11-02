//! Webhook delivery from the outbox on a real Postgres, to a real receiver
//! on loopback (ADR-0036, CONTRACTS.md 8.4, 8.5, THREAT-MODEL.md TM-18,
//! TM-19).
#![cfg(test)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::hmac;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use tutela_contracts::events::EventType;
use tutela_safenet::Policy;
use tutela_store::OutboxEvent;
use tutela_store::webhooks::WebhookSecret;
use tutelad::webhooks::{Relay, Settings};

use common::{OWN_ISS, TestDb, migrated, vault};

/// What the receiver got: the headers it checks and the body.
#[derive(Clone, Debug)]
struct Got {
    id: String,
    timestamp: String,
    signature: String,
    content_type: String,
    body: Vec<u8>,
}

#[derive(Clone, Default)]
struct Receiver {
    got: Arc<Mutex<Vec<Got>>>,
    /// Answer 500 to this many requests first.
    fail: Arc<Mutex<u32>>,
    /// Wait this long before answering.
    delay: Arc<Mutex<Duration>>,
}

async fn hook(State(r): State<Receiver>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let delay = *r.delay.lock().unwrap();
    tokio::time::sleep(delay).await;
    r.got.lock().unwrap().push(Got {
        id: h("webhook-id"),
        timestamp: h("webhook-timestamp"),
        signature: h("webhook-signature"),
        content_type: h("content-type"),
        body: body.to_vec(),
    });
    let mut fail = r.fail.lock().unwrap();
    if *fail > 0 {
        *fail -= 1;
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::NO_CONTENT
}

/// A receiver on loopback; its URL.
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
    (r, format!("http://{addr}/hook"))
}

/// The receiver's side of Standard Webhooks: the signatures that `secret`
/// accepts, checked in constant time.
fn verifies(secret: &str, got: &Got) -> bool {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap())
        .unwrap();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let mut msg = format!("{}.{}.", got.id, got.timestamp).into_bytes();
    msg.extend_from_slice(&got.body);
    got.signature.split(' ').any(|s| {
        s.strip_prefix("v1,")
            .and_then(|b| STANDARD.decode(b).ok())
            .is_some_and(|sig| hmac::verify(&key, &msg, &sig).is_ok())
    })
}

struct W {
    d: TestDb,
    db: tutelad::db::Db,
    a: tutela_contracts::tenant::TenantKey,
    b: tutela_contracts::tenant::TenantKey,
}

async fn w() -> Option<W> {
    let mut d = migrated().await?;
    let a = common::tenant_of(&mut d.owner, OWN_ISS).await;
    let b = common::tenant_of(&mut d.owner, OWN_ISS).await;
    let db = tutelad::db::Db::connect(&d.service_url, 4).unwrap();
    Some(W { d, db, a, b })
}

fn fast() -> Settings {
    Settings {
        lease: Duration::from_secs(5),
        first_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        give_up: Duration::from_secs(3600),
        timeout: Duration::from_secs(5),
        batch: 32,
        retention: Duration::from_secs(3600),
    }
}

fn relay(w: &W, name: &str, policy: Policy, s: Settings) -> Relay {
    Relay::new(
        w.db.clone(),
        vault(),
        OWN_ISS.parse().unwrap(),
        policy,
        name.to_owned(),
        s,
        Arc::new(tutelad::telemetry::Metrics::new()),
    )
    .unwrap()
}

const BY: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70f1";

impl W {
    /// Registers a webhook of `t` through the store, as part 3c's route will.
    async fn register(
        &mut self,
        t: &tutela_contracts::tenant::TenantKey,
        url: &str,
        types: &[EventType],
    ) -> (String, WebhookSecret) {
        let tx = self.d.owner.transaction().await.unwrap();
        let out = tutela_store::webhooks::register_webhook(
            &tx,
            t,
            &vault(),
            url,
            types,
            &BY.parse().unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        out
    }

    async fn emit(&mut self, t: &tutela_contracts::tenant::TenantKey, e: OutboxEvent) {
        let tx = self.d.owner.transaction().await.unwrap();
        tutela_store::emit(&tx, t, e).await.unwrap();
        tx.commit().await.unwrap();
    }

    async fn deliveries(
        &mut self,
        t: &tutela_contracts::tenant::TenantKey,
        id: &str,
    ) -> Vec<tutela_store::webhooks::Delivery> {
        let tx = self.d.owner.transaction().await.unwrap();
        let d = tutela_store::webhooks::deliveries(&tx, t, id)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        d
    }
}

fn user(n: u32) -> tutela_contracts::principal::Principal {
    format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}")
        .parse()
        .unwrap()
}

/// TM-19: each delivery is the CloudEvent, signed with the endpoint's
/// secret over id, timestamp and body; a changed body or another secret
/// does not verify. Only the webhook's types and its own tenant's events
/// arrive, each once.
#[tokio::test]
async fn tm19_deliveries_are_signed_and_carry_the_tenants_events_only() {
    let Some(mut w) = w().await else { return };
    let (r, url) = receiver().await;
    let a = w.a.clone();
    let b = w.b.clone();
    let (id, secret) = w
        .register(
            &a,
            &url,
            &[EventType::MODEL_PUBLISHED, EventType::SESSION_REVOKED],
        )
        .await;
    w.emit(&a, OutboxEvent::ModelPublished { rev: 5 }).await;
    w.emit(&a, OutboxEvent::PermissionsChanged { rev: 6 }).await;
    w.emit(&b, OutboxEvent::ModelPublished { rev: 7 }).await;
    w.emit(
        &a,
        OutboxEvent::SessionRevoked {
            principal: user(1),
            epoch: 3,
            sid: None,
        },
    )
    .await;
    let relay = relay(&w, "r1", Policy::new().dev_loopback(), fast());
    let t = relay.tick().await.unwrap();
    assert_eq!((t.handed, t.delivered, t.failed), (2, 2, 0), "{t:?}");
    let got = r.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    let types: Vec<String> = got
        .iter()
        .map(|g| {
            serde_json::from_slice::<Value>(&g.body).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        types,
        ["tutela.model.published.v1", "tutela.session.revoked.v1"]
    );
    for g in &got {
        let ce: Value = serde_json::from_slice(&g.body).unwrap();
        assert_eq!(g.content_type, "application/cloudevents+json");
        assert_eq!(g.id, ce["id"].as_str().unwrap());
        assert_eq!(ce["tenantid"], a.tid.to_string());
        assert_eq!(
            ce["source"],
            format!("tutela://tutela.example.test/{}", a.tid)
        );
        assert!(ce.get("traceparent").is_none());
        assert!(g.signature.starts_with("v1,") && !g.signature.contains(' '));
        assert!(verifies(secret.expose(), g));
        let ts: u64 = g.timestamp.parse().unwrap();
        assert!(ts.abs_diff(common::now()) < 60);
        // A changed body, or another endpoint's secret, does not verify.
        let mut changed = g.clone();
        changed.body.push(b' ');
        assert!(!verifies(secret.expose(), &changed));
        let other = format!("whsec_{}", STANDARD.encode([7u8; 32]));
        assert!(!verifies(&other, g));
    }
    // A second tick sends nothing again.
    let t = relay.tick().await.unwrap();
    assert_eq!((t.handed, t.delivered), (0, 0));
    let d = w.deliveries(&a, &id).await;
    assert!(d.iter().all(|d| d.state == "delivered" && d.attempts == 1));
    // Tenant B has no webhook and none of A's deliveries.
    assert!(w.deliveries(&b, &id).await.is_empty());
    w.d.finish().await;
}

/// A failed delivery is retried, and an event of the same subject waits
/// for it (order per subject, CONTRACTS.md 8.5); another subject does not.
/// Past `give_up` a delivery is dead, and can be sent again by hand.
#[tokio::test]
async fn failures_are_retried_in_order_per_subject_then_dead_lettered() {
    let Some(mut w) = w().await else { return };
    let (r, url) = receiver().await;
    let a = w.a.clone();
    let (id, _) = w.register(&a, &url, &[]).await;
    *r.fail.lock().unwrap() = 1;
    w.emit(
        &a,
        OutboxEvent::SessionRevoked {
            principal: user(1),
            epoch: 1,
            sid: None,
        },
    )
    .await;
    w.emit(
        &a,
        OutboxEvent::PrincipalDisabled {
            principal: user(1),
            epoch: 2,
        },
    )
    .await;
    w.emit(
        &a,
        OutboxEvent::PrincipalDisabled {
            principal: user(2),
            epoch: 1,
        },
    )
    .await;
    let relay = relay(&w, "r1", Policy::new().dev_loopback(), fast());
    // First tick: user 1's first event fails; its second waits; user 2's goes.
    let t = relay.tick().await.unwrap();
    assert_eq!((t.delivered, t.retried), (1, 1), "{t:?}");
    // Second tick: user 1's first goes, then its second, in order.
    relay.tick().await.unwrap();
    relay.tick().await.unwrap();
    let got = r.got.lock().unwrap().clone();
    let subjects: Vec<(String, u64)> = got
        .iter()
        .map(|g| {
            let v: Value = serde_json::from_slice(&g.body).unwrap();
            (
                v["subject"].as_str().unwrap().to_owned(),
                v["data"]["epoch"].as_u64().unwrap(),
            )
        })
        .collect();
    let u1: Vec<u64> = subjects
        .iter()
        .filter(|(s, _)| *s == user(1).to_string())
        .map(|(_, e)| *e)
        .collect();
    assert_eq!(u1, [1, 1, 2], "the failed one, again, then the next");
    let d = w.deliveries(&a, &id).await;
    assert!(d.iter().all(|d| d.state == "delivered"), "{d:?}");
    assert_eq!(d[0].attempts, 2);
    // A receiver that always fails: dead once `give_up` has passed.
    *r.fail.lock().unwrap() = 1000;
    w.emit(&a, OutboxEvent::ModelPublished { rev: 9 }).await;
    let short = Settings {
        give_up: Duration::from_millis(300),
        ..fast()
    };
    let dying = relay_with(&w, short);
    dying.tick().await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let t = dying.tick().await.unwrap();
    assert_eq!(t.dead, 1, "{t:?}");
    let last = w.deliveries(&a, &id).await.pop().unwrap();
    assert_eq!((last.state.as_str(), last.last_status), ("dead", Some(500)));
    // Sent again by hand, it is delivered.
    *r.fail.lock().unwrap() = 0;
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::webhooks::redeliver(&tx, &a, &id, last.seq)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    dying.tick().await.unwrap();
    assert_eq!(
        w.deliveries(&a, &id).await.pop().unwrap().state,
        "delivered"
    );
    w.d.finish().await;
}

fn relay_with(w: &W, s: Settings) -> Relay {
    relay(w, "r-dying", Policy::new().dev_loopback(), s)
}

/// TM-18: a webhook URL never reaches a private address. Registration
/// refuses loopback, private, link-local and metadata addresses, `http`, and
/// credentials; and a URL stored anyway is refused again at each send.
#[tokio::test]
async fn tm18_a_webhook_never_reaches_a_private_address() {
    let Some(mut w) = w().await else { return };
    let (r, url) = receiver().await;
    let a = w.a.clone();
    let prod = relay(&w, "r1", Policy::new(), fast());
    let tenant =
        tutelad::tenant::Tenant::of(&tutela_sdk::Identity::External(tutela_sdk::ExternalToken {
            tenant: a.clone(),
            sub: "test".to_owned(),
            azp: None,
            exp: common::now() + 60,
        }));
    let loopback_https = url.replace("http://", "https://");
    for bad in [
        "https://127.0.0.1/hook",
        "https://10.0.0.8/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[::ffff:127.0.0.1]/hook",
        "https://2130706433/hook",
        "https://localhost/hook",
        "http://example.test/hook",
        "https://user:pass@example.test/hook",
        url.as_str(),
        loopback_https.as_str(),
    ] {
        let mut conn = w.db.conn().await.unwrap();
        let tx = conn.begin(&tenant).await.unwrap();
        let e = tutelad::webhooks::register(
            &tx,
            &vault(),
            prod.client(),
            bad,
            &[],
            &BY.parse().unwrap(),
        )
        .await;
        assert!(
            matches!(e, Err(tutelad::webhooks::RegisterError::Url(_))),
            "{bad} was accepted"
        );
    }
    // Stored past the check (as a bug or an old row would), each is refused
    // again at send, and nothing reaches the receiver.
    let (http_id, _) = w.register(&a, &url, &[]).await;
    let (https_id, _) = w.register(&a, &loopback_https, &[]).await;
    w.emit(&a, OutboxEvent::ModelPublished { rev: 1 }).await;
    let t = prod.tick().await.unwrap();
    assert_eq!((t.delivered, t.retried), (0, 2), "{t:?}");
    assert!(r.got.lock().unwrap().is_empty());
    assert_eq!(
        w.deliveries(&a, &http_id).await[0].last_error.as_deref(),
        Some("url")
    );
    assert_eq!(
        w.deliveries(&a, &https_id).await[0].last_error.as_deref(),
        Some("not_public")
    );
    // A public-looking name is accepted at registration only when it
    // resolves; this one does not.
    let mut conn = w.db.conn().await.unwrap();
    let tx = conn.begin(&tenant).await.unwrap();
    assert!(
        tutelad::webhooks::register(
            &tx,
            &vault(),
            prod.client(),
            "https://hooks.invalid/h",
            &[],
            &BY.parse().unwrap()
        )
        .await
        .is_err()
    );
    drop(tx);
    drop(conn);
    w.d.finish().await;
}

/// Two replicas never send one event to one webhook at once: a claim holds
/// it for its lease.
#[tokio::test]
async fn two_replicas_never_send_one_event_twice_at_once() {
    let Some(mut w) = w().await else { return };
    let (r, url) = receiver().await;
    *r.delay.lock().unwrap() = Duration::from_millis(300);
    let a = w.a.clone();
    w.register(&a, &url, &[]).await;
    // Six subjects, so order per subject holds none of them back.
    for n in 1..=6 {
        w.emit(
            &a,
            OutboxEvent::PrincipalDisabled {
                principal: user(n),
                epoch: 1,
            },
        )
        .await;
    }
    let one = Arc::new(relay(&w, "r1", Policy::new().dev_loopback(), fast()));
    let two = relay(&w, "r2", Policy::new().dev_loopback(), fast());
    // The first replica claims and starts sending; the second comes while
    // it still holds every claim, and must leave them alone.
    let first = {
        let one = Arc::clone(&one);
        tokio::spawn(async move { one.tick().await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    let t2 = two.tick().await.unwrap();
    let t1 = first.await.unwrap().unwrap();
    assert_eq!(
        t2.delivered, 0,
        "the second replica sent what the first held"
    );
    assert_eq!(t1.delivered + t2.delivered, 6, "{t1:?} {t2:?}");
    let mut ids: Vec<String> = r.got.lock().unwrap().iter().map(|g| g.id.clone()).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!((n, ids.len()), (6, 6), "every event once");
    w.d.finish().await;
}

/// Secret rotation keeps the old secret signing for the overlap: the
/// receiver that still holds it verifies, then only the new one does.
#[tokio::test]
async fn tm19_a_rotated_secret_overlaps_then_ends() {
    let Some(mut w) = w().await else { return };
    let (r, url) = receiver().await;
    let a = w.a.clone();
    let (id, old) = w.register(&a, &url, &[]).await;
    let tx = w.d.owner.transaction().await.unwrap();
    let new = tutela_store::webhooks::rotate_webhook_secret(
        &tx,
        &a,
        &vault(),
        &id,
        Duration::from_millis(500),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_ne!(old.expose(), new.expose());
    w.emit(&a, OutboxEvent::ModelPublished { rev: 1 }).await;
    let relay = relay(&w, "r1", Policy::new().dev_loopback(), fast());
    relay.tick().await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    w.emit(&a, OutboxEvent::ModelPublished { rev: 2 }).await;
    relay.tick().await.unwrap();
    let got = r.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].signature.split(' ').count(), 2);
    assert!(verifies(old.expose(), &got[0]) && verifies(new.expose(), &got[0]));
    assert_eq!(got[1].signature.split(' ').count(), 1);
    assert!(!verifies(old.expose(), &got[1]) && verifies(new.expose(), &got[1]));
    // The secrets are sealed: neither is in the table as text.
    let rows = w
        .d
        .superuser()
        .await
        .query("SELECT encode(secret, 'escape') || coalesce(encode(previous, 'escape'), '') FROM tutela.webhook", &[])
        .await
        .unwrap();
    let text: String = rows[0].get(0);
    assert!(!text.contains(old.expose().trim_start_matches("whsec_")));
    assert!(!format!("{new:?}").contains(new.expose()));
    w.d.finish().await;
}

/// A running service delivers on its own timer (`TUTELA_WEBHOOK_POLL_MS`):
/// a model published for the app reaches the receiver, signed.
#[tokio::test]
async fn a_running_service_delivers_a_published_model() {
    let Some(mut w) = common::world_with(|c| {
        c.webhook_poll = Duration::from_millis(100);
        c.dev_mode = true;
    })
    .await
    else {
        return;
    };
    let (r, url) = receiver().await;
    let a = w.a.key.clone();
    let tx = w.d.owner.transaction().await.unwrap();
    let (_, secret) = tutela_store::webhooks::register_webhook(
        &tx,
        &a,
        &vault(),
        &url,
        &[EventType::MODEL_PUBLISHED],
        &BY.parse().unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    common::publish(
        &mut w.d.owner,
        &format!("{}\n# again\n", common::MANIFEST),
        Some(1),
    )
    .await;
    let start = std::time::Instant::now();
    while r.got.lock().unwrap().is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "nothing was delivered"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = r.got.lock().unwrap()[0].clone();
    assert!(verifies(secret.expose(), &got));
    let ce: Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(ce["type"], "tutela.model.published.v1");
    assert_eq!(ce["tenantid"], w.a.tid.as_str());
    let m = reqwest::get(w.s.ops_url("/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        m.contains("tutelad_webhook_deliveries_total{result=\"delivered\"}"),
        "{m}"
    );
    w.finish().await;
}
