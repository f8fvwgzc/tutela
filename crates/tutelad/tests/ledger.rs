//! Forwarding the local audit log to attache's evidence ledger through its
//! acknowledged Append API, on a real Postgres, to a stand-in of that API
//! on loopback that checks what attache checks (ADR-0039, CONTRACTS.md 9.3,
//! THREAT-MODEL.md TM-20).
#![cfg(test)]

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use tutela_contracts::audit::AuditEventV1;
use tutela_safenet::Policy;
use tutela_store::audit::Chain;
use tutelad::ledger::{Forwarder, LedgerConfig};
use zeroize::Zeroizing;

use common::{OWN_ISS, TestDb, migrated};

const TOKEN: &str = "att_test-forwarder-token-0000000000000000000000000";
const SEED: [u8; 32] = [42; 32];

/// What attache's Append API checks, as `docs/operations.md` and
/// `services/embassy/src/secops/ledger.rs` of attache describe it: the token,
/// the CSRF header, each record an audit.v1 of the producer's service, its
/// Ed25519 signature over the canonical JSON without `signature` by a key
/// whose RFC 7638 thumbprint is `signature.key_id`; then all or nothing,
/// deduped by `(service, id)`.
#[derive(Clone, Default)]
struct Ledger {
    public: Arc<Mutex<Option<String>>>,
    kept: Arc<Mutex<BTreeMap<(String, String), Value>>>,
    requests: Arc<Mutex<usize>>,
    down: Arc<Mutex<bool>>,
    duplicates: Arc<Mutex<usize>>,
    delay: Arc<Mutex<std::time::Duration>>,
}

fn kid_of(public: &[u8]) -> String {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        B64.encode(public)
    );
    B64.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        jwk.as_bytes(),
    ))
}

async fn append(
    State(l): State<Ledger>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> (StatusCode, Json<Value>) {
    *l.requests.lock().unwrap() += 1;
    let delay = *l.delay.lock().unwrap();
    tokio::time::sleep(delay).await;
    if *l.down.lock().unwrap() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
    }
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {TOKEN}"))
        || headers.get("x-agentsc-csrf").and_then(|v| v.to_str().ok()) != Some("1")
    {
        return (StatusCode::FORBIDDEN, Json(json!({})));
    }
    let public = STANDARD
        .decode(l.public.lock().unwrap().clone().unwrap())
        .unwrap();
    let records = req["records"].as_array().cloned().unwrap_or_default();
    if records.is_empty() || records.len() > 500 {
        return (StatusCode::BAD_REQUEST, Json(json!({})));
    }
    let mut acks = Vec::new();
    for raw in &records {
        let Ok(event) = serde_json::from_value::<AuditEventV1>(raw.clone()) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"why": "not audit.v1"})),
            );
        };
        if event.service.as_str() != "tutelad"
            || raw["signature"]["key_id"].as_str() != Some(kid_of(&public).as_str())
        {
            return (StatusCode::BAD_REQUEST, Json(json!({"why": "producer"})));
        }
        let mut signed = raw.clone();
        signed.as_object_mut().unwrap().remove("signature");
        let msg = tutela_contracts::jcs::to_canonical_string(&signed).unwrap();
        let sig = B64
            .decode(raw["signature"]["value"].as_str().unwrap_or_default())
            .unwrap_or_default();
        if UnparsedPublicKey::new(&ED25519, &public)
            .verify(msg.as_bytes(), &sig)
            .is_err()
        {
            return (StatusCode::BAD_REQUEST, Json(json!({"why": "signature"})));
        }
        acks.push((event.service.to_string(), event.id.to_string(), raw.clone()));
    }
    let mut kept = l.kept.lock().unwrap();
    let mut out = Vec::new();
    for (service, id, raw) in acks {
        let duplicate = kept.contains_key(&(service.clone(), id.clone()));
        if duplicate {
            *l.duplicates.lock().unwrap() += 1;
        }
        if duplicate && kept[&(service.clone(), id.clone())] != raw {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"why": "another payload"})),
            );
        }
        kept.insert((service, id.clone()), raw);
        out.push(json!({"id": id, "duplicate": duplicate, "gap": false}));
    }
    (StatusCode::OK, Json(json!({ "acknowledged": out })))
}

async fn ledger() -> (Ledger, String) {
    let l = Ledger::default();
    let app = axum::Router::new()
        .route("/api/v1/ledger/append", post(append))
        .with_state(l.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (l, format!("http://{addr}/api/v1/ledger/append"))
}

fn forwarder(d: &TestDb, url: &str, seed: [u8; 32], name: &str) -> Forwarder {
    Forwarder::new(
        tutelad::db::Db::connect(&d.service_url, 4).unwrap(),
        &LedgerConfig {
            url: url.to_owned(),
            token: Zeroizing::new(TOKEN.to_owned()),
            key: Zeroizing::new(seed.to_vec()),
        },
        Policy::new().dev_loopback(),
        name.to_owned(),
        Arc::new(tutelad::telemetry::Metrics::new()),
    )
    .unwrap()
}

async fn record(d: &mut TestDb, t: &tutela_contracts::tenant::TenantKey, n: u32) {
    let draft = tutelad::audit::Record::new(
        t,
        tutela_contracts::audit::Actor::new(
            format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}")
                .parse()
                .unwrap(),
        ),
        "tutela_model:publish",
        ("tutela_model", &format!("v{n}")),
    )
    .allowed(u64::from(n))
    .detail("version", n)
    .build()
    .unwrap();
    let tx = d.owner.transaction().await.unwrap();
    tutela_store::append_audit(&tx, t, &[draft]).await.unwrap();
    tx.commit().await.unwrap();
}

async fn forwarded(d: &mut TestDb, chain: &Chain) -> u64 {
    let tx = d.owner.transaction().await.unwrap();
    let n = tutela_store::audit::forwarded(&tx, chain).await.unwrap();
    tx.commit().await.unwrap();
    n
}

/// Every chain's records arrive signed, are taken, and are marked shipped;
/// the next tick sends nothing again.
#[tokio::test]
async fn tm20_records_are_forwarded_signed_and_marked_shipped() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let a = common::tenant_of(&mut d.owner, OWN_ISS).await;
    let b = common::tenant_of(&mut d.owner, OWN_ISS).await;
    for n in 1..=3 {
        record(&mut d, &a, n).await;
    }
    record(&mut d, &b, 9).await;
    let (l, url) = ledger().await;
    let fwd = forwarder(&d, &url, SEED, "r1");
    *l.public.lock().unwrap() = Some(fwd.public_key());
    let t = fwd.tick().await.unwrap();
    assert_eq!((t.shipped, t.refused, t.failed), (4, 0, 0), "{t:?}");
    assert_eq!(forwarded(&mut d, &Chain::Tenant(a.clone())).await, 3);
    assert_eq!(forwarded(&mut d, &Chain::Tenant(b.clone())).await, 1);
    let kept = l.kept.lock().unwrap().clone();
    assert_eq!(kept.len(), 4);
    let seqs: Vec<u64> = kept
        .values()
        .filter(|r| r["tenant"]["tid"] == a.tid.to_string())
        .map(|r| r["seq"].as_u64().unwrap())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(seqs, [1, 2, 3]);
    let before = *l.requests.lock().unwrap();
    let t = fwd.tick().await.unwrap();
    assert_eq!(t.shipped, 0);
    assert_eq!(
        *l.requests.lock().unwrap(),
        before,
        "nothing new is sent again"
    );
    d.finish().await;
}

/// The ledger is down: records stay in the local log, the local writes go
/// on, and when the ledger is back every record arrives, none lost.
#[tokio::test]
async fn tm20_a_ledger_outage_loses_nothing_and_blocks_nothing() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let a = common::tenant_of(&mut d.owner, OWN_ISS).await;
    let (l, url) = ledger().await;
    let fwd = forwarder(&d, &url, SEED, "r1");
    *l.public.lock().unwrap() = Some(fwd.public_key());
    *l.down.lock().unwrap() = true;
    record(&mut d, &a, 1).await;
    let t = fwd.tick().await.unwrap();
    assert_eq!((t.shipped, t.refused), (0, 1));
    // Local writes do not wait for the ledger.
    record(&mut d, &a, 2).await;
    record(&mut d, &a, 3).await;
    assert_eq!(forwarded(&mut d, &Chain::Tenant(a.clone())).await, 0);
    *l.down.lock().unwrap() = false;
    // A new replica resumes where the chain stopped.
    let other = forwarder(&d, &url, SEED, "r2");
    let t = other.tick().await.unwrap();
    assert_eq!(t.shipped, 3);
    assert_eq!(forwarded(&mut d, &Chain::Tenant(a)).await, 3);
    assert_eq!(l.kept.lock().unwrap().len(), 3);
    d.finish().await;
}

/// A batch the ledger refuses (a key it does not know for this producer)
/// is not marked shipped; the deployment's own chain is forwarded too.
#[tokio::test]
async fn tm20_a_refused_batch_waits_and_the_deployment_chain_is_forwarded() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let (l, url) = ledger().await;
    // A first key: the deployment's chain records it.
    let st_db = tutelad::db::Db::connect(&d.service_url, 2).unwrap();
    let ring = tutelad::keys::KeyRing::new(
        OWN_ISS.parse().unwrap(),
        common::vault(),
        std::time::Duration::from_secs(300),
    );
    ring.refresh(&st_db).await.unwrap();
    let right = forwarder(&d, &url, SEED, "r1");
    *l.public.lock().unwrap() = Some(right.public_key());
    let wrong = forwarder(&d, &url, [7; 32], "r2");
    let t = wrong.tick().await.unwrap();
    assert_eq!((t.shipped, t.refused), (0, 1), "{t:?}");
    assert_eq!(forwarded(&mut d, &Chain::Deployment).await, 0);
    let t = right.tick().await.unwrap();
    assert_eq!(t.shipped, 1);
    assert_eq!(forwarded(&mut d, &Chain::Deployment).await, 1);
    let kept = l.kept.lock().unwrap().clone();
    let r = kept.values().next().unwrap();
    assert_eq!(r["action"], "tutela_signing_key:create");
    assert_eq!(r["tenant"]["tid"], tutela_store::audit::DEPLOYMENT_TENANT);
    d.finish().await;
}

/// Two replicas never send one chain at once: a claim holds it while its
/// batch is on the way.
#[tokio::test]
async fn two_replicas_never_send_one_chain_at_once() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let a = common::tenant_of(&mut d.owner, OWN_ISS).await;
    for n in 1..=5 {
        record(&mut d, &a, n).await;
    }
    let (l, url) = ledger().await;
    *l.delay.lock().unwrap() = std::time::Duration::from_millis(300);
    let one = forwarder(&d, &url, SEED, "r1");
    let two = forwarder(&d, &url, SEED, "r2");
    *l.public.lock().unwrap() = Some(one.public_key());
    let (t1, t2) = tokio::join!(one.tick(), two.tick());
    let (t1, t2) = (t1.unwrap(), t2.unwrap());
    assert_eq!(t1.shipped + t2.shipped, 5, "{t1:?} {t2:?}");
    assert_eq!(*l.duplicates.lock().unwrap(), 0, "a chain was sent twice");
    assert_eq!(forwarded(&mut d, &Chain::Tenant(a)).await, 5);
    d.finish().await;
}
