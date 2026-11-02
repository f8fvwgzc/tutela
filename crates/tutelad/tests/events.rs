//! The transactional outbox through the real service, the real auth layer
//! and a real Postgres (ADR-0035, CONTRACTS.md 8.5).
#![cfg(test)]

mod common;

use common::{MANIFEST, Seed, World, events_of, world};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;

const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70e1";

fn seed(s: &Seed) -> Seed {
    Seed {
        key: s.key.clone(),
        tid: s.tid.clone(),
        org: s.org.clone(),
        project: s.project.clone(),
        assignment: s.assignment.clone(),
    }
}

async fn admin(w: &mut World) {
    let a = seed(&w.a);
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &a.key,
        &Subject::Principal(ADMIN.parse().unwrap()),
        &RoleKey::parse("owner").unwrap(),
        &a.org,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn call(w: &World, method: &str, path: &str, body: &Value) -> (StatusCode, Value) {
    let t = w.issuer.console(ADMIN, &w.a.tid, 0);
    let req = match method {
        "PUT" => common::http().put(w.s.api_url(path)),
        "GET" => common::http().get(w.s.api_url(path)),
        _ => common::http().post(w.s.api_url(path)),
    };
    let req = if method == "GET" { req } else { req.json(body) };
    let res = req.bearer_auth(t).send().await.unwrap();
    let status = res.status();
    (status, res.json().await.unwrap_or(Value::Null))
}

fn types(e: &[tutela_store::StoredEvent]) -> Vec<String> {
    e.iter().map(|e| e.event_type.to_string()).collect()
}

/// A publish emits `tutela.model.published.v1` with its revision, in its
/// own transaction; a refused or rolled-back publish emits nothing; the
/// expiry sweep emits `tutela.permissions.changed.v1`. The other tenant's
/// outbox has none of it.
#[tokio::test]
async fn changes_through_the_service_emit_their_events_and_refusals_emit_none() {
    let Some(mut w) = world().await else { return };
    admin(&mut w).await;
    let narrow = MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        "grants = { project = \"read\", invoice = \"none\" }",
    );
    let (_, active) = call(&w, "GET", "/v1/models", &Value::Null).await;
    let base = active["active"]["version"].as_i64().unwrap();
    let before = events_of(&mut w.d.owner, &w.a.key).await;
    let (status, v) = call(
        &w,
        "POST",
        "/v1/models/publish",
        &json!({"source": narrow, "expected_version": base}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    let version = v["version"].as_i64().unwrap();
    // Widening without a token: refused, nothing emitted.
    let (status, _) = call(
        &w,
        "POST",
        "/v1/models/publish",
        &json!({"source": MANIFEST, "expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Two-person on: a direct publish is refused inside the store's
    // transaction, which rolls back with its event.
    let (status, _) = call(
        &w,
        "PUT",
        "/v1/models/settings",
        &json!({"two_person": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &w,
        "POST",
        "/v1/models/publish",
        &json!({"source": format!("{narrow}\n# x\n"), "expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let after = events_of(&mut w.d.owner, &w.a.key).await;
    let new = &after[before.len()..];
    assert_eq!(types(new), ["tutela.model.published.v1"], "{new:?}");
    assert_eq!(new[0].data["rev"], rev);
    assert_eq!(new[0].subject.as_str(), w.a.tid);
    // The expiry sweep's revision is announced too.
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::assign_until(
        &tx,
        &w.a.key,
        &Subject::Principal(common::STRANGER.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &w.a.project,
        None,
        std::time::SystemTime::now() + std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let st = common::state(&w.config, &w.issuer);
    tutelad::expiry::sweep(&st.db, &st.metrics).await.unwrap();
    let last = events_of(&mut w.d.owner, &w.a.key).await;
    let sweep = last.last().unwrap();
    assert_eq!(
        sweep.event_type.to_string(),
        "tutela.permissions.changed.v1"
    );
    let tx = w.d.owner.transaction().await.unwrap();
    let now = tutela_store::rev(&tx, &w.a.key).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(sweep.data["rev"], now);
    // Numbers have no gap, and tenant B has none of A's ids.
    let seqs: Vec<u64> = last.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (1..=last.len() as u64).collect::<Vec<_>>());
    let b = events_of(&mut w.d.owner, &w.b.key).await;
    assert!(b.iter().all(|e| last.iter().all(|a| a.id != e.id)));
    // The envelope names this service's issuer's host and the tenant.
    let ce = serde_json::to_value(
        tutelad::events::envelope(&common::OWN_ISS.parse().unwrap(), w.a.key.tid, &new[0]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ce["source"],
        format!("tutela://tutela.example.test/{}", w.a.tid)
    );
    assert_eq!(ce["tenantid"], w.a.tid.as_str());
    assert_eq!(ce["specversion"], "1.0");
    w.finish().await;
}
