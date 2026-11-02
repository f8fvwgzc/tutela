//! The audit log's leftovers from part 3b (ADR-0034, CONTRACTS.md 9): a
//! timer that walks every chain and reports a broken link, and the request
//! and trace ids in each record of a request. Real Postgres, real service.
#![cfg(test)]

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutelad::admin::grpc::pb;
use tutelad::admin::grpc::pb::admin_client::AdminClient;

use common::{World, audit_of, http, world_with};

const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b2";
const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN: &str = "00f067aa0ba902b7";

async fn admin(w: &mut World) {
    for (key, org) in [
        (w.a.key.clone(), w.a.org.clone()),
        (w.b.key.clone(), w.b.org.clone()),
    ] {
        let tx = w.d.owner.transaction().await.unwrap();
        tutela_store::assign(
            &tx,
            &key,
            &Subject::Principal(ADMIN_SA.parse().unwrap()),
            &RoleKey::parse("owner").unwrap(),
            &org,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
}

async fn register(w: &World, tid: &str, headers: &[(&str, &str)]) -> StatusCode {
    let mut r = http()
        .post(w.s.api_url("/v1/admin/agents"))
        .bearer_auth(w.issuer.token(ADMIN_SA, tid, 0))
        .json(&json!({}));
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.send().await.unwrap().status()
}

async fn metrics(w: &World) -> String {
    http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

/// TM-20: a chain changed behind the service's back is found by the timer,
/// counted, and reported; the other tenant's chain is fine.
#[tokio::test]
async fn tm20_the_chain_check_finds_a_broken_link_and_reports_it() {
    let Some(mut w) = world_with(|c| c.audit_verify = Duration::from_millis(200)).await else {
        return;
    };
    admin(&mut w).await;
    for s in [w.a.tid.clone(), w.b.tid.clone()] {
        for _ in 0..3 {
            assert_eq!(register(&w, &s, &[]).await, StatusCode::OK);
        }
    }
    let st = tutelad::db::Db::connect(&w.d.service_url, 2).unwrap();
    let m = tutelad::telemetry::Metrics::new();
    let fine = tutelad::audit::check_chains(&st, &m).await.unwrap();
    assert_eq!((fine.chains, fine.broken, fine.failed), (3, 0, 0));

    // An owner who switches the trigger off rewrites a record of A.
    let su = w.d.superuser().await;
    su.batch_execute("ALTER TABLE tutela.audit_record DISABLE TRIGGER audit_record_kept")
        .await
        .unwrap();
    let n = su
        .execute(
            "UPDATE tutela.audit_record SET body = replace(body, 'register', 'registered') \
             WHERE tenant_id = $1 AND seq = 2",
            &[&w.a.tid],
        )
        .await
        .unwrap();
    su.batch_execute("ALTER TABLE tutela.audit_record ENABLE TRIGGER audit_record_kept")
        .await
        .unwrap();
    assert_eq!(n, 1);
    let found = tutelad::audit::check_chains(&st, &m).await.unwrap();
    assert_eq!((found.chains, found.broken, found.failed), (3, 1, 0));
    let text = m.render().unwrap();
    assert!(text.contains("tutelad_audit_chains_broken 1"), "{text}");
    assert!(
        text.contains("tutelad_audit_chain_checks_total{result=\"broken\"} 1"),
        "{text}"
    );

    // The service's own timer says the same on its metrics.
    let start = std::time::Instant::now();
    while !metrics(&w).await.contains("tutelad_audit_chains_broken 1") {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the timer did not report it"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    w.finish().await;
}

/// CONTRACTS.md 9.1: a record of a request carries its request id and the
/// trace and span of the caller's `traceparent`, over HTTP and gRPC; never
/// an `ip`.
#[tokio::test]
async fn a_record_carries_the_request_and_trace_ids() {
    let Some(mut w) = world_with(|_| {}).await else {
        return;
    };
    admin(&mut w).await;
    let parent = format!("00-{TRACE}-{SPAN}-01");
    let tid = w.a.tid.clone();
    assert_eq!(
        register(
            &w,
            &tid,
            &[("traceparent", &parent), ("x-request-id", "req-7f3k9q")]
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(register(&w, &tid, &[]).await, StatusCode::OK);
    let channel = tonic::transport::Endpoint::from_shared(w.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut g = AdminClient::new(channel);
    let mut req = tonic::Request::new(pb::RegisterAgentRequest::default());
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", w.issuer.token(ADMIN_SA, &tid, 0))
            .parse()
            .unwrap(),
    );
    req.metadata_mut()
        .insert("traceparent", parent.parse().unwrap());
    g.register_agent(req).await.unwrap();

    let recs: Vec<Value> = audit_of(&mut w.d.owner, &w.a.key)
        .await
        .into_iter()
        .filter(|r| r["action"] == "tutela_principal:register")
        .collect();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0]["trace_id"], TRACE);
    assert_eq!(recs[0]["span_id"], SPAN);
    assert_eq!(recs[0]["request_id"], "req-7f3k9q");
    // No traceparent: a request id of its own, no trace.
    assert!(
        recs[1]["request_id"]
            .as_str()
            .is_some_and(|r| !r.is_empty())
    );
    assert!(recs[1].get("trace_id").is_none());
    // gRPC too.
    assert_eq!(recs[2]["trace_id"], TRACE);
    assert!(recs.iter().all(|r| r.get("ip").is_none()));
    w.finish().await;
}
