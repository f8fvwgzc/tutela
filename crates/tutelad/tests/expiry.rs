//! Assignment expiry through the service: the timer, the service role's
//! grants, and the revision a caller sees.
#![cfg(test)]

mod common;

use std::time::{Duration, Instant, SystemTime};

use common::{ISS, Issuer, TestDb, USER, config, http, migrated, now, start, state, trust};
use serde_json::Value;
use tutela_contracts::decision::RuleId;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::RoleKey;
use tutela_pdp::{PathEntry, Subject};
use tutela_store::tokio_postgres::Client;
use tutelad::db::Db;
use tutelad::expiry::{Sweep, sweep};
use tutelad::telemetry::Metrics;

const AUD: &str = "tutela-authz";

/// A tenant with one org and one assignment that ends in an hour.
async fn tenant_with_expiring(owner: &mut Client) -> (TenantKey, RuleId) {
    let t = common::tenant(owner).await;
    let tx = owner.transaction().await.unwrap();
    let (org, _) = tutela_store::add_org(&tx, &t).await.unwrap();
    let (rule, _) = tutela_store::assign_until(
        &tx,
        &t,
        &Subject::Principal(USER.parse::<Principal>().unwrap()),
        &RoleKey::parse("viewer").unwrap(),
        &PathEntry::new("org".parse().unwrap(), org.to_string().parse().unwrap()),
        None,
        SystemTime::now() + Duration::from_secs(3600),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (t, rule)
}

/// As time would.
async fn pass_expiry(d: &TestDb, id: &RuleId) {
    let root = d.superuser().await;
    let n = root
        .execute(
            "UPDATE tutela.role_assignment SET expires_at = now() - interval '1 second' \
             WHERE id = $1",
            &[&id.as_str()],
        )
        .await
        .unwrap();
    assert_eq!(n, 1);
}

async fn rev_of(owner: &mut Client, t: &TenantKey) -> u64 {
    let tx = owner.transaction().await.unwrap();
    let rev = tutela_store::rev(&tx, t).await.unwrap();
    drop(tx);
    rev
}

/// One sweep, on the service role: the grants are enough, one tenant at a
/// time, and a second sweep changes nothing.
#[tokio::test]
async fn a_sweep_reaches_every_tenant_as_the_service_role() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let (a, a_rule) = tenant_with_expiring(&mut d.owner).await;
    let (b, _) = tenant_with_expiring(&mut d.owner).await;
    let (c, c_rule) = tenant_with_expiring(&mut d.owner).await;
    pass_expiry(&d, &a_rule).await;
    pass_expiry(&d, &c_rule).await;
    let (rev_a, rev_b, rev_c) = (
        rev_of(&mut d.owner, &a).await,
        rev_of(&mut d.owner, &b).await,
        rev_of(&mut d.owner, &c).await,
    );

    let db = Db::connect(&d.service_url, 2).unwrap();
    let metrics = Metrics::new();
    assert_eq!(
        sweep(&db, &metrics).await.unwrap(),
        Sweep {
            tenants: 3,
            bumped: 2,
            expired: 2,
            failed: 0,
        }
    );
    assert_eq!(rev_of(&mut d.owner, &a).await, rev_a + 1);
    assert_eq!(rev_of(&mut d.owner, &b).await, rev_b);
    assert_eq!(rev_of(&mut d.owner, &c).await, rev_c + 1);

    assert_eq!(
        sweep(&db, &metrics).await.unwrap(),
        Sweep {
            tenants: 3,
            ..Sweep::default()
        }
    );
    assert_eq!(rev_of(&mut d.owner, &a).await, rev_a + 1);
    let text = metrics.render().unwrap();
    assert!(
        text.contains("tutelad_assignments_expired_total 2"),
        "{text}"
    );
    d.finish().await;
}

/// One tenant's bad row does not stop the others.
#[tokio::test]
async fn a_failed_tenant_does_not_stop_the_sweep() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let (_, a_rule) = tenant_with_expiring(&mut d.owner).await;
    let (b, b_rule) = tenant_with_expiring(&mut d.owner).await;
    pass_expiry(&d, &a_rule).await;
    pass_expiry(&d, &b_rule).await;
    let root = d.superuser().await;
    root.execute(
        "UPDATE tutela.role_assignment SET role_id = 'Not A Role' WHERE id = $1",
        &[&a_rule.as_str()],
    )
    .await
    .unwrap();
    let rev_b = rev_of(&mut d.owner, &b).await;
    let db = Db::connect(&d.service_url, 2).unwrap();
    let s = sweep(&db, &Metrics::new()).await.unwrap();
    assert_eq!(
        s,
        Sweep {
            tenants: 2,
            bumped: 1,
            expired: 1,
            failed: 1,
        }
    );
    assert_eq!(rev_of(&mut d.owner, &b).await, rev_b + 1);
    d.finish().await;
}

/// End to end: the timer in a running service moves the revision a caller
/// reads, and the metrics show it.
#[tokio::test]
async fn a_passed_expiry_moves_the_revision_a_caller_sees() {
    let Some(mut d) = migrated().await else {
        return;
    };
    let (a, rule) = tenant_with_expiring(&mut d.owner).await;
    let tid = a.tid.to_string();
    let issuer = Issuer::new();
    let mut cfg = config(&d.service_url, trust(std::slice::from_ref(&tid)));
    cfg.expiry_sweep = Duration::from_millis(50);
    let s = start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let token = issuer.sign(ISS, &tid, AUD, now());
    let read_rev = || {
        let req = c.get(s.api_url("/v1/whoami")).bearer_auth(&token);
        async move { req.send().await.unwrap().json::<Value>().await.unwrap()["rev"].clone() }
    };
    let before = read_rev().await.as_u64().unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(read_rev().await, before, "nothing expired: no bump");

    pass_expiry(&d, &rule).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while read_rev().await != before + 1 {
        assert!(Instant::now() < deadline, "the revision did not move");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Only once.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(read_rev().await, before + 1);
    let text = c
        .get(s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("tutelad_assignments_expired_total 1"),
        "{text}"
    );
    assert!(
        text.contains(r#"tutelad_expiry_sweeps_total{result="ok"}"#),
        "{text}"
    );
    s.stop().await.unwrap();
    d.finish().await;
}
