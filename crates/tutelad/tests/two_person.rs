//! Two-person publish through the real auth layer on a real Postgres
//! (CONTRACTS.md 7.9, ADR-0029).
#![cfg(test)]

mod common;

use common::{AGENT, MANIFEST, SA, STRANGER, Seed, USER, World, http, now, world, world_with};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::approval::{self, Approval};
use tutela_store::tokio_postgres::Client;

const ALICE: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70d1";
const BOB: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70d2";

fn with_reader(level: &str) -> String {
    MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        &format!("grants = {{ project = \"read\", invoice = \"{level}\" }}"),
    )
}

async fn assign(owner: &mut Client, s: &Seed, who: &str, role: &str) {
    let tx = owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &s.key,
        &Subject::Principal(who.parse().unwrap()),
        &RoleKey::parse(role).unwrap(),
        &s.project,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Alice and Bob own both tenants' orgs.
async fn admins(w: &mut World) {
    for s in [&w.a, &w.b] {
        for who in [ALICE, BOB] {
            let tx = w.d.owner.transaction().await.unwrap();
            tutela_store::assign(
                &tx,
                &s.key,
                &Subject::Principal(who.parse().unwrap()),
                &RoleKey::parse("owner").unwrap(),
                &s.org,
                None,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
    }
}

async fn call(
    w: &World,
    method: &str,
    path: &str,
    token: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let c = http();
    let url = w.s.api_url(path);
    let req = match method {
        "GET" => c.get(url),
        "PUT" => c.put(url).json(body),
        _ => c.post(url).json(body),
    };
    let res = req.bearer_auth(token).send().await.unwrap();
    let status = res.status();
    (status, res.json().await.unwrap_or(Value::Null))
}

fn code(v: &Value) -> &str {
    v["type"]
        .as_str()
        .unwrap_or_default()
        .strip_prefix("urn:tutela:problem:")
        .unwrap_or_default()
}

async fn version(w: &World, s: &Seed) -> i64 {
    let t = w.issuer.token(ALICE, &s.tid, 0);
    let (_, v) = call(w, "GET", "/v1/models", &t, &Value::Null).await;
    v["active"]["version"].as_i64().unwrap()
}

async fn propose(w: &World, s: &Seed, who: &str, source: &str) -> Value {
    let t = w.issuer.token(who, &s.tid, 0);
    let body = json!({"source": source, "expected_version": version(w, s).await});
    let (status, v) = call(w, "POST", "/v1/models/proposals", &t, &body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v
}

async fn approve(w: &World, s: &Seed, token: &str, id: &Value, body: Value) -> (StatusCode, Value) {
    let path = format!("/v1/models/proposals/{}/approve", id.as_str().unwrap());
    let _ = s;
    call(w, "POST", &path, token, &body).await
}

#[tokio::test]
async fn tm08_the_same_principal_never_proposes_and_approves() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let s = &w.a;
    let p = propose(&w, s, ALICE, &with_reader("none")).await;
    assert_eq!(p["state"], "proposed");
    assert_eq!(p["proposed_by"], ALICE);
    assert_eq!(p["class"], "narrowing");
    assert_eq!(p["impact"]["complete"], true);

    // Alice herself, from her session or another one.
    for t in [
        w.issuer.token(ALICE, &s.tid, 0),
        w.issuer.second_session(ALICE, &s.tid),
    ] {
        let (status, v) = approve(&w, s, &t, &p["id"], json!({})).await;
        assert_eq!(
            (status, code(&v)),
            (StatusCode::FORBIDDEN, "same_person"),
            "{v}"
        );
    }
    // Alice through an agent, on a replica that takes delegated tokens.
    let delegated = common::start(&w.config, common::state_with(&w.config, &w.issuer, true)).await;
    let t = w.issuer.delegated(ALICE, AGENT, &s.tid);
    let path = format!("/v1/models/proposals/{}/approve", p["id"].as_str().unwrap());
    let res = http()
        .post(delegated.api_url(&path))
        .bearer_auth(&t)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "admin keys never pass through delegation"
    );
    // Bob through an agent is refused the same way: no approval by agent.
    let t = w.issuer.delegated(BOB, AGENT, &s.tid);
    let res = http()
        .post(delegated.api_url(&path))
        .bearer_auth(&t)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    delegated.stop().await.unwrap();

    // Others who may not change the model.
    for who in [USER, SA, STRANGER] {
        let t = w.issuer.token(who, &s.tid, 0);
        let (status, _) = approve(&w, s, &t, &p["id"], json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}");
    }

    // Bob approves, and it publishes.
    let t = w.issuer.token(BOB, &s.tid, 0);
    let (status, v) = approve(&w, s, &t, &p["id"], json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (_, got) = call(
        &w,
        "GET",
        &format!("/v1/models/proposals/{}", p["id"].as_str().unwrap()),
        &t,
        &Value::Null,
    )
    .await;
    assert_eq!(got["state"], "published");
    assert_eq!(got["decided_by"], BOB);
    assert_eq!(got["version"], v["version"]);
    let (_, kept) = call(
        &w,
        "GET",
        &format!("/v1/models/{}", v["version"]),
        &t,
        &Value::Null,
    )
    .await;
    assert_eq!(kept["author"], ALICE);
    assert_eq!(kept["approvers"], json!([BOB]));
    // It is closed now.
    let (status, v) = approve(&w, s, &t, &p["id"], json!({})).await;
    assert_eq!((status, code(&v)), (StatusCode::CONFLICT, "not_open"));
    w.finish().await;
}

#[tokio::test]
async fn tm08_a_widening_proposal_still_needs_its_token() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let s = &w.a;
    let p = propose(&w, s, ALICE, &with_reader("write")).await;
    assert_eq!(p["class"], "widening");
    let t = w.issuer.token(BOB, &s.tid, 0);
    let (status, v) = approve(&w, s, &t, &p["id"], json!({})).await;
    assert_eq!(
        (status, code(&v)),
        (StatusCode::FORBIDDEN, "approval_required")
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let pk = key.verifying_key().to_bytes();
    let tx = w.d.owner.transaction().await.unwrap();
    let kid = tutela_store::add_approver(&tx, "dana", &pk).await.unwrap();
    tx.commit().await.unwrap();
    let token = approval::mint(
        &key,
        &Approval {
            app: "crm".into(),
            from: p["from"].as_str().unwrap().into(),
            to: p["to"].as_str().unwrap().into(),
            kid: kid.clone(),
            iat: now() - 10,
            exp: now() + 600,
            tid: Some(s.tid.clone()),
        },
    )
    .unwrap();
    let (status, v) = approve(&w, s, &t, &p["id"], json!({"approval": token})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (_, kept) = call(
        &w,
        "GET",
        &format!("/v1/models/{}", v["version"]),
        &t,
        &Value::Null,
    )
    .await;
    assert_eq!(kept["approvers"], json!([BOB, kid]));
    w.finish().await;
}

#[tokio::test]
async fn while_it_is_on_a_model_is_published_only_through_two_people() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let s = &w.a;
    let (ta, tb) = (
        w.issuer.token(ALICE, &s.tid, 0),
        w.issuer.token(BOB, &s.tid, 0),
    );
    let set = |on: bool| json!({"two_person": on});
    let (status, v) = call(&w, "PUT", "/v1/models/settings", &ta, &set(true)).await;
    assert_eq!(
        (status, v["two_person"].clone()),
        (StatusCode::OK, json!(true))
    );
    let body = json!({"source": with_reader("none"), "expected_version": version(&w, s).await});
    let (status, v) = call(&w, "POST", "/v1/models/publish", &ta, &body).await;
    assert_eq!(
        (status, code(&v)),
        (StatusCode::FORBIDDEN, "two_person_required")
    );
    // Tenant B did not turn it on.
    let tb_b = w.issuer.token(ALICE, &w.b.tid, 0);
    let (_, v) = call(&w, "GET", "/v1/models/settings", &tb_b, &Value::Null).await;
    assert_eq!(v["two_person"], false);

    // Off takes two people as well.
    let (_, v) = call(&w, "PUT", "/v1/models/settings", &ta, &set(false)).await;
    assert_eq!(v, json!({"two_person": true, "off_requested_by": ALICE}));
    let (_, v) = call(&w, "PUT", "/v1/models/settings", &ta, &set(false)).await;
    assert_eq!(v["two_person"], true, "asking twice is still one person");
    let (_, v) = call(&w, "PUT", "/v1/models/settings", &tb, &set(false)).await;
    assert_eq!(v, json!({"two_person": false}));
    let (status, _) = call(&w, "POST", "/v1/models/publish", &ta, &body).await;
    assert_eq!(status, StatusCode::OK);

    // Who may not touch the setting.
    for who in [USER, SA, AGENT] {
        let t = w.issuer.token(who, &s.tid, 0);
        let (status, _) = call(&w, "PUT", "/v1/models/settings", &t, &set(true)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}");
    }
    w.finish().await;
}

#[tokio::test]
async fn a_proposal_goes_stale_when_its_report_would_change() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let a = w.a.clone_seed();
    let tb = w.issuer.token(BOB, &a.tid, 0);

    // A change of data that the report does not see keeps it fresh: an
    // approver role is not the role the proposal changes.
    let p = propose(&w, &a, ALICE, &with_reader("none")).await;
    assign(&mut w.d.owner, &a, STRANGER, "approver").await;
    let (status, v) = approve(&w, &a, &tb, &p["id"], json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // A new reader would lose too: the report changes, and so is stale.
    let p = propose(&w, &a, ALICE, &with_reader("read")).await;
    assign(
        &mut w.d.owner,
        &a,
        "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70d9",
        "reader",
    )
    .await;
    let (status, v) = approve(&w, &a, &tb, &p["id"], json!({})).await;
    assert_eq!(
        (status, code(&v)),
        (StatusCode::CONFLICT, "stale_proposal"),
        "{v}"
    );
    let (_, got) = call(
        &w,
        "GET",
        &format!("/v1/models/proposals/{}", p["id"].as_str().unwrap()),
        &tb,
        &Value::Null,
    )
    .await;
    assert_eq!(got["state"], "stale");

    // Another publish moved the active model.
    let p = propose(&w, &a, ALICE, &with_reader("read")).await;
    // A neutral change from what is active: the delete button's mode.
    let other = with_reader("none").replace(
        "when_denied = \"hide\"\n\n[ui.\"invoices.amount_cell\"]",
        "when_denied = \"disable\"\n\n[ui.\"invoices.amount_cell\"]",
    );
    let body = json!({"source": other, "expected_version": version(&w, &a).await});
    let ta = w.issuer.token(ALICE, &a.tid, 0);
    let (status, v) = call(&w, "POST", "/v1/models/publish", &ta, &body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = approve(&w, &a, &tb, &p["id"], json!({})).await;
    assert_eq!(
        (status, code(&v)),
        (StatusCode::CONFLICT, "stale_proposal"),
        "{v}"
    );

    // The proposer may withdraw an open proposal; it is then closed.
    let p = propose(&w, &a, ALICE, &with_reader("none")).await;
    let path = format!("/v1/models/proposals/{}/reject", p["id"].as_str().unwrap());
    let (status, v) = call(&w, "POST", &path, &ta, &json!({})).await;
    assert_eq!(
        (status, v["state"].clone()),
        (StatusCode::OK, json!("rejected"))
    );
    let (status, _) = approve(&w, &a, &tb, &p["id"], json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    w.finish().await;
}

#[tokio::test]
async fn a_proposal_with_a_report_cut_short_goes_stale_on_any_change() {
    let Some(mut w) = world_with(|c| c.impact_work = 1).await else {
        return;
    };
    admins(&mut w).await;
    let a = w.a.clone_seed();
    let tb = w.issuer.token(BOB, &a.tid, 0);
    let p = propose(&w, &a, ALICE, &with_reader("none")).await;
    assert_eq!(p["impact"]["complete"], false);
    assign(&mut w.d.owner, &a, STRANGER, "approver").await;
    let (status, v) = approve(&w, &a, &tb, &p["id"], json!({})).await;
    assert_eq!(
        (status, code(&v)),
        (StatusCode::CONFLICT, "stale_proposal"),
        "{v}"
    );
    // With nothing moved, it goes through.
    let p = propose(&w, &a, ALICE, &with_reader("none")).await;
    let (status, v) = approve(&w, &a, &tb, &p["id"], json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    w.finish().await;
}

#[tokio::test]
async fn tm05_a_proposal_belongs_to_its_tenant() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let p = propose(&w, &w.a, ALICE, &with_reader("none")).await;
    // Bob owns tenant B too; his token for B finds nothing of tenant A's.
    let t = w.issuer.token(BOB, &w.b.tid, 0);
    let path = format!("/v1/models/proposals/{}", p["id"].as_str().unwrap());
    let (status, _) = call(&w, "GET", &path, &t, &Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = approve(&w, &w.b, &t, &p["id"], json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, list) = call(&w, "GET", "/v1/models/proposals", &t, &Value::Null).await;
    assert_eq!(list, json!([]));
    // Who may not look or propose.
    for who in [USER, SA, AGENT] {
        let t = w.issuer.token(who, &w.a.tid, 0);
        let (status, _) = call(&w, "GET", "/v1/models/proposals", &t, &Value::Null).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}");
        let body = json!({"source": with_reader("none"), "expected_version": 0});
        let (status, _) = call(&w, "POST", "/v1/models/proposals", &t, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}");
    }
    w.finish().await;
}

trait CloneSeed {
    fn clone_seed(&self) -> Seed;
}

impl CloneSeed for Seed {
    fn clone_seed(&self) -> Seed {
        Seed {
            key: self.key.clone(),
            tid: self.tid.clone(),
            org: self.org.clone(),
            project: self.project.clone(),
            assignment: self.assignment.clone(),
        }
    }
}
