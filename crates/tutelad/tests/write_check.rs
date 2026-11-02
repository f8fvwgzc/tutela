//! `POST /v1/authz/write-check` through the real auth layer on a real
//! Postgres: per-field verdicts, moves and links (CONTRACTS.md 7.8,
//! ADR-0025).
#![cfg(test)]

mod common;

use common::{AGENT, B_USER, ISS, SA, STRANGER, Seed, USER, World, now, world};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::model::RoleKey;
use tutela_pdp::{BoundaryRule, MoveRule, OnLooser, PathEntry, Subject};
use tutela_store::tokio_postgres::Client;
use tutelad::authz::grpc::pb;
use tutelad::authz::grpc::pb::authz_client::AuthzClient;

const PATH: &str = "/v1/authz/write-check";
const OWNER_A: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70a1";
const MEMBER_A: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70a2";

fn who(subject: &str) -> Value {
    json!({"type": subject.split(':').next().unwrap(), "id": subject})
}

fn entry(e: &PathEntry) -> Value {
    json!({"type": e.type_name.to_string(), "id": e.id.to_string()})
}

fn invoice(s: &Seed, project: &PathEntry) -> Value {
    json!({"type": "invoice", "id": "inv-1", "properties": {
        "path": [entry(project), entry(&s.org)], "attrs": {}
    }})
}

fn write(subject: &str, s: &Seed) -> Value {
    json!({
        "subject": who(subject),
        "resource": invoice(s, &s.project),
        "new_attrs": {"status": "done"},
    })
}

fn project(n: &str) -> PathEntry {
    PathEntry::new("project".parse().unwrap(), n.parse().unwrap())
}

async fn assign(owner: &mut Client, s: &Seed, who: &str, role: &str, at: &PathEntry) {
    let tx = owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &s.key,
        &Subject::Principal(who.parse().unwrap()),
        &RoleKey::parse(role).unwrap(),
        at,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn add_project(owner: &mut Client, s: &Seed, name: &str) -> PathEntry {
    let p = project(name);
    let tx = owner.transaction().await.unwrap();
    tutela_store::put_scope(&tx, &s.key, &p, std::slice::from_ref(&s.org), false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    p
}

async fn set_rule(owner: &mut Client, s: &Seed, at: &PathEntry, rule: BoundaryRule) -> u64 {
    let tx = owner.transaction().await.unwrap();
    let rev = tutela_store::set_boundary(&tx, &s.key, at, &rule)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    rev
}

async fn body(res: reqwest::Response) -> Value {
    res.json().await.unwrap()
}

async fn ask(w: &World, s: &Seed, token_for: &str, body_in: &Value) -> Value {
    let token = w.issuer.token(token_for, &s.tid, 0);
    let res = w.post(PATH, &token, body_in).await;
    assert_eq!(res.status(), StatusCode::OK);
    body(res).await
}

/// p-2 holds someone who p-1 does not, and the service account may ask.
async fn with_two_projects(w: &mut World) -> (PathEntry, PathEntry) {
    let s = &w.a;
    assign(&mut w.d.owner, s, OWNER_A, "owner", &s.project).await;
    assign(&mut w.d.owner, s, MEMBER_A, "member", &s.org.clone()).await;
    let p2 = add_project(&mut w.d.owner, s, "p-2").await;
    assign(&mut w.d.owner, s, STRANGER, "approver", &p2).await;
    (s.project.clone(), p2)
}

#[tokio::test]
async fn a_write_gets_a_verdict_per_field() {
    let Some(w) = world().await else { return };
    let a = ask(&w, &w.b, SA, &write(B_USER, &w.b)).await;
    assert_eq!(a["decision"], true, "{a}");
    assert_eq!(a["context"]["tutela"]["fields"][0]["field"], "status");
    assert_eq!(a["context"]["tutela"]["fields"][0]["effect"], "allow");
    assert_eq!(
        a["context"]["tutela"]["fields"][0]["needs"],
        "invoice:write"
    );

    // A reader is denied, by field, in the same shape.
    let d = ask(&w, &w.a, SA, &write(USER, &w.a)).await;
    assert_eq!(d["decision"], false, "{d}");
    assert_eq!(d["context"]["tutela"]["effect"], "deny");
    assert_eq!(d["context"]["tutela"]["fields"][0]["effect"], "deny");
    assert!(d["context"]["tutela"].get("move").is_none());

    let m = reqwest::get(w.s.ops_url("/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for outcome in ["allow", "deny"] {
        let line =
            format!("tutelad_decisions_total{{operation=\"write_check\",outcome=\"{outcome}\"}} 1");
        assert!(m.contains(&line), "{outcome}");
    }
    w.finish().await;
}

#[tokio::test]
async fn tm05_a_write_check_cannot_cross_a_tenant() {
    let Some(w) = world().await else { return };
    // Tenant B's service asks about tenant A's resource.
    let token = w.issuer.token(SA, &w.b.tid, 0);
    let res = w.post(PATH, &token, &write(B_USER, &w.a)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v = body(res).await;
    assert_eq!(v["decision"], false);
    assert_eq!(
        v["context"]["tutela"]["fields"][0]["reason"]
            .as_str()
            .unwrap()
            .split(':')
            .next()
            .unwrap(),
        "tenant_mismatch"
    );

    // Tenant B's approver has no role in A: a move into A is refused too.
    let mut mv = write(B_USER, &w.b);
    mv["new_path"] = json!([entry(&w.a.project), entry(&w.a.org)]);
    let v = ask(&w, &w.b, SA, &mv).await;
    assert_eq!(v["decision"], false);
    let m = &v["context"]["tutela"]["move"];
    assert_eq!(m["outcome"], "refused", "{m}");
    assert!(m["reason"].as_str().unwrap().starts_with("tenant_mismatch"));

    // A link into another tenant is refused.
    let mut link = write(B_USER, &w.b);
    link["new_links"] = json!([invoice(&w.a, &w.a.project)]);
    let v = ask(&w, &w.b, SA, &link).await;
    assert_eq!(v["decision"], false);
    let r = v["context"]["tutela"]["links"][0]["reason"]
        .as_str()
        .unwrap();
    assert!(r.starts_with("tenant_mismatch"), "{r}");
    w.finish().await;
}

#[tokio::test]
async fn who_may_ask_is_the_same_as_for_a_check() {
    let Some(w) = world().await else { return };
    let token = |sub| w.issuer.token(sub, &w.a.tid, 0);
    // A person asks about itself.
    let res = w.post(PATH, &token(USER), &write(USER, &w.a)).await;
    assert_eq!(res.status(), StatusCode::OK);
    // A person does not ask about another, and neither does an agent.
    let res = w.post(PATH, &token(STRANGER), &write(USER, &w.a)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = w.post(PATH, &token(AGENT), &write(USER, &w.a)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // No token, and a token for another audience.
    let res = common::http()
        .post(w.s.api_url(PATH))
        .json(&write(USER, &w.a))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let other = w.issuer.sign(ISS, &w.a.tid, "crm-api", now());
    let res = w.post(PATH, &other, &write(USER, &w.a)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // Only a service may say who approved.
    let mut approved = write(USER, &w.a);
    approved["approved_by"] = json!([SA]);
    let res = w.post(PATH, &token(USER), &approved).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // A bad body names nothing from the body.
    let res = w.post(PATH, &token(SA), &json!({"subject": "x"})).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let nothing = json!({"subject": who(USER), "resource": invoice(&w.a, &w.a.project)});
    let res = w.post(PATH, &token(SA), &nothing).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    w.finish().await;
}

#[tokio::test]
async fn tm08_a_move_into_a_looser_scope_is_not_allowed_without_its_owner() {
    let Some(mut w) = world().await else { return };
    let (p1, p2) = with_two_projects(&mut w).await;
    let s = &w.a;
    let mut mv = json!({
        "subject": who(MEMBER_A),
        "resource": invoice(s, &p1),
        "new_path": [entry(&p2), entry(&s.org)],
    });
    let v = ask(&w, s, SA, &mv).await;
    assert_eq!(v["decision"], false, "{v}");
    let m = &v["context"]["tutela"]["move"];
    assert_eq!(m["outcome"], "needs_approval", "{m}");
    assert_eq!(m["looser"], true);
    assert_eq!(m["approve_at"], json!([entry(&p1)]));
    assert_eq!(m["gains"][0]["principals"], json!([STRANGER]), "{m}");

    // The same question from the person herself hides who gains.
    let own = ask(&w, s, MEMBER_A, &mv).await;
    assert_eq!(own["context"]["tutela"]["move"]["gains"], json!([]));

    // Someone who is no owner of the source approves nothing.
    mv["approved_by"] = json!([STRANGER]);
    let v = ask(&w, s, SA, &mv).await;
    assert_eq!(v["decision"], false);
    mv["approved_by"] = json!([OWNER_A]);
    let v = ask(&w, s, SA, &mv).await;
    assert_eq!(v["decision"], true, "{v}");

    // The source's owner can block it, also with an approval.
    let rev = set_rule(
        &mut w.d.owner,
        &w.a,
        &p1,
        BoundaryRule {
            on_looser: Some(OnLooser::Block),
            ..BoundaryRule::default()
        },
    )
    .await;
    mv["context"] = json!({"at_least_revision": rev});
    let v = ask(&w, &w.a, SA, &mv).await;
    assert_eq!(v["decision"], false);
    assert_eq!(v["context"]["tutela"]["move"]["outcome"], "refused");
    assert_eq!(v["context"]["tutela"]["rev"], rev);
    w.finish().await;
}

#[tokio::test]
async fn tm08_a_move_needs_the_rule_of_each_side() {
    let Some(mut w) = world().await else { return };
    let (p1, p2) = with_two_projects(&mut w).await;
    let s = &w.a;
    let mv = json!({
        "subject": who(MEMBER_A),
        "resource": invoice(s, &p2),
        "new_path": [entry(&p1), entry(&s.org)],
    });
    let nobody = |out: bool| BoundaryRule {
        moves_out: out.then_some(MoveRule::Nobody),
        moves_in: (!out).then_some(MoveRule::Nobody),
        ..BoundaryRule::default()
    };
    for (scope, out) in [(p2.clone(), true), (p1.clone(), false)] {
        let rev = set_rule(&mut w.d.owner, s, &scope, nobody(out)).await;
        let mut asked = mv.clone();
        asked["context"] = json!({"at_least_revision": rev});
        let v = ask(&w, s, SA, &asked).await;
        let m = &v["context"]["tutela"]["move"];
        assert_eq!(m["outcome"], "refused", "{m}");
        assert!(m["reason"].as_str().unwrap().starts_with("boundary_rule"));
        set_rule(&mut w.d.owner, s, &scope, BoundaryRule::default()).await;
    }
    w.finish().await;
}

#[tokio::test]
async fn a_moved_scope_loses_its_old_parent_and_lists_follow() {
    let Some(mut w) = world().await else { return };
    let s = &w.a;
    // p-1 under p-2: the user of p-2 reaches an invoice of p-1 only there.
    let p2 = add_project(&mut w.d.owner, s, "p-2").await;
    assign(&mut w.d.owner, s, STRANGER, "reader", &p2).await;
    let check = |path: Value| {
        json!({
            "subject": who(STRANGER),
            "action": {"name": "invoice:read"},
            "resource": {"type": "invoice", "id": "inv-1",
                         "properties": {"path": path, "attrs": {}}},
        })
    };
    let token = w.issuer.token(SA, &s.tid, 0);
    let old_path = json!([entry(&s.project), entry(&s.org)]);
    let new_path = json!([entry(&s.project), entry(&p2), entry(&s.org)]);
    let v = body(
        w.post("/access/v1/evaluation", &token, &check(old_path.clone()))
            .await,
    )
    .await;
    assert_eq!(v["decision"], false);

    let tx = w.d.owner.transaction().await.unwrap();
    let rev = tutela_store::move_scope(&tx, &s.key, &s.project, &[p2.clone(), s.org.clone()])
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut asked = check(new_path);
    asked["context"] = json!({"at_least_revision": rev});
    let v = body(w.post("/access/v1/evaluation", &token, &asked).await).await;
    assert_eq!(v["decision"], true, "{v}");
    // The list filter sees the new path in the same revision.
    let search = json!({
        "subject": who(USER),
        "action": {"name": "invoice:read"},
        "resource": {"type": "invoice"},
        "context": {"at_least_revision": rev},
    });
    let v = body(w.post("/access/v1/search/resource", &token, &search).await).await;
    assert_eq!(v["context"]["tutela"]["rev"], rev);
    w.finish().await;
}

#[tokio::test]
async fn http_and_grpc_give_the_same_verdict() {
    let Some(mut w) = world().await else { return };
    let (p1, p2) = with_two_projects(&mut w).await;
    let s = &w.a;
    let mv = json!({
        "subject": who(MEMBER_A),
        "resource": invoice(s, &p1),
        "new_path": [entry(&p2), entry(&s.org)],
        "new_attrs": {"status": "done"},
        "approved_by": [OWNER_A],
    });
    let http = ask(&w, s, SA, &mv).await;

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", w.s.api))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AuthzClient::new(channel);
    let entry_pb = |e: &PathEntry| pb::PathEntry {
        r#type: e.type_name.to_string(),
        id: e.id.to_string(),
    };
    let token = w.issuer.token(SA, &s.tid, 0);
    let mut req = tonic::Request::new(pb::WriteCheckRequest {
        subject: Some(pb::Subject {
            r#type: "user".into(),
            id: MEMBER_A.into(),
            act: None,
        }),
        resource: Some(pb::Resource {
            r#type: "invoice".into(),
            id: "inv-1".into(),
            path: vec![entry_pb(&p1), entry_pb(&s.org)],
            attrs: Default::default(),
        }),
        new_attrs: [(
            "status".to_owned(),
            pb::AttrValue {
                value: Some(pb::attr_value::Value::StringValue("done".into())),
            },
        )]
        .into(),
        new_path: Some(pb::PathEntries {
            entries: vec![entry_pb(&p2), entry_pb(&s.org)],
        }),
        new_links: vec![],
        approved_by: vec![OWNER_A.into()],
        context: None,
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let out = client.write_check(req).await.unwrap().into_inner();
    let tutela: Value = serde_json::from_str(&out.decision_json).unwrap();
    assert_eq!(tutela, http["context"]["tutela"]);
    assert_eq!(out.decision, http["decision"].as_bool().unwrap());
    w.finish().await;
}
