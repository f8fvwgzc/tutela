//! Explain and simulate through the real auth layer on a real Postgres
//! (CONTRACTS.md 7.11, ADR-0028).
#![cfg(test)]

mod common;

use common::{AGENT, B_USER, MANIFEST, SA, STRANGER, Seed, USER, World, ask, world};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::model::RoleKey;
use tutela_pdp::{PathEntry, Subject};
use tutela_store::tokio_postgres::Client;
use tutelad::authz::grpc::pb;
use tutelad::authz::grpc::pb::authz_client::AuthzClient;

const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c1";
const OWNER_P2: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c2";

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

/// The org owner of A, and an owner of a second project p-2 only.
async fn setup(w: &mut World) -> PathEntry {
    let s = w.a.clone_seed();
    assign(&mut w.d.owner, &s, ADMIN, "owner", &s.org).await;
    let p2 = PathEntry::new("project".parse().unwrap(), "p-2".parse().unwrap());
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::put_scope(&tx, &s.key, &p2, std::slice::from_ref(&s.org), false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assign(&mut w.d.owner, &s, OWNER_P2, "owner", &p2).await;
    p2
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

async fn post(w: &World, path: &str, asker: &str, s: &Seed, body: &Value) -> (StatusCode, Value) {
    let t = w.issuer.token(asker, &s.tid, 0);
    let res = w.post(path, &t, body).await;
    let status = res.status();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn an_admin_sees_why_and_others_may_not_ask() {
    let Some(mut w) = world().await else { return };
    setup(&mut w).await;
    let q = ask(USER, "invoice:read", &w.a);
    let (status, v) = post(&w, "/v1/authz/explain", ADMIN, &w.a, &q).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], true);
    let e = &v["context"]["tutela"];
    assert_eq!(e["decision"]["effect"], "allow");
    assert_eq!(e["sides"][0]["principal"], USER);
    assert_eq!(e["sides"][0]["outcome"], "assignment");
    assert_eq!(e["rules"][0]["kind"], "assignment");
    assert_eq!(e["rules"][0]["role"], "reader");
    assert_eq!(e["rules"][0]["id"], w.a.assignment.to_string());

    // A plain check never needed this: the user itself, its product service,
    // and an agent may not ask why.
    for asker in [USER, SA, AGENT] {
        let (status, _) = post(&w, "/v1/authz/explain", asker, &w.a, &q).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{asker}");
    }
    // The owner of p-2 owns nothing on the path of p-1.
    let (status, _) = post(&w, "/v1/authz/explain", OWNER_P2, &w.a, &q).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let m = reqwest::get(w.s.ops_url("/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(m.contains("tutelad_decisions_total{operation=\"explain\",outcome=\"allow\"} 1"));
    assert!(m.contains("tutelad_decisions_total{operation=\"explain\",outcome=\"error\"}"));
    w.finish().await;
}

#[tokio::test]
async fn tm09_a_path_made_up_to_reach_a_scope_one_owns_is_refused() {
    let Some(mut w) = world().await else { return };
    let p2 = setup(&mut w).await;
    let s = &w.a;
    // p-1 really sits at the org. Put it under p-2, which OWNER_P2 owns, to
    // read who holds p-1.
    let q = json!({
        "subject": {"type": "user", "id": USER},
        "action": {"name": "project:read"},
        "resource": {"type": "project", "id": "p-1", "properties": {"path": [
            {"type": "project", "id": p2.id.to_string()},
            {"type": "org", "id": s.org.id.to_string()},
        ], "attrs": {}}},
    });
    let (status, v) = post(&w, "/v1/authz/explain", OWNER_P2, s, &q).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    let (status, _) = post(&w, "/v1/authz/simulate", OWNER_P2, s, &q).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    w.finish().await;
}

#[tokio::test]
async fn tm05_an_admin_of_one_tenant_explains_nothing_in_another() {
    let Some(mut w) = world().await else { return };
    setup(&mut w).await;
    let b = w.b.clone_seed();
    assign(&mut w.d.owner, &b, ADMIN, "owner", &b.org).await;
    // ADMIN owns tenant B too. Its token for B asks about tenant A's invoice.
    // Tenant B has a p-1 of its own, at its own org, so the path is refused
    // as made up; with no such scope, the key is missing at a foreign org.
    let q = ask(B_USER, "invoice:read", &w.a);
    for path in ["/v1/authz/explain", "/v1/authz/simulate"] {
        let (status, v) = post(&w, path, ADMIN, &b, &q).await;
        assert!(
            [StatusCode::BAD_REQUEST, StatusCode::FORBIDDEN].contains(&status),
            "{path}: {status} {v}"
        );
    }
    let mut q = ask(B_USER, "invoice:read", &w.a);
    q["resource"]["properties"]["path"] = json!([{"type": "org", "id": w.a.org.id.to_string()}]);
    let (status, _) = post(&w, "/v1/authz/explain", ADMIN, &b, &q).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // About its own tenant's resource, a subject of tenant A is nobody here.
    let q = ask(USER, "invoice:read", &b);
    let (status, v) = post(&w, "/v1/authz/explain", ADMIN, &b, &q).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["context"]["tutela"]["sides"][0]["outcome"], "no_role");
    assert_eq!(v["context"]["tutela"]["rules"], json!([]));
    w.finish().await;
}

#[tokio::test]
async fn a_simulation_answers_for_a_candidate_and_writes_nothing() {
    let Some(mut w) = world().await else { return };
    setup(&mut w).await;
    let s = w.a.clone_seed();
    let write = |extra: Value| {
        let mut q = ask(USER, "invoice:write", &s);
        q["candidate"] = extra;
        q
    };
    let source = MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        "grants = { project = \"read\", invoice = \"write\" }",
    );
    let (status, v) = post(
        &w,
        "/v1/authz/simulate",
        ADMIN,
        &s,
        &write(json!({"source": source})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], true);
    assert_eq!(v["current"]["decision"], false);
    assert_eq!(v["changed"], true);
    // The live answer is the old one.
    let t = w.issuer.token(SA, &s.tid, 0);
    let live: Value = w
        .post("/access/v1/evaluation", &t, &ask(USER, "invoice:write", &s))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(live["decision"], false);

    // What if the stranger were a reader, and the user were not?
    let mut q = ask(STRANGER, "invoice:read", &s);
    q["candidate"] = json!({"add": [{"subject": STRANGER, "role": "reader",
                                      "scope": {"type": "project", "id": "p-1"}}]});
    let (_, v) = post(&w, "/v1/authz/simulate", ADMIN, &s, &q).await;
    assert_eq!(
        (v["current"]["decision"].clone(), v["decision"].clone()),
        (json!(false), json!(true))
    );
    let mut q = ask(USER, "invoice:read", &s);
    q["candidate"] = json!({"remove": [s.assignment.to_string()]});
    let (_, v) = post(&w, "/v1/authz/simulate", ADMIN, &s, &q).await;
    assert_eq!(
        (v["current"]["decision"].clone(), v["decision"].clone()),
        (json!(true), json!(false))
    );
    // No candidate: the two answers are the same.
    let (_, v) = post(
        &w,
        "/v1/authz/simulate",
        ADMIN,
        &s,
        &ask(USER, "invoice:read", &s),
    )
    .await;
    assert_eq!(v["changed"], false);

    // Bad candidates are the caller's to fix, and change nothing.
    for bad in [
        json!({"source": "not toml"}),
        json!({"remove": ["ra_nothing"]}),
        json!({"add": [{"subject": USER, "role": "reader",
                         "scope": {"type": "project", "id": "p-1"}}]}),
        json!({"add": [{"subject": "nobody", "role": "reader",
                         "scope": {"type": "project", "id": "p-1"}}]}),
    ] {
        let (status, v) = post(&w, "/v1/authz/simulate", ADMIN, &s, &write(bad.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    for asker in [USER, SA, AGENT] {
        let (status, _) = post(&w, "/v1/authz/simulate", asker, &s, &write(json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{asker}");
    }
    w.finish().await;
}

#[tokio::test]
async fn http_and_grpc_explain_alike() {
    let Some(mut w) = world().await else { return };
    setup(&mut w).await;
    let s = &w.a;
    let (_, http) = post(
        &w,
        "/v1/authz/explain",
        ADMIN,
        s,
        &ask(USER, "invoice:read", s),
    )
    .await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", w.s.api))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AuthzClient::new(channel);
    let entry = |e: &PathEntry| pb::PathEntry {
        r#type: e.type_name.to_string(),
        id: e.id.to_string(),
    };
    let mut req = tonic::Request::new(pb::EvaluationRequest {
        subject: Some(pb::Subject {
            r#type: "user".into(),
            id: USER.into(),
            act: None,
        }),
        action: Some(pb::Action {
            name: "invoice:read".into(),
        }),
        resource: Some(pb::Resource {
            r#type: "invoice".into(),
            id: "inv-1".into(),
            path: vec![entry(&s.project), entry(&s.org)],
            attrs: Default::default(),
        }),
        context: None,
    });
    let token = w.issuer.token(ADMIN, &s.tid, 0);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let out = client.explain(req).await.unwrap().into_inner();
    let tutela: Value = serde_json::from_str(&out.explanation_json).unwrap();
    assert_eq!(tutela, http["context"]["tutela"]);
    assert_eq!(out.decision, http["decision"].as_bool().unwrap());
    w.finish().await;
}
