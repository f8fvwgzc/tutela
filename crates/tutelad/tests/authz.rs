//! The evaluation APIs through the real auth layer and a real Postgres:
//! `POST /access/v1/evaluation`, `POST /access/v1/evaluations` and gRPC
//! `tutela.authz.v1`.
#![cfg(test)]

mod common;

use std::time::{Duration, SystemTime};

use common::{
    AGENT, B_USER, Issuer, SA, STRANGER, USER, World, ask, http, publish, revoke, world, world_with,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutelad::authz::grpc::pb;
use tutelad::authz::grpc::pb::authz_client::AuthzClient;

const EVAL: &str = "/access/v1/evaluation";
const BATCH: &str = "/access/v1/evaluations";

fn tutela(v: &Value) -> &Value {
    &v["context"]["tutela"]
}

/// The reason code of a result.
fn code(v: &Value) -> &str {
    let reason = tutela(v)["reason"].as_str().unwrap();
    reason.split(':').next().unwrap()
}

async fn eval(w: &World, token: &str, body: &Value) -> (StatusCode, Value) {
    let r = w.post(EVAL, token, body).await;
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

async fn store_rev(w: &mut World, tid: usize) -> u64 {
    let key = if tid == 0 { &w.a.key } else { &w.b.key };
    let tx = w.d.owner.transaction().await.unwrap();
    let rev = tutela_store::rev(&tx, key).await.unwrap();
    tx.commit().await.unwrap();
    rev
}

#[tokio::test]
async fn an_allowed_subject_gets_true_and_the_decision_names_its_revision() {
    let Some(mut w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (status, body) = eval(&w, &token, &ask(USER, "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], true, "{body}");
    assert_eq!(tutela(&body)["effect"], "allow");
    assert_eq!(tutela(&body)["level"], "read");
    assert_eq!(tutela(&body)["rev"], store_rev(&mut w, 0).await);
    // `amount` is confidential and the reader has no level on it.
    let read = tutela(&body)["field_mask"]["read"].as_array().unwrap();
    assert!(!read.contains(&json!("amount")), "{body}");
    w.finish().await;
}

#[tokio::test]
async fn a_denied_principal_gets_a_200_with_a_deny() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (status, body) = eval(&w, &token, &ask(USER, "invoice:write", &w.a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], false);
    assert!(
        tutela(&body)["reason"]
            .as_str()
            .unwrap()
            .starts_with("level_too_low")
    );

    let (status, body) = eval(&w, &token, &ask(STRANGER, "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], false);
    assert_eq!(tutela(&body)["level"], "none");
    w.finish().await;
}

#[tokio::test]
async fn a_person_may_ask_about_itself_and_about_no_one_else() {
    let Some(w) = world().await else { return };
    let mine = w.issuer.token(USER, &w.a.tid, 0);
    let (status, body) = eval(&w, &mine, &ask(USER, "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], true);

    let (status, body) = eval(&w, &mine, &ask(STRANGER, "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["type"], "urn:tutela:problem:forbidden");
    assert!(body.get("decision").is_none());

    // Naming an agent is a question about the agent.
    let mut with_agent = ask(USER, "invoice:read", &w.a);
    with_agent["subject"]["properties"] = json!({"act": {"sub": AGENT}});
    let (status, _) = eval(&w, &mine, &with_agent).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    w.finish().await;
}

/// A subject that exists only in tenant B gets, from tenant A, exactly the
/// answer of a subject that exists nowhere: a 200 deny, and nothing that
/// tells them apart.
#[tokio::test]
async fn tm05_a_subject_of_another_tenant_is_denied_like_one_that_does_not_exist() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (s1, in_b) = eval(&w, &token, &ask(B_USER, "invoice:read", &w.a)).await;
    let (s2, nowhere) = eval(&w, &token, &ask(STRANGER, "invoice:read", &w.a)).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(in_b["decision"], false);
    assert_eq!(code(&in_b), "no_role", "{in_b}");
    // The two differ only by the id each one asked about.
    let same = |v: &Value, id: &str| v.to_string().replace(id, "<subject>");
    assert_eq!(same(&in_b, B_USER), same(&nowhere, STRANGER));
    w.finish().await;
}

#[tokio::test]
async fn tm05_a_resource_of_another_tenant_is_denied_and_its_org_is_not_confirmed() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    // B's own org, with a subject who has a role there.
    let (s1, theirs) = eval(&w, &token, &ask(B_USER, "invoice:read", &w.b)).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(theirs["decision"], false);
    assert_eq!(code(&theirs), "tenant_mismatch");

    // An org that does not exist: the same answer.
    let mut fake = ask(B_USER, "invoice:read", &w.b);
    fake["resource"]["properties"]["path"][1]["id"] =
        json!("org_0193a1b2-c3d4-7f00-9a00-0000000000ff");
    let (_, nowhere) = eval(&w, &token, &fake).await;
    assert_eq!(theirs, nowhere);
    w.finish().await;
}

#[tokio::test]
async fn the_tenant_comes_from_the_token_and_nothing_in_the_request_changes_it() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    // B_USER is an approver in B. Everything here names B, and the token
    // is A's.
    let mut body = ask(B_USER, "invoice:read", &w.b);
    body["tenant"] = json!({"iss": common::ISS, "tid": w.b.tid});
    body["tid"] = json!(w.b.tid);
    let r = http()
        .post(w.s.api_url(&format!("{EVAL}?tid={}", w.b.tid)))
        .bearer_auth(&token)
        .header("x-tenant-id", &w.b.tid)
        .json(&body)
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["decision"], false, "{body}");
    assert_eq!(code(&body), "tenant_mismatch");
    w.finish().await;
}

#[tokio::test]
async fn a_verified_token_of_a_tenant_outside_the_directory_is_refused() {
    let Some(w) = world().await else { return };
    let cfg = common::config(
        &w.config.database_url,
        common::trust(&["ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d".to_owned()]),
    );
    let issuer = Issuer::new();
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;
    let token = issuer.token(SA, "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d", 0);
    let r = http()
        .post(s.api_url(EVAL))
        .bearer_auth(token)
        .json(&ask(USER, "invoice:read", &w.a))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    s.stop().await.unwrap();
    w.finish().await;
}

#[tokio::test]
async fn every_endpoint_refuses_a_caller_with_no_token_or_a_bad_one() {
    let Some(w) = world().await else { return };
    let body = ask(USER, "invoice:read", &w.a);
    for path in [EVAL, BATCH] {
        let none = http().post(w.s.api_url(path)).json(&body).send().await;
        assert_eq!(none.unwrap().status(), StatusCode::UNAUTHORIZED, "{path}");
        let stranger = Issuer::new().token(SA, &w.a.tid, 0);
        let bad = w.post(path, &stranger, &body).await;
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    w.finish().await;
}

#[tokio::test]
async fn a_bad_body_is_a_problem_document_that_quotes_nothing() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    for raw in ["not json", "{\"subject\": 7}", "[]"] {
        let r = http()
            .post(w.s.api_url(EVAL))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(raw)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{raw}");
        assert_eq!(
            r.headers()["content-type"],
            "application/problem+json",
            "{raw}"
        );
    }
    let (status, body) = eval(&w, &token, &ask(USER, "invoice:nothing", &w.a)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["type"], "urn:tutela:problem:unknown_key");
    w.finish().await;
}

/// With a check every hour, a change does not reach the replica by itself.
/// `at_least_revision` and the token's `rev` both make it look.
#[tokio::test]
async fn tm13_at_least_revision_reads_its_own_write_and_never_answers_from_older() {
    let Some(mut w) = world_with(|c| c.limits.check_every = Duration::from_secs(3)).await else {
        return;
    };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = ask(USER, "invoice:read", &w.a);
    assert_eq!(eval(&w, &token, &body).await.1["decision"], true);

    let id = w.a.assignment.clone();
    let rev = {
        let World { d, a, .. } = &mut w;
        revoke(&mut d.owner, a, &id).await
    };
    let mut fresh = body.clone();
    fresh["context"] = json!({"at_least_revision": rev});
    let (status, answer) = eval(&w, &token, &fresh).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"], false, "{answer}");
    assert_eq!(tutela(&answer)["rev"], rev);

    // A revision the database has not reached: fail closed, not an allow.
    fresh["context"] = json!({"at_least_revision": rev + 100});
    let r = w.post(EVAL, &token, &fresh).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers()["retry-after"], "1");
    let problem: Value = r.json().await.unwrap();
    assert_eq!(problem["type"], "urn:tutela:problem:stale");
    w.finish().await;
}

#[tokio::test]
async fn tm13_a_decision_is_never_older_than_the_token_rev() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 10_000);
    let r = w.post(EVAL, &token, &ask(USER, "invoice:read", &w.a)).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    w.finish().await;
}

#[tokio::test]
async fn a_change_reaches_an_answer_within_the_check_interval() {
    let Some(mut w) = world_with(|c| c.limits.check_every = Duration::from_millis(200)).await
    else {
        return;
    };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = ask(USER, "invoice:read", &w.a);
    assert_eq!(eval(&w, &token, &body).await.1["decision"], true);
    let id = w.a.assignment.clone();
    {
        let World { d, a, .. } = &mut w;
        revoke(&mut d.owner, a, &id).await;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(eval(&w, &token, &body).await.1["decision"], false);
    w.finish().await;
}

/// The revision does not move at an expiry until a sweep runs, an hour from
/// now here. The snapshot must stop at the expiry by itself.
#[tokio::test]
async fn tm13_an_assignment_stops_at_its_expiry_with_no_sweep_and_no_new_revision() {
    let Some(mut w) = world_with(|c| c.limits.check_every = Duration::from_secs(60)).await else {
        return;
    };
    {
        let World { d, a, .. } = &mut w;
        let tx = d.owner.transaction().await.unwrap();
        tutela_store::assign_until(
            &tx,
            &a.key,
            &tutela_pdp::Subject::Principal(STRANGER.parse().unwrap()),
            &tutela_pdp::model::RoleKey::parse("reader").unwrap(),
            &a.project,
            None,
            SystemTime::now() + Duration::from_millis(1500),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = ask(STRANGER, "invoice:read", &w.a);
    let (_, first) = eval(&w, &token, &body).await;
    assert_eq!(first["decision"], true, "{first}");
    let rev = tutela(&first)["rev"].clone();
    tokio::time::sleep(Duration::from_millis(1700)).await;
    let (_, after) = eval(&w, &token, &body).await;
    assert_eq!(after["decision"], false, "{after}");
    assert_eq!(tutela(&after)["rev"], rev, "the revision did not move");
    w.finish().await;
}

#[tokio::test]
async fn a_new_manifest_is_used_from_its_own_revision() {
    let Some(mut w) = world_with(|c| c.limits.check_every = Duration::ZERO).await else {
        return;
    };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = ask(USER, "invoice:read", &w.a);
    assert_eq!(eval(&w, &token, &body).await.1["decision"], true);
    // The new manifest takes `read` away from the reader.
    let narrower = common::MANIFEST.replace(
        r#"grants = { project = "read", invoice = "read" }"#,
        "grants = { project = \"read\" }",
    );
    publish(&mut w.d.owner, &narrower, Some(1)).await;
    let (_, after) = eval(&w, &token, &body).await;
    assert_eq!(after["decision"], false, "{after}");
    w.finish().await;
}

#[tokio::test]
async fn with_no_manifest_there_is_no_answer_and_never_an_allow() {
    let Some(mut d) = common::migrated().await else {
        return;
    };
    let a = common::seed(&mut d.owner, USER, "reader").await;
    let issuer = Issuer::new();
    let cfg = common::config(&d.service_url, common::trust(std::slice::from_ref(&a.tid)));
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;
    let r = http()
        .post(s.api_url(EVAL))
        .bearer_auth(issuer.token(SA, &a.tid, 0))
        .json(&ask(USER, "invoice:read", &a))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    s.stop().await.unwrap();
    d.finish().await;
}

// ---------- Batches ----------

#[tokio::test]
async fn a_batch_answers_in_order_with_defaults_and_item_overrides() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let one = ask(USER, "invoice:read", &w.a);
    let body = json!({
        "subject": one["subject"],
        "resource": one["resource"],
        "action": {"name": "invoice:read"},
        "evaluations": [
            {},
            {"action": {"name": "invoice:write"}},
            {"subject": ask(STRANGER, "invoice:read", &w.a)["subject"]},
        ],
    });
    let r: Value = w.post(BATCH, &token, &body).await.json().await.unwrap();
    let out = r["evaluations"].as_array().unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0]["decision"], true);
    assert_eq!(out[1]["decision"], false);
    assert_eq!(out[2]["decision"], false);
    assert_eq!(tutela(&out[0])["rev"], tutela(&out[2])["rev"]);
    w.finish().await;
}

#[tokio::test]
async fn a_batch_stops_where_its_semantic_says_and_an_empty_one_is_a_single_evaluation() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let read = ask(USER, "invoice:read", &w.a);
    let write = ask(USER, "invoice:write", &w.a);
    let batch = |semantic: &str| {
        json!({
            "evaluations": [read, write, read],
            "options": {"evaluations_semantic": semantic},
        })
    };
    for (semantic, want) in [
        ("execute_all", vec![true, false, true]),
        ("deny_on_first_deny", vec![true, false]),
        ("permit_on_first_permit", vec![true]),
    ] {
        let r: Value = w
            .post(BATCH, &token, &batch(semantic))
            .await
            .json()
            .await
            .unwrap();
        let got: Vec<bool> = r["evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["decision"].as_bool().unwrap())
            .collect();
        assert_eq!(got, want, "{semantic}");
    }
    let r = w.post(BATCH, &token, &batch("all_of_them")).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // No items: one evaluation, in the shape of one.
    let r: Value = w.post(BATCH, &token, &read).await.json().await.unwrap();
    assert_eq!(r["decision"], true, "{r}");
    assert!(r.get("evaluations").is_none());
    w.finish().await;
}

#[tokio::test]
async fn a_bad_item_gets_its_own_error_and_never_an_allow() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let good = ask(USER, "invoice:read", &w.a);
    let mut unknown = good.clone();
    unknown["action"]["name"] = json!("invoice:nothing");
    let body = json!({"evaluations": [unknown, {"action": {"name": "invoice:read"}}, good]});
    let r: Value = w.post(BATCH, &token, &body).await.json().await.unwrap();
    let out = r["evaluations"].as_array().unwrap();
    assert_eq!(out[0]["decision"], false);
    assert_eq!(out[0]["context"]["error"]["status"], 400);
    assert_eq!(out[1]["decision"], false, "no subject: {r}");
    assert_eq!(out[1]["context"]["error"]["status"], 400);
    assert_eq!(out[2]["decision"], true);
    w.finish().await;
}

#[tokio::test]
async fn a_batch_of_201_items_is_refused_and_one_of_200_is_not() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let item = ask(USER, "invoice:read", &w.a);
    let r = w
        .post(
            BATCH,
            &token,
            &json!({"evaluations": vec![item.clone(); 201]}),
        )
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let p: Value = r.json().await.unwrap();
    assert_eq!(p["type"], "urn:tutela:problem:too_many_items");
    let r: Value = w
        .post(BATCH, &token, &json!({"evaluations": vec![item; 200]}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(r["evaluations"].as_array().unwrap().len(), 200);
    w.finish().await;
}

#[tokio::test]
async fn a_person_cannot_hide_a_question_about_someone_else_inside_a_batch() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(USER, &w.a.tid, 0);
    let body = json!({"evaluations": [
        ask(USER, "invoice:read", &w.a),
        ask(STRANGER, "invoice:read", &w.a),
    ]});
    let r = w.post(BATCH, &token, &body).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    w.finish().await;
}

// ---------- gRPC ----------

async fn grpc(w: &World) -> AuthzClient<tonic::transport::Channel> {
    let channel = tonic::transport::Endpoint::from_shared(w.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    AuthzClient::new(channel)
}

fn with_token<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn grpc_ask(subject: &str, action: &str, s: &common::Seed) -> pb::EvaluationRequest {
    let entry = |e: &tutela_pdp::PathEntry| pb::PathEntry {
        r#type: e.type_name.to_string(),
        id: e.id.to_string(),
    };
    pb::EvaluationRequest {
        subject: Some(pb::Subject {
            r#type: subject.split(':').next().unwrap().to_owned(),
            id: subject.to_owned(),
            act: None,
        }),
        action: Some(pb::Action {
            name: action.to_owned(),
        }),
        resource: Some(pb::Resource {
            r#type: "invoice".to_owned(),
            id: "inv-1".to_owned(),
            path: vec![entry(&s.project), entry(&s.org)],
            attrs: std::collections::HashMap::new(),
        }),
        context: None,
    }
}

/// The two protocols run the same code: the same questions get the same
/// answers, field by field.
#[tokio::test]
async fn grpc_answers_as_http_does() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut client = grpc(&w).await;
    for (subject, action) in [
        (USER, "invoice:read"),
        (USER, "invoice:write"),
        (STRANGER, "invoice:read"),
        (B_USER, "invoice:read"),
    ] {
        let g = client
            .evaluate(with_token(&token, grpc_ask(subject, action, &w.a)))
            .await
            .unwrap()
            .into_inner();
        let (_, h) = eval(&w, &token, &ask(subject, action, &w.a)).await;
        let d = g.context.unwrap().tutela.unwrap();
        assert_eq!(json!(g.decision), h["decision"], "{subject} {action}");
        let t = tutela(&h);
        assert_eq!(json!(d.effect), t["effect"]);
        assert_eq!(json!(d.level), t["level"]);
        assert_eq!(json!(d.reason), t["reason"]);
        assert_eq!(json!(d.rev), t["rev"]);
        assert_eq!(json!(d.rule_ids), t["rule_ids"]);
        let mask = d.field_mask.unwrap();
        assert_eq!(json!(mask.read), t["field_mask"]["read"]);
        assert_eq!(json!(mask.write), t["field_mask"]["write"]);
    }
    w.finish().await;
}

#[tokio::test]
async fn grpc_refuses_what_http_refuses() {
    let Some(w) = world().await else { return };
    let mut client = grpc(&w).await;
    let e = client
        .evaluate(tonic::Request::new(grpc_ask(USER, "invoice:read", &w.a)))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    let person = w.issuer.token(USER, &w.a.tid, 0);
    let e = client
        .evaluate(with_token(
            &person,
            grpc_ask(STRANGER, "invoice:read", &w.a),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);

    let sa = w.issuer.token(SA, &w.a.tid, 0);
    let e = client
        .evaluate(with_token(&sa, grpc_ask(USER, "invoice:nothing", &w.a)))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);

    let late = w.issuer.token(SA, &w.a.tid, 10_000);
    let e = client
        .evaluate(with_token(&late, grpc_ask(USER, "invoice:read", &w.a)))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unavailable);

    // Another tenant's subject and resource: a deny, as over HTTP.
    let g = client
        .evaluate(with_token(&sa, grpc_ask(B_USER, "invoice:read", &w.b)))
        .await
        .unwrap()
        .into_inner();
    assert!(!g.decision);
    let reason = g.context.unwrap().tutela.unwrap().reason;
    assert!(reason.starts_with("tenant_mismatch"), "{reason}");
    w.finish().await;
}

#[tokio::test]
async fn grpc_runs_a_batch_with_the_same_rules() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut client = grpc(&w).await;
    let r = client
        .evaluations(with_token(
            &token,
            pb::EvaluationsRequest {
                evaluations: vec![
                    grpc_ask(USER, "invoice:read", &w.a),
                    grpc_ask(USER, "invoice:write", &w.a),
                    grpc_ask(USER, "invoice:read", &w.a),
                ],
                options: Some(pb::EvaluationsOptions {
                    evaluations_semantic: "deny_on_first_deny".to_owned(),
                }),
                ..pb::EvaluationsRequest::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let got: Vec<bool> = r.evaluations.iter().map(|e| e.decision).collect();
    assert_eq!(got, [true, false]);

    let e = client
        .evaluations(with_token(
            &token,
            pb::EvaluationsRequest {
                evaluations: std::iter::repeat_n(grpc_ask(USER, "invoice:read", &w.a), 201)
                    .collect(),
                ..pb::EvaluationsRequest::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    w.finish().await;
}

// ---------- Metrics, ids and metadata ----------

#[tokio::test]
async fn decisions_are_counted_by_outcome_and_the_metrics_hold_no_id() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    eval(&w, &token, &ask(USER, "invoice:read", &w.a)).await;
    eval(&w, &token, &ask(STRANGER, "invoice:read", &w.a)).await;
    eval(&w, &token, &ask(STRANGER, "invoice:read", &w.a)).await;
    let text = http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains(r#"tutelad_decisions_total{operation="evaluation",outcome="allow"} 1"#),
        "{text}"
    );
    assert!(
        text.contains(r#"tutelad_decisions_total{operation="evaluation",outcome="deny"} 2"#),
        "{text}"
    );
    for id in [USER, STRANGER, "inv-1", w.a.tid.as_str()] {
        assert!(!text.contains(id), "{id} reached the metrics");
    }
    w.finish().await;
}

#[tokio::test]
async fn the_callers_request_id_comes_back() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let r = http()
        .post(w.s.api_url(EVAL))
        .bearer_auth(&token)
        .header("x-request-id", "req-42")
        .json(&ask(USER, "invoice:read", &w.a))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["x-request-id"], "req-42");
    w.finish().await;
}

#[tokio::test]
async fn the_authzen_metadata_needs_a_token_and_names_the_endpoints() {
    let Some(w) = world().await else { return };
    let url = w.s.api_url("/.well-known/authzen-configuration");
    let none = http().get(&url).send().await.unwrap();
    assert_eq!(none.status(), StatusCode::UNAUTHORIZED);
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let m: Value = http()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pdp = m["policy_decision_point"].as_str().unwrap();
    assert_eq!(
        m["access_evaluation_endpoint"],
        format!("{pdp}/access/v1/evaluation")
    );
    assert_eq!(
        m["access_evaluations_endpoint"],
        format!("{pdp}/access/v1/evaluations")
    );
    w.finish().await;
}
